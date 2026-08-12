//! `ledger ldfi` campaign driver.
//!
//! Searches the mini key-value workload for the first violation, ranks the
//! LDFI fault hypotheses, and replays the top hypothesis with fault
//! injection to report how many faults applied or were voided.

use ledger_explorer::ldfi::hypothesis_to_schedule;
use ledger_explorer::oracle::{HistoryOracle, KeyValueSpec};
use ledger_explorer::search::{replay_with_faults, search};
use ledger_explorer::{FaultHypothesis, solve_ldfi};
use ledger_format::Hash;
use ledger_sim::{FaultInjection, Policy, RunConfig};

use crate::{DefaultMiniKv, seed_from_u64};

#[derive(Debug, Clone)]
pub struct LdfiHypothesis {
    /// Fault event ids in this cut.
    pub events: Vec<Hash>,
    /// Aggregate cut cost.
    pub cost: u64,
    /// Explanation of which causal paths are broken.
    pub explanation: String,
}

/// Result of an LDFI campaign that found a violation.
#[derive(Debug, Clone)]
pub struct LdfiReport {
    /// Campaign attempts consumed.
    pub attempts: usize,
    /// Oracle violation reason.
    pub reason: String,
    /// Steps in the violating run.
    pub steps: usize,
    /// Journal root of the violating run.
    pub journal_root: Hash,
    /// Ranked hypotheses, cheapest first.
    pub hypotheses: Vec<LdfiHypothesis>,
    /// Fault injections in the executed top schedule.
    pub schedule: Vec<FaultInjection>,
    /// Number of injections that took effect.
    pub applied: usize,
    /// Number of injections that were voided.
    pub voided: usize,
    /// True when the journal prefix before the first fault matches the base run.
    pub prefix_ok: bool,
}

/// Runs the LDFI campaign.
///
/// Returns `Ok(None)` when the campaign finds no violation within `attempts`.
pub fn run_ldfi(
    seed: u64,
    max_steps: usize,
    attempts: usize,
) -> Result<Option<LdfiReport>, String> {
    let workload = DefaultMiniKv;
    let oracle = HistoryOracle::new(&workload, KeyValueSpec::default());
    let config = RunConfig {
        seed: seed_from_u64(seed),
        policy: Policy::Bandit {
            exploration_constant: 1.414,
            pct_mix: 0.1,
        },
        max_steps,
        ..RunConfig::default()
    };

    let Some(finding) = search(&workload, &oracle, config, attempts)? else {
        return Ok(None);
    };

    let hypotheses: Vec<FaultHypothesis> = solve_ldfi(&finding.run.journal, &finding.verdict);
    let schedule = hypotheses
        .first()
        .map(|top| hypothesis_to_schedule(top, &finding.run.journal))
        .unwrap_or_default();
    let replay_report = replay_with_faults(
        &workload,
        &finding.run.journal,
        finding.seed,
        finding.run.decisions.clone(),
        schedule.clone(),
    )?;

    Ok(Some(LdfiReport {
        attempts,
        reason: finding.verdict.reason.clone(),
        steps: finding.run.steps,
        journal_root: finding.run.journal.root_hash(),
        hypotheses: hypotheses
            .into_iter()
            .map(|hypothesis| LdfiHypothesis {
                events: hypothesis.events,
                cost: hypothesis.total_cost,
                explanation: hypothesis.explanation,
            })
            .collect(),
        schedule,
        applied: replay_report.applied.len(),
        voided: replay_report.voided.len(),
        prefix_ok: replay_report.prefix_ok,
    }))
}
