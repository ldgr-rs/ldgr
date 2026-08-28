//! `ledger ldfi` campaign driver.
//!
//! Searches the mini key-value workload for the first violation, ranks the
//! LDFI fault hypotheses, and replays the top hypothesis with fault
//! injection to report how many faults applied or were voided.

use ledger_explorer::ldfi::hypothesis_to_schedule;
use ledger_explorer::maxsat::encode_hazard;
use ledger_explorer::oracle::{HistoryOracle, KeyValueSpec};
use ledger_explorer::search::{replay_with_faults, search, FaultReplayError, SearchError};
use ledger_explorer::{select_solver, solve_with, FaultHypothesis, SolverConfig, SolverError};
use ledger_format::Hash;
use ledger_sim::{Policy, RunConfig, SimFault};
use thiserror::Error;

use crate::{default_pct_mix, seed_from_u64, DefaultMiniKv, MaxSatEngineArg};

/// Errors from the `ldfi` campaign driver.
#[derive(Debug, Error)]
pub enum LdfiCmdError {
    /// Campaign search failed.
    #[error(transparent)]
    Search(#[from] SearchError),
    /// Ranking the fault hypotheses failed.
    #[error(transparent)]
    Solve(#[from] SolverError),
    /// Fault replay failed.
    #[error(transparent)]
    Replay(#[from] FaultReplayError),
}

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
    pub schedule: Vec<SimFault>,
    /// Number of injections that took effect.
    pub applied: usize,
    /// Number of injections that were voided.
    pub voided: usize,
    /// Journal entry hashes witnessing the violation.
    pub witnesses: Vec<Hash>,
    /// Effect origins for the witness entries, when captured.
    pub origins: Vec<(Hash, ledger_sim::OriginSource)>,
    /// True when the journal prefix before the first fault matches the base run.
    pub prefix_ok: bool,
}

/// Runs the LDFI campaign.
///
/// `maxsat_engine` selects the fault-solver engine for hypothesis ranking;
/// see [`MaxSatEngineArg`]. Returns `Ok(None)` when the campaign finds no
/// violation within `attempts`.
///
/// # Errors
/// Returns [`LdfiCmdError`] when search, hypothesis ranking, or replay fails.
pub fn run_ldfi(
    seed: u64,
    max_steps: usize,
    attempts: usize,
    maxsat_engine: MaxSatEngineArg,
) -> Result<Option<LdfiReport>, LdfiCmdError> {
    let workload = DefaultMiniKv;
    let oracle = HistoryOracle::new(&workload, KeyValueSpec::default());
    let config = RunConfig::builder()
        .seed(seed_from_u64(seed))
        .policy(Policy::Bandit {
            exploration_constant: 1.414,
            pct_mix: default_pct_mix(),
        })
        .max_steps(max_steps)
        .build();

    let Some(finding) = search(&workload, &oracle, config, attempts)? else {
        return Ok(None);
    };

    // Production default horizon 64; the engine comes from --maxsat-engine.
    let solver_config = SolverConfig {
        max_horizon: Some(64),
        engine: maxsat_engine.to_solver_engine(),
        ..SolverConfig::default()
    };
    let encoded = encode_hazard(&finding.run.journal, &finding.verdict, &solver_config)
        .map_err(LdfiCmdError::Solve)?;
    let mut solver = select_solver(&solver_config, &encoded);
    let hypotheses: Vec<FaultHypothesis> =
        solve_with(solver.as_mut(), &finding.run.journal, &finding.verdict)
            .map_err(LdfiCmdError::Solve)?;
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
        witnesses: finding.verdict.witnesses.clone(),
        origins: finding.run.origins.clone(),
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
