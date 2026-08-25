//! Seeded campaign search, multi-policy exploration, and replay verification.

mod bandit;
mod campaign;
mod feedback;
mod input_axis;
mod joint;
mod quad;
mod replay;
#[cfg(test)]
mod tests;

pub use bandit::{QuadBandit, run_bandit_campaign};
pub use campaign::{
    CampaignReport, Finding, Workload, run_campaign, run_monitored_campaign, search,
};
pub use feedback::{escalate, run_feedback_campaign, run_feedback_campaign_with_state};
pub use input_axis::{search_input, search_input_energy};
pub use joint::{CampaignPersist, run_joint_campaign, run_joint_campaign_with_state};
pub use quad::{QuadMutation, run_campaign_quad, run_swarm_campaign};
pub use replay::{FaultReplayReport, diff, replay, replay_with_faults};

use crate::oracle::Oracle;
use ledger_format::Hash;
use ledger_sim::{RunConfig, SeedTree, SimFault, Simulation, SwarmConfig};
use rand_core::Rng;
use std::collections::HashSet;

fn fault_injection_target(injection: &SimFault) -> Option<Hash> {
    match injection {
        SimFault::Drop(id)
        | SimFault::Delay { send: id, .. }
        | SimFault::Crash(id)
        | SimFault::Corrupt { write: id, .. }
        | SimFault::CrashState { write: id, .. } => Some(*id),
        SimFault::Partition { .. } => None,
    }
}

/// Search deterministic seeds sequentially until the first oracle violation.
///
/// Returns the finding, if any, and the number of runs consumed. The total is
/// always exactly `budget`, so a campaign can compute its remaining budget.
fn find_first_violation<W: Workload, O: Oracle>(
    workload: &W,
    oracle: &O,
    base: &RunConfig,
    budget: usize,
) -> Result<(Option<Finding>, usize), String> {
    for attempt in 0..budget {
        let mut config = base.clone();
        config.seed_mut()[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());
        let run = Simulation::new(config.clone(), workload.programs())
            .run()
            .map_err(|error| format!("simulation failed: {error:?}"))?;
        let verdict = effective_verdict(&run, oracle.check(&run));
        if verdict.violated {
            return Ok((
                Some(Finding {
                    seed: config.seed(),
                    run,
                    verdict,
                }),
                attempt + 1,
            ));
        }
    }
    Ok((None, budget))
}

/// Promote an incomplete run to a liveness violation.
///
/// A run that never completed is a finding regardless of what the oracle
/// saw on the partial journal: an exhausted step budget or pending tasks
/// at quiescence both mean the system under test failed to make progress.
pub fn effective_verdict(run: &ledger_sim::RunResult, verdict: crate::Verdict) -> crate::Verdict {
    if run.outcome == ledger_sim::RunOutcome::Completed {
        return verdict;
    }
    let reason = match run.outcome {
        ledger_sim::RunOutcome::BudgetExhausted => format!(
            "liveness violation: step budget exhausted after {} steps with tasks pending",
            run.steps
        ),
        _ => "liveness violation: run quiesced with pending tasks".to_string(),
    };
    // Structural witnesses first; a stalled run may have none, so fall
    // back to the journal tail: the last entries show where progress
    // stopped.
    let mut witnesses = crate::oracle::witnesses_from_journal(&run.journal);
    if witnesses.is_empty() {
        let ids: Vec<ledger_format::Hash> = run.journal.entries().map(|entry| entry.id).collect();
        let start = ids.len().saturating_sub(8);
        witnesses = ids[start..].to_vec();
    }
    crate::oracle::Verdict::fail(witnesses, reason)
}

/// Shared fault-class budget for the swarm axis across every campaign type.
///
/// This is a budget, not a semantic guarantee: once this many distinct
/// post-crash state classes have been applied in one run, further sampled
/// crashes are skipped. Matches [`SwarmConfig::default`].
const SWARM_FAULT_CLASSES_PER_RUN: usize = 2;

/// Shared crash-probability ceiling for the swarm axis across every campaign
/// type, so quad and swarm-only campaigns draw comparable distributions.
const SWARM_CRASH_CEILING: f64 = 0.1;

/// Max-delay budget for the swarm-only campaign, so its swarm draws match the
/// quad campaign's default budget.
const SWARM_CAMPAIGN_MAX_DELAY_BUDGET: u64 = 8;

fn draw_swarm(seed: Hash, label: &str, budget: u64, crash_ceiling: f64) -> SwarmConfig {
    let mut rng = SeedTree::new(seed).rng(label);
    let scale = |value: u64| value as f64 / u64::MAX as f64;
    SwarmConfig {
        drop_probability: scale(rng.next_u64()),
        delay_probability: scale(rng.next_u64()),
        max_delay_ticks: rng.next_u64() % (budget + 1),
        crash_probability: scale(rng.next_u64()) * crash_ceiling,
        fault_classes_per_run: SWARM_FAULT_CLASSES_PER_RUN,
    }
}

fn draw_fault_subset(
    library: &[SimFault],
    max_per_run: usize,
    rng: &mut impl Rng,
) -> Vec<SimFault> {
    let cap = max_per_run.min(library.len());
    let count = (rng.next_u64() as usize) % (cap + 1);
    let mut chosen = Vec::with_capacity(count);
    let mut used: HashSet<usize> = HashSet::new();
    while chosen.len() < count {
        let index = (rng.next_u64() as usize) % library.len();
        if used.insert(index) {
            chosen.push(library[index].clone());
        }
    }
    chosen
}

fn describe_variant(config: &RunConfig, attempt: usize, input_label: Option<&str>) -> String {
    let swarm = config.swarm();
    let faults = config
        .fault_schedule()
        .iter()
        .map(|fault| format!("{fault:?}"))
        .collect::<Vec<_>>()
        .join(",");
    let input = input_label
        .map(|label| format!(" input={label}"))
        .unwrap_or_default();
    format!(
        "attempt={attempt} policy={:?} swarm=drop={:.6} delay={:.6} max_delay={} crash={:.6} classes={} faults=[{faults}]{input}",
        config.policy(),
        swarm.drop_probability,
        swarm.delay_probability,
        swarm.max_delay_ticks,
        swarm.crash_probability,
        swarm.fault_classes_per_run,
    )
}
