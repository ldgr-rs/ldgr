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
pub use ledger_journal::{Journal, PersistentJournal};
pub use quad::{QuadMutation, run_campaign_quad, run_swarm_campaign};
pub use replay::{
    FaultReplayError, FaultReplayReport, JournalDiff, diff, replay, replay_prefix, replay_strict,
    replay_with_faults,
};

use crate::oracle::Oracle;
use ledger_format::EntryHash;
use ledger_sim::{Probability, RunConfig, SeedTree, SimFault, Simulation, SwarmConfig};
use rand_core::Rng;
use std::collections::HashSet;

/// Typed error for campaign search and replay paths.
///
/// Preserves the underlying [`ledger_sim::RuntimeError`] instead of
/// flattening it into a string, so callers keep the typed cause.
#[derive(Debug, thiserror::Error)]
pub enum SearchError {
    #[error("simulation failed: {0}")]
    Simulation(Box<ledger_sim::RuntimeError>),
    #[error("solver failed: {0}")]
    Solver(#[from] crate::solver::SolverError),
    #[error("canonical hash failed: {0}")]
    Canonical(#[from] ledger_sim::ConfigCanonicalError),
    #[error("probability draw failed: {0}")]
    Probability(#[from] ledger_sim::ProbabilityError),
    #[error("solver state: {0}")]
    State(#[from] crate::solver_state::SolverStateError),
    #[error("pbt sampling failed: {0}")]
    Pbt(#[from] crate::pbt::PbtError),
    #[error("bandit selected unknown arm {arm:#x}")]
    UnknownArm { arm: u64 },
    #[error(transparent)]
    Replay(Box<FaultReplayError>),
}

impl From<ledger_sim::RuntimeError> for SearchError {
    fn from(error: ledger_sim::RuntimeError) -> Self {
        Self::Simulation(Box::new(error))
    }
}

impl From<FaultReplayError> for SearchError {
    fn from(error: FaultReplayError) -> Self {
        Self::Replay(Box::new(error))
    }
}

fn fault_injection_target(injection: &SimFault) -> Option<EntryHash> {
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
) -> Result<(Option<Finding>, usize), SearchError> {
    for attempt in 0..budget {
        let mut seed = base.seed();
        seed.0[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());
        let config = base.clone().with_seed(seed);
        let run = Simulation::new(config.clone(), workload.programs()).run()?;
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
/// saw on the partial journal: an exhausted step budget, pending tasks
/// at quiescence, or a mid-run monitor halt all mean the system under test
/// failed to make progress.
pub fn effective_verdict(run: &ledger_sim::RunResult, verdict: crate::Verdict) -> crate::Verdict {
    let reason = match &run.outcome {
        ledger_sim::RunOutcome::Completed => return verdict,
        ledger_sim::RunOutcome::BudgetExhausted => format!(
            "liveness violation: step budget exhausted after {} steps with tasks pending",
            run.steps
        ),
        ledger_sim::RunOutcome::Blocked => {
            "liveness violation: run quiesced with pending tasks".to_string()
        }
        ledger_sim::RunOutcome::MonitorHalt(reason) => {
            format!("monitor halt: {reason}")
        }
    };
    // Structural witnesses first; a stalled or halted run may have none, so
    // fall back to the journal tail: the last entries show where progress
    // stopped.
    let mut witnesses = crate::oracle::witnesses_from_journal(&run.journal);
    if witnesses.is_empty() {
        witnesses = run.journal.tail_ids(8);
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

fn unbiased_range(rng: &mut impl Rng, bound: u64) -> u64 {
    if bound == u64::MAX {
        return rng.next_u64();
    }
    let limit = bound + 1;
    let threshold = u64::MAX - (u64::MAX % limit);
    loop {
        let value = rng.next_u64();
        if value < threshold {
            return value % limit;
        }
    }
}

fn draw_swarm(
    seed: EntryHash,
    label: &str,
    budget: u64,
    crash_ceiling: f64,
) -> Result<SwarmConfig, ledger_sim::ProbabilityError> {
    let mut rng = SeedTree::new(seed).rng(label);
    let scale = |value: u64| value as f64 / u64::MAX as f64;
    let drop_probability = Probability::new(scale(rng.next_u64()))?;
    let delay_probability = Probability::new(scale(rng.next_u64()))?;
    let crash_probability = Probability::new(scale(rng.next_u64()) * crash_ceiling)?;
    Ok(SwarmConfig {
        drop_probability,
        delay_probability,
        max_delay_ticks: unbiased_range(&mut rng, budget),
        crash_probability,
        fault_classes_per_run: SWARM_FAULT_CLASSES_PER_RUN,
    })
}

fn draw_fault_subset(
    library: &[SimFault],
    max_per_run: usize,
    rng: &mut impl Rng,
) -> Vec<SimFault> {
    let cap = max_per_run.min(library.len());
    let count = unbiased_range(rng, cap as u64) as usize;
    let mut chosen = Vec::with_capacity(count);
    let mut used: HashSet<usize> = HashSet::new();
    while chosen.len() < count {
        let index = unbiased_range(rng, (library.len() - 1) as u64) as usize;
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
        swarm.drop_probability.get(),
        swarm.delay_probability.get(),
        swarm.max_delay_ticks,
        swarm.crash_probability.get(),
        swarm.fault_classes_per_run,
    )
}
