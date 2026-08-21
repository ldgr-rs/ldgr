use super::Workload;
use crate::diagnosis::first_divergence;
use ledger_format::Hash;
use ledger_sim::{Policy, RunConfig, RunResult, SimFault, Simulation};

/// Replay one workload under a recorded scheduling decision sequence.
pub fn replay<W: Workload>(
    workload: &W,
    seed: Hash,
    decisions: Vec<usize>,
) -> Result<RunResult, String> {
    let mut config = RunConfig::builder()
        .seed(seed)
        .policy(Policy::Replay)
        .build();
    *config.max_steps_mut() = decisions.len().saturating_add(256);
    Simulation::with_replay(config, workload.programs(), decisions)
        .run()
        .map_err(|error| format!("replay failed: {error}"))
}

/// Outcome of a fault-injected replay.
#[derive(Debug, Clone)]
pub struct FaultReplayReport {
    pub run: RunResult,
    /// Schedule injections that took effect: the first injection per applied
    /// event, in schedule order.
    pub applied: Vec<SimFault>,
    /// Injections whose target event never fired, whose class was superseded
    /// by an earlier injection on the same event, or which target a link
    /// rather than an event (voided faults are data).
    pub voided: Vec<SimFault>,
    /// No divergence before the first applied fault.
    pub prefix_ok: bool,
}

/// Replay one workload with a fault schedule injected at causal positions.
pub fn replay_with_faults<W: Workload>(
    workload: &W,
    base: &ledger_journal::Journal,
    seed: Hash,
    decisions: Vec<usize>,
    schedule: Vec<SimFault>,
) -> Result<FaultReplayReport, String> {
    let mut config = RunConfig::builder()
        .seed(seed)
        .policy(Policy::Replay)
        .fault_schedule(schedule.clone())
        .build();
    *config.max_steps_mut() = decisions.len().saturating_add(256);
    let run = Simulation::with_replay(config, workload.programs(), decisions)
        .run()
        .map_err(|error| format!("fault replay failed: {error}"))?;
    let applied_set: std::collections::HashSet<&Hash> = run.applied_faults.iter().collect();
    let mut seen_applied = std::collections::HashSet::new();
    let mut applied = Vec::new();
    let mut voided = Vec::new();
    for injection in schedule {
        match super::fault_injection_target(&injection) {
            // A link partition targets no single event, so it cannot be
            // attributed to an applied event id; it is reported voided.
            None => voided.push(injection),
            Some(id) if applied_set.contains(&id) && seen_applied.insert(id) => {
                applied.push(injection);
            }
            Some(_) => voided.push(injection),
        }
    }
    let base_ids: Vec<_> = base.entries().map(|entry| entry.id).collect();
    let replay_ids: Vec<_> = run.journal.entries().map(|entry| entry.id).collect();
    let first_fault = run
        .applied_faults
        .iter()
        .filter_map(|id| base_ids.iter().position(|base| base == id))
        .min()
        .unwrap_or(base_ids.len());
    let prefix_ok = base_ids.len() >= first_fault
        && replay_ids.len() >= first_fault
        && base_ids
            .iter()
            .zip(replay_ids.iter())
            .take(first_fault)
            .all(|(base, replay)| base == replay);
    Ok(FaultReplayReport {
        run,
        applied,
        voided,
        prefix_ok,
    })
}

pub fn diff(left: &RunResult, right: &RunResult) -> Option<(Hash, Hash)> {
    first_divergence(&left.journal, &right.journal).map(|(left, right)| {
        (
            left.map_or([0; 32], |entry| entry.id),
            right.map_or([0; 32], |entry| entry.id),
        )
    })
}
