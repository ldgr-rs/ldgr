use super::ddmin::ddmin;
use super::journal_inputs;
use crate::oracle::Oracle;
use crate::search::{Finding, Workload};
use ledger_sim::{Policy, RunConfig, SimFault, Simulation};

/// Outcome of the input-delta debugging stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputReduction {
    /// One-minimal input values in journal order.
    pub inputs: Vec<u64>,
    /// True when the reduced inputs still violate the oracle.
    pub violation_preserved: bool,
}

/// Input-delta debugging over the generated input that produced a finding.
///
/// The input is read from the failing journal's `InputStep` entries, so ddmin
/// runs over the exact sequence that violated the oracle. Every candidate
/// replays under the finding's recorded schedule, keeping the input reduction
/// on the finding's own schedule axis. When no reduction preserves the
/// violation, the un-reduced journal input is returned with
/// `violation_preserved` false; the stage never errors on that.
pub fn minimize_input<W, O>(
    workload_template: &W,
    oracle: &O,
    finding: &Finding,
    generator: &str,
) -> InputReduction
where
    W: Workload + ?Sized,
    O: Oracle + ?Sized,
{
    minimize_input_with_faults(workload_template, oracle, finding, generator, &[])
}

/// Input-delta debugging under a pinned fault schedule.
///
/// Every candidate replays with `schedule` injected, so the reduction runs
/// on the finding's own (input, schedule, fault) triple. Required for joint
/// plants whose violation needs the injected fault.
pub fn minimize_input_with_faults<W, O>(
    workload_template: &W,
    oracle: &O,
    finding: &Finding,
    generator: &str,
    schedule: &[SimFault],
) -> InputReduction
where
    W: Workload + ?Sized,
    O: Oracle + ?Sized,
{
    let full = journal_inputs(&finding.run.journal, generator);
    let fails = |candidate: &[u64]| -> bool {
        let workload = workload_template.with_inputs(candidate);
        let config = RunConfig::builder()
            .seed(finding.seed)
            .policy(Policy::Replay)
            .max_steps(finding.run.decisions.len().saturating_add(256))
            .fault_schedule(schedule.to_vec())
            .build();
        Simulation::with_replay(config, workload.programs(), finding.run.decisions.clone())
            .run()
            .map(|run| oracle.check(&run).violated)
            .unwrap_or(false)
    };
    let preserved = fails(&full);
    let inputs = if preserved { ddmin(&full, fails) } else { full };
    InputReduction {
        inputs,
        violation_preserved: preserved,
    }
}
