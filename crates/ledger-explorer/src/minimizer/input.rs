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

/// Input-delta debugging over the journal's exact violating input. Replays
/// under the finding's schedule; never errors on irreducible input.
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

/// Input reduction under a pinned fault schedule, for joint plants.
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
