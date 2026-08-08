//! Seeded campaign search and replay comparison.

use crate::config::{Policy, RunConfig};
use crate::oracle::{Oracle, Verdict, first_divergence};
use crate::runtime::{Instruction, RunResult, Simulation};

/// A workload that can be executed by the prototype simulator.
pub trait Workload {
    /// Build task programs for a run.
    fn programs(&self) -> Vec<Vec<Instruction>>;
}

/// One violating campaign result.
#[derive(Debug)]
pub struct Finding {
    /// Root seed that found the violation.
    pub seed: [u8; 32],
    /// Completed run.
    pub run: RunResult,
    /// Oracle verdict.
    pub verdict: Verdict,
}

/// Search deterministic seeds until an oracle fails.
pub fn search<W: Workload, O: Oracle>(
    workload: &W,
    oracle: &O,
    base: RunConfig,
    attempts: usize,
) -> Result<Option<Finding>, String> {
    for attempt in 0..attempts {
        let mut config = base.clone();
        config.seed[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());
        let run = Simulation::new(config.clone(), workload.programs())
            .run()
            .map_err(|error| format!("simulation failed: {error:?}"))?;
        let verdict = oracle.check(&run.journal);
        if verdict.violated {
            return Ok(Some(Finding {
                seed: config.seed,
                run,
                verdict,
            }));
        }
    }
    Ok(None)
}

/// Replay one workload under a recorded scheduling policy.
pub fn replay<W: Workload>(
    workload: &W,
    seed: [u8; 32],
    decisions: Vec<usize>,
) -> Result<RunResult, String> {
    let mut config = RunConfig {
        seed,
        policy: Policy::Replay,
        ..RunConfig::default()
    };
    config.max_steps = decisions.len().saturating_add(10);
    Simulation::with_replay(config, workload.programs(), decisions)
        .run()
        .map_err(|error| format!("replay failed: {error}"))
}

/// Return the first divergence between two runs.
pub fn diff(left: &RunResult, right: &RunResult) -> Option<([u8; 32], [u8; 32])> {
    first_divergence(&left.journal, &right.journal).map(|(left, right)| {
        (
            left.map_or([0; 32], |entry| entry.id),
            right.map_or([0; 32], |entry| entry.id),
        )
    })
}
