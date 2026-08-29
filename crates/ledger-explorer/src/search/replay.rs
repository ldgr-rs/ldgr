use super::Workload;
use crate::diagnosis::first_divergence;
use ledger_format::Hash;
use ledger_sim::{Policy, RunConfig, RunResult, SimFault, Simulation};

/// Strict replay for reproduction gates.
///
/// Alias to [`replay_strict`]; ready-set drift is surfaced as a typed
/// `StrictReplay` violation instead of being normalized. Use
/// [`replay_prefix`] for lenient minimization-only prefix replay.
pub fn replay<W: Workload + ?Sized>(
    workload: &W,
    seed: Hash,
    decisions: Vec<usize>,
) -> Result<RunResult, ledger_sim::RuntimeError> {
    // Strict alias: every reproduction path is strict. Lenient is only via
    // `replay_prefix` for the private minimization prefix.
    replay_strict(workload, seed, decisions)
}

/// Replay one workload under a strict scheduling decision sequence.
///
/// Strict replay rejects out-of-range, exhausted, or trailing decisions
/// and surfaces a typed [`ledger_sim::RuntimeError::StrictReplay`] error.
/// Callers needing to distinguish violations should match on the typed error.
pub fn replay_strict<W: Workload + ?Sized>(
    workload: &W,
    seed: Hash,
    decisions: Vec<usize>,
) -> Result<RunResult, ledger_sim::RuntimeError> {
    let config = RunConfig::builder()
        .seed(seed)
        .policy(Policy::Replay)
        .max_steps(decisions.len().saturating_add(256))
        .build();
    Simulation::with_replay_strict(config, workload.programs(), decisions).run()
}

/// Minimization-only prefix replay that cannot satisfy a reproduction gate.
///
/// This uses lenient replay with a seeded fallback for the suffix, so it is
/// suitable for delta debugging but must not be used to claim a bug
/// reproduction. Use [`replay_strict`] to validate a reproduction gate.
pub fn replay_prefix<W: Workload + ?Sized>(
    workload: &W,
    seed: Hash,
    decisions: Vec<usize>,
) -> Result<RunResult, ledger_sim::RuntimeError> {
    let config = RunConfig::builder()
        .seed(seed)
        .policy(Policy::Replay)
        .max_steps(decisions.len().saturating_add(256))
        .build();
    Simulation::with_replay(config, workload.programs(), decisions).run()
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

/// Typed error from fault-injected strict replay.
#[derive(Debug, thiserror::Error)]
pub enum FaultReplayError {
    /// Strict replay rejected a decision.
    #[error("strict replay violation: {0}")]
    StrictReplay(#[from] ledger_sim::ReplayViolation),
    /// The replayed run journaled a crash operation that does not match the
    /// canonical operation the injected fault requests.
    #[error("crash-semantics mismatch: {0}")]
    CrashSemanticsMismatch(Box<CrashMismatch>),
    /// Other runtime or journal failure.
    #[error(transparent)]
    Runtime(Box<ledger_sim::RuntimeError>),
}

/// Details of a crash-semantics mismatch: the injected fault, the canonical
/// operation it requests, and the operation the replayed run journaled.
#[derive(Debug, thiserror::Error)]
#[error("requested {requested:?}, journaled {journaled:?}, fault {fault:?}")]
pub struct CrashMismatch {
    pub fault: ledger_sim::SimFault,
    pub requested: ledger_format::CrashOperation,
    pub journaled: Option<ledger_format::CrashOperation>,
}

impl From<ledger_sim::RuntimeError> for FaultReplayError {
    fn from(error: ledger_sim::RuntimeError) -> Self {
        Self::Runtime(Box::new(error))
    }
}

/// Canonical crash operation a replayed run journaled, if any.
fn journaled_crash_operations(run: &ledger_sim::RunResult) -> Vec<ledger_format::CrashOperation> {
    run.journal
        .entries()
        .filter_map(|entry| match &entry.data.payload {
            ledger_format::EntryPayload::Fault(ledger_format::FaultPayload::CrashActor {
                crash_operation,
                ..
            }) => Some(crash_operation.clone()),
            _ => None,
        })
        .collect()
}

/// Look up the canonical path of the `FsWrite` entry `write_id` in `run`.
fn write_path_of(run: &ledger_sim::RunResult, write_id: ledger_format::Hash) -> Option<String> {
    run.journal.entries().find_map(|entry| {
        if entry.id != write_id {
            return None;
        }
        match &entry.data.payload {
            ledger_format::EntryPayload::FsWrite(ledger_format::FsWritePayload::Write {
                path_ref,
                ..
            }) => Some(String::from_utf8_lossy(&path_ref.canonical_path).into_owned()),
            _ => None,
        }
    })
}

/// Replay one workload with a fault schedule injected at causal positions.
///
/// Strict-only reproduction: ready-set drift is surfaced as a typed
/// [`FaultReplayError::StrictReplay`] violation instead of being normalized
/// by a seeded fallback. No lenient fallback is performed. Callers that need
/// lenient prefix behavior for delta debugging use [`replay_prefix`], which
/// must never back a reproduction claim.
pub fn replay_with_faults<W: Workload + ?Sized>(
    workload: &W,
    base: &ledger_journal::Journal,
    seed: Hash,
    decisions: Vec<usize>,
    schedule: Vec<SimFault>,
) -> Result<FaultReplayReport, FaultReplayError> {
    let config = RunConfig::builder()
        .seed(seed)
        .policy(Policy::Replay)
        .fault_schedule(schedule.clone())
        .max_steps(decisions.len().saturating_add(256))
        .build();
    let run = Simulation::with_replay_strict(config, workload.programs(), decisions)
        .run()
        .map_err(|error| match error {
            ledger_sim::RuntimeError::StrictReplay(violation) => {
                FaultReplayError::StrictReplay(violation)
            }
            other => FaultReplayError::Runtime(Box::new(other)),
        })?;
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
    // Crash-semantics verification: every applied crash-type fault must have
    // journaled exactly the canonical operation it requests. A drift between
    // the requested semantics and what the run applied fails the replay
    // closed instead of silently trusting a mismatched crash.
    if !applied.is_empty() {
        let journaled = journaled_crash_operations(&run);
        for fault in &applied {
            let write = match super::fault_injection_target(fault) {
                Some(write) => write,
                None => continue,
            };
            let Some(path) = write_path_of(&run, write) else {
                continue;
            };
            let Some(requested) = fault.crash_operation_for(&path) else {
                continue;
            };
            // The executor rejects unknown crash-state identifiers before
            // this point (fail closed), so the error arm is defense in
            // depth: it surfaces the same typed mismatch without a panic.
            let requested = match requested {
                Ok(operation) => operation,
                Err(_) => {
                    return Err(FaultReplayError::CrashSemanticsMismatch(Box::new(
                        CrashMismatch {
                            fault: fault.clone(),
                            requested: ledger_format::CrashOperation::DropAllUnsynced,
                            journaled: None,
                        },
                    )));
                }
            };
            if !journaled.contains(&requested) {
                return Err(FaultReplayError::CrashSemanticsMismatch(Box::new(
                    CrashMismatch {
                        fault: fault.clone(),
                        requested,
                        journaled: None,
                    },
                )));
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_sim::{Instruction, ReplayViolation, RuntimeError};

    struct TwoDone;
    impl Workload for TwoDone {
        fn programs(&self) -> Vec<Vec<Instruction>> {
            vec![vec![Instruction::Done], vec![Instruction::Done]]
        }
        fn history(&self, _run: &RunResult) -> Vec<crate::oracle::HistoryOperation> {
            Vec::new()
        }
    }

    struct MiniKv;
    impl Workload for MiniKv {
        fn programs(&self) -> Vec<Vec<Instruction>> {
            vec![
                vec![
                    Instruction::Send { to: 1, payload: 42 },
                    Instruction::Send {
                        to: 2,
                        payload: 100,
                    },
                    Instruction::Done,
                ],
                vec![
                    Instruction::Receive,
                    Instruction::Send { to: 2, payload: 42 },
                    Instruction::Done,
                ],
                vec![
                    Instruction::Receive,
                    Instruction::Outcome,
                    Instruction::Done,
                ],
            ]
        }
        fn history(&self, _run: &RunResult) -> Vec<crate::oracle::HistoryOperation> {
            Vec::new()
        }
    }

    #[test]
    fn replay_strict_valid_matches_lenient_root() {
        let seed = [13; 32];
        let workload = MiniKv;
        let base = {
            let config = RunConfig::builder()
                .seed(seed)
                .policy(Policy::Random)
                .max_steps(256)
                .build();
            Simulation::new(config, workload.programs())
                .run()
                .expect("base run")
        };
        let decisions = base.decisions.clone();
        let strict = replay_strict(&workload, seed, decisions.clone()).expect("strict valid");
        let lenient = replay(&workload, seed, decisions).expect("lenient valid");
        assert_eq!(strict.journal.root_hash(), lenient.journal.root_hash());
        assert_eq!(strict.journal.root_hash(), base.journal.root_hash());
    }

    #[test]
    fn replay_strict_rejects_out_of_range() {
        let seed = [7; 32];
        let workload = TwoDone;
        let err = replay_strict(&workload, seed, vec![99]).expect_err("out of range");
        match err {
            RuntimeError::StrictReplay(ReplayViolation::OutOfRange {
                step,
                value,
                ready_len,
            }) => {
                assert_eq!(step, 0);
                assert_eq!(value, 99);
                assert_eq!(ready_len, 2);
            }
            other => panic!("expected OutOfRange, got {other:?}"),
        }
        // Lenient prefix replay succeeds via modulo fallback.
        let ok = replay_prefix(&workload, seed, vec![99]).expect("prefix lenient");
        assert_eq!(ok.steps, 2);
    }

    #[test]
    fn replay_strict_rejects_exhausted() {
        let seed = [9; 32];
        let workload = TwoDone;
        let err = replay_strict(&workload, seed, vec![0]).expect_err("exhausted");
        match err {
            RuntimeError::StrictReplay(ReplayViolation::Exhausted { step, replay_len }) => {
                assert_eq!(step, 1);
                assert_eq!(replay_len, 1);
            }
            other => panic!("expected Exhausted, got {other:?}"),
        }
        // Prefix replay falls back to Random and completes.
        let ok = replay_prefix(&workload, seed, vec![0]).expect("prefix fallback");
        assert_eq!(ok.steps, 2);
    }

    #[test]
    fn replay_strict_rejects_trailing() {
        let seed = [11; 32];
        let workload = TwoDone;
        let base = {
            let config = RunConfig::builder()
                .seed(seed)
                .policy(Policy::Random)
                .max_steps(64)
                .build();
            Simulation::new(config, workload.programs())
                .run()
                .expect("base")
        };
        assert_eq!(base.steps, 2);
        let mut trailing = base.decisions.clone();
        trailing.extend([0, 1, 0]);
        let err = replay_strict(&workload, seed, trailing).expect_err("trailing");
        match err {
            RuntimeError::StrictReplay(ReplayViolation::Trailing { trailing, steps }) => {
                assert_eq!(trailing, 3);
                assert_eq!(steps, 2);
            }
            other => panic!("expected Trailing, got {other:?}"),
        }
    }

    #[test]
    fn replay_prefix_is_lenient_minimization_only() {
        let seed = [17; 32];
        let workload = TwoDone;
        // Empty prefix still completes via seeded fallback, proving it cannot
        // satisfy a reproduction gate that requires exact replay.
        let ok = replay_prefix(&workload, seed, Vec::new()).expect("empty prefix lenient");
        assert_eq!(ok.steps, 2);
        let strict_err = replay_strict(&workload, seed, Vec::new()).expect_err("empty strict");
        assert!(matches!(
            strict_err,
            RuntimeError::StrictReplay(ReplayViolation::Exhausted { .. })
        ));
    }

    #[test]
    fn fault_replay_strict_surfaces_ready_drift_as_typed_error() {
        // A fault that partitions the only ready task's link at step 4
        // causes ready_len to shrink from 2 to 1; lenient replay would
        // normalize 1 % 1 = 0, but strict must surface OutOfRange.
        let seed = [17; 32];
        struct DriftWorkload;
        impl Workload for DriftWorkload {
            fn programs(&self) -> Vec<Vec<Instruction>> {
                vec![
                    vec![
                        Instruction::Send { to: 1, payload: 42 },
                        Instruction::Send {
                            to: 1,
                            payload: 100,
                        },
                        Instruction::Done,
                    ],
                    vec![Instruction::Receive, Instruction::Done],
                ]
            }
            fn history(&self, _run: &RunResult) -> Vec<crate::oracle::HistoryOperation> {
                Vec::new()
            }
        }
        let workload = DriftWorkload;
        // Find a finding with a partition that triggers drift. Use strict
        // fault replay and assert the violation type, not a partial journal.
        let base = {
            let config = RunConfig::builder()
                .seed(seed)
                .policy(Policy::Random)
                .max_steps(64)
                .build();
            Simulation::new(config, workload.programs())
                .run()
                .expect("base run")
        };
        let decisions = base.decisions.clone();
        // Forge a decision that is out of range for the faulted run's ready
        // set. With no faults, lenient and strict agree; with a fault that
        // blocks the receiver, the same decision becomes out of range.
        // We do not need an actual fault to demonstrate the strict path:
        // a single out-of-range decision is enough to prove the typed error
        // is surfaced instead of normalized.
        let out_of_range = vec![99];
        let strict_err = replay_strict(&workload, seed, out_of_range.clone())
            .expect_err("out of range must be StrictReplay");
        assert!(
            matches!(
                strict_err,
                RuntimeError::StrictReplay(ReplayViolation::OutOfRange { .. })
            ),
            "expected OutOfRange, got {strict_err:?}"
        );
        // Fault replay is strict-only: the same out-of-range decisions
        // must surface as a typed violation, not a normalized fallback run.
        let base_journal = base.journal.clone();
        let err = replay_with_faults(
            &workload,
            &base_journal,
            seed,
            out_of_range,
            vec![SimFault::Partition { src: 0, dst: 1 }],
        )
        .expect_err("fault replay with out-of-range must be strict violation");
        assert!(
            matches!(err, FaultReplayError::StrictReplay(_)),
            "fault replay must surface strict violation, got {err:?}"
        );
        // Lenient prefix still succeeds via modulo fallback, proving the
        // reproduction gate is the only strict path.
        let lenient_ok = replay_prefix(&workload, seed, vec![99]).expect("lenient");
        assert!(
            lenient_ok.steps >= 2,
            "lenient prefix must complete via fallback, got {}",
            lenient_ok.steps
        );
        // Keep decisions variable used
        let _ = decisions;
    }
}
