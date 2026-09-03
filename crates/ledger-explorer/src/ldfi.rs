//! Lineage-Driven Fault Injection (LDFI) solver over causal provenance DAGs.

use crate::oracle::Verdict;
use crate::solver::{FaultSolver, SolverError};
use ledger_format::{EntryHash, EntryKind, EntryPayload};
use ledger_journal::Journal;
use ledger_sim::SimFault;
use std::collections::HashSet;

/// A single faultable boundary event.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FaultableEvent {
    pub event: EntryHash,
    pub kind: EntryKind,
    /// Cost weight for injecting this fault.
    pub cost: u64,
}

/// A candidate fault hypothesis (cut) that breaks derivation paths of an oracle outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultHypothesis {
    pub events: Vec<EntryHash>,
    pub total_cost: u64,
    pub explanation: String,
}

/// Solve with an explicit [`FaultSolver`] implementation.
///
/// This is the generic path for call sites that need to inject a solver, for
/// example the CaDiCaL-backed [`crate::solver::MaxSatSolver`] behind the
/// `solver-cadical` feature. Unlike swallowing the result, the solver error
/// propagates to the caller.
pub fn solve_with(
    solver: &mut dyn FaultSolver,
    journal: &Journal,
    verdict: &Verdict,
) -> Result<Vec<FaultHypothesis>, SolverError> {
    solver.solve(journal, verdict)
}

/// Convert an LDFI hypothesis cut into an executable fault schedule.
///
/// Recv and FsRead faults target the event they observe, not the observing
/// entry: a Recv faults the Send it observes, an FsRead faults the FsWrite it
/// observes. Every applicable injection class is emitted per event kind, so a
/// cut exercises Drop, Delay, Partition, Corrupt, and CrashState instead of
/// only two classes. A target id is injected at most once per schedule.
pub fn hypothesis_to_schedule(hyp: &FaultHypothesis, journal: &Journal) -> Vec<SimFault> {
    let mut schedule = Vec::new();
    let mut seen = HashSet::new();
    let mut seen_classes = HashSet::new();
    let push = |schedule: &mut Vec<SimFault>,
                seen_classes: &mut HashSet<(u8, EntryHash)>,
                injection: SimFault| {
        let key = injection_key(&injection);
        if seen_classes.insert(key) {
            schedule.push(injection);
        }
    };
    for event in &hyp.events {
        if !seen.insert(*event) {
            continue;
        }
        let Some(entry) = journal.get(event) else {
            continue;
        };
        match entry.data.kind {
            EntryKind::Send => {
                push(&mut schedule, &mut seen_classes, SimFault::Drop(*event));
                push(
                    &mut schedule,
                    &mut seen_classes,
                    SimFault::Delay {
                        send: *event,
                        ticks: 1,
                    },
                );
                if let EntryPayload::Send(ledger_format::SendFrame { to, .. }) = &entry.data.payload
                {
                    push(
                        &mut schedule,
                        &mut seen_classes,
                        SimFault::Partition {
                            src: entry.data.actor,
                            dst: *to,
                        },
                    );
                }
            }
            EntryKind::Recv => {
                if let Some(parent) = send_parent(entry.data.parents.as_slice(), journal) {
                    push(&mut schedule, &mut seen_classes, SimFault::Drop(parent));
                    push(
                        &mut schedule,
                        &mut seen_classes,
                        SimFault::Delay {
                            send: parent,
                            ticks: 1,
                        },
                    );
                    if let Some(send_entry) = journal.get(&parent) {
                        push(
                            &mut schedule,
                            &mut seen_classes,
                            SimFault::Partition {
                                src: send_entry.data.actor,
                                dst: entry.data.actor,
                            },
                        );
                    }
                }
            }
            EntryKind::FsWrite => {
                push(
                    &mut schedule,
                    &mut seen_classes,
                    SimFault::Corrupt {
                        write: *event,
                        xor_mask: 1,
                    },
                );
                push(
                    &mut schedule,
                    &mut seen_classes,
                    SimFault::CrashState {
                        write: *event,
                        state: 0,
                    },
                );
            }
            EntryKind::FsRead => {
                if let Some(parent) = fs_write_parent(entry.data.parents.as_slice(), journal) {
                    push(
                        &mut schedule,
                        &mut seen_classes,
                        SimFault::Corrupt {
                            write: parent,
                            xor_mask: 1,
                        },
                    );
                    push(
                        &mut schedule,
                        &mut seen_classes,
                        SimFault::CrashState {
                            write: parent,
                            state: 0,
                        },
                    );
                }
            }
            EntryKind::TimerFire => {
                push(
                    &mut schedule,
                    &mut seen_classes,
                    SimFault::Delay {
                        send: *event,
                        ticks: 1,
                    },
                );
            }
            _ => {}
        }
    }
    schedule
}

/// The dedup key for one injection: its class tag plus its target.
///
/// Entry-targeted injections key on the entry id; a partition keys on the
/// directed link. The class tag keeps distinct injection classes for the same
/// target (drop, delay, partition, corrupt, crash-state) all executable.
fn injection_key(injection: &SimFault) -> (u8, EntryHash) {
    match injection {
        SimFault::Drop(id) => (0, *id),
        SimFault::Delay { send, .. } => (1, *send),
        SimFault::Crash(id) => (2, *id),
        SimFault::Corrupt { write, .. } => (3, *write),
        SimFault::CrashState { write, .. } => (4, *write),
        SimFault::Partition { src, dst } => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&src.0.to_le_bytes());
            hasher.update(&dst.0.to_le_bytes());
            (5, EntryHash(*hasher.finalize().as_bytes()))
        }
    }
}

/// The `Send` parent of an entry, if any.
///
/// A `Recv` observes a `Send`, but its parent list also carries block or
/// wake dependencies. Search the parents for the `Send` kind specifically.
fn send_parent(parents: &[EntryHash], journal: &Journal) -> Option<EntryHash> {
    parents.iter().copied().find(|parent| {
        journal
            .get(parent)
            .is_some_and(|entry| entry.data.kind == EntryKind::Send)
    })
}

fn fs_write_parent(parents: &[EntryHash], journal: &Journal) -> Option<EntryHash> {
    parents.iter().copied().find(|parent| {
        journal
            .get(parent)
            .is_some_and(|entry| entry.data.kind == EntryKind::FsWrite)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solver::HittingSetSolver;
    use ledger_format::ActorId;
    use ledger_format::CanonicalValue;
    #[test]
    fn empty_provenance_fails_closed_with_typed_error() {
        // Faultable Sends on actor 1 and a witness outcome on actor 2 with no
        // faultable ancestors: backward provenance yields no paths. The typed
        // hazard walk must fail closed with `EmptyProvenance` instead of
        // ranking an unrelated single max-cost event. The support for an
        // empty path set is `Opaque`, so no minimum claim is possible.
        use crate::solver::SolverError;
        use crate::support::{SupportExpr, support_from_paths};
        let mut journal = Journal::new();
        for value in 0..4u64 {
            journal
                .append(
                    EntryKind::Send,
                    ActorId(1),
                    [],
                    EntryPayload::Send(ledger_format::SendFrame {
                        message_id: ledger_format::MessageId::new(ActorId(1), 0),
                        from: ActorId(1),
                        to: ActorId(2),
                        original_content: value.to_le_bytes().to_vec(),
                    }),
                )
                .expect("append must succeed");
        }
        let outcome = journal
            .append(
                EntryKind::Outcome,
                ActorId(2),
                [],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: EntryHash([0x00; 32]),
                    value: CanonicalValue::Unsigned(0),
                }),
            )
            .expect("append must succeed");

        let verdict = Verdict::fail(vec![outcome], "planted");
        let empty: Vec<Vec<ledger_format::EntryHash>> = Vec::new();
        let support = support_from_paths(&empty, false);
        assert_eq!(support, SupportExpr::Opaque);
        assert!(
            !support.is_strong(),
            "empty provenance cannot back a minimum claim"
        );
        let mut solver = HittingSetSolver::new();
        let error = solve_with(&mut solver, &journal, &verdict).expect_err("solve must fail");
        assert_eq!(error, SolverError::EmptyProvenance);
        // The MaxSAT encoding fails the same way: no hard clause exists.
        let config = crate::solver::SolverConfig::default();
        let encode_error = crate::maxsat::encode_hazard(&journal, &verdict, &config)
            .expect_err("encode must fail");
        assert_eq!(encode_error, SolverError::EmptyProvenance);
    }

    #[test]
    fn solve_with_trait_object_matches_concrete_solver() {
        let mut journal = Journal::new();
        let send = journal
            .append(
                EntryKind::Send,
                ActorId(1),
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(ActorId(1), 0),
                    from: ActorId(1),
                    to: ActorId(2),
                    original_content: 1u64.to_le_bytes().to_vec(),
                }),
            )
            .expect("append must succeed");
        let outcome = journal
            .append(
                EntryKind::Outcome,
                ActorId(1),
                [send],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: EntryHash([0x00; 32]),
                    value: CanonicalValue::Unsigned(0),
                }),
            )
            .expect("append must succeed");
        let verdict = Verdict::fail(vec![outcome], "trait check");

        let mut boxed: Box<dyn FaultSolver> = Box::new(HittingSetSolver::new());
        let via_trait = solve_with(boxed.as_mut(), &journal, &verdict).expect("trait must succeed");
        let mut concrete = HittingSetSolver::new();
        let direct = concrete
            .solve(&journal, &verdict)
            .expect("concrete must succeed");
        assert_eq!(via_trait, direct);
    }
}
