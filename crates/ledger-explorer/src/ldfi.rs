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

/// Generic solver path. Errors propagate to the caller.
pub fn solve_with(
    solver: &mut dyn FaultSolver,
    journal: &Journal,
    verdict: &Verdict,
) -> Result<Vec<FaultHypothesis>, SolverError> {
    solver.solve(journal, verdict)
}

/// Hypothesis cut to executable schedule. Recv/FsRead fault the observed
/// write; every class per kind; each target once.
///
/// Sends with journaled duplicate evidence map to `Duplicate` alone: the
/// witness already shows the extra delivery, so re-injection is the most
/// specific reproduction. All other sends map to the Drop/Delay/Partition
/// triple exactly as before.
pub fn hypothesis_to_schedule(hyp: &FaultHypothesis, journal: &Journal) -> Vec<SimFault> {
    let mut schedule = Vec::new();
    let mut seen = HashSet::new();
    let mut seen_classes = HashSet::new();
    let duplicates = crate::lineage::duplicate_senders(journal);
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
                if duplicates.contains(event) {
                    push(
                        &mut schedule,
                        &mut seen_classes,
                        SimFault::Duplicate { send: *event },
                    );
                    continue;
                }
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
                    if duplicates.contains(&parent) {
                        push(
                            &mut schedule,
                            &mut seen_classes,
                            SimFault::Duplicate { send: parent },
                        );
                        continue;
                    }
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

/// Dedup key: class tag plus target (partitions hash the link).
fn injection_key(injection: &SimFault) -> (u8, EntryHash) {
    match injection {
        SimFault::Drop(id) => (0, *id),
        SimFault::Delay { send, .. } => (1, *send),
        SimFault::Crash(id) => (2, *id),
        SimFault::Corrupt { write, .. } => (3, *write),
        SimFault::CrashState { write, .. } => (4, *write),
        SimFault::Duplicate { send } => (6, *send),
        SimFault::Partition { src, dst } => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&src.0.to_le_bytes());
            hasher.update(&dst.0.to_le_bytes());
            (5, EntryHash(*hasher.finalize().as_bytes()))
        }
    }
}

/// `Send` parent of an entry, skipping block/wake parents.
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
        // Empty paths yield `Opaque`; solve and encode fail `EmptyProvenance`.
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

    fn duplicate_journal() -> (Journal, EntryHash) {
        let mut journal = Journal::new();
        let message_id = ledger_format::MessageId::new(ActorId(1), 0);
        let send = journal
            .append(
                EntryKind::Send,
                ActorId(1),
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id,
                    from: ActorId(1),
                    to: ActorId(2),
                    original_content: 7u64.to_le_bytes().to_vec(),
                }),
            )
            .expect("append must succeed");
        for _ in 0..2 {
            journal
                .append(
                    EntryKind::Recv,
                    ActorId(2),
                    [send],
                    EntryPayload::Recv(ledger_format::RecvFrame {
                        message_id,
                        from: ActorId(1),
                        to: ActorId(2),
                        observed_content: 7u64.to_le_bytes().to_vec(),
                    }),
                )
                .expect("append must succeed");
        }
        journal
            .append(
                EntryKind::Fault,
                ActorId(1),
                [send],
                EntryPayload::Fault(ledger_format::FaultPayload::DuplicateMessage {
                    message_id,
                    copy_ordinal: 1,
                }),
            )
            .expect("append must succeed");
        (journal, send)
    }

    #[test]
    fn duplicate_marked_send_maps_to_duplicate_only() {
        let (journal, send) = duplicate_journal();
        let hyp = FaultHypothesis {
            events: vec![send],
            total_cost: 2,
            explanation: String::new(),
        };
        assert_eq!(
            hypothesis_to_schedule(&hyp, &journal),
            vec![SimFault::Duplicate { send }]
        );
    }

    #[test]
    fn unmarked_send_maps_to_triple() {
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
                    original_content: 7u64.to_le_bytes().to_vec(),
                }),
            )
            .expect("append must succeed");
        let hyp = FaultHypothesis {
            events: vec![send],
            total_cost: 2,
            explanation: String::new(),
        };
        let schedule = hypothesis_to_schedule(&hyp, &journal);
        assert_eq!(schedule.len(), 3, "unmarked sends keep the triple");
        assert!(schedule.contains(&SimFault::Drop(send)));
    }

    #[test]
    fn duplicate_detector_ignores_mismatched_message() {
        let (mut journal, _) = duplicate_journal();
        journal
            .append(
                EntryKind::Fault,
                ActorId(1),
                [],
                EntryPayload::Fault(ledger_format::FaultPayload::DuplicateMessage {
                    message_id: ledger_format::MessageId::new(ActorId(9), 9),
                    copy_ordinal: 1,
                }),
            )
            .expect("append must succeed");
        let marked = crate::lineage::duplicate_senders(&journal);
        assert_eq!(marked.len(), 1, "only the matching send marks");
    }
}
