//! Lineage-Driven Fault Injection (LDFI) solver over causal provenance DAGs.

use crate::oracle::Verdict;
use crate::solver::{FaultSolver, SolverError};
use ledger_format::{ActorId, EntryKind, EntryPayload, Hash};
use ledger_journal::Journal;
use ledger_sim::SimFault;
use std::collections::HashSet;

/// A single faultable boundary event.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FaultableEvent {
    pub event: Hash,
    pub kind: EntryKind,
    /// Cost weight for injecting this fault.
    pub cost: u64,
}

/// A candidate fault hypothesis (cut) that breaks derivation paths of an oracle outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultHypothesis {
    pub events: Vec<Hash>,
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
                seen_classes: &mut HashSet<(u8, Hash)>,
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
                            dst: *to as ActorId,
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
fn injection_key(injection: &SimFault) -> (u8, Hash) {
    match injection {
        SimFault::Drop(id) => (0, *id),
        SimFault::Delay { send, .. } => (1, *send),
        SimFault::Crash(id) => (2, *id),
        SimFault::Corrupt { write, .. } => (3, *write),
        SimFault::CrashState { write, .. } => (4, *write),
        SimFault::Partition { src, dst } => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&src.to_le_bytes());
            hasher.update(&dst.to_le_bytes());
            (5, *hasher.finalize().as_bytes())
        }
    }
}

/// The `Send` parent of an entry, if any.
///
/// A `Recv` observes a `Send`, but its parent list also carries block or
/// wake dependencies. Search the parents for the `Send` kind specifically.
fn send_parent(parents: &[Hash], journal: &Journal) -> Option<Hash> {
    parents.iter().copied().find(|parent| {
        journal
            .get(parent)
            .is_some_and(|entry| entry.data.kind == EntryKind::Send)
    })
}

fn fs_write_parent(parents: &[Hash], journal: &Journal) -> Option<Hash> {
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
    use ledger_format::CanonicalValue;
    #[test]
    fn fallback_cut_is_a_proper_subset_of_faultable_events() {
        // Faultable Sends on actor 1 and a witness outcome on actor 2 with no
        // faultable ancestors: backward provenance yields no paths, so the
        // fallback must rank a single high-cost event rather than every
        // faultable event.
        let mut journal = Journal::new();
        let mut sends = Vec::new();
        for value in 0..4u64 {
            sends.push(
                journal
                    .append(
                        EntryKind::Send,
                        1,
                        [],
                        EntryPayload::Send(ledger_format::SendFrame {
                            message_id: ledger_format::MessageId::new(1, 0),
                            from: 1,
                            to: 2,
                            original_content: value.to_le_bytes().to_vec(),
                        }),
                    )
                    .expect("append must succeed"),
            );
        }
        let outcome = journal
            .append(
                EntryKind::Outcome,
                2,
                [],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: [0x00; 32],
                    value: CanonicalValue::Unsigned(0),
                }),
            )
            .expect("append must succeed");

        let verdict = Verdict::fail(vec![outcome], "planted");
        let mut solver = HittingSetSolver::new();
        let hypotheses = solve_with(&mut solver, &journal, &verdict).expect("solve must succeed");
        assert!(
            !hypotheses.is_empty(),
            "the fallback must seed at least one hypothesis"
        );
        let cut = &hypotheses[0];
        assert!(!cut.events.is_empty());
        assert!(
            cut.events.len() < sends.len(),
            "the fallback cut must be a proper subset of the faultable events"
        );
        for id in &cut.events {
            assert!(
                sends.contains(id),
                "the cut must draw from the faultable events"
            );
        }
    }

    #[test]
    fn solve_with_trait_object_matches_concrete_solver() {
        let mut journal = Journal::new();
        let send = journal
            .append(
                EntryKind::Send,
                1,
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(1, 0),
                    from: 1,
                    to: 2,
                    original_content: 1u64.to_le_bytes().to_vec(),
                }),
            )
            .expect("append must succeed");
        let outcome = journal
            .append(
                EntryKind::Outcome,
                1,
                [send],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: [0x00; 32],
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
