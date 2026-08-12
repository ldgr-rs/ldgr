//! Lineage-Driven Fault Injection (LDFI) solver over causal provenance DAGs.

use crate::oracle::Verdict;
use ledger_format::{ActorId, EntryKind, Hash, Payload};
use ledger_journal::Journal;
use ledger_sim::FaultInjection;
use std::collections::{BTreeSet, HashSet};

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

/// Legacy compatibility alias.
pub type FaultCut = FaultableEvent;

/// Suggest ranked fault hypotheses using Horn derivation path analysis and minimum hitting sets.
pub fn solve_ldfi(journal: &Journal, verdict: &Verdict) -> Vec<FaultHypothesis> {
    if verdict.witnesses.is_empty() && journal.is_empty() {
        return Vec::new();
    }

    let mut all_paths: Vec<Vec<FaultableEvent>> = Vec::new();
    for witness in &verdict.witnesses {
        let mut current_path = Vec::new();
        collect_derivation_paths(journal, *witness, &mut current_path, &mut all_paths);
    }

    // Fall back to a heuristic cut when backward provenance has none.
    // Without derivation paths a hitting-set solution cannot be ranked; take
    // the highest-cost faultable event as a single non-trivial cut instead of
    // every faultable event, which would make any single event trivially
    // minimal.
    if all_paths.is_empty() {
        let mut fallback_events = Vec::new();
        for entry in journal.entries() {
            if is_faultable(entry.data.kind) {
                fallback_events.push(FaultableEvent {
                    event: entry.id,
                    kind: entry.data.kind,
                    cost: event_fault_cost(journal, &entry.id),
                });
            }
        }
        if let Some(highest) = fallback_events.iter().max_by_key(|event| event.cost) {
            all_paths.push(vec![highest.clone()]);
        }
    }

    if all_paths.is_empty() {
        return Vec::new();
    }

    let hitting_sets = compute_minimal_hitting_sets(&all_paths);
    let mut hypotheses: Vec<FaultHypothesis> = hitting_sets
        .into_iter()
        .map(|events_set| {
            let events: Vec<Hash> = events_set.into_iter().collect();
            let total_cost = events
                .iter()
                .map(|h| event_fault_cost(journal, h))
                .sum::<u64>();
            let explanation = format!(
                "Minimum hitting set cut with {} fault(s) breaking {} causal derivation path(s)",
                events.len(),
                all_paths.len()
            );
            FaultHypothesis {
                events,
                total_cost,
                explanation,
            }
        })
        .collect();

    hypotheses.sort_by_key(|h| (h.total_cost, h.events.len()));
    hypotheses
}

/// Legacy helper for single-event cuts.
pub fn suggest_cut(journal: &Journal, verdict: &Verdict) -> Vec<FaultableEvent> {
    let hypotheses = solve_ldfi(journal, verdict);
    let mut seen = HashSet::new();
    let mut cuts = Vec::new();

    for hyp in hypotheses {
        for event in hyp.events {
            if seen.insert(event) {
                let cost = event_fault_cost(journal, &event);
                let kind = journal
                    .get(&event)
                    .map(|e| e.data.kind)
                    .unwrap_or(EntryKind::Send);
                cuts.push(FaultableEvent { event, kind, cost });
            }
        }
    }
    cuts.sort_by_key(|c| c.cost);
    cuts
}

/// Convert an LDFI hypothesis cut into an executable fault schedule.
///
/// Recv and FsRead faults target the event they observe, not the observing
/// entry: a Recv faults the Send it observes, an FsRead faults the FsWrite it
/// observes. Every applicable injection class is emitted per event kind, so a
/// cut exercises Drop, Delay, Partition, Corrupt, and CrashState instead of
/// only two classes. A target id is injected at most once per schedule.
pub fn hypothesis_to_schedule(hyp: &FaultHypothesis, journal: &Journal) -> Vec<FaultInjection> {
    let mut schedule = Vec::new();
    let mut seen = HashSet::new();
    let mut seen_classes = HashSet::new();
    let push = |schedule: &mut Vec<FaultInjection>,
                seen_classes: &mut HashSet<(u8, Hash)>,
                injection: FaultInjection| {
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
                push(
                    &mut schedule,
                    &mut seen_classes,
                    FaultInjection::Drop(*event),
                );
                push(
                    &mut schedule,
                    &mut seen_classes,
                    FaultInjection::Delay {
                        send: *event,
                        ticks: 1,
                    },
                );
                if let Payload::Pair { left, .. } = &entry.data.payload {
                    push(
                        &mut schedule,
                        &mut seen_classes,
                        FaultInjection::Partition {
                            src: entry.data.actor,
                            dst: *left as ActorId,
                        },
                    );
                }
            }
            EntryKind::Recv => {
                if let Some(parent) = send_parent(entry.data.parents.as_slice(), journal) {
                    push(
                        &mut schedule,
                        &mut seen_classes,
                        FaultInjection::Drop(parent),
                    );
                    push(
                        &mut schedule,
                        &mut seen_classes,
                        FaultInjection::Delay {
                            send: parent,
                            ticks: 1,
                        },
                    );
                    if let Some(send_entry) = journal.get(&parent) {
                        push(
                            &mut schedule,
                            &mut seen_classes,
                            FaultInjection::Partition {
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
                    FaultInjection::Corrupt {
                        write: *event,
                        xor_mask: 1,
                    },
                );
                push(
                    &mut schedule,
                    &mut seen_classes,
                    FaultInjection::CrashState {
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
                        FaultInjection::Corrupt {
                            write: parent,
                            xor_mask: 1,
                        },
                    );
                    push(
                        &mut schedule,
                        &mut seen_classes,
                        FaultInjection::CrashState {
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
                    FaultInjection::Delay {
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
fn injection_key(injection: &FaultInjection) -> (u8, Hash) {
    match injection {
        FaultInjection::Drop(id) => (0, *id),
        FaultInjection::Delay { send, .. } => (1, *send),
        FaultInjection::Crash(id) => (2, *id),
        FaultInjection::Corrupt { write, .. } => (3, *write),
        FaultInjection::CrashState { write, .. } => (4, *write),
        FaultInjection::Partition { src, dst } => {
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

fn event_fault_cost(journal: &Journal, hash: &Hash) -> u64 {
    journal
        .get(hash)
        .map(|e| match e.data.kind {
            EntryKind::Send | EntryKind::Recv => 2,
            EntryKind::TimerFire | EntryKind::TimerSet => 3,
            EntryKind::FsRead | EntryKind::FsWrite => 4,
            _ => 5,
        })
        .unwrap_or(10)
}

fn is_faultable(kind: EntryKind) -> bool {
    matches!(
        kind,
        EntryKind::Send
            | EntryKind::Recv
            | EntryKind::FsRead
            | EntryKind::FsWrite
            | EntryKind::TimerFire
            | EntryKind::TimerSet
    )
}

fn collect_derivation_paths(
    journal: &Journal,
    current: Hash,
    current_path: &mut Vec<FaultableEvent>,
    paths: &mut Vec<Vec<FaultableEvent>>,
) {
    let Some(entry) = journal.get(&current) else {
        return;
    };

    let pushed = if is_faultable(entry.data.kind) {
        current_path.push(FaultableEvent {
            event: current,
            kind: entry.data.kind,
            cost: event_fault_cost(journal, &current),
        });
        true
    } else {
        false
    };

    if entry.data.parents.is_empty() {
        if !current_path.is_empty() {
            paths.push(current_path.clone());
        }
    } else {
        for parent in &entry.data.parents {
            collect_derivation_paths(journal, *parent, current_path, paths);
        }
    }

    if pushed {
        current_path.pop();
    }
}

fn compute_minimal_hitting_sets(paths: &[Vec<FaultableEvent>]) -> Vec<BTreeSet<Hash>> {
    let mut candidate_sets: Vec<BTreeSet<Hash>> = vec![BTreeSet::new()];

    for path in paths {
        let path_hashes: HashSet<Hash> = path.iter().map(|e| e.event).collect();
        let mut next_candidates: Vec<BTreeSet<Hash>> = Vec::new();

        for current in candidate_sets {
            if current.iter().any(|h| path_hashes.contains(h)) {
                next_candidates.push(current);
            } else {
                for &h in &path_hashes {
                    let mut expanded = current.clone();
                    expanded.insert(h);
                    next_candidates.push(expanded);
                }
            }
        }

        candidate_sets = prune_supersets(next_candidates);
    }

    candidate_sets
}

fn prune_supersets(sets: Vec<BTreeSet<Hash>>) -> Vec<BTreeSet<Hash>> {
    let mut minimal = Vec::new();
    for s in sets {
        let is_superset = minimal
            .iter()
            .any(|existing: &BTreeSet<Hash>| existing.is_subset(&s) && existing != &s);
        if !is_superset {
            minimal.retain(|existing: &BTreeSet<Hash>| !s.is_subset(existing));
            if !minimal.contains(&s) {
                minimal.push(s);
            }
        }
    }
    minimal
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_format::Payload;

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
                        Payload::Pair {
                            left: 2,
                            right: value,
                        },
                    )
                    .expect("append must succeed"),
            );
        }
        let outcome = journal
            .append(EntryKind::Outcome, 2, [], Payload::Number(0))
            .expect("append must succeed");

        let verdict = Verdict::fail(vec![outcome], "planted");
        let hypotheses = solve_ldfi(&journal, &verdict);
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
}
