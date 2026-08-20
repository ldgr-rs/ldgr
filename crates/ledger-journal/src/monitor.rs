//! Journal correctness monitor: coverage, parent fidelity, vector-clock
//! recomputation, and replay determinism.
//!
//! The monitor runs on every sim run and forked replay. It checks per-actor
//! monotonic sequence, parent resolution, observed-value parent fidelity, and
//! re-derives each entry's vector clock from its parents, so the journal is
//! self-verifying without re-execution.

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;
use hashbrown::HashMap;

use crate::clock::VectorClock;
use crate::dag::{Journal, JournalError};
use ledger_format::{ActorId, EntryKind, Hash};

/// A correctness defect found while auditing a journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MonitorIssue {
    /// A per-actor sequence number is not monotonic.
    NonMonotonicSequence {
        /// The offending actor.
        actor: ActorId,
        /// The expected next sequence value.
        expected: u64,
        /// The observed sequence value.
        actual: u64,
    },
    /// An entry references a parent that is not present in the journal.
    MissingParent {
        /// The entry with the dangling reference.
        entry_id: Hash,
        /// The absent parent hash.
        parent: Hash,
    },
    /// An observed-value entry lacks a parent of the required kind.
    ParentKindMismatch {
        /// The entry whose parents were checked.
        entry_id: Hash,
        /// The kind of parent the entry requires.
        expected_kind: &'static str,
        /// The kind of the nearest non-matching parent.
        actual_kind: &'static str,
    },
    /// The stored vector clock does not equal the recomputed clock.
    VectorClockMismatch {
        /// The entry whose clock is wrong.
        entry_id: Hash,
        /// The clock re-derived from the parents.
        expected: VectorClock,
        /// The clock stored in the entry.
        actual: VectorClock,
    },
    /// A forked replay diverged from the original at a position.
    ReplayDivergence {
        /// Index of the first divergent entry in the entry stream.
        position: usize,
    },
    /// A cross-boundary effect was not journaled exactly once.
    ///
    /// The journal must hold exactly as many entries per actor as the effect
    /// boundary reported. A shortfall means an effect leaked past the
    /// boundary; a surplus means entries were written outside it.
    CoverageMismatch {
        /// The actor whose coverage counts disagree.
        actor: ActorId,
        /// Entries the effect boundary reported journaling for the actor.
        boundary_entries: u64,
        /// Entries actually present in the journal for the actor.
        journal_entries: u64,
    },
}

/// Verification report produced by the journal correctness monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    /// Total entries audited.
    pub entries_audited: usize,
    /// Distinct actors verified.
    pub actors_count: usize,
    /// Root DAG hash.
    pub root_hash: Hash,
}

/// Monitor that verifies structural integrity and causal fidelity of a Journal.
#[derive(Debug, Default)]
pub struct JournalCorrectnessMonitor;

impl JournalCorrectnessMonitor {
    /// Audit a journal DAG and return every defect found.
    ///
    /// No re-execution is needed; every check is derived from the journal
    /// itself.
    pub fn audit(journal: &Journal) -> Vec<MonitorIssue> {
        let mut issues = Vec::new();
        let mut actor_seqs: HashMap<ActorId, u64> = HashMap::new();

        for entry in journal.entries() {
            let expected = actor_seqs.get(&entry.data.actor).copied().unwrap_or(0);
            if entry.data.sequence != expected {
                issues.push(MonitorIssue::NonMonotonicSequence {
                    actor: entry.data.actor,
                    expected,
                    actual: entry.data.sequence,
                });
            }
            actor_seqs.insert(entry.data.actor, expected + 1);

            let mut clock = VectorClock::default();
            let mut parents_resolvable = true;
            for parent in &entry.data.parents {
                match journal.get(parent) {
                    Some(parent_entry) => {
                        clock = clock.merge(&parent_entry.vector_clock);
                    }
                    None => {
                        parents_resolvable = false;
                        issues.push(MonitorIssue::MissingParent {
                            entry_id: entry.id,
                            parent: *parent,
                        });
                    }
                }
            }
            check_parent_kind(entry, journal, &mut issues);

            // Vector-clock recomputation: max(parents) plus the actor's own
            // increment.
            if parents_resolvable {
                let expected_clock = clock.incremented(entry.data.actor);
                if expected_clock != entry.vector_clock {
                    issues.push(MonitorIssue::VectorClockMismatch {
                        entry_id: entry.id,
                        expected: expected_clock,
                        actual: entry.vector_clock.clone(),
                    });
                }
            }
        }

        issues.sort_by(cmp_issue);
        issues
    }

    /// Audit a journal DAG for complete causal integrity.
    ///
    /// Returns the first defect as a [`JournalError`]; use [`Self::audit`]
    /// to collect every defect.
    pub fn verify(journal: &Journal) -> Result<VerificationReport, JournalError> {
        let issues = Self::audit(journal);
        if let Some(issue) = issues.first() {
            return Err(issue_to_error(issue));
        }
        let mut actors = HashMap::new();
        for entry in journal.entries() {
            actors.insert(entry.data.actor, ());
        }
        Ok(VerificationReport {
            entries_audited: journal.len(),
            actors_count: actors.len(),
            root_hash: journal.root_hash(),
        })
    }

    /// Verify that a forked replay's entry stream matches the original.
    ///
    /// Returns `Err` with a single [`MonitorIssue::ReplayDivergence`] at the
    /// first differing index.
    pub fn verify_replay_fidelity(
        original: &Journal,
        fork: &Journal,
    ) -> Result<(), Vec<MonitorIssue>> {
        let mut original_ids = original.entries().map(|entry| entry.id);
        let mut fork_ids = fork.entries().map(|entry| entry.id);
        let mut position = 0usize;
        loop {
            match (original_ids.next(), fork_ids.next()) {
                (Some(left), Some(right)) if left == right => {
                    position += 1;
                }
                (Some(_), Some(_)) | (None, Some(_)) | (Some(_), None) => {
                    return Err(vec![MonitorIssue::ReplayDivergence { position }]);
                }
                (None, None) => return Ok(()),
            }
        }
    }

    /// Verify boundary coverage: every cross-boundary effect produces exactly
    /// one journal entry.
    ///
    /// Compares each actor's reported boundary count against the entries
    /// present in the journal and returns a [`MonitorIssue::CoverageMismatch`]
    /// per disagreement.
    pub fn check_coverage(
        journal: &Journal,
        boundary_entries: &[(ActorId, u64)],
    ) -> Vec<MonitorIssue> {
        let mut journal_counts: HashMap<ActorId, u64> = HashMap::new();
        for entry in journal.entries() {
            *journal_counts.entry(entry.data.actor).or_insert(0) += 1;
        }
        let reported: HashMap<ActorId, u64> = boundary_entries.iter().copied().collect();

        let mut issues: Vec<MonitorIssue> = reported
            .iter()
            .filter_map(|(actor, reported_count)| {
                let actual = journal_counts.get(actor).copied().unwrap_or(0);
                if *reported_count == actual {
                    None
                } else {
                    Some(MonitorIssue::CoverageMismatch {
                        actor: *actor,
                        boundary_entries: *reported_count,
                        journal_entries: actual,
                    })
                }
            })
            .collect();

        for (actor, actual) in journal_counts {
            if !reported.contains_key(&actor) {
                issues.push(MonitorIssue::CoverageMismatch {
                    actor,
                    boundary_entries: 0,
                    journal_entries: actual,
                });
            }
        }

        issues.sort_by(cmp_issue);
        issues
    }
}

/// Check observed-value parent fidelity for `Recv`, `FsRead`, and `Wake`.
fn check_parent_kind(entry: &crate::dag::Entry, journal: &Journal, issues: &mut Vec<MonitorIssue>) {
    let expected = match entry.data.kind {
        EntryKind::Recv => Some("Send"),
        EntryKind::FsRead => Some("FsWrite"),
        EntryKind::Wake => Some("enabler"),
        _ => None,
    };
    let Some(expected) = expected else {
        return;
    };

    let mut actual_kind = "none";
    let mut matched = false;
    for parent in &entry.data.parents {
        let Some(parent_entry) = journal.get(parent) else {
            continue;
        };
        actual_kind = kind_name(parent_entry.data.kind);
        let is_enabler = matches!(
            parent_entry.data.kind,
            EntryKind::Send
                | EntryKind::Recv
                | EntryKind::FsWrite
                | EntryKind::FsFsync
                | EntryKind::TimerFire
        );
        let ok = match expected {
            "Send" => matches!(parent_entry.data.kind, EntryKind::Send),
            "FsWrite" => matches!(parent_entry.data.kind, EntryKind::FsWrite),
            _ => is_enabler,
        };
        if ok {
            matched = true;
            break;
        }
    }
    if !matched {
        issues.push(MonitorIssue::ParentKindMismatch {
            entry_id: entry.id,
            expected_kind: expected,
            actual_kind,
        });
    }
}

/// Total order over issues: variant tag first, then each variant's fields.
///
/// Sorting with this comparator removes HashMap iteration-order dependence
/// from emitted issue vectors.
fn cmp_issue(left: &MonitorIssue, right: &MonitorIssue) -> Ordering {
    fn tag(issue: &MonitorIssue) -> u8 {
        match issue {
            MonitorIssue::NonMonotonicSequence { .. } => 0,
            MonitorIssue::MissingParent { .. } => 1,
            MonitorIssue::ParentKindMismatch { .. } => 2,
            MonitorIssue::VectorClockMismatch { .. } => 3,
            MonitorIssue::ReplayDivergence { .. } => 4,
            MonitorIssue::CoverageMismatch { .. } => 5,
        }
    }
    tag(left)
        .cmp(&tag(right))
        .then_with(|| match (left, right) {
            (
                MonitorIssue::NonMonotonicSequence {
                    actor,
                    expected,
                    actual,
                },
                MonitorIssue::NonMonotonicSequence {
                    actor: other_actor,
                    expected: other_expected,
                    actual: other_actual,
                },
            ) => actor
                .cmp(other_actor)
                .then(expected.cmp(other_expected))
                .then(actual.cmp(other_actual)),
            (
                MonitorIssue::MissingParent { entry_id, parent },
                MonitorIssue::MissingParent {
                    entry_id: other_entry,
                    parent: other_parent,
                },
            ) => entry_id.cmp(other_entry).then(parent.cmp(other_parent)),
            (
                MonitorIssue::ParentKindMismatch {
                    entry_id,
                    expected_kind,
                    actual_kind,
                },
                MonitorIssue::ParentKindMismatch {
                    entry_id: other_entry,
                    expected_kind: other_expected,
                    actual_kind: other_actual,
                },
            ) => entry_id
                .cmp(other_entry)
                .then(expected_kind.cmp(other_expected))
                .then(actual_kind.cmp(other_actual)),
            (
                MonitorIssue::VectorClockMismatch {
                    entry_id,
                    expected,
                    actual,
                },
                MonitorIssue::VectorClockMismatch {
                    entry_id: other_entry,
                    expected: other_expected,
                    actual: other_actual,
                },
            ) => entry_id
                .cmp(other_entry)
                .then(cmp_clock(expected, other_expected))
                .then(cmp_clock(actual, other_actual)),
            (
                MonitorIssue::ReplayDivergence { position },
                MonitorIssue::ReplayDivergence {
                    position: other_position,
                },
            ) => position.cmp(other_position),
            (
                MonitorIssue::CoverageMismatch {
                    actor,
                    boundary_entries,
                    journal_entries,
                },
                MonitorIssue::CoverageMismatch {
                    actor: other_actor,
                    boundary_entries: other_boundary,
                    journal_entries: other_journal,
                },
            ) => actor
                .cmp(other_actor)
                .then(boundary_entries.cmp(other_boundary))
                .then(journal_entries.cmp(other_journal)),
            _ => Ordering::Equal,
        })
}

/// Compare two vector clocks by their canonical (actor, value) pair sequences
/// in ascending actor order.
fn cmp_clock(left: &VectorClock, right: &VectorClock) -> Ordering {
    left.iter().cmp(right.iter())
}

/// Map a kind to a stable display name for issue reporting.
fn kind_name(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Spawn => "Spawn",
        EntryKind::Block => "Block",
        EntryKind::Wake => "Wake",
        EntryKind::TimerSet => "TimerSet",
        EntryKind::TimerFire => "TimerFire",
        EntryKind::ClockRead => "ClockRead",
        EntryKind::Send => "Send",
        EntryKind::Recv => "Recv",
        EntryKind::FsWrite => "FsWrite",
        EntryKind::FsFsync => "FsFsync",
        EntryKind::FsRead => "FsRead",
        EntryKind::RngDraw { .. } => "RngDraw",
        EntryKind::Outcome => "Outcome",
        EntryKind::Assert => "Assert",
        EntryKind::Snapshot => "Snapshot",
        EntryKind::Epoch => "Epoch",
        EntryKind::InputStep { .. } => "InputStep",
        EntryKind::CapRequest => "CapRequest",
        EntryKind::CapGrant => "CapGrant",
        EntryKind::CapInvoke => "CapInvoke",
        EntryKind::CapRevoke => "CapRevoke",
        EntryKind::Fault { .. } => "Fault",
        EntryKind::StepBegin => "StepBegin",
        EntryKind::StepEnd => "StepEnd",
    }
}

fn issue_to_error(issue: &MonitorIssue) -> JournalError {
    match issue {
        MonitorIssue::NonMonotonicSequence {
            actor,
            expected,
            actual,
        } => JournalError::NonMonotonicSequence {
            actor: *actor,
            expected: *expected,
            actual: *actual,
        },
        MonitorIssue::MissingParent { parent, .. } => JournalError::MissingParent(*parent),
        MonitorIssue::ParentKindMismatch {
            entry_id,
            expected_kind,
            actual_kind,
        } => JournalError::InvariantViolation(format!(
            "entry {:02x?} requires a {expected_kind} parent, found {actual_kind}",
            &entry_id[..4]
        )),
        MonitorIssue::VectorClockMismatch { entry_id, .. } => {
            JournalError::InvariantViolation(format!(
                "entry {:02x?} vector clock does not match recomputation",
                &entry_id[..4]
            ))
        }
        MonitorIssue::ReplayDivergence { position } => JournalError::InvariantViolation(format!(
            "forked replay diverges from original at position {position}"
        )),
        MonitorIssue::CoverageMismatch {
            actor,
            boundary_entries,
            journal_entries,
        } => JournalError::InvariantViolation(format!(
            "actor {actor} boundary reported {boundary_entries} entries, journal holds {journal_entries}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::VectorClock;
    use crate::dag::{Entry, JournalState};
    use ledger_format::{EntryData, Payload};
    use std::sync::Arc;

    #[test]
    fn verify_accepts_valid_journal() {
        let mut journal = Journal::new();
        journal
            .append(
                EntryKind::InputStep {
                    generator: 0,
                    replay: 0,
                },
                1,
                [],
                Payload::Number(1),
            )
            .unwrap();
        journal
            .append(EntryKind::Outcome, 1, [], Payload::Number(2))
            .unwrap();
        let report = JournalCorrectnessMonitor::verify(&journal).unwrap();
        assert_eq!(report.entries_audited, 2);
        assert_eq!(report.actors_count, 1);
        assert!(JournalCorrectnessMonitor::audit(&journal).is_empty());
    }

    #[test]
    fn valid_observed_value_parents_pass_fidelity() {
        let mut journal = Journal::new();
        let send = journal
            .append(EntryKind::Send, 1, [], Payload::Number(1))
            .unwrap();
        journal
            .append(EntryKind::Recv, 2, [send], Payload::Number(2))
            .unwrap();
        let fs_write = journal
            .append(EntryKind::FsWrite, 1, [], Payload::Number(3))
            .unwrap();
        journal
            .append(EntryKind::FsRead, 2, [fs_write], Payload::Number(4))
            .unwrap();
        let timer_fire = journal
            .append(EntryKind::TimerFire, 1, [], Payload::Number(5))
            .unwrap();
        journal
            .append(EntryKind::Wake, 2, [timer_fire], Payload::Number(6))
            .unwrap();
        assert!(JournalCorrectnessMonitor::audit(&journal).is_empty());
    }

    #[test]
    fn recv_without_send_parent_reports_kind_mismatch() {
        let mut journal = Journal::new();
        let outcome = journal
            .append(EntryKind::Outcome, 1, [], Payload::Number(1))
            .unwrap();
        let recv = journal
            .append(EntryKind::Recv, 2, [outcome], Payload::Number(2))
            .unwrap();
        let issues = JournalCorrectnessMonitor::audit(&journal);
        assert_eq!(issues.len(), 1);
        assert!(matches!(
            issues[0],
            MonitorIssue::ParentKindMismatch {
                entry_id,
                expected_kind: "Send",
                actual_kind: "Outcome",
            } if entry_id == recv
        ));
    }

    #[test]
    fn fsread_without_fswrite_parent_reports_kind_mismatch() {
        let mut journal = Journal::new();
        let outcome = journal
            .append(EntryKind::Outcome, 1, [], Payload::Number(1))
            .unwrap();
        let fs_read = journal
            .append(EntryKind::FsRead, 1, [outcome], Payload::Number(2))
            .unwrap();
        let issues = JournalCorrectnessMonitor::audit(&journal);
        assert_eq!(issues.len(), 1);
        assert!(matches!(
            issues[0],
            MonitorIssue::ParentKindMismatch {
                entry_id,
                expected_kind: "FsWrite",
                actual_kind: "Outcome",
            } if entry_id == fs_read
        ));
    }

    #[test]
    fn rewritten_parent_reports_missing_parent() {
        let mut journal = Journal::new();
        journal
            .append(EntryKind::Outcome, 1, [], Payload::Number(1))
            .unwrap();
        let second = journal
            .append(EntryKind::Outcome, 1, [], Payload::Number(2))
            .unwrap();
        // Rewrite the second entry's parent link to a hash that does not exist.
        let tampered = Entry::new(
            EntryData {
                kind: EntryKind::Outcome,
                actor: 1,
                parents: vec![Hash::default()],
                vector_clock: Vec::new(),
                sequence: 1,
                payload: Payload::Number(2),
            },
            journal.get(&second).unwrap().vector_clock.clone(),
        )
        .unwrap();
        let state = Arc::new(JournalState {
            base: Arc::new(HashMap::from([(tampered.id, Arc::new(tampered.clone()))])),
            overlay: HashMap::new(),
            heads: HashMap::from([(1, tampered.id)]),
            order: Arc::new(vec![tampered.id]),
            overlay_order: Vec::new(),
        });
        let tampered_journal = Journal {
            state,
            scratch: Vec::new(),
        };

        let issues = JournalCorrectnessMonitor::audit(&tampered_journal);
        assert!(issues.iter().any(|issue| matches!(
            issue,
            MonitorIssue::MissingParent { entry_id, parent }
                if *entry_id == tampered.id && *parent == Hash::default()
        )));
    }

    #[test]
    fn broken_vector_clock_reports_mismatch() {
        let entry = Entry::new(
            EntryData {
                kind: EntryKind::Outcome,
                actor: 1,
                parents: Vec::new(),
                vector_clock: Vec::new(),
                sequence: 0,
                payload: Payload::Number(1),
            },
            VectorClock::new(),
        )
        .unwrap();
        let state = Arc::new(JournalState {
            base: Arc::new(HashMap::from([(entry.id, Arc::new(entry.clone()))])),
            overlay: HashMap::new(),
            heads: HashMap::from([(1, entry.id)]),
            order: Arc::new(vec![entry.id]),
            overlay_order: Vec::new(),
        });
        let journal = Journal {
            state,
            scratch: Vec::new(),
        };

        let issues = JournalCorrectnessMonitor::audit(&journal);
        assert_eq!(issues.len(), 1);
        match &issues[0] {
            MonitorIssue::VectorClockMismatch {
                entry_id,
                expected,
                actual,
            } => {
                assert_eq!(*entry_id, entry.id);
                assert_eq!(
                    expected.get(1),
                    1,
                    "recomputed clock must increment actor 1"
                );
                assert_eq!(actual.get(1), 0, "stored clock never incremented");
            }
            other => panic!("expected VectorClockMismatch, got {other:?}"),
        }
    }

    #[test]
    fn replay_fidelity_accepts_identical_and_rejects_divergent() {
        let mut original = Journal::new();
        original
            .append(EntryKind::Outcome, 1, [], Payload::Number(1))
            .unwrap();
        original
            .append(EntryKind::Outcome, 2, [], Payload::Number(2))
            .unwrap();

        let identical = original.fork();
        JournalCorrectnessMonitor::verify_replay_fidelity(&original, &identical).unwrap();

        let mut divergent = original.fork();
        divergent
            .append(EntryKind::Send, 3, [], Payload::Number(3))
            .unwrap();
        assert!(matches!(
            JournalCorrectnessMonitor::verify_replay_fidelity(&original, &divergent),
            Err(issues) if matches!(
                issues.as_slice(),
                [MonitorIssue::ReplayDivergence { position: 2 }]
            )
        ));
    }

    #[test]
    fn coverage_mismatch_reports_shortfall_and_surplus() {
        let mut journal = Journal::new();
        journal
            .append(EntryKind::Outcome, 1, [], Payload::Number(1))
            .unwrap();
        journal
            .append(EntryKind::Outcome, 1, [], Payload::Number(2))
            .unwrap();
        journal
            .append(EntryKind::Outcome, 2, [], Payload::Number(3))
            .unwrap();

        // Exact counts must pass.
        let exact = JournalCorrectnessMonitor::check_coverage(&journal, &[(1, 2), (2, 1)]);
        assert!(exact.is_empty(), "exact coverage must pass: {exact:?}");

        // A reported shortfall (boundary says 1, journal holds 2) must flag actor 1.
        let shortfall = JournalCorrectnessMonitor::check_coverage(&journal, &[(1, 1), (2, 1)]);
        assert!(shortfall.iter().any(|issue| matches!(
            issue,
            MonitorIssue::CoverageMismatch {
                actor: 1,
                boundary_entries: 1,
                journal_entries: 2
            }
        )));

        // A reported surplus (boundary says 3, journal holds 1) must flag actor 2.
        let surplus = JournalCorrectnessMonitor::check_coverage(&journal, &[(1, 2), (2, 3)]);
        assert!(surplus.iter().any(|issue| matches!(
            issue,
            MonitorIssue::CoverageMismatch {
                actor: 2,
                boundary_entries: 3,
                journal_entries: 1
            }
        )));

        // An unreported actor that nonetheless has entries is a leak.
        let missing = JournalCorrectnessMonitor::check_coverage(&journal, &[(1, 2)]);
        assert!(missing.iter().any(|issue| matches!(
            issue,
            MonitorIssue::CoverageMismatch {
                actor: 2,
                boundary_entries: 0,
                journal_entries: 1
            }
        )));
    }

    #[test]
    fn coverage_issues_are_deterministically_ordered() {
        let mut journal = Journal::new();
        for actor in 1..=5u32 {
            for _ in 0..2 {
                journal
                    .append(EntryKind::Outcome, actor, [], Payload::Number(actor as u64))
                    .unwrap();
            }
        }
        // Actor 6 is journaled but never reported by the boundary.
        journal
            .append(EntryKind::Outcome, 6, [], Payload::Number(7))
            .unwrap();

        // Every reported count disagrees with the journal, so all six actors
        // emit a CoverageMismatch and both HashMap collection paths run.
        let boundary: Vec<(ActorId, u64)> =
            (1..=5u32).map(|actor| (actor, actor as u64 + 5)).collect();
        let expected: Vec<MonitorIssue> = vec![
            MonitorIssue::CoverageMismatch {
                actor: 1,
                boundary_entries: 6,
                journal_entries: 2,
            },
            MonitorIssue::CoverageMismatch {
                actor: 2,
                boundary_entries: 7,
                journal_entries: 2,
            },
            MonitorIssue::CoverageMismatch {
                actor: 3,
                boundary_entries: 8,
                journal_entries: 2,
            },
            MonitorIssue::CoverageMismatch {
                actor: 4,
                boundary_entries: 9,
                journal_entries: 2,
            },
            MonitorIssue::CoverageMismatch {
                actor: 5,
                boundary_entries: 10,
                journal_entries: 2,
            },
            MonitorIssue::CoverageMismatch {
                actor: 6,
                boundary_entries: 0,
                journal_entries: 1,
            },
        ];

        let first = JournalCorrectnessMonitor::check_coverage(&journal, &boundary);
        let second = JournalCorrectnessMonitor::check_coverage(&journal, &boundary);
        assert_eq!(first, expected, "issues must be sorted by actor");
        assert_eq!(
            second, expected,
            "same-seed runs must emit issues in identical order"
        );
    }

    #[test]
    fn audit_orders_mixed_issue_kinds() {
        // The broken entry has a dangling parent; the recv entry references the
        // broken entry as a Send-parent it can never satisfy. The order Vec
        // lists the recv first, so unsorted iteration emits ParentKindMismatch
        // before MissingParent. The sorted output must flip that order.
        let broken = Entry::new(
            EntryData {
                kind: EntryKind::Outcome,
                actor: 1,
                parents: vec![Hash::default()],
                vector_clock: Vec::new(),
                sequence: 0,
                payload: Payload::Number(1),
            },
            VectorClock::new(),
        )
        .unwrap();
        let recv = Entry::new(
            EntryData {
                kind: EntryKind::Recv,
                actor: 2,
                parents: vec![broken.id],
                vector_clock: Vec::new(),
                sequence: 0,
                payload: Payload::Number(2),
            },
            VectorClock::new().incremented(2),
        )
        .unwrap();
        let state = Arc::new(JournalState {
            base: Arc::new(HashMap::from([
                (broken.id, Arc::new(broken.clone())),
                (recv.id, Arc::new(recv.clone())),
            ])),
            overlay: HashMap::new(),
            heads: HashMap::from([(1, broken.id), (2, recv.id)]),
            order: Arc::new(vec![recv.id, broken.id]),
            overlay_order: Vec::new(),
        });
        let journal = Journal {
            state,
            scratch: Vec::new(),
        };

        let issues = JournalCorrectnessMonitor::audit(&journal);
        assert_eq!(
            issues,
            vec![
                MonitorIssue::MissingParent {
                    entry_id: broken.id,
                    parent: Hash::default(),
                },
                MonitorIssue::ParentKindMismatch {
                    entry_id: recv.id,
                    expected_kind: "Send",
                    actual_kind: "Outcome",
                },
            ],
            "issues must be sorted by variant kind"
        );
    }
}
