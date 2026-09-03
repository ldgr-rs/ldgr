//! First-divergence localization and causal diagnosis.

use ledger_journal::{Entry, Journal};

/// Append order can interleave concurrent entries; vector-clock order cannot.
fn entries_in_vc_order(journal: &Journal) -> Vec<&Entry> {
    let mut entries = journal.entries().collect::<Vec<_>>();
    entries.sort_by_key(|entry| (entry.data.actor, entry.data.sequence));
    entries
}

/// First-divergence outcome. `Truncated` carries the longer side's extra
/// entry; never collapse to `Identical`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Divergence<'a> {
    Identical,
    Diverged {
        left: &'a Entry,
        right: &'a Entry,
    },
    Truncated {
        left: Option<&'a Entry>,
        right: Option<&'a Entry>,
    },
}

impl<'a> Divergence<'a> {
    /// Whether the compared streams match exactly.
    #[allow(dead_code)]
    pub fn is_identical(&self) -> bool {
        matches!(self, Self::Identical)
    }
}

/// Compare in vector-clock order; concurrent append interleavings are not
/// divergences. Prefixes report `Truncated`, never `Identical`.
pub fn first_divergence<'a>(left: &'a Journal, right: &'a Journal) -> Divergence<'a> {
    let mut left_iter = entries_in_vc_order(left).into_iter();
    let mut right_iter = entries_in_vc_order(right).into_iter();
    loop {
        match (left_iter.next(), right_iter.next()) {
            (None, None) => return Divergence::Identical,
            (Some(left_entry), Some(right_entry)) => {
                if left_entry.id != right_entry.id {
                    return Divergence::Diverged {
                        left: left_entry,
                        right: right_entry,
                    };
                }
            }
            // Truncation is explicit, not identical.
            (Some(extra), None) => {
                return Divergence::Truncated {
                    left: Some(extra),
                    right: None,
                };
            }
            (None, Some(extra)) => {
                return Divergence::Truncated {
                    left: None,
                    right: Some(extra),
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_format::ActorId;
    use ledger_format::EntryHash;
    use ledger_format::{CanonicalValue, EntryKind, EntryPayload, SequenceNumber};
    use ledger_sim::RunResult;

    fn journal_with(values: &[u64]) -> Journal {
        let mut journal = Journal::new();
        for value in values {
            journal
                .append(
                    EntryKind::Outcome,
                    ActorId(1),
                    [],
                    EntryPayload::Outcome(ledger_format::OutcomePayload {
                        schema: EntryHash([0x00; 32]),
                        value: CanonicalValue::Unsigned(*value),
                    }),
                )
                .expect("append must succeed");
        }
        journal
    }

    fn run(journal: Journal) -> RunResult {
        RunResult {
            outcome: ledger_sim::RunOutcome::Completed,
            journal_error: None,
            journal,
            decisions: Vec::new(),
            trace: Vec::new(),
            registers: Vec::new(),
            steps: 0,
            monitor_issues: Vec::new(),
            applied_faults: Vec::new(),
            origins: Vec::new(),
            protection: ledger_sim::BeltStatus::NotArmed,
        }
    }

    #[test]
    fn first_divergence_ignores_append_order_of_concurrent_entries() {
        let left = run(concurrent_journal(&[(1, 10), (2, 20)]));
        let right = run(concurrent_journal(&[(2, 20), (1, 10)]));

        assert!(
            first_divergence(&left.journal, &right.journal).is_identical(),
            "identical vector-clock semantics must not read as a divergence"
        );
    }

    /// Append concurrent entries for two actors in the given order.
    ///
    /// Each actor's entries chain on that actor's own head, so the entries are
    /// concurrent across actors and their vector clocks do not depend on the
    /// append order.
    fn concurrent_journal(order: &[(u32, u64)]) -> Journal {
        let mut journal = Journal::new();
        for (actor, value) in order {
            journal
                .append(
                    EntryKind::Outcome,
                    ActorId(*actor),
                    [],
                    EntryPayload::Outcome(ledger_format::OutcomePayload {
                        schema: EntryHash([0x00; 32]),
                        value: CanonicalValue::Unsigned(*value),
                    }),
                )
                .expect("append must succeed");
        }
        journal
    }

    #[test]
    fn prefix_truncation_reports_truncated_either_way() {
        let left = run(journal_with(&[1, 2, 3, 4]));
        let right = run(journal_with(&[1, 2, 3]));

        match first_divergence(&left.journal, &right.journal) {
            Divergence::Truncated {
                left: Some(_),
                right: None,
            } => {}
            other => panic!("a strict prefix must report Truncated, got {other:?}"),
        }

        let swapped_left = run(journal_with(&[1, 2, 3]));
        let swapped_right = run(journal_with(&[1, 2, 3, 4]));
        match first_divergence(&swapped_left.journal, &swapped_right.journal) {
            Divergence::Truncated {
                left: None,
                right: Some(_),
            } => {}
            other => panic!("prefix direction must report Truncated, got {other:?}"),
        }
    }

    #[test]
    fn first_divergence_reports_divergent_concurrent_pair_in_vc_order() {
        // The concurrent entries differ in value; the append orders differ
        // between the runs. The VC-order walk must still find the pair.
        let left = run(concurrent_journal(&[(1, 10), (2, 20)]));
        let right = run(concurrent_journal(&[(2, 20), (1, 99)]));

        match first_divergence(&left.journal, &right.journal) {
            Divergence::Diverged {
                left: left_entry,
                right: right_entry,
            } => {
                assert_eq!(
                    (left_entry.data.actor, left_entry.data.sequence),
                    (ActorId(1), SequenceNumber(0))
                );
                assert_eq!(
                    (right_entry.data.actor, right_entry.data.sequence),
                    (ActorId(1), SequenceNumber(0))
                );
                assert_ne!(left_entry.id, right_entry.id);
            }
            other => panic!("runs must diverge, got {other:?}"),
        }
    }
}
