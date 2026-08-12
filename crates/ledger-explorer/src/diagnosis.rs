//! First-divergence localization and causal diagnosis.

use ledger_format::Hash;
use ledger_journal::{Entry, Journal};
use ledger_sim::RunResult;

/// Collect a journal's entries in vector-clock order.
///
/// Append order is a total order that can interleave concurrent entries
/// differently between two runs; the vector-clock projection orders by
/// `(actor, per-actor sequence)`, which is independent of the interleaving.
fn entries_in_vc_order(journal: &Journal) -> Vec<&Entry> {
    let mut entries = journal.entries().collect::<Vec<_>>();
    entries.sort_by_key(|entry| (entry.data.actor, entry.data.sequence));
    entries
}

/// Compare two journals at their first divergent entry pair.
///
/// Both streams are walked in vector-clock order, so a difference in append
/// order of concurrent entries is not a divergence. A strict prefix of one
/// journal is a truncated replay, not a behavior change: it returns `None`
/// like an identical match. When the journals do diverge, both sides of the
/// returned pair are `Some`.
pub fn first_divergence<'a>(
    left: &'a Journal,
    right: &'a Journal,
) -> Option<(Option<&'a Entry>, Option<&'a Entry>)> {
    let mut left_iter = entries_in_vc_order(left).into_iter();
    let mut right_iter = entries_in_vc_order(right).into_iter();
    loop {
        match (left_iter.next(), right_iter.next()) {
            (None, None) => return None,
            (Some(left_entry), Some(right_entry)) => {
                if left_entry.id != right_entry.id {
                    return Some((Some(left_entry), Some(right_entry)));
                }
            }
            // One journal truncated early. A truncated replay is a leak
            // case, not a behavior-change divergence.
            (Some(_), None) | (None, Some(_)) => return None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CausalDivergence {
    pub first_divergent_left: Hash,
    pub first_divergent_right: Hash,
    pub neighborhood: Vec<Hash>,
}

/// Bisect two runs at their first divergence.
///
/// The neighborhood is the left divergent entry plus its parents, which
/// frames a code-change bisect. Returns `None` when the runs are identical
/// or when one run is a prefix of the other: a truncated replay is not a
/// behavior-change divergence, matching [`first_divergence`].
pub fn causal_bisect(left: &RunResult, right: &RunResult) -> Option<CausalDivergence> {
    let (left_entry, right_entry) = first_divergence(&left.journal, &right.journal)?;
    let left_entry = left_entry?;
    let right_entry = right_entry?;
    let mut neighborhood = Vec::with_capacity(left_entry.data.parents.len() + 1);
    neighborhood.push(left_entry.id);
    for parent in &left_entry.data.parents {
        if !neighborhood.contains(parent) {
            neighborhood.push(*parent);
        }
    }
    Some(CausalDivergence {
        first_divergent_left: left_entry.id,
        first_divergent_right: right_entry.id,
        neighborhood,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_format::{EntryKind, Payload};

    fn journal_with(values: &[u64]) -> Journal {
        let mut journal = Journal::new();
        for value in values {
            journal
                .append(EntryKind::Outcome, 1, [], Payload::Number(*value))
                .expect("append must succeed");
        }
        journal
    }

    fn run(journal: Journal) -> RunResult {
        RunResult {
            journal,
            decisions: Vec::new(),
            trace: Vec::new(),
            registers: Vec::new(),
            steps: 0,
            monitor_issues: Vec::new(),
            applied_faults: Vec::new(),
        }
    }

    #[test]
    fn causal_bisect_finds_divergent_pair_and_neighborhood() {
        let left = run(journal_with(&[1, 2, 3]));
        let right = run(journal_with(&[1, 2, 9]));

        let divergence = causal_bisect(&left, &right).expect("diverging runs must bisect");
        let left_ids = left.journal.entries().map(|e| e.id).collect::<Vec<_>>();
        let right_ids = right.journal.entries().map(|e| e.id).collect::<Vec<_>>();

        assert_eq!(divergence.first_divergent_left, left_ids[2]);
        assert_eq!(divergence.first_divergent_right, right_ids[2]);
        assert_ne!(
            divergence.first_divergent_left,
            divergence.first_divergent_right
        );
        assert!(
            !divergence.neighborhood.is_empty(),
            "the neighborhood must contain the left entry"
        );
        assert_eq!(divergence.neighborhood[0], divergence.first_divergent_left);
        assert!(
            divergence.neighborhood.contains(&left_ids[1]),
            "the neighborhood must contain the left entry's parent"
        );
    }

    #[test]
    fn causal_bisect_returns_none_for_identical_runs() {
        let left = run(journal_with(&[1, 2, 3]));
        let right = run(journal_with(&[1, 2, 3]));
        assert!(causal_bisect(&left, &right).is_none());
    }

    #[test]
    fn causal_bisect_returns_none_for_prefix_run() {
        let left = run(journal_with(&[1, 2, 3, 4]));
        let right = run(journal_with(&[1, 2, 3]));
        assert!(causal_bisect(&left, &right).is_none());
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
                .append(EntryKind::Outcome, *actor, [], Payload::Number(*value))
                .expect("append must succeed");
        }
        journal
    }

    #[test]
    fn first_divergence_ignores_append_order_of_concurrent_entries() {
        let left = run(concurrent_journal(&[(1, 10), (2, 20)]));
        let right = run(concurrent_journal(&[(2, 20), (1, 10)]));

        assert!(
            first_divergence(&left.journal, &right.journal).is_none(),
            "identical vector-clock semantics must not read as a divergence"
        );
        assert!(causal_bisect(&left, &right).is_none());
    }

    #[test]
    fn prefix_truncation_is_not_a_divergence_either_way() {
        let left = run(journal_with(&[1, 2, 3, 4]));
        let right = run(journal_with(&[1, 2, 3]));

        assert!(
            first_divergence(&left.journal, &right.journal).is_none(),
            "a strict prefix must not read as a divergence"
        );
        assert!(causal_bisect(&left, &right).is_none());

        let swapped_left = run(journal_with(&[1, 2, 3]));
        let swapped_right = run(journal_with(&[1, 2, 3, 4]));
        assert!(
            first_divergence(&swapped_left.journal, &swapped_right.journal).is_none(),
            "prefix direction must not matter"
        );
        assert!(causal_bisect(&swapped_left, &swapped_right).is_none());
    }

    #[test]
    fn first_divergence_reports_divergent_concurrent_pair_in_vc_order() {
        // The concurrent entries differ in value; the append orders differ
        // between the runs. The VC-order walk must still find the pair.
        let left = run(concurrent_journal(&[(1, 10), (2, 20)]));
        let right = run(concurrent_journal(&[(2, 20), (1, 99)]));

        let (left_entry, right_entry) =
            first_divergence(&left.journal, &right.journal).expect("runs must diverge");
        let left_entry = left_entry.expect("divergent pair carries the left entry");
        let right_entry = right_entry.expect("divergent pair carries the right entry");
        assert_eq!((left_entry.data.actor, left_entry.data.sequence), (1, 0));
        assert_eq!((right_entry.data.actor, right_entry.data.sequence), (1, 0));
        assert_ne!(left_entry.id, right_entry.id);
    }
}
