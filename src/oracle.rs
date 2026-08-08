//! Offline predicates over immutable journal entries.

use crate::format::{EntryKind, Payload};
use crate::journal::{Entry, Journal};

/// A predicate result with the entries that explain it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// Whether the predicate failed.
    pub violated: bool,
    /// Entries that witness the result.
    pub witnesses: Vec<[u8; 32]>,
    /// Human-readable explanation.
    pub reason: String,
}

/// A journal oracle.
pub trait Oracle {
    /// Evaluate the oracle against a journal.
    fn check(&self, journal: &Journal) -> Verdict;
}

/// Detect the mini-KV stale-read marker.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinearizabilityOracle;

impl Oracle for LinearizabilityOracle {
    fn check(&self, journal: &Journal) -> Verdict {
        let witnesses = journal
            .entries()
            .filter(|entry| entry.data.kind == EntryKind::Outcome && entry.data.actor == 2)
            .filter_map(|entry| match entry.data.payload {
                Payload::Number(100) => Some(entry.id),
                _ => None,
            })
            .collect::<Vec<_>>();
        let violated = !witnesses.is_empty();
        Verdict {
            violated,
            witnesses,
            reason: if violated {
                "node B returned before replicated state was visible".into()
            } else {
                "no stale read observed".into()
            },
        }
    }
}

/// Compare two journal streams and return their first differing pair.
pub fn first_divergence<'a>(
    left: &'a Journal,
    right: &'a Journal,
) -> Option<(Option<&'a Entry>, Option<&'a Entry>)> {
    let mut left_iter = left.entries();
    let mut right_iter = right.entries();
    loop {
        let l = left_iter.next();
        let r = right_iter.next();
        if l.map(|entry| entry.id) != r.map(|entry| entry.id) {
            return Some((l, r));
        }
        l?;
    }
}
