//! Content-addressed causal journal with vector-clock summaries.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Arc;

use crate::format::{ActorId, EntryData, EntryKind, Payload};

/// A BLAKE3 content address.
pub type Hash = [u8; 32];

/// Error returned when a journal invariant is violated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalError {
    /// A referenced parent is not present in the journal.
    MissingParent(Hash),
    /// A per-actor sequence number is not monotonic.
    NonMonotonicSequence {
        actor: ActorId,
        expected: u64,
        actual: u64,
    },
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingParent(hash) => write!(f, "missing parent {:02x?}", &hash[..4]),
            Self::NonMonotonicSequence {
                actor,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "actor {actor} expected sequence {expected}, got {actual}"
                )
            }
        }
    }
}

impl std::error::Error for JournalError {}

/// A compact vector-clock summary.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VectorClock(BTreeMap<ActorId, u64>);

impl VectorClock {
    /// Merge two clocks by component-wise maximum.
    pub fn merge(&self, other: &Self) -> Self {
        let mut merged = self.0.clone();
        for (&actor, &value) in &other.0 {
            merged
                .entry(actor)
                .and_modify(|current| *current = (*current).max(value))
                .or_insert(value);
        }
        Self(merged)
    }

    /// Increment the component for an actor.
    pub fn incremented(&self, actor: ActorId) -> Self {
        let mut next = self.0.clone();
        let value = next.entry(actor).or_default();
        *value = value.saturating_add(1);
        Self(next)
    }

    /// Read one actor component.
    pub fn get(&self, actor: ActorId) -> u64 {
        self.0.get(&actor).copied().unwrap_or(0)
    }

    /// Return true when this clock happens before or equals another clock.
    pub fn happens_before_or_equal(&self, other: &Self) -> bool {
        self.0
            .iter()
            .all(|(&actor, &value)| value <= other.get(actor))
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        crate::cbor::map(&mut out, self.0.len());
        for (&actor, &value) in &self.0 {
            crate::cbor::unsigned(&mut out, actor as u64);
            crate::cbor::unsigned(&mut out, value);
        }
        out
    }
}

/// An immutable, content-addressed journal entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub id: Hash,
    pub data: EntryData,
    pub vector_clock: VectorClock,
}

impl Entry {
    fn new(data: EntryData, vector_clock: VectorClock) -> Self {
        let mut encoded = data.canonical_bytes();
        encoded.extend_from_slice(&vector_clock.encode());
        let id = *blake3::hash(&encoded).as_bytes();
        Self {
            id,
            data,
            vector_clock,
        }
    }
}

#[derive(Clone)]
struct JournalState {
    entries: HashMap<Hash, Arc<Entry>>,
    heads: HashMap<ActorId, Hash>,
    order: Vec<Hash>,
}

/// An append-only in-memory journal view. Forks share immutable entries.
#[derive(Clone)]
pub struct Journal {
    state: Arc<JournalState>,
}

impl Default for Journal {
    fn default() -> Self {
        Self::new()
    }
}

impl Journal {
    /// Create an empty journal.
    pub fn new() -> Self {
        Self {
            state: Arc::new(JournalState {
                entries: HashMap::new(),
                heads: HashMap::new(),
                order: Vec::new(),
            }),
        }
    }

    /// Fork this view. Existing entries remain shared by reference.
    pub fn fork(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }

    /// Append an entry and return its content address.
    pub fn append(
        &mut self,
        kind: EntryKind,
        actor: ActorId,
        observed_parents: impl IntoIterator<Item = Hash>,
        payload: Payload,
    ) -> Result<Hash, JournalError> {
        let mut parents = Vec::new();
        if let Some(previous) = self.state.heads.get(&actor) {
            parents.push(*previous);
        }
        for parent in observed_parents {
            if !parents.contains(&parent) {
                parents.push(parent);
            }
        }
        for parent in &parents {
            if !self.state.entries.contains_key(parent) {
                return Err(JournalError::MissingParent(*parent));
            }
        }
        let sequence = self
            .state
            .heads
            .get(&actor)
            .and_then(|head| self.state.entries.get(head))
            .map_or(0, |entry| entry.data.sequence + 1);
        let mut clock = VectorClock::default();
        for parent in &parents {
            if let Some(entry) = self.state.entries.get(parent) {
                clock = clock.merge(&entry.vector_clock);
            }
        }
        clock = clock.incremented(actor);
        let data = EntryData {
            kind,
            actor,
            parents,
            vector_clock: Vec::new(),
            sequence,
            payload,
        };
        let entry = Arc::new(Entry::new(data, clock));
        let id = entry.id;
        let state = Arc::make_mut(&mut self.state);
        state.entries.insert(id, Arc::clone(&entry));
        state.heads.insert(actor, id);
        state.order.push(id);
        Ok(id)
    }

    /// Look up an entry by content address.
    pub fn get(&self, id: &Hash) -> Option<&Entry> {
        self.state.entries.get(id).map(Arc::as_ref)
    }

    /// Return entries in append order.
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.state.order.iter().filter_map(|id| self.get(id))
    }

    /// Return the last entry, if any.
    pub fn last(&self) -> Option<&Entry> {
        self.state.order.last().and_then(|id| self.get(id))
    }

    /// Return a root hash for the current ordered view.
    pub fn root_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        for id in &self.state.order {
            hasher.update(id);
        }
        *hasher.finalize().as_bytes()
    }

    /// Return the causal backward closure of an entry.
    pub fn causal_closure(&self, start: Hash) -> Result<Vec<Hash>, JournalError> {
        if self.get(&start).is_none() {
            return Err(JournalError::MissingParent(start));
        }
        let mut seen = std::collections::HashSet::new();
        let mut stack = vec![start];
        while let Some(id) = stack.pop() {
            if seen.insert(id)
                && let Some(entry) = self.get(&id)
            {
                stack.extend(entry.data.parents.iter().copied());
            }
        }
        Ok(self
            .state
            .order
            .iter()
            .copied()
            .filter(|id| seen.contains(id))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_adds_local_parent_and_increments_clock() {
        let mut journal = Journal::new();
        let first = journal
            .append(EntryKind::InputStep, 1, [], Payload::Number(1))
            .unwrap();
        let second = journal
            .append(EntryKind::Outcome, 1, [], Payload::Empty)
            .unwrap();
        let entry = journal.get(&second).unwrap();
        assert_eq!(entry.data.parents, vec![first]);
        assert_eq!(entry.vector_clock.get(1), 2);
    }

    #[test]
    fn fork_shares_content_and_diverges_order() {
        let mut journal = Journal::new();
        let shared = journal
            .append(EntryKind::InputStep, 1, [], Payload::Number(1))
            .unwrap();
        let mut fork = journal.fork();
        let fork_head = fork
            .append(EntryKind::Outcome, 2, [shared], Payload::Empty)
            .unwrap();
        assert!(journal.get(&fork_head).is_none());
        assert!(fork.get(&shared).is_some());
    }
}
