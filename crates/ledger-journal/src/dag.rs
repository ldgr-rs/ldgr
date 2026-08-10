//! Content-addressed immutable causal DAG with a frozen base and a
//! post-fork overlay.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use hashbrown::HashMap;

use crate::clock::VectorClock;
use ledger_format::{ActorId, EntryData, EntryKind, Hash, Payload};

/// Entries added to the overlay before it is frozen back into the base.
///
/// A larger threshold batches more post-fork appends between freeze cycles at
/// the cost of a larger transient overlay. The freeze itself rebuilds the base
/// map, so the threshold bounds how often that rebuild runs.
const OVERLAY_THRESHOLD: usize = 1024;

/// Error returned when a journal invariant is violated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalError {
    /// A referenced parent is not present in the journal.
    MissingParent(Hash),
    /// A per-actor sequence number is not monotonic.
    NonMonotonicSequence {
        /// The actor whose sequence is not monotonic.
        actor: ActorId,
        /// The expected next sequence value.
        expected: u64,
        /// The observed sequence value.
        actual: u64,
    },
    /// A required invariant check failed.
    InvariantViolation(String),
    /// A payload could not be canonically encoded before hashing.
    ///
    /// Encoding is validated before the content hash is computed so that a
    /// non-canonical payload can never silently change a hash.
    InvalidPayload(String),
    /// A sealed segment or recovery log is corrupt.
    SegmentCorrupt(String),
    /// A snapshot state hash does not match its recorded payload.
    SnapshotHashMismatch,
    /// The on-disk snapshot store is corrupt or unreadable.
    SnapshotStoreError(String),
    /// The content-addressed archive is corrupt or truncated.
    ArchiveHashMismatch,
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
            Self::InvariantViolation(msg) => write!(f, "journal invariant violated: {msg}"),
            Self::InvalidPayload(msg) => write!(f, "payload cannot be canonically encoded: {msg}"),
            Self::SegmentCorrupt(msg) => write!(f, "corrupt segment: {msg}"),
            Self::SnapshotHashMismatch => write!(f, "snapshot state hash mismatch"),
            Self::SnapshotStoreError(msg) => write!(f, "corrupt snapshot store: {msg}"),
            Self::ArchiveHashMismatch => write!(f, "corrupt archive: hash chain mismatch"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for JournalError {}

/// An immutable, content-addressed journal entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// BLAKE3 content address over the canonical encoding.
    pub id: Hash,
    /// The journal entry data covered by the content hash.
    pub data: EntryData,
    /// Happens-before summary at the time the entry was appended.
    pub vector_clock: VectorClock,
}

impl Entry {
    /// Construct a new entry, deriving its BLAKE3 content hash.
    ///
    /// The payload is validated before the hash is computed, so a
    /// non-canonical payload returns [`JournalError::InvalidPayload`]
    /// instead of silently hashing truncated bytes.
    pub fn new(data: EntryData, vector_clock: VectorClock) -> Result<Self, JournalError> {
        let mut encoded = data
            .try_canonical_bytes()
            .map_err(|err| JournalError::InvalidPayload(err.to_string()))?;
        encoded.extend_from_slice(&vector_clock.encode());
        let id = *blake3::hash(&encoded).as_bytes();
        Ok(Self {
            id,
            data,
            vector_clock,
        })
    }

    /// Construct a new entry, encoding into a caller-provided scratch buffer.
    ///
    /// Produces byte-identical ids to [`Self::new`] and avoids two
    /// allocations per entry on the hot path. The buffer is hashed before
    /// return, so the caller may reuse it after the call.
    pub fn new_with_scratch(
        data: EntryData,
        vector_clock: VectorClock,
        scratch: &mut Vec<u8>,
    ) -> Result<Self, JournalError> {
        scratch.clear();
        data.encode_into(scratch)
            .map_err(|err| JournalError::InvalidPayload(err.to_string()))?;
        vector_clock.encode_into(scratch);
        let id = *blake3::hash(&*scratch).as_bytes();
        Ok(Self {
            id,
            data,
            vector_clock,
        })
    }
}

/// Immutable journal state shared across forks.
///
/// Forks share the frozen base map and order by reference and copy the small
/// overlay, head, and overlay-order maps. The first append on a branch clones
/// those small maps via `Arc::make_mut`; later appends mutate them directly.
#[derive(Debug, Clone)]
pub(crate) struct JournalState {
    /// Frozen, content-addressed entry map shared by all forks.
    pub(crate) base: Arc<HashMap<Hash, Arc<Entry>>>,
    /// Branch-local entries appended since the last freeze.
    pub(crate) overlay: HashMap<Hash, Arc<Entry>>,
    /// Branch-local per-actor head map (most recent entry per actor).
    pub(crate) heads: HashMap<ActorId, Hash>,
    /// Frozen append order for the base entries.
    pub(crate) order: Arc<Vec<Hash>>,
    /// Branch-local append order for overlay entries.
    pub(crate) overlay_order: Vec<Hash>,
}

impl JournalState {
    /// Freeze the overlay into the base.
    ///
    /// Rebasing a shared base would copy the full manifest on every threshold
    /// crossing, which the post-fork append path must never pay. The freeze
    /// is deferred while the base is shared: the overlay keeps growing, and
    /// the merge runs in place (O(overlay)) once the last sibling fork is
    /// dropped. Base and order are shared and released together, so the base
    /// check decides both.
    fn freeze_overlay(&mut self) {
        match Arc::get_mut(&mut self.base) {
            Some(base) => base.extend(self.overlay.drain()),
            None => return,
        }
        match Arc::get_mut(&mut self.order) {
            Some(order) => order.append(&mut self.overlay_order),
            None => {
                let mut merged = Vec::with_capacity(self.order.len() + self.overlay_order.len());
                merged.extend_from_slice(&self.order);
                merged.append(&mut self.overlay_order);
                self.order = Arc::new(merged);
            }
        }
    }
}

/// An append-only in-memory journal view. Forks share immutable entries.
#[derive(Debug, Clone)]
pub struct Journal {
    /// Shared journal state. Crate-visible so the correctness monitor can
    /// construct tampered journals for negative tests.
    pub(crate) state: Arc<JournalState>,
    /// Reusable canonical-encoding buffer for the append hot path.
    ///
    /// Cleared and refilled per append; the hash is computed before reuse, so
    /// the append path avoids two allocations per entry.
    pub(crate) scratch: Vec<u8>,
}

impl Default for Journal {
    fn default() -> Self {
        Self::new()
    }
}

impl Journal {
    pub fn new() -> Self {
        Self {
            state: Arc::new(JournalState {
                base: Arc::new(HashMap::new()),
                overlay: HashMap::new(),
                heads: HashMap::new(),
                order: Arc::new(Vec::new()),
                overlay_order: Vec::new(),
            }),
            scratch: Vec::new(),
        }
    }

    /// Fork this view. Existing entries remain shared by reference.
    pub fn fork(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            scratch: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.state.order.len() + self.state.overlay_order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Append an entry and return its content address.
    ///
    /// A non-canonical payload returns [`JournalError::InvalidPayload`] and
    /// no entry is added. See [`JournalState::freeze_overlay`] for how a
    /// post-fork append never pays an O(#entries) rebase.
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
        let observed = observed_parents.into_iter();
        if observed.size_hint().1 != Some(0) {
            for parent in observed {
                if !parents.contains(&parent) {
                    parents.push(parent);
                }
            }
        }
        let sequence = self
            .state
            .heads
            .get(&actor)
            .and_then(|head| self.get(head))
            .map_or(0, |entry| entry.data.sequence + 1);

        // Merge all parents in one pass; a single parent clones its clock
        // directly as the fast path.
        let mut clock = VectorClock::default();
        if parents.len() == 1 {
            let entry = self
                .get(&parents[0])
                .ok_or(JournalError::MissingParent(parents[0]))?;
            clock = entry.vector_clock.clone();
        } else {
            for parent in &parents {
                let entry = self
                    .get(parent)
                    .ok_or(JournalError::MissingParent(*parent))?;
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
        let entry = Arc::new(Entry::new_with_scratch(data, clock, &mut self.scratch)?);
        let id = entry.id;

        let state = Arc::make_mut(&mut self.state);
        state.overlay.insert(id, Arc::clone(&entry));
        state.overlay_order.push(id);
        state.heads.insert(actor, id);
        if state.overlay.len() >= OVERLAY_THRESHOLD {
            state.freeze_overlay();
        }
        Ok(id)
    }

    /// Look up an entry by content address.
    ///
    /// The branch-local overlay is searched before the frozen base.
    pub fn get(&self, id: &Hash) -> Option<&Entry> {
        self.state
            .overlay
            .get(id)
            .or_else(|| self.state.base.get(id))
            .map(Arc::as_ref)
    }

    /// Return entries in append order.
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.state
            .order
            .iter()
            .chain(self.state.overlay_order.iter())
            .filter_map(|id| self.get(id))
    }

    /// Return the last entry, if any.
    pub fn last(&self) -> Option<&Entry> {
        let id = self.state.overlay_order.last().or(self.state.order.last());
        id.and_then(|id| self.get(id))
    }

    /// Return the head entry hash for a specific actor.
    pub fn head_for_actor(&self, actor: ActorId) -> Option<Hash> {
        self.state.heads.get(&actor).copied()
    }

    /// Return a root hash for the current ordered view.
    pub fn root_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        for id in self
            .state
            .order
            .iter()
            .chain(self.state.overlay_order.iter())
        {
            hasher.update(id);
        }
        *hasher.finalize().as_bytes()
    }

    /// Return raw order vector.
    pub fn order(&self) -> &[Hash] {
        &self.state.order
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use ledger_format::{CborValue, Payload};

    #[test]
    fn append_rejects_non_canonical_payload_without_hashing() {
        let mut journal = Journal::new();
        let bad_payload = Payload::Value(CborValue::Float(f64::NAN));
        let result = journal.append(EntryKind::Outcome, 1, [], bad_payload);
        assert!(matches!(result, Err(JournalError::InvalidPayload(_))));
        assert!(journal.is_empty());
    }

    #[test]
    fn append_rejects_disallowed_tag_without_hashing() {
        let mut journal = Journal::new();
        let bad_payload = Payload::Value(CborValue::Tag(99, Box::new(CborValue::Unsigned(1))));
        let result = journal.append(EntryKind::Outcome, 1, [], bad_payload);
        assert!(matches!(result, Err(JournalError::InvalidPayload(_))));
        assert!(journal.is_empty());
    }

    #[test]
    fn fork_is_isolated_and_preserves_shared_entries() {
        let mut journal = Journal::new();
        let mut pre_fork = Vec::new();
        for i in 0..1000 {
            pre_fork.push(
                journal
                    .append(
                        EntryKind::InputStep {
                            generator: 0,
                            replay: 0,
                        },
                        1,
                        [],
                        Payload::Number(i),
                    )
                    .unwrap(),
            );
        }

        let mut fork_a = journal.fork();
        let mut fork_b = journal.fork();

        let mut a_ids = Vec::new();
        for i in 0..1000 {
            a_ids.push(
                fork_a
                    .append(EntryKind::Outcome, 1, [], Payload::Number(i))
                    .unwrap(),
            );
        }
        let mut b_ids = Vec::new();
        for i in 0..1000 {
            b_ids.push(
                fork_b
                    .append(EntryKind::Outcome, 1, [], Payload::Number(i + 1000))
                    .unwrap(),
            );
        }

        for id in &a_ids {
            assert!(fork_a.get(id).is_some(), "branch A must see its entries");
            assert!(fork_b.get(id).is_none(), "branch B must not see A entries");
            assert!(journal.get(id).is_none(), "original must be unchanged");
        }
        for id in &b_ids {
            assert!(fork_b.get(id).is_some());
            assert!(fork_a.get(id).is_none());
            assert!(journal.get(id).is_none());
        }
        for id in &pre_fork {
            assert!(journal.get(id).is_some(), "original keeps pre-fork entries");
            assert!(fork_a.get(id).is_some(), "branch A keeps pre-fork entries");
            assert!(fork_b.get(id).is_some(), "branch B keeps pre-fork entries");
        }

        assert_eq!(journal.len(), 1000);
        assert_eq!(fork_a.len(), 2000);
        assert_eq!(fork_b.len(), 2000);
        assert_ne!(fork_a.root_hash(), journal.root_hash());
        assert_ne!(fork_b.root_hash(), journal.root_hash());

        let original = journal.get(&pre_fork[0]).map(|entry| entry.id).unwrap();
        let a_shared = fork_a.get(&pre_fork[0]).map(|entry| entry.id).unwrap();
        let b_shared = fork_b.get(&pre_fork[0]).map(|entry| entry.id).unwrap();
        assert_eq!(original, a_shared);
        assert_eq!(original, b_shared);
    }

    #[test]
    fn overlay_freezes_into_base_after_threshold_when_exclusive() {
        let journal = Journal::new();
        let mut fork = journal.fork();
        drop(journal);
        let extra = OVERLAY_THRESHOLD * 2 + 10;
        for i in 0..extra {
            fork.append(EntryKind::Outcome, 1, [], Payload::Number(i as u64))
                .unwrap();
        }
        assert_eq!(fork.len(), extra);
        let last = fork.entries().last().unwrap();
        assert!(fork.get(&last.id).is_some());
        assert_eq!(fork.order().len(), OVERLAY_THRESHOLD * 2);
        assert_eq!(
            fork.entries().count(),
            OVERLAY_THRESHOLD * 2 + 10,
            "all entries survive freeze cycles"
        );
    }

    #[test]
    fn overlay_freezes_are_deferred_while_base_is_shared() {
        let journal = Journal::new();
        let mut fork = journal.fork();
        let extra = OVERLAY_THRESHOLD * 2 + 10;
        for i in 0..extra {
            fork.append(EntryKind::Outcome, 1, [], Payload::Number(i as u64))
                .unwrap();
        }
        assert_eq!(fork.len(), extra);
        assert_eq!(
            fork.order().len(),
            0,
            "shared base must not be rebased while the original is alive"
        );
        assert_eq!(
            fork.entries().count(),
            OVERLAY_THRESHOLD * 2 + 10,
            "deferred freeze must not drop entries"
        );
    }

    #[test]
    fn sequence_resumes_across_actor_heads_after_fork() {
        let mut journal = Journal::new();
        journal
            .append(EntryKind::Outcome, 1, [], Payload::Number(0))
            .unwrap();
        let mut fork = journal.fork();
        let id = fork
            .append(EntryKind::Outcome, 1, [], Payload::Number(1))
            .unwrap();
        let entry = fork.get(&id).unwrap();
        assert_eq!(entry.data.sequence, 1);
        assert_eq!(entry.vector_clock.get(1), 2);
    }
}
