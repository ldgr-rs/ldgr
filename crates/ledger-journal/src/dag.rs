//! Content-addressed immutable causal DAG with a frozen base and a
//! post-fork overlay.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use hashbrown::HashMap;

use crate::clock::VectorClock;
use ledger_format::{ActorId, EntryData, EntryKind, EntryPayload, Hash};

/// Entries added to the overlay before it is frozen back into the base.
///
/// A larger threshold batches more post-fork appends between freeze cycles at
/// the cost of a larger transient overlay. The freeze itself rebuilds the base
/// map, so the threshold bounds how often that rebuild runs.
const OVERLAY_THRESHOLD: usize = 1024;

/// Error returned when a journal invariant is violated.
#[non_exhaustive]
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
        Ok(Self::new_with_scratch_recorded(data, vector_clock, scratch)?.0)
    }

    /// [`Self::new_with_scratch`] plus the byte length of the canonical
    /// `EntryData` prefix written into `scratch`.
    ///
    /// The batch storage path reuses the scratch bytes as an
    /// already-encoded frame payload and needs the data/clock split point
    /// without re-encoding. The hashed bytes are identical to
    /// [`Self::new_with_scratch`].
    pub(crate) fn new_with_scratch_recorded(
        data: EntryData,
        vector_clock: VectorClock,
        scratch: &mut Vec<u8>,
    ) -> Result<(Self, usize), JournalError> {
        scratch.clear();
        data.encode_into(scratch)
            .map_err(|err| JournalError::InvalidPayload(err.to_string()))?;
        let data_len = scratch.len();
        vector_clock.encode_into(scratch);
        let id = *blake3::hash(&*scratch).as_bytes();
        Ok((
            Self {
                id,
                data,
                vector_clock,
            },
            data_len,
        ))
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

/// One pending entry of a [`Journal::append_batch`] call.
///
/// Fields mirror the parameters of [`Journal::append`]; see the field docs
/// for how parents are assembled inside a batch.
#[derive(Debug, Clone)]
pub struct BatchEntry {
    /// Journal event kind.
    pub kind: EntryKind,
    /// Appending actor.
    pub actor: ActorId,
    /// Observed external parents known before the batch starts.
    ///
    /// Order is preserved. Duplicates of already-listed parents are dropped
    /// exactly as in [`Journal::append`].
    pub observed_parents: Vec<Hash>,
    /// Append the previous batch entry's id as a trailing observed parent.
    ///
    /// "Previous" is the immediately preceding entry of the same
    /// [`Journal::append_batch`] call. Entries whose causal parent is an
    /// earlier entry of the same group (`Wake` after `TimerFire`, a fault
    /// after its `Send`) cannot list that parent up front because the id
    /// does not exist until the earlier entry is hashed; this flag resolves
    /// it at append time. The reference is skipped when it duplicates an
    /// existing parent, matching [`Journal::append`], and when the entry is
    /// first in its call.
    pub chain_previous: bool,
    /// Payload covered by the content hash.
    pub payload: EntryPayload,
}

impl BatchEntry {
    /// A batch entry with no observed parents.
    pub fn new(kind: EntryKind, actor: ActorId, payload: EntryPayload) -> Self {
        Self {
            kind,
            actor,
            observed_parents: Vec::new(),
            chain_previous: false,
            payload,
        }
    }

    /// Chain this entry to the immediately preceding batch entry.
    pub fn chained(mut self) -> Self {
        self.chain_previous = true;
        self
    }
}

/// Encoded result pieces of one appended entry.
///
/// `payload` holds the canonical `data || vector_clock` bytes whose BLAKE3
/// digest is `id`; `data_len` marks the split between the two parts. The
/// segment writer turns these into storage frames without a second CBOR
/// pass over the entry.
#[derive(Debug, Clone)]
pub struct EntryFrame {
    /// Content address of the encoded entry.
    pub id: Hash,
    /// Byte length of the canonical `EntryData` prefix of `payload`.
    pub data_len: usize,
    /// Canonical `data || vector_clock` bytes.
    pub payload: Vec<u8>,
    /// True when the entry kind belongs to the fault-relevant set.
    ///
    /// Carried so frame-based storage writes preserve the sealed-segment
    /// warm-retention flag without re-decoding payloads.
    pub fault_relevant: bool,
}

/// Return true when an entry kind belongs to the fault-relevant set.
///
/// The warm retention tier keeps segments carrying these kinds loose.
pub(crate) fn kind_is_fault_relevant(kind: &EntryKind) -> bool {
    matches!(
        kind,
        EntryKind::Fault | EntryKind::Outcome | EntryKind::Assert
    )
}

/// Overlay-then-base entry lookup on an exclusively borrowed state.
fn state_lookup<'a>(state: &'a JournalState, id: &Hash) -> Option<&'a Entry> {
    state
        .overlay
        .get(id)
        .or_else(|| state.base.get(id))
        .map(Arc::as_ref)
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
        payload: EntryPayload,
    ) -> Result<Hash, JournalError> {
        let previous_head = self.state.heads.get(&actor).copied();
        let mut parents = Vec::new();
        if let Some(previous) = previous_head {
            parents.push(previous);
        }
        let observed = observed_parents.into_iter();
        if observed.size_hint().1 != Some(0) {
            for parent in observed {
                if !parents.contains(&parent) {
                    parents.push(parent);
                }
            }
        }
        let (sequence, head_entry) = match previous_head {
            Some(head) => {
                let entry = self.get(&head).ok_or(JournalError::MissingParent(head))?;
                (entry.data.sequence.saturating_add(1), Some(entry))
            }
            None => (0, None),
        };

        // Merge all parents in one pass; a single parent clones its clock
        // directly as the fast path.
        let mut clock = VectorClock::default();
        if parents.len() == 1 {
            if let Some(entry) = head_entry {
                clock = entry.vector_clock.clone();
            } else {
                let entry = self
                    .get(&parents[0])
                    .ok_or(JournalError::MissingParent(parents[0]))?;
                clock = entry.vector_clock.clone();
            }
        } else if !parents.is_empty() {
            for parent in &parents {
                let entry = self
                    .get(parent)
                    .ok_or(JournalError::MissingParent(*parent))?;
                clock = clock.merge(&entry.vector_clock);
            }
        }
        clock = clock.incremented(actor);

        let data = EntryData {
            format_version: ledger_format::FORMAT_VERSION,
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

    /// Append a group of entries in order, returning their content addresses.
    ///
    /// Byte-equality contract: appending `batch` produces ids, vector
    /// clocks, per-entry parents, and the journal root hash byte-identical
    /// to calling [`Journal::append`] once per item in the same order. Ids
    /// stay eager and per-entry; each entry hashes its own canonical bytes,
    /// so a following same-actor entry consumes that id as its head parent
    /// exactly as before. Only bookkeeping is amortized: one shared-state
    /// claim, capacity reserves, and one overlay-freeze threshold check per
    /// batch instead of per entry.
    ///
    /// Entries are applied in order until the first invalid payload, which
    /// returns [`JournalError::InvalidPayload`] and leaves the already
    /// applied prefix in place, mirroring how an [`Journal::append`] failure
    /// leaves earlier appends untouched.
    ///
    /// An empty batch changes nothing and does not claim shared state.
    pub fn append_batch(&mut self, batch: Vec<BatchEntry>) -> Result<Vec<Hash>, JournalError> {
        self.append_batch_impl(batch, None)
    }

    /// [`Journal::append_batch`] plus the canonical frame payload of every
    /// appended entry pushed onto `frames`.
    ///
    /// Storage reuses these bytes instead of re-encoding each entry. On an
    /// error the frames of the successfully appended prefix stay on `frames`
    /// in append order.
    #[cfg(feature = "std")]
    pub(crate) fn append_batch_with_frames(
        &mut self,
        batch: Vec<BatchEntry>,
        frames: &mut Vec<EntryFrame>,
    ) -> Result<Vec<Hash>, JournalError> {
        frames.reserve(batch.len());
        self.append_batch_impl(batch, Some(frames))
    }

    fn append_batch_impl(
        &mut self,
        batch: Vec<BatchEntry>,
        mut frames: Option<&mut Vec<EntryFrame>>,
    ) -> Result<Vec<Hash>, JournalError> {
        let count = batch.len();
        let mut ids = Vec::with_capacity(count);
        if count == 0 {
            return Ok(ids);
        }

        // One claim covers the whole batch; later entries mutate the
        // unshared state directly, like repeated post-fork appends do.
        let state = Arc::make_mut(&mut self.state);
        state.overlay.reserve(count);
        state.overlay_order.reserve(count);

        for spec in batch {
            let previous_head = state.heads.get(&spec.actor).copied();

            // Parent assembly mirrors `append` exactly: actor head first,
            // then observed parents in order, deduplicated against the
            // parents already listed. The chained reference resolves after
            // those and lands last.
            let mut parents = Vec::with_capacity(
                spec.observed_parents.len()
                    + usize::from(previous_head.is_some())
                    + usize::from(spec.chain_previous),
            );
            if let Some(previous) = previous_head {
                parents.push(previous);
            }
            for parent in spec.observed_parents.iter() {
                if !parents.contains(parent) {
                    parents.push(*parent);
                }
            }
            if spec.chain_previous
                && let Some(previous_id) = ids.last().copied()
                && !parents.contains(&previous_id)
            {
                parents.push(previous_id);
            }

            // Sequence probe. The head must exist exactly as in `append`;
            // a missing head fails before any clock work.
            let head_info: Option<(u64, VectorClock)> = match previous_head {
                Some(head) => {
                    let entry =
                        state_lookup(state, &head).ok_or(JournalError::MissingParent(head))?;
                    Some((entry.data.sequence, entry.vector_clock.clone()))
                }
                None => None,
            };
            let sequence = match &head_info {
                Some((previous_sequence, _)) => previous_sequence.saturating_add(1),
                None => 0,
            };

            // Clock merge mirrors `append`: a single parent clones its
            // clock directly as the fast path, several parents merge in
            // parent order, none starts from the empty clock.
            let mut clock = VectorClock::default();
            if parents.len() == 1 {
                if previous_head.is_some() {
                    clock = head_info.map_or_else(VectorClock::new, |(_, c)| c);
                } else {
                    let entry = state_lookup(state, &parents[0])
                        .ok_or(JournalError::MissingParent(parents[0]))?;
                    clock = entry.vector_clock.clone();
                }
            } else if !parents.is_empty() {
                for parent in &parents {
                    let entry =
                        state_lookup(state, parent).ok_or(JournalError::MissingParent(*parent))?;
                    clock = clock.merge(&entry.vector_clock);
                }
            }
            clock = clock.incremented(spec.actor);

            let data = EntryData {
                format_version: ledger_format::FORMAT_VERSION,
                kind: spec.kind,
                actor: spec.actor,
                parents,
                vector_clock: Vec::new(),
                sequence,
                payload: spec.payload,
            };

            // Eager per-entry hashing: identical bytes and ids as
            // `Entry::new_with_scratch` (same implementation).
            let (entry, data_len) =
                Entry::new_with_scratch_recorded(data, clock, &mut self.scratch)?;
            let id = entry.id;

            if let Some(out) = frames.as_deref_mut() {
                out.push(EntryFrame {
                    id,
                    data_len,
                    payload: self.scratch.clone(),
                    fault_relevant: kind_is_fault_relevant(&spec.kind),
                });
            }

            state.overlay.insert(id, Arc::new(entry));
            state.overlay_order.push(id);
            state.heads.insert(spec.actor, id);
            ids.push(id);
        }

        // One threshold check per batch. Freezing at batch end leaves the
        // same observable maps as freezing mid-batch: entries keep their
        // lookup path (overlay before base) either way.
        if state.overlay.len() >= OVERLAY_THRESHOLD {
            state.freeze_overlay();
        }
        Ok(ids)
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

    /// Look up an entry Arc by content address.
    pub(crate) fn get_arc(&self, id: &Hash) -> Option<Arc<Entry>> {
        self.state
            .overlay
            .get(id)
            .cloned()
            .or_else(|| self.state.base.get(id).cloned())
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

    /// Return the frozen base order vector.
    ///
    /// Only the base is returned; the overlay order lives separately and is
    /// chained by callers that need the full view. The name makes the
    /// partial view explicit.
    pub fn base_order(&self) -> &[Hash] {
        &self.state.order
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_format::EntryPayload;

    #[test]
    fn append_rejects_non_canonical_payload_without_hashing() {
        let mut journal = Journal::new();
        let bad_payload = EntryPayload::Outcome(ledger_format::OutcomePayload {
            schema: [0x00; 32],
            value: ledger_format::CanonicalValue::Float(f64::NAN),
        });
        let result = journal.append(EntryKind::Outcome, 1, [], bad_payload);
        assert!(matches!(result, Err(JournalError::InvalidPayload(_))));
        assert!(journal.is_empty());
    }

    #[test]
    fn append_rejects_disallowed_tag_without_hashing() {
        let mut journal = Journal::new();
        // NaN is rejected by CanonicalValue before hashing.
        let bad_payload = EntryPayload::Outcome(ledger_format::OutcomePayload {
            schema: [0x00; 32],
            value: ledger_format::CanonicalValue::Float(f64::NAN),
        });
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
                        EntryKind::InputStep,
                        1,
                        [],
                        EntryPayload::InputStep(ledger_format::InputStepPayload {
                            generator: 0,
                            replay: 0,
                            value: ledger_format::CanonicalValue::Unsigned(i),
                        }),
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
                    .append(
                        EntryKind::Outcome,
                        1,
                        [],
                        EntryPayload::Outcome(ledger_format::OutcomePayload {
                            schema: [0x00; 32],
                            value: ledger_format::CanonicalValue::Unsigned(i),
                        }),
                    )
                    .unwrap(),
            );
        }
        let mut b_ids = Vec::new();
        for i in 0..1000 {
            b_ids.push(
                fork_b
                    .append(
                        EntryKind::Outcome,
                        1,
                        [],
                        EntryPayload::Outcome(ledger_format::OutcomePayload {
                            schema: [0x00; 32],
                            value: ledger_format::CanonicalValue::Unsigned(i + 1000),
                        }),
                    )
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
            fork.append(
                EntryKind::Outcome,
                1,
                [],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: [0x00; 32],
                    value: ledger_format::CanonicalValue::Unsigned(i as u64),
                }),
            )
            .unwrap();
        }
        assert_eq!(fork.len(), extra);
        let last = fork.entries().last().unwrap();
        assert!(fork.get(&last.id).is_some());
        assert_eq!(fork.base_order().len(), OVERLAY_THRESHOLD * 2);
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
            fork.append(
                EntryKind::Outcome,
                1,
                [],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: [0x00; 32],
                    value: ledger_format::CanonicalValue::Unsigned(i as u64),
                }),
            )
            .unwrap();
        }
        assert_eq!(fork.len(), extra);
        assert_eq!(
            fork.base_order().len(),
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
            .append(
                EntryKind::Outcome,
                1,
                [],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: [0x00; 32],
                    value: ledger_format::CanonicalValue::Unsigned(0),
                }),
            )
            .unwrap();
        let mut fork = journal.fork();
        let id = fork
            .append(
                EntryKind::Outcome,
                1,
                [],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: [0x00; 32],
                    value: ledger_format::CanonicalValue::Unsigned(1),
                }),
            )
            .unwrap();
        let entry = fork.get(&id).unwrap();
        assert_eq!(entry.data.sequence, 1);
        assert_eq!(entry.vector_clock.get(1), 2);
    }
}
