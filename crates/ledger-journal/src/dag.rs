//! Content-addressed immutable causal DAG with a frozen base and a
//! post-fork overlay.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use hashbrown::{HashMap, HashSet};

use crate::clock::VectorClock;
use ledger_format::{
    ActorId, EntryData, EntryHash, EntryKind, EntryPayload, SequenceNumber,
    limits::MAX_PARENTS_PER_ENTRY,
};

/// Overlay entries before freeze. Bounds rebuild frequency vs transient size.
const OVERLAY_THRESHOLD: usize = 1024;

/// Error returned when a journal invariant is violated.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalError {
    /// A referenced parent is not present in the journal.
    MissingParent(EntryHash),
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
    /// Payload failed canonical encoding before hashing.
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
            Self::MissingParent(hash) => write!(f, "missing parent {:02x?}", &hash.0[..4]),
            Self::NonMonotonicSequence {
                actor,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "actor {} expected sequence {expected}, got {actual}",
                    actor.0
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

impl core::error::Error for JournalError {}

/// An immutable, content-addressed journal entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// BLAKE3 content address over the canonical encoding.
    pub id: EntryHash,
    /// The journal entry data covered by the content hash.
    pub data: EntryData,
    /// Happens-before summary at the time the entry was appended.
    pub vector_clock: VectorClock,
}

impl Entry {
    /// Construct a new entry, deriving its BLAKE3 content hash.
    pub fn new(data: EntryData, vector_clock: VectorClock) -> Result<Self, JournalError> {
        let mut encoded = data
            .try_canonical_bytes()
            .map_err(|err| JournalError::InvalidPayload(err.to_string()))?;
        encoded.extend_from_slice(&vector_clock.encode());
        let id = EntryHash(*blake3::hash(&encoded).as_bytes());
        Ok(Self {
            id,
            data,
            vector_clock,
        })
    }

    /// Construct a new entry into a caller-provided scratch buffer.
    pub fn new_with_scratch(
        data: EntryData,
        vector_clock: VectorClock,
        scratch: &mut Vec<u8>,
    ) -> Result<Self, JournalError> {
        Ok(Self::new_with_scratch_recorded(data, vector_clock, scratch)?.0)
    }

    /// [`Self::new_with_scratch`] plus the canonical `EntryData` prefix length.
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
        let id = EntryHash(*blake3::hash(&*scratch).as_bytes());
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
#[derive(Debug, Clone)]
pub(crate) struct JournalState {
    pub(crate) base: Arc<HashMap<EntryHash, Arc<Entry>>>,
    pub(crate) overlay: HashMap<EntryHash, Arc<Entry>>,
    pub(crate) heads: HashMap<ActorId, EntryHash>,
    pub(crate) order: Arc<Vec<EntryHash>>,
    pub(crate) overlay_order: Vec<EntryHash>,
}

impl JournalState {
    /// Freeze the overlay into the base. Deferred while shared so post-fork
    /// appends never pay an O(#entries) rebase.
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
#[derive(Debug, Clone)]
pub struct BatchEntry {
    /// Journal event kind.
    pub kind: EntryKind,
    /// Appending actor.
    pub actor: ActorId,
    /// Observed external parents known before the batch starts.
    pub observed_parents: Vec<EntryHash>,
    /// Append the previous batch entry id as trailing parent.
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
#[derive(Debug, Clone)]
pub struct EntryFrame {
    /// Content address of the encoded entry.
    pub id: EntryHash,
    /// Byte length of the canonical `EntryData` prefix of `payload`.
    pub data_len: usize,
    /// Canonical `data || vector_clock` bytes.
    pub payload: Vec<u8>,
    /// True when the entry kind belongs to the fault-relevant set.
    pub fault_relevant: bool,
}

/// Return true when a kind belongs to the fault-relevant set.
pub(crate) fn kind_is_fault_relevant(kind: &EntryKind) -> bool {
    matches!(
        kind,
        EntryKind::Fault | EntryKind::Outcome | EntryKind::Assert
    )
}

fn state_lookup<'a>(state: &'a JournalState, id: &EntryHash) -> Option<&'a Entry> {
    state
        .overlay
        .get(id)
        .or_else(|| state.base.get(id))
        .map(Arc::as_ref)
}

/// Assemble ordered parents with O(n) dedup, first occurrence wins.
/// Fails closed with `InvalidPayload` over the format cap.
fn assemble_parents(
    head: Option<EntryHash>,
    observed: impl IntoIterator<Item = EntryHash>,
    chain: Option<EntryHash>,
) -> Result<Vec<EntryHash>, JournalError> {
    let mut seen = HashSet::new();
    let mut parents = Vec::new();
    if let Some(previous) = head {
        seen.insert(previous);
        parents.push(previous);
    }
    for parent in observed {
        if seen.insert(parent) {
            if parents.len() >= MAX_PARENTS_PER_ENTRY {
                return Err(JournalError::InvalidPayload(
                    "parent count exceeds format limit".to_string(),
                ));
            }
            parents.push(parent);
        }
    }
    if let Some(chained) = chain
        && seen.insert(chained)
    {
        if parents.len() >= MAX_PARENTS_PER_ENTRY {
            return Err(JournalError::InvalidPayload(
                "parent count exceeds format limit".to_string(),
            ));
        }
        parents.push(chained);
    }
    Ok(parents)
}

/// An append-only in-memory journal view. Forks share immutable entries.
#[derive(Debug, Clone)]
pub struct Journal {
    pub(crate) state: Arc<JournalState>,
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
    pub fn append(
        &mut self,
        kind: EntryKind,
        actor: ActorId,
        observed_parents: impl IntoIterator<Item = EntryHash>,
        payload: EntryPayload,
    ) -> Result<EntryHash, JournalError> {
        let previous_head = self.state.heads.get(&actor).copied();
        let parents_vec = assemble_parents(previous_head, observed_parents, None)?;
        let (sequence, head_entry) = match previous_head {
            Some(head) => {
                let entry = self.get(&head).ok_or(JournalError::MissingParent(head))?;
                (
                    SequenceNumber(entry.data.sequence.0.saturating_add(1)),
                    Some(entry),
                )
            }
            None => (SequenceNumber(0), None),
        };

        let mut clock = VectorClock::default();
        if parents_vec.len() == 1 {
            if let Some(entry) = head_entry {
                clock = entry.vector_clock.clone();
            } else {
                let entry = self
                    .get(&parents_vec[0])
                    .ok_or(JournalError::MissingParent(parents_vec[0]))?;
                clock = entry.vector_clock.clone();
            }
        } else if !parents_vec.is_empty() {
            for parent in &parents_vec {
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
            parents: parents_vec.into_iter().collect(),
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

    /// Append entries in order, returning their content addresses.
    ///
    /// Byte-identical to looping [`Journal::append`]. Stops at the first
    /// invalid payload, leaving the applied prefix in place.
    pub fn append_batch(&mut self, batch: Vec<BatchEntry>) -> Result<Vec<EntryHash>, JournalError> {
        self.append_batch_impl(batch, None)
    }

    /// [`Journal::append_batch`] plus the canonical frame payload per entry.
    #[cfg(feature = "std")]
    pub(crate) fn append_batch_with_frames(
        &mut self,
        batch: Vec<BatchEntry>,
        frames: &mut Vec<EntryFrame>,
    ) -> Result<Vec<EntryHash>, JournalError> {
        frames.reserve(batch.len());
        self.append_batch_impl(batch, Some(frames))
    }

    fn append_batch_impl(
        &mut self,
        batch: Vec<BatchEntry>,
        mut frames: Option<&mut Vec<EntryFrame>>,
    ) -> Result<Vec<EntryHash>, JournalError> {
        let count = batch.len();
        let mut ids = Vec::with_capacity(count);
        if count == 0 {
            return Ok(ids);
        }

        let state = Arc::make_mut(&mut self.state);
        state.overlay.reserve(count);
        state.overlay_order.reserve(count);

        for spec in batch {
            let previous_head = state.heads.get(&spec.actor).copied();

            let chain = if spec.chain_previous {
                ids.last().copied()
            } else {
                None
            };
            let parents_vec =
                assemble_parents(previous_head, spec.observed_parents.iter().copied(), chain)?;

            let head_info: Option<(SequenceNumber, VectorClock)> = match previous_head {
                Some(head) => {
                    let entry =
                        state_lookup(state, &head).ok_or(JournalError::MissingParent(head))?;
                    Some((entry.data.sequence, entry.vector_clock.clone()))
                }
                None => None,
            };
            let sequence = match &head_info {
                Some((previous_sequence, _)) => {
                    SequenceNumber(previous_sequence.0.saturating_add(1))
                }
                None => SequenceNumber(0),
            };

            let mut clock = VectorClock::default();
            if parents_vec.len() == 1 {
                if previous_head.is_some() {
                    clock = head_info.map_or_else(VectorClock::new, |(_, c)| c);
                } else {
                    let entry = state_lookup(state, &parents_vec[0])
                        .ok_or(JournalError::MissingParent(parents_vec[0]))?;
                    clock = entry.vector_clock.clone();
                }
            } else if !parents_vec.is_empty() {
                for parent in &parents_vec {
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
                parents: parents_vec.into_iter().collect(),
                vector_clock: Vec::new(),
                sequence,
                payload: spec.payload,
            };

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

        if state.overlay.len() >= OVERLAY_THRESHOLD {
            state.freeze_overlay();
        }
        Ok(ids)
    }

    /// Look up an entry by content address (overlay before base).
    pub fn get(&self, id: &EntryHash) -> Option<&Entry> {
        self.state
            .overlay
            .get(id)
            .or_else(|| self.state.base.get(id))
            .map(Arc::as_ref)
    }

    pub(crate) fn get_arc(&self, id: &EntryHash) -> Option<Arc<Entry>> {
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

    /// Return up to `count` trailing entry ids in chronological order.
    pub fn tail_ids(&self, count: usize) -> Vec<EntryHash> {
        let total = self.state.order.len() + self.state.overlay_order.len();
        let skip = total.saturating_sub(count);
        self.state
            .order
            .iter()
            .chain(self.state.overlay_order.iter())
            .skip(skip)
            .copied()
            .collect()
    }

    /// Return the last entry, if any.
    pub fn last(&self) -> Option<&Entry> {
        let id = self.state.overlay_order.last().or(self.state.order.last());
        id.and_then(|id| self.get(id))
    }

    /// Return the head entry hash for a specific actor.
    pub fn head_for_actor(&self, actor: ActorId) -> Option<EntryHash> {
        self.state.heads.get(&actor).copied()
    }

    /// Return a root hash for the current ordered view.
    pub fn root_hash(&self) -> EntryHash {
        let mut hasher = blake3::Hasher::new();
        for id in self
            .state
            .order
            .iter()
            .chain(self.state.overlay_order.iter())
        {
            hasher.update(&id.0);
        }
        EntryHash(*hasher.finalize().as_bytes())
    }

    /// Return the frozen base order (overlay excluded).
    pub fn base_order(&self) -> &[EntryHash] {
        &self.state.order
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use ledger_format::{ActorId, EntryHash, EntryPayload, SequenceNumber};

    #[test]
    fn append_rejects_non_canonical_payload_without_hashing() {
        let mut journal = Journal::new();
        let bad_payload = EntryPayload::Outcome(ledger_format::OutcomePayload {
            schema: EntryHash([0x00; 32]),
            value: ledger_format::CanonicalValue::Float(f64::NAN),
        });
        let result = journal.append(EntryKind::Outcome, ActorId(1), [], bad_payload);
        assert!(matches!(result, Err(JournalError::InvalidPayload(_))));
        assert!(journal.is_empty());
    }

    #[test]
    fn append_rejects_disallowed_tag_without_hashing() {
        let mut journal = Journal::new();
        let bad_payload = EntryPayload::Outcome(ledger_format::OutcomePayload {
            schema: EntryHash([0x00; 32]),
            value: ledger_format::CanonicalValue::Float(f64::NAN),
        });
        let result = journal.append(EntryKind::Outcome, ActorId(1), [], bad_payload);
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
                        ActorId(1),
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
                        ActorId(1),
                        [],
                        EntryPayload::Outcome(ledger_format::OutcomePayload {
                            schema: EntryHash([0x00; 32]),
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
                        ActorId(1),
                        [],
                        EntryPayload::Outcome(ledger_format::OutcomePayload {
                            schema: EntryHash([0x00; 32]),
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
                ActorId(1),
                [],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: EntryHash([0x00; 32]),
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
                ActorId(1),
                [],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: EntryHash([0x00; 32]),
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
                ActorId(1),
                [],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: EntryHash([0x00; 32]),
                    value: ledger_format::CanonicalValue::Unsigned(0),
                }),
            )
            .unwrap();
        let mut fork = journal.fork();
        let id = fork
            .append(
                EntryKind::Outcome,
                ActorId(1),
                [],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: EntryHash([0x00; 32]),
                    value: ledger_format::CanonicalValue::Unsigned(1),
                }),
            )
            .unwrap();
        let entry = fork.get(&id).unwrap();
        assert_eq!(entry.data.sequence, SequenceNumber(1));
        assert_eq!(entry.vector_clock.get(ActorId(1)), 2);
    }

    fn outcome_payload(value: u64) -> EntryPayload {
        EntryPayload::Outcome(ledger_format::OutcomePayload {
            schema: EntryHash([0x00; 32]),
            value: ledger_format::CanonicalValue::Unsigned(value),
        })
    }

    #[test]
    fn wide_entry_dedups_in_order_without_quadratic_scan() {
        let mut journal = Journal::new();
        let mut bases = Vec::new();
        for i in 0..512 {
            bases.push(
                journal
                    .append(
                        EntryKind::Outcome,
                        ActorId((i % 8) as u32 + 10),
                        [],
                        outcome_payload(i),
                    )
                    .unwrap(),
            );
        }
        let mut observed = Vec::with_capacity(1026);
        observed.extend(bases.iter().copied());
        observed.extend(bases.iter().copied());
        observed.push(bases[0]);
        let head = journal.head_for_actor(ActorId(10)).unwrap();
        observed.push(head);
        let wide = journal
            .append(
                EntryKind::Outcome,
                ActorId(99),
                observed,
                outcome_payload(9999),
            )
            .unwrap();
        let entry = journal.get(&wide).unwrap();
        assert_eq!(entry.data.parents.len(), 512);
        assert_eq!(entry.data.parents.as_slice(), bases.as_slice());
        let mut seen = HashSet::new();
        for parent in &entry.data.parents {
            assert!(seen.insert(*parent), "parents must be deduped");
        }
        let mut journal_b = Journal::new();
        let mut bases_b = Vec::new();
        for i in 0..512 {
            bases_b.push(
                journal_b
                    .append(
                        EntryKind::Outcome,
                        ActorId((i % 8) as u32 + 10),
                        [],
                        outcome_payload(i),
                    )
                    .unwrap(),
            );
        }
        assert_eq!(bases_b, bases);
        let mut observed_b = Vec::with_capacity(1026);
        observed_b.extend(bases_b.iter().copied());
        observed_b.extend(bases_b.iter().copied());
        observed_b.push(bases_b[0]);
        observed_b.push(journal_b.head_for_actor(ActorId(10)).unwrap());
        let batch_ids = journal_b
            .append_batch(vec![BatchEntry {
                kind: EntryKind::Outcome,
                actor: ActorId(99),
                observed_parents: observed_b,
                chain_previous: false,
                payload: outcome_payload(9999),
            }])
            .unwrap();
        assert_eq!(batch_ids[0], wide);
        assert_eq!(
            journal_b.get(&wide).unwrap().data.parents.as_slice(),
            entry.data.parents.as_slice()
        );
    }

    #[test]
    fn parent_count_over_cap_fails_closed() {
        let mut journal = Journal::new();
        let mut observed = Vec::new();
        for i in 0..(MAX_PARENTS_PER_ENTRY + 1) {
            let mut raw = [0u8; 32];
            raw[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            raw[8] = 0xab;
            observed.push(EntryHash(raw));
        }
        let result = journal.append(EntryKind::Outcome, ActorId(1), observed, outcome_payload(0));
        assert!(
            matches!(result, Err(JournalError::InvalidPayload(_))),
            "parent overflow must fail closed, got {result:?}"
        );
        assert!(journal.is_empty());
    }
}
