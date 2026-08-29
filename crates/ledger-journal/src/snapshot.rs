//! Actor checkpoint and snapshot manager.
//!
//! Each snapshot carries a BLAKE3 hash of its opaque state payload, so
//! on-disk corruption is detectable when the snapshot is loaded.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::clock::VectorClock;
use crate::dag::{Journal, JournalError};
#[cfg(any(feature = "std", test))]
use alloc::format;
#[cfg(any(feature = "std", test))]
use alloc::string::ToString;
#[cfg(any(feature = "std", test))]
use ledger_format::CborValue;
use ledger_format::{ActorId, Hash, cbor};

/// Default snapshot interval in entries per actor.
pub const DEFAULT_SNAPSHOT_INTERVAL: u64 = 100_000;

/// A point-in-time actor state snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Actor identity.
    pub actor: ActorId,
    /// Sequence number at snapshot time.
    pub sequence: u64,
    /// Content address of the corresponding journal entry.
    pub entry_id: Hash,
    /// Vector clock at snapshot time.
    pub vector_clock: VectorClock,
    /// BLAKE3 hash of `state_data`, used for corruption detection.
    pub state_hash: Hash,
    /// Opaque serialized state bytes.
    pub state_data: Vec<u8>,
}

impl Snapshot {
    /// Construct a snapshot, deriving the state hash from the payload.
    pub fn new(
        actor: ActorId,
        sequence: u64,
        entry_id: Hash,
        vector_clock: VectorClock,
        state_data: Vec<u8>,
    ) -> Self {
        let state_hash = *blake3::hash(&state_data).as_bytes();
        Self {
            actor,
            sequence,
            entry_id,
            vector_clock,
            state_hash,
            state_data,
        }
    }

    /// Validate the state hash against the recorded payload.
    pub fn validate(&self) -> Result<(), JournalError> {
        let recomputed = *blake3::hash(&self.state_data).as_bytes();
        if recomputed != self.state_hash {
            return Err(JournalError::SnapshotHashMismatch);
        }
        Ok(())
    }

    /// Encode the snapshot as deterministic canonical bytes.
    ///
    /// Field order is fixed and the vector clock encodes with ascending
    /// actor keys, so equal snapshots encode byte-for-byte identically.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        cbor::array(&mut out, 6);
        cbor::unsigned(&mut out, self.actor as u64);
        cbor::unsigned(&mut out, self.sequence);
        cbor::bytes(&mut out, &self.entry_id);
        cbor::bytes(&mut out, &self.vector_clock.encode());
        cbor::bytes(&mut out, &self.state_hash);
        cbor::bytes(&mut out, &self.state_data);
        out
    }

    /// Decode a snapshot from canonical bytes.
    ///
    /// Rejects non-canonical encodings. The state hash is not verified here;
    /// call [`Self::validate`] for that.
    #[cfg(any(feature = "std", test))]
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, JournalError> {
        let value = CborValue::from_canonical_bytes(bytes)
            .map_err(|err| JournalError::SnapshotStoreError(err.to_string()))?;
        let items = match value {
            CborValue::Array(items) => items,
            _ => {
                return Err(JournalError::SnapshotStoreError(
                    "snapshot encoding is not an array".into(),
                ));
            }
        };
        if items.len() != 6 {
            return Err(JournalError::SnapshotStoreError(
                "snapshot encoding has wrong item count".into(),
            ));
        }
        let actor = match &items[0] {
            CborValue::Unsigned(actor) => u32::try_from(*actor).map_err(|_| {
                JournalError::SnapshotStoreError("snapshot actor exceeds u32".into())
            })?,
            _ => {
                return Err(JournalError::SnapshotStoreError(
                    "snapshot actor is not an unsigned integer".into(),
                ));
            }
        };
        let sequence = match &items[1] {
            CborValue::Unsigned(sequence) => *sequence,
            _ => {
                return Err(JournalError::SnapshotStoreError(
                    "snapshot sequence is not an unsigned integer".into(),
                ));
            }
        };
        let entry_id = decode_hash(&items[2], "entry id")?;
        let vector_clock = match &items[3] {
            CborValue::Bytes(bytes) => decode_vector_clock(bytes)?,
            _ => {
                return Err(JournalError::SnapshotStoreError(
                    "snapshot vector clock is not bytes".into(),
                ));
            }
        };
        let state_hash = decode_hash(&items[4], "state hash")?;
        let state_data = match &items[5] {
            CborValue::Bytes(bytes) => bytes.clone(),
            _ => {
                return Err(JournalError::SnapshotStoreError(
                    "snapshot state data is not bytes".into(),
                ));
            }
        };
        Ok(Self {
            actor,
            sequence,
            entry_id,
            vector_clock,
            state_hash,
            state_data,
        })
    }
}

#[cfg(any(feature = "std", test))]
fn decode_hash(value: &CborValue, field: &str) -> Result<Hash, JournalError> {
    match value {
        CborValue::Bytes(bytes) if bytes.len() == 32 => {
            let mut hash = Hash::default();
            hash.copy_from_slice(bytes);
            Ok(hash)
        }
        _ => Err(JournalError::SnapshotStoreError(format!(
            "snapshot {field} is not a 32-byte hash"
        ))),
    }
}

#[cfg(any(feature = "std", test))]
fn decode_vector_clock(bytes: &[u8]) -> Result<VectorClock, JournalError> {
    let value = CborValue::from_canonical_bytes(bytes)
        .map_err(|err| JournalError::SnapshotStoreError(err.to_string()))?;
    let pairs = match value {
        CborValue::Map(pairs) => pairs,
        _ => {
            return Err(JournalError::SnapshotStoreError(
                "snapshot vector clock is not a CBOR map".into(),
            ));
        }
    };
    let mut entries = BTreeMap::new();
    for (key, val) in pairs {
        let actor = match key {
            CborValue::Unsigned(actor) => u32::try_from(actor).map_err(|_| {
                JournalError::SnapshotStoreError("vector clock actor exceeds u32".into())
            })?,
            _ => {
                return Err(JournalError::SnapshotStoreError(
                    "vector clock key is not an unsigned integer".into(),
                ));
            }
        };
        let count = match val {
            CborValue::Unsigned(count) => count,
            _ => {
                return Err(JournalError::SnapshotStoreError(
                    "vector clock value is not an unsigned integer".into(),
                ));
            }
        };
        entries.insert(actor, count);
    }
    Ok(VectorClock::from_map(entries))
}

/// Manages periodic snapshots across simulated actors.
#[derive(Debug, Clone)]
pub struct SnapshotManager {
    snapshots: BTreeMap<ActorId, Vec<Snapshot>>,
    snapshot_interval: u64,
}

impl Default for SnapshotManager {
    fn default() -> Self {
        Self::new(DEFAULT_SNAPSHOT_INTERVAL)
    }
}

impl SnapshotManager {
    /// Create a new snapshot manager with a given entry interval.
    pub fn new(interval: u64) -> Self {
        Self {
            snapshots: BTreeMap::new(),
            snapshot_interval: interval.max(1),
        }
    }

    /// Check whether an actor has reached a snapshot checkpoint.
    pub fn should_snapshot(&self, _actor: ActorId, current_seq: u64) -> bool {
        current_seq > 0 && current_seq.is_multiple_of(self.snapshot_interval)
    }

    /// Record a snapshot for an actor.
    pub fn record_snapshot(&mut self, snapshot: Snapshot) {
        self.snapshots
            .entry(snapshot.actor)
            .or_default()
            .push(snapshot);
    }

    /// Get the latest snapshot for an actor.
    pub fn latest_snapshot(&self, actor: ActorId) -> Option<&Snapshot> {
        self.snapshots.get(&actor).and_then(|list| list.last())
    }

    /// Return every recorded snapshot, oldest first per actor.
    pub fn all(&self) -> impl Iterator<Item = &Snapshot> {
        self.snapshots.values().flatten()
    }

    /// Validate every recorded snapshot against a journal.
    ///
    /// Each snapshot must reproduce its state hash and reference an existing
    /// journal entry.
    pub fn validate_all(&self, journal: &Journal) -> Result<(), JournalError> {
        for snapshots in self.snapshots.values() {
            for snapshot in snapshots {
                snapshot.validate()?;
                if journal.get(&snapshot.entry_id).is_none() {
                    return Err(JournalError::MissingParent(snapshot.entry_id));
                }
            }
        }
        Ok(())
    }

    /// Load and validate the latest snapshot for an actor.
    ///
    /// Fails with [`JournalError::SnapshotHashMismatch`] when the recorded
    /// state hash does not match the payload, or with
    /// [`JournalError::MissingParent`] when the referenced journal entry no
    /// longer exists.
    pub fn load(
        &self,
        journal: &Journal,
        actor: ActorId,
    ) -> Result<Option<&Snapshot>, JournalError> {
        let snapshot = match self.latest_snapshot(actor) {
            Some(snapshot) => snapshot,
            None => return Ok(None),
        };
        snapshot.validate()?;
        if journal.get(&snapshot.entry_id).is_none() {
            return Err(JournalError::MissingParent(snapshot.entry_id));
        }
        Ok(Some(snapshot))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag::Journal;
    use alloc::vec;
    use ledger_format::{EntryKind, EntryPayload};

    #[test]
    fn snapshot_hash_detects_corruption() {
        let snapshot = Snapshot::new(1, 7, Hash::default(), VectorClock::new(), vec![1, 2, 3, 4]);
        snapshot.validate().unwrap();

        let mut tampered = snapshot.clone();
        tampered.state_data = vec![1, 2, 3, 5];
        assert!(matches!(
            tampered.validate(),
            Err(JournalError::SnapshotHashMismatch)
        ));
    }

    #[test]
    fn load_validates_state_and_entry() {
        let mut journal = Journal::new();
        let entry_id = journal
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
        let mut manager = SnapshotManager::new(1);
        manager.record_snapshot(Snapshot::new(
            1,
            1,
            entry_id,
            VectorClock::new(),
            vec![9, 9],
        ));
        manager.load(&journal, 1).unwrap();

        let mut missing = manager.clone();
        missing.snapshots.get_mut(&1).unwrap()[0].entry_id = Hash::default();
        assert!(matches!(
            missing.load(&journal, 1),
            Err(JournalError::MissingParent(_))
        ));
    }

    #[test]
    fn interval_defaults_to_one_hundred_thousand() {
        let manager = SnapshotManager::default();
        assert!(!manager.should_snapshot(1, 99_999));
        assert!(manager.should_snapshot(1, 100_000));
    }

    #[test]
    fn canonical_bytes_round_trip() {
        let snapshot = Snapshot::new(
            1,
            7,
            Hash::default(),
            VectorClock::from_map([(1, 3), (9, 2)]),
            vec![1, 2, 3, 4],
        );
        let bytes = snapshot.to_canonical_bytes();
        let decoded = Snapshot::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded, snapshot);
        assert_eq!(decoded.to_canonical_bytes(), bytes);
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let snapshot = Snapshot::new(
            2,
            3,
            Hash::default(),
            VectorClock::from_map([(9, 1), (2, 1)]),
            vec![9, 9, 9],
        );
        assert_eq!(snapshot.to_canonical_bytes(), snapshot.to_canonical_bytes());
    }

    #[test]
    fn canonical_bytes_reject_wrong_field_count() {
        let snapshot = Snapshot::new(1, 1, Hash::default(), VectorClock::new(), vec![]);
        let mut bytes = snapshot.to_canonical_bytes();
        bytes[0] = 0x80; // six-item array becomes an empty array
        assert!(matches!(
            Snapshot::from_canonical_bytes(&bytes),
            Err(JournalError::SnapshotStoreError(_))
        ));
    }

    #[test]
    fn load_without_snapshot_returns_none() {
        let journal = Journal::new();
        let manager = SnapshotManager::default();
        assert!(manager.load(&journal, 3).unwrap().is_none());
    }
}
