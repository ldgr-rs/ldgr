//! Durable facade over an in-memory [`Journal`] and a [`SegmentStore`].
// ledger-lint:allow (storage infrastructure uses the ambient filesystem by design, same as segment.rs)
//!
//! The in-memory journal is the authority for reads and for the DAG; the
//! segment store is the durable copy. Every append is written to both, so
//! ordering is identical in memory and on disk, and `open` rebuilds the DAG
//! by replaying persisted entries in append order.
//!
//! On append the journal runs first, then the store. A store I/O failure is
//! returned while the journal keeps the entry, so memory is never silently
//! behind disk. That failed entry is then absent from disk, the next append
//! references it as a parent, and the next `open` fails with `MissingParent`.
//! After a store append failure treat the facade as terminal: stop appending
//! and discard the journal.

use std::format;
use std::fs;
use std::path::PathBuf;
use std::string::ToString;
use std::vec::Vec;

use crate::dag::{Entry, Journal, JournalError};
use crate::monitor::{JournalCorrectnessMonitor, VerificationReport};
use crate::retention::RetentionClass;
use crate::segment::{SealedSegment, SegmentStore};
use crate::snapshot::{DEFAULT_SNAPSHOT_INTERVAL, Snapshot, SnapshotManager};
use crate::snapshot_store::SnapshotStore;
use ledger_format::{ActorId, EntryKind, Hash, Payload};

/// A journal that is both in-memory and durably persisted.
///
/// Reads and DAG operations delegate to the in-memory journal. The store
/// holds the durable copy, and periodic per-actor snapshots append to an
/// on-disk snapshot store.
#[derive(Debug)]
pub struct PersistentJournal {
    journal: Journal,
    store: SegmentStore,
    snapshots: SnapshotManager,
    snapshot_store: SnapshotStore,
}

impl PersistentJournal {
    /// Create a fresh store and an empty journal at `dir`.
    pub fn create(dir: impl Into<PathBuf>) -> Result<Self, JournalError> {
        Self::create_with_interval(dir, DEFAULT_SNAPSHOT_INTERVAL)
    }

    /// Create a fresh store and an empty journal with a snapshot interval.
    ///
    /// See [`SnapshotManager::should_snapshot`].
    pub fn create_with_interval(
        dir: impl Into<PathBuf>,
        interval: u64,
    ) -> Result<Self, JournalError> {
        let dir: PathBuf = dir.into();
        let store = SegmentStore::new(&dir)?;
        let snapshot_store = SnapshotStore::new(&dir)?;
        Ok(Self {
            journal: Journal::new(),
            store,
            snapshots: SnapshotManager::new(interval),
            snapshot_store,
        })
    }

    /// Open an existing store and reconstruct the journal from its entries.
    ///
    /// Snapshots are validated, then entries are replayed in append order
    /// through [`Journal::append`]. The replayed entry must reproduce the
    /// persisted id and vector clock; a mismatch means the store is
    /// inconsistent and the open fails instead of silently diverging.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, JournalError> {
        Self::open_with_interval(dir, DEFAULT_SNAPSHOT_INTERVAL)
    }

    /// Open an existing store with a snapshot interval for future recording.
    ///
    /// The interval does not affect the loaded snapshots; it only governs which
    /// appends record new snapshots after the open.
    pub fn open_with_interval(
        dir: impl Into<PathBuf>,
        interval: u64,
    ) -> Result<Self, JournalError> {
        let dir: PathBuf = dir.into();
        let mut snapshots = SnapshotManager::new(interval);
        for snapshot in SnapshotStore::load(&dir)? {
            snapshots.record_snapshot(snapshot);
        }
        let store = SegmentStore::load(&dir)?;
        let mut journal = Journal::new();
        for entry in store.entries_in_append_order()? {
            let id = journal.append(
                entry.data.kind,
                entry.data.actor,
                entry.data.parents.iter().copied(),
                entry.data.payload.clone(),
            )?;
            if id != entry.id {
                return Err(JournalError::InvariantViolation(format!(
                    "entry replayed as {:02x?} but persisted as {:02x?}",
                    &id[..4],
                    &entry.id[..4]
                )));
            }
            let replayed = journal.get(&id).ok_or_else(|| {
                JournalError::InvariantViolation("replayed entry missing from journal".to_string())
            })?;
            if replayed.vector_clock != entry.vector_clock {
                return Err(JournalError::InvariantViolation(format!(
                    "entry {:02x?} vector clock diverges on reload",
                    &id[..4]
                )));
            }
        }
        snapshots.validate_all(&journal)?;
        let snapshot_store = SnapshotStore::new(&dir)?;
        Ok(Self {
            journal,
            store,
            snapshots,
            snapshot_store,
        })
    }

    /// Fork this journal into a fresh directory, sharing sealed segments.
    ///
    /// Sealed segment files are hard-linked into `fork_dir`, so the fork
    /// aliases the parent's content by inode; the fallback is a byte copy
    /// (correct, not deduplicated). The fork gets its own manifest, WAL, and
    /// snapshot store. The parent's open-writer tail is re-framed into the
    /// fork's WAL so the fork's on-disk prefix covers every pre-fork entry.
    /// Snapshots are not inherited.
    pub fn fork(&self, fork_dir: impl Into<PathBuf>) -> Result<Self, JournalError> {
        let fork_dir: PathBuf = fork_dir.into();
        let journal = self.journal.fork();

        fs::create_dir_all(&fork_dir).map_err(journal_io)?;
        let parent_dir = self.store.dir();
        for segment in self.store.segments() {
            let name = segment.file_name();
            let dst = fork_dir.join(&name);
            if let Some(bytes) = self.store.archived_bytes(segment.id) {
                // An archived segment has no loose file in the parent; write
                // its verified bytes atomically (temp + rename).
                crate::segment::write_loose_file(&fork_dir, segment.id, bytes.as_slice())?;
            } else {
                let src = parent_dir.join(&name);
                if fs::hard_link(&src, &dst).is_err() {
                    fs::copy(&src, &dst).map_err(journal_io)?;
                }
            }
        }

        // Reopen the shared segments in the fork directory, then re-frame the
        // parent's open-writer tail so every pre-fork entry is durable here.
        let mut store = SegmentStore::load(&fork_dir)?;
        let sealed_count: u64 = self
            .store
            .segments()
            .iter()
            .map(|segment| segment.entry_count)
            .sum();
        for entry in self.journal.entries().skip(sealed_count as usize) {
            store.append(entry)?;
        }
        store.write_manifest()?;

        let snapshot_store = SnapshotStore::new(&fork_dir)?;
        Ok(Self {
            journal,
            store,
            snapshots: SnapshotManager::new(DEFAULT_SNAPSHOT_INTERVAL),
            snapshot_store,
        })
    }

    /// Append an entry to the journal and the store, returning its id.
    ///
    /// A journal validation failure leaves both sides unchanged. A store
    /// failure is returned while the journal keeps the entry; treat the
    /// facade as terminal then (see the module documentation).
    ///
    /// A snapshot is recorded at interval boundaries. The journal entry is
    /// durable before its snapshot, so a snapshot never references an entry
    /// absent from the store.
    pub fn append(
        &mut self,
        kind: EntryKind,
        actor: ActorId,
        observed_parents: impl IntoIterator<Item = Hash>,
        payload: Payload,
    ) -> Result<Hash, JournalError> {
        let id = self
            .journal
            .append(kind, actor, observed_parents, payload)?;
        let entry = self.journal.get(&id).ok_or_else(|| {
            JournalError::InvariantViolation("appended entry missing from journal".to_string())
        })?;
        self.store.append(entry)?;
        if self.snapshots.should_snapshot(actor, entry.data.sequence) {
            let snapshot = Snapshot::new(
                actor,
                entry.data.sequence,
                id,
                entry.vector_clock.clone(),
                Vec::new(),
            );
            self.snapshots.record_snapshot(snapshot.clone());
            self.snapshot_store.append(&snapshot)?;
        }
        Ok(id)
    }

    /// Look up an entry by content address in the in-memory journal.
    pub fn get(&self, id: &Hash) -> Option<&Entry> {
        self.journal.get(id)
    }

    /// Return the root hash over the ordered entry ids.
    pub fn root_hash(&self) -> Hash {
        self.journal.root_hash()
    }

    pub fn len(&self) -> usize {
        self.journal.len()
    }

    pub fn is_empty(&self) -> bool {
        self.journal.is_empty()
    }

    /// Return entries in append order.
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.journal.entries()
    }

    /// Seal the open writer into an immutable segment and reset the WAL.
    ///
    /// The store also seals automatically when the buffer reaches the target
    /// segment size.
    pub fn force_seal(&mut self) -> Result<(), JournalError> {
        self.store.seal_writer()
    }

    /// Return the current retention class.
    pub fn retention(&self) -> RetentionClass {
        self.store.retention()
    }

    /// Set the retention class and apply it to the store immediately.
    ///
    /// Retention is non-destructive; a store reopens byte-identically under
    /// every class.
    pub fn set_retention(&mut self, class: RetentionClass) -> Result<(), JournalError> {
        self.store.set_retention(class)
    }

    /// Persist the segment manifest describing all sealed segments.
    pub fn write_manifest(&self) -> Result<(), JournalError> {
        self.store.write_manifest()
    }

    /// Return the number of entries buffered in the open writer.
    pub fn buffered_count(&self) -> u64 {
        self.store.buffered_count()
    }

    /// Return the sealed segments in append order.
    pub fn segments(&self) -> &[SealedSegment] {
        self.store.segments()
    }

    /// Return the snapshot manager.
    pub fn snapshots(&self) -> &SnapshotManager {
        &self.snapshots
    }

    /// Audit the in-memory journal for structural and causal integrity.
    ///
    /// Delegates to [`JournalCorrectnessMonitor::verify`].
    pub fn verify(&self) -> Result<VerificationReport, JournalError> {
        JournalCorrectnessMonitor::verify(&self.journal)
    }
}

fn journal_io(err: std::io::Error) -> JournalError {
    JournalError::SegmentCorrupt(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::VectorClock;
    use ledger_format::EntryData;
    use std::vec;
    use std::vec::Vec;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ldgr-persistent-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn raw_entry(actor: ActorId, sequence: u64, parents: Vec<Hash>, clock: VectorClock) -> Entry {
        Entry::new(
            EntryData {
                kind: EntryKind::Outcome,
                actor,
                parents,
                vector_clock: Vec::new(),
                sequence,
                payload: Payload::Number(sequence),
            },
            clock,
        )
        .unwrap()
    }

    #[test]
    fn open_rejects_persisted_stream_with_missing_parent() {
        let dir = temp_dir("missing-parent");
        {
            let mut store = SegmentStore::new(&dir).unwrap();
            let first = raw_entry(1, 0, Vec::new(), VectorClock::from_map([(1, 1)]));
            let orphan = raw_entry(
                2,
                0,
                vec![[0xab; 32]],
                VectorClock::from_map([(1, 1), (2, 1)]),
            );
            store.append(&first).unwrap();
            store.append(&orphan).unwrap();
        }
        let result = PersistentJournal::open(&dir);
        assert!(
            matches!(result, Err(JournalError::MissingParent(_))),
            "replay must reject a parent absent from the store"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_rejects_vector_clock_divergence() {
        let dir = temp_dir("clock-divergence");
        {
            let mut store = SegmentStore::new(&dir).unwrap();
            let entry = Entry::new(
                EntryData {
                    kind: EntryKind::Outcome,
                    actor: 1,
                    parents: Vec::new(),
                    vector_clock: Vec::new(),
                    sequence: 0,
                    payload: Payload::Number(0),
                },
                VectorClock::from_map([(1, 7)]),
            )
            .unwrap();
            store.append(&entry).unwrap();
        }
        let result = PersistentJournal::open(&dir);
        assert!(
            matches!(result, Err(JournalError::InvariantViolation(_))),
            "replay must reject a clock the DAG cannot re-derive"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
