//! Layered storage crash model with write provenance and corruption operators.

use ledger_format::{EntryKind, EntryPayload, Hash, PathRef};
use ledger_journal::{Journal, JournalError};
use std::collections::{BTreeMap, HashSet};

/// Builds a canonical path reference for a string path.
///
/// CONSUMER DEBT (lane 2): the sim binds the canonical path hash through
/// the journal's BLAKE3 helper once that lands; the deterministic zero hash
/// keeps lane-1 journals byte-stable.
fn path_ref(path: &str) -> PathRef {
    let canonical =
        ledger_format::canonicalize(path.as_bytes()).unwrap_or_else(|_| path.as_bytes().to_vec());
    PathRef {
        path_hash: [0x00; 32],
        canonical_path: canonical,
    }
}

/// Crash operators modeling failure modes in storage subsystems.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrashOperator {
    /// Drop all dirty, unsynced writes.
    DropAllUnsynced,
    /// Drop an adversarial subset of dirty paths.
    // ledger-lint:allow:HashSet (apply_crash_operator sorts the subset
    // before iterating, so restore order is deterministic)
    DropSubset(HashSet<String>),
    /// Simulate a torn write by persisting a truncated/partial value.
    TornWrite { path: String, partial_value: u64 },
    /// Corrupt stored bits at a specific path.
    BitFlipCorruption { path: String, xor_mask: u64 },
    /// Torn write at sector granularity: only a prefix of the write's sectors
    /// commit to storage.
    TornWriteSectors {
        /// Path of the torn write.
        path: String,
        /// Number of sectors committed before the crash.
        sectors_committed: u64,
        /// Total sectors the write spans. Must be at least 1.
        total_sectors: u64,
    },
    /// Flip a deterministic bit pattern across a sector range.
    CorruptRange {
        /// Path whose stored value is corrupted.
        path: String,
        /// First affected sector.
        start_sector: u64,
        /// Number of affected sectors.
        sector_count: u64,
        /// Bytes per sector.
        sector_size: u64,
    },
}

/// Page-level state in simulated storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageState {
    Clean,
    Dirty,
    /// Page allocated as zero-fill but not yet written by the workload.
    Allocated,
}

/// Journaling file-system emulation mode.
///
/// - Writeback: data writes may survive a crash without fsync; metadata does not.
/// - Ordered: data commits before metadata; unfsynced journaled writes are lost.
/// - Data: data and metadata commit together on fsync; unfsynced writes are lost.
#[cfg(feature = "sim-fs-journaling")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum JournalingMode {
    Writeback,
    Ordered,
    #[default]
    Data,
}

/// A layered storage simulator supporting fsync boundaries and crash operators.
#[derive(Debug, Default)]
pub struct SimFs {
    values: BTreeMap<String, (u64, Hash, PageState)>,
    synced: BTreeMap<String, (u64, Hash)>,
    /// Pending journaled writes that replay on fsync.
    #[cfg(feature = "sim-fs-journaling")]
    journal: BTreeMap<String, (u64, Hash)>,
    /// Pending metadata-only renames that commit on fsync.
    #[cfg(feature = "sim-fs-journaling")]
    pending_renames: BTreeMap<String, String>,
    #[cfg(feature = "sim-fs-journaling")]
    journal_mode: JournalingMode,
}

impl SimFs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Write a value to the page cache and record its causal write event.
    pub fn write(
        &mut self,
        journal: &mut Journal,
        actor: u32,
        path: &str,
        value: u64,
    ) -> Result<Hash, JournalError> {
        let id = journal.append(
            EntryKind::FsWrite,
            actor,
            [],
            EntryPayload::FsWrite(ledger_format::FsWritePayload::Write {
                path_ref: path_ref(path),
                offset: 0,
                content: value.to_le_bytes().to_vec(),
            }),
        )?;
        self.values
            .insert(path.to_owned(), (value, id, PageState::Dirty));
        #[cfg(feature = "sim-fs-journaling")]
        self.journal.insert(path.to_owned(), (value, id));
        Ok(id)
    }

    /// Allocate a zero-filled page in the page cache.
    ///
    /// The allocation journals an `FsWrite` entry with a zero value (the
    /// write id proves the causal write event). Reads of an allocated page
    /// return `Ok(None)` as if the page were not yet written; `fsync` flushes
    /// the allocation to a durable zero.
    pub fn allocate(
        &mut self,
        journal: &mut Journal,
        actor: u32,
        path: &str,
    ) -> Result<Hash, JournalError> {
        let id = journal.append(
            EntryKind::FsWrite,
            actor,
            [],
            EntryPayload::FsWrite(ledger_format::FsWritePayload::Allocate {
                path_ref: path_ref(path),
            }),
        )?;
        self.values
            .insert(path.to_owned(), (0, id, PageState::Allocated));
        #[cfg(feature = "sim-fs-journaling")]
        self.journal.insert(path.to_owned(), (0, id));
        Ok(id)
    }

    /// Flush all dirty page-cache entries to durable synced storage.
    ///
    /// Under journaling the journal replays first: committed records become
    /// durable, then pending renames commit, then dirty pages flush.
    pub fn fsync(&mut self, journal: &mut Journal, actor: u32) -> Result<Hash, JournalError> {
        // The store-level barrier persists every dirty file; the root path is
        // the canonical identity of that barrier.
        let id = journal.append(
            EntryKind::FsFsync,
            actor,
            [],
            EntryPayload::FsFsync(ledger_format::FsSyncPayload {
                path_ref: path_ref("/"),
            }),
        )?;
        #[cfg(feature = "sim-fs-journaling")]
        {
            for (path, (value, write_id)) in &self.journal {
                self.synced.insert(path.clone(), (*value, *write_id));
            }
            self.journal.clear();
            let renames = core::mem::take(&mut self.pending_renames);
            for (from, to) in renames {
                if let Some((value, write_id)) = self.synced.remove(&from) {
                    self.synced.insert(to, (value, write_id));
                }
            }
        }
        for (path, (val, write_id, state)) in &mut self.values {
            *state = PageState::Clean;
            self.synced.insert(path.clone(), (*val, *write_id));
        }
        Ok(id)
    }

    /// Read a value from page cache, recording provenance of the observed write.
    ///
    /// An allocated-but-unwritten page reads as absent: the read journals no
    /// observed write parent.
    pub fn read(
        &self,
        journal: &mut Journal,
        actor: u32,
        path: &str,
    ) -> Result<Option<u64>, JournalError> {
        match self.values.get(path) {
            Some(&(value, write_id, state)) if state != PageState::Allocated => {
                journal.append(
                    EntryKind::FsRead,
                    actor,
                    [write_id],
                    EntryPayload::FsRead(ledger_format::FsReadPayload {
                        path_ref: path_ref(path),
                        offset: 0,
                        requested_len: 1,
                        observed: ledger_format::ObservedRead::Present {
                            content: value.to_le_bytes().to_vec(),
                        },
                    }),
                )?;
                Ok(Some(value))
            }
            _ => {
                journal.append(
                    EntryKind::FsRead,
                    actor,
                    [],
                    EntryPayload::FsRead(ledger_format::FsReadPayload {
                        path_ref: path_ref(path),
                        offset: 0,
                        requested_len: 1,
                        observed: ledger_format::ObservedRead::Missing,
                    }),
                )?;
                Ok(None)
            }
        }
    }

    /// Rename a path (fsync-less by default).
    ///
    /// Journals an `FsWrite` entry carrying the target path. Without
    /// journaling the rename is immediate and durable. Under journaling the
    /// page-cache entry moves immediately but the durable rename commits only
    /// on fsync; a `crash_journaled` without an intervening fsync loses the
    /// rename and the original path keeps its value.
    pub fn rename(
        &mut self,
        journal: &mut Journal,
        actor: u32,
        from: &str,
        to: &str,
    ) -> Result<Hash, JournalError> {
        let id = journal.append(
            EntryKind::FsWrite,
            actor,
            [],
            EntryPayload::FsWrite(ledger_format::FsWritePayload::Rename {
                from_path_ref: path_ref(from),
                to_path_ref: path_ref(to),
            }),
        )?;
        if let Some((value, write_id, state)) = self.values.remove(from) {
            self.values.insert(to.to_owned(), (value, write_id, state));
        }
        #[cfg(feature = "sim-fs-journaling")]
        {
            self.pending_renames.insert(from.to_owned(), to.to_owned());
        }
        #[cfg(not(feature = "sim-fs-journaling"))]
        {
            if let Some((value, write_id)) = self.synced.remove(from) {
                self.synced.insert(to.to_owned(), (value, write_id));
            }
        }
        Ok(id)
    }

    /// Append a value to a path with O_APPEND semantics that can tear.
    ///
    /// Journals an `FsWrite` entry carrying the appended value. Without
    /// journaling the append behaves like a normal dirty write and a crash
    /// drops it. Under journaling a crash persists only `value / 2` of the
    /// appended amount; an fsync persists the full append.
    pub fn append_tear(
        &mut self,
        journal: &mut Journal,
        actor: u32,
        path: &str,
        value: u64,
    ) -> Result<Hash, JournalError> {
        let id = journal.append(
            EntryKind::FsWrite,
            actor,
            [],
            EntryPayload::FsWrite(ledger_format::FsWritePayload::Write {
                path_ref: path_ref(path),
                offset: 0,
                content: value.to_le_bytes().to_vec(),
            }),
        )?;
        let current = self.values.get(path).map_or(0, |(value, _, _)| *value);
        let full = current.saturating_add(value);
        self.values
            .insert(path.to_owned(), (full, id, PageState::Dirty));
        #[cfg(feature = "sim-fs-journaling")]
        {
            let torn = full.saturating_sub(value.saturating_div(2));
            self.synced.insert(path.to_owned(), (torn, id));
        }
        Ok(id)
    }

    /// Execute a standard crash by resetting all dirty writes to last fsynced state.
    pub fn crash(&mut self) {
        self.apply_crash_operator(&CrashOperator::DropAllUnsynced);
    }

    /// Replay the journal and apply the crash model for the configured mode.
    ///
    /// In Writeback mode journaled data writes survive the crash. In Data and
    /// Ordered modes unfsynced journaled writes are lost. Pending renames
    /// never survive without fsync.
    #[cfg(feature = "sim-fs-journaling")]
    pub fn crash_journaled(&mut self) {
        if self.journal_mode == JournalingMode::Writeback {
            for (path, (value, write_id)) in &self.journal {
                self.synced.insert(path.clone(), (*value, *write_id));
            }
        }
        self.journal.clear();
        self.pending_renames.clear();
        self.apply_crash_operator(&CrashOperator::DropAllUnsynced);
    }

    #[cfg(feature = "sim-fs-journaling")]
    pub fn set_journaling_mode(&mut self, mode: JournalingMode) {
        self.journal_mode = mode;
    }

    /// Apply an explicit crash operator to simulate arbitrary crash states.
    ///
    /// A crash terminates the journaling session: the write-ahead journal and
    /// any pending renames are discarded, matching real journaling file systems
    /// where an uncommitted transaction is dropped on replay. When the
    /// `sim-fs-journaling` feature is off this is a no-op for the journal.
    pub fn apply_crash_operator(&mut self, op: &CrashOperator) {
        #[cfg(feature = "sim-fs-journaling")]
        {
            self.journal.clear();
            self.pending_renames.clear();
        }
        match op {
            CrashOperator::DropAllUnsynced => {
                self.values = self
                    .synced
                    .iter()
                    .map(|(k, (v, h))| (k.clone(), (*v, *h, PageState::Clean)))
                    .collect();
            }
            CrashOperator::DropSubset(paths_to_drop) => {
                // HashSet order must not choose the restore sequence; sort
                // so the crash operator stays deterministic even if the
                // loop ever grows journaled steps.
                let mut ordered: Vec<&String> = paths_to_drop.iter().collect();
                ordered.sort();
                for path in ordered {
                    if let Some((synced_val, synced_hash)) = self.synced.get(path) {
                        self.values
                            .insert(path.clone(), (*synced_val, *synced_hash, PageState::Clean));
                    } else {
                        self.values.remove(path);
                    }
                }
            }
            CrashOperator::TornWrite {
                path,
                partial_value,
            } => {
                if let Some(entry) = self.values.get_mut(path) {
                    entry.0 = *partial_value;
                }
            }
            CrashOperator::BitFlipCorruption { path, xor_mask } => {
                if let Some(entry) = self.values.get_mut(path) {
                    entry.0 ^= *xor_mask;
                }
            }
            CrashOperator::TornWriteSectors {
                path,
                sectors_committed,
                total_sectors,
            } => {
                if let Some(entry) = self.values.get_mut(path)
                    && entry.2 == PageState::Dirty
                {
                    let divisor = (*total_sectors).max(1);
                    entry.0 = entry.0.saturating_mul(*sectors_committed) / divisor;
                }
            }
            CrashOperator::CorruptRange {
                path,
                start_sector,
                sector_count,
                sector_size,
            } => {
                if let Some(entry) = self.values.get_mut(path) {
                    entry.0 ^= sector_range_mask(*start_sector, *sector_count, *sector_size);
                }
            }
        }
    }
}

/// Build the deterministic byte mask for a sector range, clamped to the 8
/// bytes of a u64 value.
///
/// The mask covers bytes `[start_sector * sector_size,
/// (start_sector + sector_count) * sector_size)`. A range that begins at or
/// beyond byte 8 flips nothing because a u64 value has no such bytes.
fn sector_range_mask(start_sector: u64, sector_count: u64, sector_size: u64) -> u64 {
    let start_byte = start_sector.saturating_mul(sector_size);
    if start_byte >= 8 {
        return 0;
    }
    let length = sector_count.saturating_mul(sector_size);
    let end_byte = start_byte.saturating_add(length).min(8);
    let mut mask: u64 = 0;
    let mut byte = start_byte;
    while byte < end_byte {
        mask |= 0xFFu64 << (byte * 8);
        byte += 1;
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_journal::Journal;

    fn new_journal() -> Journal {
        Journal::new()
    }

    #[test]
    fn allocate_reads_as_absent_until_synced() {
        let mut journal = new_journal();
        let mut fs = SimFs::new();
        fs.allocate(&mut journal, 0, "k").unwrap();
        assert_eq!(fs.read(&mut journal, 0, "k").unwrap(), None);
        fs.fsync(&mut journal, 0).unwrap();
        assert_eq!(fs.read(&mut journal, 0, "k").unwrap(), Some(0));
    }

    #[test]
    fn torn_write_sectors_commits_prefix_only() {
        let mut journal = new_journal();
        let mut fs = SimFs::new();
        fs.write(&mut journal, 0, "k", 100).unwrap();
        fs.apply_crash_operator(&CrashOperator::TornWriteSectors {
            path: "k".into(),
            sectors_committed: 1,
            total_sectors: 2,
        });
        assert_eq!(fs.read(&mut journal, 0, "k").unwrap(), Some(50));

        let mut journal = new_journal();
        let mut fs = SimFs::new();
        fs.write(&mut journal, 0, "k", 100).unwrap();
        fs.apply_crash_operator(&CrashOperator::TornWriteSectors {
            path: "k".into(),
            sectors_committed: 0,
            total_sectors: 2,
        });
        assert_eq!(fs.read(&mut journal, 0, "k").unwrap(), Some(0));
    }

    #[test]
    fn corrupt_range_flips_in_range_bytes_only() {
        let mut journal = new_journal();
        let mut fs = SimFs::new();
        fs.write(&mut journal, 0, "k", 0xA5A5A5A5A5A5A5A5).unwrap();
        let original = fs.read(&mut journal, 0, "k").unwrap().unwrap();
        fs.apply_crash_operator(&CrashOperator::CorruptRange {
            path: "k".into(),
            start_sector: 0,
            sector_count: 1,
            sector_size: 4,
        });
        let corrupted = fs.read(&mut journal, 0, "k").unwrap().unwrap();
        assert_ne!(corrupted, original);
        // An out-of-range corruption leaves the value unchanged.
        fs.apply_crash_operator(&CrashOperator::CorruptRange {
            path: "k".into(),
            start_sector: 2,
            sector_count: 1,
            sector_size: 4,
        });
        assert_eq!(fs.read(&mut journal, 0, "k").unwrap().unwrap(), corrupted);
    }
}

#[cfg(all(test, feature = "sim-fs-journaling"))]
mod journaling_tests {
    use super::*;
    use ledger_journal::Journal;

    fn new_journal() -> Journal {
        Journal::new()
    }

    #[test]
    fn journaling_data_mode_loses_unfsynced_writes_on_crash() {
        let mut journal = new_journal();
        let mut fs = SimFs::new();
        fs.write(&mut journal, 0, "k", 7).unwrap();
        fs.crash_journaled();
        assert_eq!(fs.read(&mut journal, 0, "k").unwrap(), None);
    }

    #[test]
    fn journaling_writeback_persists_writes() {
        let mut journal = new_journal();
        let mut fs = SimFs::new();
        fs.set_journaling_mode(JournalingMode::Writeback);
        fs.write(&mut journal, 0, "k", 7).unwrap();
        fs.crash_journaled();
        assert_eq!(fs.read(&mut journal, 0, "k").unwrap(), Some(7));
    }

    #[test]
    fn journaling_rename_needs_fsync() {
        let mut journal = new_journal();
        let mut fs = SimFs::new();
        fs.write(&mut journal, 0, "a", 5).unwrap();
        fs.fsync(&mut journal, 0).unwrap();
        fs.rename(&mut journal, 0, "a", "b").unwrap();
        fs.crash_journaled();
        assert_eq!(fs.read(&mut journal, 0, "a").unwrap(), Some(5));
        assert_eq!(fs.read(&mut journal, 0, "b").unwrap(), None);

        let mut journal = new_journal();
        let mut fs = SimFs::new();
        fs.write(&mut journal, 0, "a", 5).unwrap();
        fs.fsync(&mut journal, 0).unwrap();
        fs.rename(&mut journal, 0, "a", "b").unwrap();
        fs.fsync(&mut journal, 0).unwrap();
        fs.crash_journaled();
        assert_eq!(fs.read(&mut journal, 0, "a").unwrap(), None);
        assert_eq!(fs.read(&mut journal, 0, "b").unwrap(), Some(5));
    }

    #[test]
    fn journaling_append_can_tear() {
        let mut journal = new_journal();
        let mut fs = SimFs::new();
        fs.append_tear(&mut journal, 0, "f", 100).unwrap();
        fs.crash_journaled();
        assert_eq!(fs.read(&mut journal, 0, "f").unwrap(), Some(50));

        let mut journal = new_journal();
        let mut fs = SimFs::new();
        fs.append_tear(&mut journal, 0, "f", 100).unwrap();
        fs.fsync(&mut journal, 0).unwrap();
        fs.crash_journaled();
        assert_eq!(fs.read(&mut journal, 0, "f").unwrap(), Some(100));
    }

    /// A raw crash operator (the executor's swarm path) must also discard the
    /// write-ahead journal: an unfsynced write must not resurrect on a later
    /// fsync, matching real journaling semantics (jbd2 discards uncommitted
    /// transactions on replay).
    #[test]
    fn crash_operator_discards_unfsynced_journaled_writes() {
        let mut journal = new_journal();
        let mut fs = SimFs::new();
        fs.write(&mut journal, 0, "k", 7).unwrap();
        fs.apply_crash_operator(&CrashOperator::DropAllUnsynced);
        fs.fsync(&mut journal, 0).unwrap();
        assert_eq!(
            fs.read(&mut journal, 0, "k").unwrap(),
            None,
            "the crash must discard the journal so fsync cannot resurrect the write"
        );
    }
}
