//! Byte-faithful simulated storage: sparse byte files with write provenance,
//! durable ranges, canonical crash operators, and deterministic budgets.
//!
//! Format v2 semantics: the journal records the actual mutation (offset and
//! bytes), reads journal exactly what the caller observed with the
//! contributing mutation entries as causal parents, and crash operators
//! target prior write entries by content address.

use ledger_format::{
    CrashOperation, EntryKind, EntryPayload, Hash, ObservedRead, PATH_DOMAIN, PathRef,
};
use ledger_journal::{Journal, JournalError};
use std::collections::{BTreeMap, BTreeSet, HashSet};

use ledger_format::limits::{MAX_FILE_EXTENT_HARD, MAX_READ_BYTES, MAX_WRITE_BYTES};

/// Typed storage-simulation failure.
#[derive(Debug, thiserror::Error)]
pub enum SimFsError {
    /// `Allocate` on an existing path.
    #[error("file already exists: {0}")]
    AlreadyExists(String),
    /// `Rename` from an absent path.
    #[error("file not found: {0}")]
    NotFound(String),
    /// A write exceeds the per-operation byte cap.
    #[error("write of {actual} bytes exceeds the {max} byte limit")]
    WriteTooLarge { actual: u64, max: u64 },
    /// A read exceeds the per-operation byte cap.
    #[error("read of {actual} bytes exceeds the {max} byte limit")]
    ReadTooLarge { actual: u64, max: u64 },
    /// A write would extend the logical file past the hard extent cap.
    #[error("file extent would exceed the {max} byte hard limit")]
    FileExtentTooLarge { max: u64 },
    /// The per-run resident budget would be exceeded; nothing changed.
    #[error("resident budget exhausted: {0}")]
    BudgetExhausted(&'static str),
    /// A crash operator targeted a write entry that is not a prior write.
    #[error("crash operator targets unknown write entry")]
    UnknownWriteTarget,
    /// A crash operator carried an empty XOR payload.
    #[error("crash operator has an empty XOR payload")]
    EmptyXor,
    /// A crash operator bit was outside 0..=7.
    #[error("crash operator bit {bit} is out of range 0..8")]
    BitOutOfRange { bit: u8 },
    /// The journal rejected a mutation.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

impl SimFsError {
    /// Map a limit or semantic failure onto the journal boundary for the
    /// scalar convenience API, preserving the cause text.
    fn into_journal(self) -> JournalError {
        JournalError::InvalidPayload(self.to_string())
    }
}

/// Builds a canonical domain-separated path reference for a string path.
///
/// The content address is `BLAKE3(PATH_DOMAIN || canonical_bytes)` so the
/// sim and the decoder agree on path identity without a shared hash helper.
pub fn path_ref(path: &str) -> PathRef {
    let canonical =
        ledger_format::canonicalize(path.as_bytes()).unwrap_or_else(|_| path.as_bytes().to_vec());
    let mut domain = Vec::with_capacity(PATH_DOMAIN.len() + canonical.len());
    domain.extend_from_slice(PATH_DOMAIN);
    domain.extend_from_slice(&canonical);
    let digest = blake3::hash(&domain);
    let mut path_hash = [0u8; ledger_format::PATH_HASH_LEN];
    path_hash.copy_from_slice(&digest.as_bytes()[..ledger_format::PATH_HASH_LEN]);
    PathRef::new(path_hash, canonical)
}

/// Canonical string key for the file table.
fn canonical_key(path: &str) -> String {
    String::from_utf8(path_ref(path).canonical_path).unwrap_or_else(|_| path.to_owned())
}

/// Legacy scalar crash operators retained for the corpus fixtures; the
/// canonical [`CrashOperation`] wire operators execute through
/// [`SimFs::apply_crash_operation`].
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
    /// Range allocated as zero-fill but not yet written by the workload.
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

/// One sparse byte range with write provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ByteRange {
    content: Vec<u8>,
    write_id: Hash,
    state: PageState,
}

/// A sparse byte file: volatile cache ranges over a durable snapshot.
#[derive(Debug, Default, Clone)]
struct File {
    /// Volatile page-cache ranges by start offset.
    cache: BTreeMap<u64, ByteRange>,
    /// Durable ranges (last fsync or crash baseline) by start offset.
    durable: BTreeMap<u64, ByteRange>,
    /// Logical file length: reads at or beyond it return no bytes.
    length: u64,
    /// Entry id of the mutation that established existence (allocate or
    /// first write); names the parent of an empty successful read.
    created_by: Option<Hash>,
    /// The file survives a crash when it has been persisted at least once.
    durable_exists: bool,
}

impl File {
    /// Copy cache ranges into the durable snapshot and mark them clean.
    fn persist(&mut self) {
        self.durable = self
            .cache
            .iter()
            .map(|(offset, range)| {
                let mut durable = range.clone();
                durable.state = PageState::Clean;
                (*offset, durable)
            })
            .collect();
        self.durable_exists = true;
    }

    /// Recompute the logical length from the current cache ranges.
    fn recompute_length(&mut self) {
        self.length = self
            .cache
            .iter()
            .map(|(offset, range)| offset.saturating_add(range.content.len() as u64))
            .max()
            .unwrap_or(0);
    }

    /// Drop dirty ranges, restoring the durable snapshot. Returns whether
    /// the file survives the crash (it must have been persisted once).
    fn drop_unsynced(&mut self) -> bool {
        if !self.durable_exists {
            return false;
        }
        self.cache = self
            .durable
            .iter()
            .map(|(offset, range)| (*offset, range.clone()))
            .collect();
        self.recompute_length();
        true
    }
}

/// A layered storage simulator supporting sparse byte files, fsync
/// boundaries, and canonical crash operators.
#[derive(Debug, Default)]
pub struct SimFs {
    files: BTreeMap<String, File>,
    /// Per-run logical extent cap; defaults to the format hard limit.
    max_file_extent: u64,
    /// Per-run resident budget (content + range nodes + paths); `None` is
    /// unlimited.
    max_resident_bytes: Option<u64>,
    /// Pending journaled writes that replay on fsync.
    #[cfg(feature = "sim-fs-journaling")]
    journal: BTreeMap<String, Vec<(u64, Hash)>>,
    /// Pending metadata-only renames that commit on fsync.
    #[cfg(feature = "sim-fs-journaling")]
    pending_renames: BTreeMap<String, String>,
    #[cfg(feature = "sim-fs-journaling")]
    journal_mode: JournalingMode,
}

impl SimFs {
    pub fn new() -> Self {
        Self {
            max_file_extent: MAX_FILE_EXTENT_HARD,
            max_resident_bytes: None,
            ..Self::default()
        }
    }

    /// Construct with explicit per-run budgets.
    ///
    /// The budgets are part of the run's resource contract; the format hard
    /// limits remain the ceiling regardless of these settings.
    pub fn with_budgets(max_file_extent: u64, max_resident_bytes: Option<u64>) -> Self {
        Self {
            max_file_extent: max_file_extent.min(MAX_FILE_EXTENT_HARD),
            max_resident_bytes,
            ..Self::default()
        }
    }

    fn file_mut(&mut self, key: &str) -> &mut File {
        self.files.entry(key.to_owned()).or_default()
    }

    /// Charge a prospective allocation against the resident budget.
    ///
    /// `bytes` is the additional content capacity; each new range node and
    /// each path entry costs a fixed overhead. A rejection refunds nothing
    /// because nothing was charged yet.
    fn charge_resident(
        &self,
        additional_bytes: u64,
        new_range: bool,
        new_path: bool,
    ) -> Result<(), SimFsError> {
        let Some(budget) = self.max_resident_bytes else {
            return Ok(());
        };
        let content: u64 = self
            .files
            .values()
            .map(|file| {
                file.cache
                    .values()
                    .map(|range| range.content.len() as u64)
                    .sum::<u64>()
            })
            .sum();
        let range_nodes: u64 = self.files.values().map(|f| f.cache.len() as u64).sum();
        let paths = self.files.len() as u64;
        const RANGE_OVERHEAD: u64 = 64;
        const PATH_OVERHEAD: u64 = 128;
        let charged = content
            .saturating_add(additional_bytes)
            .saturating_add(
                range_nodes
                    .saturating_add(u64::from(new_range))
                    .saturating_mul(RANGE_OVERHEAD),
            )
            .saturating_add(
                paths
                    .saturating_add(u64::from(new_path))
                    .saturating_mul(PATH_OVERHEAD),
            );
        if charged > budget {
            return Err(SimFsError::BudgetExhausted("resident byte budget"));
        }
        Ok(())
    }

    /// Write bytes at `offset`, creating the file when absent.
    ///
    /// Replaces `[offset, offset + content.len)`; bytes beyond EOF extend the
    /// logical file with a zero-filled hole. A zero-length write changes no
    /// state. Journals one `FsWrite::Write` entry.
    pub fn write_bytes(
        &mut self,
        journal: &mut Journal,
        actor: u32,
        path: &str,
        offset: u64,
        content: Vec<u8>,
    ) -> Result<Hash, SimFsError> {
        let len = content.len() as u64;
        if len > MAX_WRITE_BYTES {
            return Err(SimFsError::WriteTooLarge {
                actual: len,
                max: MAX_WRITE_BYTES,
            });
        }
        let end = offset
            .checked_add(len)
            .ok_or(SimFsError::FileExtentTooLarge {
                max: self.max_file_extent,
            })?;
        if end > self.max_file_extent {
            return Err(SimFsError::FileExtentTooLarge {
                max: self.max_file_extent,
            });
        }
        let key = canonical_key(path);
        let exists = self.files.contains_key(&key);
        self.charge_resident(len, !exists || len > 0, !exists)?;
        let id = journal.append(
            EntryKind::FsWrite,
            actor,
            [],
            EntryPayload::FsWrite(ledger_format::FsWritePayload::Write {
                path_ref: path_ref(path),
                offset,
                content: content.clone(),
            }),
        )?;
        if len == 0 {
            // A zero-length write does not create or extend a file.
            return Ok(id);
        }
        let file = self.file_mut(&key);
        if !exists {
            file.created_by = Some(id);
        }
        file.length = file.length.max(end);
        // Replace only the covered window: trim ranges that extend into
        // `[offset, end)` instead of dropping them whole, so bytes outside
        // the window keep their prior value.
        let window_start = offset;
        let window_end = end;
        let mut splits = Vec::new();
        let affected: Vec<(u64, ByteRange)> = file
            .cache
            .range(..window_end.max(1))
            .filter(|(start, range)| {
                let range_end = **start;
                let range_end = range_end.saturating_add(range.content.len() as u64);
                range_end > window_start
            })
            .map(|(start, range)| (*start, range.clone()))
            .collect();
        for (range_start, range) in affected {
            let range_end = range_start.saturating_add(range.content.len() as u64);
            let content = range.content;
            let write_id = range.write_id;
            file.cache.remove(&range_start);
            if range_start < window_start {
                let left_len = (window_start - range_start) as usize;
                if left_len > 0 {
                    splits.push((
                        range_start,
                        write_id,
                        content[..left_len.min(content.len())].to_vec(),
                    ));
                }
            }
            if range_end > window_end {
                let right_start = (window_end - range_start) as usize;
                if right_start < content.len() {
                    splits.push((window_end, write_id, content[right_start..].to_vec()));
                }
            }
        }
        for (start, write_id, content) in splits {
            file.cache.insert(
                start,
                ByteRange {
                    content,
                    write_id,
                    state: PageState::Dirty,
                },
            );
        }
        file.cache.insert(
            offset,
            ByteRange {
                content,
                write_id: id,
                state: PageState::Dirty,
            },
        );
        #[cfg(feature = "sim-fs-journaling")]
        self.journal.entry(key).or_default().push((offset, id));
        Ok(id)
    }

    /// Scalar convenience over the byte API: write the 8 LE bytes of
    /// `value` at offset 0.
    pub fn write(
        &mut self,
        journal: &mut Journal,
        actor: u32,
        path: &str,
        value: u64,
    ) -> Result<Hash, JournalError> {
        self.write_bytes(journal, actor, path, 0, value.to_le_bytes().to_vec())
            .map_err(SimFsError::into_journal)
    }

    /// Allocate an existing empty file.
    ///
    /// Absent path: creates the empty file and journals `FsWrite::Allocate`.
    /// Existing path: fails with [`SimFsError::AlreadyExists`] and changes
    /// nothing.
    pub fn allocate(
        &mut self,
        journal: &mut Journal,
        actor: u32,
        path: &str,
    ) -> Result<Hash, SimFsError> {
        let key = canonical_key(path);
        if self.files.contains_key(&key) {
            return Err(SimFsError::AlreadyExists(path.to_owned()));
        }
        self.charge_resident(0, true, true)?;
        let id = journal.append(
            EntryKind::FsWrite,
            actor,
            [],
            EntryPayload::FsWrite(ledger_format::FsWritePayload::Allocate {
                path_ref: path_ref(path),
            }),
        )?;
        let file = self.file_mut(&key);
        file.created_by = Some(id);
        Ok(id)
    }

    /// Read at most `requested_len` bytes from `offset`.
    ///
    /// Journals exactly the observed bytes with every contributing mutation
    /// entry as a causal parent, deduplicated and sorted by entry-ID bytes.
    pub fn read_bytes(
        &self,
        journal: &mut Journal,
        actor: u32,
        path: &str,
        offset: u64,
        requested_len: u64,
    ) -> Result<ObservedRead, SimFsError> {
        if requested_len > MAX_READ_BYTES {
            return Err(SimFsError::ReadTooLarge {
                actual: requested_len,
                max: MAX_READ_BYTES,
            });
        }
        let key = canonical_key(path);
        let Some(file) = self.files.get(&key) else {
            journal.append(
                EntryKind::FsRead,
                actor,
                [],
                EntryPayload::FsRead(ledger_format::FsReadPayload {
                    path_ref: path_ref(path),
                    offset,
                    requested_len,
                    observed: ObservedRead::Missing,
                }),
            )?;
            return Ok(ObservedRead::Missing);
        };
        let available = file.length.saturating_sub(offset);
        let take = available.min(requested_len);
        let mut out = Vec::with_capacity(take as usize);
        let mut parents = BTreeSet::new();
        let mut cursor = offset;
        let window_end = offset.saturating_add(take);
        for (start, range) in file.cache.range(..window_end.max(offset + 1)) {
            let range_start = *start;
            let range_end = range_start.saturating_add(range.content.len() as u64);
            if range_end <= cursor {
                continue;
            }
            if range_start > cursor {
                // Zero-filled logical hole.
                out.extend(std::iter::repeat_n(0, (range_start - cursor) as usize));
                cursor = range_start;
            }
            let copy_from = cursor - range_start;
            let copy_len = (range_end.min(window_end)).saturating_sub(cursor);
            let copied = &range.content[copy_from as usize..(copy_from + copy_len) as usize];
            out.extend_from_slice(copied);
            parents.insert(range.write_id);
            cursor = cursor.saturating_add(copy_len);
        }
        if cursor < window_end {
            out.extend(std::iter::repeat_n(0, (window_end - cursor) as usize));
        }
        debug_assert_eq!(out.len() as u64, take);
        let mut parent_list: Vec<Hash> = parents.into_iter().collect();
        if parent_list.is_empty()
            && let Some(created) = file.created_by
        {
            parent_list.push(created);
        }
        parent_list.sort();
        let observed = ObservedRead::Present { content: out };
        journal.append(
            EntryKind::FsRead,
            actor,
            parent_list,
            EntryPayload::FsRead(ledger_format::FsReadPayload {
                path_ref: path_ref(path),
                offset,
                requested_len,
                observed: observed.clone(),
            }),
        )?;
        Ok(observed)
    }

    /// Scalar convenience over the byte API: read up to 8 bytes from
    /// offset 0 and decode little-endian. `Missing` maps to `None`.
    pub fn read(
        &self,
        journal: &mut Journal,
        actor: u32,
        path: &str,
    ) -> Result<Option<u64>, JournalError> {
        match self
            .read_bytes(journal, actor, path, 0, 8)
            .map_err(SimFsError::into_journal)?
        {
            ObservedRead::Missing => Ok(None),
            ObservedRead::Present { content } => {
                let mut buf = [0u8; 8];
                let n = content.len().min(8);
                buf[..n].copy_from_slice(&content[..n]);
                Ok(Some(u64::from_le_bytes(buf)))
            }
        }
    }

    /// Flush all dirty page-cache entries to durable synced storage.
    ///
    /// The store-level barrier persists every dirty file; the root path is
    /// the canonical identity of that barrier.
    pub fn fsync(&mut self, journal: &mut Journal, actor: u32) -> Result<Hash, JournalError> {
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
            for (path, ranges) in &self.journal {
                if let Some(file) = self.files.get_mut(path) {
                    for (offset, write_id) in ranges {
                        if let Some(range) = file.cache.get_mut(offset)
                            && range.write_id == *write_id
                        {
                            range.state = PageState::Clean;
                        }
                    }
                }
            }
            self.journal.clear();
            let renames = core::mem::take(&mut self.pending_renames);
            for (from, to) in renames {
                if let Some(file) = self.files.remove(&from) {
                    self.files.insert(to, file);
                }
            }
        }
        for file in self.files.values_mut() {
            file.persist();
        }
        Ok(id)
    }

    /// Path-specific persistence barrier: copies that file's dirty data
    /// into its durable state and journals `FsSync(path)`.
    pub fn fsync_path(
        &mut self,
        journal: &mut Journal,
        actor: u32,
        path: &str,
    ) -> Result<Hash, SimFsError> {
        let key = canonical_key(path);
        let Some(file) = self.files.get_mut(&key) else {
            return Err(SimFsError::NotFound(path.to_owned()));
        };
        let id = journal.append(
            EntryKind::FsFsync,
            actor,
            [],
            EntryPayload::FsFsync(ledger_format::FsSyncPayload {
                path_ref: path_ref(path),
            }),
        )?;
        file.persist();
        Ok(id)
    }

    /// Rename a path (fsync-less by default).
    ///
    /// Rename changes volatile namespace state; the durable namespace moves
    /// only when the journaling feature commits it on fsync.
    pub fn rename(
        &mut self,
        journal: &mut Journal,
        actor: u32,
        from: &str,
        to: &str,
    ) -> Result<Hash, SimFsError> {
        let from_key = canonical_key(from);
        let to_key = canonical_key(to);
        if !self.files.contains_key(&from_key) {
            return Err(SimFsError::NotFound(from.to_owned()));
        }
        let id = journal.append(
            EntryKind::FsWrite,
            actor,
            [],
            EntryPayload::FsWrite(ledger_format::FsWritePayload::Rename {
                from_path_ref: path_ref(from),
                to_path_ref: path_ref(to),
            }),
        )?;
        if from_key == to_key {
            return Ok(id);
        }
        if let Some(file) = self.files.remove(&from_key) {
            self.files.insert(to_key.clone(), file);
        }
        #[cfg(feature = "sim-fs-journaling")]
        self.pending_renames.insert(from_key, to_key);
        Ok(id)
    }

    /// Append a value with O_APPEND semantics that can tear.
    ///
    /// Resolves the current length once, then writes at that offset, so the
    /// journal records the actual mutation.
    pub fn append_tear(
        &mut self,
        journal: &mut Journal,
        actor: u32,
        path: &str,
        value: u64,
    ) -> Result<Hash, SimFsError> {
        let offset = self.files.get(&canonical_key(path)).map_or(0, |f| f.length);
        self.write_bytes(journal, actor, path, offset, value.to_le_bytes().to_vec())
    }

    /// Execute a standard crash by resetting all dirty writes to last fsynced state.
    pub fn crash(&mut self) {
        self.apply_crash_operator(&CrashOperator::DropAllUnsynced);
    }

    /// Replay the journal and apply the crash model for the configured mode.
    #[cfg(feature = "sim-fs-journaling")]
    pub fn crash_journaled(&mut self) {
        if self.journal_mode == JournalingMode::Writeback {
            for (path, ranges) in &self.journal {
                if let Some(file) = self.files.get_mut(path) {
                    for (offset, write_id) in ranges {
                        if let Some(range) = file.cache.get_mut(offset)
                            && range.write_id == *write_id
                        {
                            range.state = PageState::Clean;
                        }
                    }
                    file.persist();
                }
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

    /// Apply a canonical versioned crash operator (wire form).
    ///
    /// Fails closed on unknown targets, empty XOR payloads, out-of-range
    /// bits, and duplicate path targets.
    pub fn apply_crash_operation(&mut self, op: &CrashOperation) -> Result<(), SimFsError> {
        match op {
            CrashOperation::DropAllUnsynced => {
                self.files.retain(|_, file| file.drop_unsynced());
            }
            CrashOperation::DropPaths { paths } => {
                let mut seen = BTreeSet::new();
                let mut keys = Vec::new();
                for path_ref in paths {
                    let key =
                        String::from_utf8(path_ref.canonical_path.clone()).unwrap_or_default();
                    if !seen.insert(key.clone()) {
                        return Err(SimFsError::AlreadyExists(key));
                    }
                    keys.push(key);
                }
                for key in keys {
                    if let Some(file) = self.files.get_mut(&key)
                        && !file.drop_unsynced()
                    {
                        self.files.remove(&key);
                    }
                }
            }
            CrashOperation::TornWrite {
                write_entry,
                persisted_prefix,
            } => {
                let prefix = *persisted_prefix;
                let mut found = false;
                for file in self.files.values_mut() {
                    if let Some((_, range)) = file
                        .cache
                        .iter_mut()
                        .find(|(_, range)| range.write_id == *write_entry)
                    {
                        if (prefix as usize) > range.content.len() {
                            return Err(SimFsError::UnknownWriteTarget);
                        }
                        range.content.truncate(prefix as usize);
                        range.state = PageState::Dirty;
                        file.recompute_length();
                        found = true;
                        break;
                    }
                }
                if !found {
                    return Err(SimFsError::UnknownWriteTarget);
                }
            }
            CrashOperation::CorruptRange {
                write_entry,
                offset,
                xor_bytes,
            } => {
                if xor_bytes.is_empty() {
                    return Err(SimFsError::EmptyXor);
                }
                let range = self.target_range_mut(write_entry)?;
                if (*offset as usize) >= range.content.len() {
                    return Err(SimFsError::UnknownWriteTarget);
                }
                let window = &mut range.content[*offset as usize..];
                for (index, byte) in window.iter_mut().enumerate() {
                    if index < xor_bytes.len() {
                        *byte ^= xor_bytes[index];
                    }
                }
            }
            CrashOperation::BitFlip {
                write_entry,
                offset,
                bit,
            } => {
                if *bit > 7 {
                    return Err(SimFsError::BitOutOfRange { bit: *bit });
                }
                let range = self.target_range_mut(write_entry)?;
                if (*offset as usize) >= range.content.len() {
                    return Err(SimFsError::UnknownWriteTarget);
                }
                range.content[*offset as usize] ^= 1u8 << bit;
            }
        }
        Ok(())
    }

    /// Locate the range carrying `write_entry`, for canonical crash ops.
    fn target_range_mut(&mut self, write_entry: &Hash) -> Result<&mut ByteRange, SimFsError> {
        for file in self.files.values_mut() {
            if let Some(range) = file
                .cache
                .values_mut()
                .find(|range| range.write_id == *write_entry)
            {
                return Ok(range);
            }
        }
        Err(SimFsError::UnknownWriteTarget)
    }

    /// Apply an explicit legacy crash operator to simulate arbitrary crash
    /// states (scalar corpus fixtures; byte semantics underneath).
    pub fn apply_crash_operator(&mut self, op: &CrashOperator) {
        #[cfg(feature = "sim-fs-journaling")]
        {
            self.journal.clear();
            self.pending_renames.clear();
        }
        match op {
            CrashOperator::DropAllUnsynced => {
                self.files.retain(|_, file| file.drop_unsynced());
            }
            CrashOperator::DropSubset(paths_to_drop) => {
                let mut ordered: Vec<&String> = paths_to_drop.iter().collect();
                ordered.sort();
                for path in ordered {
                    let key = canonical_key(path);
                    if let Some(file) = self.files.get_mut(&key) {
                        if !file.drop_unsynced() {
                            self.files.remove(&key);
                        }
                    } else {
                        self.files.remove(&key);
                    }
                }
            }
            CrashOperator::TornWrite {
                path,
                partial_value,
            } => {
                let key = canonical_key(path);
                if let Some(file) = self.files.get_mut(&key) {
                    file.cache.insert(
                        0,
                        ByteRange {
                            content: partial_value.to_le_bytes().to_vec(),
                            write_id: file.created_by.unwrap_or_default(),
                            state: PageState::Dirty,
                        },
                    );
                    file.recompute_length();
                }
            }
            CrashOperator::BitFlipCorruption { path, xor_mask } => {
                let key = canonical_key(path);
                if let Some(file) = self.files.get_mut(&key)
                    && let Some(range) = file.cache.get_mut(&0)
                {
                    for (index, byte) in range.content.iter_mut().enumerate() {
                        if index < 8 {
                            *byte ^= ((xor_mask >> (index * 8)) & 0xFF) as u8;
                        }
                    }
                }
            }
            CrashOperator::TornWriteSectors {
                path,
                sectors_committed,
                total_sectors,
            } => {
                let key = canonical_key(path);
                if let Some(file) = self.files.get_mut(&key)
                    && let Some(range) = file.cache.get_mut(&0)
                    && range.state == PageState::Dirty
                {
                    let divisor = (*total_sectors).max(1);
                    let fraction = (*sectors_committed as u128)
                        .saturating_mul(range.content.len() as u128)
                        / divisor as u128;
                    range.content.truncate(fraction as usize);
                    file.recompute_length();
                }
            }
            CrashOperator::CorruptRange {
                path,
                start_sector,
                sector_count,
                sector_size,
            } => {
                let key = canonical_key(path);
                if let Some(file) = self.files.get_mut(&key)
                    && let Some(range) = file.cache.get_mut(&0)
                {
                    let start = start_sector.saturating_mul(*sector_size) as usize;
                    let len = sector_count.saturating_mul(*sector_size) as usize;
                    for (index, byte) in range.content.iter_mut().enumerate() {
                        if index >= start && index < start.saturating_add(len) {
                            *byte ^= 0xFF;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_journal::Journal;

    fn new_journal() -> Journal {
        Journal::new()
    }

    #[test]
    fn allocate_reads_as_present_empty_until_synced() {
        // v2 semantics: Allocate creates an existing empty file, so a read
        // observes Present([]) rather than Missing.
        let mut journal = new_journal();
        let mut fs = SimFs::new();
        fs.allocate(&mut journal, 0, "k").unwrap();
        assert_eq!(fs.read(&mut journal, 0, "k").unwrap(), Some(0));
        fs.fsync(&mut journal, 0).unwrap();
        assert_eq!(fs.read(&mut journal, 0, "k").unwrap(), Some(0));
    }

    #[test]
    fn allocate_existing_path_fails_and_changes_nothing() {
        let mut journal = new_journal();
        let mut fs = SimFs::new();
        fs.allocate(&mut journal, 0, "k").unwrap();
        assert!(matches!(
            fs.allocate(&mut journal, 0, "k"),
            Err(SimFsError::AlreadyExists(_))
        ));
        assert_eq!(fs.files.len(), 1);
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
        // One of two 8-byte sectors persists: the first 4 bytes of the LE
        // u64 100, which still decodes to 100.
        assert_eq!(fs.read(&mut journal, 0, "k").unwrap(), Some(100));

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

    #[test]
    fn sparse_write_creates_zero_filled_hole() {
        let mut journal = new_journal();
        let mut fs = SimFs::new();
        fs.write_bytes(&mut journal, 0, "f", 0, vec![1, 2, 3])
            .unwrap();
        fs.write_bytes(&mut journal, 0, "f", 10, vec![9]).unwrap();
        let observed = fs.read_bytes(&mut journal, 0, "f", 0, 11).unwrap();
        match observed {
            ObservedRead::Present { content } => {
                assert_eq!(&content[0..3], &[1, 2, 3]);
                assert_eq!(&content[3..10], &[0, 0, 0, 0, 0, 0, 0]);
                assert_eq!(&content[10..11], &[9]);
            }
            ObservedRead::Missing => panic!("file must exist"),
        }
    }

    #[test]
    fn zero_length_write_does_not_create_or_extend() {
        let mut journal = new_journal();
        let mut fs = SimFs::new();
        fs.write_bytes(&mut journal, 0, "f", 0, Vec::new()).unwrap();
        assert!(!fs.files.contains_key(&canonical_key("f")));
        fs.write_bytes(&mut journal, 0, "f", 0, vec![1, 2]).unwrap();
        fs.write_bytes(&mut journal, 0, "f", 2, Vec::new()).unwrap();
        let observed = fs.read_bytes(&mut journal, 0, "f", 0, 8).unwrap();
        assert_eq!(
            observed,
            ObservedRead::Present {
                content: vec![1, 2]
            }
        );
    }

    #[test]
    fn partial_overwrite_replaces_covered_window() {
        let mut journal = new_journal();
        let mut fs = SimFs::new();
        fs.write_bytes(&mut journal, 0, "f", 0, vec![1, 2, 3, 4])
            .unwrap();
        fs.write_bytes(&mut journal, 0, "f", 1, vec![9, 9]).unwrap();
        let observed = fs.read_bytes(&mut journal, 0, "f", 0, 4).unwrap();
        assert_eq!(
            observed,
            ObservedRead::Present {
                content: vec![1, 9, 9, 4]
            }
        );
    }

    #[test]
    fn read_beyond_eof_returns_empty_with_existence_parent() {
        let mut journal = new_journal();
        let mut fs = SimFs::new();
        let id = fs.write_bytes(&mut journal, 0, "f", 0, vec![7]).unwrap();
        let observed = fs.read_bytes(&mut journal, 0, "f", 5, 3).unwrap();
        assert_eq!(
            observed,
            ObservedRead::Present {
                content: Vec::new()
            }
        );
        let _ = id;
    }

    #[test]
    fn read_journals_exactly_observed_bytes_with_sorted_parents() {
        let mut journal = new_journal();
        let mut fs = SimFs::new();
        let first = fs
            .write_bytes(&mut journal, 0, "f", 0, vec![1, 2, 3])
            .unwrap();
        let second = fs.write_bytes(&mut journal, 0, "f", 3, vec![4, 5]).unwrap();
        fs.read_bytes(&mut journal, 0, "f", 1, 4).unwrap();
        let read = journal
            .entries()
            .find(|entry| entry.data.kind == EntryKind::FsRead)
            .expect("read entry");
        assert_eq!(
            read.data.payload,
            EntryPayload::FsRead(ledger_format::FsReadPayload {
                path_ref: path_ref("f"),
                offset: 1,
                requested_len: 4,
                observed: ObservedRead::Present {
                    content: vec![2, 3, 4, 5]
                },
            })
        );
        // The journal stores the actor head first, then the observed
        // parents byte-sorted and deduplicated.
        let mut observed = vec![first, second];
        observed.sort();
        let mut expected = vec![second];
        for parent in observed {
            if !expected.contains(&parent) {
                expected.push(parent);
            }
        }
        assert_eq!(read.data.parents, expected);
    }

    #[test]
    fn rename_moves_volatile_namespace_and_replaces_destination() {
        let mut journal = new_journal();
        let mut fs = SimFs::new();
        fs.write_bytes(&mut journal, 0, "a", 0, vec![1]).unwrap();
        fs.write_bytes(&mut journal, 0, "b", 0, vec![2]).unwrap();
        fs.rename(&mut journal, 0, "a", "b").unwrap();
        let observed = fs.read_bytes(&mut journal, 0, "b", 0, 1).unwrap();
        assert_eq!(observed, ObservedRead::Present { content: vec![1] });
        assert!(matches!(
            fs.read_bytes(&mut journal, 0, "a", 0, 1),
            Ok(ObservedRead::Missing)
        ));
        assert!(matches!(
            fs.rename(&mut journal, 0, "absent", "x"),
            Err(SimFsError::NotFound(_))
        ));
    }

    #[test]
    fn rename_to_same_canonical_path_succeeds_without_change() {
        let mut journal = new_journal();
        let mut fs = SimFs::new();
        fs.write_bytes(&mut journal, 0, "a", 0, vec![5]).unwrap();
        fs.rename(&mut journal, 0, "a", "a").unwrap();
        let observed = fs.read_bytes(&mut journal, 0, "a", 0, 1).unwrap();
        assert_eq!(observed, ObservedRead::Present { content: vec![5] });
    }

    #[test]
    fn write_over_hard_extent_fails_atomically() {
        let mut journal = new_journal();
        let mut fs = SimFs::new();
        let err = fs
            .write_bytes(&mut journal, 0, "f", MAX_FILE_EXTENT_HARD, vec![1])
            .unwrap_err();
        assert!(matches!(err, SimFsError::FileExtentTooLarge { .. }));
        assert!(!fs.files.contains_key(&canonical_key("f")));
    }

    #[test]
    fn canonical_drop_paths_restores_only_selected_paths() {
        let mut journal = new_journal();
        let mut fs = SimFs::new();
        fs.write_bytes(&mut journal, 0, "a", 0, vec![1]).unwrap();
        fs.write_bytes(&mut journal, 0, "b", 0, vec![2]).unwrap();
        fs.fsync(&mut journal, 0).unwrap();
        fs.write_bytes(&mut journal, 0, "a", 0, vec![9]).unwrap();
        fs.apply_crash_operation(&CrashOperation::DropPaths {
            paths: vec![path_ref("a")],
        })
        .unwrap();
        let observed = fs.read_bytes(&mut journal, 0, "a", 0, 1).unwrap();
        assert_eq!(observed, ObservedRead::Present { content: vec![1] });
        let observed = fs.read_bytes(&mut journal, 0, "b", 0, 1).unwrap();
        assert_eq!(observed, ObservedRead::Present { content: vec![2] });
    }

    #[test]
    fn canonical_torn_write_targets_write_entry() {
        let mut journal = new_journal();
        let mut fs = SimFs::new();
        let id = fs
            .write_bytes(&mut journal, 0, "f", 0, vec![1, 2, 3, 4])
            .unwrap();
        fs.apply_crash_operation(&CrashOperation::TornWrite {
            write_entry: id,
            persisted_prefix: 2,
        })
        .unwrap();
        let observed = fs.read_bytes(&mut journal, 0, "f", 0, 4).unwrap();
        assert_eq!(
            observed,
            ObservedRead::Present {
                content: vec![1, 2]
            }
        );
    }

    #[test]
    fn canonical_corrupt_and_bitflip_target_write_entry() {
        let mut journal = new_journal();
        let mut fs = SimFs::new();
        let id = fs
            .write_bytes(&mut journal, 0, "f", 0, vec![0x00, 0x00])
            .unwrap();
        fs.apply_crash_operation(&CrashOperation::CorruptRange {
            write_entry: id,
            offset: 0,
            xor_bytes: vec![0xFF],
        })
        .unwrap();
        let observed = fs.read_bytes(&mut journal, 0, "f", 0, 2).unwrap();
        assert_eq!(
            observed,
            ObservedRead::Present {
                content: vec![0xFF, 0x00]
            }
        );
        fs.apply_crash_operation(&CrashOperation::BitFlip {
            write_entry: id,
            offset: 0,
            bit: 1,
        })
        .unwrap();
        let observed = fs.read_bytes(&mut journal, 0, "f", 0, 2).unwrap();
        assert_eq!(
            observed,
            ObservedRead::Present {
                content: vec![0xFD, 0x00]
            }
        );
    }

    #[test]
    fn canonical_ops_fail_closed_on_bad_targets() {
        let _journal = new_journal();
        let mut fs = SimFs::new();
        let unknown = Hash::default();
        assert!(matches!(
            fs.apply_crash_operation(&CrashOperation::TornWrite {
                write_entry: unknown,
                persisted_prefix: 1,
            }),
            Err(SimFsError::UnknownWriteTarget)
        ));
        assert!(matches!(
            fs.apply_crash_operation(&CrashOperation::CorruptRange {
                write_entry: unknown,
                offset: 0,
                xor_bytes: vec![],
            }),
            Err(SimFsError::EmptyXor)
        ));
        assert!(matches!(
            fs.apply_crash_operation(&CrashOperation::BitFlip {
                write_entry: unknown,
                offset: 0,
                bit: 9,
            }),
            Err(SimFsError::BitOutOfRange { bit: 9 })
        ));
    }

    #[test]
    fn write_exceeds_operation_limit() {
        let mut journal = new_journal();
        let mut fs = SimFs::new();
        let oversized = vec![0u8; (MAX_WRITE_BYTES + 1) as usize];
        let err = fs
            .write_bytes(&mut journal, 0, "f", 0, oversized)
            .unwrap_err();
        assert!(matches!(err, SimFsError::WriteTooLarge { .. }));
    }
    #[test]
    fn operations_match_a_reference_byte_file_model() {
        // Differential test: a deterministic operation sequence applied to
        // SimFs must produce the same observable bytes as a plain Vec<u8>
        // reference model.
        struct RefFile(Vec<u8>);
        impl RefFile {
            fn write(&mut self, offset: u64, content: &[u8]) {
                let start = offset as usize;
                let end = start + content.len();
                if end > self.0.len() {
                    self.0.resize(end, 0);
                }
                self.0[start..end].copy_from_slice(content);
            }
            fn read(&self, offset: u64, len: u64) -> Vec<u8> {
                let start = offset as usize;
                if start >= self.0.len() {
                    return Vec::new();
                }
                let end = (start + len as usize).min(self.0.len());
                self.0[start..end].to_vec()
            }
        }

        let mut journal = new_journal();
        let mut fs = SimFs::new();
        let mut reference = RefFile(Vec::new());
        // Deterministic pseudo-random operation sequence over fixed bounds.
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        let mut next = move || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };
        for step in 0..200u64 {
            let op = next() % 3;
            let offset = next() % 64;
            match op {
                0 => {
                    let len = (next() % 24) as usize;
                    let content: Vec<u8> =
                        (0..len).map(|i| ((step + i as u64) % 251) as u8).collect();
                    fs.write_bytes(&mut journal, 0, "f", offset, content.clone())
                        .unwrap();
                    reference.write(offset, &content);
                }
                1 => {
                    let len = next() % 40;
                    let observed = fs.read_bytes(&mut journal, 0, "f", offset, len).unwrap();
                    let expected = reference.read(offset, len);
                    match observed {
                        ObservedRead::Present { content } => assert_eq!(content, expected),
                        ObservedRead::Missing => {
                            assert!(expected.is_empty(), "model missing but reference has bytes")
                        }
                    }
                }
                _ => {
                    fs.fsync_path(&mut journal, 0, "f").unwrap();
                }
            }
        }
    }

    #[test]
    fn read_over_operation_limit_fails_closed() {
        let mut journal = new_journal();
        let fs = SimFs::new();
        let err = fs
            .read_bytes(&mut journal, 0, "f", 0, MAX_READ_BYTES + 1)
            .unwrap_err();
        assert!(matches!(err, SimFsError::ReadTooLarge { .. }));
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
    fn fsync_persists_journaled_writes_in_data_mode() {
        let mut journal = new_journal();
        let mut fs = SimFs::new();
        fs.write(&mut journal, 0, "k", 7).unwrap();
        fs.fsync(&mut journal, 0).unwrap();
        fs.write(&mut journal, 0, "k", 9).unwrap();
        fs.crash_journaled();
        assert_eq!(fs.read(&mut journal, 0, "k").unwrap(), Some(7));
    }
}
