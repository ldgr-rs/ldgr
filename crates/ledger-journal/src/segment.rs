//! Append-only segment storage with zstd-at-seal compression, a sparse
//! hash-to-offset index, and WAL-shaped recovery.
//!
//! This module is storage infrastructure, not a simulation runtime. It uses
//! the ambient filesystem directly; simulation code must route I/O through
//! `SimFs` instead.
//!
//! Sealed segment file layout:
//!
//! ```text
//! [magic "LDGR" 4 bytes][version u32][entry_count u64][uncompressed_len u64]
//! [root_hash 32 bytes]
//! [zstd-compressed frame block]
//! [sparse index: index_len x (offset u64 BE, prefix u32 BE)]
//! [trailer: index_len u32 BE][sample_interval u32 BE][compressed_len u64 BE]
//! ```
//!
//! Each frame is length-delimited: a u64 little-endian payload length
//! followed by the entry id (32 bytes), a u64 little-endian data length, the
//! canonical entry data bytes, and the vector-clock encoding. The id is
//! stored in the frame and re-derived from the payload on read, so
//! corruption is detectable.
//!
//! Open-segment frames are duplicated into a WAL file. A crash that leaves a
//! partial tail is recovered by truncating the WAL to the last complete
//! frame. A stale temp file from an interrupted seal is removed at load.
// ledger-lint:allow:fs:: (storage infrastructure uses the ambient filesystem by design)

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::format;
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::string::{String, ToString};
use std::sync::Arc;
use std::vec::Vec;

use crate::archive::{ARCHIVE_FILE, ArchiveStore};
use crate::clock::VectorClock;
use crate::dag::{Entry, JournalError};
use crate::retention::{KEEP_TAIL, RetentionClass};
use ledger_format::{ActorId, CborValue, EntryData, EntryKind, FaultSpec, Hash, Payload};

/// Target size in bytes for a sealed segment.
pub const SEGMENT_TARGET_SIZE: usize = 64 * 1024 * 1024;

/// Sparse-index sampling interval in frames.
const SAMPLE_INTERVAL: u32 = 32;

/// Number of bytes in the segment file header.
const HEADER_LEN: usize = 56;

/// Number of bytes in the segment file trailer.
const TRAILER_LEN: usize = 16;

/// Bytes of metadata following the id field in a manifest record.
///
/// The fields after `id` are entry_count, uncompressed_len, compressed_len,
/// sample_interval, and samples length: 8 + 8 + 8 + 4 + 8 = 36 bytes plus the
/// 32-byte root hash.
const MANIFEST_RECORD_META_LEN: usize = 68;

/// Bytes of one sparse index entry (offset u64 BE, prefix u32 BE).
const INDEX_ENTRY_LEN: usize = 12;

/// Minimum payload size of a valid frame (id + data length + minimal data).
const MIN_FRAME_PAYLOAD: usize = 40;

const SEGMENT_MAGIC: &[u8; 4] = b"LDGR";
const WAL_FILE: &str = "wal.bin";
const MANIFEST_FILE: &str = "manifest.bin";

/// Metadata for one sealed, immutable segment.
#[derive(Debug, Clone)]
pub struct SealedSegment {
    /// Monotonic segment identifier.
    pub id: u64,
    /// Number of entries stored in the segment.
    pub entry_count: u64,
    /// Size of the uncompressed frame block in bytes.
    pub uncompressed_len: u64,
    /// Size of the zstd-compressed block in bytes.
    pub compressed_len: u64,
    /// Root hash over the ordered entry ids.
    pub root_hash: Hash,
    /// Sparse-index sampling interval in frames.
    pub sample_interval: u32,
    /// True when any frame carries a Fault, Outcome, or Assert kind.
    ///
    /// The warm retention tier keeps such segments loose.
    pub contains_fault_relevant: bool,
    /// Sparse index entries, sorted by offset.
    samples: Vec<(u64, u32)>,
}

impl SealedSegment {
    /// Return the on-disk file name of this sealed segment.
    pub(crate) fn file_name(&self) -> String {
        segment_file_name(self.id)
    }
}

/// In-memory accumulation buffer for the open segment.
#[derive(Debug, Default)]
pub struct SegmentWriter {
    buffer: Vec<u8>,
    index: Vec<(Hash, u64)>,
    fault_relevant: bool,
}

impl SegmentWriter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one entry frame to the buffer.
    ///
    /// Returns the encoded frame bytes so the caller can duplicate them into a
    /// recovery log without re-encoding.
    pub fn append(&mut self, entry: &Entry) -> Result<Vec<u8>, JournalError> {
        let frame = encode_entry_frame(entry)?;
        let offset = self.buffer.len() as u64;
        self.index.push((entry.id, offset));
        self.fault_relevant |= kind_is_fault_relevant(&entry.data.kind);
        self.buffer.extend_from_slice(&frame);
        Ok(frame)
    }

    /// Return the current buffer size in bytes.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Return the number of buffered frames.
    pub fn entry_count(&self) -> u64 {
        self.index.len() as u64
    }

    /// Return true when the buffer has reached the target segment size.
    pub fn should_seal(&self) -> bool {
        self.buffer.len() >= SEGMENT_TARGET_SIZE
    }

    /// Seal the buffer into an immutable segment file.
    ///
    /// The frame block is zstd-compressed, a sparse index samples every
    /// SAMPLE_INTERVAL-th frame, and the file is written atomically (temp
    /// file plus rename).
    pub fn seal(&self, dir: &Path, segment_id: u64) -> Result<SealedSegment, JournalError> {
        let compressed = zstd::encode_all(&self.buffer[..], 3).map_err(segment_io)?;
        let mut samples = Vec::new();
        let mut hasher = blake3::Hasher::new();
        for (i, (id, offset)) in self.index.iter().enumerate() {
            hasher.update(id);
            if i % SAMPLE_INTERVAL as usize == 0 {
                samples.push((*offset, prefix_of(id)));
            }
        }
        let root_hash = *hasher.finalize().as_bytes();

        let file_name = segment_file_name(segment_id);
        let tmp_path = dir.join(format!("{file_name}.tmp"));
        {
            let mut file = BufWriter::new(File::create(&tmp_path).map_err(segment_io)?);
            write_header(
                &mut file,
                self.index.len() as u64,
                self.buffer.len() as u64,
                &root_hash,
            )?;
            file.write_all(&compressed).map_err(segment_io)?;
            for &(offset, prefix) in &samples {
                file.write_all(&offset.to_be_bytes()).map_err(segment_io)?;
                file.write_all(&prefix.to_be_bytes()).map_err(segment_io)?;
            }
            write_trailer(
                &mut file,
                samples.len() as u32,
                SAMPLE_INTERVAL,
                compressed.len() as u64,
            )?;
            file.flush().map_err(segment_io)?;
            file.get_ref().sync_all().map_err(segment_io)?;
        }
        fs::rename(&tmp_path, dir.join(&file_name)).map_err(segment_io)?;

        Ok(SealedSegment {
            id: segment_id,
            entry_count: self.index.len() as u64,
            uncompressed_len: self.buffer.len() as u64,
            compressed_len: compressed.len() as u64,
            root_hash,
            sample_interval: SAMPLE_INTERVAL,
            contains_fault_relevant: self.fault_relevant,
            samples,
        })
    }
}

/// Header of an immutable serialized .ldgr journal segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentHeader {
    /// Magic identifier (0x4c444752 = 'LDGR').
    pub magic: [u8; 4],
    /// Segment format version.
    pub version: u32,
    /// Number of entries in this segment.
    pub entry_count: u64,
    /// Root hash of the segment entries.
    pub root_hash: Hash,
}

impl SegmentHeader {
    pub fn new(entry_count: u64, root_hash: Hash) -> Self {
        Self {
            magic: *b"LDGR",
            version: 1,
            entry_count,
            root_hash,
        }
    }
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.magic);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.entry_count.to_be_bytes());
        out.extend_from_slice(&self.root_hash);
    }
}

/// One sealed segment whose bytes live in the archive instead of a loose file.
///
/// The bytes are the full serialized segment file contents, kept in memory
/// so lookups and re-extraction work without touching the archive.
#[derive(Debug, Clone)]
pub struct ArchivedSegment {
    /// Ordinal of the archived segment.
    pub(crate) id: u64,
    /// Full serialized segment file bytes.
    pub(crate) bytes: Arc<Vec<u8>>,
}

/// Append-only on-disk segment store.
///
/// Frames accumulate in an in-memory writer and duplicate into a WAL file for
/// crash recovery. A seal writes an immutable compressed, indexed segment
/// file and removes the WAL. On `load`, a partial WAL tail is truncated to
/// the last complete frame and the surviving frames recover into a fresh
/// writer.
///
/// Sealed segments are retained by tier. Archived segments move their bytes
/// into `archive.ldgr` and drop their loose file, but the bytes stay
/// available in memory, so reads and re-extraction always work and the store
/// is non-lossy.
#[derive(Debug)]
pub struct SegmentStore {
    dir: PathBuf,
    sealed: Vec<SealedSegment>,
    archived: Vec<ArchivedSegment>,
    retention: RetentionClass,
    writer: SegmentWriter,
    wal: Option<BufWriter<File>>,
    next_segment_id: u64,
    decompressed: RefCell<Option<(u64, Arc<Vec<u8>>)>>,
}

impl SegmentStore {
    /// Open a store rooted at `dir`, creating it if necessary.
    ///
    /// Sealed segments already in `dir` are left untouched; a recoverable WAL
    /// is loaded into the writer.
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, JournalError> {
        Self::open_internal(dir.into(), true)
    }

    /// Open a store rooted at `dir` and load its persisted state.
    ///
    /// Stale temp files are removed, a trailing segment that does not match
    /// its trailer is dropped, and a partial WAL tail is truncated to the
    /// last complete frame.
    pub fn load(dir: impl Into<PathBuf>) -> Result<Self, JournalError> {
        Self::open_internal(dir.into(), false)
    }

    fn open_internal(dir: PathBuf, fresh: bool) -> Result<Self, JournalError> {
        fs::create_dir_all(&dir).map_err(segment_io)?;
        let mut store = Self {
            dir,
            sealed: Vec::new(),
            archived: Vec::new(),
            retention: RetentionClass::Hot,
            writer: SegmentWriter::new(),
            wal: None,
            next_segment_id: 0,
            decompressed: RefCell::new(None),
        };
        store.recover_temp_files();
        if !fresh {
            store.load_sealed_segments()?;
        }
        store.recover_wal()?;
        Ok(store)
    }

    /// Append one entry. Seals the open segment when the buffer is full.
    pub fn append(&mut self, entry: &Entry) -> Result<(), JournalError> {
        if self.wal.is_none() {
            let path = self.dir.join(WAL_FILE);
            let file = File::create(&path).map_err(segment_io)?;
            self.wal = Some(BufWriter::new(file));
        }
        let frame = self.writer.append(entry)?;
        if let Some(wal) = self.wal.as_mut() {
            wal.write_all(&frame).map_err(segment_io)?;
        }
        if self.writer.should_seal() {
            self.seal_writer()?;
        }
        Ok(())
    }

    /// Seal the open writer into a segment file and reset the WAL.
    pub fn seal_writer(&mut self) -> Result<(), JournalError> {
        if self.writer.is_empty() {
            return Ok(());
        }
        let segment = self.writer.seal(&self.dir, self.next_segment_id)?;
        self.next_segment_id += 1;
        self.sealed.push(segment);
        self.writer = SegmentWriter::new();
        self.wal = None;
        // Invariant: the WAL mirrors the open-writer contents. A stale WAL
        // left after a seal would be re-ingested by a later `load`,
        // duplicating entries already sealed into the segment.
        let wal_path = self.dir.join(WAL_FILE);
        match fs::remove_file(&wal_path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(segment_io(err)),
        }
        if self.retention != RetentionClass::Hot {
            self.retain()?;
        }
        Ok(())
    }

    /// Return the entry stored under `hash`, if any.
    ///
    /// The open writer is consulted first. Sealed segments decompress on
    /// demand; a sparse-index scan locates the frame and a full scan
    /// backstops it.
    pub fn get(&self, hash: &Hash) -> Result<Option<Arc<Entry>>, JournalError> {
        if let Some((_, offset)) = self.writer.index.iter().find(|(id, _)| id == hash) {
            let payload = frame_payload_at(&self.writer.buffer, *offset)?;
            return decode_frame_payload(payload).map(Some);
        }
        for segment in &self.sealed {
            if let Some(entry) = self.get_from_sealed(segment, hash)? {
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }

    /// Persist the manifest describing all sealed segments.
    ///
    /// The manifest records the retention class and the loose/archived and
    /// fault-relevant split per segment. Archive contents are re-verified by
    /// chain hash on load; these flags are a hint only.
    pub fn write_manifest(&self) -> Result<(), JournalError> {
        let path = self.dir.join(MANIFEST_FILE);
        let tmp_path = self.dir.join(format!("{MANIFEST_FILE}.tmp"));
        {
            let mut file = BufWriter::new(File::create(&tmp_path).map_err(segment_io)?);
            file.write_all(&2u32.to_be_bytes()).map_err(segment_io)?;
            file.write_all(&[self.retention.to_u8()])
                .map_err(segment_io)?;
            file.write_all(&(self.sealed.len() as u64).to_be_bytes())
                .map_err(segment_io)?;
            for segment in &self.sealed {
                file.write_all(&segment.id.to_be_bytes())
                    .map_err(segment_io)?;
                file.write_all(&segment.entry_count.to_be_bytes())
                    .map_err(segment_io)?;
                file.write_all(&segment.uncompressed_len.to_be_bytes())
                    .map_err(segment_io)?;
                file.write_all(&segment.compressed_len.to_be_bytes())
                    .map_err(segment_io)?;
                file.write_all(&segment.sample_interval.to_be_bytes())
                    .map_err(segment_io)?;
                file.write_all(&(segment.samples.len() as u64).to_be_bytes())
                    .map_err(segment_io)?;
                file.write_all(&segment.root_hash).map_err(segment_io)?;
                let archived = u8::from(self.archived.iter().any(|a| a.id == segment.id));
                let flags = archived | (u8::from(segment.contains_fault_relevant) << 1);
                file.write_all(&[flags]).map_err(segment_io)?;
            }
            file.flush().map_err(segment_io)?;
            file.get_ref().sync_all().map_err(segment_io)?;
        }
        fs::rename(&tmp_path, &path).map_err(segment_io)?;
        Ok(())
    }

    /// Return the sealed segments in append order.
    pub fn segments(&self) -> &[SealedSegment] {
        &self.sealed
    }

    /// Return the current retention class.
    pub fn retention(&self) -> RetentionClass {
        self.retention
    }

    /// Set the retention class and apply it immediately.
    ///
    /// Raising the class re-extracts archived segments back to loose files.
    /// The store stays byte-identical under every class.
    pub fn set_retention(&mut self, class: RetentionClass) -> Result<(), JournalError> {
        self.retention = class;
        self.retain()
    }

    /// Enforce the current retention class over every sealed segment.
    ///
    /// Warm archives segments that are neither fault-relevant nor in the
    /// newest `KEEP_TAIL`; cold archives everything. The archive is rebuilt
    /// only when records must be removed; a pure append extends the chain.
    pub fn retain(&mut self) -> Result<(), JournalError> {
        let existing = ArchiveStore::load(&self.dir)?;
        let mut archive_map: BTreeMap<u64, Vec<u8>> = existing.into_iter().collect();
        let tail_start = self.newest_tail_start();

        let mut pending_append: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut needs_rebuild = false;
        for segment in &self.sealed {
            let want_loose = self.should_keep_loose(segment, tail_start);
            let in_archive = archive_map.contains_key(&segment.id);
            if want_loose && in_archive {
                let bytes = match archive_map.remove(&segment.id) {
                    Some(bytes) => bytes,
                    None => {
                        return Err(JournalError::SegmentCorrupt(format!(
                            "archived segment {} is missing",
                            segment.id
                        )));
                    }
                };
                write_loose_file(&self.dir, segment.id, &bytes)?;
                needs_rebuild = true;
            } else if !want_loose && !in_archive {
                let path = self.dir.join(segment.file_name());
                let bytes = fs::read(&path).map_err(segment_io)?;
                pending_append.push((segment.id, bytes));
            }
        }

        if needs_rebuild {
            for (ordinal, bytes) in &pending_append {
                archive_map.insert(*ordinal, bytes.clone());
            }
            let mut records: Vec<(u64, Vec<u8>)> = archive_map
                .iter()
                .map(|(ordinal, bytes)| (*ordinal, bytes.clone()))
                .collect();
            records.sort_by_key(|(ordinal, _)| *ordinal);
            if records.is_empty() {
                match fs::remove_file(self.dir.join(ARCHIVE_FILE)) {
                    Ok(()) => {}
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                    Err(err) => return Err(segment_io(err)),
                }
            } else {
                ArchiveStore::write_all(&self.dir, &records)?;
            }
        } else if !pending_append.is_empty() {
            let mut archive = ArchiveStore::new(&self.dir)?;
            for (ordinal, bytes) in &pending_append {
                archive.append(*ordinal, bytes)?;
            }
        }

        let mut new_archived: Vec<ArchivedSegment> = archive_map
            .into_iter()
            .map(|(id, bytes)| ArchivedSegment {
                id,
                bytes: Arc::new(bytes),
            })
            .collect();
        for (ordinal, bytes) in pending_append {
            if !new_archived.iter().any(|archived| archived.id == ordinal) {
                new_archived.push(ArchivedSegment {
                    id: ordinal,
                    bytes: Arc::new(bytes),
                });
            }
        }
        new_archived.sort_by_key(|archived| archived.id);
        self.archived = new_archived;

        for segment in &self.sealed {
            if self
                .archived
                .iter()
                .any(|archived| archived.id == segment.id)
            {
                let path = self.dir.join(segment.file_name());
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                    Err(err) => return Err(segment_io(err)),
                }
            }
        }
        self.write_manifest()?;
        Ok(())
    }

    /// Return true when the warm tier keeps a segment loose.
    fn should_keep_loose(&self, segment: &SealedSegment, tail_start: u64) -> bool {
        match self.retention {
            RetentionClass::Hot => true,
            RetentionClass::Warm => segment.contains_fault_relevant || segment.id >= tail_start,
            RetentionClass::Cold => false,
        }
    }

    /// Return the ordinal of the `KEEP_TAIL`-th newest segment.
    ///
    /// Segments at or above this ordinal form the newest tail; with fewer
    /// than `KEEP_TAIL` segments the whole store is the tail.
    fn newest_tail_start(&self) -> u64 {
        let mut ids: Vec<u64> = self.sealed.iter().map(|segment| segment.id).collect();
        ids.sort_unstable();
        if ids.len() <= KEEP_TAIL {
            return 0;
        }
        ids[ids.len() - KEEP_TAIL]
    }

    /// Return the store directory.
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    /// Return the open writer entry count.
    pub fn buffered_count(&self) -> u64 {
        self.writer.entry_count()
    }

    /// Return all persisted entries in append order.
    ///
    /// Sealed segments are walked oldest to newest, then the open writer
    /// buffer. Every frame is hash-verified during decode; a corrupt frame
    /// aborts the walk. Used by the persistent-journal facade to rebuild the
    /// in-memory DAG.
    pub(crate) fn entries_in_append_order(&self) -> Result<Vec<Arc<Entry>>, JournalError> {
        let mut out = Vec::new();
        for segment in &self.sealed {
            let block = self.decompressed_block(segment)?;
            let mut offset = 0usize;
            while offset < block.len() {
                let Some((next, payload)) = next_frame(&block, offset)? else {
                    break;
                };
                out.push(decode_frame_payload(payload)?);
                offset = next;
            }
        }
        let mut offset = 0usize;
        while offset < self.writer.buffer.len() {
            let Some((next, payload)) = next_frame(&self.writer.buffer, offset)? else {
                break;
            };
            out.push(decode_frame_payload(payload)?);
            offset = next;
        }
        Ok(out)
    }

    fn get_from_sealed(
        &self,
        segment: &SealedSegment,
        hash: &Hash,
    ) -> Result<Option<Arc<Entry>>, JournalError> {
        let block = self.decompressed_block(segment)?;
        if let Some(offset) = locate_in_block(&block, &segment.samples, hash)? {
            let payload = frame_payload_at(&block, offset)?;
            let entry = decode_frame_payload(payload)?;
            if entry.id == *hash {
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }

    fn decompressed_block(&self, segment: &SealedSegment) -> Result<Arc<Vec<u8>>, JournalError> {
        if let Some((id, block)) = self.decompressed.borrow().as_ref()
            && *id == segment.id
        {
            return Ok(Arc::clone(block));
        }
        let bytes = self.segment_bytes(segment.id)?;
        let start = HEADER_LEN;
        let end = start + segment.compressed_len as usize;
        if end > bytes.len() {
            return Err(JournalError::SegmentCorrupt(format!(
                "segment {} compressed block is truncated",
                segment.id
            )));
        }
        let compressed = &bytes[start..end];
        let block = zstd::decode_all(compressed).map_err(segment_io)?;
        if block.len() != segment.uncompressed_len as usize {
            return Err(JournalError::SegmentCorrupt(format!(
                "segment {} uncompressed length mismatch: expected {}, got {}",
                segment.id,
                segment.uncompressed_len,
                block.len()
            )));
        }
        let block = Arc::new(block);
        self.decompressed
            .replace(Some((segment.id, Arc::clone(&block))));
        Ok(block)
    }

    /// Return the full serialized bytes of a sealed segment.
    ///
    /// Archived segments read from the in-memory archive index; the rest read
    /// from their loose file.
    fn segment_bytes(&self, id: u64) -> Result<Arc<Vec<u8>>, JournalError> {
        if let Some(archived) = self.archived.iter().find(|archived| archived.id == id) {
            return Ok(Arc::clone(&archived.bytes));
        }
        let path = self.dir.join(segment_file_name(id));
        Ok(Arc::new(fs::read(&path).map_err(segment_io)?))
    }

    /// Return the archived bytes of a segment, when it is archived.
    pub(crate) fn archived_bytes(&self, id: u64) -> Option<Arc<Vec<u8>>> {
        self.archived
            .iter()
            .find(|archived| archived.id == id)
            .map(|archived| Arc::clone(&archived.bytes))
    }

    fn recover_temp_files(&mut self) {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".seg.tmp") || name.ends_with("manifest.bin.tmp") {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    fn load_sealed_segments(&mut self) -> Result<(), JournalError> {
        let manifest_path = self.dir.join(MANIFEST_FILE);
        let (mut retention, manifest_entries) = if manifest_path.is_file() {
            self.read_manifest(&manifest_path)?
        } else {
            (RetentionClass::Hot, Vec::new())
        };

        // Archive contents are the source of truth for which segments are
        // archived; the manifest flags are a hint only.
        let archive_records = ArchiveStore::load(&self.dir)?;
        let mut archived_bytes: BTreeMap<u64, Arc<Vec<u8>>> = BTreeMap::new();
        for (ordinal, bytes) in archive_records {
            archived_bytes.insert(ordinal, Arc::new(bytes));
        }

        // Prefer manifest ids; fall back to the sorted union of loose-file
        // ids and archive ordinals.
        let ids: Vec<u64> = if !manifest_entries.is_empty() {
            manifest_entries.iter().map(|entry| entry.id).collect()
        } else {
            let mut ids = self.discover_segment_ids()?;
            for ordinal in archived_bytes.keys() {
                if !ids.contains(ordinal) {
                    ids.push(*ordinal);
                }
            }
            ids.sort_unstable();
            ids
        };
        self.next_segment_id = ids.last().copied().map_or(0, |id| id + 1);

        let count = ids.len();
        let mut loaded = Vec::new();
        for (i, id) in ids.into_iter().enumerate() {
            let is_archived = archived_bytes.contains_key(&id);
            let mut segment = match if is_archived {
                parse_segment_bytes(&archived_bytes[&id], id)?
            } else {
                read_segment_meta(&self.dir, id)?
            } {
                Some(segment) => segment,
                None if i + 1 == count && !is_archived => {
                    // The last segment is a partial tail; truncate it.
                    continue;
                }
                None => {
                    return Err(JournalError::SegmentCorrupt(format!(
                        "segment {id} is corrupt and is not the tail"
                    )));
                }
            };
            segment.contains_fault_relevant = manifest_entries
                .iter()
                .find(|entry| entry.id == id)
                .is_some_and(|entry| entry.fault_relevant);
            loaded.push(segment);
        }
        self.sealed = loaded;

        for (ordinal, bytes) in archived_bytes {
            if self.sealed.iter().any(|segment| segment.id == ordinal) {
                self.archived.push(ArchivedSegment { id: ordinal, bytes });
            }
        }
        self.archived.sort_by_key(|archived| archived.id);

        // Persisted retention: the manifest class when known. When the
        // manifest is absent or legacy but an archive exists, infer the class
        // from how much of the store is archived.
        if !self.archived.is_empty() && retention == RetentionClass::Hot {
            let all_archived = self
                .sealed
                .iter()
                .all(|segment| self.archived.iter().any(|a| a.id == segment.id));
            retention = if all_archived {
                RetentionClass::Cold
            } else {
                RetentionClass::Warm
            };
        }
        self.retention = retention;
        Ok(())
    }

    fn read_manifest(
        &self,
        path: &Path,
    ) -> Result<(RetentionClass, Vec<ManifestEntry>), JournalError> {
        let mut file = File::open(path).map_err(segment_io)?;
        let mut version = [0u8; 4];
        file.read_exact(&mut version).map_err(segment_io)?;
        let version = u32::from_be_bytes(version);
        if version != 1 && version != 2 {
            return Err(JournalError::SegmentCorrupt(
                "unsupported manifest version".to_string(),
            ));
        }
        let retention = if version >= 2 {
            let mut byte = [0u8; 1];
            file.read_exact(&mut byte).map_err(segment_io)?;
            RetentionClass::from_u8(byte[0]).ok_or_else(|| {
                JournalError::SegmentCorrupt("invalid retention class in manifest".to_string())
            })?
        } else {
            RetentionClass::Hot
        };
        let mut count = [0u8; 8];
        file.read_exact(&mut count).map_err(segment_io)?;
        let count = u64::from_be_bytes(count);
        let mut entries = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let mut id = [0u8; 8];
            file.read_exact(&mut id).map_err(segment_io)?;
            let id = u64::from_be_bytes(id);
            // Skip the 68 metadata bytes to reach the next record.
            file.seek(SeekFrom::Current(MANIFEST_RECORD_META_LEN as i64))
                .map_err(segment_io)?;
            let flags = if version >= 2 {
                let mut flags = [0u8; 1];
                file.read_exact(&mut flags).map_err(segment_io)?;
                flags[0]
            } else {
                0
            };
            entries.push(ManifestEntry {
                id,
                fault_relevant: flags & 0x02 != 0,
            });
        }
        Ok((retention, entries))
    }

    fn discover_segment_ids(&self) -> Result<Vec<u64>, JournalError> {
        let mut ids = Vec::new();
        for entry in fs::read_dir(&self.dir).map_err(segment_io)? {
            let entry = entry.map_err(segment_io)?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(rest) = name.strip_prefix("segment-")
                && let Some(digits) = rest.strip_suffix(".seg")
                && let Ok(id) = digits.parse::<u64>()
            {
                ids.push(id);
            }
        }
        ids.sort_unstable();
        Ok(ids)
    }

    fn recover_wal(&mut self) -> Result<(), JournalError> {
        let wal_path = self.dir.join(WAL_FILE);
        if !wal_path.is_file() {
            return Ok(());
        }
        let mut bytes = Vec::new();
        fs::File::open(&wal_path)
            .and_then(|mut file| file.read_to_end(&mut bytes))
            .map_err(segment_io)?;
        if bytes.is_empty() {
            return Ok(());
        }
        let truncate_to = last_complete_frame_end(&bytes)?;
        if truncate_to < bytes.len() as u64 {
            fs::File::options()
                .write(true)
                .open(&wal_path)
                .and_then(|file| file.set_len(truncate_to))
                .map_err(segment_io)?;
        }

        let mut recovered = Vec::new();
        let mut offset = 0usize;
        while offset < truncate_to as usize {
            let (next, payload) = next_frame(&bytes, offset)?
                .ok_or_else(|| JournalError::SegmentCorrupt("WAL frame walk failed".to_string()))?;
            recovered.push(decode_frame_payload(payload)?);
            offset = next;
        }
        for entry in recovered {
            self.writer.append(&entry)?;
        }
        // Invariant: the WAL mirrors the open-writer contents. An append-mode
        // handle lets the next append extend the recovered WAL instead of
        // truncating it.
        if self.writer.entry_count() > 0 {
            let file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&wal_path)
                .map_err(segment_io)?;
            self.wal = Some(BufWriter::new(file));
        }
        Ok(())
    }
}

/// One manifest record for a sealed segment.
struct ManifestEntry {
    id: u64,
    fault_relevant: bool,
}

/// Return true when an entry kind belongs to the fault-relevant set.
///
/// The warm tier keeps segments carrying these kinds loose.
pub(crate) fn kind_is_fault_relevant(kind: &EntryKind) -> bool {
    matches!(
        kind,
        EntryKind::Fault { .. } | EntryKind::Outcome | EntryKind::Assert
    )
}

/// Write the full bytes of a sealed segment to its loose file atomically.
///
/// The temp file is synced before the rename, so a crash mid-write never
/// leaves a partial loose segment under its final name.
pub(crate) fn write_loose_file(dir: &Path, id: u64, bytes: &[u8]) -> Result<(), JournalError> {
    let file_name = segment_file_name(id);
    let tmp_path = dir.join(format!("{file_name}.tmp"));
    {
        let mut file = BufWriter::new(File::create(&tmp_path).map_err(segment_io)?);
        file.write_all(bytes).map_err(segment_io)?;
        file.flush().map_err(segment_io)?;
        file.get_ref().sync_all().map_err(segment_io)?;
    }
    fs::rename(&tmp_path, dir.join(&file_name)).map_err(segment_io)?;
    Ok(())
}

fn segment_file_name(id: u64) -> String {
    format!("segment-{id:06}.seg")
}

fn prefix_of(hash: &Hash) -> u32 {
    u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]])
}

fn segment_io(err: io::Error) -> JournalError {
    JournalError::SegmentCorrupt(err.to_string())
}

/// Encode one entry as a length-delimited frame.
fn encode_entry_frame(entry: &Entry) -> Result<Vec<u8>, JournalError> {
    let data_bytes = entry
        .data
        .try_canonical_bytes()
        .map_err(|err| JournalError::InvalidPayload(err.to_string()))?;
    let vc_bytes = entry.vector_clock.encode();
    let payload_len = 32 + 8 + data_bytes.len() + vc_bytes.len();
    let mut out = Vec::with_capacity(8 + payload_len);
    out.extend_from_slice(&(payload_len as u64).to_le_bytes());
    out.extend_from_slice(&entry.id);
    out.extend_from_slice(&(data_bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(&data_bytes);
    out.extend_from_slice(&vc_bytes);
    Ok(out)
}

/// Return the payload slice for the frame starting at `offset`.
fn frame_payload_at(block: &[u8], offset: u64) -> Result<&[u8], JournalError> {
    let offset = offset as usize;
    if offset + 8 > block.len() {
        return Err(JournalError::SegmentCorrupt(
            "frame offset out of bounds".to_string(),
        ));
    }
    let len =
        u64::from_le_bytes(block[offset..offset + 8].try_into().map_or([0; 8], |b| b)) as usize;
    let end = offset + 8 + len;
    if end > block.len() {
        return Err(JournalError::SegmentCorrupt(
            "frame length exceeds block".to_string(),
        ));
    }
    Ok(&block[offset + 8..end])
}

fn next_frame(block: &[u8], offset: usize) -> Result<Option<(usize, &[u8])>, JournalError> {
    if offset >= block.len() {
        return Ok(None);
    }
    if offset + 8 > block.len() {
        return Err(JournalError::SegmentCorrupt(
            "partial frame length prefix".to_string(),
        ));
    }
    let len =
        u64::from_le_bytes(block[offset..offset + 8].try_into().map_or([0; 8], |b| b)) as usize;
    if len < MIN_FRAME_PAYLOAD {
        return Err(JournalError::SegmentCorrupt(
            "frame payload below minimum size".to_string(),
        ));
    }
    let end = offset + 8 + len;
    if end > block.len() {
        return Err(JournalError::SegmentCorrupt(
            "frame extends past block end".to_string(),
        ));
    }
    Ok(Some((end, &block[offset + 8..end])))
}

/// Reconstruct an entry from a frame payload, verifying the stored hash.
fn decode_frame_payload(payload: &[u8]) -> Result<Arc<Entry>, JournalError> {
    if payload.len() < MIN_FRAME_PAYLOAD {
        return Err(JournalError::SegmentCorrupt(
            "frame payload too short".to_string(),
        ));
    }
    let mut id = Hash::default();
    id.copy_from_slice(&payload[0..32]);
    let data_len = u64::from_le_bytes(payload[32..40].try_into().map_or([0; 8], |b| b)) as usize;
    let data_end = 40 + data_len;
    if data_end > payload.len() {
        return Err(JournalError::SegmentCorrupt(
            "frame data length exceeds payload".to_string(),
        ));
    }
    let data_bytes = &payload[40..data_end];
    let vc_bytes = &payload[data_end..];

    let mut reencoded = Vec::with_capacity(data_bytes.len() + vc_bytes.len());
    reencoded.extend_from_slice(data_bytes);
    reencoded.extend_from_slice(vc_bytes);
    let recomputed = *blake3::hash(&reencoded).as_bytes();
    if recomputed != id {
        return Err(JournalError::SegmentCorrupt(
            "entry hash mismatch; data or clock corrupted".to_string(),
        ));
    }

    let data = decode_entry_data(data_bytes)?;
    let vector_clock = decode_vector_clock(vc_bytes)?;
    Ok(Arc::new(Entry {
        id,
        data,
        vector_clock,
    }))
}

/// Locate the frame holding `hash` inside an uncompressed block.
fn locate_in_block(
    block: &[u8],
    samples: &[(u64, u32)],
    hash: &Hash,
) -> Result<Option<u64>, JournalError> {
    let prefix = prefix_of(hash);
    for (i, &(sample_offset, sample_prefix)) in samples.iter().enumerate() {
        if sample_prefix != prefix {
            continue;
        }
        let window_end = samples
            .get(i + 1)
            .map_or(block.len() as u64, |&(offset, _)| offset);
        if let Some(found) = scan_window(block, sample_offset, window_end, hash)? {
            return Ok(Some(found));
        }
    }
    scan_window(block, 0, block.len() as u64, hash)
}

fn scan_window(
    block: &[u8],
    start: u64,
    end: u64,
    hash: &Hash,
) -> Result<Option<u64>, JournalError> {
    let mut offset = start as usize;
    let end = end as usize;
    while offset + 8 <= end {
        let Some((next, payload)) = next_frame(block, offset)? else {
            break;
        };
        if payload.len() >= 32 && payload[0..32] == *hash {
            return Ok(Some(offset as u64));
        }
        offset = next;
    }
    Ok(None)
}

/// Return the byte length of the longest run of complete frames in the WAL.
fn last_complete_frame_end(bytes: &[u8]) -> Result<u64, JournalError> {
    let mut offset = 0usize;
    let mut last_complete = 0usize;
    while offset + 8 <= bytes.len() {
        let len =
            u64::from_le_bytes(bytes[offset..offset + 8].try_into().map_or([0; 8], |b| b)) as usize;
        if len < MIN_FRAME_PAYLOAD {
            break;
        }
        let end = offset + 8 + len;
        if end > bytes.len() {
            break;
        }
        last_complete = end;
        offset = end;
    }
    Ok(last_complete as u64)
}

fn decode_vector_clock(bytes: &[u8]) -> Result<VectorClock, JournalError> {
    let value = CborValue::from_canonical_bytes(bytes)
        .map_err(|err| JournalError::SegmentCorrupt(err.to_string()))?;
    let mut entries = std::collections::BTreeMap::new();
    match value {
        CborValue::Map(pairs) => {
            for (key, val) in pairs {
                let actor = match key {
                    CborValue::Unsigned(actor) => actor as ActorId,
                    _ => {
                        return Err(JournalError::SegmentCorrupt(
                            "vector clock key is not an unsigned integer".to_string(),
                        ));
                    }
                };
                let count = match val {
                    CborValue::Unsigned(count) => count,
                    _ => {
                        return Err(JournalError::SegmentCorrupt(
                            "vector clock value is not an unsigned integer".to_string(),
                        ));
                    }
                };
                entries.insert(actor, count);
            }
        }
        _ => {
            return Err(JournalError::SegmentCorrupt(
                "vector clock is not a CBOR map".to_string(),
            ));
        }
    }
    Ok(VectorClock::from_map(entries))
}

fn decode_entry_data(bytes: &[u8]) -> Result<EntryData, JournalError> {
    let value = CborValue::from_canonical_bytes(bytes)
        .map_err(|err| JournalError::SegmentCorrupt(err.to_string()))?;
    let items = match value {
        CborValue::Array(items) => items,
        _ => return corrupt("entry encoding is not an array"),
    };
    if items.len() != 6 {
        return corrupt("entry encoding has wrong item count");
    }
    let kind = decode_kind(&items[0])?;
    let actor = match &items[1] {
        CborValue::Unsigned(actor) => *actor as ActorId,
        _ => return corrupt("entry actor is not an unsigned integer"),
    };
    let parents = decode_parents(&items[2])?;
    let vector_clock = decode_vc_vec(&items[3])?;
    let sequence = match &items[4] {
        CborValue::Unsigned(seq) => *seq,
        _ => return corrupt("entry sequence is not an unsigned integer"),
    };
    let payload = decode_payload(&items[5])?;
    Ok(EntryData {
        kind,
        actor,
        parents,
        vector_clock,
        sequence,
        payload,
    })
}

fn decode_parents(value: &CborValue) -> Result<Vec<Hash>, JournalError> {
    let items = match value {
        CborValue::Array(items) => items,
        _ => return corrupt("parents is not an array"),
    };
    let mut parents = Vec::with_capacity(items.len());
    for item in items {
        match item {
            CborValue::Bytes(bytes) if bytes.len() == 32 => {
                let mut hash = Hash::default();
                hash.copy_from_slice(bytes);
                parents.push(hash);
            }
            _ => return corrupt("parent is not a 32-byte hash"),
        }
    }
    Ok(parents)
}

fn decode_vc_vec(value: &CborValue) -> Result<Vec<u64>, JournalError> {
    let items = match value {
        CborValue::Array(items) => items,
        _ => return corrupt("entry vector clock is not an array"),
    };
    let mut clock = Vec::with_capacity(items.len());
    for item in items {
        match item {
            CborValue::Unsigned(value) => clock.push(*value),
            _ => return corrupt("entry vector clock component is not unsigned"),
        }
    }
    Ok(clock)
}

fn decode_kind(value: &CborValue) -> Result<EntryKind, JournalError> {
    let (tag, fields): (u64, &[CborValue]) = match value {
        CborValue::Unsigned(tag) => (*tag, &[]),
        CborValue::Array(items) => {
            let tag = match items.first() {
                Some(CborValue::Unsigned(tag)) => *tag,
                _ => return corrupt("structured kind tag is not unsigned"),
            };
            (tag, &items[1..])
        }
        _ => return corrupt("kind is neither tag nor array"),
    };
    let kind = match tag {
        0 => EntryKind::Spawn,
        1 => EntryKind::Block,
        2 => EntryKind::Wake,
        3 => EntryKind::TimerSet,
        4 => EntryKind::TimerFire,
        5 => EntryKind::ClockRead,
        6 => EntryKind::Send,
        7 => EntryKind::Recv,
        8 => EntryKind::FsWrite,
        9 => EntryKind::FsFsync,
        10 => EntryKind::FsRead,
        11 => {
            let stream = unsigned_field(fields, 0)?;
            EntryKind::RngDraw {
                stream: stream as u32,
            }
        }
        12 => EntryKind::Outcome,
        13 => EntryKind::Assert,
        14 => EntryKind::Snapshot,
        15 => EntryKind::Epoch,
        16 => {
            let generator = unsigned_field(fields, 0)?;
            let replay = unsigned_field(fields, 1)?;
            EntryKind::InputStep { generator, replay }
        }
        17 => EntryKind::CapRequest,
        18 => EntryKind::CapGrant,
        19 => EntryKind::CapInvoke,
        20 => EntryKind::CapRevoke,
        21 => {
            let fault = decode_fault(fields.first().ok_or_else(|| {
                JournalError::SegmentCorrupt("Fault kind has no fields".to_string())
            })?)?;
            EntryKind::Fault { fault }
        }
        22 => EntryKind::StepBegin,
        23 => EntryKind::StepEnd,
        _ => return corrupt("unknown kind tag"),
    };
    Ok(kind)
}

fn unsigned_field(fields: &[CborValue], index: usize) -> Result<u64, JournalError> {
    match fields.get(index) {
        Some(CborValue::Unsigned(value)) => Ok(*value),
        _ => corrupt("structured kind field is not unsigned"),
    }
}

fn decode_fault(value: &CborValue) -> Result<FaultSpec, JournalError> {
    let fault = match value {
        CborValue::Unsigned(0) => FaultSpec::Drop,
        CborValue::Unsigned(3) => FaultSpec::Crash,
        CborValue::Unsigned(4) => FaultSpec::Corrupt,
        CborValue::Array(items) => match (items.first(), items.get(1), items.get(2)) {
            (Some(CborValue::Unsigned(1)), Some(CborValue::Unsigned(ticks)), None) => {
                FaultSpec::Delay { ticks: *ticks }
            }
            (
                Some(CborValue::Unsigned(2)),
                Some(CborValue::Unsigned(src)),
                Some(CborValue::Unsigned(dst)),
            ) => FaultSpec::Partition {
                src: *src as ActorId,
                dst: *dst as ActorId,
            },
            (Some(CborValue::Unsigned(5)), Some(CborValue::Unsigned(state)), None) => {
                FaultSpec::CrashState(*state)
            }
            _ => return corrupt("unknown fault encoding"),
        },
        _ => return corrupt("unknown fault encoding"),
    };
    Ok(fault)
}

fn decode_payload(value: &CborValue) -> Result<Payload, JournalError> {
    let items = match value {
        CborValue::Array(items) => items,
        _ => return corrupt("payload is not an array"),
    };
    let tag = match items.first() {
        Some(CborValue::Unsigned(tag)) => *tag,
        _ => return corrupt("payload tag is not unsigned"),
    };
    let payload = match (tag, items.as_slice()) {
        (6, [_]) => Payload::Empty,
        (0, [_, CborValue::Unsigned(value)]) => Payload::Number(*value),
        (4, [_, value]) => match value {
            CborValue::Unsigned(value) => Payload::Signed(*value as i64),
            CborValue::Negative(value) if *value <= i64::MAX as u64 => {
                Payload::Signed(-(*value as i64) - 1)
            }
            _ => return corrupt("invalid signed payload"),
        },
        (1, [_, CborValue::Text(text)]) => Payload::Text(text.clone()),
        (2, [_, CborValue::Bytes(bytes)]) => Payload::Bytes(bytes.clone()),
        (3, [_, CborValue::Unsigned(left), CborValue::Unsigned(right)]) => Payload::Pair {
            left: *left,
            right: *right,
        },
        (5, [_, value]) => Payload::Value(value.clone()),
        _ => return corrupt("unknown payload tag"),
    };
    Ok(payload)
}

fn corrupt<T>(message: &str) -> Result<T, JournalError> {
    Err(JournalError::SegmentCorrupt(message.to_string()))
}

fn write_header(
    file: &mut impl Write,
    entry_count: u64,
    uncompressed_len: u64,
    root_hash: &Hash,
) -> Result<(), JournalError> {
    file.write_all(SEGMENT_MAGIC).map_err(segment_io)?;
    file.write_all(&1u32.to_be_bytes()).map_err(segment_io)?;
    file.write_all(&entry_count.to_be_bytes())
        .map_err(segment_io)?;
    file.write_all(&uncompressed_len.to_be_bytes())
        .map_err(segment_io)?;
    file.write_all(root_hash).map_err(segment_io)?;
    Ok(())
}

fn write_trailer(
    file: &mut impl Write,
    index_len: u32,
    sample_interval: u32,
    compressed_len: u64,
) -> Result<(), JournalError> {
    file.write_all(&index_len.to_be_bytes())
        .map_err(segment_io)?;
    file.write_all(&sample_interval.to_be_bytes())
        .map_err(segment_io)?;
    file.write_all(&compressed_len.to_be_bytes())
        .map_err(segment_io)?;
    Ok(())
}

/// Read segment metadata and sparse index from a loose file.
///
/// Returns `Ok(None)` when the file is a partial tail that does not match its
/// trailer.
fn read_segment_meta(dir: &Path, id: u64) -> Result<Option<SealedSegment>, JournalError> {
    let path = dir.join(segment_file_name(id));
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = fs::read(&path).map_err(segment_io)?;
    parse_segment_bytes(&bytes, id)
}

/// Parse segment metadata and sparse index from full serialized bytes.
///
/// The bytes must match the on-disk segment layout exactly; archived segment
/// bytes are the same as a loose file. Returns `Ok(None)` when the bytes do
/// not form a complete segment.
fn parse_segment_bytes(bytes: &[u8], id: u64) -> Result<Option<SealedSegment>, JournalError> {
    let file_len = bytes.len() as u64;
    if file_len < (HEADER_LEN + TRAILER_LEN) as u64 {
        return Ok(None);
    }

    let trailer = &bytes[file_len as usize - TRAILER_LEN..];
    let index_len = u32::from_be_bytes(trailer[0..4].try_into().map_or([0; 4], |b| b)) as usize;
    let sample_interval = u32::from_be_bytes(trailer[4..8].try_into().map_or([0; 4], |b| b));
    let compressed_len = u64::from_be_bytes(trailer[8..16].try_into().map_or([0; 8], |b| b));

    let expected_len = HEADER_LEN as u64
        + compressed_len
        + (index_len * INDEX_ENTRY_LEN) as u64
        + TRAILER_LEN as u64;
    if file_len != expected_len {
        return Ok(None);
    }
    if &bytes[0..4] != SEGMENT_MAGIC {
        return Ok(None);
    }
    let entry_count = u64::from_be_bytes(bytes[8..16].try_into().map_or([0; 8], |b| b));
    let uncompressed_len = u64::from_be_bytes(bytes[16..24].try_into().map_or([0; 8], |b| b));
    let mut root_hash = Hash::default();
    root_hash.copy_from_slice(&bytes[24..56]);

    let mut samples = Vec::with_capacity(index_len);
    let index_start = HEADER_LEN + compressed_len as usize;
    for i in 0..index_len {
        let base = index_start + i * INDEX_ENTRY_LEN;
        let entry = &bytes[base..base + INDEX_ENTRY_LEN];
        let offset = u64::from_be_bytes(entry[0..8].try_into().map_or([0; 8], |b| b));
        let prefix = u32::from_be_bytes(entry[8..12].try_into().map_or([0; 4], |b| b));
        samples.push((offset, prefix));
    }

    Ok(Some(SealedSegment {
        id,
        entry_count,
        uncompressed_len,
        compressed_len,
        root_hash,
        sample_interval,
        contains_fault_relevant: false,
        samples,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag::Journal;
    use std::vec;

    fn build_entries(count: usize, actor: ActorId, base: u64) -> Vec<Entry> {
        let mut journal = Journal::new();
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let id = journal
                .append(
                    EntryKind::InputStep {
                        generator: 0,
                        replay: 0,
                    },
                    actor,
                    [],
                    Payload::Number(base + i as u64),
                )
                .unwrap();
            out.push(journal.get(&id).unwrap().clone());
        }
        out
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ldgr-segment-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn writer_seal_round_trip_via_store() {
        let entries = build_entries(500, 1, 0);
        let dir = temp_dir("round-trip");
        let mut store = SegmentStore::new(&dir).unwrap();
        for entry in &entries {
            store.append(entry).unwrap();
        }
        store.seal_writer().unwrap();

        let reloaded = SegmentStore::load(&dir).unwrap();
        for entry in &entries {
            let found = reloaded.get(&entry.id).unwrap();
            assert!(found.is_some(), "entry must survive seal and load");
            assert_eq!(found.unwrap().data, entry.data);
        }
        assert!(reloaded.get(&Hash::default()).unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn get_via_sparse_index() {
        let entries = build_entries(10_000, 1, 0);
        let dir = temp_dir("sparse");
        let mut store = SegmentStore::new(&dir).unwrap();
        for entry in &entries {
            store.append(entry).unwrap();
        }
        store.seal_writer().unwrap();
        let reloaded = SegmentStore::load(&dir).unwrap();

        for probe in [0usize, 1, 63, 64, 511, 512, 999, 4_999, 9_999] {
            let found = reloaded.get(&entries[probe].id).unwrap();
            assert!(found.is_some(), "probe {probe} must be found");
            assert_eq!(found.unwrap().id, entries[probe].id);
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn segment_seals_at_target_size() {
        let dir = temp_dir("multi-seal");
        let mut store = SegmentStore::new(&dir).unwrap();
        for (sequence, _) in (0..3).enumerate() {
            let entry = Entry::new(
                EntryData {
                    kind: EntryKind::Outcome,
                    actor: 1,
                    parents: Vec::new(),
                    vector_clock: Vec::new(),
                    sequence: sequence as u64,
                    payload: Payload::Bytes(vec![0xab; 30 * 1024 * 1024]),
                },
                VectorClock::new(),
            )
            .unwrap();
            store.append(&entry).unwrap();
        }
        assert_eq!(
            store.segments().len(),
            1,
            "buffer must seal once past the target size"
        );
        let reloaded = SegmentStore::load(&dir).unwrap();
        assert_eq!(reloaded.segments().len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn partial_tail_truncation_recovery() {
        let entries = build_entries(200, 1, 0);
        let dir = temp_dir("wal-recovery");
        {
            let mut store = SegmentStore::new(&dir).unwrap();
            for entry in &entries {
                store.append(entry).unwrap();
            }
            // Simulate a crash mid-write: a partial frame appended to the WAL.
            let wal_path = dir.join(WAL_FILE);
            let mut file = fs::OpenOptions::new().append(true).open(&wal_path).unwrap();
            file.write_all(&0u64.to_le_bytes()).unwrap();
            file.write_all(&[0xde, 0xad, 0xbe, 0xef]).unwrap();
        }
        let store = SegmentStore::load(&dir).unwrap();
        for entry in &entries {
            assert!(
                store.get(&entry.id).unwrap().is_some(),
                "complete frames must survive recovery"
            );
        }
        let wal_bytes = fs::read(dir.join(WAL_FILE)).unwrap();
        let recovered_end = last_complete_frame_end(&wal_bytes).unwrap();
        assert_eq!(
            wal_bytes.len() as u64,
            recovered_end,
            "WAL must be truncated to last complete frame"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn recovered_tail_survives_append_and_reopen() {
        let entries = build_entries(200, 1, 0);
        let more = build_entries(50, 2, 0);
        let dir = temp_dir("wal-recover-append");
        {
            let mut store = SegmentStore::new(&dir).unwrap();
            for entry in &entries {
                store.append(entry).unwrap();
            }
            // Crash mid-write: a partial frame appended to the WAL.
            let wal_path = dir.join(WAL_FILE);
            let mut file = fs::OpenOptions::new().append(true).open(&wal_path).unwrap();
            file.write_all(&0u64.to_le_bytes()).unwrap();
            file.write_all(&[0xde, 0xad, 0xbe, 0xef]).unwrap();
        }
        // Recovery truncates the partial tail; the writer keeps the recovered
        // frames. A subsequent append must extend the recovered WAL, never
        // truncate it, so the tail survives the next reopen.
        {
            let mut store = SegmentStore::load(&dir).unwrap();
            for entry in &more {
                store.append(entry).unwrap();
            }
        }
        let reloaded = SegmentStore::load(&dir).unwrap();
        for entry in entries.iter().chain(more.iter()) {
            assert!(
                reloaded.get(&entry.id).unwrap().is_some(),
                "every frame must survive recover-then-append-then-reopen"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_wal_reopens_cleanly() {
        let dir = temp_dir("empty-wal");
        {
            let _ = SegmentStore::new(&dir).unwrap();
        }
        let mut store = SegmentStore::load(&dir).unwrap();
        // An empty writer leaves no WAL file; appending after load must
        // create a fresh WAL without any recovered-frame bookkeeping.
        let entry = Entry::new(
            EntryData {
                kind: EntryKind::Outcome,
                actor: 1,
                parents: Vec::new(),
                vector_clock: Vec::new(),
                sequence: 0,
                payload: Payload::Number(1),
            },
            VectorClock::default().incremented(1),
        )
        .unwrap();
        store.append(&entry).unwrap();
        drop(store);
        let reloaded = SegmentStore::load(&dir).unwrap();
        assert!(reloaded.get(&entry.id).unwrap().is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_last_segment_is_truncated_on_load() {
        let entries = build_entries(300, 1, 0);
        let dir = temp_dir("truncate-last");
        {
            let mut store = SegmentStore::new(&dir).unwrap();
            for entry in &entries {
                store.append(entry).unwrap();
            }
            store.seal_writer().unwrap();
            store.write_manifest().unwrap();
        }
        // Corrupt the trailer of the sealed segment file.
        let seg_path = dir.join(segment_file_name(0));
        let len = fs::metadata(&seg_path).unwrap().len();
        let mut file = fs::OpenOptions::new().write(true).open(&seg_path).unwrap();
        file.seek(SeekFrom::Start(len - 4)).unwrap();
        file.write_all(&[0xff, 0xff, 0xff, 0xff]).unwrap();

        let store = SegmentStore::load(&dir).unwrap();
        assert!(
            store.segments().is_empty(),
            "partial tail must be truncated"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_round_trip() {
        let entries = build_entries(400, 2, 0);
        let dir = temp_dir("manifest");
        {
            let mut store = SegmentStore::new(&dir).unwrap();
            for entry in &entries {
                store.append(entry).unwrap();
            }
            store.seal_writer().unwrap();
            store.write_manifest().unwrap();
        }
        let reloaded = SegmentStore::load(&dir).unwrap();
        assert_eq!(reloaded.segments().len(), 1);
        assert!(reloaded.get(&entries[123].id).unwrap().is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn multi_segment_manifest_round_trip() {
        let first = build_entries(300, 1, 0);
        let second = build_entries(200, 2, 0);
        let third = build_entries(100, 3, 0);
        let dir = temp_dir("manifest-multi");
        {
            let mut store = SegmentStore::new(&dir).unwrap();
            for entry in &first {
                store.append(entry).unwrap();
            }
            store.seal_writer().unwrap();
            for entry in &second {
                store.append(entry).unwrap();
            }
            store.seal_writer().unwrap();
            for entry in &third {
                store.append(entry).unwrap();
            }
            store.seal_writer().unwrap();
            store.write_manifest().unwrap();
        }
        let reloaded = SegmentStore::load(&dir).unwrap();
        assert_eq!(reloaded.segments().len(), 3);
        assert_eq!(reloaded.segments()[0].id, 0);
        assert_eq!(reloaded.segments()[1].id, 1);
        assert_eq!(reloaded.segments()[2].id, 2);
        assert_eq!(reloaded.segments()[0].entry_count, 300);
        assert_eq!(reloaded.segments()[1].entry_count, 200);
        assert_eq!(reloaded.segments()[2].entry_count, 100);
        for entry in first.iter().chain(&second).chain(&third) {
            assert!(
                reloaded.get(&entry.id).unwrap().is_some(),
                "every entry must survive a multi-segment manifest reload"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_then_append_preserves_recovered_tail() {
        let entries = build_entries(5, 1, 0);
        let tail = build_entries(3, 1, 5);
        let dir = temp_dir("wal-tail");
        {
            let mut store = SegmentStore::new(&dir).unwrap();
            for entry in &entries {
                store.append(entry).unwrap();
            }
        }
        {
            let mut store = SegmentStore::load(&dir).unwrap();
            for entry in &tail {
                store.append(entry).unwrap();
            }
        }
        let store = SegmentStore::load(&dir).unwrap();
        assert_eq!(store.buffered_count(), 8);
        for entry in entries.iter().chain(tail.iter()) {
            assert!(
                store.get(&entry.id).unwrap().is_some(),
                "recovered tail must survive reopen and append"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn seal_then_reopen_has_no_duplicate_replay() {
        let entries = build_entries(10, 1, 0);
        let tail = build_entries(4, 1, 10);
        let dir = temp_dir("seal-reopen");
        {
            let mut store = SegmentStore::new(&dir).unwrap();
            for entry in &entries {
                store.append(entry).unwrap();
            }
            store.seal_writer().unwrap();
            for entry in &tail {
                store.append(entry).unwrap();
            }
        }
        let store = SegmentStore::load(&dir).unwrap();
        assert_eq!(store.segments().len(), 1);
        assert_eq!(store.segments()[0].entry_count, 10);
        assert_eq!(store.buffered_count(), 4);
        for entry in entries.iter().chain(tail.iter()) {
            assert!(
                store.get(&entry.id).unwrap().is_some(),
                "every entry must be retrievable after seal and reopen"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn crash_right_after_seal_reopens_cleanly() {
        let entries = build_entries(10, 1, 0);
        let dir = temp_dir("seal-crash");
        {
            let mut store = SegmentStore::new(&dir).unwrap();
            for entry in &entries {
                store.append(entry).unwrap();
            }
            store.seal_writer().unwrap();
        }
        let store = SegmentStore::load(&dir).unwrap();
        assert_eq!(store.segments().len(), 1);
        assert_eq!(store.segments()[0].entry_count, 10);
        assert_eq!(store.buffered_count(), 0);
        for entry in &entries {
            assert!(
                store.get(&entry.id).unwrap().is_some(),
                "sealed entries must be retrievable after crash"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
