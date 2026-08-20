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
//!
//! The module root keeps the segment types, the shared frame codec, and the
//! boot path. Concern-owned implementations live in the submodules:
//! [`writer`] (append and seal), [`recovery`] (WAL and temp-file recovery),
//! [`indexing`] (hash lookup and the sparse index), and [`retention`]
//! (manifest and archival policy).
// ledger-lint:allow:fs:: (storage infrastructure uses the ambient filesystem by design)

use std::cell::RefCell;
use std::format;
use std::fs::{self, File};
use std::io::{self, BufWriter};
use std::path::{Path, PathBuf};
use std::string::{String, ToString};
use std::sync::Arc;
use std::vec::Vec;

use crate::clock::VectorClock;
use crate::dag::{Entry, JournalError};
use crate::retention::RetentionClass;
use ledger_format::{CborValue, EntryData, EntryKind, FaultSpec, Hash, Payload};

mod indexing;
mod recovery;
mod retention;
mod writer;

pub(crate) use retention::write_loose_file;

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
    /// Reused canonical-encode buffer for slice appends.
    ///
    /// Cleared per entry; one allocation serves every framed entry of a
    /// slice.
    encode_scratch: Vec<u8>,
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

    /// Return the store directory.
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }
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

/// Read an 8-byte little-endian integer from `bytes[offset..offset + 8]`.
///
/// Callers bounds-check the window first; the slice is exactly 8 bytes by
/// construction, so the conversion is a plain copy (debug-asserted), with no
/// unreachable defensive arm.
fn read_u64_le_at(bytes: &[u8], offset: usize) -> u64 {
    debug_assert!(offset + 8 <= bytes.len(), "window must be bounds-checked");
    let mut array = [0u8; 8];
    array.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(array)
}

/// Read a `u32` big-endian from `bytes[offset..offset + 4]`.
///
/// Window validity is the caller's responsibility (see `read_u64_le_at`).
fn read_u32_be_at(bytes: &[u8], offset: usize) -> u32 {
    debug_assert!(offset + 4 <= bytes.len(), "window must be bounds-checked");
    let mut array = [0u8; 4];
    array.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_be_bytes(array)
}

/// Read a `u64` big-endian from `bytes[offset..offset + 8]`.
///
/// Window validity is the caller's responsibility (see `read_u64_le_at`).
fn read_u64_be_at(bytes: &[u8], offset: usize) -> u64 {
    debug_assert!(offset + 8 <= bytes.len(), "window must be bounds-checked");
    let mut array = [0u8; 8];
    array.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_be_bytes(array)
}

/// Return the payload slice for the frame starting at `offset`.
///
/// The u64 length prefix is hostile input: every span computation is
/// checked, so a prefix near `u64::MAX` yields [`JournalError::SegmentCorrupt`]
/// instead of a wrapping-index panic.
fn frame_payload_at(block: &[u8], offset: u64) -> Result<&[u8], JournalError> {
    let prefix_end = offset
        .checked_add(8)
        .ok_or_else(|| JournalError::SegmentCorrupt("frame offset out of bounds".to_string()))?;
    if prefix_end > block.len() as u64 {
        return Err(JournalError::SegmentCorrupt(
            "frame offset out of bounds".to_string(),
        ));
    }
    // Safe: prefix_end <= block.len(), so the usize conversion is lossless.
    let prefix_end = prefix_end as usize;
    let len = read_u64_le_at(block, offset as usize);
    let frame_end = (prefix_end as u64)
        .checked_add(len)
        .ok_or_else(|| JournalError::SegmentCorrupt("frame length exceeds block".to_string()))?;
    if frame_end > block.len() as u64 {
        return Err(JournalError::SegmentCorrupt(
            "frame length exceeds block".to_string(),
        ));
    }
    // Safe: frame_end <= block.len(), so the usize conversion is lossless.
    Ok(&block[prefix_end..frame_end as usize])
}

/// Walk to the frame at `offset`, validating the length prefix.
///
/// The u64 length prefix is hostile input: every span computation is
/// checked, so a prefix near `u64::MAX` yields
/// [`JournalError::SegmentCorrupt`] instead of a wrapping-index panic.
fn next_frame(block: &[u8], offset: usize) -> Result<Option<(usize, &[u8])>, JournalError> {
    if offset >= block.len() {
        return Ok(None);
    }
    let prefix_end = offset
        .checked_add(8)
        .ok_or_else(|| JournalError::SegmentCorrupt("partial frame length prefix".to_string()))?;
    if prefix_end > block.len() {
        return Err(JournalError::SegmentCorrupt(
            "partial frame length prefix".to_string(),
        ));
    }
    let len = read_u64_le_at(block, offset);
    if len < MIN_FRAME_PAYLOAD as u64 {
        return Err(JournalError::SegmentCorrupt(
            "frame payload below minimum size".to_string(),
        ));
    }
    let frame_end = (prefix_end as u64)
        .checked_add(len)
        .ok_or_else(|| JournalError::SegmentCorrupt("frame extends past block end".to_string()))?;
    if frame_end > block.len() as u64 {
        return Err(JournalError::SegmentCorrupt(
            "frame extends past block end".to_string(),
        ));
    }
    // Safe: frame_end <= block.len(), so the usize conversion is lossless.
    let frame_end = frame_end as usize;
    Ok(Some((frame_end, &block[prefix_end..frame_end])))
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
    let data_len = read_u64_le_at(payload, 32);
    // Checked span math: a hostile data length yields SegmentCorrupt, never
    // a wrapping-index panic.
    let data_end = 40u64.checked_add(data_len).ok_or_else(|| {
        JournalError::SegmentCorrupt("frame data length exceeds payload".to_string())
    })?;
    if data_end > payload.len() as u64 {
        return Err(JournalError::SegmentCorrupt(
            "frame data length exceeds payload".to_string(),
        ));
    }
    // Safe: data_end <= payload.len(), so the usize conversion is lossless.
    let data_end = data_end as usize;
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

fn decode_vector_clock(bytes: &[u8]) -> Result<VectorClock, JournalError> {
    let value = CborValue::from_canonical_bytes(bytes)
        .map_err(|err| JournalError::SegmentCorrupt(err.to_string()))?;
    let mut entries = std::collections::BTreeMap::new();
    match value {
        CborValue::Map(pairs) => {
            for (key, val) in pairs {
                let actor = match key {
                    CborValue::Unsigned(actor) => u32::try_from(actor).map_err(|_| {
                        JournalError::SegmentCorrupt("vector clock actor exceeds u32".to_string())
                    })?,
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
        CborValue::Unsigned(actor) => u32::try_from(*actor)
            .map_err(|_| JournalError::SegmentCorrupt("entry actor exceeds u32".to_string()))?,
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
                stream: u32::try_from(stream).map_err(|_| {
                    JournalError::SegmentCorrupt("rng draw stream exceeds u32".to_string())
                })?,
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
                src: u32::try_from(*src).map_err(|_| {
                    JournalError::SegmentCorrupt("partition src exceeds u32".to_string())
                })?,
                dst: u32::try_from(*dst).map_err(|_| {
                    JournalError::SegmentCorrupt("partition dst exceeds u32".to_string())
                })?,
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
            CborValue::Unsigned(value) => Payload::Signed(i64::try_from(*value).map_err(|_| {
                JournalError::SegmentCorrupt("signed payload exceeds i64".to_string())
            })?),
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

#[cfg(test)]
mod tests {
    use super::recovery::{last_complete_frame_end, parse_segment_bytes};
    use super::*;
    use crate::clock::VectorClock;
    use crate::dag::{BatchEntry, Journal};
    use ledger_format::ActorId;
    use ledger_format::Hash;
    use std::io::{Seek, SeekFrom, Write};
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
    fn hostile_trailer_lengths_are_rejected_not_wrapped() {
        // index_len = u32::MAX: the sparse index product overflows usize on
        // 32-bit builds (the checked_mul path) and cannot match the real
        // file length anywhere. Both cases must read as an incomplete
        // segment, never a panic and never a wrong-sized slice.
        let mut bytes = vec![0u8; HEADER_LEN + TRAILER_LEN];
        let trailer = &mut bytes[HEADER_LEN..];
        trailer[0..4].copy_from_slice(&(u32::MAX).to_be_bytes());
        trailer[4..8].copy_from_slice(&0u32.to_be_bytes());
        trailer[8..16].copy_from_slice(&0u64.to_be_bytes());
        assert!(parse_segment_bytes(&bytes, 1).unwrap().is_none());

        // compressed_len = u64::MAX: the expected-length addition overflows
        // u64 and must read as an incomplete segment.
        let mut bytes = vec![0u8; HEADER_LEN + TRAILER_LEN];
        let trailer = &mut bytes[HEADER_LEN..];
        trailer[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(parse_segment_bytes(&bytes, 2).unwrap().is_none());
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

    /// Build a varied stream whose kinds include the fault-relevant set.
    fn build_varied_entries(count: usize) -> Vec<Entry> {
        let mut journal = Journal::new();
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let kind = match i % 4 {
                0 => EntryKind::Outcome,
                1 => EntryKind::TimerSet,
                2 => EntryKind::Send,
                _ => EntryKind::Fault {
                    fault: ledger_format::FaultSpec::Partition { src: 1, dst: 2 },
                },
            };
            let payload = if i % 3 == 0 {
                Payload::Text(format!("payload-{i:03}"))
            } else {
                Payload::Number(i as u64)
            };
            let actor = (i % 2) as u32 + 1;
            let id = journal.append(kind, actor, [], payload).unwrap();
            out.push(journal.get(&id).unwrap().clone());
        }
        out
    }

    #[test]
    fn slice_and_frames_match_per_entry_encoding() {
        let entries = build_varied_entries(40);
        let refs: Vec<&Entry> = entries.iter().collect();

        // Per-entry reference encoding.
        let mut per_entry = SegmentWriter::new();
        for entry in &refs {
            per_entry.append(entry).unwrap();
        }

        // One-shot slice encoding through the reused scratch.
        let mut sliced = SegmentWriter::new();
        sliced.append_slice(&refs).unwrap();

        // Pre-encoded journal frames: zero CBOR passes in the writer.
        let mut source = Journal::new();
        let batch = entries
            .iter()
            .map(|entry| {
                BatchEntry::new(
                    entry.data.kind,
                    entry.data.actor,
                    entry.data.payload.clone(),
                )
            })
            .collect();
        let mut frames = Vec::new();
        source.append_batch_with_frames(batch, &mut frames).unwrap();
        // The journal must reproduce exactly these ids in append order.
        let frame_ids: Vec<Hash> = frames.iter().map(|frame| frame.id).collect();
        let journal_ids: Vec<Hash> = entries.iter().map(|entry| entry.id).collect();
        assert_eq!(frame_ids, journal_ids);

        let mut framed = SegmentWriter::new();
        framed.append_frames(&frames).unwrap();

        assert_eq!(per_entry.buffer, sliced.buffer, "slice bytes must match");
        assert_eq!(per_entry.buffer, framed.buffer, "frame bytes must match");
        assert_eq!(per_entry.index, sliced.index);
        assert_eq!(per_entry.index, framed.index);
        assert!(
            sliced.fault_relevant,
            "fault-relevant kinds must set the flag"
        );
        assert!(framed.fault_relevant, "the flag rides on EntryFrame");
    }

    #[test]
    fn empty_slice_appends_are_noops() {
        let mut writer = SegmentWriter::new();
        writer.append_slice(&[]).unwrap();
        writer.append_frames(&[]).unwrap();
        assert!(writer.is_empty());

        let dir = temp_dir("empty-slice");
        let mut store = SegmentStore::new(&dir).unwrap();
        store.append_slice(&[]).unwrap();
        store.append_frames(&[]).unwrap();
        assert_eq!(store.buffered_count(), 0);
        assert!(
            !dir.join(WAL_FILE).exists(),
            "an empty slice must not create a WAL"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_slice_wal_recovery_round_trip() {
        let entries = build_varied_entries(120);
        let refs: Vec<&Entry> = entries.iter().collect();
        let dir = temp_dir("slice-wal");
        {
            let mut store = SegmentStore::new(&dir).unwrap();
            // Mixed slices and single appends share one WAL; every byte
            // range duplicates into it contiguously.
            store.append_slice(&refs[..50]).unwrap();
            for entry in &entries[50..80] {
                store.append(entry).unwrap();
            }
            store.append_slice(&refs[80..]).unwrap();
        }
        // Simulate a crash mid-write with a partial trailing frame.
        let wal_path = dir.join(WAL_FILE);
        let mut file = fs::OpenOptions::new().append(true).open(&wal_path).unwrap();
        file.write_all(&7u64.to_le_bytes()).unwrap();
        file.write_all(&[0xde, 0xad]).unwrap();
        drop(file);

        let reloaded = SegmentStore::load(&dir).unwrap();
        assert_eq!(
            reloaded.buffered_count(),
            entries.len() as u64,
            "every complete frame must recover"
        );
        for entry in &entries {
            let found = reloaded.get(&entry.id).unwrap();
            assert!(
                found.is_some(),
                "{:02x?} must survive recovery",
                &entry.id[..4]
            );
            let found = found.unwrap();
            assert_eq!(found.id, entry.id);
            assert_eq!(found.data, entry.data);
        }
        let wal_bytes = fs::read(dir.join(WAL_FILE)).unwrap();
        let recovered_end = last_complete_frame_end(&wal_bytes).unwrap();
        assert_eq!(
            wal_bytes.len() as u64,
            recovered_end,
            "WAL truncates to the last complete frame"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Hostile length prefixes must produce typed errors, never panics.
    #[test]
    fn frame_walks_reject_hostile_length_prefixes() {
        for prefix in [
            u64::MAX,
            u64::MAX - 7, // 2^64 - 8: prefix_end + len wraps u64 exactly
            1u64 << 63,
            1u64 << 40,
            1024, // fits u64 but exceeds the buffer
            65536,
        ] {
            // next_frame: the strict walk rejects the prefix.
            let mut block = vec![0u8; 16];
            block[..8].copy_from_slice(&prefix.to_le_bytes());
            assert!(
                matches!(next_frame(&block, 0), Err(JournalError::SegmentCorrupt(_))),
                "prefix {prefix} must be rejected by next_frame, not panic"
            );
            // frame_payload_at: same rejection with a raw offset.
            assert!(
                matches!(
                    frame_payload_at(&block, 0),
                    Err(JournalError::SegmentCorrupt(_))
                ),
                "prefix {prefix} must be rejected by frame_payload_at, not panic"
            );
            // last_complete_frame_end: a prefix that cannot fit ends the run
            // like any truncated tail; never a panic and never a wrap.
            let end = last_complete_frame_end(&block).unwrap();
            assert_eq!(end, 0, "prefix {prefix} must end the complete run");
        }
    }

    /// A hostile data length inside a frame payload yields SegmentCorrupt.
    #[test]
    fn decode_frame_payload_rejects_hostile_data_length() {
        for data_len in [u64::MAX, u64::MAX - 39, 1u64 << 40, 1024] {
            let mut payload = vec![0u8; MIN_FRAME_PAYLOAD];
            payload[32..40].copy_from_slice(&data_len.to_le_bytes());
            assert!(
                matches!(
                    decode_frame_payload(&payload),
                    Err(JournalError::SegmentCorrupt(_))
                ),
                "data_len {data_len} must be rejected, not panic"
            );
        }
    }

    /// Valid frames walk exactly as before the checked-arithmetic fix.
    #[test]
    fn frame_walks_valid_path_is_unchanged() {
        let mut block = Vec::new();
        let payload_a = vec![0xabu8; 40];
        block.extend_from_slice(&(payload_a.len() as u64).to_le_bytes());
        block.extend_from_slice(&payload_a);
        let payload_b = vec![0xcdu8; 64];
        block.extend_from_slice(&(payload_b.len() as u64).to_le_bytes());
        block.extend_from_slice(&payload_b);

        let (next, found) = next_frame(&block, 0).unwrap().expect("frame one");
        assert_eq!(next, 48);
        assert_eq!(found, &payload_a[..]);
        let (next, found) = next_frame(&block, next).unwrap().expect("frame two");
        assert_eq!(next, 48 + 72);
        assert_eq!(found, &payload_b[..]);
        assert!(next_frame(&block, next).unwrap().is_none());

        assert_eq!(frame_payload_at(&block, 0).unwrap(), &payload_a[..]);
        assert_eq!(frame_payload_at(&block, 48).unwrap(), &payload_b[..]);
        assert_eq!(last_complete_frame_end(&block).unwrap(), block.len() as u64);
    }

    /// A hostile prefix after valid frames ends the run at the last complete
    /// frame, exactly like a truncated tail.
    #[test]
    fn last_complete_run_stops_at_hostile_prefix() {
        let mut wal = Vec::new();
        let payload = vec![0x11u8; 40];
        wal.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        wal.extend_from_slice(&payload);
        wal.extend_from_slice(&u64::MAX.to_le_bytes());
        let end = last_complete_frame_end(&wal).unwrap();
        assert_eq!(end, 48, "run ends before the hostile prefix");
    }

    #[test]
    fn slice_seal_produces_identical_segment_bytes() {
        let entries = build_varied_entries(30);
        let refs: Vec<&Entry> = entries.iter().collect();
        let dir_single = temp_dir("seal-single");
        let dir_slice = temp_dir("seal-slice");

        let mut single = SegmentStore::new(&dir_single).unwrap();
        for entry in &refs {
            single.append(entry).unwrap();
        }
        single.seal_writer().unwrap();

        let mut sliced = SegmentStore::new(&dir_slice).unwrap();
        sliced.append_slice(&refs).unwrap();
        sliced.seal_writer().unwrap();

        let a = fs::read(dir_single.join(segment_file_name(0))).unwrap();
        let b = fs::read(dir_slice.join(segment_file_name(0))).unwrap();
        assert_eq!(a, b, "sealed segment bytes must be identical");

        let _ = fs::remove_dir_all(&dir_single);
        let _ = fs::remove_dir_all(&dir_slice);
    }

    #[test]
    fn crash_window_sealed_and_wal_duplicate_is_deduplicated() {
        // Simulate the window where seal made the segment durable but the
        // WAL was not yet removed: both contain identical frames.
        let entries = build_entries(8, 1, 0);
        let dir = temp_dir("crash-window-dedup");
        {
            let mut store = SegmentStore::new(&dir).unwrap();
            for entry in &entries {
                store.append(entry).unwrap();
            }
            let wal_path = dir.join(WAL_FILE);
            let pre_seal_wal = fs::read(&wal_path).unwrap();
            store.seal_writer().unwrap();
            // Crash between durable rename and WAL removal: restore the
            // pre-seal WAL so both the sealed segment and its frames exist.
            fs::write(&wal_path, &pre_seal_wal).unwrap();
        }
        let store = SegmentStore::load(&dir).unwrap();
        assert_eq!(store.segments().len(), 1, "sealed segment survives");
        assert_eq!(
            store.buffered_count(),
            0,
            "duplicate WAL must not re-create buffered entries"
        );
        for entry in &entries {
            assert!(
                store.get(&entry.id).unwrap().is_some(),
                "sealed entry must remain retrievable"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_segment_bytes_rejects_unsupported_version() {
        let entries = build_entries(4, 1, 0);
        let dir = temp_dir("version-reject");
        let mut store = SegmentStore::new(&dir).unwrap();
        for entry in &entries {
            store.append(entry).unwrap();
        }
        store.seal_writer().unwrap();
        let seg_path = dir.join(segment_file_name(0));
        let mut bytes = fs::read(&seg_path).unwrap();
        // Bump version field to 99.
        bytes[4..8].copy_from_slice(&99u32.to_be_bytes());
        let err = parse_segment_bytes(&bytes, 0).unwrap_err();
        assert!(
            matches!(err, JournalError::SegmentCorrupt(_)),
            "unsupported version must be rejected, got {err:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn archive_tmp_is_removed_on_recovery() {
        let dir = temp_dir("archive-tmp");
        let _ = SegmentStore::new(&dir).unwrap();
        let tmp_path = dir.join("archive.ldgr.tmp");
        fs::write(&tmp_path, b"stale").unwrap();
        assert!(tmp_path.is_file());
        let _ = SegmentStore::load(&dir).unwrap();
        assert!(
            !tmp_path.exists(),
            "archive.ldgr.tmp must be removed on recovery"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
