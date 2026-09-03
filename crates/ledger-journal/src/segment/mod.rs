//! Append-only segment storage with zstd-at-seal compression and WAL recovery.
//!
//! Storage uses the ambient filesystem; simulation code must use `SimFs`.
//!
//! Sealed layout:
//!
//! ```text
//! [outer prefix 16 bytes: magic "LDGS" 4 bytes]
//! [format_version u32 LE = FORMAT_VERSION 4 bytes]
//! [header_len u32 LE 4 bytes][flags u32 LE = 0 4 bytes]
//! [CBOR header header_len bytes: array(4) of
//!  entry_count unsigned, uncompressed_len unsigned,
//!  root_hash bytes(32), sample_interval unsigned]
//! [zstd-compressed frame block compressed_len bytes, level 3]
//! [sparse index: index_len x (offset u64 BE, prefix u32 BE), 12 bytes each]
//! [trailer 16 bytes: index_len u32 BE]
//! [sample_interval u32 BE][compressed_len u64 BE]
//! ```
//!
//! Frames are length-delimited and hash-verified on read.
//! Partial WAL tails truncate to the last complete frame.
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
use ledger_format::{ActorId, CborValue, EntryData, EntryHash};

mod indexing;
mod recovery;
mod retention;
mod writer;

pub(crate) use retention::write_loose_file;

/// Target size for a sealed segment.
pub const SEGMENT_TARGET_SIZE: usize = 64 * 1024 * 1024;

const SAMPLE_INTERVAL: u32 = 32;

const TRAILER_LEN: usize = 16;

const MANIFEST_RECORD_META_LEN: usize = 68;

const INDEX_ENTRY_LEN: usize = 12;

const MIN_FRAME_PAYLOAD: usize = 40;

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
    pub root_hash: EntryHash,
    /// Sparse-index sampling interval in frames.
    pub sample_interval: u32,
    /// True when any frame carries a Fault, Outcome, or Assert kind.
    pub contains_fault_relevant: bool,
    /// Byte offset where the compressed block begins.
    pub data_offset: u64,
    /// Sparse index entries, sorted by offset.
    samples: Vec<(u64, u32)>,
}

impl SealedSegment {
    /// Return the on-disk file name of this sealed segment.
    pub(crate) fn file_name(&self) -> String {
        segment_file_name(self.id)
    }
}

/// Typestate markers for segment storage lifecycles.
pub mod state {
    use super::SealedSegment;

    /// Open writer accepting appends.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Open;

    /// Sealed immutable segment.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Sealed;

    mod private {
        pub trait SealedTrait {}
        impl SealedTrait for super::Open {}
        impl SealedTrait for super::Sealed {}
    }

    /// Storage bound to a writer state.
    pub trait WriterState:
        private::SealedTrait + Clone + Copy + PartialEq + Eq + core::fmt::Debug
    {
        /// Per-state sealed storage.
        type SealedStore: Clone + core::fmt::Debug;
    }

    impl WriterState for Open {
        type SealedStore = ();
    }

    impl WriterState for Sealed {
        type SealedStore = SealedSegment;
    }
}

/// In-memory accumulation buffer for an open segment.
#[derive(Debug, Clone)]
pub struct SegmentWriter<S: state::WriterState = state::Open> {
    buffer: Vec<u8>,
    index: Vec<(EntryHash, u64)>,
    fault_relevant: bool,
    encode_scratch: Vec<u8>,
    sealed: S::SealedStore,
    _state: core::marker::PhantomData<S>,
}

impl SegmentWriter<state::Open> {
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn entry_count(&self) -> u64 {
        self.index.len() as u64
    }

    pub fn should_seal(&self) -> bool {
        self.buffer.len() >= SEGMENT_TARGET_SIZE
    }
}

impl SegmentWriter<state::Sealed> {
    pub fn metadata(&self) -> &SealedSegment {
        &self.sealed
    }

    /// Consume the sealed handle into its metadata.
    pub fn into_metadata(self) -> SealedSegment {
        self.sealed
    }

    pub fn id(&self) -> u64 {
        self.sealed.id
    }

    pub fn entry_count(&self) -> u64 {
        self.sealed.entry_count
    }

    pub fn contains_fault_relevant(&self) -> bool {
        self.sealed.contains_fault_relevant
    }

    pub fn is_empty(&self) -> bool {
        self.sealed.entry_count == 0
    }
}

impl Default for SegmentWriter<state::Open> {
    fn default() -> Self {
        Self {
            buffer: Vec::new(),
            index: Vec::new(),
            fault_relevant: false,
            encode_scratch: Vec::new(),
            sealed: (),
            _state: core::marker::PhantomData,
        }
    }
}

/// One sealed segment whose bytes live in the archive.
#[derive(Debug, Clone)]
pub struct ArchivedSegment {
    pub(crate) id: u64,
    pub(crate) bytes: Arc<Vec<u8>>,
}

/// Append-only on-disk segment store.
#[derive(Debug)]
pub struct SegmentStore {
    dir: PathBuf,
    sealed: Vec<SealedSegment>,
    archived: Vec<ArchivedSegment>,
    retention: RetentionClass,
    writer: SegmentWriter<state::Open>,
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
    pub fn set_retention(&mut self, class: RetentionClass) -> Result<(), JournalError> {
        self.retention = class;
        self.retain()
    }

    /// Open a store rooted at `dir`, creating it if necessary.
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, JournalError> {
        Self::open_internal(dir.into(), true)
    }

    /// Open a store rooted at `dir` and load its persisted state.
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

fn prefix_of(hash: &EntryHash) -> u32 {
    u32::from_le_bytes([hash.0[0], hash.0[1], hash.0[2], hash.0[3]])
}

fn segment_io(err: io::Error) -> JournalError {
    JournalError::SegmentCorrupt(err.to_string())
}

/// Read u64 LE at offset; caller bounds-checks the window.
fn read_u64_le_at(bytes: &[u8], offset: usize) -> u64 {
    debug_assert!(offset + 8 <= bytes.len(), "window must be bounds-checked");
    let mut array = [0u8; 8];
    array.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(array)
}

/// Read u32 BE at offset; caller bounds-checks the window.
fn read_u32_be_at(bytes: &[u8], offset: usize) -> u32 {
    debug_assert!(offset + 4 <= bytes.len(), "window must be bounds-checked");
    let mut array = [0u8; 4];
    array.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_be_bytes(array)
}

/// Read u64 BE at offset; caller bounds-checks the window.
fn read_u64_be_at(bytes: &[u8], offset: usize) -> u64 {
    debug_assert!(offset + 8 <= bytes.len(), "window must be bounds-checked");
    let mut array = [0u8; 8];
    array.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_be_bytes(array)
}

/// Return the payload slice for the frame at `offset`. Checked for hostile lengths.
fn frame_payload_at(block: &[u8], offset: u64) -> Result<&[u8], JournalError> {
    let prefix_end = offset
        .checked_add(8)
        .ok_or_else(|| JournalError::SegmentCorrupt("frame offset out of bounds".to_string()))?;
    if prefix_end > block.len() as u64 {
        return Err(JournalError::SegmentCorrupt(
            "frame offset out of bounds".to_string(),
        ));
    }
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
    Ok(&block[prefix_end..frame_end as usize])
}

/// Walk to the frame at `offset`. Checked for hostile lengths.
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
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&payload[0..32]);
    let id = EntryHash(raw);
    let data_len = read_u64_le_at(payload, 32);
    let data_end = 40u64.checked_add(data_len).ok_or_else(|| {
        JournalError::SegmentCorrupt("frame data length exceeds payload".to_string())
    })?;
    if data_end > payload.len() as u64 {
        return Err(JournalError::SegmentCorrupt(
            "frame data length exceeds payload".to_string(),
        ));
    }
    let data_end = data_end as usize;
    let data_bytes = &payload[40..data_end];
    let vc_bytes = &payload[data_end..];

    let mut reencoded = Vec::with_capacity(data_bytes.len() + vc_bytes.len());
    reencoded.extend_from_slice(data_bytes);
    reencoded.extend_from_slice(vc_bytes);
    let recomputed = EntryHash(*blake3::hash(&reencoded).as_bytes());
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
                    CborValue::Unsigned(actor) => ActorId(u32::try_from(actor).map_err(|_| {
                        JournalError::SegmentCorrupt("vector clock actor exceeds u32".to_string())
                    })?),
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
    // Owned by ledger-format; journal maps the error class.
    EntryData::from_canonical_bytes(bytes)
        .map_err(|err| JournalError::SegmentCorrupt(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::recovery::{last_complete_frame_end, parse_segment_bytes};
    use super::*;

    const HEADER_LEN: usize = 56;
    use crate::clock::VectorClock;
    use crate::dag::{BatchEntry, Journal};
    use ledger_format::{ActorId, EntryHash, EntryKind, EntryPayload, SequenceNumber, StreamId};
    use std::io::{Seek, SeekFrom, Write};
    use std::vec;

    fn build_entries(count: usize, actor: ActorId, base: u64) -> Vec<Entry> {
        let mut journal = Journal::new();
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let id = journal
                .append(
                    EntryKind::InputStep,
                    actor,
                    [],
                    EntryPayload::InputStep(ledger_format::InputStepPayload {
                        generator: 0,
                        replay: 0,
                        value: ledger_format::CanonicalValue::Unsigned(base + i as u64),
                    }),
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
        let entries = build_entries(500, ActorId(1), 0);
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
        assert!(reloaded.get(&EntryHash([0u8; 32])).unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn get_via_sparse_index() {
        let entries = build_entries(10_000, ActorId(1), 0);
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
        for (sequence, _) in (0..5).enumerate() {
            let entry = Entry::new(
                EntryData {
                    format_version: ledger_format::FORMAT_VERSION,
                    kind: EntryKind::RngDraw,
                    actor: ActorId(1),
                    parents: Default::default(),
                    vector_clock: Vec::new(),
                    sequence: SequenceNumber(sequence as u64),
                    payload: EntryPayload::RngDraw(ledger_format::RngDrawPayload {
                        stream: StreamId(0),
                        draw_index: 0,
                        content: vec![0xab; 16 * 1024 * 1024 - 1024],
                    }),
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
        let mut bytes = vec![0u8; HEADER_LEN + TRAILER_LEN];
        let trailer = &mut bytes[HEADER_LEN..];
        trailer[0..4].copy_from_slice(&(u32::MAX).to_be_bytes());
        trailer[4..8].copy_from_slice(&0u32.to_be_bytes());
        trailer[8..16].copy_from_slice(&0u64.to_be_bytes());
        assert!(parse_segment_bytes(&bytes, 1).unwrap().is_none());

        let mut bytes = vec![0u8; HEADER_LEN + TRAILER_LEN];
        let trailer = &mut bytes[HEADER_LEN..];
        trailer[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(parse_segment_bytes(&bytes, 2).unwrap().is_none());
    }

    #[test]
    fn partial_tail_truncation_recovery() {
        let entries = build_entries(200, ActorId(1), 0);
        let dir = temp_dir("wal-recovery");
        {
            let mut store = SegmentStore::new(&dir).unwrap();
            for entry in &entries {
                store.append(entry).unwrap();
            }
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
        let entries = build_entries(200, ActorId(1), 0);
        let more = build_entries(50, ActorId(2), 0);
        let dir = temp_dir("wal-recover-append");
        {
            let mut store = SegmentStore::new(&dir).unwrap();
            for entry in &entries {
                store.append(entry).unwrap();
            }
            let wal_path = dir.join(WAL_FILE);
            let mut file = fs::OpenOptions::new().append(true).open(&wal_path).unwrap();
            file.write_all(&0u64.to_le_bytes()).unwrap();
            file.write_all(&[0xde, 0xad, 0xbe, 0xef]).unwrap();
        }
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
        let entry = Entry::new(
            EntryData {
                format_version: ledger_format::FORMAT_VERSION,
                kind: EntryKind::Outcome,
                actor: ActorId(1),
                parents: Default::default(),
                vector_clock: Vec::new(),
                sequence: SequenceNumber(0),
                payload: EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: EntryHash([0x00; 32]),
                    value: ledger_format::CanonicalValue::Unsigned(1),
                }),
            },
            VectorClock::default().incremented(ActorId(1)),
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
        let entries = build_entries(300, ActorId(1), 0);
        let dir = temp_dir("truncate-last");
        {
            let mut store = SegmentStore::new(&dir).unwrap();
            for entry in &entries {
                store.append(entry).unwrap();
            }
            store.seal_writer().unwrap();
            store.write_manifest().unwrap();
        }
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
        let entries = build_entries(400, ActorId(2), 0);
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
        let first = build_entries(300, ActorId(1), 0);
        let second = build_entries(200, ActorId(2), 0);
        let third = build_entries(100, ActorId(3), 0);
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
        let entries = build_entries(5, ActorId(1), 0);
        let tail = build_entries(3, ActorId(1), 5);
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
        let entries = build_entries(10, ActorId(1), 0);
        let tail = build_entries(4, ActorId(1), 10);
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
        let entries = build_entries(10, ActorId(1), 0);
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

    fn build_varied_entries(count: usize) -> Vec<Entry> {
        let mut journal = Journal::new();
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let value = i as u64;
            let (kind, payload) = match i % 4 {
                0 => (
                    EntryKind::Outcome,
                    EntryPayload::Outcome(ledger_format::OutcomePayload {
                        schema: EntryHash([0x00; 32]),
                        value: ledger_format::CanonicalValue::Unsigned(value),
                    }),
                ),
                1 => (
                    EntryKind::TimerSet,
                    EntryPayload::TimerSet {
                        timer_id: value,
                        deadline_ticks: value,
                    },
                ),
                2 => (
                    EntryKind::Send,
                    EntryPayload::Send(ledger_format::SendFrame {
                        message_id: ledger_format::MessageId::new(ActorId(1), value),
                        from: ActorId(1),
                        to: ActorId(2),
                        original_content: value.to_le_bytes().to_vec(),
                    }),
                ),
                _ => (
                    EntryKind::Fault,
                    EntryPayload::Fault(ledger_format::FaultPayload::Partition {
                        src: ActorId(1),
                        dst: ActorId(2),
                        enabled: true,
                    }),
                ),
            };
            let actor = ActorId((i % 2) as u32 + 1);
            let id = journal.append(kind, actor, [], payload).unwrap();
            out.push(journal.get(&id).unwrap().clone());
        }
        out
    }

    #[test]
    fn slice_and_frames_match_per_entry_encoding() {
        let entries = build_varied_entries(40);
        let refs: Vec<&Entry> = entries.iter().collect();

        let mut per_entry = SegmentWriter::new();
        for entry in &refs {
            per_entry.append(entry).unwrap();
        }

        let mut sliced = SegmentWriter::new();
        sliced.append_slice(&refs).unwrap();

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
        let frame_ids: Vec<EntryHash> = frames.iter().map(|frame| frame.id).collect();
        let journal_ids: Vec<EntryHash> = entries.iter().map(|entry| entry.id).collect();
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
            store.append_slice(&refs[..50]).unwrap();
            for entry in &entries[50..80] {
                store.append(entry).unwrap();
            }
            store.append_slice(&refs[80..]).unwrap();
        }
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
                &entry.id.0[..4]
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
            let mut block = vec![0u8; 16];
            block[..8].copy_from_slice(&prefix.to_le_bytes());
            assert!(
                matches!(next_frame(&block, 0), Err(JournalError::SegmentCorrupt(_))),
                "prefix {prefix} must be rejected by next_frame, not panic"
            );
            assert!(
                matches!(
                    frame_payload_at(&block, 0),
                    Err(JournalError::SegmentCorrupt(_))
                ),
                "prefix {prefix} must be rejected by frame_payload_at, not panic"
            );
            let mut wal = Vec::new();
            ledger_format::frame::encode_prefix(&mut wal, ledger_format::frame::MAGIC_WAL, 0);
            wal.extend_from_slice(&prefix.to_le_bytes());
            let end = last_complete_frame_end(&wal).unwrap();
            assert_eq!(
                end,
                ledger_format::frame::FRAME_PREFIX_LEN as u64,
                "prefix {prefix} must end the complete run"
            );
        }
    }

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
        let mut wal = Vec::new();
        ledger_format::frame::encode_prefix(&mut wal, ledger_format::frame::MAGIC_WAL, 0);
        wal.extend_from_slice(&block);
        assert_eq!(last_complete_frame_end(&wal).unwrap(), wal.len() as u64);
    }

    #[test]
    fn last_complete_run_stops_at_hostile_prefix() {
        let mut wal = Vec::new();
        ledger_format::frame::encode_prefix(&mut wal, ledger_format::frame::MAGIC_WAL, 0);
        let payload = vec![0x11u8; 40];
        wal.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        wal.extend_from_slice(&payload);
        wal.extend_from_slice(&u64::MAX.to_le_bytes());
        let end = last_complete_frame_end(&wal).unwrap();
        assert_eq!(
            end,
            (ledger_format::frame::FRAME_PREFIX_LEN + 48) as u64,
            "run ends before the hostile prefix"
        );
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
        let entries = build_entries(8, ActorId(1), 0);
        let dir = temp_dir("crash-window-dedup");
        {
            let mut store = SegmentStore::new(&dir).unwrap();
            for entry in &entries {
                store.append(entry).unwrap();
            }
            let wal_path = dir.join(WAL_FILE);
            let pre_seal_wal = fs::read(&wal_path).unwrap();
            store.seal_writer().unwrap();
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
        let entries = build_entries(4, ActorId(1), 0);
        let dir = temp_dir("version-reject");
        let mut store = SegmentStore::new(&dir).unwrap();
        for entry in &entries {
            store.append(entry).unwrap();
        }
        store.seal_writer().unwrap();
        let seg_path = dir.join(segment_file_name(0));
        let mut bytes = fs::read(&seg_path).unwrap();
        bytes[4..8].copy_from_slice(&99u32.to_le_bytes());
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

    #[test]
    fn seal_returns_sealed_handle_with_read_methods() {
        let entries = build_entries(64, ActorId(1), 0);
        let dir = temp_dir("typestate-seal");
        fs::create_dir_all(&dir).unwrap();
        let mut open = SegmentWriter::new();
        for entry in &entries {
            open.append(entry).unwrap();
        }
        assert_eq!(open.entry_count(), 64);
        assert!(!open.is_empty());
        let sealed = open.seal(&dir, 7).unwrap();
        assert_eq!(sealed.id(), 7);
        assert_eq!(sealed.entry_count(), 64);
        assert!(!sealed.is_empty());
        let meta = sealed.into_metadata();
        assert_eq!(meta.id, 7);
        assert_eq!(meta.entry_count, 64);
        assert_eq!(meta.sample_interval, super::SAMPLE_INTERVAL);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sealed_file_matches_documented_layout() {
        let entries = build_entries(40, ActorId(1), 0);
        let dir = temp_dir("layout-pin");
        let mut store = SegmentStore::new(&dir).unwrap();
        for entry in &entries {
            store.append(entry).unwrap();
        }
        store.seal_writer().unwrap();
        let bytes = fs::read(dir.join(segment_file_name(0))).unwrap();
        assert_eq!(&bytes[0..4], b"LDGS");
        assert_eq!(
            u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            ledger_format::FORMAT_VERSION
        );
        let header_len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), 0);
        let segment = &store.segments()[0];
        assert_eq!(
            segment.data_offset,
            (ledger_format::frame::FRAME_PREFIX_LEN + header_len) as u64
        );
        let trailer = &bytes[bytes.len() - super::TRAILER_LEN..];
        let index_len = u32::from_be_bytes(trailer[0..4].try_into().unwrap()) as usize;
        assert_eq!(
            u32::from_be_bytes(trailer[4..8].try_into().unwrap()),
            segment.sample_interval
        );
        let compressed_len = u64::from_be_bytes(trailer[8..16].try_into().unwrap());
        assert_eq!(compressed_len, segment.compressed_len);
        assert_eq!(
            bytes.len() as u64,
            segment.data_offset
                + compressed_len
                + (index_len * super::INDEX_ENTRY_LEN) as u64
                + super::TRAILER_LEN as u64
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
