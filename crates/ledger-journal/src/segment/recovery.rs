//! Boot and crash recovery: WAL truncation and temp-file cleanup.
//!
//! [`super::SegmentStore::recover_wal`] truncates a partial WAL tail to the
//! last complete frame; [`super::SegmentStore::recover_temp_files`] removes
//! stale seal temp files. Segment loading
//! ([`super::SegmentStore::load_sealed_segments`]) re-verifies sealed
//! segments and archive chains.
// ledger-lint:allow:fs:: (storage infrastructure uses the ambient filesystem by design)

use std::collections::BTreeMap;
use std::format;
use std::fs;
use std::io::{BufWriter, Read};
use std::path::Path;
use std::string::ToString;
use std::sync::Arc;
use std::vec::Vec;

use hashbrown::HashSet;

use crate::archive::ArchiveStore;
use crate::dag::JournalError;
use crate::retention::RetentionClass;
use ledger_format::EntryHash;

use super::{
    ArchivedSegment, INDEX_ENTRY_LEN, MANIFEST_FILE, MIN_FRAME_PAYLOAD, SealedSegment,
    SegmentStore, TRAILER_LEN, WAL_FILE, decode_frame_payload, next_frame, prefix_of,
    read_u32_be_at, read_u64_be_at, read_u64_le_at, segment_file_name, segment_io,
};

impl SegmentStore {
    pub(crate) fn recover_temp_files(&mut self) {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".seg.tmp")
                || name.ends_with("manifest.bin.tmp")
                || name == "archive.ldgr.tmp"
            {
                // Best-effort cleanup of a crash-left temp file. `NotFound`
                // (another process removed it) is tolerated; any other error
                // is deliberately ignored: next load re-scans and the stale
                // temp is then either still present (cleaned again) or gone.
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    pub(crate) fn load_sealed_segments(&mut self) -> Result<(), JournalError> {
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
        // ids and archive ordinals. The union uses a HashSet so discovery
        // stays O(segments) instead of O(segments^2) via Vec::contains.
        let ids: Vec<u64> = if !manifest_entries.is_empty() {
            manifest_entries.iter().map(|entry| entry.id).collect()
        } else {
            let mut ids = self.discover_segment_ids()?;
            let mut known: HashSet<u64> = ids.iter().copied().collect();
            for ordinal in archived_bytes.keys() {
                if known.insert(*ordinal) {
                    ids.push(*ordinal);
                }
            }
            ids.sort_unstable();
            ids
        };
        self.next_segment_id = ids.last().copied().map_or(0, |id| id + 1);

        let count = ids.len();
        // O(segments) fault-flag lookup; the prior per-id linear find was
        // O(segments^2) on stores with many sealed segments.
        let fault_flags: hashbrown::HashMap<u64, bool> = manifest_entries
            .iter()
            .map(|entry| (entry.id, entry.fault_relevant))
            .collect();
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
            segment.contains_fault_relevant = fault_flags.get(&id).copied().unwrap_or(false);
            loaded.push(segment);
        }
        self.sealed = loaded;

        // O(segments) sealed-membership test via a HashSet.
        let sealed_ids: HashSet<u64> = self.sealed.iter().map(|segment| segment.id).collect();
        for (ordinal, bytes) in archived_bytes {
            if sealed_ids.contains(&ordinal) {
                self.archived.push(ArchivedSegment { id: ordinal, bytes });
            }
        }
        self.archived.sort_by_key(|archived| archived.id);

        // Persisted retention: the manifest class when known. When the
        // manifest is absent or legacy but an archive exists, infer the class
        // from how much of the store is archived. HashSet keeps the check
        // O(segments).
        if !self.archived.is_empty() && retention == RetentionClass::Hot {
            let archived_ids: HashSet<u64> = self.archived.iter().map(|a| a.id).collect();
            let all_archived = self
                .sealed
                .iter()
                .all(|segment| archived_ids.contains(&segment.id));
            retention = if all_archived {
                RetentionClass::Cold
            } else {
                RetentionClass::Warm
            };
        }
        self.retention = retention;
        Ok(())
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

    pub(crate) fn recover_wal(&mut self) -> Result<(), JournalError> {
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

        // Validate the outer v2 prefix before walking frames; frames start
        // after the 16-byte prefix.
        let prefix = ledger_format::frame::parse_prefix(&bytes, ledger_format::frame::MAGIC_WAL)
            .map_err(|err| JournalError::SegmentCorrupt(format!("WAL prefix invalid: {err:?}")))?;
        if prefix.header_len != 0 {
            return Err(JournalError::SegmentCorrupt(
                "WAL header_len must be 0".to_string(),
            ));
        }
        let wal_prefix = ledger_format::frame::FRAME_PREFIX_LEN;

        // Sealed ids are content hashes, so membership is definitive.
        // Collect them before replaying the WAL so a crash window that
        // left both a sealed segment and its WAL prefix does not double
        // replay.
        let sealed_ids: HashSet<EntryHash> = self
            .entries_in_append_order()?
            .into_iter()
            .map(|entry| entry.id)
            .collect();

        let mut recovered = Vec::new();
        let mut offset = wal_prefix;
        while offset < truncate_to as usize {
            let (next, payload) = next_frame(&bytes, offset)?
                .ok_or_else(|| JournalError::SegmentCorrupt("WAL frame walk failed".to_string()))?;
            let entry = decode_frame_payload(payload)?;
            // Skip frames whose content already lives in a sealed segment.
            if !sealed_ids.contains(&entry.id) {
                recovered.push(entry);
            }
            offset = next;
        }
        for entry in &recovered {
            self.writer.append(entry)?;
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
/// Return the byte length of the longest run of complete frames in the WAL.
///
/// A length prefix that cannot fit the buffer (including a wrap-around
/// prefix near `u64::MAX`) ends the run like any truncated tail; the walk
/// never panics on hostile input.
pub(crate) fn last_complete_frame_end(bytes: &[u8]) -> Result<u64, JournalError> {
    // Frames start after the 16-byte outer prefix. A WAL with no complete
    // frame truncates to the prefix itself.
    let prefix = ledger_format::frame::FRAME_PREFIX_LEN;
    if bytes.len() < prefix {
        return Ok(0);
    }
    let mut offset = prefix;
    let mut last_complete = prefix as u64;
    while offset + 8 <= bytes.len() {
        let len = read_u64_le_at(bytes, offset);
        if len < MIN_FRAME_PAYLOAD as u64 {
            break;
        }
        // Checked span math: a wrapping prefix is an incomplete frame.
        let Some(end) = (offset as u64)
            .checked_add(8)
            .and_then(|end| end.checked_add(len))
        else {
            break;
        };
        if end > bytes.len() as u64 {
            break;
        }
        // Safe: end <= bytes.len(), so the usize conversion is lossless.
        let end = end as usize;
        last_complete = end as u64;
        offset = end;
    }
    Ok(last_complete)
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
pub(crate) fn parse_segment_bytes(
    bytes: &[u8],
    id: u64,
) -> Result<Option<SealedSegment>, JournalError> {
    let file_len = bytes.len() as u64;
    if file_len < (ledger_format::frame::FRAME_PREFIX_LEN + TRAILER_LEN) as u64 {
        return Ok(None);
    }

    let trailer = &bytes[file_len as usize - TRAILER_LEN..];
    let index_len = read_u32_be_at(trailer, 0) as usize;
    let _sample_interval = read_u32_be_at(trailer, 4);
    let compressed_len = read_u64_be_at(trailer, 8);

    // Validate the outer frame prefix first: any version other than 2 fails
    // closed before any header field is trusted.
    let prefix =
        match ledger_format::frame::parse_prefix(bytes, ledger_format::frame::MAGIC_SEGMENT) {
            Ok(prefix) => prefix,
            Err(ledger_format::FrameError::WrongMagic)
            | Err(ledger_format::FrameError::TruncatedFrame) => {
                return Ok(None);
            }
            Err(ledger_format::FrameError::UnsupportedVersion(v)) => {
                return Err(JournalError::SegmentCorrupt(format!(
                    "unsupported segment version {v}, expected 2"
                )));
            }
            Err(ledger_format::FrameError::HeaderTooLarge(_))
            | Err(ledger_format::FrameError::ReservedFlags(_)) => {
                return Ok(None);
            }
        };
    let header_len = prefix.header_len as usize;
    let header_end = ledger_format::frame::FRAME_PREFIX_LEN + header_len;
    if header_end as u64 + TRAILER_LEN as u64 > file_len {
        return Ok(None);
    }
    let header_bytes = &bytes[ledger_format::frame::FRAME_PREFIX_LEN..header_end];
    let header = match ledger_format::CborValue::from_canonical_bytes(header_bytes) {
        Ok(ledger_format::CborValue::Array(items)) if items.len() == 4 => items,
        _ => return Ok(None),
    };
    let entry_count = match &header[0] {
        ledger_format::CborValue::Unsigned(v) => *v,
        _ => return Ok(None),
    };
    let uncompressed_len = match &header[1] {
        ledger_format::CborValue::Unsigned(v) => *v,
        _ => return Ok(None),
    };
    let mut root_raw = [0u8; 32];
    match &header[2] {
        ledger_format::CborValue::Bytes(b) if b.len() == 32 => {
            root_raw.copy_from_slice(b);
        }
        _ => return Ok(None),
    }
    let root_hash = EntryHash(root_raw);
    let header_sample_interval = match &header[3] {
        ledger_format::CborValue::Unsigned(v) if *v <= u32::MAX as u64 => *v as u32,
        _ => return Ok(None),
    };

    // Belt-and-braces length arithmetic: `index_len * INDEX_ENTRY_LEN` could
    // overflow usize on a 32-bit build for a hostile trailer, so the product
    // is checked before it is compared against the real file length. Every
    // overflow path is a shape mismatch and reads as an incomplete segment,
    // matching the other `Ok(None)` returns below.
    let index_bytes = match index_len.checked_mul(INDEX_ENTRY_LEN) {
        Some(product) => product as u64,
        None => return Ok(None),
    };
    let data_offset = header_end as u64;
    let expected_len = data_offset
        .checked_add(compressed_len)
        .and_then(|v| v.checked_add(index_bytes))
        .and_then(|v| v.checked_add(TRAILER_LEN as u64));
    if expected_len != Some(file_len) {
        return Ok(None);
    }

    let mut samples = Vec::with_capacity(index_len);
    let index_start = data_offset as usize + compressed_len as usize;
    for i in 0..index_len {
        let base = index_start + i * INDEX_ENTRY_LEN;
        let entry = &bytes[base..base + INDEX_ENTRY_LEN];
        let offset = read_u64_be_at(entry, 0);
        let prefix = read_u32_be_at(entry, 8);
        samples.push((offset, prefix));
    }

    // Format review section 12: the complete decompressed segment is
    // verified before it becomes readable. Every frame is decoded (which
    // re-verifies each entry hash), then the entry count, the segment root,
    // and every sparse-index sample are recomputed from the decoded frames.
    // A sampled tail check would accept a corrupted middle.
    let compressed = &bytes[data_offset as usize..index_start];
    let block = zstd::decode_all(compressed).map_err(segment_io)?;
    if block.len() as u64 != uncompressed_len {
        return Err(JournalError::SegmentCorrupt(format!(
            "segment {id} uncompressed length mismatch: expected {uncompressed_len}, got {}",
            block.len()
        )));
    }
    let mut hasher = blake3::Hasher::new();
    let mut decoded = 0u64;
    let mut sample_pos = 0usize;
    let mut offset = 0usize;
    while let Some((next, payload)) = next_frame(&block, offset)? {
        let entry = decode_frame_payload(payload)?;
        if sample_pos < samples.len() && samples[sample_pos].0 == offset as u64 {
            if samples[sample_pos].1 != prefix_of(&entry.id) {
                return Err(JournalError::SegmentCorrupt(format!(
                    "segment {id} sparse index prefix mismatch at offset {}",
                    offset
                )));
            }
            sample_pos += 1;
        }
        hasher.update(&entry.id.0);
        decoded += 1;
        offset = next;
    }
    if decoded != entry_count {
        return Err(JournalError::SegmentCorrupt(format!(
            "segment {id} entry count mismatch: header says {entry_count}, decoded {decoded}"
        )));
    }
    if EntryHash(*hasher.finalize().as_bytes()) != root_hash {
        return Err(JournalError::SegmentCorrupt(format!(
            "segment {id} root hash mismatch after full decode"
        )));
    }
    if sample_pos != samples.len() {
        return Err(JournalError::SegmentCorrupt(format!(
            "segment {id} sparse index references {} non-frame offsets",
            samples.len() - sample_pos
        )));
    }

    Ok(Some(SealedSegment {
        id,
        entry_count,
        uncompressed_len,
        compressed_len,
        root_hash,
        sample_interval: header_sample_interval,
        contains_fault_relevant: false,
        data_offset,
        samples,
    }))
}
