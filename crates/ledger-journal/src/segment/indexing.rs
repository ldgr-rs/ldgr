//! Entry lookup and the sparse hash index.
//!
//! Lookup consults the open writer first, then sealed segments. Sealed
//! blocks decompress on demand; [`super::SegmentStore::get_from_sealed`]
//! locates a frame with the sparse index and the root frame codec, with a
//! full window scan as backstop.
// ledger-lint:allow:fs:: (storage infrastructure uses the ambient filesystem by design)

use std::format;
use std::fs;
use std::sync::Arc;
use std::vec::Vec;

use crate::dag::{Entry, JournalError};
use ledger_format::Hash;

use super::{
    SealedSegment, SegmentStore, decode_frame_payload, frame_payload_at, next_frame, prefix_of,
    segment_file_name, segment_io,
};

impl SegmentStore {
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
        let start = segment.data_offset as usize;
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
