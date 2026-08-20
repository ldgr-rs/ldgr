//! Open-segment writer: append, seal, and recovery-log plumbing.
//!
//! [`super::SegmentWriter`] accumulates frames and seals them into an
//! immutable segment file with a sparse index. The [`super::SegmentStore`]
//! writer methods keep the WAL byte-identical to the writer buffer and seal
//! on size.
// ledger-lint:allow:fs:: (storage infrastructure uses the ambient filesystem by design)

use std::format;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::string::ToString;
use std::vec::Vec;

use crate::dag::{Entry, EntryFrame, JournalError, kind_is_fault_relevant};
use crate::retention::RetentionClass;
use ledger_format::Hash;

use super::{
    SAMPLE_INTERVAL, SEGMENT_MAGIC, SEGMENT_TARGET_SIZE, SealedSegment, SegmentStore,
    SegmentWriter, WAL_FILE, prefix_of, segment_file_name, segment_io,
};

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

    /// Append frames for all entries, encoding each exactly once.
    ///
    /// Frames assemble directly into the segment buffer from one reused
    /// encode scratch, so a slice costs no per-frame allocations beyond
    /// index growth. Byte layout is identical to per-entry [`Self::append`].
    pub fn append_slice(&mut self, entries: &[&Entry]) -> Result<(), JournalError> {
        if entries.is_empty() {
            return Ok(());
        }
        self.index.reserve(entries.len());
        for entry in entries {
            let data_len = encode_entry_payload(entry, &mut self.encode_scratch)?;
            let offset = self.buffer.len() as u64;
            write_frame(&mut self.buffer, &entry.id, data_len, &self.encode_scratch);
            self.index.push((entry.id, offset));
            self.fault_relevant |= kind_is_fault_relevant(&entry.data.kind);
        }
        Ok(())
    }

    /// Append pre-encoded frames produced by
    /// [`crate::dag::Journal::append_batch_with_frames`].
    ///
    /// The canonical bytes leave the journal once and are copied straight
    /// into the segment buffer; no CBOR pass runs here at all.
    pub fn append_frames(&mut self, frames: &[EntryFrame]) -> Result<(), JournalError> {
        if frames.is_empty() {
            return Ok(());
        }
        self.index.reserve(frames.len());
        for frame in frames {
            let offset = self.buffer.len() as u64;
            write_frame(&mut self.buffer, &frame.id, frame.data_len, &frame.payload);
            self.index.push((frame.id, offset));
            self.fault_relevant |= frame.fault_relevant;
        }
        Ok(())
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
                // Sample count is bounded by the in-memory index: one sample
                // pair per SAMPLE_INTERVAL entries, so u32 cannot truncate
                // before the index itself exhausts memory.
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

impl SegmentStore {
    /// Append one entry. Seals the open segment when the buffer is full.
    pub fn append(&mut self, entry: &Entry) -> Result<(), JournalError> {
        self.ensure_wal()?;
        let frame = self.writer.append(entry)?;
        if let Some(wal) = self.wal.as_mut() {
            wal.write_all(&frame).map_err(segment_io)?;
        }
        if self.writer.should_seal() {
            self.seal_writer()?;
        }
        Ok(())
    }

    /// Append frames for a slice of entries with one recovery-log write.
    ///
    /// Frames encode once into the writer and duplicate to the WAL as one
    /// contiguous write_all, so the durable byte stream is identical to
    /// per-entry appends while syscall and encoding counts drop per batch.
    /// The seal check runs once after the whole slice.
    pub fn append_slice(&mut self, entries: &[&Entry]) -> Result<(), JournalError> {
        if entries.is_empty() {
            return Ok(());
        }
        self.ensure_wal()?;
        let start = self.writer.len();
        self.writer.append_slice(entries)?;
        self.write_wal_range(start)?;
        if self.writer.should_seal() {
            self.seal_writer()?;
        }
        Ok(())
    }

    /// Append pre-encoded journal batch frames with one recovery-log write.
    ///
    /// See [`Self::append_slice`]; this variant skips even the storage-side
    /// canonical encode by consuming [`EntryFrame`] bytes.
    pub fn append_frames(&mut self, frames: &[EntryFrame]) -> Result<(), JournalError> {
        if frames.is_empty() {
            return Ok(());
        }
        self.ensure_wal()?;
        let start = self.writer.len();
        self.writer.append_frames(frames)?;
        self.write_wal_range(start)?;
        if self.writer.should_seal() {
            self.seal_writer()?;
        }
        Ok(())
    }

    /// Open the recovery log when the store has none yet.
    fn ensure_wal(&mut self) -> Result<(), JournalError> {
        if self.wal.is_none() {
            let path = self.dir.join(WAL_FILE);
            let file = File::create(&path).map_err(segment_io)?;
            self.wal = Some(BufWriter::new(file));
        }
        Ok(())
    }

    /// Duplicate writer bytes from `start` into the recovery log.
    fn write_wal_range(&mut self, start: usize) -> Result<(), JournalError> {
        if let Some(wal) = self.wal.as_mut() {
            wal.write_all(&self.writer.buffer[start..])
                .map_err(segment_io)?;
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

    /// Return the open writer entry count.
    pub fn buffered_count(&self) -> u64 {
        self.writer.entry_count()
    }
}
/// Encode `data || vector_clock` into `scratch`; return the data prefix len.
fn encode_entry_payload(entry: &Entry, scratch: &mut Vec<u8>) -> Result<usize, JournalError> {
    scratch.clear();
    entry
        .data
        .encode_into(scratch)
        .map_err(|err| JournalError::InvalidPayload(err.to_string()))?;
    let data_len = scratch.len();
    entry.vector_clock.encode_into(scratch);
    Ok(data_len)
}

/// Append one length-delimited frame for an already-encoded payload.
///
/// `payload` is the canonical `data || vector_clock` bytes, split at
/// `data_len`. Field order and widths are identical to the framing of
/// `encode_entry_frame`; a test pins the two byte-for-byte equal.
fn write_frame(buffer: &mut Vec<u8>, id: &Hash, data_len: usize, payload: &[u8]) {
    let payload_len = 32 + 8 + payload.len();
    buffer.reserve(8 + payload_len);
    buffer.extend_from_slice(&(payload_len as u64).to_le_bytes());
    buffer.extend_from_slice(id);
    buffer.extend_from_slice(&(data_len as u64).to_le_bytes());
    buffer.extend_from_slice(payload);
}

/// Encode one entry as a length-delimited frame.
fn encode_entry_frame(entry: &Entry) -> Result<Vec<u8>, JournalError> {
    let mut scratch = Vec::new();
    let data_len = encode_entry_payload(entry, &mut scratch)?;
    let mut out = Vec::with_capacity(8 + 32 + 8 + scratch.len());
    write_frame(&mut out, &entry.id, data_len, &scratch);
    Ok(out)
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
