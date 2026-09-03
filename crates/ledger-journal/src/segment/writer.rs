//! Open-segment writer: append, seal, and recovery-log plumbing.
// ledger-lint:allow:fs:: (storage infrastructure uses the ambient filesystem by design)

use std::format;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::string::ToString;
use std::vec::Vec;

use crate::dag::{Entry, EntryFrame, JournalError, kind_is_fault_relevant};
use crate::retention::RetentionClass;
use ledger_format::EntryHash;

use super::{
    SAMPLE_INTERVAL, SealedSegment, SegmentStore, SegmentWriter, WAL_FILE, prefix_of,
    segment_file_name, segment_io, state,
};

impl SegmentWriter<state::Open> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one entry frame to the buffer.
    pub fn append(&mut self, entry: &Entry) -> Result<Vec<u8>, JournalError> {
        let frame = encode_entry_frame(entry)?;
        let offset = self.buffer.len() as u64;
        self.index.push((entry.id, offset));
        self.fault_relevant |= kind_is_fault_relevant(&entry.data.kind);
        self.buffer.extend_from_slice(&frame);
        Ok(frame)
    }

    /// Append frames for all entries, encoding each exactly once.
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

    /// Append pre-encoded journal batch frames.
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

    /// Seal the buffer into an immutable segment file.
    pub fn seal(
        self,
        dir: &Path,
        segment_id: u64,
    ) -> Result<SegmentWriter<state::Sealed>, JournalError> {
        let compressed = zstd::encode_all(&self.buffer[..], 3).map_err(segment_io)?;
        let mut samples = Vec::new();
        let mut hasher = blake3::Hasher::new();
        for (i, (id, offset)) in self.index.iter().enumerate() {
            hasher.update(&id.0);
            if i % SAMPLE_INTERVAL as usize == 0 {
                samples.push((*offset, prefix_of(id)));
            }
        }
        let root_hash = EntryHash(*hasher.finalize().as_bytes());

        let file_name = segment_file_name(segment_id);
        let tmp_path = dir.join(format!("{file_name}.tmp"));
        let data_offset = {
            let mut header = Vec::new();
            ledger_format::cbor::array(&mut header, 4);
            ledger_format::cbor::unsigned(&mut header, self.index.len() as u64);
            ledger_format::cbor::unsigned(&mut header, self.buffer.len() as u64);
            ledger_format::cbor::bytes(&mut header, &root_hash.0);
            ledger_format::cbor::unsigned(&mut header, SAMPLE_INTERVAL as u64);
            ledger_format::frame::FRAME_PREFIX_LEN + header.len()
        };
        {
            let mut file = BufWriter::new(File::create(&tmp_path).map_err(segment_io)?);
            write_header(
                &mut file,
                self.index.len() as u64,
                self.buffer.len() as u64,
                &root_hash,
                SAMPLE_INTERVAL,
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

        let fault_relevant = self.fault_relevant;
        let meta = SealedSegment {
            id: segment_id,
            entry_count: self.index.len() as u64,
            uncompressed_len: self.buffer.len() as u64,
            compressed_len: compressed.len() as u64,
            root_hash,
            sample_interval: SAMPLE_INTERVAL,
            contains_fault_relevant: fault_relevant,
            data_offset: data_offset as u64,
            samples,
        };
        Ok(SegmentWriter {
            buffer: Vec::new(),
            index: Vec::new(),
            fault_relevant,
            encode_scratch: Vec::new(),
            sealed: meta,
            _state: core::marker::PhantomData,
        })
    }
}

impl SegmentStore {
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

    fn ensure_wal(&mut self) -> Result<(), JournalError> {
        if self.wal.is_none() {
            let path = self.dir.join(WAL_FILE);
            let mut file = File::create(&path).map_err(segment_io)?;
            let mut prefix = Vec::new();
            ledger_format::frame::encode_prefix(&mut prefix, ledger_format::frame::MAGIC_WAL, 0);
            file.write_all(&prefix).map_err(segment_io)?;
            self.wal = Some(BufWriter::new(file));
        }
        Ok(())
    }

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
        let open_writer = std::mem::take(&mut self.writer);
        let sealed_handle = open_writer.seal(&self.dir, self.next_segment_id)?;
        self.next_segment_id += 1;
        self.sealed.push(sealed_handle.into_metadata());
        self.wal = None;
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

    pub fn buffered_count(&self) -> u64 {
        self.writer.entry_count()
    }
}
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
fn write_frame(buffer: &mut Vec<u8>, id: &EntryHash, data_len: usize, payload: &[u8]) {
    let payload_len = 32 + 8 + payload.len();
    buffer.reserve(8 + payload_len);
    buffer.extend_from_slice(&(payload_len as u64).to_le_bytes());
    buffer.extend_from_slice(&id.0);
    buffer.extend_from_slice(&(data_len as u64).to_le_bytes());
    buffer.extend_from_slice(payload);
}

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
    root_hash: &EntryHash,
    sample_interval: u32,
) -> Result<(), JournalError> {
    let mut header = Vec::new();
    ledger_format::cbor::array(&mut header, 4);
    ledger_format::cbor::unsigned(&mut header, entry_count);
    ledger_format::cbor::unsigned(&mut header, uncompressed_len);
    ledger_format::cbor::bytes(&mut header, &root_hash.0);
    ledger_format::cbor::unsigned(&mut header, sample_interval as u64);
    let header_len = u32::try_from(header.len())
        .map_err(|_| JournalError::SegmentCorrupt("segment header exceeds u32".to_string()))?;
    let mut prefix = Vec::new();
    ledger_format::frame::encode_prefix(
        &mut prefix,
        ledger_format::frame::MAGIC_SEGMENT,
        header_len,
    );
    file.write_all(&prefix).map_err(segment_io)?;
    file.write_all(&header).map_err(segment_io)?;
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
