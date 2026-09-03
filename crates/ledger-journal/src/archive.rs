//! Content-addressed archive of sealed segments.
//!
//! Durable base of a journal store; re-extracting restores loose files.
//!
//! File layout:
//!
//! ```text
//! [magic "LDAR" 4 bytes][version u32 BE = 1 4 bytes]
//! [record_count u64 BE 8 bytes][chain hash 32 bytes]
//! [record: ordinal u64 LE 8 bytes][len u64 LE 8 bytes]
//! [segment file bytes len bytes]
//! [record: ...]
//! ```
//!
//! Header is 48 bytes; record prefix is 16 bytes. Chain covers
//! `chain || ordinal LE || len LE || record bytes` from empty BLAKE3.
//! Header rewrite is the commit point; load re-hashes the stream.
// ledger-lint:allow:fs:: (storage infrastructure uses the ambient filesystem by design)

use std::format;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::string::ToString;
use std::vec::Vec;

use crate::dag::JournalError;
use ledger_format::EntryHash;
use ledger_format::frame::MAGIC_JOURNAL_ARCHIVE;

/// Archive file name inside a journal directory.
pub const ARCHIVE_FILE: &str = "archive.ldgr";
const ARCHIVE_FORMAT_VERSION: u32 = 1;
const CHAIN_OFFSET: usize = 16;
const HEADER_LEN: usize = 4 + 4 + 8 + 32;
const RECORD_COUNT_OFFSET: usize = 8;
const RECORD_PREFIX_LEN: usize = 16;

/// Append-only content-addressed archive store.
#[derive(Debug)]
pub struct ArchiveStore {
    file: File,
    chain: EntryHash,
    record_count: u64,
}

impl ArchiveStore {
    /// Open the archive rooted at `dir`, creating the file if needed.
    pub fn new(dir: &Path) -> Result<Self, JournalError> {
        fs::create_dir_all(dir).map_err(archive_io)?;
        let path = dir.join(ARCHIVE_FILE);
        let (file, chain, record_count) = if path.is_file() {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .map_err(archive_io)?;
            let (chain, record_count) = read_header(&mut file)?;
            file.seek(SeekFrom::End(0)).map_err(archive_io)?;
            (file, chain, record_count)
        } else {
            let mut file = File::create(&path).map_err(archive_io)?;
            let chain = initial_chain();
            write_header(&mut file, 0, &chain)?;
            (file, chain, 0)
        };
        Ok(Self {
            file,
            chain,
            record_count,
        })
    }

    /// Append one sealed segment to the archive.
    pub fn append(
        &mut self,
        segment_ordinal: u64,
        segment_bytes: &[u8],
    ) -> Result<(), JournalError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.chain.0);
        hasher.update(&segment_ordinal.to_le_bytes());
        hasher.update(&(segment_bytes.len() as u64).to_le_bytes());
        hasher.update(segment_bytes);
        let next = EntryHash(*hasher.finalize().as_bytes());

        self.file
            .write_all(&segment_ordinal.to_le_bytes())
            .map_err(archive_io)?;
        self.file
            .write_all(&(segment_bytes.len() as u64).to_le_bytes())
            .map_err(archive_io)?;
        self.file.write_all(segment_bytes).map_err(archive_io)?;
        self.file
            .seek(SeekFrom::Start(CHAIN_OFFSET as u64))
            .map_err(archive_io)?;
        self.file.write_all(&next.0).map_err(archive_io)?;
        self.file
            .seek(SeekFrom::Start(RECORD_COUNT_OFFSET as u64))
            .map_err(archive_io)?;
        self.file
            .write_all(&(self.record_count + 1).to_be_bytes())
            .map_err(archive_io)?;
        self.file.seek(SeekFrom::End(0)).map_err(archive_io)?;
        self.file.flush().map_err(archive_io)?;
        self.chain = next;
        self.record_count += 1;
        Ok(())
    }

    /// Load and hash-verify every archived segment. Empty when missing.
    pub fn load(dir: &Path) -> Result<Vec<(u64, Vec<u8>)>, JournalError> {
        let path = dir.join(ARCHIVE_FILE);
        if !path.is_file() {
            return Ok(Vec::new());
        }
        let bytes = fs::read(&path).map_err(archive_io)?;
        if bytes.len() < HEADER_LEN {
            return Err(JournalError::ArchiveHashMismatch);
        }
        if &bytes[0..4] != MAGIC_JOURNAL_ARCHIVE {
            return Err(JournalError::ArchiveHashMismatch);
        }
        let version = u32::from_be_bytes(bytes[4..8].try_into().map_or([0; 4], |b| b));
        if version != ARCHIVE_FORMAT_VERSION {
            return Err(JournalError::ArchiveHashMismatch);
        }
        let record_count = u64::from_be_bytes(bytes[8..16].try_into().map_or([0; 8], |b| b));
        let recorded_chain: EntryHash = bytes[CHAIN_OFFSET..HEADER_LEN]
            .try_into()
            .map_or(EntryHash([0; 32]), EntryHash);

        let mut chain = initial_chain();
        let mut records = Vec::new();
        let mut offset = HEADER_LEN;
        while offset < bytes.len() {
            if offset + RECORD_PREFIX_LEN > bytes.len() {
                return Err(JournalError::ArchiveHashMismatch);
            }
            let ordinal =
                u64::from_le_bytes(bytes[offset..offset + 8].try_into().map_or([0; 8], |b| b));
            let len = u64::from_le_bytes(
                bytes[offset + 8..offset + 16]
                    .try_into()
                    .map_or([0; 8], |b| b),
            ) as usize;
            offset += RECORD_PREFIX_LEN;
            if offset + len > bytes.len() {
                return Err(JournalError::ArchiveHashMismatch);
            }
            let record = &bytes[offset..offset + len];
            offset += len;
            let mut hasher = blake3::Hasher::new();
            hasher.update(&chain.0);
            hasher.update(&ordinal.to_le_bytes());
            hasher.update(&(len as u64).to_le_bytes());
            hasher.update(record);
            chain = EntryHash(*hasher.finalize().as_bytes());
            records.push((ordinal, record.to_vec()));
        }
        if chain != recorded_chain {
            return Err(JournalError::ArchiveHashMismatch);
        }
        if records.len() as u64 != record_count {
            return Err(JournalError::ArchiveHashMismatch);
        }
        Ok(records)
    }

    /// Rewrite the archive from scratch with exactly `records`.
    pub(crate) fn write_all(dir: &Path, records: &[(u64, Vec<u8>)]) -> Result<(), JournalError> {
        let path = dir.join(ARCHIVE_FILE);
        let tmp_path = dir.join(format!("{ARCHIVE_FILE}.tmp"));
        {
            let mut file = BufWriter::new(File::create(&tmp_path).map_err(archive_io)?);
            let mut chain = initial_chain();
            write_header(&mut file, records.len() as u64, &chain)?;
            for (ordinal, bytes) in records {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&chain.0);
                hasher.update(&ordinal.to_le_bytes());
                hasher.update(&(bytes.len() as u64).to_le_bytes());
                hasher.update(bytes);
                chain = EntryHash(*hasher.finalize().as_bytes());
                file.write_all(&ordinal.to_le_bytes()).map_err(archive_io)?;
                file.write_all(&(bytes.len() as u64).to_le_bytes())
                    .map_err(archive_io)?;
                file.write_all(bytes).map_err(archive_io)?;
            }
            file.seek(SeekFrom::Start(0)).map_err(archive_io)?;
            write_header(&mut file, records.len() as u64, &chain)?;
            file.flush().map_err(archive_io)?;
            file.get_ref().sync_all().map_err(archive_io)?;
        }
        fs::rename(&tmp_path, &path).map_err(archive_io)?;
        Ok(())
    }
}

fn initial_chain() -> EntryHash {
    EntryHash(*blake3::hash(b"").as_bytes())
}

fn write_header(
    file: &mut impl Write,
    record_count: u64,
    chain: &EntryHash,
) -> Result<(), JournalError> {
    file.write_all(MAGIC_JOURNAL_ARCHIVE).map_err(archive_io)?;
    file.write_all(&ARCHIVE_FORMAT_VERSION.to_be_bytes())
        .map_err(archive_io)?;
    file.write_all(&record_count.to_be_bytes())
        .map_err(archive_io)?;
    file.write_all(&chain.0).map_err(archive_io)?;
    Ok(())
}

fn read_header(file: &mut File) -> Result<(EntryHash, u64), JournalError> {
    let mut header = [0u8; HEADER_LEN];
    file.read_exact(&mut header).map_err(archive_io)?;
    if &header[0..4] != MAGIC_JOURNAL_ARCHIVE {
        return Err(JournalError::ArchiveHashMismatch);
    }
    let version = u32::from_be_bytes(header[4..8].try_into().map_or([0; 4], |b| b));
    if version != ARCHIVE_FORMAT_VERSION {
        return Err(JournalError::ArchiveHashMismatch);
    }
    let record_count = u64::from_be_bytes(header[8..16].try_into().map_or([0; 8], |b| b));
    let chain: EntryHash = header[CHAIN_OFFSET..HEADER_LEN]
        .try_into()
        .map_or(EntryHash([0; 32]), EntryHash);
    Ok((chain, record_count))
}

fn archive_io(err: std::io::Error) -> JournalError {
    JournalError::SegmentCorrupt(err.to_string())
}
