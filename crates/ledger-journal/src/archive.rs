//! Content-addressed archive of sealed segments.
//!
//! The archive is the always-recoverable durable base of a journal store. A
//! cold store keeps only the manifest and this file. A warm store keeps the
//! newest and fault-relevant segments loose and moves the rest here. Raising
//! the retention class re-extracts archived segments back to loose files, so
//! nothing is ever lost.
//!
//! File layout:
//!
//! ```text
//! [magic "LDAR" 4 bytes][version u32 BE][record_count u64 BE]
//! [chain hash 32 bytes]
//! [record: ordinal u64 LE][len u64 LE][segment file bytes]
//! [record: ...]
//! ```
//!
//! The chain hash is a running BLAKE3 hash over the whole record stream.
//! Each append advances the chain and rewrites the header. The header
//! rewrite is the commit point. On load the whole stream is re-hashed and
//! compared against the recorded chain, so a torn write, truncation, or byte
//! flip is detected. Each record holds the full serialized bytes of one
//! sealed `segment-NNNNNN.seg` file, including its own header and trailer.
// ledger-lint:allow:fs:: (storage infrastructure uses the ambient filesystem by design)

use std::format;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::string::ToString;
use std::vec::Vec;

use crate::dag::JournalError;
use ledger_format::Hash;

/// Name of the archive file inside a journal directory.
pub const ARCHIVE_FILE: &str = "archive.ldgr";
/// Four-byte magic identifying an archive file.
const ARCHIVE_MAGIC: &[u8; 4] = b"LDAR";
/// Archive format version.
const ARCHIVE_FORMAT_VERSION: u32 = 1;
/// Byte offset of the chain hash within the header.
const CHAIN_OFFSET: usize = 16;
/// Total header length: magic, version, record count, chain hash.
const HEADER_LEN: usize = 4 + 4 + 8 + 32;
/// Byte offset of the record count within the header.
const RECORD_COUNT_OFFSET: usize = 8;
/// Bytes of one record prefix: ordinal and length.
const RECORD_PREFIX_LEN: usize = 16;

/// Append-only content-addressed archive store.
#[derive(Debug)]
pub struct ArchiveStore {
    file: File,
    chain: Hash,
    record_count: u64,
}

impl ArchiveStore {
    /// Open the archive rooted at `dir`, creating the file if needed.
    ///
    /// An existing stream is continued from the recorded chain hash and
    /// record count.
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
    ///
    /// The chain hash in the header is rewritten to the new running hash;
    /// that rewrite is the commit point.
    pub fn append(
        &mut self,
        segment_ordinal: u64,
        segment_bytes: &[u8],
    ) -> Result<(), JournalError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.chain);
        hasher.update(&segment_ordinal.to_le_bytes());
        hasher.update(&(segment_bytes.len() as u64).to_le_bytes());
        hasher.update(segment_bytes);
        let next = *hasher.finalize().as_bytes();

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
        self.file.write_all(&next).map_err(archive_io)?;
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

    /// Load and hash-verify every archived segment.
    ///
    /// Returns an empty vector when the archive file does not exist. A chain
    /// mismatch, truncation, or structural defect returns
    /// [`JournalError::ArchiveHashMismatch`].
    pub fn load(dir: &Path) -> Result<Vec<(u64, Vec<u8>)>, JournalError> {
        let path = dir.join(ARCHIVE_FILE);
        if !path.is_file() {
            return Ok(Vec::new());
        }
        let bytes = fs::read(&path).map_err(archive_io)?;
        if bytes.len() < HEADER_LEN {
            return Err(JournalError::ArchiveHashMismatch);
        }
        if &bytes[0..4] != ARCHIVE_MAGIC {
            return Err(JournalError::ArchiveHashMismatch);
        }
        let version = u32::from_be_bytes(bytes[4..8].try_into().map_or([0; 4], |b| b));
        if version != ARCHIVE_FORMAT_VERSION {
            return Err(JournalError::ArchiveHashMismatch);
        }
        let record_count = u64::from_be_bytes(bytes[8..16].try_into().map_or([0; 8], |b| b));
        let recorded_chain: Hash = bytes[CHAIN_OFFSET..HEADER_LEN]
            .try_into()
            .map_or([0; 32], |b| b);

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
            hasher.update(&chain);
            hasher.update(&ordinal.to_le_bytes());
            hasher.update(&(len as u64).to_le_bytes());
            hasher.update(record);
            chain = *hasher.finalize().as_bytes();
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
    ///
    /// Used when a retention change re-extracts segments. The file is written
    /// atomically (temp file plus rename).
    pub(crate) fn write_all(dir: &Path, records: &[(u64, Vec<u8>)]) -> Result<(), JournalError> {
        let path = dir.join(ARCHIVE_FILE);
        let tmp_path = dir.join(format!("{ARCHIVE_FILE}.tmp"));
        {
            let mut file = BufWriter::new(File::create(&tmp_path).map_err(archive_io)?);
            let mut chain = initial_chain();
            write_header(&mut file, records.len() as u64, &chain)?;
            for (ordinal, bytes) in records {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&chain);
                hasher.update(&ordinal.to_le_bytes());
                hasher.update(&(bytes.len() as u64).to_le_bytes());
                hasher.update(bytes);
                chain = *hasher.finalize().as_bytes();
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

/// The chain hash of an empty record stream.
fn initial_chain() -> Hash {
    *blake3::hash(b"").as_bytes()
}

fn write_header(
    file: &mut impl Write,
    record_count: u64,
    chain: &Hash,
) -> Result<(), JournalError> {
    file.write_all(ARCHIVE_MAGIC).map_err(archive_io)?;
    file.write_all(&ARCHIVE_FORMAT_VERSION.to_be_bytes())
        .map_err(archive_io)?;
    file.write_all(&record_count.to_be_bytes())
        .map_err(archive_io)?;
    file.write_all(chain).map_err(archive_io)?;
    Ok(())
}

fn read_header(file: &mut File) -> Result<(Hash, u64), JournalError> {
    let mut header = [0u8; HEADER_LEN];
    file.read_exact(&mut header).map_err(archive_io)?;
    if &header[0..4] != ARCHIVE_MAGIC {
        return Err(JournalError::ArchiveHashMismatch);
    }
    let version = u32::from_be_bytes(header[4..8].try_into().map_or([0; 4], |b| b));
    if version != ARCHIVE_FORMAT_VERSION {
        return Err(JournalError::ArchiveHashMismatch);
    }
    let record_count = u64::from_be_bytes(header[8..16].try_into().map_or([0; 8], |b| b));
    let chain: Hash = header[CHAIN_OFFSET..HEADER_LEN]
        .try_into()
        .map_or([0; 32], |b| b);
    Ok((chain, record_count))
}

fn archive_io(err: std::io::Error) -> JournalError {
    JournalError::SegmentCorrupt(err.to_string())
}
