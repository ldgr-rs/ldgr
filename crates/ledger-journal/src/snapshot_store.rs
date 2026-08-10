//! On-disk snapshot persistence.
//!
//! Snapshots append to a single `snapshots.ldgr` file. The file starts with a
//! header holding a format version and a running BLAKE3 chain hash over the
//! whole record stream, so the file is content-addressed. Each append extends
//! the record stream and rewrites the chain hash in the header. The header
//! rewrite is the commit point. On load the entire record stream is re-hashed
//! and compared against the recorded chain, so a torn write or truncation is
//! detected.
//!
//! File layout:
//!
//! ```text
//! [magic "LDSN" 4 bytes][version u32 BE][chain hash 32 bytes]
//! [record: len u64 LE][snapshot canonical bytes]
//! [record: len u64 LE][snapshot canonical bytes]
//! ...
//! ```
// ledger-lint:allow:fs:: (storage infrastructure uses the ambient filesystem by design)

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::string::ToString;
use std::vec::Vec;

use crate::dag::JournalError;
use crate::snapshot::Snapshot;
use ledger_format::Hash;

/// Name of the snapshot store file inside a journal directory.
const SNAPSHOT_FILE: &str = "snapshots.ldgr";
/// Four-byte magic identifying a snapshot store file.
const SNAPSHOT_MAGIC: &[u8; 4] = b"LDSN";
/// Snapshot store format version.
const SNAPSHOT_FORMAT_VERSION: u32 = 1;
/// Byte offset of the chain hash within the header.
const CHAIN_OFFSET: usize = 8;
/// Total header length: magic, version, chain hash.
const HEADER_LEN: usize = 4 + 4 + 32;

/// Append-only on-disk snapshot store.
///
/// The chain hash is kept in memory and rewritten to the header on every
/// append.
#[derive(Debug)]
pub struct SnapshotStore {
    file: File,
    chain: Hash,
}

impl SnapshotStore {
    /// Open the store rooted at `dir`, creating the file if needed.
    ///
    /// An existing stream is continued from the recorded chain hash.
    pub fn new(dir: &Path) -> Result<Self, JournalError> {
        fs::create_dir_all(dir).map_err(snapshot_io)?;
        let path = dir.join(SNAPSHOT_FILE);
        let (file, chain) = if path.is_file() {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .map_err(snapshot_io)?;
            let chain = read_header_chain(&mut file)?;
            file.seek(SeekFrom::End(0)).map_err(snapshot_io)?;
            (file, chain)
        } else {
            let mut file = File::create(&path).map_err(snapshot_io)?;
            let chain = initial_chain();
            write_header(&mut file, &chain)?;
            (file, chain)
        };
        Ok(Self { file, chain })
    }

    /// Append one snapshot to the record stream.
    ///
    /// The chain hash in the header is rewritten after the record; that
    /// rewrite is the commit point. A crash before it leaves the file
    /// detectable as corrupt on the next load.
    pub fn append(&mut self, snapshot: &Snapshot) -> Result<(), JournalError> {
        let record = snapshot.to_canonical_bytes();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.chain);
        hasher.update(&record);
        let next = *hasher.finalize().as_bytes();

        self.file
            .write_all(&(record.len() as u64).to_le_bytes())
            .map_err(snapshot_io)?;
        self.file.write_all(&record).map_err(snapshot_io)?;
        self.file
            .seek(SeekFrom::Start(CHAIN_OFFSET as u64))
            .map_err(snapshot_io)?;
        self.file.write_all(&next).map_err(snapshot_io)?;
        self.file.seek(SeekFrom::End(0)).map_err(snapshot_io)?;
        self.file.flush().map_err(snapshot_io)?;
        self.chain = next;
        Ok(())
    }

    /// Load and hash-verify every persisted snapshot.
    ///
    /// Returns an empty vector when the store file does not exist. A chain
    /// mismatch or a partial record tail returns [`JournalError::SnapshotHashMismatch`];
    /// a structurally invalid header or record returns
    /// [`JournalError::SnapshotStoreError`].
    pub fn load(dir: &Path) -> Result<Vec<Snapshot>, JournalError> {
        let path = dir.join(SNAPSHOT_FILE);
        if !path.is_file() {
            return Ok(Vec::new());
        }
        let bytes = fs::read(&path).map_err(snapshot_io)?;
        if bytes.len() < HEADER_LEN {
            return Err(JournalError::SnapshotStoreError(
                "snapshot file is too short".into(),
            ));
        }
        if &bytes[0..4] != SNAPSHOT_MAGIC {
            return Err(JournalError::SnapshotStoreError(
                "snapshot file magic mismatch".into(),
            ));
        }
        let version = u32::from_be_bytes(bytes[4..8].try_into().map_or([0; 4], |b| b));
        if version != SNAPSHOT_FORMAT_VERSION {
            return Err(JournalError::SnapshotStoreError(
                "unsupported snapshot format version".into(),
            ));
        }
        let recorded_chain: Hash = bytes[8..HEADER_LEN].try_into().map_or([0; 32], |b| b);

        let mut chain = initial_chain();
        let mut snapshots = Vec::new();
        let mut offset = HEADER_LEN;
        while offset < bytes.len() {
            if offset + 8 > bytes.len() {
                return Err(JournalError::SnapshotHashMismatch);
            }
            let len = u64::from_le_bytes(bytes[offset..offset + 8].try_into().map_or([0; 8], |b| b))
                as usize;
            offset += 8;
            if offset + len > bytes.len() {
                return Err(JournalError::SnapshotHashMismatch);
            }
            let record = &bytes[offset..offset + len];
            offset += len;
            let mut hasher = blake3::Hasher::new();
            hasher.update(&chain);
            hasher.update(record);
            chain = *hasher.finalize().as_bytes();
            snapshots.push(Snapshot::from_canonical_bytes(record)?);
        }
        if chain != recorded_chain {
            return Err(JournalError::SnapshotHashMismatch);
        }
        Ok(snapshots)
    }
}

/// The chain hash of an empty record stream.
fn initial_chain() -> Hash {
    *blake3::hash(b"").as_bytes()
}

fn write_header(file: &mut impl Write, chain: &Hash) -> Result<(), JournalError> {
    file.write_all(SNAPSHOT_MAGIC).map_err(snapshot_io)?;
    file.write_all(&SNAPSHOT_FORMAT_VERSION.to_be_bytes())
        .map_err(snapshot_io)?;
    file.write_all(chain).map_err(snapshot_io)?;
    Ok(())
}

fn read_header_chain(file: &mut File) -> Result<Hash, JournalError> {
    let mut header = [0u8; HEADER_LEN];
    file.read_exact(&mut header).map_err(snapshot_io)?;
    if &header[0..4] != SNAPSHOT_MAGIC {
        return Err(JournalError::SnapshotStoreError(
            "snapshot file magic mismatch".into(),
        ));
    }
    let version = u32::from_be_bytes(header[4..8].try_into().map_or([0; 4], |b| b));
    if version != SNAPSHOT_FORMAT_VERSION {
        return Err(JournalError::SnapshotStoreError(
            "unsupported snapshot format version".into(),
        ));
    }
    Ok(header[8..HEADER_LEN].try_into().map_or([0; 32], |b| b))
}

fn snapshot_io(err: std::io::Error) -> JournalError {
    JournalError::SnapshotStoreError(err.to_string())
}
