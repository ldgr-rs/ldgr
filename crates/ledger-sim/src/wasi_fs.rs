//! SimFs-backed WASI filesystem virtualization: `wasi_snapshot_preview1` shadow onto `SimFs`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ledger_format::ActorId;
use ledger_journal::{Journal, JournalError};

use crate::backend_sim::record_first_journal_error;
use crate::simfs::SimFs;

/// SimFs-backed host for WASI filesystem operations.
///
/// Shares the same `SimFs` and journal as `SimBackend`, so WASI file effects
/// land in the same causal DAG the native boundary writes. Each operation
/// journals through `SimFs::write`/`read`/`fsync` which append `FsWrite`,
/// `FsRead`, `FsFsync` entries via the shared journal.
#[derive(Clone)]
pub struct SimFsHost {
    fs: Arc<Mutex<SimFs>>,
    journal: Arc<Mutex<Journal>>,
    journal_error: Arc<Mutex<Option<JournalError>>>,
    actor: ActorId,
}

impl SimFsHost {
    /// Create a host that journals through the given shared state.
    pub fn new(
        fs: Arc<Mutex<SimFs>>,
        journal: Arc<Mutex<Journal>>,
        journal_error: Arc<Mutex<Option<JournalError>>>,
        actor: ActorId,
    ) -> Self {
        Self {
            fs,
            journal,
            journal_error,
            actor,
        }
    }

    /// Write `value` at `path`, journaling `FsWrite`.
    pub fn write(&self, path: &str, value: u64) -> Result<ledger_format::Hash, JournalError> {
        let mut journal = self.journal.lock().unwrap_or_else(|e| e.into_inner());
        let mut fs = self.fs.lock().unwrap_or_else(|e| e.into_inner());
        match fs.write(&mut journal, self.actor, path, value) {
            Ok(id) => Ok(id),
            Err(error) => {
                record_first_journal_error(&self.journal_error, &error);
                Err(error)
            }
        }
    }

    /// Read at `path`, journaling `FsRead` (with `FsWrite` parent when present).
    pub fn read(&self, path: &str) -> Result<Option<u64>, JournalError> {
        let mut journal = self.journal.lock().unwrap_or_else(|e| e.into_inner());
        let fs = self.fs.lock().unwrap_or_else(|e| e.into_inner());
        match fs.read(&mut journal, self.actor, path) {
            Ok(value) => Ok(value),
            Err(error) => {
                record_first_journal_error(&self.journal_error, &error);
                Err(error)
            }
        }
    }

    /// Flush dirty entries, journaling `FsFsync`.
    pub fn fsync(&self) -> Result<ledger_format::Hash, JournalError> {
        let mut journal = self.journal.lock().unwrap_or_else(|e| e.into_inner());
        let mut fs = self.fs.lock().unwrap_or_else(|e| e.into_inner());
        match fs.fsync(&mut journal, self.actor) {
            Ok(id) => Ok(id),
            Err(error) => {
                record_first_journal_error(&self.journal_error, &error);
                Err(error)
            }
        }
    }

    /// Crash storage, journaling `Fault(CrashState(0))`.
    pub fn crash(&self) {
        // Journal the crash fault (mirrors SimBackend::fs().crash()). A failed
        // append still crashes storage; the error is recorded in the shared
        // slot so it surfaces like every other journaling failure here.
        {
            let mut journal = self.journal.lock().unwrap_or_else(|e| e.into_inner());
            if let Err(error) = journal.append(
                ledger_format::EntryKind::Fault,
                self.actor,
                [],
                ledger_format::EntryPayload::Fault(ledger_format::FaultPayload::CrashActor {
                    actor: self.actor,
                    crash_operation: ledger_format::CrashOperation::DropAllUnsynced,
                }),
            ) {
                record_first_journal_error(&self.journal_error, &error);
            }
        }
        self.fs.lock().unwrap_or_else(|e| e.into_inner()).crash();
    }
}

/// Deterministic fd for a path: `blake3(path)[0..4]` masked to 31 bits.
///
/// Guaranteed distinct from stdin/stdout/stderr (0,1,2) by clamping the range
/// to `>= 3`. Deterministic across runs and independent of Hasher randomization.
pub fn deterministic_fd(path: &str) -> u32 {
    let hash = blake3::hash(path.as_bytes());
    let bytes = hash.as_bytes();
    let raw = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) & 0x7fffffff;
    if raw < 3 { raw + 3 } else { raw }
}

/// Parse guest bytes into the `u64` stored in `SimFs`.
///
/// Tries decimal UTF-8 first (`"42"`), then first 8 bytes LE, then hashes the
/// byte slice via `blake3` into a `u64`. Deterministic and total.
pub fn bytes_to_u64(bytes: &[u8]) -> u64 {
    // Best-effort UTF-8/decimal interpretation; non-decimal bytes fall
    // through to the LE and hash forms below.
    if let Ok(text) = core::str::from_utf8(bytes) {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            // A non-numeric token falls through to the byte forms below.
            if let Ok(value) = trimmed.parse::<u64>() {
                return value;
            }
            // Also try signed parse for guest that writes negative sentinel.
            // A non-numeric token falls through to the byte forms below.
            if let Ok(value) = trimmed.parse::<i64>() {
                return value as u64;
            }
        }
    }
    if bytes.len() >= 8 {
        let mut array = [0u8; 8];
        array.copy_from_slice(&bytes[..8]);
        return u64::from_le_bytes(array);
    }
    if !bytes.is_empty() {
        // Hash remaining bytes to a u64 deterministically.
        let hash = blake3::hash(bytes);
        let h = hash.as_bytes();
        return u64::from_le_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]);
    }
    0
}

/// In-memory fd table mapping virtual fds to `SimFs` path keys.
#[derive(Debug, Default)]
pub struct WasiFdTable {
    // ledger-lint:allow:HashMap (fd-to-path lookups only; never iterated)
    map: HashMap<u32, String>,
}

impl WasiFdTable {
    /// Create an empty table.
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Open `path` and return its deterministic fd, inserting the mapping.
    pub fn open(&mut self, path: &str) -> u32 {
        let fd = deterministic_fd(path);
        self.map.insert(fd, path.to_owned());
        fd
    }

    /// Lookup path for `fd`.
    pub fn get(&self, fd: u32) -> Option<&str> {
        self.map.get(&fd).map(|s| s.as_str())
    }

    /// Remove `fd` from the table.
    pub fn close(&mut self, fd: u32) -> bool {
        self.map.remove(&fd).is_some()
    }

    /// Check whether `fd` is a virtual file descriptor.
    pub fn contains(&self, fd: u32) -> bool {
        self.map.contains_key(&fd)
    }
}
