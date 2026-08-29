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
///
/// v2 open-file model: handles are monotonic from 3 and are never reused
/// during one actor run; each description carries its cursor, append mode,
/// granted rights, open flags, and closed state.
#[derive(Debug, Default)]
pub struct WasiFdTable {
    // ledger-lint:allow:HashMap (fd-to-description lookups only; never
    // iterated for behavior)
    map: HashMap<u32, OpenFileDescription>,
    next_fd: u32,
}

/// Granted rights on an open file description.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FdRights {
    /// Reads are permitted.
    pub read: bool,
    /// Writes are permitted.
    pub write: bool,
    /// The cursor may be repositioned.
    pub seek: bool,
}

/// Open flags for one open file description.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FdFlags {
    /// Writes append at the resolved end of file.
    pub append: bool,
}

/// One open file description: canonical path, cursor, append mode, granted
/// rights, open flags, and closed state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFileDescription {
    /// Path key into the shared `SimFs`.
    pub path: String,
    /// Monotonic handle assigned by the owning table.
    pub fd: u32,
    /// Current cursor; reads and writes advance it by the transferred length.
    pub cursor: u64,
    /// Append mode; resolves EOF once per host call.
    pub append: bool,
    /// Granted rights.
    pub rights: FdRights,
    /// Open flags.
    pub flags: FdFlags,
    /// Closed state; closed handles fail with typed errors.
    pub closed: bool,
}

/// Typed open-file-table failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FdError {
    /// The per-actor handle limit is exhausted.
    #[error("fd table full")]
    FdTableFull,
    /// The handle is not open.
    #[error("fd not open")]
    NotOpen,
    /// The handle was closed.
    #[error("fd closed")]
    Closed,
    /// The operation is not granted by the description rights.
    #[error("fd operation not granted")]
    NotGranted,
}

/// Per-actor open-file limit from the format contract.
pub const MAX_OPEN_FDS: u32 = 4096;

impl WasiFdTable {
    /// Create an empty table.
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            next_fd: 3,
        }
    }

    /// Open `path` and return a monotonic handle from 3.
    ///
    /// Handles are not reused during one actor run; table exhaustion returns
    /// [`FdError::FdTableFull`].
    pub fn open(&mut self, path: &str) -> Result<u32, FdError> {
        self.open_with_flags(path, FdRights::default(), FdFlags::default())
    }

    /// Open `path` with explicit rights and flags.
    pub fn open_with_flags(
        &mut self,
        path: &str,
        rights: FdRights,
        flags: FdFlags,
    ) -> Result<u32, FdError> {
        if self.map.len() as u32 >= MAX_OPEN_FDS {
            return Err(FdError::FdTableFull);
        }
        let fd = self.next_fd;
        self.next_fd = self.next_fd.saturating_add(1);
        self.map.insert(
            fd,
            OpenFileDescription {
                path: path.to_owned(),
                fd,
                cursor: 0,
                append: flags.append,
                rights,
                flags,
                closed: false,
            },
        );
        Ok(fd)
    }

    /// Lookup the description for `fd`.
    pub fn get(&self, fd: u32) -> Option<&OpenFileDescription> {
        self.map.get(&fd)
    }

    /// Resolve `fd` to its path key.
    pub fn path_for(&self, fd: u32) -> Option<&str> {
        self.map
            .get(&fd)
            .map(|description| description.path.as_str())
    }

    /// Remove `fd` from the table.
    pub fn close(&mut self, fd: u32) -> bool {
        match self.map.get_mut(&fd) {
            Some(description) => {
                description.closed = true;
                true
            }
            None => false,
        }
    }

    /// Check whether `fd` is a virtual file descriptor.
    pub fn contains(&self, fd: u32) -> bool {
        self.map.contains_key(&fd)
    }

    /// Advance the cursor by `delta` after a successful transfer.
    pub fn advance_cursor(&mut self, fd: u32, delta: u64) -> Result<(), FdError> {
        let description = self.map.get_mut(&fd).ok_or(FdError::NotOpen)?;
        if description.closed {
            return Err(FdError::Closed);
        }
        description.cursor = description.cursor.saturating_add(delta);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_are_monotonic_from_three_and_not_reused() {
        let mut table = WasiFdTable::new();
        let a = table.open("a").unwrap();
        let b = table.open("b").unwrap();
        assert_eq!(a, 3);
        assert_eq!(b, 4);
        // Closing does not free the handle for reuse.
        assert!(table.close(a));
        let c = table.open("c").unwrap();
        assert_eq!(c, 5);
    }

    #[test]
    fn table_full_returns_fd_error() {
        let mut table = WasiFdTable::new();
        for index in 0..MAX_OPEN_FDS {
            table
                .open(&format!("f{index}"))
                .expect("table accepts until the limit");
        }
        assert_eq!(table.open("overflow"), Err(FdError::FdTableFull));
    }

    #[test]
    fn cursor_advances_by_transferred_length() {
        let mut table = WasiFdTable::new();
        let fd = table.open("k").unwrap();
        table.advance_cursor(fd, 4).unwrap();
        let description = table.get(fd).expect("open description");
        assert_eq!(description.cursor, 4);
        table.close(fd);
        assert_eq!(table.advance_cursor(fd, 0), Err(FdError::Closed));
    }

    #[test]
    fn closed_and_unknown_handles_fail_with_typed_errors() {
        let mut table = WasiFdTable::new();
        let fd = table.open("k").unwrap();
        table.close(fd);
        assert!(table.contains(fd), "closed handles stay addressable");
        assert!(table.get(fd).is_some_and(|description| description.closed));
        assert!(!table.contains(99));
        assert_eq!(table.advance_cursor(99, 0), Err(FdError::NotOpen));
    }

    #[test]
    fn open_with_flags_records_append_mode() {
        let mut table = WasiFdTable::new();
        let fd = table
            .open_with_flags(
                "k",
                FdRights {
                    read: true,
                    write: true,
                    seek: true,
                },
                FdFlags { append: true },
            )
            .unwrap();
        let description = table.get(fd).unwrap();
        assert!(description.append);
        assert!(description.rights.write);
    }
}
