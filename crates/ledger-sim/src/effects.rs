//! Effect boundary between the system under test and deterministic execution.

use crate::net::Message;
use crate::origin::OriginSource;
use crate::time::Clock;
use core::panic::Location;
use ledger_format::{EntryHash, StreamId};
use rand_core::Rng;

/// Identifier for a task spawned through the executor boundary.
pub type TaskId = u64;

/// Network boundary exposed to systems under test.
///
/// Implementors serve the deterministic simulated network surface: message
/// send, timed receive, and readiness checks. State is interior-mutable so the
/// boundary can be reached through a shared reference.
pub trait Net {
    /// Queue a message for delivery. Returns false if the link is partitioned.
    fn send(&self, message: Message) -> bool;

    /// Queue a message for delivery, recording where the send came from.
    ///
    /// The origin lands in the session side channel keyed by the Send entry
    /// hash; journal bytes are unchanged. The default drops the origin so
    /// existing implementations stay correct without code changes.
    fn send_loc(&self, message: Message, at: OriginSource) -> bool {
        let _ = at;
        self.send(message)
    }

    /// Take the first deliverable message for `task` available at `now`.
    fn recv(&self, task: usize, now: u64) -> Option<Message>;

    fn has_ready_message(&self, task: usize, now: u64) -> bool;
}

/// Tracked aliases for the network boundary: same behavior, plus origin
/// capture into the session side channel when the backend supports it.
pub trait NetExt: Net {
    #[track_caller]
    fn send_tracked(&self, message: Message) -> bool {
        self.send_loc(message, Location::caller().into())
    }
}

impl<T: Net + ?Sized> NetExt for T {}

/// Source-preserving storage error.
#[derive(Debug)]
#[repr(transparent)]
pub struct FsError(pub ledger_journal::JournalError);

impl core::fmt::Display for FsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl core::error::Error for FsError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl From<ledger_journal::JournalError> for FsError {
    fn from(error: ledger_journal::JournalError) -> Self {
        Self(error)
    }
}

impl core::ops::Deref for FsError {
    type Target = ledger_journal::JournalError;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FsError {
    /// Extract the underlying journal error.
    pub fn into_journal(self) -> ledger_journal::JournalError {
        self.0
    }
}

/// Storage boundary exposed to systems under test.
///
/// Implementors serve the layered simulated storage surface: page-cache write,
/// fsync flush, and provenance-tracked read. Journaling is handled by the
/// backend, so the caller never sees the journal.
pub trait Fs {
    /// Write a value to the page cache and return its journal entry id.
    fn write(&self, path: &str, value: u64) -> Result<EntryHash, FsError>;

    /// Write with origin capture; see [`Net::send_loc`]. Default delegates.
    fn write_loc(&self, path: &str, value: u64, at: OriginSource) -> Result<EntryHash, FsError> {
        let _ = at;
        self.write(path, value)
    }

    /// Flush all dirty page-cache entries to durable synced storage.
    fn fsync(&self) -> Result<EntryHash, FsError>;

    /// Flush with origin capture; see [`Net::send_loc`]. Default delegates.
    fn fsync_loc(&self, at: OriginSource) -> Result<EntryHash, FsError> {
        let _ = at;
        self.fsync()
    }

    /// Read a value from page cache, recording provenance of the observed write.
    fn read(&self, path: &str) -> Result<Option<u64>, FsError>;

    /// Crash storage into the deterministic post-crash state.
    fn crash(&self);

    /// Crash with origin capture; see [`Net::send_loc`]. Default delegates.
    fn crash_loc(&self, at: OriginSource) {
        let _ = at;
        self.crash()
    }
}

/// Tracked aliases for the storage boundary. Read is deliberately absent:
/// its provenance entries are appended inside the fs layer, so there is no
/// entry id observable at this boundary to key an origin against.
pub trait FsExt: Fs {
    #[track_caller]
    fn write_tracked(&self, path: &str, value: u64) -> Result<EntryHash, FsError> {
        self.write_loc(path, value, Location::caller().into())
    }

    #[track_caller]
    fn fsync_tracked(&self) -> Result<EntryHash, FsError> {
        self.fsync_loc(Location::caller().into())
    }

    #[track_caller]
    fn crash_tracked(&self) {
        self.crash_loc(Location::caller().into())
    }
}

impl<T: Fs + ?Sized> FsExt for T {}

/// Effect boundary implemented by simulation and production backends.
///
/// Simulation backends drive the journal; production backends forward to the
/// ambient host. The trait is not object-safe: systems under test take it
/// generically or concretely.
///
/// The returned RNG handles are infallible `rand_core::Rng` values (the
/// rand_core 0.10 replacement for the deprecated `RngCore`). Simulation
/// backends journal every draw; production backends serve OS entropy.
pub trait Effects {
    /// Return a handle to the current virtual clock.
    fn clock(&self) -> Clock;

    /// Return an RNG handle for a labeled stream.
    ///
    /// Simulation backends serve a deterministic, seed-tree-derived stream and
    /// journal each draw as an `RngDraw { stream }` entry so the consumption
    /// order is replayable. Production backends serve OS entropy.
    fn rng(&mut self, stream: StreamId) -> &mut impl Rng;

    /// Sleep for a duration measured in virtual ticks.
    ///
    /// One tick is one microsecond; simulation backends convert the duration
    /// to ticks before registering the timer. The returned future carries no
    /// `Send` bound because the sim is single-threaded.
    #[allow(async_fn_in_trait)] // this trait predates edition-2024 async fn support
    async fn sleep(&self, d: core::time::Duration);

    fn net(&self) -> &dyn Net;

    fn fs(&self) -> &dyn Fs;
}

#[cfg(test)]
mod fs_error_tests {
    use super::FsError;
    use core::error::Error;
    use ledger_journal::JournalError;

    #[test]
    fn fs_error_preserves_source_and_display() {
        let journal_err = JournalError::InvalidPayload("bad payload".to_string());
        let fs_err = FsError(journal_err.clone());
        // Display delegates to inner
        assert_eq!(fs_err.to_string(), journal_err.to_string());
        // Source preserves inner
        assert!(fs_err.source().is_some());
        assert_eq!(
            fs_err.source().unwrap().to_string(),
            journal_err.to_string()
        );
        // From conversion
        let from: FsError = journal_err.clone().into();
        assert_eq!(from.0, journal_err);
        // Deref delegates
        assert_eq!(*from, journal_err);
        // into_journal extracts
        assert_eq!(from.into_journal(), journal_err);
    }

    #[test]
    fn fs_error_into_journal_round_trips() {
        let err = JournalError::MissingParent(ledger_format::EntryHash([1u8; 32]));
        let fs_err = FsError(err.clone());
        assert_eq!(fs_err.into_journal(), err);
    }
}
