//! Effect boundary between the system under test and deterministic execution.

use crate::net::Message;
use crate::time::Clock;
use ledger_format::{Hash, StreamId};
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

    /// Take the first deliverable message for `task` available at `now`.
    fn recv(&self, task: usize, now: u64) -> Option<Message>;

    fn has_ready_message(&self, task: usize, now: u64) -> bool;
}

/// Storage boundary exposed to systems under test.
///
/// Implementors serve the layered simulated storage surface: page-cache write,
/// fsync flush, and provenance-tracked read. Journaling is handled by the
/// backend, so the caller never sees the journal.
pub trait Fs {
    /// Write a value to the page cache and return its journal entry id.
    fn write(&self, path: &str, value: u64) -> Result<Hash, ledger_journal::JournalError>;

    /// Flush all dirty page-cache entries to durable synced storage.
    fn fsync(&self) -> Result<Hash, ledger_journal::JournalError>;

    /// Read a value from page cache, recording provenance of the observed write.
    fn read(&self, path: &str) -> Result<Option<u64>, ledger_journal::JournalError>;

    /// Crash storage into the deterministic post-crash state.
    fn crash(&self);
}

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
    #[allow(async_fn_in_trait)]
    async fn sleep(&self, d: core::time::Duration);

    fn net(&self) -> &dyn Net;

    fn fs(&self) -> &dyn Fs;
}
