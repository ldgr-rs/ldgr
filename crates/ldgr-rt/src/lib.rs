#![deny(unsafe_code)]

//! Drop-in deterministic runtime facade for ldgr simulation.
//!
//! The SUT writes against this crate instead of touching ambient time, entropy,
//! threads, or sockets directly. With `sim` the facade forwards to the deterministic
//! executor (virtual time, seed-tree RNG, SimNet, SimFs) over a process boundary
//! so the SUT does not link AGPL code. Without `sim` it forwards to `tokio` and
//! the OS. The surface is identical on both paths.
//!
//! In production `sim` is IPC-only: `run()` spawns the `ledger` engine binary
//! (`LEDGER_ENGINE_BIN` or `ledger` on PATH) and serves `rt-server` over a Unix
//! socket. The `sim-link` feature keeps the old direct `ledger-sim` link for
//! workspace tests and examples. It is not for SUT crates published outside the
//! workspace.
//!
//! The crate is a curated facade: implementation modules are private and every
//! SUT-facing item is re-exported at the root, one name per feature set.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod proto;

#[cfg(any(feature = "sim", feature = "sim-link"))]
mod ipc;
mod net;
mod rng;
mod runtime;
#[cfg(feature = "sim")]
mod shim;
mod task;
mod time;

#[cfg(any(feature = "sim", feature = "sim-link"))]
pub use ipc::{ENGINE_CONNECT_TIMEOUT_SECS, EngineProcess, IpcError, RunOutcome};
pub use ledger_format::StreamId;
pub use net::{Conn, SharedNetwork, shared_network};
pub use rng::DetRng;
pub use runtime::{
    Handle, IpcFault, JournalFault, RunCompletion, RunConfig, RunResult, RuntimeError, TaskMain,
    register_workload, run, run_named,
};
#[cfg(feature = "sim")]
pub use shim::{EngineSession, ShimError};
pub use task::{TaskId, task_id_for};
pub use time::{SimClock, now};

/// Compile-time surface probe: both `sim` and non-`sim` builds expose the same
/// public methods on the handle. This function type-checks the probe trait.
pub fn probe() {
    runtime::assert_surface();
}
