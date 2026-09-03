#![deny(unsafe_code)]

//! Drop-in deterministic runtime facade for ldgr simulation.
//! SUT targets this crate, not ambient time/entropy/threads/sockets.
//! `sim` forwards to the deterministic executor over a process boundary;
//! otherwise to `tokio`/OS. `sim-link` keeps the direct link for tests only.

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
pub use ipc::{
    ENGINE_CONNECT_TIMEOUT_SECS, EngineProcess, IpcError, MAX_IPC_ACTOR, MAX_IPC_ATTEMPTS,
    MAX_WORKLOAD_NAME_BYTES, RunOutcome,
};
pub use ledger_format::StreamId;
pub use net::{Conn, SharedNetwork, shared_network};
pub use rng::{DetRng, MAX_ENTROPY_DETAIL_BYTES, RngError};
pub use runtime::{
    Handle, IpcFault, JournalFault, RunCompletion, RunConfig, RunResult, RuntimeError, TaskMain,
    register_workload, run, run_named,
};
#[cfg(feature = "sim")]
pub use shim::{EngineSession, ShimError};
pub use task::{TaskId, task_id_for};
pub use time::{ClockError, SimClock};

/// Compile-time surface probe (same `Handle` surface under every feature set).
pub fn probe() {
    runtime::assert_surface();
}
