#![deny(unsafe_code)]
#![allow(missing_docs)]

//! Deterministic simulation runtime, effect boundaries, schedulers, and fault injection models.
// ledger-lint:allow:rdrand (the belt re-export names the hardware-entropy opcode scan)
// ledger-lint:allow:rdseed (the belt re-export names the hardware-entropy opcode scan)

pub mod adapter;
pub mod backend_sim;
pub mod backend_tokio;
#[cfg(feature = "backend-wasm")]
pub mod backend_wasm;
pub mod config;
pub mod dpor;
pub mod effects;
pub mod executor;
pub mod net;
pub mod runtime;
pub mod scheduler;
pub mod seedtree;
pub mod sentinel;
#[cfg(all(feature = "sentinel", target_os = "linux"))]
pub mod sentinel_belt;
pub mod simfs;
pub mod time;

pub use backend_sim::SimBackend;
pub use backend_tokio::TokioBackend;
#[cfg(feature = "backend-wasm")]
pub use backend_wasm::{WasmBackend, WasmError};
pub use config::{FaultInjection, Policy, RunConfig, SwarmConfig};
pub use dpor::{DporConfig, DporReport, DporRun, run_dpor};
pub use effects::{Effects, Fs, Net, TaskId};
pub use executor::{Boundary, Executor};
pub use net::{DnsTable, Message, SimNet, backoff, backoff_jittered};
pub use runtime::{Instruction, RunResult, RuntimeError, Simulation, Task, TaskBuilder};
pub use scheduler::{NoveltyModel, Scheduler, StepTrace};
pub use seedtree::SeedTree;
pub use sentinel::{BeltStatus, LeakClass, Sentinel, activate_process_belt};
#[cfg(all(feature = "sentinel", target_os = "linux"))]
pub use sentinel_belt::{
    DetectionReport, ProcessBeltStatus, SentinelError, arm_belt, belt_status, install_process_belt,
    install_seccomp_denylist, run_detected, scan_rdrand_rdseed, shim_path, trap_rdtsc,
};
#[cfg(feature = "sim-fs-journaling")]
pub use simfs::JournalingMode;
pub use simfs::{CrashOperator, PageState, SimFs};
pub use time::{TimerFired, VirtualTime};
