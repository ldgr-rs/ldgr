#![deny(unsafe_code)]
#![allow(missing_docs)]

//! Deterministic simulation runtime, effect boundaries, schedulers, and fault injection models.
// ledger-lint:allow:rdrand (the belt re-export names the hardware-entropy opcode scan)
// ledger-lint:allow:rdseed (the belt re-export names the hardware-entropy opcode scan)

mod adapter;
mod backend_sim;
mod backend_tokio;
#[cfg(feature = "backend-wasm")]
mod backend_wasm;
mod config;
mod config_canonical;
mod dpor;
mod effects;
mod executor;
mod net;
mod origin;
mod runtime;
mod scheduler;
mod seedtree;
mod sentinel;
#[cfg(all(feature = "sentinel", target_os = "linux"))]
mod sentinel_belt;
mod simfs;
mod time;
#[cfg(feature = "backend-wasm")]
mod wasi_fs;

pub use backend_sim::{SimBackend, SimStreamRng};
pub use backend_tokio::{TokioBackend, VirtualOverride};
#[cfg(feature = "backend-wasm")]
pub use backend_wasm::{WASI_RANDOM_STREAM, WasmBackend, WasmError, WasmResult};
pub use config::{Policy, RunConfig, RunConfigBuilder, SimFault, SwarmConfig};
pub use config_canonical::{
    ConfigCanonicalError, FORMAT_VERSION, MAX_DNS_NAME_LEN, canonical_hash, from_canonical_bytes,
    to_canonical_bytes,
};
pub use dpor::{DporConfig, DporReport, DporRun, run_dpor};
pub use effects::{Effects, Fs, FsExt, Net, NetExt, TaskId};
pub use executor::{Boundary, Executor};
pub use net::{DnsTable, LinkConfig, Message, SimNet, backoff, backoff_jittered};
pub use origin::{EffectOrigin, OriginSource};
pub use runtime::{
    Instruction, RunResult, RuntimeError, SCHED_ACTOR, SCHED_STREAM, Simulation, TaskBuilder,
};
pub use scheduler::{NoveltyModel, Scheduler, StepTrace};
pub use seedtree::SeedTree;
pub use sentinel::{BeltStatus, LeakClass, Sentinel, TscTrapGuard, activate_process_belt};
#[cfg(all(feature = "sentinel", target_os = "linux"))]
pub use sentinel_belt::{
    DetectionReport, ProcessBeltStatus, SentinelError, allow_rdtsc, arm_belt, belt_status,
    install_process_belt, install_seccomp_denylist, run_detected, scan_rdrand_rdseed, shim_path,
    trap_rdtsc,
};
#[cfg(feature = "sim-fs-journaling")]
pub use simfs::JournalingMode;
pub use simfs::{CrashOperator, PageState, SimFs};
pub use time::{Clock, TimerFired, VirtualTime};
#[cfg(feature = "backend-wasm")]
pub use wasi_fs::SimFsHost;
