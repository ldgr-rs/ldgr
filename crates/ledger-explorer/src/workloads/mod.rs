//! Reference distributed workloads for deterministic simulation and fault injection.

pub mod mini_kv;
pub mod storage_crash;
pub mod two_phase_commit;

pub use mini_kv::MiniKvWorkload;
pub use storage_crash::StorageCrashWorkload;
pub use two_phase_commit::TwoPhaseCommitWorkload;
