//! Determinism leak sentinel and runtime ground-truth verification.
// ledger-lint:allow:rdrand (the belt scan report names the hardware-entropy intrinsics)
// ledger-lint:allow:rdseed (the belt scan report names the hardware-entropy intrinsics)

use std::collections::HashSet;

/// Leak classes checked by the sentinel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeakClass {
    /// Non-deterministic wall-clock read.
    WallClock,
    /// Unseeded random number generation.
    AmbientRng,
    /// Direct timestamp-counter or hardware-entropy read.
    TimestampCounter,
    /// Direct uncontrolled system threading.
    RawThread,
    /// Ambient file system access bypassing SimFs.
    UnsimulatedIo,
    /// Non-deterministic environment variable access.
    EnvVarEntropy,
}

/// Activation state of the process belt for one sim run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeltStatus {
    /// Belt unavailable: non-Linux platform or the `sentinel` feature is off.
    Unavailable,
    /// Belt present but not armed for this process; the run path changed nothing.
    NotArmed,
    /// Belt active: the seccomp denylist and the RDTSC trap are installed.
    Active {
        /// RDRAND/RDSEED opcodes were found in an executable mapping.
        rdrand_rdseed_present: bool,
    },
    /// Belt activation failed; the message carries the cause.
    Failed(String),
}

/// Belt hook invoked at the sim run entry on Linux builds with `sentinel`.
#[cfg(all(feature = "sentinel", target_os = "linux"))]
pub use crate::sentinel_belt::activate_process_belt;

/// Belt hook no-op for platforms without the belt.
///
/// The no-op keeps the call site identical across builds so the run path can
/// invoke the hook unconditionally.
#[cfg(not(all(feature = "sentinel", target_os = "linux")))]
pub fn activate_process_belt() -> BeltStatus {
    BeltStatus::Unavailable
}

/// Runtime sentinel that tracks and flags unjournaled ambient effects.
#[derive(Debug, Default)]
pub struct Sentinel {
    detected_leaks: HashSet<LeakClass>,
}

impl Sentinel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Report an unjournaled ambient operation.
    pub fn record_leak(&mut self, class: LeakClass) {
        self.detected_leaks.insert(class);
    }

    /// Return true if any determinism leaks were detected.
    pub fn has_leaks(&self) -> bool {
        !self.detected_leaks.is_empty()
    }

    pub fn leaks(&self) -> &HashSet<LeakClass> {
        &self.detected_leaks
    }
}
