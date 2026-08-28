//! Determinism leak sentinel and runtime ground-truth verification.
// ledger-lint:allow:rdrand (the belt scan report names the hardware-entropy intrinsics)
// ledger-lint:allow:rdseed (the belt scan report names the hardware-entropy intrinsics)
// ledger-lint:allow:env::var (the belt install gate reads LEDGER_SENTINEL_BELT; host-side configuration, not simulation state)

use std::collections::HashSet;
use std::ffi::OsStr;

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
///
/// The semantic variant is the primary value; [`Display`] is only the
/// presentation view. No production code may branch on the rendered text.
#[derive(Debug, Clone)]
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
    /// Belt activation failed; the typed error carries the cause.
    Failed(SentinelError),
}

impl PartialEq for BeltStatus {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Unavailable, Self::Unavailable) | (Self::NotArmed, Self::NotArmed) => true,
            (
                Self::Active {
                    rdrand_rdseed_present: left,
                },
                Self::Active {
                    rdrand_rdseed_present: right,
                },
            ) => left == right,
            (Self::Failed(left), Self::Failed(right)) => left == right,
            _ => false,
        }
    }
}

impl Eq for BeltStatus {}

impl core::fmt::Display for BeltStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unavailable => write!(f, "unavailable"),
            Self::NotArmed => write!(f, "not armed"),
            Self::Active {
                rdrand_rdseed_present,
            } => write!(f, "active (rdrand/rdseed present: {rdrand_rdseed_present})"),
            Self::Failed(error) => write!(f, "activation failed: {error}"),
        }
    }
}

/// Whether the process belt must be active for a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProtectionMode {
    /// Belt must be active; failure is a typed run error.
    Required,
    /// Belt is best-effort; failures warn and continue.
    #[default]
    BestEffort,
}

/// Belt mode derived from the host environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum BeltMode {
    /// Belt is disabled.
    #[default]
    Disabled,
    /// Belt is best-effort.
    BestEffort,
    /// Belt is required.
    Required,
}

/// Effective protection for a run, derived from host and env.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EffectiveProtection {
    /// Belt is disabled for this run.
    #[default]
    Disabled,
    /// Belt is best-effort for this run.
    BestEffort,
    /// Belt is required for this run.
    Required,
}

impl EffectiveProtection {
    /// True when the belt is required.
    pub fn is_required(self) -> bool {
        matches!(self, Self::Required)
    }

    /// True when the belt is enabled in any mode.
    pub fn is_enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// True when an active belt is needed.
    pub fn needs_active_belt(self) -> bool {
        self.is_required()
    }
}

impl From<ProtectionMode> for EffectiveProtection {
    fn from(mode: ProtectionMode) -> Self {
        match mode {
            ProtectionMode::Required => Self::Required,
            ProtectionMode::BestEffort => Self::BestEffort,
        }
    }
}

impl From<BeltMode> for EffectiveProtection {
    fn from(mode: BeltMode) -> Self {
        match mode {
            BeltMode::Disabled => Self::Disabled,
            BeltMode::BestEffort => Self::BestEffort,
            BeltMode::Required => Self::Required,
        }
    }
}

impl From<Option<ProtectionMode>> for EffectiveProtection {
    fn from(value: Option<ProtectionMode>) -> Self {
        match value {
            Some(ProtectionMode::Required) => Self::Required,
            Some(ProtectionMode::BestEffort) => Self::BestEffort,
            None => Self::Disabled,
        }
    }
}

impl From<EffectiveProtection> for Option<ProtectionMode> {
    fn from(value: EffectiveProtection) -> Self {
        match value {
            EffectiveProtection::Disabled => None,
            EffectiveProtection::BestEffort => Some(ProtectionMode::BestEffort),
            EffectiveProtection::Required => Some(ProtectionMode::Required),
        }
    }
}

/// Pure env parsing for `LEDGER_SENTINEL_BELT`.
///
/// `None` means the variable is unset. The value is compared
/// case-insensitively after lossy UTF-8 conversion: `required` maps to
/// `Required`, `1`/`true`/`on`/`yes` map to `BestEffort`, everything else
/// maps to `Disabled`. The parse never reads ambient state beyond its
/// argument, so it is deterministic and testable.
pub(crate) fn belt_env_mode(value: Option<&OsStr>) -> BeltMode {
    match value {
        None => BeltMode::Disabled,
        Some(raw) => {
            let lower = raw.to_string_lossy().to_ascii_lowercase();
            match lower.as_str() {
                "required" => BeltMode::Required,
                "1" | "true" | "on" | "yes" => BeltMode::BestEffort,
                _ => BeltMode::Disabled,
            }
        }
    }
}

/// Host-side gate: read the belt mode from the process environment. The belt
/// is an installation gate, not simulation state, so the env read is
/// host-side by design and covered by this file's lint markers.
pub(crate) fn belt_env_mode_from_env() -> BeltMode {
    belt_env_mode(std::env::var_os("LEDGER_SENTINEL_BELT").as_deref())
}

/// Belt hook invoked at the sim run entry on Linux builds with `sentinel`.
#[cfg(all(feature = "sentinel", target_os = "linux"))]
pub use crate::sentinel_belt::{
    activate_process_belt, activate_process_belt_for_effective, TscTrapGuard,
};

/// Sentinel belt errors.
///
/// Defined here, outside the platform-gated belt module, so every platform
/// can name the typed failure the guard and the run entry report.
#[derive(Debug, Clone)]
pub enum SentinelError {
    /// The seccomp architecture is not covered by this crate.
    UnsupportedArch,
    /// The built interposition shim is missing on disk.
    ShimMissing(std::path::PathBuf),
    /// A prctl operation failed with the given errno.
    Prctl(&'static str, i32),
    /// An I/O error while spawning the probe or parsing its log.
    ///
    /// `std::io::Error` is not `Clone`; the `Arc` keeps the status record
    /// (`OnceLock::get().cloned()`) cloneable without flattening the error
    /// into a string.
    Io(std::sync::Arc<std::io::Error>),
    /// The probe exited without the expected zero status.
    NonZeroExit(std::process::ExitStatus),
}

impl core::fmt::Display for SentinelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedArch => write!(f, "sentinel belt does not support this architecture"),
            Self::ShimMissing(path) => write!(f, "sentinel shim not found: {}", path.display()),
            Self::Prctl(operation, errno) => write!(f, "{operation} failed with errno {errno}"),
            Self::Io(error) => write!(f, "sentinel belt I/O error: {error}"),
            Self::NonZeroExit(status) => write!(f, "probe did not exit cleanly: {status:?}"),
        }
    }
}

impl std::error::Error for SentinelError {}

impl PartialEq for SentinelError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::UnsupportedArch, Self::UnsupportedArch) => true,
            (Self::ShimMissing(left), Self::ShimMissing(right)) => left == right,
            (Self::Prctl(left_op, left_errno), Self::Prctl(right_op, right_errno)) => {
                left_op == right_op && left_errno == right_errno
            }
            // std::io::Error has no structural equality; kind plus the raw
            // OS error code identifies the failure for equality purposes.
            (Self::Io(left), Self::Io(right)) => {
                left.kind() == right.kind() && left.raw_os_error() == right.raw_os_error()
            }
            (Self::NonZeroExit(left), Self::NonZeroExit(right)) => left == right,
            _ => false,
        }
    }
}

impl Eq for SentinelError {}

/// Belt hook no-op for platforms without the belt.
///
/// The no-op keeps the call site identical across builds so the run path can
/// invoke the hook unconditionally.
#[cfg(not(all(feature = "sentinel", target_os = "linux")))]
pub fn activate_process_belt() -> BeltStatus {
    BeltStatus::Unavailable
}

#[cfg(not(all(feature = "sentinel", target_os = "linux")))]
pub fn activate_process_belt_for_effective(_effective: EffectiveProtection) -> BeltStatus {
    BeltStatus::Unavailable
}

/// Dummy TSC trap guard for platforms without the belt.
#[cfg(not(all(feature = "sentinel", target_os = "linux")))]
#[derive(Debug, Default)]
pub struct TscTrapGuard;

#[cfg(not(all(feature = "sentinel", target_os = "linux")))]
impl TscTrapGuard {
    /// No-op constructor for platforms without the belt.
    pub fn arm_if_armed() -> Self {
        Self
    }

    /// No-op for effective mode on platforms without the belt.
    pub fn arm_for_effective(_effective: EffectiveProtection) -> Self {
        Self
    }

    /// No trap was ever requested, so there is no activation failure.
    pub fn activation_error(&self) -> Option<&SentinelError> {
        None
    }
}

/// Runtime sentinel that tracks and flags unjournaled ambient effects.
#[derive(Debug, Default)]
pub struct Sentinel {
    // ledger-lint:allow:HashSet (leak classes are membership-checked and
    // counted; the set is never iterated for output order)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Recover the semantic variant and payload from a status; production
    /// code consumes BeltStatus exactly this way, by variant match, never by
    /// parsing the rendered text.
    fn typed_payload(status: &BeltStatus) -> Option<&SentinelError> {
        match status {
            BeltStatus::Failed(error) => Some(error),
            BeltStatus::Unavailable | BeltStatus::NotArmed | BeltStatus::Active { .. } => None,
        }
    }

    /// Every variant round-trips through clone and equality; the semantic
    /// variant, not rendered text, is the comparison key.
    #[test]
    fn belt_status_variants_round_trip() {
        let cases = [
            BeltStatus::Unavailable,
            BeltStatus::NotArmed,
            BeltStatus::Active {
                rdrand_rdseed_present: false,
            },
            BeltStatus::Active {
                rdrand_rdseed_present: true,
            },
            BeltStatus::Failed(SentinelError::Prctl("PR_SET_TSC", 22)),
            BeltStatus::Failed(SentinelError::ShimMissing("/missing/shim".into())),
            BeltStatus::Failed(SentinelError::NonZeroExit(
                std::process::ExitStatus::default(),
            )),
        ];
        for (index, status) in cases.iter().enumerate() {
            // Clone preserves the variant and payload.
            assert_eq!(status, &cases[index].clone());
            // Every other distinct variant compares unequal; only the
            // identical variant compares equal.
            for (other_index, other) in cases.iter().enumerate() {
                assert_eq!(
                    status == other,
                    index == other_index,
                    "variant {index:?} must equal only itself"
                );
            }
            // The typed payload is reachable only through the Failed variant.
            assert_eq!(
                typed_payload(status).is_some(),
                matches!(status, BeltStatus::Failed(_))
            );
        }
    }

    /// Display is the presentation view: it derives from the typed variant
    /// and never replaces it as the dispatch key.
    #[test]
    fn belt_status_display_is_presentation_only() {
        let active = BeltStatus::Active {
            rdrand_rdseed_present: true,
        };
        assert_eq!(active.to_string(), "active (rdrand/rdseed present: true)");
        let failed: BeltStatus = BeltStatus::Failed(SentinelError::Prctl("PR_SET_TSC", 22));
        // The rendered text carries the typed error's Display, so a log line
        // stays informative while the variant keeps the typed payload.
        assert_eq!(
            failed.to_string(),
            format!(
                "activation failed: {}",
                SentinelError::Prctl("PR_SET_TSC", 22)
            )
        );
        let unavailable = BeltStatus::Unavailable;
        assert_eq!(unavailable.to_string(), "unavailable");
        let not_armed = BeltStatus::NotArmed;
        assert_eq!(not_armed.to_string(), "not armed");
    }

    /// The Failed round-trip recovers the exact typed error, unchanged by
    /// any string rendering in between.
    #[test]
    fn failed_carries_typed_error_not_a_flattened_string() {
        let status = BeltStatus::Failed(SentinelError::Io(std::sync::Arc::new(
            std::io::Error::from_raw_os_error(13),
        )));
        let recovered: &SentinelError = typed_payload(&status).expect("Failed must carry an error");
        assert!(matches!(recovered, SentinelError::Io(_)));
        // Equality never depends on rendered text: two statuses built from
        // equal typed errors compare equal, and the string view is derived.
        let again = BeltStatus::Failed(SentinelError::Io(std::sync::Arc::new(
            std::io::Error::from_raw_os_error(13),
        )));
        assert_eq!(status, again);
        assert_eq!(status.to_string(), again.to_string());
    }

    #[test]
    fn belt_env_mode_pure_matrix() {
        use std::ffi::OsStr;
        assert_eq!(belt_env_mode(None), BeltMode::Disabled);
        assert_eq!(belt_env_mode(Some(OsStr::new(""))), BeltMode::Disabled);
        assert_eq!(belt_env_mode(Some(OsStr::new("0"))), BeltMode::Disabled);
        assert_eq!(belt_env_mode(Some(OsStr::new("false"))), BeltMode::Disabled);
        assert_eq!(belt_env_mode(Some(OsStr::new("off"))), BeltMode::Disabled);
        assert_eq!(belt_env_mode(Some(OsStr::new("no"))), BeltMode::Disabled);
        assert_eq!(belt_env_mode(Some(OsStr::new("1"))), BeltMode::BestEffort);
        assert_eq!(
            belt_env_mode(Some(OsStr::new("true"))),
            BeltMode::BestEffort
        );
        assert_eq!(belt_env_mode(Some(OsStr::new("on"))), BeltMode::BestEffort);
        assert_eq!(belt_env_mode(Some(OsStr::new("yes"))), BeltMode::BestEffort);
        assert_eq!(
            belt_env_mode(Some(OsStr::new("TRUE"))),
            BeltMode::BestEffort
        );
        assert_eq!(belt_env_mode(Some(OsStr::new("YES"))), BeltMode::BestEffort);
        assert_eq!(
            belt_env_mode(Some(OsStr::new("required"))),
            BeltMode::Required
        );
        assert_eq!(
            belt_env_mode(Some(OsStr::new("REQUIRED"))),
            BeltMode::Required
        );
        assert_eq!(
            belt_env_mode(Some(OsStr::new("Required"))),
            BeltMode::Required
        );
        assert_eq!(
            belt_env_mode(Some(OsStr::new("unknown"))),
            BeltMode::Disabled
        );
    }

    #[test]
    fn protection_mode_default_is_best_effort() {
        assert_eq!(ProtectionMode::default(), ProtectionMode::BestEffort);
        assert_eq!(BeltMode::default(), BeltMode::Disabled);
    }
}
