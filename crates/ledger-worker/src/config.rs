// ledger-lint:allow - host daemon startup inspects the ambient filesystem
// to pick a private directory for its control socket, by design
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Configuration for a [`crate::Worker`] instance.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Path for the Unix domain socket that serves the control plane.
    pub uds_path: PathBuf,
    /// How long a pulled task stays leased before it can be re-queued.
    pub lease_timeout: Duration,
    /// Maximum number of tasks the worker may execute concurrently.
    pub max_concurrent: usize,
    /// Eight-hex runtime-profile fingerprint bound into every published
    /// certificate. Detected once at startup so all certs from one process
    /// carry the same profile identity.
    pub profile_hex8: String,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            uds_path: default_uds_path(),
            lease_timeout: Duration::from_secs(30),
            max_concurrent: 4,
            profile_hex8: crate::RuntimeProfile::detect().fingerprint_hex8(),
        }
    }
}

impl WorkerConfig {
    /// Create a config with a custom UDS path and default remaining fields.
    pub fn new(uds_path: PathBuf) -> Self {
        Self {
            uds_path,
            ..Self::default()
        }
    }
}

/// Default control-socket path: a per-process randomized filename inside
/// the first usable platform-private directory.
///
/// Randomization removes the stale-socket remove-then-bind race: two
/// daemons or restarts never contend for one well-known path, and an
/// attacker cannot pre-place a socket at a predictable location.
pub fn default_uds_path() -> PathBuf {
    let dir = private_socket_dir().unwrap_or_else(std::env::temp_dir);
    dir.join(format!(
        "worker-{}-{}.sock",
        std::process::id(),
        nanos_now()
    ))
}

/// Wall-clock nanoseconds for default-path randomization only; simulation
/// time is untouched.
fn nanos_now() -> u128 {
    // Documented default: a clock before the epoch (clock skew) falls back
    // to zero; the value only randomizes a per-process directory name.
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// First usable owner-only directory for the default control socket.
///
/// Preference order: `/run/ledger` (created 0700 when missing), then
/// `$XDG_RUNTIME_DIR`, then `None` which makes the caller fall back to the
/// shared temp directory with a randomized socket name. A directory counts
/// as usable only when it exists, is owner-only, and belongs to this uid,
/// so only this uid can create or unlink sockets inside it.
#[cfg(unix)]
pub fn private_socket_dir() -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let run_ledger = Path::new("/run/ledger");
    if !run_ledger.exists() {
        // Deliberate best effort: only root can create under /run; every
        // other user skips this candidate through the checks below.
        let _ = std::fs::create_dir(run_ledger);
        // Deliberate best effort: an unwritable /run/ledger fails the later
        // usability check instead of the permission write itself.
        let _ = std::fs::set_permissions(run_ledger, std::fs::Permissions::from_mode(0o700));
    }
    if dir_is_private_to_self(run_ledger) {
        return Some(run_ledger.to_path_buf());
    }
    // An absent XDG dir falls through to the next candidate.
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        let dir = PathBuf::from(xdg);
        if dir_is_private_to_self(&dir) {
            return Some(dir);
        }
    }
    None
}

/// Non-unix builds have no private-directory concept here; callers fall
/// back to the temp directory with a randomized name.
#[cfg(not(unix))]
pub fn private_socket_dir() -> Option<PathBuf> {
    None
}

/// True when `dir` exists, is owner-only, and belongs to this uid.
#[cfg(unix)]
fn dir_is_private_to_self(dir: &Path) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    match std::fs::metadata(dir) {
        Ok(md) => {
            md.is_dir()
                && md.permissions().mode() & 0o077 == 0
                && current_uid().is_some_and(|uid| md.uid() == uid)
        }
        Err(_) => false,
    }
}

/// This process's real uid via `/proc/self` ownership (Linux); `None` when
/// the platform cannot answer without extra dependencies.
#[cfg(unix)]
fn current_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").ok().map(|md| md.uid())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_values() {
        let cfg = WorkerConfig::default();
        assert_eq!(cfg.lease_timeout, Duration::from_secs(30));
        assert_eq!(cfg.max_concurrent, 4);
        // The profile fingerprint is detected at startup and stable within
        // the process.
        let again = WorkerConfig::default();
        assert_eq!(cfg.profile_hex8, again.profile_hex8);
        assert_eq!(cfg.profile_hex8.len(), 8);
        assert!(
            cfg.profile_hex8
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn new_overrides_path() {
        let cfg = WorkerConfig::new(PathBuf::from("/tmp/custom.sock"));
        assert_eq!(cfg.uds_path, PathBuf::from("/tmp/custom.sock"));
        assert_eq!(cfg.lease_timeout, Duration::from_secs(30));
    }

    #[test]
    fn default_uds_path_is_randomized_inside_private_dir() {
        let first = WorkerConfig::default().uds_path;
        let second = WorkerConfig::default().uds_path;
        for path in [&first, &second] {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .expect("default path has a file name");
            assert!(
                name.starts_with("worker-") && name.ends_with(".sock"),
                "unexpected default socket name {name}"
            );
        }
        // Randomized names never collide across calls.
        assert_ne!(first, second);
        // The parent is the resolved private directory or the temp fallback.
        let expected_parent = private_socket_dir().unwrap_or_else(std::env::temp_dir);
        assert_eq!(first.parent(), Some(expected_parent.as_path()));
    }
}
