// ledger-lint:allow - host daemon startup reads ambient config by design

//! Configuration for a [`crate::Worker`] instance.
//!
//! The worker is a pure client: it owns no control-plane socket. In
//! standalone mode it drains a local queue file; with a control-plane
//! endpoint it dials the external control plane and receives assignments
//! over one outbound session.

use std::time::Duration;

/// Configuration for a [`crate::Worker`] instance.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
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
            lease_timeout: Duration::from_secs(30),
            max_concurrent: 4,
            profile_hex8: crate::RuntimeProfile::detect().fingerprint_hex8(),
        }
    }
}

impl WorkerConfig {
    /// Create a config with the given lease timeout and default remaining
    /// fields.
    pub fn new(lease_timeout: Duration) -> Self {
        Self {
            lease_timeout,
            ..Self::default()
        }
    }
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
    fn new_overrides_lease_timeout() {
        let cfg = WorkerConfig::new(Duration::from_secs(5));
        assert_eq!(cfg.lease_timeout, Duration::from_secs(5));
        assert_eq!(cfg.max_concurrent, 4);
    }
}
