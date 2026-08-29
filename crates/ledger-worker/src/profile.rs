//! Runtime profile handshake between worker and control plane.
//!
//! A [`RuntimeProfile`] captures the engine build and host shape a worker
//! runs under: `engine_sha`, `toolchain`, compile-time `features`,
//! `sut_hashes` (system-under-test digests, provided at registration),
//! `cpu_topology`, and `env_sanitation` (names of stripped variable
//! patterns). The blake3 [`RuntimeProfile::fingerprint`] over the canonical
//! field encoding is the handshake identity:
//!
//! - Wire: the session hello carries the hex fingerprint in
//!   `RuntimeProfile.fingerprint_hex`; the control plane validates it.
//! - Certificates: emission sites append `+<hex8>` to the builder id when
//!   `LEDGER_PROFILE_FINGERPRINT` is set (see
//!   `examples/nightly_swarm_campaign.rs`), binding certificates to the
//!   runtime that produced them.
//!
//! The fingerprint is deterministic: list fields are sorted before hashing,
//! so equal profiles fingerprint equally regardless of registration order.

use ledger_format::Hash;
use serde::{Deserialize, Serialize};

/// Default env-sanitation pattern: stripped variable name families.
pub const DEFAULT_ENV_SANITATION: &str = "LEDGER_*";

/// Toolchain recorded when `LDGR_TOOLCHAIN` is not provided at build time.
const FALLBACK_TOOLCHAIN: &str = "pinned-1.97";

/// Engine revision recorded when `LDGR_ENGINE_SHA` is not provided.
const FALLBACK_ENGINE_SHA: &str = "dev";

/// Build and host shape of a worker, hashed into handshakes and certificates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeProfile {
    /// Engine git revision (`LDGR_ENGINE_SHA` at build time, else "dev").
    pub engine_sha: String,
    /// Toolchain identifier (`LDGR_TOOLCHAIN` at build time, else pinned).
    pub toolchain: String,
    /// Compile-time feature list, comma separated and sorted.
    pub features: String,
    /// System-under-test digests, provided at registration.
    pub sut_hashes: Vec<String>,
    /// Host CPU shape as reported by `available_parallelism`.
    pub cpu_topology: String,
    /// Names of stripped environment variable patterns.
    pub env_sanitation: Vec<String>,
}

impl RuntimeProfile {
    /// Detect the profile of the running worker.
    ///
    /// Compile-time fields come from the `LDGR_*` build environment with
    /// documented fallbacks; `cpu_topology` is read from the host.
    pub fn detect() -> Self {
        Self {
            engine_sha: option_env!("LDGR_ENGINE_SHA")
                .unwrap_or(FALLBACK_ENGINE_SHA)
                .to_string(),
            toolchain: option_env!("LDGR_TOOLCHAIN")
                .unwrap_or(FALLBACK_TOOLCHAIN)
                .to_string(),
            features: feature_list(),
            sut_hashes: Vec::new(),
            cpu_topology: cpu_topology(),
            env_sanitation: vec![DEFAULT_ENV_SANITATION.to_string()],
        }
    }

    /// Deterministic blake3 fingerprint over the canonical field encoding.
    ///
    /// Fields are encoded length-prefixed in declaration order; `sut_hashes`
    /// and `env_sanitation` are sorted first so registration order does not
    /// change the fingerprint.
    pub fn fingerprint(&self) -> Hash {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }

    /// First eight hex chars of [`Self::fingerprint`], for builder ids.
    pub fn fingerprint_hex8(&self) -> String {
        let mut s = String::with_capacity(8);
        for b in self.fingerprint().iter().take(4) {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_str(&self.engine_sha, &mut out);
        encode_str(&self.toolchain, &mut out);
        encode_str(&self.features, &mut out);
        encode_sorted_strings(&self.sut_hashes, &mut out);
        encode_str(&self.cpu_topology, &mut out);
        encode_sorted_strings(&self.env_sanitation, &mut out);
        out
    }
}

fn encode_str(s: &str, out: &mut Vec<u8>) {
    out.extend_from_slice(&(s.len() as u64).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn encode_sorted_strings(list: &[String], out: &mut Vec<u8>) {
    let mut sorted: Vec<&str> = list.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    out.extend_from_slice(&(sorted.len() as u64).to_le_bytes());
    for s in sorted {
        encode_str(s, out);
    }
}

/// Comma-separated sorted list of enabled crate features.
///
/// Every crate feature must appear here: the list feeds the runtime-profile
/// fingerprint, so an unlisted feature would make different builds claim
/// the same identity.
fn feature_list() -> String {
    let mut features: Vec<&'static str> = Vec::new();
    if cfg!(feature = "control-plane") {
        features.push("control-plane");
    }
    if cfg!(feature = "grpc") {
        features.push("grpc");
    }
    if cfg!(feature = "sim-fs-journaling") {
        features.push("sim-fs-journaling");
    }
    features.sort_unstable();
    features.join(",")
}

/// Host CPU shape; parallelism count when available, else "unknown".
fn cpu_topology() -> String {
    match std::thread::available_parallelism() {
        Ok(cpus) => format!("cpus={cpus}"),
        Err(_) => "cpus=unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RuntimeProfile {
        RuntimeProfile {
            engine_sha: "abc123".to_string(),
            toolchain: "pinned-1.97".to_string(),
            features: "grpc,sim-fs-journaling".to_string(),
            sut_hashes: vec!["sut-b".to_string(), "sut-a".to_string()],
            cpu_topology: "cpus=8".to_string(),
            env_sanitation: vec![DEFAULT_ENV_SANITATION.to_string()],
        }
    }

    #[test]
    fn fingerprint_is_deterministic() {
        assert_eq!(sample().fingerprint(), sample().fingerprint());
    }

    #[test]
    fn fingerprint_changes_on_any_field_change() {
        let base = sample();
        let mutations = [
            RuntimeProfile {
                engine_sha: "def456".to_string(),
                ..base.clone()
            },
            RuntimeProfile {
                toolchain: "pinned-1.98".to_string(),
                ..base.clone()
            },
            RuntimeProfile {
                features: "grpc".to_string(),
                ..base.clone()
            },
            RuntimeProfile {
                sut_hashes: vec!["sut-a".to_string()],
                ..base.clone()
            },
            RuntimeProfile {
                cpu_topology: "cpus=16".to_string(),
                ..base.clone()
            },
            RuntimeProfile {
                env_sanitation: ["LEDGER_*", "TMP_*"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                ..base
            },
        ];
        let base_fp = sample().fingerprint();
        for (i, m) in mutations.iter().enumerate() {
            assert_ne!(
                m.fingerprint(),
                base_fp,
                "mutation {i} must change the fingerprint"
            );
        }
    }

    #[test]
    fn fingerprint_ignores_list_order() {
        // Same members, different insertion order: equal fingerprints.
        let reversed = RuntimeProfile {
            sut_hashes: vec!["sut-b".to_string(), "sut-a".to_string()],
            env_sanitation: vec![DEFAULT_ENV_SANITATION.to_string()],
            ..sample()
        };
        let sorted = RuntimeProfile {
            sut_hashes: vec!["sut-a".to_string(), "sut-b".to_string()],
            env_sanitation: vec![DEFAULT_ENV_SANITATION.to_string()],
            ..sample()
        };
        assert_eq!(reversed.fingerprint(), sorted.fingerprint());
    }

    #[test]
    fn detect_fills_defaults() {
        let detected = RuntimeProfile::detect();
        assert!(!detected.engine_sha.is_empty());
        assert!(!detected.toolchain.is_empty());
        assert!(detected.cpu_topology.starts_with("cpus="));
        assert_eq!(
            detected.env_sanitation,
            vec![DEFAULT_ENV_SANITATION.to_string()]
        );
    }

    #[test]
    fn detect_features_lists_exactly_the_enabled_features() {
        // The wire list must match what detect() can produce: every enabled
        // crate feature present, nothing else. A missing cfg arm here would
        // give two different builds the same fingerprint.
        let mut expected: Vec<&str> = Vec::new();
        if cfg!(feature = "control-plane") {
            expected.push("control-plane");
        }
        if cfg!(feature = "grpc") {
            expected.push("grpc");
        }
        if cfg!(feature = "sim-fs-journaling") {
            expected.push("sim-fs-journaling");
        }
        expected.sort_unstable();
        let detected = RuntimeProfile::detect();
        let listed: Vec<&str> = if detected.features.is_empty() {
            Vec::new()
        } else {
            detected.features.split(',').collect()
        };
        assert_eq!(listed, expected);
    }

    #[test]
    fn fingerprint_hex8_is_eight_lowercase_hex_chars() {
        let hex8 = sample().fingerprint_hex8();
        assert_eq!(hex8.len(), 8);
        assert!(hex8.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(hex8, hex8.to_ascii_lowercase());
    }
}
