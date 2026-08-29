//! Execution identity: the canonical run and build binding.
//!
//! An [`ExecutionIdentity`] binds every fact that must match for two runs to
//! be comparable: the engine build (source revision, dirty state, version,
//! toolchain, target triple, build profile, enabled features, and lockfile
//! digest), the SUT and guest artifacts, the workload and its inputs, the
//! backend and runtime profile, the canonical `RunConfig` digest and seed-tree
//! root, the fault specification, the oracle and support-provider versions,
//! the journal format and crash-semantics versions, and the deterministic
//! resource limits.
//!
//! The canonical byte form is length-prefixed field encoding in declaration
//! order. The digest is a BLAKE3 keyed hash over those bytes with a fixed
//! domain key, so identity digests are domain-separated from every other hash
//! in the system. An identity missing required build data is incomplete and
//! has no digest: [`Self::digest`] returns `None`, and a root comparison must
//! fail before comparing roots when either side is incomplete.

use alloc::string::String;
use alloc::vec::Vec;

use ledger_format::Hash;

/// Domain key for execution-identity digests. Exactly 32 bytes; changing the
/// key changes every identity digest and is a breaking format change.
const IDENTITY_DOMAIN_KEY: [u8; 32] = *b"ldgr.execution-identity.v1\0\0\0\0\0\0";

/// Journal format version bound by every identity. Bumped only by an approved
/// format change (E2 owns format v2).
pub const JOURNAL_FORMAT_VERSION: u32 = 1;

/// Crash-semantics version bound by every identity. Bumped only by an approved
/// crash-semantics change (E2 owns versioned fail-closed recovery).
pub const CRASH_SEMANTICS_VERSION: u32 = 1;

/// Deterministic resource limits bound by an execution identity.
///
/// The identity binds the limits so a run executed under different budgets is
/// never compared as if it were the same run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResourceLimits {
    /// Maximum scheduler steps granted to the run.
    pub max_steps: u64,
}

/// Canonical build and run binding for one execution.
///
/// Fields in the build segment come from compile-time capture (see
/// `ledger_explorer::identity::EngineBuild`); fields in the run segment come
/// from the configuration and context of the specific run. An identity is
/// complete when every required build field is present; see
/// [`Self::is_complete`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionIdentity {
    // Build segment (compile-time derived).
    /// ldgr source revision; `None` means build data was missing at compile
    /// time, which makes the identity incomplete.
    pub engine_revision: Option<String>,
    /// Whether the ldgr source tree was dirty at build time.
    pub engine_dirty: bool,
    /// Engine crate version baked at compile time.
    pub engine_version: String,
    /// Toolchain identifier baked at compile time.
    pub toolchain: String,
    /// Target triple baked at compile time.
    pub target_triple: String,
    /// Build profile (`debug` or `release`) baked at compile time.
    pub build_profile: String,
    /// Enabled engine features, comma separated and sorted.
    pub features: String,
    /// Digest of the workspace lockfile baked at compile time.
    pub lockfile_digest: Option<Hash>,
    // Run segment (runtime derived).
    /// SUT repository revision; `None` when no SUT is bound.
    pub sut_revision: Option<String>,
    /// Whether the SUT tree was dirty at execution time.
    pub sut_dirty: bool,
    /// Digest of the SUT artifact when one is bound.
    pub sut_artifact_digest: Option<Hash>,
    /// Digest of a guest or component artifact when one is used.
    pub guest_digest: Option<Hash>,
    /// Workload identifier selecting the instruction programs.
    pub workload_id: String,
    /// Digest of the workload program set.
    pub program_digest: Hash,
    /// Digests of every workload input, order independent.
    pub input_digests: Vec<Hash>,
    /// Backend identifier (`sim`, `wasm`, `tokio`).
    pub backend: String,
    /// Runtime profile description or fingerprint of the executing host.
    pub runtime_profile: String,
    /// Digest of the canonical `RunConfig` bytes.
    pub run_config_digest: Hash,
    /// Root of the run's seed tree (the config root seed).
    pub seed_tree_root: Hash,
    /// Digest of the fault specification; `None` when no faults are bound.
    pub faultspec_digest: Option<Hash>,
    /// Oracle version; `None` when the default oracle is used.
    pub oracle_version: Option<u64>,
    /// Support-provider version; `None` when no provider is bound.
    pub support_provider_version: Option<u64>,
    /// Journal format version at execution time.
    pub journal_format_version: u32,
    /// Crash-semantics version at execution time.
    pub crash_semantics_version: u32,
    /// Deterministic resource limits the run executed under.
    pub resource_limits: ResourceLimits,
}

impl ExecutionIdentity {
    /// Whether every required build field is present.
    ///
    /// An identity with missing build data (no source revision, no lockfile
    /// digest, or an empty version, toolchain, target, or profile) is
    /// incomplete: it cannot be compared against another identity, and
    /// [`Self::digest`] returns `None`.
    pub fn is_complete(&self) -> bool {
        self.engine_revision.is_some()
            && self.lockfile_digest.is_some()
            && !self.engine_version.is_empty()
            && !self.toolchain.is_empty()
            && !self.target_triple.is_empty()
            && !self.build_profile.is_empty()
    }

    /// Canonical length-prefixed field encoding in declaration order.
    ///
    /// `input_digests` is sorted before encoding so insertion order never
    /// changes the bytes. The encoding is total: an incomplete identity still
    /// encodes, it just has no comparable digest.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_opt_str(&self.engine_revision, &mut out);
        encode_bool(self.engine_dirty, &mut out);
        encode_str(&self.engine_version, &mut out);
        encode_str(&self.toolchain, &mut out);
        encode_str(&self.target_triple, &mut out);
        encode_str(&self.build_profile, &mut out);
        encode_str(&self.features, &mut out);
        encode_opt_hash(&self.lockfile_digest, &mut out);
        encode_opt_str(&self.sut_revision, &mut out);
        encode_bool(self.sut_dirty, &mut out);
        encode_opt_hash(&self.sut_artifact_digest, &mut out);
        encode_opt_hash(&self.guest_digest, &mut out);
        encode_str(&self.workload_id, &mut out);
        encode_hash(&self.program_digest, &mut out);
        encode_hashes(&self.input_digests, &mut out);
        encode_str(&self.backend, &mut out);
        encode_str(&self.runtime_profile, &mut out);
        encode_hash(&self.run_config_digest, &mut out);
        encode_hash(&self.seed_tree_root, &mut out);
        encode_opt_hash(&self.faultspec_digest, &mut out);
        encode_opt_u64(self.oracle_version, &mut out);
        encode_opt_u64(self.support_provider_version, &mut out);
        encode_u32(self.journal_format_version, &mut out);
        encode_u32(self.crash_semantics_version, &mut out);
        encode_u64(self.resource_limits.max_steps, &mut out);
        out
    }

    /// Domain-separated BLAKE3 digest of the canonical identity bytes.
    ///
    /// Returns `None` when the identity is incomplete. Callers must treat a
    /// `None` as an identity disagreement before any root comparison.
    pub fn digest(&self) -> Option<Hash> {
        if !self.is_complete() {
            return None;
        }
        Some(*blake3::keyed_hash(&IDENTITY_DOMAIN_KEY, &self.canonical_bytes()).as_bytes())
    }
}

fn encode_bool(value: bool, out: &mut Vec<u8>) {
    out.push(u8::from(value));
}

fn encode_u32(value: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&u64::from(value).to_le_bytes());
}

fn encode_u64(value: u64, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn encode_opt_u64(value: Option<u64>, out: &mut Vec<u8>) {
    match value {
        Some(v) => {
            out.push(1);
            encode_u64(v, out);
        }
        None => out.push(0),
    }
}

fn encode_str(value: &str, out: &mut Vec<u8>) {
    out.extend_from_slice(&(value.len() as u64).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn encode_opt_str(value: &Option<String>, out: &mut Vec<u8>) {
    match value {
        Some(s) => {
            out.push(1);
            encode_str(s, out);
        }
        None => out.push(0),
    }
}

fn encode_hash(value: &Hash, out: &mut Vec<u8>) {
    out.extend_from_slice(value);
}

fn encode_opt_hash(value: &Option<Hash>, out: &mut Vec<u8>) {
    match value {
        Some(h) => {
            out.push(1);
            encode_hash(h, out);
        }
        None => out.push(0),
    }
}

fn encode_hashes(values: &[Hash], out: &mut Vec<u8>) {
    let mut sorted: Vec<Hash> = values.to_vec();
    sorted.sort_unstable();
    out.extend_from_slice(&(sorted.len() as u64).to_le_bytes());
    for hash in &sorted {
        encode_hash(hash, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    /// A complete identity with distinct values in every field.
    fn sample() -> ExecutionIdentity {
        ExecutionIdentity {
            engine_revision: Some("rev-abc123".to_string()),
            engine_dirty: false,
            engine_version: "0.1.0".to_string(),
            toolchain: "1.97.1-x86_64-unknown-linux-gnu".to_string(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            build_profile: "debug".to_string(),
            features: "default,solver-cadical".to_string(),
            lockfile_digest: Some([0x11; 32]),
            sut_revision: Some("sut-rev-9".to_string()),
            sut_dirty: false,
            sut_artifact_digest: Some([0x22; 32]),
            guest_digest: Some([0x33; 32]),
            workload_id: "kv".to_string(),
            program_digest: [0x44; 32],
            input_digests: vec![[0x55; 32], [0x66; 32]],
            backend: "sim".to_string(),
            runtime_profile: "cpus=8".to_string(),
            run_config_digest: [0x77; 32],
            seed_tree_root: [0x88; 32],
            faultspec_digest: Some([0x99; 32]),
            oracle_version: Some(1),
            support_provider_version: Some(2),
            journal_format_version: JOURNAL_FORMAT_VERSION,
            crash_semantics_version: CRASH_SEMANTICS_VERSION,
            resource_limits: ResourceLimits { max_steps: 10_000 },
        }
    }

    #[test]
    fn digest_is_deterministic() {
        let identity = sample();
        assert_eq!(identity.digest(), identity.digest());
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        assert_eq!(sample().canonical_bytes(), sample().canonical_bytes());
    }

    #[test]
    fn digest_changes_when_any_field_changes() {
        let base = sample();
        let base_digest = base.digest().expect("sample identity is complete");
        let mutations: Vec<(&str, ExecutionIdentity)> = vec![
            (
                "engine_revision",
                ExecutionIdentity {
                    engine_revision: Some("rev-other".to_string()),
                    ..base.clone()
                },
            ),
            (
                "engine_dirty",
                ExecutionIdentity {
                    engine_dirty: true,
                    ..base.clone()
                },
            ),
            (
                "engine_version",
                ExecutionIdentity {
                    engine_version: "0.2.0".to_string(),
                    ..base.clone()
                },
            ),
            (
                "toolchain",
                ExecutionIdentity {
                    toolchain: "1.98.0".to_string(),
                    ..base.clone()
                },
            ),
            (
                "target_triple",
                ExecutionIdentity {
                    target_triple: "aarch64-unknown-linux-gnu".to_string(),
                    ..base.clone()
                },
            ),
            (
                "build_profile",
                ExecutionIdentity {
                    build_profile: "release".to_string(),
                    ..base.clone()
                },
            ),
            (
                "features",
                ExecutionIdentity {
                    features: "solver-cadical".to_string(),
                    ..base.clone()
                },
            ),
            (
                "lockfile_digest",
                ExecutionIdentity {
                    lockfile_digest: Some([0x12; 32]),
                    ..base.clone()
                },
            ),
            (
                "sut_revision",
                ExecutionIdentity {
                    sut_revision: Some("sut-rev-other".to_string()),
                    ..base.clone()
                },
            ),
            (
                "sut_dirty",
                ExecutionIdentity {
                    sut_dirty: true,
                    ..base.clone()
                },
            ),
            (
                "sut_artifact_digest",
                ExecutionIdentity {
                    sut_artifact_digest: Some([0x23; 32]),
                    ..base.clone()
                },
            ),
            (
                "guest_digest",
                ExecutionIdentity {
                    guest_digest: Some([0x34; 32]),
                    ..base.clone()
                },
            ),
            (
                "workload_id",
                ExecutionIdentity {
                    workload_id: "linearizable-register".to_string(),
                    ..base.clone()
                },
            ),
            (
                "program_digest",
                ExecutionIdentity {
                    program_digest: [0x45; 32],
                    ..base.clone()
                },
            ),
            (
                "input_digests",
                ExecutionIdentity {
                    input_digests: vec![[0x55; 32]],
                    ..base.clone()
                },
            ),
            (
                "backend",
                ExecutionIdentity {
                    backend: "wasm".to_string(),
                    ..base.clone()
                },
            ),
            (
                "runtime_profile",
                ExecutionIdentity {
                    runtime_profile: "cpus=16".to_string(),
                    ..base.clone()
                },
            ),
            (
                "run_config_digest",
                ExecutionIdentity {
                    run_config_digest: [0x78; 32],
                    ..base.clone()
                },
            ),
            (
                "seed_tree_root",
                ExecutionIdentity {
                    seed_tree_root: [0x89; 32],
                    ..base.clone()
                },
            ),
            (
                "faultspec_digest",
                ExecutionIdentity {
                    faultspec_digest: Some([0x9a; 32]),
                    ..base.clone()
                },
            ),
            (
                "oracle_version",
                ExecutionIdentity {
                    oracle_version: Some(3),
                    ..base.clone()
                },
            ),
            (
                "support_provider_version",
                ExecutionIdentity {
                    support_provider_version: Some(4),
                    ..base.clone()
                },
            ),
            (
                "journal_format_version",
                ExecutionIdentity {
                    journal_format_version: 2,
                    ..base.clone()
                },
            ),
            (
                "crash_semantics_version",
                ExecutionIdentity {
                    crash_semantics_version: 2,
                    ..base.clone()
                },
            ),
            (
                "resource_limits",
                ExecutionIdentity {
                    resource_limits: ResourceLimits { max_steps: 20_000 },
                    ..base.clone()
                },
            ),
        ];
        for (name, mutation) in &mutations {
            let digest = mutation.digest().expect("mutated identity stays complete");
            assert_ne!(digest, base_digest, "{name} must change the digest");
        }
    }

    #[test]
    fn input_digest_order_does_not_change_digest() {
        let a = sample();
        let mut b = sample();
        b.input_digests.reverse();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        assert_eq!(a.digest(), b.digest());
    }

    #[test]
    fn missing_revision_makes_identity_incomplete() {
        let identity = ExecutionIdentity {
            engine_revision: None,
            ..sample()
        };
        assert!(!identity.is_complete());
        assert_eq!(identity.digest(), None);
    }

    #[test]
    fn missing_lockfile_makes_identity_incomplete() {
        let identity = ExecutionIdentity {
            lockfile_digest: None,
            ..sample()
        };
        assert!(!identity.is_complete());
        assert_eq!(identity.digest(), None);
    }

    #[test]
    fn empty_build_fields_make_identity_incomplete() {
        for field in [
            "engine_version",
            "toolchain",
            "target_triple",
            "build_profile",
        ] {
            let mut identity = sample();
            match field {
                "engine_version" => identity.engine_version = String::new(),
                "toolchain" => identity.toolchain = String::new(),
                "target_triple" => identity.target_triple = String::new(),
                "build_profile" => identity.build_profile = String::new(),
                _ => unreachable!(),
            }
            assert!(!identity.is_complete(), "{field} empty must be incomplete");
            assert_eq!(
                identity.digest(),
                None,
                "{field} empty must yield no digest"
            );
        }
    }

    #[test]
    fn run_segment_options_do_not_affect_completeness() {
        let identity = ExecutionIdentity {
            sut_revision: None,
            sut_artifact_digest: None,
            guest_digest: None,
            faultspec_digest: None,
            oracle_version: None,
            support_provider_version: None,
            ..sample()
        };
        assert!(identity.is_complete());
        assert!(identity.digest().is_some());
    }

    #[test]
    fn digest_is_domain_separated_from_plain_blake3() {
        let identity = sample();
        let digest = identity.digest().expect("sample identity is complete");
        let plain = blake3::hash(&identity.canonical_bytes());
        assert_ne!(&digest, plain.as_bytes());
    }
}
