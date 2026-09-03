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
//! has no digest: [`Self::digest`] returns `Ok(None)`, and a root comparison
//! must fail before comparing roots when either side is incomplete.
//!
//! Trust boundary: every `String` field and `input_digests` crosses the
//! host/journal boundary (compile-time build capture and runtime run context
//! are both host-supplied). Encoding validates each field against
//! `MAX_IDENTITY_FIELD_BYTES` and the input list against
//! `MAX_IDENTITY_INPUT_DIGESTS` before any length conversion or allocation,
//! and fails closed with a typed error. [`ExecutionIdentity::digest`]
//! returns `Ok(None)` for incomplete identities and `Err` for oversize
//! fields, so oversize identities surface errors rather than silently
//! becoming incomparable.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::dag::JournalError;
use ledger_format::EntryHash;

/// Domain key for execution-identity digests. Exactly 32 bytes; changing the
/// key changes every identity digest and is a breaking format change.
const IDENTITY_DOMAIN_KEY: [u8; 32] = *b"ldgr.execution-identity.v1\0\0\0\0\0\0";

/// Journal format version bound by every identity. Bumped only by an approved
/// format change.
pub const JOURNAL_FORMAT_VERSION: u32 = 1;

/// Crash-semantics version bound by every identity. Bumped only by an approved
/// crash-semantics change.
pub const CRASH_SEMANTICS_VERSION: u32 = 1;

/// Maximum bytes of one host-supplied identity string field.
///
/// Precedent is `MAX_CANONICAL_PATH_BYTES` (4096) in `ledger-format`: long
/// enough for versions, toolchain ids, triples, profiles, feature lists,
/// workload ids, backend names, runtime profiles, and revisions, tight enough
/// to bound the canonical encoding before allocation.
pub const MAX_IDENTITY_FIELD_BYTES: usize = 4096;

/// Maximum digests in `input_digests`.
///
/// Precedent is `MAX_PARENTS_PER_ENTRY` (4096) in `ledger-format`: the same
/// shape (a bounded list of 32-byte hashes) and the same bound discipline.
pub const MAX_IDENTITY_INPUT_DIGESTS: usize = 4096;

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
    pub lockfile_digest: Option<EntryHash>,
    // Run segment (runtime derived).
    /// SUT repository revision; `None` when no SUT is bound.
    pub sut_revision: Option<String>,
    /// Whether the SUT tree was dirty at execution time.
    pub sut_dirty: bool,
    /// Digest of the SUT artifact when one is bound.
    pub sut_artifact_digest: Option<EntryHash>,
    /// Digest of a guest or component artifact when one is used.
    pub guest_digest: Option<EntryHash>,
    /// Workload identifier selecting the instruction programs.
    pub workload_id: String,
    /// Digest of the workload program set.
    pub program_digest: EntryHash,
    /// Digests of every workload input, order independent.
    pub input_digests: Vec<EntryHash>,
    /// Backend identifier (`sim`, `wasm`, `tokio`).
    pub backend: String,
    /// Runtime profile description or fingerprint of the executing host.
    pub runtime_profile: String,
    /// Digest of the canonical `RunConfig` bytes.
    pub run_config_digest: EntryHash,
    /// Root of the run's seed tree (the config root seed).
    pub seed_tree_root: EntryHash,
    /// Digest of the fault specification; `None` when no faults are bound.
    pub faultspec_digest: Option<EntryHash>,
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
    /// changes the bytes. The encoding is total over complete and incomplete
    /// identities alike when every field fits its cap; oversize host-supplied
    /// fields fail closed with [`JournalError::InvalidPayload`]. No length is
    /// converted with `as`, and the output is pre-allocated from a
    /// checked total bounded by the per-field caps.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, JournalError> {
        check_str_len("engine_version", &self.engine_version)?;
        check_str_len("toolchain", &self.toolchain)?;
        check_str_len("target_triple", &self.target_triple)?;
        check_str_len("build_profile", &self.build_profile)?;
        check_str_len("features", &self.features)?;
        check_str_len("workload_id", &self.workload_id)?;
        check_str_len("backend", &self.backend)?;
        check_str_len("runtime_profile", &self.runtime_profile)?;
        check_opt_str_len("engine_revision", self.engine_revision.as_ref())?;
        check_opt_str_len("sut_revision", self.sut_revision.as_ref())?;
        if self.input_digests.len() > MAX_IDENTITY_INPUT_DIGESTS {
            return Err(JournalError::InvalidPayload(
                "input_digests exceeds identity limit".to_string(),
            ));
        }
        let mut out = Vec::with_capacity(self.encoded_len_bound());
        encode_opt_str(&self.engine_revision, &mut out)?;
        encode_bool(self.engine_dirty, &mut out);
        encode_str(&self.engine_version, &mut out)?;
        encode_str(&self.toolchain, &mut out)?;
        encode_str(&self.target_triple, &mut out)?;
        encode_str(&self.build_profile, &mut out)?;
        encode_str(&self.features, &mut out)?;
        encode_opt_hash(&self.lockfile_digest, &mut out);
        encode_opt_str(&self.sut_revision, &mut out)?;
        encode_bool(self.sut_dirty, &mut out);
        encode_opt_hash(&self.sut_artifact_digest, &mut out);
        encode_opt_hash(&self.guest_digest, &mut out);
        encode_str(&self.workload_id, &mut out)?;
        encode_hash(&self.program_digest, &mut out);
        encode_hashes(&self.input_digests, &mut out)?;
        encode_str(&self.backend, &mut out)?;
        encode_str(&self.runtime_profile, &mut out)?;
        encode_hash(&self.run_config_digest, &mut out);
        encode_hash(&self.seed_tree_root, &mut out);
        encode_opt_hash(&self.faultspec_digest, &mut out);
        encode_opt_u64(self.oracle_version, &mut out);
        encode_opt_u64(self.support_provider_version, &mut out);
        encode_u32(self.journal_format_version, &mut out);
        encode_u32(self.crash_semantics_version, &mut out);
        encode_u64(self.resource_limits.max_steps, &mut out);
        Ok(out)
    }

    /// Upper bound of the canonical encoding from the per-field caps.
    ///
    /// Every variable field contributes its capped length plus its length
    /// prefix; fixed fields contribute their exact widths. The caller
    /// pre-allocates exactly this bound after the cap checks above, so a
    /// hostile identity cannot force an unbounded reservation.
    fn encoded_len_bound(&self) -> usize {
        let str_fields = [
            self.engine_version.len(),
            self.toolchain.len(),
            self.target_triple.len(),
            self.build_profile.len(),
            self.features.len(),
            self.workload_id.len(),
            self.backend.len(),
            self.runtime_profile.len(),
        ];
        let opt_str_fields = [
            self.engine_revision.as_ref().map_or(0, |s| s.len()),
            self.sut_revision.as_ref().map_or(0, |s| s.len()),
        ];
        // 8-byte length prefix per string, 1-byte presence per option,
        // 1 byte per bool, 8 bytes per u64-shaped integer, 32 per hash.
        let mut bound = 2 + 8 * 4 + 9 + 1 + 8 + 7 * 32 + 3 + 8 * 3;
        for len in str_fields {
            bound += 8 + len.min(MAX_IDENTITY_FIELD_BYTES);
        }
        for len in opt_str_fields {
            bound += 1 + 8 + len.min(MAX_IDENTITY_FIELD_BYTES);
        }
        bound += 8 + self.input_digests.len().min(MAX_IDENTITY_INPUT_DIGESTS) * 32;
        bound
    }

    /// Domain-separated BLAKE3 digest of the canonical identity bytes.
    ///
    /// Returns `Ok(None)` for incomplete identities and `Err` when the
    /// encoding exceeds the trust-boundary caps. Callers must treat both
    /// as identity disagreement before any root comparison.
    pub fn digest(&self) -> Result<Option<EntryHash>, JournalError> {
        if !self.is_complete() {
            return Ok(None);
        }
        let bytes = self.canonical_bytes()?;
        Ok(Some(EntryHash(
            *blake3::keyed_hash(&IDENTITY_DOMAIN_KEY, &bytes).as_bytes(),
        )))
    }
}

fn check_str_len(field: &str, value: &str) -> Result<(), JournalError> {
    if value.len() > MAX_IDENTITY_FIELD_BYTES {
        return Err(JournalError::InvalidPayload(alloc::format!(
            "identity field {field} exceeds limit"
        )));
    }
    Ok(())
}

fn check_opt_str_len(field: &str, value: Option<&String>) -> Result<(), JournalError> {
    if let Some(s) = value {
        check_str_len(field, s)?;
    }
    Ok(())
}

fn encode_len(len: usize, field: &str, out: &mut Vec<u8>) -> Result<(), JournalError> {
    let wide = u64::try_from(len).map_err(|_| {
        JournalError::InvalidPayload(alloc::format!("identity field {field} length exceeds u64"))
    })?;
    out.extend_from_slice(&wide.to_le_bytes());
    Ok(())
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

fn encode_str(value: &str, out: &mut Vec<u8>) -> Result<(), JournalError> {
    check_str_len("field", value)?;
    encode_len(value.len(), "field", out)?;
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn encode_opt_str(value: &Option<String>, out: &mut Vec<u8>) -> Result<(), JournalError> {
    match value {
        Some(s) => {
            out.push(1);
            encode_str(s, out)?;
        }
        None => out.push(0),
    }
    Ok(())
}

fn encode_hash(value: &EntryHash, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.0);
}

fn encode_opt_hash(value: &Option<EntryHash>, out: &mut Vec<u8>) {
    match value {
        Some(h) => {
            out.push(1);
            encode_hash(h, out);
        }
        None => out.push(0),
    }
}

fn encode_hashes(values: &[EntryHash], out: &mut Vec<u8>) -> Result<(), JournalError> {
    if values.len() > MAX_IDENTITY_INPUT_DIGESTS {
        return Err(JournalError::InvalidPayload(
            "input_digests exceeds identity limit".to_string(),
        ));
    }
    let mut sorted: Vec<EntryHash> = values.to_vec();
    sorted.sort_unstable();
    encode_len(sorted.len(), "input_digests", out)?;
    for hash in &sorted {
        encode_hash(hash, out);
    }
    Ok(())
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
            lockfile_digest: Some(EntryHash([0x11; 32])),
            sut_revision: Some("sut-rev-9".to_string()),
            sut_dirty: false,
            sut_artifact_digest: Some(EntryHash([0x22; 32])),
            guest_digest: Some(EntryHash([0x33; 32])),
            workload_id: "kv".to_string(),
            program_digest: EntryHash([0x44; 32]),
            input_digests: vec![EntryHash([0x55; 32]), EntryHash([0x66; 32])],
            backend: "sim".to_string(),
            runtime_profile: "cpus=8".to_string(),
            run_config_digest: EntryHash([0x77; 32]),
            seed_tree_root: EntryHash([0x88; 32]),
            faultspec_digest: Some(EntryHash([0x99; 32])),
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
        assert_eq!(
            sample().canonical_bytes().unwrap(),
            sample().canonical_bytes().unwrap()
        );
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
                    lockfile_digest: Some(EntryHash([0x12; 32])),
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
                    sut_artifact_digest: Some(EntryHash([0x23; 32])),
                    ..base.clone()
                },
            ),
            (
                "guest_digest",
                ExecutionIdentity {
                    guest_digest: Some(EntryHash([0x34; 32])),
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
                    program_digest: EntryHash([0x45; 32]),
                    ..base.clone()
                },
            ),
            (
                "input_digests",
                ExecutionIdentity {
                    input_digests: vec![EntryHash([0x55; 32])],
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
                    run_config_digest: EntryHash([0x78; 32]),
                    ..base.clone()
                },
            ),
            (
                "seed_tree_root",
                ExecutionIdentity {
                    seed_tree_root: EntryHash([0x89; 32]),
                    ..base.clone()
                },
            ),
            (
                "faultspec_digest",
                ExecutionIdentity {
                    faultspec_digest: Some(EntryHash([0x9a; 32])),
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
        assert_eq!(a.canonical_bytes().unwrap(), b.canonical_bytes().unwrap());
        assert_eq!(a.digest(), b.digest());
    }

    #[test]
    fn missing_revision_makes_identity_incomplete() {
        let identity = ExecutionIdentity {
            engine_revision: None,
            ..sample()
        };
        assert!(!identity.is_complete());
        assert_eq!(identity.digest(), Ok(None));
    }

    #[test]
    fn missing_lockfile_makes_identity_incomplete() {
        let identity = ExecutionIdentity {
            lockfile_digest: None,
            ..sample()
        };
        assert!(!identity.is_complete());
        assert_eq!(identity.digest(), Ok(None));
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
                Ok(None),
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
        assert!(identity.digest().expect("complete").is_some());
    }

    #[test]
    fn digest_is_domain_separated_from_plain_blake3() {
        let identity = sample();
        let digest = identity
            .digest()
            .expect("sample identity is complete")
            .expect("complete identity has a digest");
        let plain = blake3::hash(&identity.canonical_bytes().unwrap());
        assert_ne!(digest.0, *plain.as_bytes());
    }

    #[test]
    fn oversize_field_fails_closed_with_typed_error() {
        let mut identity = sample();
        identity.backend = "x".repeat(MAX_IDENTITY_FIELD_BYTES + 1);
        let err = identity.canonical_bytes().unwrap_err();
        assert!(
            matches!(err, crate::dag::JournalError::InvalidPayload(_)),
            "oversize field must fail closed, got {err:?}"
        );
        assert_eq!(
            identity.digest(),
            Err(crate::dag::JournalError::InvalidPayload(
                "identity field backend exceeds limit".to_string()
            )),
            "digest must surface the typed error instead of mapping it to None"
        );
    }

    #[test]
    fn oversize_input_list_fails_closed() {
        let mut identity = sample();
        identity.input_digests = vec![EntryHash([0x55; 32]); MAX_IDENTITY_INPUT_DIGESTS + 1];
        assert!(
            matches!(
                identity.canonical_bytes().unwrap_err(),
                crate::dag::JournalError::InvalidPayload(_)
            ),
            "oversize input list must fail closed"
        );
        assert!(identity.digest().is_err());
    }

    #[test]
    fn at_cap_identity_still_encodes() {
        let mut identity = sample();
        identity.backend = "x".repeat(MAX_IDENTITY_FIELD_BYTES);
        identity.input_digests = vec![EntryHash([0x55; 32]); MAX_IDENTITY_INPUT_DIGESTS];
        assert!(identity.canonical_bytes().is_ok());
        assert!(identity.digest().expect("at-cap").is_some());
    }
}
