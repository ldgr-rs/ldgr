//! Host-side execution-identity derivation.
//!
//! [`EngineBuild`] captures the engine build segment at compile time: source
//! revision and dirty state, engine version, toolchain, target triple, build
//! profile, enabled features, and the workspace lockfile digest. The capture
//! is compile-time only; a mutable runtime environment variable is never the
//! identity source.
//!
//! [`assemble_identity`] combines the build segment with the run context into
//! the canonical [`ExecutionIdentity`] from `ledger-journal`.
// ledger-lint:allow:env::var (host-side identity capture; the cross-process determinism test re-execs the test binary with a marker env var)
// ledger-lint:allow:SystemTime::now (host-side identity capture; the cross-process test uniquifies the temp file name with the system clock)
// ledger-lint:allow:std::fs:: (host-side identity capture; the cross-process test exchanges the digest through a temp file)

use ledger_format::Hash;
use ledger_journal::{
    CRASH_SEMANTICS_VERSION, ExecutionIdentity, JOURNAL_FORMAT_VERSION, ResourceLimits,
};

/// Toolchain recorded when `LDGR_TOOLCHAIN` is not provided at build time.
const FALLBACK_TOOLCHAIN: &str = "pinned-1.97";

/// Target triple fallback when `build.rs` did not emit `LDGR_TARGET`.
const FALLBACK_TARGET: &str = "unknown-unknown";

/// Build-segment facts captured at compile time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineBuild {
    /// ldgr source revision (`LDGR_ENGINE_SHA` at build time). `None` when
    /// the revision was not provided, which makes identities incomplete.
    pub revision: Option<String>,
    /// Whether the ldgr source tree was dirty at build time.
    pub dirty: bool,
    /// Engine crate version (`CARGO_PKG_VERSION`).
    pub version: String,
    /// Toolchain identifier (`LDGR_TOOLCHAIN` at build time, else pinned).
    pub toolchain: String,
    /// Target triple emitted by `build.rs`.
    pub target_triple: String,
    /// Build profile (`debug` or `release`) emitted by `build.rs`.
    pub build_profile: String,
    /// Enabled engine features, comma separated and sorted.
    pub features: String,
    /// Digest of the workspace lockfile baked in at compile time.
    pub lockfile_digest: Option<Hash>,
}

impl EngineBuild {
    /// Capture the build segment of the binary that links this crate.
    pub fn detect() -> Self {
        Self {
            revision: option_env!("LDGR_ENGINE_SHA").map(str::to_string),
            dirty: option_env!("LDGR_DIRTY").is_some_and(|v| v == "1"),
            version: env!("CARGO_PKG_VERSION").to_string(),
            toolchain: option_env!("LDGR_TOOLCHAIN")
                .unwrap_or(FALLBACK_TOOLCHAIN)
                .to_string(),
            target_triple: option_env!("LDGR_TARGET")
                .unwrap_or(FALLBACK_TARGET)
                .to_string(),
            build_profile: option_env!("LDGR_BUILD_PROFILE")
                .unwrap_or("unknown")
                .to_string(),
            features: feature_list(),
            lockfile_digest: Some(lockfile_digest()),
        }
    }
}

/// Run-context facts filled by the caller for one specific execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityContext {
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
    /// Digests of every workload input.
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
    /// Deterministic resource limits the run executes under.
    pub resource_limits: ResourceLimits,
}

/// Combine the captured build segment with a run context into a full identity.
pub fn assemble_identity(build: &EngineBuild, context: &IdentityContext) -> ExecutionIdentity {
    ExecutionIdentity {
        engine_revision: build.revision.clone(),
        engine_dirty: build.dirty,
        engine_version: build.version.clone(),
        toolchain: build.toolchain.clone(),
        target_triple: build.target_triple.clone(),
        build_profile: build.build_profile.clone(),
        features: build.features.clone(),
        lockfile_digest: build.lockfile_digest,
        sut_revision: context.sut_revision.clone(),
        sut_dirty: context.sut_dirty,
        sut_artifact_digest: context.sut_artifact_digest,
        guest_digest: context.guest_digest,
        workload_id: context.workload_id.clone(),
        program_digest: context.program_digest,
        input_digests: context.input_digests.clone(),
        backend: context.backend.clone(),
        runtime_profile: context.runtime_profile.clone(),
        run_config_digest: context.run_config_digest,
        seed_tree_root: context.seed_tree_root,
        faultspec_digest: context.faultspec_digest,
        oracle_version: context.oracle_version,
        support_provider_version: context.support_provider_version,
        journal_format_version: JOURNAL_FORMAT_VERSION,
        crash_semantics_version: CRASH_SEMANTICS_VERSION,
        resource_limits: context.resource_limits,
    }
}

/// Comma-separated sorted list of enabled crate features.
///
/// The list feeds the identity digest, so an unlisted feature would make
/// different builds claim the same identity.
fn feature_list() -> String {
    let mut features: Vec<&'static str> = Vec::new();
    if cfg!(feature = "solver-cadical") {
        features.push("solver-cadical");
    }
    features.sort_unstable();
    features.join(",")
}

/// Digest of the workspace `Cargo.lock` baked in at compile time.
///
/// `include_str!` freezes the lockfile bytes into the binary and makes cargo
/// rebuild when the lockfile changes, so the digest is a build-time constant
/// without a build-dependency on blake3.
fn lockfile_digest() -> Hash {
    let lockfile = include_str!("../../../Cargo.lock");
    *blake3::hash(lockfile.as_bytes()).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_build() -> EngineBuild {
        EngineBuild {
            revision: Some("rev-abc123".to_string()),
            dirty: false,
            version: "0.1.0".to_string(),
            toolchain: "pinned-1.97".to_string(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            build_profile: "debug".to_string(),
            features: "solver-cadical".to_string(),
            lockfile_digest: Some([0x11; 32]),
        }
    }

    fn sample_context() -> IdentityContext {
        IdentityContext {
            sut_revision: None,
            sut_dirty: false,
            sut_artifact_digest: None,
            guest_digest: None,
            workload_id: "kv".to_string(),
            program_digest: [0x44; 32],
            input_digests: Vec::new(),
            backend: "sim".to_string(),
            runtime_profile: "cpus=8".to_string(),
            run_config_digest: [0x77; 32],
            seed_tree_root: [0x88; 32],
            faultspec_digest: None,
            oracle_version: None,
            support_provider_version: None,
            resource_limits: ResourceLimits { max_steps: 10_000 },
        }
    }

    #[test]
    fn detect_captures_every_build_field() {
        let build = EngineBuild::detect();
        assert!(!build.version.is_empty());
        assert!(!build.toolchain.is_empty());
        assert!(!build.target_triple.is_empty());
        assert!(build.lockfile_digest.is_some());
        assert!(!build.features.is_empty() || cfg!(not(feature = "solver-cadical")));
    }

    #[test]
    fn detect_is_stable_within_one_binary() {
        let a = EngineBuild::detect();
        let b = EngineBuild::detect();
        assert_eq!(a, b);
    }

    #[test]
    fn feature_list_is_sorted() {
        let list = feature_list();
        let parts: Vec<&str> = if list.is_empty() {
            Vec::new()
        } else {
            list.split(',').collect()
        };
        let mut sorted = parts.clone();
        sorted.sort_unstable();
        assert_eq!(parts, sorted);
    }

    #[test]
    fn assemble_maps_build_and_context_fields() {
        let build = sample_build();
        let context = sample_context();
        let identity = assemble_identity(&build, &context);
        assert_eq!(identity.engine_revision, build.revision);
        assert_eq!(identity.backend, "sim");
        assert_eq!(identity.journal_format_version, JOURNAL_FORMAT_VERSION);
        assert_eq!(identity.crash_semantics_version, CRASH_SEMANTICS_VERSION);
        assert!(identity.digest().is_some(), "sample identity is complete");
    }

    #[test]
    fn identical_construction_across_processes() {
        // Re-exec the current test binary as a child; the child writes the
        // identity digest of the same build segment and context to a temp
        // file, and the parent asserts byte equality. Deterministic
        // construction must not depend on process-local state. The child
        // communicates through a file because libtest captures test stdout.
        const CHILD_ENV: &str = "LDGR_IDENTITY_CHILD";
        const CHILD_OUT: &str = "LDGR_IDENTITY_CHILD_OUT";
        let digest = |build: &EngineBuild, context: &IdentityContext| {
            ledger_format::hash_to_hex(
                &assemble_identity(build, context)
                    .digest()
                    .expect("complete identity"),
            )
        };
        if std::env::var_os(CHILD_ENV).is_some() {
            // Child mode: write the digest marker and exit before the harness
            // runs the rest of the suite, so a child never re-execs itself.
            let out = std::env::var_os(CHILD_OUT).expect("child out path is set");
            std::fs::write(
                &out,
                format!("{}\n", digest(&sample_build(), &sample_context())),
            )
            .expect("child must write the digest");
            std::process::exit(0);
        }
        let exe = std::env::current_exe().expect("test binary path is available");
        let out_path = std::env::temp_dir().join(format!(
            "ldgr-identity-child-{}-{}.digest",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock after epoch")
                .as_nanos()
        ));
        let child = std::process::Command::new(exe)
            .env(CHILD_ENV, "1")
            .env(CHILD_OUT, &out_path)
            .arg("identity::tests::identical_construction_across_processes")
            .output()
            .expect("child must run");
        assert!(
            child.status.success(),
            "child exited {:?}",
            child.status.code()
        );
        let child_digest =
            std::fs::read_to_string(&out_path).expect("child writes the digest marker");
        let _ = std::fs::remove_file(&out_path);
        assert_eq!(
            child_digest.trim(),
            digest(&sample_build(), &sample_context())
        );
    }

    #[test]
    fn dirty_tree_changes_the_digest() {
        let build = sample_build();
        let context = sample_context();
        let clean = assemble_identity(&build, &context).digest();
        let dirty = assemble_identity(
            &EngineBuild {
                dirty: true,
                ..sample_build()
            },
            &context,
        )
        .digest();
        assert_ne!(clean, dirty);
    }

    #[test]
    fn feature_ordering_is_canonical() {
        let build = sample_build();
        let context = sample_context();
        let a = assemble_identity(
            &EngineBuild {
                features: "a,b".to_string(),
                ..build.clone()
            },
            &context,
        )
        .digest();
        let b = assemble_identity(
            &EngineBuild {
                features: "b,a".to_string(),
                ..build
            },
            &context,
        )
        .digest();
        assert_ne!(
            a, b,
            "features are bound as given; callers sort before capture"
        );
    }
}
