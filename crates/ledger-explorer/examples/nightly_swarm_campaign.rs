//! Nightly bounded swarm campaign driver.
//!
//! Runs the explorer's seeded swarm campaign over one reference instruction
//! workload, writes a machine-readable campaign summary plus one `.ldgr`
//! repro manifest per finding, and exits zero on completion. This binary is a
//! pure artifact producer. Campaign policy (which findings are expected and
//! which findings must open an issue) lives in
//! `.github/workflows/nightly-campaigns.yml`, not here.
//!
//! When `LEDGER_CERT_OUT` requests a certificate, the builder id records the
//! runtime profile: `LEDGER_BUILDER_ID` (default "nightly-swarm-campaign")
//! gains a `+<hex8>` suffix from `LEDGER_PROFILE_FINGERPRINT` when that
//! variable is set, binding the certificate to the worker runtime profile
//! handshake (`ledger_worker::profile`).
// ledger-lint:allow (host-side campaign driver; it writes manifests with std::fs, unlike simulation code)

use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};

use ledger_explorer::oracle::{AssertionOracle, HistoryOracle, KeyValueSpec};
use ledger_explorer::search::{CampaignReport, Finding, run_swarm_campaign};
use ledger_explorer::workloads::{MiniKvWorkload, TwoPhaseCommitWorkload};
use ledger_format::{EntryHash, RunManifest};
use ledger_sim::{Policy, RunConfig};

/// Hard cap on campaign attempts. Keeps a nightly run time-bounded on a free
/// runner no matter what the caller passes.
const MAX_ATTEMPTS: usize = 512;

/// Default root seed. Fixed so repeated nightlies replay the same campaign.
const DEFAULT_SEED: u64 = 0x5EED_C0DE;

/// Default instruction budget per run. The reference instruction workloads are
/// a few instructions long; this is generous headroom.
const DEFAULT_MAX_STEPS: usize = 256;

/// Default output directory for campaign artifacts.
const DEFAULT_OUT: &str = "campaign-out";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkloadKind {
    MiniKv,
    TwoPhaseCommit,
}

impl WorkloadKind {
    fn name(self) -> &'static str {
        match self {
            Self::MiniKv => "mini-kv",
            Self::TwoPhaseCommit => "two-phase-commit",
        }
    }

    fn oracle_name(self) -> &'static str {
        match self {
            Self::MiniKv => "history-key-value",
            Self::TwoPhaseCommit => "assertion",
        }
    }
}

struct Args {
    workload: WorkloadKind,
    runs: usize,
    seed: u64,
    max_steps: usize,
    out: PathBuf,
}

fn usage(program: &str) -> String {
    format!(
        "usage: {program} [--workload mini-kv|two-phase-commit] [--runs N] [--seed N] \
         [--max-steps N] [--out DIR]\n\
         Runs a bounded swarm campaign and writes campaign-summary.json plus one \
         .ldgr repro manifest per finding into --out (default: {DEFAULT_OUT})."
    )
}

fn parse_args() -> Result<Option<Args>, String> {
    let mut args = env::args();
    let program = args
        .next()
        .unwrap_or_else(|| "nightly_swarm_campaign".into());
    let mut workload = WorkloadKind::MiniKv;
    let mut runs = 256usize;
    let mut seed = DEFAULT_SEED;
    let mut max_steps = DEFAULT_MAX_STEPS;
    let mut out = PathBuf::from(DEFAULT_OUT);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                println!("{}", usage(&program));
                return Ok(None);
            }
            "--workload" => {
                workload = match args.next().as_deref() {
                    Some("mini-kv") => WorkloadKind::MiniKv,
                    Some("two-phase-commit") => WorkloadKind::TwoPhaseCommit,
                    other => return Err(format!("unknown workload {other:?}")),
                };
            }
            "--runs" => {
                runs = args
                    .next()
                    .and_then(|value| value.parse().ok())
                    .ok_or("--runs needs a number")?;
            }
            "--seed" => {
                seed = args
                    .next()
                    .and_then(|value| value.parse().ok())
                    .ok_or("--seed needs a number")?;
            }
            "--max-steps" => {
                max_steps = args
                    .next()
                    .and_then(|value| value.parse().ok())
                    .ok_or("--max-steps needs a number")?;
            }
            "--out" => out = PathBuf::from(args.next().ok_or("--out needs a path")?),
            other => return Err(format!("unknown argument {other:?}\n{}", usage(&program))),
        }
    }
    Ok(Some(Args {
        workload,
        runs: runs.min(MAX_ATTEMPTS),
        seed,
        max_steps,
        out,
    }))
}

/// Base config for a campaign. The swarm campaign derives each attempt seed
/// from this base and draws swarm knobs from the seeded stream, so the whole
/// campaign is deterministic.
fn base_config(seed: u64, max_steps: usize) -> RunConfig {
    let mut seed_bytes = [0u8; 32];
    seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
    RunConfig::builder()
        .seed(EntryHash(seed_bytes))
        .policy(Policy::Random)
        .max_steps(max_steps)
        .build()
}

/// Recover the campaign attempt index from a finding seed. The swarm campaign
/// writes the attempt index into the first eight bytes of each attempt seed.
fn attempt_of(seed: &EntryHash) -> usize {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&seed.0[..8]);
    u64::from_le_bytes(bytes) as usize
}

/// Build a pinned run manifest for one finding, mirroring the corpus fixture
/// writer in `gen_corpus.rs`.
fn build_manifest(finding: &Finding) -> RunManifest {
    let mut actor_heads = BTreeMap::new();
    for entry in finding.run.journal.entries() {
        actor_heads.insert(entry.data.actor, entry.id);
    }
    RunManifest {
        format_version: ledger_format::FORMAT_VERSION,
        crash_semantics_version: ledger_format::CRASH_SEMANTICS_VERSION,
        root_seed: finding.seed,
        policy_tag: "swarm:random".into(),
        journal_root: finding.run.journal.root_hash(),
        entry_count: finding.run.journal.len() as u64,
        actor_heads,
        execution_identity: None,
    }
}

fn hex(hash: &EntryHash) -> String {
    hash.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Escape one string for safe embedding in a JSON string literal.
fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

/// Write the summary JSON and one `.ldgr` manifest per finding into `out`.
///
/// The summary is a machine-readable campaign report. A formal in-toto
/// Statement certificate (`campaign-certificate.json`) is also emitted via
/// `certs.rs` when `LEDGER_CERT_OUT` is set, so the summary no longer claims
/// to be the sole artifact. The `note` field in the summary points to the
/// companion certificate.
fn emit(
    report: &CampaignReport,
    workload_name: &str,
    oracle_name: &str,
    base_seed: &EntryHash,
    max_steps: usize,
    out: &Path,
) -> Result<(), String> {
    std::fs::create_dir_all(out).map_err(|error| format!("create {}: {error}", out.display()))?;

    let mut findings_json = Vec::with_capacity(report.findings.len());
    for finding in &report.findings {
        let attempt = attempt_of(&finding.seed);
        let variant = report.variants.get(attempt).cloned().unwrap_or_default();
        let file_name = format!("repro-{attempt:04}.ldgr");
        let manifest = build_manifest(finding);
        let bytes = manifest
            .to_canonical_bytes()
            .map_err(|error| format!("manifest encode: {error}"))?;
        let path = out.join(&file_name);
        std::fs::write(&path, bytes)
            .map_err(|error| format!("write {}: {error}", path.display()))?;
        findings_json.push(format!(
            r#"{{"attempt":{attempt},"seed":"{}","journal_root":"{}","entry_count":{},"reason":"{}","variant":"{}","repro_manifest":"{}"}}"#,
            hex(&finding.seed),
            hex(&finding.run.journal.root_hash()),
            finding.run.journal.len(),
            json_escape(&finding.verdict.reason),
            json_escape(&variant),
            file_name
        ));
    }

    let summary = format!(
        r#"{{"campaign":"swarm","workload":"{}","oracle":"{}","base_seed":"{}","policy":"random","max_steps":{},"runs_executed":{},"distinct_journal_roots":{},"findings":[{}],"note":"Machine-readable nightly campaign summary. A formal in-toto Statement certificate (campaign-certificate.json) is emitted alongside this summary via certs.rs; every finding has a companion .ldgr repro manifest in this directory and repros are unminimized."}}"#,
        workload_name,
        oracle_name,
        hex(base_seed),
        max_steps,
        report.runs_executed,
        report.distinct_roots,
        findings_json.join(",")
    );
    std::fs::write(out.join("campaign-summary.json"), summary)
        .map_err(|error| format!("write summary: {error}"))?;
    Ok(())
}

/// Canonical digest of the base config, attested as
/// `externalParameters.runConfigDigest` in the certificate.
///
/// The versioned canonical bytes come from the owned codec in
/// `ledger_sim::config_canonical`; this driver no longer carries a private
/// copy, so the worker boundary and the certificate can never disagree.
fn run_config_digest(config: &RunConfig) -> Result<EntryHash, String> {
    ledger_sim::canonical_hash(config)
        .map_err(|error| format!("run config canonical bytes: {error}"))
}

/// Bind a builder id to the runtime profile fingerprint.
///
/// When a fingerprint is supplied its first eight hex chars are appended as
/// `+<hex8>` so certificates record which runtime profile produced them
/// (`ledger_worker::profile` handshake). Characters other than ASCII hex
/// digits are dropped, and a fingerprint with fewer than eight surviving
/// chars is ignored, so a malformed variable cannot alter the builder id.
fn bind_builder_id(base: &str, fingerprint: Option<&str>) -> String {
    let Some(fp) = fingerprint else {
        return base.to_string();
    };
    let hex8: String = fp
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(8)
        .collect();
    if hex8.len() == 8 {
        format!("{base}+{}", hex8.to_ascii_lowercase())
    } else {
        base.to_string()
    }
}

/// Certificate builder id from the environment.
///
/// Base id is `LEDGER_BUILDER_ID` (default "nightly-swarm-campaign"); when
/// `LEDGER_PROFILE_FINGERPRINT` is set the runtime-profile short fingerprint
/// is bound into it via [`bind_builder_id`].
fn builder_id() -> String {
    let base = env::var("LEDGER_BUILDER_ID").unwrap_or_else(|_| "nightly-swarm-campaign".into());
    bind_builder_id(
        &base,
        env::var("LEDGER_PROFILE_FINGERPRINT").ok().as_deref(),
    )
}

fn drive(args: &Args) -> Result<(), String> {
    let base = base_config(args.seed, args.max_steps);
    let report = match args.workload {
        WorkloadKind::MiniKv => {
            let oracle = HistoryOracle::new(&MiniKvWorkload, KeyValueSpec::default());
            run_swarm_campaign(&MiniKvWorkload, &oracle, base.clone(), args.runs)
                .map_err(|error| format!("mini-kv swarm campaign failed: {error}"))?
        }
        WorkloadKind::TwoPhaseCommit => run_swarm_campaign(
            &TwoPhaseCommitWorkload,
            &AssertionOracle,
            base.clone(),
            args.runs,
        )
        .map_err(|error| format!("two-phase-commit swarm campaign failed: {error}"))?,
    };
    emit(
        &report,
        args.workload.name(),
        args.workload.oracle_name(),
        &base.seed(),
        args.max_steps,
        &args.out,
    )?;
    if let Ok(cert_out) = env::var("LEDGER_CERT_OUT")
        && !cert_out.trim().is_empty()
    {
        let cert_path = PathBuf::from(cert_out);
        if let Some(parent) = cert_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create {}: {error}", parent.display()))?;
        }
        let digest = run_config_digest(&base)?;
        let builder_id = builder_id();
        report
            .write_certificate(&cert_path, digest, &builder_id, None)
            .map_err(|error| format!("certificate emit: {error}"))?;
        println!("certificate written to {}", cert_path.display());
    }
    println!(
        "swarm campaign complete: workload={} runs={} distinct_roots={} findings={} out={}",
        args.workload.name(),
        report.runs_executed,
        report.distinct_roots,
        report.findings.len(),
        args.out.display()
    );
    for finding in &report.findings {
        let attempt = attempt_of(&finding.seed);
        println!(
            "  finding: attempt={attempt} seed={} root={} reason={}",
            hex(&finding.seed),
            hex(&finding.run.journal.root_hash()),
            finding.verdict.reason
        );
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    match parse_args() {
        Ok(None) => std::process::ExitCode::SUCCESS,
        Ok(Some(args)) => match drive(&args) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("ledger: {error}");
                std::process::ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("ledger: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mini_kv_swarm_campaign_is_deterministic_and_finds_the_planted_race() {
        let base = base_config(42, 128);
        let oracle = HistoryOracle::new(&MiniKvWorkload, KeyValueSpec::default());
        let first = run_swarm_campaign(&MiniKvWorkload, &oracle, base.clone(), 24).unwrap();
        let second = run_swarm_campaign(&MiniKvWorkload, &oracle, base, 24).unwrap();
        assert!(
            !first.findings.is_empty(),
            "the planted stale-read race must fire under swarm faults"
        );
        assert_eq!(first.runs_executed, 24);
        assert_eq!(first.distinct_roots, second.distinct_roots);
        assert_eq!(first.variants, second.variants);
        assert_eq!(first.findings.len(), second.findings.len());
        for (a, b) in first.findings.iter().zip(second.findings.iter()) {
            assert_eq!(a.seed, b.seed);
            assert_eq!(a.run.journal.root_hash(), b.run.journal.root_hash());
        }
    }

    #[test]
    fn two_phase_commit_swarm_campaign_holds_under_swarm_faults() {
        let base = base_config(7, 128);
        let report =
            run_swarm_campaign(&TwoPhaseCommitWorkload, &AssertionOracle, base, 24).unwrap();
        assert_eq!(report.runs_executed, 24);
        assert!(
            report.findings.is_empty(),
            "the clean two-phase-commit workload must hold under swarm faults"
        );
    }

    #[test]
    fn attempt_of_recovers_the_campaign_attempt_index() {
        let base = base_config(0, 64);
        for attempt in 0..16usize {
            let mut seed = base.seed();
            seed[..8].copy_from_slice(&(attempt as u64).to_le_bytes());
            assert_eq!(attempt_of(&seed), attempt);
        }
    }

    #[test]
    fn builder_id_binds_eight_hex_chars_when_fingerprint_present() {
        assert_eq!(bind_builder_id("nightly", None), "nightly");
        let fp = "0123456789abcdef";
        assert_eq!(
            bind_builder_id("nightly", Some(fp)),
            "nightly+01234567",
            "only the first eight hex chars bind"
        );
        // Uppercase input normalizes to lowercase.
        assert_eq!(bind_builder_id("b", Some("ABCDEF01")), "b+abcdef01");
    }

    #[test]
    fn builder_id_ignores_malformed_fingerprint() {
        // Fewer than eight surviving hex chars leaves the base id untouched.
        assert_eq!(bind_builder_id("nightly", Some("zz9")), "nightly");
        assert_eq!(bind_builder_id("nightly", Some("garbage")), "nightly");
        assert_eq!(bind_builder_id("nightly", Some("")), "nightly");
    }
}
