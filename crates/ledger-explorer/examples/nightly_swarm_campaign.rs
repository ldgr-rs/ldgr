//! Nightly bounded swarm campaign driver.
//!
//! Runs the explorer's seeded swarm campaign over one reference instruction
//! workload, writes a machine-readable campaign summary plus one `.ldgr`
//! repro manifest per finding, and exits zero on completion. This binary is a
//! pure artifact producer. Campaign policy (which findings are expected and
//! which findings must open an issue) lives in
//! `.github/workflows/nightly-campaigns.yml`, not here.
// ledger-lint:allow (host-side campaign driver; it writes manifests with std::fs, unlike simulation code)

use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};

use ledger_explorer::oracle::{AssertionOracle, HistoryOracle, KeyValueSpec};
use ledger_explorer::search::{CampaignReport, Finding, run_swarm_campaign};
use ledger_explorer::workloads::{MiniKvWorkload, TwoPhaseCommitWorkload};
use ledger_format::{Hash, RunManifest};
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
    RunConfig {
        seed: seed_bytes,
        policy: Policy::Random,
        max_steps,
        ..RunConfig::default()
    }
}

/// Recover the campaign attempt index from a finding seed. The swarm campaign
/// writes the attempt index into the first eight bytes of each attempt seed.
fn attempt_of(seed: &Hash) -> usize {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&seed[..8]);
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
        format_version: 1,
        root_seed: finding.seed,
        policy_tag: "swarm:random".into(),
        journal_root: finding.run.journal.root_hash(),
        entry_count: finding.run.journal.len() as u64,
        actor_heads,
        extensions: BTreeMap::new(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
/// The summary is a machine-readable campaign report, not a formal
/// certificate: the repo has no certificate schema yet, so this file names
/// itself a summary in its own `note` field.
fn emit(
    report: &CampaignReport,
    workload_name: &str,
    oracle_name: &str,
    base_seed: &Hash,
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
        r#"{{"campaign":"swarm","workload":"{}","oracle":"{}","base_seed":"{}","policy":"random","max_steps":{},"runs_executed":{},"distinct_journal_roots":{},"findings":[{}],"note":"Machine-readable nightly campaign summary. This is a summary, not a formal certificate. Every finding has a companion .ldgr repro manifest in this directory; repros are unminimized."}}"#,
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
        &base.seed,
        args.max_steps,
        &args.out,
    )?;
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
            let mut seed = base.seed;
            seed[..8].copy_from_slice(&(attempt as u64).to_le_bytes());
            assert_eq!(attempt_of(&seed), attempt);
        }
    }
}
