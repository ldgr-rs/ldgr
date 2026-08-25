//! Command-line interface for the Ledger DST platform.
// ledger-lint:allow (host application; the CLI reads project files and spawns
//   tool processes, unlike simulation code)

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use clap_complete::Shell;

use ledger_cli::format_check::{FormatCheckOutcome, check_file};
use ledger_cli::ldfi_cmd::{self, LdfiReport};
use ledger_cli::scaffold;
use ledger_cli::scaffold_consensus;
use ledger_cli::{
    Cli, Command, DefaultMiniKv, MaxSatEngineArg, generate_completions, is_verbose, seed_from_u64,
};
use ledger_explorer::search::{Workload, replay, search};
use ledger_explorer::{HistoryOracle, KeyValueSpec, Oracle, minimize_schedule};
use ledger_format::Hash;
use ledger_sim::{Policy, RunConfig, SimFault, Simulation};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let verbose = is_verbose(cli.verbose.filter());
    let result = match &cli.command {
        Command::Sim {
            seed,
            policy,
            exploration_constant,
            priority_changes,
            max_steps,
            runs,
        } => run_sim(
            &cli,
            verbose,
            *seed,
            policy.to_policy(*exploration_constant, *priority_changes),
            *max_steps,
            *runs,
        ),
        Command::Repro {
            seed,
            policy,
            exploration_constant,
            priority_changes,
            max_steps,
        } => run_repro(
            &cli,
            verbose,
            *seed,
            policy.to_policy(*exploration_constant, *priority_changes),
            *max_steps,
        ),
        Command::Minimize {
            seed,
            policy,
            exploration_constant,
            priority_changes,
            max_steps,
            runs,
        } => run_minimize(
            &cli,
            verbose,
            *seed,
            policy.to_policy(*exploration_constant, *priority_changes),
            *max_steps,
            *runs,
        ),
        Command::Diff {
            seed_a,
            seed_b,
            max_steps,
        } => run_diff(&cli, verbose, *seed_a, *seed_b, *max_steps),
        Command::Doctor => run_doctor(&cli),
        Command::Init { dir, force, sut } => run_init(&cli, dir.as_deref(), *force, *sut),
        Command::Format { file, check } if *check => run_format_check(&cli, file),
        Command::Format { .. } => {
            eprintln!("ledger: `format` currently supports only `--check`");
            Ok(ExitCode::FAILURE)
        }
        Command::Ldfi {
            seed,
            max_steps,
            attempts,
            maxsat_engine,
        } => run_ldfi(&cli, verbose, *seed, *max_steps, *attempts, *maxsat_engine),
        Command::Completions { shell } => run_completions(*shell),
        Command::Ingest { input, fidelity } => run_ingest(&cli, input, *fidelity),
        Command::Cert { cmd } => match cmd {
            ledger_cli::CertCommand::Verify { path } => run_cert_verify(&cli, path),
        },
        Command::Faults { cmd } => match cmd {
            ledger_cli::FaultsCommand::Compile { file } => run_faults_compile(&cli, file),
            ledger_cli::FaultsCommand::Apply {
                file,
                seed_hex,
                workload,
            } => run_faults_apply(&cli, file, seed_hex, workload),
        },
        Command::Coverage { input, format } => run_coverage(&cli, input, format),
        Command::Scaffold {
            template,
            dir,
            force,
        } => run_scaffold(&cli, dir, template, *force),
        #[cfg(unix)]
        Command::RtServer { socket } => run_rt_server(socket),
    };
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("ledger: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Renders the violation record emitted by the `--json` sim path.
fn json_violation(reason: &str, steps: usize, root: Hash) -> String {
    serde_json::json!({
        "status": "violation",
        "reason": reason,
        "steps": steps,
        "journal_root": ledger_format::hash_to_hex(&root)
    })
    .to_string()
}

/// Print captured origins for the witness entries of a violation.
///
/// Origins exist only for runs that flowed through origin-capturing calls
/// (tracked facade sends, direct backend use). Instruction-program runs have
/// no per-effect call sites, so this prints nothing there by design.
fn print_effect_origins(origins: &[(Hash, ledger_sim::OriginSource)], witnesses: &[Hash]) {
    let hits: Vec<_> = origins
        .iter()
        .filter(|(id, _)| witnesses.contains(id))
        .collect();
    if hits.is_empty() {
        return;
    }
    println!("Effect origins:");
    for (id, source) in hits {
        if let ledger_sim::OriginSource::Source(origin) = source {
            let hex = ledger_format::hash_to_hex(id);
            println!("  {} at {}:{}", &hex[..8], origin.file, origin.line);
        }
    }
}

fn run_sim(
    cli: &Cli,
    verbose: bool,
    seed: u64,
    policy: Policy,
    max_steps: usize,
    runs: usize,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let _ = verbose;
    let config = RunConfig::builder()
        .seed(seed_from_u64(seed))
        .policy(policy)
        .max_steps(max_steps)
        .build();
    let workload = DefaultMiniKv;
    let oracle = HistoryOracle::new(&workload, KeyValueSpec::default());

    if cli.ndjson {
        for attempt in 0..runs {
            let mut attempt_config = config.clone();
            attempt_config.seed_mut()[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());
            let run = Simulation::new(attempt_config, workload.programs()).run()?;
            let verdict = oracle.check(&run);
            let status = if verdict.violated {
                "violation"
            } else {
                "passed"
            };
            let value = serde_json::json!({
                "attempt": attempt,
                "status": status,
                "steps": run.steps,
                "journal_root": ledger_format::hash_to_hex(&run.journal.root_hash()),
                "reason": verdict.reason
            });
            println!("{}", value);
        }
        return Ok(ExitCode::SUCCESS);
    }

    if let Some(finding) = search(&workload, &oracle, config, runs)? {
        if cli.json {
            println!(
                "{}",
                json_violation(
                    &finding.verdict.reason,
                    finding.run.steps,
                    finding.run.journal.root_hash()
                )
            );
        } else {
            println!("Violation detected: {}", finding.verdict.reason);
            println!(
                "Journal root: {}",
                ledger_format::hash_to_hex(&finding.run.journal.root_hash())
            );
            println!("Steps executed: {}", finding.run.steps);
            print_effect_origins(&finding.run.origins, &finding.verdict.witnesses);
        }
    } else if cli.json {
        println!(r#"{{"status":"passed","runs":{runs}}}"#);
    } else {
        println!("Simulation passed ({runs} runs evaluated, zero violations).");
    }
    Ok(ExitCode::SUCCESS)
}

fn run_repro(
    cli: &Cli,
    _verbose: bool,
    seed: u64,
    policy: Policy,
    max_steps: usize,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let workload = DefaultMiniKv;
    let seed_hash = seed_from_u64(seed);
    let config = RunConfig::builder()
        .seed(seed_hash)
        .policy(policy)
        .max_steps(max_steps)
        .build();
    let run = Simulation::new(config, workload.programs()).run()?;
    let replayed = replay(&workload, seed_hash, run.decisions.clone())?;

    let matches = run.journal.root_hash() == replayed.journal.root_hash();
    if cli.json || cli.ndjson {
        let value = serde_json::json!({
            "reproducible": matches,
            "journal_root": ledger_format::hash_to_hex(&replayed.journal.root_hash())
        });
        println!("{}", value);
    } else {
        println!("Replay status: reproducible = {matches}");
        println!(
            "Journal root: {}",
            ledger_format::hash_to_hex(&replayed.journal.root_hash())
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn run_minimize(
    cli: &Cli,
    _verbose: bool,
    seed: u64,
    policy: Policy,
    max_steps: usize,
    runs: usize,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let workload = DefaultMiniKv;
    let oracle = HistoryOracle::new(&workload, KeyValueSpec::default());
    let config = RunConfig::builder()
        .seed(seed_from_u64(seed))
        .policy(policy)
        .max_steps(max_steps)
        .build();
    if let Some(finding) = search(&workload, &oracle, config, runs)? {
        let report = minimize_schedule(&finding.run.decisions, |decisions| {
            replay(&workload, finding.seed, decisions.to_vec())
                .map(|run| oracle.check(&run).violated)
                .unwrap_or(false)
        });
        if cli.json || cli.ndjson {
            println!(
                r#"{{"original_steps":{},"minimized_steps":{},"reduction_percent":{:.2}}}"#,
                report.original_count, report.minimized_count, report.reduction_percent
            );
        } else {
            println!(
                "Schedule minimized: {} -> {} decisions ({:.1}% reduction)",
                report.original_count, report.minimized_count, report.reduction_percent
            );
        }
    } else if cli.json || cli.ndjson {
        println!(r#"{{"status":"passed","runs":{runs}}}"#);
    } else {
        println!("No violation found; nothing to minimize.");
    }
    Ok(ExitCode::SUCCESS)
}

fn run_diff(
    cli: &Cli,
    _verbose: bool,
    seed_a: u64,
    seed_b: u64,
    max_steps: usize,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let workload = DefaultMiniKv;
    let c1 = RunConfig::builder()
        .seed(seed_from_u64(seed_a))
        .max_steps(max_steps)
        .build();
    let c2 = RunConfig::builder()
        .seed(seed_from_u64(seed_b))
        .max_steps(max_steps)
        .build();
    let r1 = Simulation::new(c1, workload.programs()).run()?;
    let r2 = Simulation::new(c2, workload.programs()).run()?;

    let diff_pair = ledger_explorer::diff(&r1, &r2);
    if cli.json || cli.ndjson {
        let value = match diff_pair {
            Some((a, b)) => {
                serde_json::json!({"divergence": [ledger_format::hash_to_hex(&a), ledger_format::hash_to_hex(&b)]})
            }
            None => serde_json::json!({"divergence": null}),
        };
        println!("{}", value);
    } else {
        match diff_pair {
            Some((a, b)) => println!(
                "First divergence entry pair: {} {}",
                ledger_format::hash_to_hex(&a),
                ledger_format::hash_to_hex(&b)
            ),
            None => println!("No divergence"),
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn run_doctor(cli: &Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let cwd = std::env::current_dir()?;
    let root = ledger_cli::checks::find_repo_root(&cwd);
    let report = ledger_cli::checks::run_doctor(&root);
    if cli.json {
        let entries: Vec<serde_json::Value> = report
            .outcomes
            .iter()
            .map(|outcome| {
                let status = if outcome.ok { "ok" } else { "fail" };
                serde_json::json!({"check": outcome.name, "status": status, "detail": outcome.detail})
            })
            .collect();
        let value = serde_json::json!({"doctor": entries});
        println!("{}", value);
    } else if cli.ndjson {
        for outcome in &report.outcomes {
            let status = if outcome.ok { "ok" } else { "fail" };
            let value = serde_json::json!({"check": outcome.name, "status": status, "detail": outcome.detail});
            println!("{}", value);
        }
    } else {
        println!("ledger-doctor: checking repository at {}", root.display());
        for line in report.render() {
            println!("  {line}");
        }
        let failed = report.outcomes.iter().filter(|outcome| !outcome.ok).count();
        if report.all_ok() {
            println!("All checks passed.");
        } else {
            println!("{failed} check(s) failed.");
        }
    }
    Ok(if report.all_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn run_init(
    cli: &Cli,
    dir: Option<&str>,
    force: bool,
    sut: bool,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let base: PathBuf = match dir {
        Some(path) => PathBuf::from(path),
        None => std::env::current_dir()?,
    };
    if sut {
        scaffold::write_sut_scaffold(&base, force)?;
        let files = [
            base.join("Cargo.toml"),
            base.join("src").join("main.rs"),
            base.join("tests").join("surface.rs"),
            base.join("README.md"),
        ];
        if cli.json || cli.ndjson {
            let value = serde_json::json!({
                "status": "initialized",
                "dir": base.display().to_string(),
                "files": files.iter().map(|path| path.display().to_string()).collect::<Vec<_>>()
            });
            println!("{}", value);
        } else {
            println!("Initialized ledger SUT project in {}", base.display());
            for path in &files {
                println!("  created: {}", path.display());
            }
        }
        return Ok(ExitCode::SUCCESS);
    }
    let report = scaffold::scaffold(&base, force)?;
    if cli.json || cli.ndjson {
        let value = serde_json::json!({
            "status": "initialized",
            "dir": base.display().to_string(),
            "files": report.created.iter().map(|path| path.display().to_string()).collect::<Vec<_>>()
        });
        println!("{}", value);
    } else {
        println!("Initialized ledger project in {}", base.display());
        for path in &report.created {
            println!("  created: {}", path.display());
        }
        for path in &report.skipped {
            println!("  skipped (exists): {}", path.display());
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn run_scaffold(
    cli: &Cli,
    dir: &Path,
    template: &str,
    force: bool,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let report = scaffold_consensus::scaffold_consensus(dir, template, force)?;
    if cli.json || cli.ndjson {
        let value = serde_json::json!({
            "status": "scaffolded",
            "template": template,
            "dir": dir.display().to_string(),
            "files": report.created.iter().map(|path| path.display().to_string()).collect::<Vec<_>>()
        });
        println!("{}", value);
    } else {
        println!("Scaffolded ledger {template} example in {}", dir.display());
        for path in &report.created {
            println!("  created: {}", path.display());
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn run_format_check(cli: &Cli, file: &Path) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match check_file(file) {
        Err(error) => {
            eprintln!("ledger: {error}");
            Ok(ExitCode::FAILURE)
        }
        Ok(FormatCheckOutcome::Canonical) => {
            if cli.json || cli.ndjson {
                let value =
                    serde_json::json!({"canonical": true, "file": file.display().to_string()});
                println!("{}", value);
            } else {
                println!("[ok] {}: canonical", file.display());
            }
            Ok(ExitCode::SUCCESS)
        }
        Ok(FormatCheckOutcome::NonCanonical { reason }) => {
            if cli.json || cli.ndjson {
                let value = serde_json::json!({"canonical": false, "file": file.display().to_string(), "reason": reason});
                println!("{}", value);
            } else {
                println!("[FAIL] {}: {reason}", file.display());
            }
            Ok(ExitCode::FAILURE)
        }
    }
}

fn run_ldfi(
    cli: &Cli,
    verbose: bool,
    seed: u64,
    max_steps: usize,
    attempts: usize,
    maxsat_engine: MaxSatEngineArg,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let Some(report) = ldfi_cmd::run_ldfi(seed, max_steps, attempts, maxsat_engine)? else {
        if cli.json || cli.ndjson {
            println!(r#"{{"status":"passed","attempts":{attempts}}}"#);
        } else {
            println!("LDFI campaign passed ({attempts} runs evaluated, zero violations).");
        }
        return Ok(ExitCode::SUCCESS);
    };
    if cli.json {
        println!("{}", ldfi_json(&report));
    } else if cli.ndjson {
        let base = serde_json::json!({
            "status": "violation",
            "reason": report.reason,
            "steps": report.steps,
            "journal_root": ledger_format::hash_to_hex(&report.journal_root),
            "attempts": report.attempts
        });
        println!("{}", base);
        for (index, hypothesis) in report.hypotheses.iter().enumerate() {
            let h = serde_json::json!({
                "hypothesis": index,
                "events": hypothesis.events.len(),
                "cost": hypothesis.cost,
                "explanation": hypothesis.explanation
            });
            println!("{}", h);
        }
        let replay = serde_json::json!({
            "replay": {"applied": report.applied, "voided": report.voided, "prefix_ok": report.prefix_ok},
            "schedule": report.schedule.iter().map(describe_injection).collect::<Vec<_>>()
        });
        println!("{}", replay);
    } else {
        println!("Violation detected: {}", report.reason);
        println!(
            "Journal root: {}",
            ledger_format::hash_to_hex(&report.journal_root)
        );
        println!("Steps executed: {}", report.steps);
        print_effect_origins(&report.origins, &report.witnesses);
        println!("LDFI hypotheses:");
        for (index, hypothesis) in report.hypotheses.iter().enumerate() {
            println!(
                "  cut[{index}]: {} event(s), cost {} - {}",
                hypothesis.events.len(),
                hypothesis.cost,
                hypothesis.explanation
            );
        }
        println!(
            "Replay with faults: prefix_ok = {}, applied = {}, voided = {}",
            report.prefix_ok, report.applied, report.voided
        );
        if verbose {
            println!("Schedule:");
            for injection in &report.schedule {
                println!("  {}", describe_injection(injection));
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn ldfi_json(report: &LdfiReport) -> String {
    serde_json::json!({
        "status": "violation",
        "reason": report.reason,
        "steps": report.steps,
        "journal_root": ledger_format::hash_to_hex(&report.journal_root),
        "hypotheses": report.hypotheses.iter().map(|hypothesis| serde_json::json!({
            "events": hypothesis.events.len(),
            "cost": hypothesis.cost,
            "explanation": hypothesis.explanation
        })).collect::<Vec<_>>(),
        "replay": {"applied": report.applied, "voided": report.voided, "prefix_ok": report.prefix_ok},
        "schedule": report.schedule.iter().map(describe_injection).collect::<Vec<_>>(),
        "origins": report.origins.iter().map(|(id, source)| match source {
            ledger_sim::OriginSource::Source(origin) => serde_json::json!({
                "entry": ledger_format::hash_to_hex(id),
                "file": origin.file,
                "line": origin.line
            }),
            _ => serde_json::json!({"entry": ledger_format::hash_to_hex(id)}),
        }).collect::<Vec<_>>()
    }).to_string()
}

fn describe_injection(injection: &SimFault) -> String {
    match injection {
        SimFault::Drop(id) => format!("drop:{}", hex_prefix(id)),
        SimFault::Delay { send, ticks } => format!("delay:{}:{ticks}", hex_prefix(send)),
        SimFault::Partition { src, dst } => format!("partition:{src}->{dst}"),
        SimFault::Crash(id) => format!("crash:{}", hex_prefix(id)),
        SimFault::Corrupt { write, xor_mask } => {
            format!("corrupt:{}:mask={xor_mask}", hex_prefix(write))
        }
        SimFault::CrashState { write, state } => {
            format!("crash-state:{}:{state}", hex_prefix(write))
        }
    }
}

/// Renders the first four bytes of a hash as lowercase hex.
fn hex_prefix(hash: &Hash) -> String {
    hash[..4].iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Renders a 32-byte hash as 64-char lowercase hex.
fn hex_hash(hash: &Hash) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn run_ingest(
    cli: &Cli,
    input: &Path,
    fidelity: ledger_cli::FidelityArg,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let config = ledger_adapters::OtelIngestConfig::new(fidelity.to_fidelity(), true, 100_000);
    let ingested = ledger_adapters::otel::ingest_otel_file_with_config(input, config)?;
    let root_hex = hex_hash(&ingested.journal.root_hash());
    let envelope_hash = hex_hash(&ingested.envelope_hash()?);
    let fidelity_str = fidelity.as_str();
    let certifiable = ingested.is_certifiable();
    let entries = ingested.journal.len();
    if cli.json || cli.ndjson {
        println!(
            r#"{{"journal_root":"{root_hex}","fidelity":"{fidelity_str}","envelope_hash":"{envelope_hash}","certifiable":{certifiable},"entries":{entries}}}"#
        );
    } else {
        println!("Journal root: {root_hex}");
        println!("Fidelity: {fidelity_str}");
        println!("Envelope hash: {envelope_hash}");
        println!("Certifiable: {certifiable}");
        println!("Entries: {entries}");
    }
    Ok(ExitCode::SUCCESS)
}

fn run_cert_verify(cli: &Cli, path: &Path) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let effective_json = cli.json || cli.ndjson;
    match ledger_cli::cert_cmd::run_verify(path, effective_json) {
        Ok(output) => {
            println!("{output}");
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            eprintln!("ledger: {error}");
            Ok(ExitCode::FAILURE)
        }
    }
}

fn run_faults_compile(cli: &Cli, file: &Path) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let effective_json = cli.json || cli.ndjson;
    match ledger_cli::faults_cmd::compile_scenario(file, effective_json) {
        Ok(output) => {
            println!("{output}");
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            eprintln!("ledger: {error}");
            Ok(ExitCode::FAILURE)
        }
    }
}

fn run_faults_apply(
    cli: &Cli,
    file: &Path,
    seed_hex: &str,
    workload: &str,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let effective_json = cli.json || cli.ndjson;
    match ledger_cli::faults_cmd::apply_scenario(file, seed_hex, workload, effective_json) {
        Ok(output) => {
            println!("{output}");
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            eprintln!("ledger: {error}");
            Ok(ExitCode::FAILURE)
        }
    }
}

fn run_coverage(
    _cli: &Cli,
    input: &Path,
    format: &str,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match ledger_cli::coverage_cmd::run(input, format) {
        Ok(output) => {
            println!("{output}");
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            eprintln!("ledger: {error}");
            Ok(ExitCode::FAILURE)
        }
    }
}

#[cfg(unix)]
fn run_rt_server(socket: &Path) -> Result<ExitCode, Box<dyn std::error::Error>> {
    ledger_cli::rt_server::run(socket)
}

fn run_completions(shell: Shell) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut stdout = io::stdout();
    generate_completions(shell, &mut stdout);
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::json_violation;

    #[test]
    fn json_violation_escapes_quote_and_newline() {
        let reason = "read of \"k\" returned 0,\nexpected 42";
        let text = json_violation(reason, 7, [0u8; 32]);
        assert!(
            text.contains("\\\""),
            "quote must be escaped as \\\": {text}"
        );
        assert!(
            text.contains("\\n"),
            "newline must be escaped as \\n: {text}"
        );
        assert!(
            !text.contains(reason),
            "raw reason must not appear unescaped: {text}"
        );
    }
}
