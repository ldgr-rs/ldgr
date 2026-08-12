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
use ledger_cli::{Cli, Command, DefaultMiniKv, generate_completions, is_verbose, seed_from_u64};
use ledger_explorer::search::{Workload, replay, search};
use ledger_explorer::{HistoryOracle, KeyValueSpec, Oracle, minimize_schedule, solve_ldfi};
use ledger_format::Hash;
use ledger_sim::{FaultInjection, Policy, RunConfig, Simulation};

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
        Command::Init { dir, force } => run_init(&cli, dir.as_deref(), *force),
        Command::Format { file, check } if *check => run_format_check(&cli, file),
        Command::Format { .. } => {
            eprintln!("ledger: `format` currently supports only `--check`");
            Ok(ExitCode::FAILURE)
        }
        Command::Ldfi {
            seed,
            max_steps,
            attempts,
        } => run_ldfi(&cli, verbose, *seed, *max_steps, *attempts),
        Command::Completions { shell } => run_completions(*shell),
    };
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("ledger: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Escapes one string for safe embedding in a JSON string literal.
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

/// Renders the violation record emitted by the `--json` sim path.
fn json_violation(reason: &str, steps: usize, root: Hash) -> String {
    format!(
        r#"{{"status":"violation","reason":"{}","steps":{},"journal_root":"{:02x?}"}}"#,
        json_escape(reason),
        steps,
        root
    )
}

fn run_sim(
    cli: &Cli,
    verbose: bool,
    seed: u64,
    policy: Policy,
    max_steps: usize,
    runs: usize,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let config = RunConfig {
        seed: seed_from_u64(seed),
        policy,
        max_steps,
        ..RunConfig::default()
    };
    let workload = DefaultMiniKv;
    let oracle = HistoryOracle::new(&workload, KeyValueSpec::default());

    if cli.ndjson {
        for attempt in 0..runs {
            let mut attempt_config = config.clone();
            attempt_config.seed[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());
            let run = Simulation::new(attempt_config, workload.programs()).run()?;
            let verdict = oracle.check(&run);
            let status = if verdict.violated {
                "violation"
            } else {
                "passed"
            };
            println!(
                r#"{{"attempt":{attempt},"status":"{status}","steps":{},"journal_root":"{:02x?}","reason":"{}"}}"#,
                run.steps,
                run.journal.root_hash(),
                json_escape(&verdict.reason)
            );
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
            println!("Journal root: {:02x?}", finding.run.journal.root_hash());
            println!("Steps executed: {}", finding.run.steps);
            let hypotheses = solve_ldfi(&finding.run.journal, &finding.verdict);
            println!("LDFI cuts generated: {}", hypotheses.len());
            if verbose {
                for (index, hypothesis) in hypotheses.iter().enumerate() {
                    println!(
                        "  cut[{}]: {} faultable event(s) - {}",
                        index,
                        hypothesis.events.len(),
                        hypothesis.explanation
                    );
                }
            }
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
    let config = RunConfig {
        seed: seed_hash,
        policy,
        max_steps,
        ..RunConfig::default()
    };
    let run = Simulation::new(config, workload.programs()).run()?;
    let replayed = replay(&workload, seed_hash, run.decisions.clone())?;

    let matches = run.journal.root_hash() == replayed.journal.root_hash();
    if cli.json || cli.ndjson {
        println!(
            r#"{{"reproducible":{},"journal_root":"{:02x?}"}}"#,
            matches,
            replayed.journal.root_hash()
        );
    } else {
        println!("Replay status: reproducible = {matches}");
        println!("Journal root: {:02x?}", replayed.journal.root_hash());
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
    let config = RunConfig {
        seed: seed_from_u64(seed),
        policy,
        max_steps,
        ..RunConfig::default()
    };
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
    let c1 = RunConfig {
        seed: seed_from_u64(seed_a),
        max_steps,
        ..RunConfig::default()
    };
    let c2 = RunConfig {
        seed: seed_from_u64(seed_b),
        max_steps,
        ..RunConfig::default()
    };
    let r1 = Simulation::new(c1, workload.programs()).run()?;
    let r2 = Simulation::new(c2, workload.programs()).run()?;

    let diff_pair = ledger_explorer::diff(&r1, &r2);
    if cli.json || cli.ndjson {
        println!(r#"{{"divergence":"{:02x?}"}}"#, diff_pair);
    } else {
        println!("First divergence entry pair: {:02x?}", diff_pair);
    }
    Ok(ExitCode::SUCCESS)
}

fn run_doctor(cli: &Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let cwd = std::env::current_dir()?;
    let root = ledger_cli::checks::find_repo_root(&cwd);
    let report = ledger_cli::checks::run_doctor(&root);
    if cli.json {
        let entries: Vec<String> = report
            .outcomes
            .iter()
            .map(|outcome| {
                let status = if outcome.ok { "ok" } else { "fail" };
                format!(
                    r#"{{"check":"{}","status":"{status}","detail":"{}"}}"#,
                    json_escape(outcome.name),
                    json_escape(&outcome.detail)
                )
            })
            .collect();
        println!(r#"{{"doctor":[{}]}}"#, entries.join(","));
    } else if cli.ndjson {
        for outcome in &report.outcomes {
            let status = if outcome.ok { "ok" } else { "fail" };
            println!(
                r#"{{"check":"{}","status":"{status}","detail":"{}"}}"#,
                json_escape(outcome.name),
                json_escape(&outcome.detail)
            );
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
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let base: PathBuf = match dir {
        Some(path) => PathBuf::from(path),
        None => std::env::current_dir()?,
    };
    let report = scaffold::scaffold(&base, force)?;
    if cli.json || cli.ndjson {
        let files: Vec<String> = report
            .created
            .iter()
            .map(|path| format!(r#""{}""#, json_escape(&path.display().to_string())))
            .collect();
        println!(
            r#"{{"status":"initialized","dir":"{}","files":[{}]}}"#,
            json_escape(&base.display().to_string()),
            files.join(",")
        );
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

fn run_format_check(cli: &Cli, file: &Path) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match check_file(file) {
        Err(error) => {
            eprintln!("ledger: {error}");
            Ok(ExitCode::FAILURE)
        }
        Ok(FormatCheckOutcome::Canonical) => {
            if cli.json || cli.ndjson {
                println!(
                    r#"{{"canonical":true,"file":"{}"}}"#,
                    json_escape(&file.display().to_string())
                );
            } else {
                println!("[ok] {}: canonical", file.display());
            }
            Ok(ExitCode::SUCCESS)
        }
        Ok(FormatCheckOutcome::NonCanonical { reason }) => {
            if cli.json || cli.ndjson {
                println!(
                    r#"{{"canonical":false,"file":"{}","reason":"{}"}}"#,
                    json_escape(&file.display().to_string()),
                    json_escape(&reason)
                );
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
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let Some(report) = ldfi_cmd::run_ldfi(seed, max_steps, attempts)? else {
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
        println!(
            r#"{{"status":"violation","reason":"{}","steps":{},"journal_root":"{:02x?}","attempts":{}}}"#,
            json_escape(&report.reason),
            report.steps,
            report.journal_root,
            report.attempts
        );
        for (index, hypothesis) in report.hypotheses.iter().enumerate() {
            println!(
                r#"{{"hypothesis":{index},"events":{},"cost":{},"explanation":"{}"}}"#,
                hypothesis.events.len(),
                hypothesis.cost,
                json_escape(&hypothesis.explanation)
            );
        }
        println!(
            r#"{{"replay":{{"applied":{},"voided":{},"prefix_ok":{}}},"schedule":[{}]}}"#,
            report.applied,
            report.voided,
            report.prefix_ok,
            report
                .schedule
                .iter()
                .map(|injection| format!(r#""{}""#, describe_injection(injection)))
                .collect::<Vec<String>>()
                .join(",")
        );
    } else {
        println!("Violation detected: {}", report.reason);
        println!("Journal root: {:02x?}", report.journal_root);
        println!("Steps executed: {}", report.steps);
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
    let hypotheses: Vec<String> = report
        .hypotheses
        .iter()
        .map(|hypothesis| {
            format!(
                r#"{{"events":{},"cost":{},"explanation":"{}"}}"#,
                hypothesis.events.len(),
                hypothesis.cost,
                json_escape(&hypothesis.explanation)
            )
        })
        .collect();
    let schedule: Vec<String> = report
        .schedule
        .iter()
        .map(|injection| format!(r#""{}""#, describe_injection(injection)))
        .collect();
    format!(
        r#"{{"status":"violation","reason":"{}","steps":{},"journal_root":"{:02x?}","hypotheses":[{}],"replay":{{"applied":{},"voided":{},"prefix_ok":{}}},"schedule":[{}]}}"#,
        json_escape(&report.reason),
        report.steps,
        report.journal_root,
        hypotheses.join(","),
        report.applied,
        report.voided,
        report.prefix_ok,
        schedule.join(",")
    )
}

fn describe_injection(injection: &FaultInjection) -> String {
    match injection {
        FaultInjection::Drop(id) => format!("drop:{}", hex_prefix(id)),
        FaultInjection::Delay { send, ticks } => format!("delay:{}:{ticks}", hex_prefix(send)),
        FaultInjection::Partition { src, dst } => format!("partition:{src}->{dst}"),
        FaultInjection::Crash(id) => format!("crash:{}", hex_prefix(id)),
        FaultInjection::Corrupt { write, xor_mask } => {
            format!("corrupt:{}:mask={xor_mask}", hex_prefix(write))
        }
        FaultInjection::CrashState { write, state } => {
            format!("crash-state:{}:{state}", hex_prefix(write))
        }
    }
}

/// Renders the first four bytes of a hash as lowercase hex.
fn hex_prefix(hash: &Hash) -> String {
    hash[..4].iter().map(|byte| format!("{byte:02x}")).collect()
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
