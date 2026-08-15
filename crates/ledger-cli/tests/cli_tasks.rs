//! Integration tests for the ledger CLI.
//!
//! The tests exercise the library backend in process and the compiled binary
//! for exit-code and NDJSON behavior.

use std::path::{Path, PathBuf};
use std::process::Command;

fn ledger_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ledger")
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ldgr-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn repo_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    ledger_cli::checks::find_repo_root(manifest_dir)
}

#[test]
fn doctor_reports_ok_on_repo() {
    let root = repo_root();
    let report = ledger_cli::checks::run_doctor(&root);
    assert!(
        report.all_ok(),
        "doctor reported failures:\n{}",
        report.render().join("\n")
    );
    let lines = report.render();
    assert!(lines.iter().any(|line| line.starts_with("[ok] toolchain")));
    assert!(lines.iter().any(|line| line.starts_with("[ok] lockfile")));
    assert!(lines.iter().any(|line| line.starts_with("[ok] ci parity")));
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("[ok] format conformance"))
    );
}

#[test]
fn init_scaffolds_files() {
    let dir = temp_dir("init");
    let report = ledger_cli::scaffold::scaffold(&dir, false).unwrap();
    assert!(dir.join("repro.ldgr").is_file());
    assert!(dir.join("src").join("main.rs").is_file());
    assert!(dir.join("README.md").is_file());
    assert!(dir.join("AGENTS.md").is_file());
    assert_eq!(report.created.len(), 4);

    let generated = ledger_cli::format_check::check_file(&dir.join("repro.ldgr")).unwrap();
    assert_eq!(
        generated,
        ledger_cli::format_check::FormatCheckOutcome::Canonical
    );

    let error = ledger_cli::scaffold::scaffold(&dir, false).unwrap_err();
    assert!(matches!(
        error,
        ledger_cli::scaffold::ScaffoldError::RefuseOverwrite(_)
    ));

    std::fs::write(dir.join("repro.ldgr"), b"sentinel").unwrap();
    ledger_cli::scaffold::scaffold(&dir, true).unwrap();
    let bytes = std::fs::read(dir.join("repro.ldgr")).unwrap();
    assert_ne!(bytes.as_slice(), b"sentinel");
}

#[test]
fn completions_generate_bash() {
    let mut out = Vec::new();
    ledger_cli::generate_completions(ledger_cli::Shell::Bash, &mut out);
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("_ledger"),
        "bash completions must define _ledger, got:\n{text}"
    );
}

#[test]
fn format_check_reports_non_canonical() {
    use ledger_cli::format_check::{FormatCheckOutcome, check_bytes};

    let canonical = [0x18, 0x2a];
    assert_eq!(check_bytes(&canonical), FormatCheckOutcome::Canonical);

    let non_minimal = [0x19, 0x00, 0x2a];
    assert!(matches!(
        check_bytes(&non_minimal),
        FormatCheckOutcome::NonCanonical { .. }
    ));

    let indefinite = [0x9f, 0x01, 0x02, 0xff];
    assert!(matches!(
        check_bytes(&indefinite),
        FormatCheckOutcome::NonCanonical { .. }
    ));

    let dir = temp_dir("format");
    let good = dir.join("good.ldgr");
    let bad = dir.join("bad.ldgr");
    std::fs::write(&good, canonical).unwrap();
    std::fs::write(&bad, non_minimal).unwrap();

    let ok = Command::new(ledger_bin())
        .args(["format", "--check"])
        .arg(&good)
        .output()
        .unwrap();
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );

    let fail = Command::new(ledger_bin())
        .args(["format", "--check"])
        .arg(&bad)
        .output()
        .unwrap();
    assert!(
        !fail.status.success(),
        "non-canonical file must exit non-zero"
    );
}

#[test]
fn ndjson_emits_lines() {
    let out = Command::new(ledger_bin())
        .args(["sim", "--ndjson", "--seed", "0", "--runs", "20"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines.len() >= 2, "expected multiple NDJSON lines:\n{text}");
    for line in &lines {
        assert!(line.starts_with('{'), "not a JSON object line: {line}");
    }
}

#[test]
fn json_output_is_one_object() {
    let out = Command::new(ledger_bin())
        .args(["sim", "--json", "--seed", "0", "--runs", "50"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 1, "expected exactly one JSON object:\n{text}");
    let line = lines[0];
    assert!(
        line.starts_with('{') && line.ends_with('}'),
        "not a single JSON object: {line}"
    );
    assert!(
        line.contains("\"status\":\"violation\""),
        "seed 0 must violate the mini-kv spec:\n{line}"
    );
}

#[test]
fn ldfi_executes_top_hypothesis() {
    let report = ledger_cli::ldfi_cmd::run_ldfi(0, 256, 16)
        .unwrap()
        .expect("campaign should find the mini-kv violation");
    assert!(!report.hypotheses.is_empty());
    assert!(!report.schedule.is_empty());
    assert_eq!(
        report.applied + report.voided,
        report.schedule.len(),
        "every scheduled injection is either applied or voided"
    );
    assert!(
        report.applied > 0,
        "the top hypothesis must execute at least one injection (applied {}), \
         guarding the LDFI parent-mapping fix",
        report.applied
    );

    let out = Command::new(ledger_bin())
        .args(["ldfi", "--attempts", "8"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "ldfi CLI failed with {:?}\nstderr: {}\nstdout: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("Replay with faults") && text.contains("prefix_ok"),
        "output must report the applied/voided counts and prefix_ok:\n{text}"
    );
}
