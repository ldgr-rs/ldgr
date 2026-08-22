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
fn init_sut_scaffolds_files() {
    let dir = temp_dir("sut-lib");
    ledger_cli::scaffold::write_sut_scaffold(&dir, false).unwrap();
    assert!(dir.join("Cargo.toml").is_file());
    assert!(dir.join("src").join("main.rs").is_file());
    assert!(dir.join("tests").join("surface.rs").is_file());
    assert!(dir.join("README.md").is_file());

    let cargo = std::fs::read_to_string(dir.join("Cargo.toml")).unwrap();
    assert!(
        cargo.contains("ldgr-rt"),
        "Cargo.toml must contain ldgr-rt marker"
    );
    assert!(
        cargo.contains("ldgr-rt/sim"),
        "Cargo.toml must mirror sim feature"
    );

    let surface = std::fs::read_to_string(dir.join("tests").join("surface.rs")).unwrap();
    assert!(
        surface.contains("probe()"),
        "surface.rs must contain probe() marker"
    );

    let readme = std::fs::read_to_string(dir.join("README.md")).unwrap();
    assert!(
        readme.contains("--features sim"),
        "README.md must contain --features sim"
    );
    assert!(
        readme.contains("LEDGER_SENTINEL_BELT"),
        "README.md must mention LEDGER_SENTINEL_BELT"
    );

    let main_rs = std::fs::read_to_string(dir.join("src").join("main.rs")).unwrap();
    assert!(main_rs.contains("Handle"), "main.rs must use Handle");
    assert!(main_rs.contains("clock"), "main.rs must read clock");
    assert!(main_rs.contains("rng"), "main.rs must draw rng");
    assert!(main_rs.contains("net_send"), "main.rs must use net_send");
    assert!(main_rs.contains("spawn"), "main.rs must spawn child");

    // Refuses without force on second call.
    let error = ledger_cli::scaffold::write_sut_scaffold(&dir, false).unwrap_err();
    assert!(
        matches!(
            error,
            ledger_cli::scaffold::ScaffoldError::RefuseOverwrite(_)
        ),
        "second sut init without force must refuse"
    );

    // Force overwrites.
    std::fs::write(dir.join("Cargo.toml"), b"sentinel").unwrap();
    ledger_cli::scaffold::write_sut_scaffold(&dir, true).unwrap();
    let bytes = std::fs::read(dir.join("Cargo.toml")).unwrap();
    assert_ne!(bytes.as_slice(), b"sentinel");

    // Generic init unchanged still works in separate dir.
    let generic = temp_dir("sut-generic-check");
    let report = ledger_cli::scaffold::scaffold(&generic, false).unwrap();
    assert!(generic.join("repro.ldgr").is_file());
    assert_eq!(report.created.len(), 4);
}

#[test]
fn init_sut_via_cli() {
    let dir = temp_dir("sut-cli");
    let out = Command::new(ledger_bin())
        .args(["init", "--sut", dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "cli sut init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dir.join("Cargo.toml").is_file());
    let cargo = std::fs::read_to_string(dir.join("Cargo.toml")).unwrap();
    assert!(cargo.contains("ldgr-rt"));
    let readme = std::fs::read_to_string(dir.join("README.md")).unwrap();
    assert!(readme.contains("--features sim"));
    let surface = std::fs::read_to_string(dir.join("tests").join("surface.rs")).unwrap();
    assert!(surface.contains("probe()"));

    // Second without force must fail.
    let out2 = Command::new(ledger_bin())
        .args(["init", "--sut", dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !out2.status.success(),
        "second sut init without force must fail"
    );

    // With force succeeds.
    let out3 = Command::new(ledger_bin())
        .args(["init", "--sut", "--force", dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out3.status.success(),
        "sut init --force must succeed: {}",
        String::from_utf8_lossy(&out3.stderr)
    );

    // Generic unchanged via CLI.
    let generic = temp_dir("sut-cli-generic");
    let out4 = Command::new(ledger_bin())
        .args(["init", generic.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out4.status.success(),
        "generic init via cli must still work: {}",
        String::from_utf8_lossy(&out4.stderr)
    );
    assert!(generic.join("repro.ldgr").is_file());
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
    let report = ledger_cli::ldfi_cmd::run_ldfi(0, 256, 16, ledger_cli::MaxSatEngineArg::Auto)
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

#[test]
fn ingest_otlp_ndjson_outputs_journal_root() {
    use ledger_adapters::{OtelEvent, OtelSpan};
    let dir = temp_dir("ingest");
    let path = dir.join("spans.ndjson");
    let span1 = OtelSpan {
        trace_id: "trace-1".into(),
        span_id: "span-1".into(),
        parent_span_id: None,
        name: "op-a".into(),
        events: vec![OtelEvent { name: "ev1".into() }],
    };
    let span2 = OtelSpan {
        trace_id: "trace-1".into(),
        span_id: "span-2".into(),
        parent_span_id: Some("span-1".into()),
        name: "op-b".into(),
        events: vec![],
    };
    let mut ndjson = String::new();
    ndjson.push_str(&serde_json::to_string(&span1).unwrap());
    ndjson.push('\n');
    ndjson.push_str(&serde_json::to_string(&span2).unwrap());
    ndjson.push('\n');
    // blank line must be skipped
    ndjson.push('\n');
    std::fs::write(&path, ndjson).unwrap();

    // library path: dedup + parent causality + fidelity
    let cfg = ledger_adapters::OtelIngestConfig::new(
        ledger_adapters::Fidelity::LineageOnly,
        true,
        100_000,
    );
    let ing = ledger_adapters::otel::ingest_otel_file_with_config(&path, cfg).unwrap();
    assert!(
        !ing.journal.is_empty(),
        "journal must be non-empty after ingest"
    );
    let root_hex: String = ing
        .journal
        .root_hash()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let envelope_hex: String = ing
        .envelope_hash()
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    // CLI --json path
    let out = Command::new(ledger_bin())
        .args([
            "--json",
            "ingest",
            "--input",
            path.to_str().unwrap(),
            "--fidelity",
            "lineage-only",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "ingest --json failed: stderr={} stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.lines().next().unwrap();
    assert!(
        line.contains("\"journal_root\""),
        "missing journal_root: {line}"
    );
    assert!(line.contains(&root_hex), "root mismatch: {line}");
    assert!(
        line.contains("\"envelope_hash\""),
        "missing envelope_hash: {line}"
    );
    assert!(
        line.contains(&envelope_hex),
        "envelope hash mismatch: {line}"
    );
    assert!(line.contains("\"fidelity\":\"lineage-only\""), "{line}");
    assert!(line.contains("\"certifiable\":false"), "{line}");
    assert!(line.contains("\"entries\""), "{line}");
    let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
    assert!(parsed.get("journal_root").is_some());
    assert!(parsed.get("envelope_hash").is_some());

    // CLI human path
    let out2 = Command::new(ledger_bin())
        .args(["ingest", "--input", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out2.status.success(),
        "ingest human failed: {}",
        String::from_utf8_lossy(&out2.stderr)
    );
    let text2 = String::from_utf8_lossy(&out2.stdout);
    assert!(
        text2.contains("Journal root:"),
        "human output missing Journal root: {text2}"
    );
    assert!(text2.contains(&root_hex), "human root mismatch: {text2}");
}

#[test]
fn scaffold_consensus_creates_mini_raft_files() {
    let dir = temp_dir("scaffold-consensus-lib");
    let report =
        ledger_cli::scaffold_consensus::scaffold_consensus(&dir, "consensus", false).unwrap();
    assert!(dir.join("Cargo.toml").is_file());
    assert!(dir.join("src").join("main.rs").is_file());
    let cargo = std::fs::read_to_string(dir.join("Cargo.toml")).unwrap();
    assert!(
        cargo.contains("ledger-explorer"),
        "Cargo.toml must contain ledger-explorer"
    );
    let main_rs = std::fs::read_to_string(dir.join("src").join("main.rs")).unwrap();
    assert!(
        main_rs.contains("mini_raft"),
        "consensus template must contain mini_raft"
    );
    assert_eq!(report.created.len(), 2);
    let err =
        ledger_cli::scaffold_consensus::scaffold_consensus(&dir, "consensus", false).unwrap_err();
    assert!(
        matches!(err, ledger_cli::scaffold::ScaffoldError::RefuseOverwrite(_)),
        "second scaffold without force must refuse"
    );
    std::fs::write(dir.join("Cargo.toml"), b"sentinel").unwrap();
    ledger_cli::scaffold_consensus::scaffold_consensus(&dir, "consensus", true).unwrap();
    let bytes = std::fs::read(dir.join("Cargo.toml")).unwrap();
    assert_ne!(bytes.as_slice(), b"sentinel");

    let dir2 = temp_dir("scaffold-consensus-cli");
    let out = Command::new(ledger_bin())
        .args([
            "scaffold",
            "--template",
            "consensus",
            dir2.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "scaffold cli failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let main2 = std::fs::read_to_string(dir2.join("src").join("main.rs")).unwrap();
    assert!(main2.contains("mini_raft"));
    let out2 = Command::new(ledger_bin())
        .args([
            "scaffold",
            "--template",
            "consensus",
            dir2.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !out2.status.success(),
        "second scaffold without force must fail"
    );
    let out3 = Command::new(ledger_bin())
        .args([
            "scaffold",
            "--template",
            "consensus",
            "--force",
            dir2.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out3.status.success(),
        "scaffold --force must succeed: {}",
        String::from_utf8_lossy(&out3.stderr)
    );

    let dir3 = temp_dir("scaffold-kv");
    ledger_cli::scaffold_consensus::scaffold_consensus(&dir3, "kv", false).unwrap();
    let kv_main = std::fs::read_to_string(dir3.join("src").join("main.rs")).unwrap();
    assert!(
        kv_main.contains("MiniKvWorkload"),
        "kv template must contain MiniKvWorkload"
    );

    let dir4 = temp_dir("scaffold-2pc");
    ledger_cli::scaffold_consensus::scaffold_consensus(&dir4, "2pc", false).unwrap();
    let pc_main = std::fs::read_to_string(dir4.join("src").join("main.rs")).unwrap();
    assert!(
        pc_main.contains("TwoPhaseCommitWorkload"),
        "2pc template must contain TwoPhaseCommitWorkload"
    );
}
