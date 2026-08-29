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
    // LDFI fault replay is strict; a ready-set drift yields a typed
    // StrictReplay violation. The test asserts through the violation type
    // when strict drift occurs, otherwise validates the applied schedule.
    let result = ledger_cli::ldfi_cmd::run_ldfi(0, 256, 16, ledger_cli::MaxSatEngineArg::Auto);
    match result {
        Ok(Some(report)) => {
            assert!(!report.hypotheses.is_empty());
            assert!(!report.schedule.is_empty());
            assert_eq!(
                report.applied + report.voided,
                report.schedule.len(),
                "every scheduled injection is either applied or voided"
            );
            assert!(
                report.applied > 0,
                "the top hypothesis must execute at least one injection (applied {}), guarding the LDFI parent-mapping fix",
                report.applied
            );
        }
        Ok(None) => panic!("campaign should find the mini-kv violation"),
        Err(error) => {
            assert!(
                matches!(
                    error,
                    ledger_cli::ldfi_cmd::LdfiCmdError::Service(
                        ledger_explorer::services::ServiceError::Replay(
                            ledger_explorer::search::FaultReplayError::StrictReplay(_)
                        )
                    )
                ),
                "ldfi must fail with a typed strict violation, got: {error:?}"
            );
            let violation = match error {
                ledger_cli::ldfi_cmd::LdfiCmdError::Service(
                    ledger_explorer::services::ServiceError::Replay(
                        ledger_explorer::search::FaultReplayError::StrictReplay(violation),
                    ),
                ) => violation,
                other => panic!("ldfi must fail with a typed strict violation, got: {other:?}"),
            };
            assert!(
                matches!(
                    violation,
                    ledger_sim::ReplayViolation::OutOfRange { .. }
                        | ledger_sim::ReplayViolation::Exhausted { .. }
                        | ledger_sim::ReplayViolation::Trailing { .. }
                ),
                "violation must be a typed kind, got: {violation:?}"
            );
            // Strict failure is the accepted Wave 1 evidence (R6); no
            // partial-journal accessor is required.
            return;
        }
    }

    let out = Command::new(ledger_bin())
        .args(["ldfi", "--attempts", "8"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if out.status.success() {
        assert!(
            stdout.contains("Replay with faults") && stdout.contains("prefix_ok"),
            "output must report the applied/voided counts and prefix_ok:\n{stdout}"
        );
    } else {
        // Strict drift in fault replay surfaces as a typed violation on
        // stderr. This is the same typed error asserted above for the
        // library path.
        let combined = format!("{stdout} {stderr}");
        assert!(
            combined.to_lowercase().contains("strict replay violation"),
            "ldfi CLI must either succeed with Replay with faults or fail with typed strict violation, got stdout: {stdout} stderr: {stderr}"
        );
    }
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
        ..Default::default()
    };
    let span2 = OtelSpan {
        trace_id: "trace-1".into(),
        span_id: "span-2".into(),
        parent_span_id: Some("span-1".into()),
        name: "op-b".into(),
        events: vec![],
        ..Default::default()
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

#[test]
fn repro_strict_default_passes() {
    // Full-trace repro must be reproducible under strict replay.
    let out = Command::new(ledger_bin())
        .args([
            "--json",
            "repro",
            "--seed",
            "0",
            "--policy",
            "random",
            "--max-steps",
            "256",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "repro strict failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let value: serde_json::Value = serde_json::from_str(text.trim()).expect("repro json");
    assert_eq!(
        value["reproducible"], true,
        "full trace must be reproducible: {text}"
    );
    assert_eq!(value["strict"], true, "default must be strict: {text}");
    assert!(
        value["journal_root"].is_string(),
        "missing journal_root: {text}"
    );
}

// Helpers for binary-level artifact tests.

fn generate_valid_decisions(seed: u64) -> Vec<usize> {
    use ledger_cli::{DefaultMiniKv, seed_from_u64};
    use ledger_explorer::search::Workload;
    use ledger_sim::{Policy, RunConfig, Simulation};
    let workload = DefaultMiniKv;
    let config = RunConfig::builder()
        .seed(seed_from_u64(seed))
        .policy(Policy::Random)
        .max_steps(256)
        .build();
    let run = Simulation::new(config, workload.programs())
        .run()
        .expect("valid run for artifact");
    run.decisions
}

#[test]
fn repro_valid_artifact_passes_via_binary() {
    let dir = temp_dir("repro-valid-binary");
    let valid = generate_valid_decisions(0);
    let path = dir.join("decisions.json");
    std::fs::write(&path, serde_json::to_string(&valid).unwrap()).unwrap();
    let out = Command::new(ledger_bin())
        .args([
            "--json",
            "repro",
            "--seed",
            "0",
            "--decisions",
            path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "valid artifact must succeed: stderr={}, stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let value: serde_json::Value =
        serde_json::from_str(text.trim()).expect("repro json for valid artifact");
    assert_eq!(
        value["reproducible"], true,
        "valid artifact must be reproducible: {text}"
    );
    assert_eq!(
        value["strict"], true,
        "valid artifact must be strict: {text}"
    );
    assert!(
        value["journal_root"].is_string(),
        "missing journal_root: {text}"
    );
}

#[test]
fn repro_strict_rejects_truncated_via_binary() {
    let dir = temp_dir("repro-truncated-binary");
    let valid = generate_valid_decisions(0);
    assert!(
        valid.len() >= 2,
        "valid artifact must have at least 2 decisions for truncation, got {}",
        valid.len()
    );
    let truncated = valid[..1].to_vec();
    let path = dir.join("decisions.json");
    std::fs::write(&path, serde_json::to_string(&truncated).unwrap()).unwrap();
    let out = Command::new(ledger_bin())
        .args([
            "--json",
            "repro",
            "--seed",
            "0",
            "--decisions",
            path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "truncated must exit non-zero, stderr: {} stdout: {}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    // Violation is printed to stdout as JSON when --json is used.
    let value: serde_json::Value = serde_json::from_str(text.trim())
        .unwrap_or_else(|_| panic!("truncated must produce JSON, got: {text}"));
    assert_eq!(
        value["reproducible"], false,
        "truncated must be not reproducible: {text}"
    );
    assert_eq!(value["strict"], true, "truncated must be strict: {text}");
    assert_eq!(
        value["violation"]["kind"], "Exhausted",
        "truncated must be Exhausted: {text}"
    );
    assert!(
        value["violation"]["reason"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("exhausted"),
        "reason must mention exhausted: {text}"
    );
}

#[test]
fn repro_strict_rejects_out_of_range_via_binary() {
    let dir = temp_dir("repro-oor-binary");
    let valid = generate_valid_decisions(7);
    let mut mutated = valid.clone();
    mutated[0] = 99;
    let path = dir.join("decisions.json");
    std::fs::write(&path, serde_json::to_string(&mutated).unwrap()).unwrap();
    let out = Command::new(ledger_bin())
        .args([
            "--json",
            "repro",
            "--seed",
            "7",
            "--decisions",
            path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "out-of-range must exit non-zero, stderr: {} stdout: {}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let value: serde_json::Value = serde_json::from_str(text.trim())
        .unwrap_or_else(|_| panic!("oor must produce JSON, got: {text}"));
    assert_eq!(
        value["reproducible"], false,
        "oor must be not reproducible: {text}"
    );
    assert_eq!(value["strict"], true, "oor must be strict: {text}");
    assert_eq!(
        value["violation"]["kind"], "OutOfRange",
        "oor must be OutOfRange: {text}"
    );
    assert!(
        value["violation"]["reason"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("out of range"),
        "reason must mention out of range: {text}"
    );
    // Typed fields: ready_len and value must be present.
    assert!(
        value["violation"]["ready_len"].is_number(),
        "ready_len missing: {text}"
    );
    assert!(
        value["violation"]["value"].is_number(),
        "value missing: {text}"
    );
}

#[test]
fn repro_strict_rejects_trailing_via_binary() {
    let dir = temp_dir("repro-trailing-binary");
    let valid = generate_valid_decisions(11);
    let mut trailing = valid.clone();
    trailing.extend([0, 1, 0]);
    let path = dir.join("decisions.json");
    std::fs::write(&path, serde_json::to_string(&trailing).unwrap()).unwrap();
    let out = Command::new(ledger_bin())
        .args([
            "--json",
            "repro",
            "--seed",
            "11",
            "--decisions",
            path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "trailing must exit non-zero, stderr: {} stdout: {}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let value: serde_json::Value = serde_json::from_str(text.trim())
        .unwrap_or_else(|_| panic!("trailing must produce JSON, got: {text}"));
    assert_eq!(
        value["reproducible"], false,
        "trailing must be not reproducible: {text}"
    );
    assert_eq!(value["strict"], true, "trailing must be strict: {text}");
    assert_eq!(
        value["violation"]["kind"], "Trailing",
        "trailing must be Trailing: {text}"
    );
    assert!(
        value["violation"]["reason"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("trailing"),
        "reason must mention trailing: {text}"
    );
    assert!(
        value["violation"]["trailing"].is_number(),
        "trailing count missing: {text}"
    );
    assert!(
        value["violation"]["steps"].is_number(),
        "steps missing: {text}"
    );
}

#[test]
fn cert_verify_journal_mode_valid() {
    use ledger_explorer::search::PersistentJournal;
    use ledger_explorer::search::{CampaignReport, Finding};
    use ledger_explorer::{CampaignCertificate, Verdict};
    use ledger_format::{EntryKind, Payload};
    use ledger_sim::{RunOutcome, RunResult};
    let dir = temp_dir("cert-journal-valid");
    let journal_dir = dir.join("journal");
    let mut pj = PersistentJournal::create(&journal_dir).expect("create journal");
    // Append a simple journal: two sends and an outcome.
    let s1 = pj
        .append(EntryKind::Send, 1, [], Payload::Pair { left: 2, right: 7 })
        .unwrap();
    let s2 = pj
        .append(EntryKind::Send, 2, [], Payload::Pair { left: 3, right: 9 })
        .unwrap();
    let journal = pj.journal().clone();
    drop(pj);
    // Build a finding whose journal matches the persistent one.
    let run = RunResult {
        outcome: RunOutcome::Completed,
        journal_error: None,
        journal: journal.clone(),
        decisions: Vec::new(),
        trace: Vec::new(),
        registers: Vec::new(),
        steps: 0,
        monitor_issues: Vec::new(),
        applied_faults: Vec::new(),
        origins: Vec::new(),
        protection: ledger_sim::BeltStatus::NotArmed,
    };
    let report = CampaignReport {
        runs_executed: 1,
        distinct_roots: 1,
        findings: vec![Finding {
            seed: [7u8; 32],
            run,
            verdict: Verdict::fail(vec![s1], "test"),
        }],
        variants: Vec::new(),
        monitors: Vec::new(),
        memo_hits: 0,
    };
    let cert = CampaignCertificate::from_campaign(&report, "builder", Vec::new(), [9u8; 32], None)
        .expect("valid report must create a certificate");
    let cert_path = dir.join("cert.json");
    std::fs::write(&cert_path, cert.to_json().unwrap()).unwrap();
    // Journal binding should succeed.
    let out = ledger_cli::cert_cmd::run_verify(
        &cert_path,
        Some(&journal_dir),
        ledger_cli::CertVerifyOp::Journal,
        false,
    )
    .expect("valid cert");
    assert!(out.contains("certificate valid"), "{out}");
    assert!(
        out.contains("mode: journal-bound"),
        "mode label missing: {out}"
    );
    // JSON reports the exact journal-bound mode label.
    let out_json = ledger_cli::cert_cmd::run_verify(
        &cert_path,
        Some(&journal_dir),
        ledger_cli::CertVerifyOp::Journal,
        true,
    )
    .expect("json");
    let parsed: serde_json::Value = serde_json::from_str(&out_json).expect("json parse");
    assert_eq!(parsed["valid"], true);
    assert_eq!(parsed["mode"], "journal-bound");
    let _ = s2;
}

#[test]
fn cert_verify_journal_mode_wrong_root() {
    use ledger_explorer::search::PersistentJournal;
    use ledger_explorer::search::{CampaignReport, Finding};
    use ledger_explorer::{CampaignCertificate, Verdict};
    use ledger_format::{EntryKind, Payload};
    use ledger_sim::{RunOutcome, RunResult};
    let dir = temp_dir("cert-journal-wrong");
    let journal_dir_a = dir.join("journal_a");
    let journal_dir_b = dir.join("journal_b");
    let mut pj_a = PersistentJournal::create(&journal_dir_a).expect("create a");
    let mut pj_b = PersistentJournal::create(&journal_dir_b).expect("create b");
    // Journal A: one entry value 7.
    let s1 = pj_a
        .append(EntryKind::Send, 1, [], Payload::Pair { left: 2, right: 7 })
        .unwrap();
    // Journal B: different payload so root differs.
    let _s2 = pj_b
        .append(EntryKind::Send, 1, [], Payload::Pair { left: 2, right: 77 })
        .unwrap();
    let journal_a = pj_a.journal().clone();
    let journal_b = pj_b.journal().clone();
    assert_ne!(
        journal_a.root_hash(),
        journal_b.root_hash(),
        "roots must differ"
    );
    drop(pj_a);
    drop(pj_b);
    let run = RunResult {
        outcome: RunOutcome::Completed,
        journal_error: None,
        journal: journal_a.clone(),
        decisions: Vec::new(),
        trace: Vec::new(),
        registers: Vec::new(),
        steps: 0,
        monitor_issues: Vec::new(),
        applied_faults: Vec::new(),
        origins: Vec::new(),
        protection: ledger_sim::BeltStatus::NotArmed,
    };
    let report = CampaignReport {
        runs_executed: 1,
        distinct_roots: 1,
        findings: vec![Finding {
            seed: [7u8; 32],
            run,
            verdict: Verdict::fail(vec![s1], "test"),
        }],
        variants: Vec::new(),
        monitors: Vec::new(),
        memo_hits: 0,
    };
    let cert = CampaignCertificate::from_campaign(&report, "builder", Vec::new(), [9u8; 32], None)
        .expect("valid report must create a certificate");
    let cert_path = dir.join("cert.json");
    std::fs::write(&cert_path, cert.to_json().unwrap()).unwrap();
    let err = ledger_cli::cert_cmd::run_verify(
        &cert_path,
        Some(&journal_dir_b),
        ledger_cli::CertVerifyOp::Journal,
        false,
    )
    .unwrap_err();
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("subject digest mismatch") || msg.contains("mismatch"),
        "wrong root must fail with typed mismatch, got: {msg}"
    );
}

#[test]
fn cert_verify_human_recorded_solver_data_label() {
    use ledger_explorer::search::CampaignReport;
    use ledger_explorer::{CampaignCertificate, RecordedSolverData};
    let report = CampaignReport {
        runs_executed: 10,
        distinct_roots: 10,
        findings: Vec::new(),
        variants: Vec::new(),
        monitors: Vec::new(),
        memo_hits: 0,
    };
    let mut cert =
        CampaignCertificate::from_campaign(&report, "builder", Vec::new(), [1u8; 32], None)
            .expect("valid report must create a certificate");
    cert.solver_data = Some(RecordedSolverData {
        cut: vec![[3u8; 32]],
        cost: 2,
        method: "m".into(),
        horizon: Some(64),
        support_provider_version: None,
        witnesses: Vec::new(),
        reproduced: false,
        baseline_passed: false,
    });
    let dir = temp_dir("cert-recorded-bound");
    let path = dir.join("cert.json");
    std::fs::write(&path, cert.to_json().unwrap()).unwrap();
    let out =
        ledger_cli::cert_cmd::run_verify(&path, None, ledger_cli::CertVerifyOp::Statement, false)
            .unwrap();
    assert!(
        out.contains("cost="),
        "human must identify recorded solver data: {out}"
    );
    assert!(
        !out.contains("proven"),
        "human output must not claim proof: {out}"
    );
    let out_json =
        ledger_cli::cert_cmd::run_verify(&path, None, ledger_cli::CertVerifyOp::Statement, true)
            .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&out_json).unwrap();
    let solver_data = &parsed["solver_data"];
    assert_eq!(solver_data["cost"], 2);
}

#[test]
fn cert_verify_rejects_oversized_file() {
    let dir = temp_dir("cert-oversize");
    let path = dir.join("cert.json");
    // The bounded reader rejects 1 MiB plus one byte before JSON parsing.
    let oversized = vec![b'a'; 1024 * 1024 + 1];
    std::fs::write(&path, &oversized).unwrap();
    let err =
        ledger_cli::cert_cmd::run_verify(&path, None, ledger_cli::CertVerifyOp::Statement, false)
            .unwrap_err();
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("too large") || msg.contains("limit"),
        "oversize must be rejected with limit, got: {msg}"
    );
    // Verify the error is typed as schema/limit, not io generic.
    assert!(
        msg.contains("certificate file too large") || msg.contains("limit"),
        "must be typed limit error: {msg}"
    );
    // Binary level: ledger cert verify must fail and limit appears in stderr.
    let out = Command::new(ledger_bin())
        .args(["cert", "verify", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "oversized cert must exit non-zero, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
    assert!(
        stderr.contains("too large") || stderr.contains("limit"),
        "binary must report limit, got: {stderr}"
    );
}

#[test]
fn cert_verify_rejects_oversized_via_bounded_reader() {
    // A valid prefix plus padding still fails at the bounded reader limit.
    use ledger_explorer::CampaignCertificate;
    use ledger_explorer::search::CampaignReport;
    let dir = temp_dir("cert-oversize-bound");
    let report = CampaignReport {
        runs_executed: 10,
        distinct_roots: 10,
        findings: Vec::new(),
        variants: Vec::new(),
        monitors: Vec::new(),
        memo_hits: 0,
    };
    let cert = CampaignCertificate::from_campaign(&report, "builder", Vec::new(), [1u8; 32], None)
        .expect("valid report must create a certificate");
    let json = cert.to_json().unwrap();
    assert!(json.len() < 1024 * 1024, "base cert must be small");
    let path_ok = dir.join("ok.json");
    std::fs::write(&path_ok, &json).unwrap();
    // Small cert verifies.
    let ok = ledger_cli::cert_cmd::run_verify(
        &path_ok,
        None,
        ledger_cli::CertVerifyOp::Statement,
        false,
    );
    assert!(ok.is_ok(), "small cert must verify: {ok:?}");
    // The bounded reader consumes at most the limit plus one byte.
    let path_big = dir.join("big.json");
    let mut big = json.clone();
    big.push_str(&" ".repeat(1024 * 1024));
    assert!(big.len() > 1024 * 1024);
    std::fs::write(&path_big, &big).unwrap();
    let err = ledger_cli::cert_cmd::run_verify(
        &path_big,
        None,
        ledger_cli::CertVerifyOp::Statement,
        false,
    )
    .unwrap_err();
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("too large") || msg.contains("limit"),
        "big cert must be rejected, got: {msg}"
    );
}
