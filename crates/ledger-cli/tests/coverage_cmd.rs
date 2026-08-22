use std::path::PathBuf;

fn temp_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ldgr-coverage-{name}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir.join(format!("{name}.ndjson"))
}

fn root_hex(byte: u8) -> String {
    [byte; 32].iter().map(|b| format!("{b:02x}")).collect()
}

fn write_ndjson(path: &PathBuf, lines: &[String]) {
    let content = lines.join("\n");
    std::fs::write(path, content).unwrap();
}

#[test]
fn coverage_lcov_output_has_da_and_end() {
    let path = temp_path("lcov");
    let lines = vec![
        serde_json::json!({"root_hex": root_hex(1), "run_index": 0, "finding": true}).to_string(),
        serde_json::json!({"root_hex": root_hex(2), "run_index": 1, "finding": false}).to_string(),
    ];
    write_ndjson(&path, &lines);
    let output = ledger_cli::coverage_cmd::run(&path, "lcov").unwrap();
    assert!(
        output.contains("SF:ledger-campaign"),
        "missing SF: {output}"
    );
    assert!(output.contains("DA:1,1"), "missing DA 1: {output}");
    assert!(output.contains("DA:2,0"), "missing DA 2: {output}");
    assert!(
        output.contains("end_of_record"),
        "missing end_of_record: {output}"
    );
    assert!(output.contains("LF:2"), "missing LF: {output}");
    assert!(output.contains("LH:1"), "missing LH: {output}");
}

#[test]
fn coverage_sarif_parses_as_json() {
    let path = temp_path("sarif");
    let lines = vec![
        serde_json::json!({"root_hex": root_hex(3), "run_index": 0, "finding": true}).to_string(),
        serde_json::json!({"root_hex": root_hex(4), "run_index": 1, "finding": false}).to_string(),
    ];
    write_ndjson(&path, &lines);
    let output = ledger_cli::coverage_cmd::run(&path, "sarif").unwrap();
    let value: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(value["version"], "2.1.0");
    let results = value["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert!(results.iter().any(|result| result["level"] == "error"));
    assert!(results.iter().any(|result| result["level"] == "note"));
}

#[test]
fn coverage_jacoco_has_counter() {
    let path = temp_path("jacoco");
    let lines = vec![
        serde_json::json!({"root_hex": root_hex(5), "run_index": 0, "finding": true}).to_string(),
        serde_json::json!({"root_hex": root_hex(6), "run_index": 1, "finding": false}).to_string(),
        serde_json::json!({"root_hex": root_hex(7), "run_index": 2, "finding": false}).to_string(),
    ];
    write_ndjson(&path, &lines);
    let output = ledger_cli::coverage_cmd::run(&path, "jacoco").unwrap();
    assert!(output.contains("<counter"), "missing counter: {output}");
    assert!(output.contains("type=\"LINE\""), "missing LINE: {output}");
    assert!(
        output.contains("missed=\"2\""),
        "missed should be 2: {output}"
    );
    assert!(
        output.contains("covered=\"1\""),
        "covered should be 1: {output}"
    );
}

#[test]
fn coverage_ndjson_comments_and_empty_skipped() {
    let path = temp_path("comments");
    // Header comment, blank line, then two records with different order
    let content = format!(
        "# ledger coverage ndjson v1\n\n{}\n# comment\n{}\n",
        serde_json::json!({"root_hex": root_hex(10), "run_index": 1, "finding": false}),
        serde_json::json!({"root_hex": root_hex(9), "run_index": 0, "finding": true})
    );
    std::fs::write(&path, content).unwrap();
    let lcov_first = ledger_cli::coverage_cmd::run(&path, "lcov").unwrap();
    let lcov_second = ledger_cli::coverage_cmd::run(&path, "lcov").unwrap();
    assert_eq!(lcov_first, lcov_second, "output must be deterministic");
    assert!(lcov_first.contains("DA:1,1"));
    assert!(lcov_first.contains("DA:2,0"));
}

#[test]
fn coverage_unknown_format_error() {
    let path = temp_path("unknown");
    write_ndjson(&path, &[]);
    let error = ledger_cli::coverage_cmd::run(&path, "cobertura").unwrap_err();
    assert!(
        error.to_string().to_lowercase().contains("unknown format"),
        "got: {error}"
    );
}
