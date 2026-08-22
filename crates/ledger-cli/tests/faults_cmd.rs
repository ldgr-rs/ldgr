use std::path::PathBuf;

use ledger_cli::faults_cmd::{apply_scenario, compile_scenario};

fn temp_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ldgr-faults-{name}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir.join(format!("{name}.dsl"))
}

fn write_dsl(name: &str, dsl: &str) -> PathBuf {
    let path = temp_path(name);
    std::fs::write(&path, dsl).unwrap();
    path
}

#[test]
fn compile_human_lists_kind_target_cost() {
    let path = write_dsl(
        "human",
        "scenario demo\ndrop 25% of a->b Msgs for 1s every 5s\npartition a->c\n",
    );
    let out = compile_scenario(&path, false).unwrap();
    assert!(out.contains("scenario 'demo': 2 fault(s)"), "got: {out}");
    assert!(
        out.contains("[0] kind=send target=a->b cost=25"),
        "got: {out}"
    );
    assert!(
        out.contains("[1] kind=send target=a->c cost=1"),
        "got: {out}"
    );
}

#[test]
fn compile_json_array_parses() {
    let path = write_dsl(
        "json",
        "scenario demo\ndrop 40% of a->b Msgs for 1s every 5s\ncrash-restart replica-2 after FsFsync\n",
    );
    let out = compile_scenario(&path, true).unwrap();
    let value: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(value["scenario"], "demo");
    assert_eq!(value["fault_count"], 2);
    assert_eq!(value["faults"][0]["kind"], "send");
    assert_eq!(value["faults"][0]["target"], "a->b");
    assert_eq!(value["faults"][0]["cost"], 40);
    assert_eq!(value["faults"][1]["kind"], "fs-write");
    assert_eq!(value["faults"][1]["target"], "replica-2");
    assert_eq!(value["faults"][1]["cost"], 1);
}

#[test]
fn compile_rejects_storm_with_nonzero_error() {
    let storm = "scenario s\n\
                 partition a->b\npartition a->c\npartition a->d\n\
                 partition b->c\npartition b->d\npartition c->d\n";
    let path = write_dsl("storm", storm);
    let error = compile_scenario(&path, false).unwrap_err();
    assert!(
        error.to_string().contains("storm detected"),
        "expected storm rejection, got: {error}"
    );
}

#[test]
fn apply_roundtrip_root_is_stable_hex() {
    let path = write_dsl(
        "apply",
        "scenario app\npartition replica-0->replica-1\ndrop 10% of replica-0->replica-1 Msgs for 1s every 5s\n",
    );
    let seed_a = "3f2a9b7c11d04e5fa6b8c9d0e1f23456789abcdef0123456789abcdef0123456";
    let seed_b = "4f2a9b7c11d04e5fa6b8c9d0e1f23456789abcdef0123456789abcdef0123456";

    let first = apply_scenario(&path, seed_a, "kv", true).unwrap();
    let second = apply_scenario(&path, seed_a, "kv", true).unwrap();
    assert_eq!(first, second, "same seed must reproduce the same root");

    let value: serde_json::Value = serde_json::from_str(&first).unwrap();
    let root = value["journal_root_hex"].as_str().expect("root hex string");
    assert_eq!(root.len(), 64, "root must be 64 hex chars: {root}");
    assert!(root.chars().all(|c| c.is_ascii_hexdigit()));
    // The bridge targets synthetic sentinel hashes; the count key exists and
    // stays stable even when no journal event matches them.
    assert!(value["applied_faults"].is_u64());

    // A different seed must move the root.
    let third = apply_scenario(&path, seed_b, "kv", true).unwrap();
    let third_value: serde_json::Value = serde_json::from_str(&third).unwrap();
    assert_ne!(
        value["journal_root_hex"], third_value["journal_root_hex"],
        "different seeds must diverge"
    );
}

#[test]
fn apply_rejects_bad_seed_hex_and_unknown_workload() {
    let path = write_dsl("badseed", "scenario app\npartition a->b\n");
    let error = apply_scenario(&path, "nothex", "kv", true).unwrap_err();
    assert!(error.to_string().contains("invalid --seed-hex"));

    let error = apply_scenario(&path, &"a".repeat(64), "redis", true).unwrap_err();
    assert!(error.to_string().contains("unknown workload redis"));
}

#[test]
fn apply_human_branch_is_deterministic_and_not_json() {
    let path = write_dsl("apply-human", "scenario app\npartition a->b\n");
    let seed = "a".repeat(64);
    let first = apply_scenario(&path, &seed, "kv", false).unwrap();
    let second = apply_scenario(&path, &seed, "kv", false).unwrap();
    assert_eq!(first, second, "human branch must be deterministic");
    assert!(
        first.contains("journal root:"),
        "human output must contain journal root: {first}"
    );
    assert!(
        first.contains("applied faults:"),
        "human output must contain applied faults: {first}"
    );
    assert!(
        !first.trim_start().starts_with('{'),
        "human output must not be JSON: {first}"
    );
    // JSON branch for same seed must parse.
    let json_out = apply_scenario(&path, &seed, "kv", true).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json_out).unwrap();
    assert!(value.get("journal_root_hex").is_some());
}
