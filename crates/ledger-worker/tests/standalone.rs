use std::time::Duration;

use ledger_sim::RunConfig;
use ledger_worker::{InMemoryQueue, Task, WorkerConfig, run_drain_once};

fn hex_is_lower_hex(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

#[test]
fn drain_once_with_task_produces_json() {
    let config = WorkerConfig {
        lease_timeout: Duration::from_secs(30),
        max_concurrent: 1,
        ..WorkerConfig::default()
    };
    let mut q = InMemoryQueue::new(config.lease_timeout);
    let run_config = RunConfig::builder()
        .seed(ledger_format::EntryHash([3u8; 32]))
        .build();
    q.push(Task::new("task-1", run_config, "kv"));
    let line = run_drain_once(config, Box::new(q)).expect("should produce a JSON line");
    let v: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
    assert_eq!(v["task_id"], "task-1");
    let jr = v["journal_root"].as_str().expect("journal_root str");
    assert!(
        hex_is_lower_hex(jr),
        "journal_root must be 64 hex chars, got {jr}"
    );
    // Verify it decodes and is lowercase hex.
    let decoded = ledger_worker::hex_to_hash(jr).expect("hex decode");
    assert_eq!(decoded.0.len(), 32);
    assert_eq!(jr, jr.to_ascii_lowercase());
    let steps = v["steps"].as_u64().expect("steps u64");
    assert!(steps > 0, "steps must be >0, got {steps}");
}

#[test]
fn drain_once_empty_returns_none() {
    let config = WorkerConfig::default();
    let q = InMemoryQueue::new(Duration::from_secs(30));
    let result = run_drain_once(config, Box::new(q));
    assert!(
        result.is_none(),
        "empty queue must produce no result line, got {result:?}"
    );
}

#[test]
fn drain_once_default_config_empty_returns_none() {
    let config = WorkerConfig::default();
    let q = InMemoryQueue::new(config.lease_timeout);
    let result = run_drain_once(config, Box::new(q));
    assert!(result.is_none());
}

#[test]
fn drain_once_journal_root_is_deterministic() {
    let config_a = WorkerConfig {
        lease_timeout: Duration::from_secs(30),
        ..WorkerConfig::default()
    };
    let config_b = config_a.clone();
    let run_config = RunConfig::builder()
        .seed(ledger_format::EntryHash([7u8; 32]))
        .build();
    let mut qa = InMemoryQueue::new(Duration::from_secs(30));
    qa.push(Task::new("det", run_config.clone(), "kv"));
    let mut qb = InMemoryQueue::new(Duration::from_secs(30));
    qb.push(Task::new("det", run_config, "kv"));
    let la = run_drain_once(config_a, Box::new(qa)).unwrap();
    let lb = run_drain_once(config_b, Box::new(qb)).unwrap();
    let va: serde_json::Value = serde_json::from_str(&la).unwrap();
    let vb: serde_json::Value = serde_json::from_str(&lb).unwrap();
    assert_eq!(va["journal_root"], vb["journal_root"]);
    assert_eq!(va["steps"], vb["steps"]);
}
