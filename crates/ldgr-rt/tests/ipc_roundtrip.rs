// ledger-lint:allow (host integration test resolves the engine binary from env / build dir; not simulation code)
#![cfg(any(feature = "sim", feature = "sim-link"))]

use std::path::PathBuf;

use ldgr_rt::EngineProcess;
use ledger_format::{ActorId, EntryHash};

/// Probe the engine binary: `LEDGER_ENGINE_BIN`, else the sibling `ledger`
/// build artifact. No CWD/PATH fallback. Missing explicit binary panics.
fn probe_engine_path() -> Option<PathBuf> {
    match std::env::var("LEDGER_ENGINE_BIN") {
        Ok(env) if !env.trim().is_empty() => {
            let path = PathBuf::from(&env);
            if path.exists() {
                return Some(path);
            }
            panic!(
                "LEDGER_ENGINE_BIN is set to {env} but the binary does not exist; \
             build ledger-cli or clear LEDGER_ENGINE_BIN"
            );
        }
        _ => {}
    }
    let mut dir = std::env::current_exe().ok()?;
    // Pop the test binary name, then walk up past `deps` to the profile dir.
    dir.pop();
    if dir.file_name().and_then(|n| n.to_str()) == Some("deps") {
        dir.pop();
    }
    let sibling = dir.join("ledger");
    sibling.exists().then_some(sibling)
}

/// Shared roundtrip determinism body (kv workload, root stability).
async fn run_determinism_checks(engine: PathBuf) {
    eprintln!("using engine {}", engine.display());
    let mut proc = EngineProcess::spawn(Some(engine))
        .await
        .expect("spawn engine");
    let seed = EntryHash([42u8; 32]);
    let outcome1 = proc
        .run_workload("kv", seed, 1, ActorId(0))
        .expect("first run must succeed");
    assert_eq!(
        outcome1.roots.len(),
        1,
        "single attempt must yield one root"
    );
    let hex1 = ledger_format::hash_to_hex(&outcome1.roots[0]);
    assert_eq!(hex1.len(), 64, "root must be 64 hex chars: {hex1}");
    // Determinism: second call with same seed must yield same root.
    let outcome2 = proc
        .run_workload("kv", seed, 1, ActorId(0))
        .expect("second run must succeed");
    assert_eq!(
        outcome1.roots, outcome2.roots,
        "same seed must yield same root"
    );

    // Different seed still deterministic across two calls.
    let other_seed = EntryHash([43u8; 32]);
    let outcome3 = proc
        .run_workload("kv", other_seed, 1, ActorId(0))
        .expect("third run must succeed");
    let outcome4 = proc
        .run_workload("kv", other_seed, 1, ActorId(0))
        .expect("fourth run must succeed");
    assert_eq!(outcome3.roots, outcome4.roots, "other seed determinism");

    // Multiple attempts: roots len must match attempts and be deterministic.
    let multi1 = proc
        .run_workload("kv", seed, 2, ActorId(0))
        .expect("multi attempt run");
    assert_eq!(multi1.roots.len(), 2, "attempts=2 must yield two roots");
    for root in &multi1.roots {
        assert_eq!(ledger_format::hash_to_hex(root).len(), 64);
    }
    let multi2 = proc
        .run_workload("kv", seed, 2, ActorId(0))
        .expect("multi attempt run2");
    assert_eq!(multi1.roots, multi2.roots, "multi-attempt determinism");

    // Actor threading: the same seed under a different actor stays
    // deterministic per actor.
    let actor1_first = proc
        .run_workload("kv", seed, 1, ActorId(1))
        .expect("actor 1 run must succeed");
    let actor1_second = proc
        .run_workload("kv", seed, 1, ActorId(1))
        .expect("actor 1 rerun must succeed");
    assert_eq!(
        actor1_first.roots, actor1_second.roots,
        "same seed and actor must yield same root"
    );
}

/// Required integration gate: never skips. When the engine binary is absent
/// or unusable this test fails with a setup message, mirroring the
/// pg_queue suite's documented "never skips" discipline.
///
/// Only an explicit `LEDGER_ENGINE_BIN` or the sibling `ledger` binary from
/// the same cargo build satisfies the gate. No CWD or PATH fallback is
/// accepted, so an unverified installed binary cannot satisfy it.
#[test]
#[cfg(unix)]
fn required_ipc_roundtrip_determinism() {
    let engine = probe_engine_path().unwrap_or_else(|| {
        panic!(
            "required IPC roundtrip gate needs the engine binary, found none: \
             set LEDGER_ENGINE_BIN to a `ledger` binary with the rt-server subcommand, \
             or build ledger-cli in the workspace so the sibling binary exists. \
             No CWD or PATH fallback is accepted so an unverified binary \
             cannot satisfy this gate."
        )
    });
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(run_determinism_checks(engine));
}

/// Optional local test: exercises the same roundtrip but skips explicitly
/// when no engine binary is present. Named separately so CI can run the
/// required gate without this skip being mistaken for coverage.
#[test]
#[cfg(unix)]
fn ipc_roundtrip_optional_local() {
    let Some(engine) = probe_engine_path() else {
        eprintln!(
            "skipping ipc_roundtrip_optional_local: ledger binary not found \
             (set LEDGER_ENGINE_BIN or build ledger-cli)"
        );
        return;
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(run_determinism_checks(engine));
}
