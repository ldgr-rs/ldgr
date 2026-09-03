//! Wasm throughput gate: >= 100k entries/s on `run_throughput`, with a
//! minimum entry count ruling out vacuous passes.
#![cfg(feature = "backend-wasm")]

use ledger_sim::{SeedTree, WasmBackend};
use std::time::Instant;

/// Load the release guest artifact.
fn release_guest_wasm_bytes() -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/wasm32-wasip1/release/wasm_guest.wasm");
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "release guest artifact missing at {}; run `cargo build --release --target wasm32-wasip1 -p wasm-guest` first. error: {error}",
            path.display()
        )
    })
}

/// Entries journaled by one guest `run_throughput` invocation.
const ENTRIES_PER_RUN: usize = 2_000;
/// Invocations inside the timed section; enough to smooth one-off jitter.
const INNER_LOOPS: usize = 5;
/// Documented W1 budget.
const MIN_ENTRIES_PER_SECOND: f64 = 100_000.0;
/// Fuel enough for the whole throughput workload with margin.
const FUEL_BUDGET: u64 = 2_000_000_000;

#[test]
fn wasm_throughput_gate_100k_entries_per_second() {
    // The gate is defined against the release profile (AGENTS.md evidence
    // gate). A debug-profile host cannot sustain the bar under parallel test
    // load, so unoptimized sweeps skip it instead of flaking.
    if cfg!(debug_assertions) {
        eprintln!("skipping: throughput gate is a release-profile gate (run with --release)");
        return;
    }
    let wasm = release_guest_wasm_bytes();
    let engine = WasmBackend::new_engine().expect("engine must build");
    let module = wasmtime::Module::new(&engine, &wasm).expect("guest module must compile");

    let run_once = || {
        let mut backend =
            WasmBackend::from_module(SeedTree::new(ledger_format::EntryHash([0; 32])), &module)
                .expect("backend must instantiate")
                .with_fuel_budget(FUEL_BUDGET);
        backend
            .run_export("run_throughput")
            .expect("throughput export must run");
        let journal = backend.journal_snapshot();
        let count = journal.len();
        assert!(
            count >= ENTRIES_PER_RUN,
            "one run_throughput invocation must journal >= {ENTRIES_PER_RUN} entries, got {count}; \
             a fast no-op guest must not pass the rate gate vacuously"
        );
        count
    };

    // Warm up once so the timed section measures steady state, not first-run
    // engine setup.
    run_once();

    let started = Instant::now();
    let mut total_entries = 0usize;
    for _ in 0..INNER_LOOPS {
        total_entries += run_once();
    }
    let elapsed = started.elapsed();
    let entries_per_second = total_entries as f64 / elapsed.as_secs_f64();

    println!(
        "wasm throughput gate: {entries_per_second:.0} entries/s ({total_entries} entries in {elapsed:?}, bar {MIN_ENTRIES_PER_SECOND:.0}/s)"
    );
    assert!(
        entries_per_second >= MIN_ENTRIES_PER_SECOND,
        "wasm throughput {entries_per_second:.0} entries/s is below the {MIN_ENTRIES_PER_SECOND:.0} entries/s W1 budget"
    );
}
