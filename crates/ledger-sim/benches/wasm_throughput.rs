//! Wasm throughput benchmark.
//!
//! Target: >= 100k journaled entries/s at ~10k guest instructions/entry. The
//! guest `run_throughput` entry journals one `RngDraw` per ~10k-instruction
//! compute loop. This benchmark measures how many of those journaled entries
//! the Wasm backend sustains per second, including wasmtime execution, host
//! boundary crossing, and journal hashing.
//!
//! The empty-export bench isolates pure wasmtime trampoline cost (no host
//! calls, no journaling). Together the two benches show whether crossing cost
//! justifies a batch descriptor export (A3) or the dominant cost is journal
//! hashing.
//!
//! Methodology: release guest artifact only; engine and module compiled once
//! outside the timed section; criterion `iter_batched` with `SmallInput` to
//! isolate steady-state dispatch; 10 samples, 2s warmup. All rates are
//! wall-clock host time, never an input to simulation.
// ledger-lint:allow (host-side benchmark reads the guest artifact from disk; it is not simulation code)
#![cfg(feature = "backend-wasm")]

use criterion::{Criterion, criterion_group, criterion_main};
use ledger_sim::{SeedTree, WasmBackend};

/// Entries journaled by one guest `run_throughput` invocation.
const ENTRIES_PER_RUN: u64 = 2_000;

fn load_guest() -> Vec<u8> {
    // Throughput must be measured against an optimized guest artifact.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/wasm32-wasip1/release/wasm_guest.wasm");
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "release guest artifact missing at {}; run `cargo build --release --target wasm32-wasip1 -p wasm-guest` first. error: {error}",
            path.display()
        )
    })
}

fn bench_w1_throughput(c: &mut Criterion) {
    let wasm = load_guest();
    // Prebuild the engine and compile the module once. The timed section must
    // measure steady-state guest throughput, not module compilation.
    let engine = WasmBackend::new_engine().unwrap();
    let module = wasmtime::Module::new(&engine, &wasm).unwrap();
    c.bench_function("w1_guest_throughput_2000_entries", |b| {
        b.iter_batched(
            || {
                WasmBackend::from_module(SeedTree::new(ledger_format::EntryHash([0; 32])), &module)
                    .unwrap()
                    .with_fuel_budget(2_000_000_000)
            },
            |mut backend| {
                let _ = backend.run_export("run_throughput").unwrap();
                let journal = backend.journal_snapshot();
                let count = journal.len();
                assert!(
                    count as u64 >= ENTRIES_PER_RUN,
                    "expected >= {ENTRIES_PER_RUN} entries, got {count}"
                );
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_empty_export_trampoline(c: &mut Criterion) {
    let wasm = load_guest();
    let engine = WasmBackend::new_engine().unwrap();
    let module = wasmtime::Module::new(&engine, &wasm).unwrap();
    c.bench_function("w1_empty_export_trampoline", |b| {
        b.iter_batched(
            || {
                WasmBackend::from_module(SeedTree::new(ledger_format::EntryHash([0; 32])), &module)
                    .unwrap()
                    .with_fuel_budget(2_000_000_000)
            },
            |mut backend| {
                backend.run_export("run_empty").unwrap();
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    name = wasm_benches;
    config = Criterion::default().sample_size(10).warm_up_time(std::time::Duration::from_secs(2));
    targets = bench_w1_throughput, bench_empty_export_trampoline
);
criterion_main!(wasm_benches);
