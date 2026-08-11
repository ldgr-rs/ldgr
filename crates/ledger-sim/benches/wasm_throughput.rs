//! Wasm throughput benchmark.
// ledger-lint:allow (host-side benchmark reads the guest artifact from disk; it is not simulation code)
//!
//! Target: >= 100k journaled entries/s at ~10k guest instructions/entry. The
//! guest `run_throughput` entry journals one `RngDraw` per ~10k-instruction
//! compute loop. This benchmark measures how many of those journaled entries
//! the Wasm backend sustains per second, including wasmtime execution, host
//! boundary crossing, and journal hashing.
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
                WasmBackend::from_module(SeedTree::new([0; 32]), &module)
                    .unwrap()
                    .with_fuel_budget(2_000_000_000)
            },
            |mut backend| {
                let _ = backend.run_export("run_throughput").unwrap();
                let journal = backend.journal().lock().unwrap();
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

criterion_group!(
    name = wasm_benches;
    config = Criterion::default().sample_size(10).warm_up_time(std::time::Duration::from_secs(2));
    targets = bench_w1_throughput
);
criterion_main!(wasm_benches);
