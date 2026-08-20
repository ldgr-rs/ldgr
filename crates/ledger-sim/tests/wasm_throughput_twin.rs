//! Throughput workload native twin: Wasm and native backends journal identically.
//!
//! The guest `run_throughput` draws 2000 values from stream 9 with an inner
//! compute loop. This test runs the same logic natively via `SimBackend` and
//! asserts byte-identical output and identical journal root hashes.
#![cfg(feature = "backend-wasm")]

mod common;

use ledger_journal::JournalCorrectnessMonitor;
use ledger_sim::{Effects, SeedTree, SimBackend, WasmBackend};
use rand_core::Rng;

/// Throughput constants must match `wasm-guest/src/lib.rs`.
const THROUGHPUT_DRAWS: u32 = 2_000;
const THROUGHPUT_LOOP_ITERS: u32 = 1_500;
const THROUGHPUT_STREAM: u32 = 9;

fn native_throughput(seed: [u8; 32]) -> (Vec<u8>, ledger_journal::Journal) {
    let mut backend = SimBackend::new(SeedTree::new(seed));
    let mut accumulator: u64 = 0;
    for _ in 0..THROUGHPUT_DRAWS {
        let value = Effects::rng(&mut backend, THROUGHPUT_STREAM).next_u64();
        let mut working = value;
        for _ in 0..THROUGHPUT_LOOP_ITERS {
            working = working.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1);
        }
        accumulator = accumulator.wrapping_add(working);
    }
    let output = accumulator.to_le_bytes().to_vec();
    // The guest emits via ledger_log, but native has no log boundary for this
    // value. Journal comparison is against the throughput entries only; output
    // is the 8-byte accumulator. The Wasm guest also emits 8 bytes via
    // ledger_log, so outputs must match.
    let journal = backend.journal_snapshot();
    (output, journal)
}

#[test]
fn throughput_native_twin_root_equality() {
    let seed = [7u8; 32];
    let (native_output, native_journal) = native_throughput(seed);

    let wasm = common::guest_wasm_bytes();
    let mut backend = WasmBackend::from_wasm(SeedTree::new(seed), &wasm).unwrap();
    backend = backend.with_fuel_budget(2_000_000_000);
    let wasm_output = backend.run_export("run_throughput").unwrap();
    let wasm_journal = backend.journal_snapshot();

    assert_eq!(
        wasm_output, native_output,
        "throughput output must be byte-identical across backends"
    );
    assert_eq!(
        wasm_journal.root_hash(),
        native_journal.root_hash(),
        "throughput journal roots must match"
    );
    assert_eq!(
        wasm_journal.len(),
        native_journal.len(),
        "throughput entry counts must match"
    );
    assert!(
        JournalCorrectnessMonitor::audit(&wasm_journal).is_empty(),
        "wasm throughput journal must be causally sound"
    );
    assert!(
        JournalCorrectnessMonitor::audit(&native_journal).is_empty(),
        "native throughput journal must be causally sound"
    );
    // Verify the journal contains exactly 2000 RngDraw entries plus no extra.
    assert_eq!(
        wasm_journal.len(),
        THROUGHPUT_DRAWS as usize,
        "throughput must journal exactly {} RngDraw entries",
        THROUGHPUT_DRAWS
    );
}

#[test]
fn throughput_native_twin_is_deterministic() {
    let seed = [42u8; 32];
    let (a_out, a_journal) = native_throughput(seed);
    let (b_out, b_journal) = native_throughput(seed);
    assert_eq!(a_out, b_out);
    assert_eq!(a_journal.root_hash(), b_journal.root_hash());
}
