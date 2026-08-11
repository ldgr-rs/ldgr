//! Corpus-bug reproduction through a Wasm guest.
//!
//! The guest `run_stale` implements a stale-read: it reads a key twice and
//! serves the cached first value for the second read. The oracle flags the
//! `STALE_DIVERGENCE` marker. A native twin draws the same stream; the two
//! journals must be byte-identical.
#![cfg(feature = "backend-wasm")]

mod common;

use ledger_sim::{Effects, SeedTree, SimBackend, WasmBackend};
use rand_core::Rng;

const SEED: [u8; 32] = [11; 32];
const STALE_STREAM: u32 = 11;

/// Native twin of the guest's stale-read workload, drawing the same stream.
fn native_twin() -> (Vec<u8>, ledger_journal::Journal) {
    let mut backend = SimBackend::new(SeedTree::new(SEED));
    let fresh = backend.rng(STALE_STREAM).next_u64();
    let fresh_second = backend.rng(STALE_STREAM).next_u64();
    let stale = fresh;
    let mut output = Vec::new();
    output.extend_from_slice(format!("fresh={fresh_second} stale={stale}\n").as_bytes());
    if stale != fresh_second {
        output.extend_from_slice(b"STALE_DIVERGENCE\n");
    }
    (output, backend.journal().lock().unwrap().clone())
}

#[test]
fn corpus_bug_reproduced_through_wasm_guest() {
    let wasm = common::guest_wasm_bytes();
    let mut backend = WasmBackend::from_wasm(SeedTree::new(SEED), &wasm)
        .unwrap()
        .with_fuel_budget(10_000_000);
    let output = backend.run_export("run_stale").unwrap().to_vec();
    let output_text = String::from_utf8_lossy(&output);
    assert!(
        output_text.contains("STALE_DIVERGENCE"),
        "the planted stale-read bug must fire in the guest: {output_text}"
    );
}

#[test]
fn corpus_bug_native_wasm_zero_false_divergence() {
    let (native_output, native_journal) = native_twin();

    let wasm = common::guest_wasm_bytes();
    let mut backend = WasmBackend::from_wasm(SeedTree::new(SEED), &wasm)
        .unwrap()
        .with_fuel_budget(10_000_000);
    let wasm_output = backend.run_export("run_stale").unwrap().to_vec();
    let wasm_journal = backend.journal().lock().unwrap().clone();

    assert_eq!(native_output, wasm_output, "output must be byte-identical");
    assert_eq!(
        native_journal.root_hash(),
        wasm_journal.root_hash(),
        "native and Wasm journals must be byte-identical on the bug workload"
    );
}
