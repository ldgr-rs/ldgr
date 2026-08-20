//! Native and Wasm backends produce identical behavior.
//!
//! The guest `run_boundary` entry crosses the ledger host-function boundary:
//! `ledger.rng_u64` (seed tree + journaled `RngDraw`), `ledger.log` (observable
//! output), and `ledger.sleep` (virtual time). Each crossing is forwarded to
//! the same `SimBackend` the native backend drives.
//!
//! This test runs the same workload natively (a Rust twin over `SimBackend`)
//! and through the Wasm sandbox (`WasmBackend`), then asserts:
//! - observable output is byte-identical,
//! - the journal root hashes match,
//! - both journals pass the correctness monitor.
#![cfg(feature = "backend-wasm")]

mod common;

use ledger_format::{EntryKind, StreamId};
use ledger_journal::{Journal, JournalCorrectnessMonitor};
use ledger_sim::{Effects, SeedTree, SimBackend, WasmBackend};
use rand_core::Rng;

/// Root seed shared by both backends.
const SEED: [u8; 32] = [9; 32];
/// Stream id drawn by both the guest and the native twin.
const STREAM: StreamId = 7;
/// Number of draws in the workload.
const DRAW_COUNT: u64 = 4;
/// Virtual-time sleep in the workload.
const SLEEP_TICKS: u64 = 3;
/// Payload exchanged by the message-passing workload.
const PING_PAYLOAD: u64 = 0xCAFE_F00D;

/// Run the workload natively over a fresh `SimBackend`.
fn native_twin() -> (Vec<u8>, Journal) {
    let mut backend = SimBackend::new(SeedTree::new(SEED));
    let mut output = Vec::new();
    for index in 0..DRAW_COUNT {
        let value = Effects::rng(&mut backend, STREAM).next_u64();
        output.extend_from_slice(format!("draw[{index}]={value}\n").as_bytes());
    }
    futures::executor::block_on(Effects::sleep(
        &backend,
        core::time::Duration::from_micros(SLEEP_TICKS),
    ));
    output.extend_from_slice(b"after-sleep\n");
    let journal = backend.journal_snapshot();
    (output, journal)
}

/// Run the same workload through the Wasm sandbox.
fn wasm_twin() -> (Vec<u8>, Journal) {
    let mut backend =
        WasmBackend::from_wasm(SeedTree::new(SEED), &common::guest_wasm_bytes()).unwrap();
    let output = backend.run_guest().unwrap();
    let journal = backend.journal_snapshot();
    (output, journal)
}

#[test]
fn wasm_guest_matches_native_twin() {
    let (native_output, native_journal) = native_twin();
    let (wasm_output, wasm_journal) = wasm_twin();

    assert_eq!(
        wasm_output, native_output,
        "observable output must be byte-identical across backends"
    );
    assert_eq!(
        wasm_journal.root_hash(),
        native_journal.root_hash(),
        "journal root hashes must match across backends"
    );
    assert!(
        JournalCorrectnessMonitor::audit(&wasm_journal).is_empty(),
        "wasm journal must be causally sound"
    );
    assert!(
        JournalCorrectnessMonitor::audit(&native_journal).is_empty(),
        "native journal must be causally sound"
    );
}

/// The WASI boundary is virtualized: `random_get` and `clock_time_get` are
/// served from the seed tree and virtual time, so two instantiations produce
/// byte-identical stdout and the virtual clock reads zero before any sleep.
#[test]
fn wasi_random_and_clock_are_deterministic() {
    let wasm = common::guest_wasm_bytes();
    let mut first = WasmBackend::from_wasm(SeedTree::new([4; 32]), &wasm).unwrap();
    let first_output = first.run_export("run_virtualized").unwrap();
    let mut second = WasmBackend::from_wasm(SeedTree::new([4; 32]), &wasm).unwrap();
    let second_output = second.run_export("run_virtualized").unwrap();

    assert_eq!(
        first_output, second_output,
        "virtualized WASI output must be deterministic across instantiations"
    );
    // Virtual time starts at zero, so the monotonic clock reads 0.
    let text = String::from_utf8_lossy(&first_output);
    assert!(
        text.contains("monotonic=0"),
        "monotonic clock must read virtual time 0 before any sleep; got {text:?}"
    );
    assert!(
        text.starts_with("random="),
        "random_get output must be present; got {text:?}"
    );
}

/// Different seeds yield different `random_get` bytes (the stream is
/// seed-derived, not constant).
#[test]
fn wasi_random_differs_across_seeds() {
    let wasm = common::guest_wasm_bytes();
    let a = WasmBackend::from_wasm(SeedTree::new([1; 32]), &wasm)
        .unwrap()
        .run_export("run_virtualized")
        .unwrap();
    let b = WasmBackend::from_wasm(SeedTree::new([2; 32]), &wasm)
        .unwrap()
        .run_export("run_virtualized")
        .unwrap();
    assert_ne!(
        a, b,
        "different seeds must produce different random_get bytes"
    );
}

/// Fuel bounds a runaway guest: `run_forever` must trap with FuelExhausted
/// instead of looping forever.
#[test]
fn fuel_bounds_runaway_guest() {
    let wasm = common::guest_wasm_bytes();
    let mut backend = WasmBackend::from_wasm(SeedTree::new([3; 32]), &wasm).unwrap();
    let result = backend.run_export("run_forever");
    assert!(
        matches!(result, Err(ledger_sim::WasmError::FuelExhausted)),
        "runaway guest must be trapped by the fuel budget; got {result:?}"
    );
}

/// Guest WASI stdout is captured deterministically through the virtualized
/// output sink.
#[test]
fn wasi_stdout_is_captured() {
    let wasm = common::guest_wasm_bytes();
    let mut backend = WasmBackend::from_wasm(SeedTree::new([5; 32]), &wasm).unwrap();
    let output = backend.run_export("run_virtualized").unwrap();
    assert!(
        !output.is_empty(),
        "guest WASI stdout must be captured into the output buffer"
    );
    assert!(
        output.windows(7).any(|w| w == b"random="),
        "output must contain the random_get line"
    );
}

/// RR execution-trace validation.
///
/// `Config::rr(RRConfig::Recording)` enables wasmtime's engine-enforced
/// execution-trace determinism. The engine build must REJECT any config that
/// permits nondeterminism (NaN canonicalization or relaxed-SIMD disabled),
/// proving `validate_rr_determinism_conflicts` is live in the pinned version.
#[test]
fn rr_recording_engine_rejects_nondeterministic_config() {
    let mut config = wasmtime::Config::new();
    config.rr(wasmtime::RRConfig::Recording);
    // Deliberately omit the two required determinism settings.
    config.cranelift_nan_canonicalization(false);
    config.relaxed_simd_deterministic(false);
    let engine = wasmtime::Engine::new(&config);
    assert!(
        engine.is_err(),
        "rr recording must reject a config that permits nondeterminism"
    );
}

/// The production WasmBackend enables rr recording AND the required
/// determinism settings, so its engine must build and run the guest
/// deterministically across invocations.
#[test]
fn rr_recording_backend_is_deterministic() {
    let wasm = common::guest_wasm_bytes();
    let mut first = WasmBackend::from_wasm(SeedTree::new(SEED), &wasm)
        .unwrap()
        .with_fuel_budget(10_000_000);
    let mut second = WasmBackend::from_wasm(SeedTree::new(SEED), &wasm)
        .unwrap()
        .with_fuel_budget(10_000_000);
    let first_out = first.run_export("run_virtualized").unwrap().to_vec();
    let second_out = second.run_export("run_virtualized").unwrap().to_vec();
    assert_eq!(first_out, second_out);
    let first_root = first.journal_snapshot().root_hash();
    let second_root = second.journal_snapshot().root_hash();
    assert_eq!(first_root, second_root);
}

/// WASI crossings are journaled: `random_get` and `clock_time_get` each produce
/// exactly one entry in the inner backend's journal, so the coverage rule (one
/// entry per cross-boundary effect) holds for WASI randomness and time.
#[test]
fn wasi_random_and_clock_journal_entries() {
    let wasm = common::guest_wasm_bytes();
    let mut first = WasmBackend::from_wasm(SeedTree::new([4; 32]), &wasm).unwrap();
    let _ = first.run_export("run_virtualized").unwrap();
    let journal = first.journal_snapshot();
    assert!(
        !journal.is_empty(),
        "a virtualized WASI run must journal entries"
    );
    let kinds = journal
        .entries()
        .map(|entry| entry.data.kind)
        .collect::<Vec<_>>();
    assert!(
        kinds.iter().any(|kind| matches!(
            kind,
            EntryKind::RngDraw {
                stream: ledger_sim::WASI_RANDOM_STREAM
            }
        )),
        "random_get must journal one RngDraw on the WASI stream; got {kinds:?}"
    );
    assert!(
        kinds
            .iter()
            .any(|kind| matches!(kind, EntryKind::ClockRead)),
        "clock_time_get must journal one ClockRead; got {kinds:?}"
    );

    let mut second = WasmBackend::from_wasm(SeedTree::new([4; 32]), &wasm).unwrap();
    let _ = second.run_export("run_virtualized").unwrap();
    assert_eq!(
        first.journal_snapshot().root_hash(),
        second.journal_snapshot().root_hash(),
        "same seed must produce identical journal roots"
    );
}

/// Run the guest's message-passing workload natively over `SimBackend::net`.
fn native_pingpong() -> (Vec<u8>, Journal) {
    use ledger_sim::Message;
    let backend = SimBackend::new(SeedTree::new(SEED));
    let now = backend.clock().now();
    let sent = backend.net().send(Message {
        from: 0,
        to: 0,
        payload: PING_PAYLOAD,
        send_id: [0; 32],
        deliver_at: now,
    });
    let received_payload = backend
        .net()
        .recv(0, backend.clock().now())
        .map(|message| message.payload);
    let mut output = format!("sent={sent} received={received_payload:?}\n").into_bytes();
    if sent && received_payload == Some(PING_PAYLOAD) {
        output.extend_from_slice(b"PINGPONG_OK\n");
    }
    (output, backend.journal_snapshot())
}

/// The guest network boundary matches the native boundary on a send/recv
/// workload: byte-identical output and identical journal roots.
///
/// This is also the effect-level port-validation guard for backend-portable
/// replay: the `Send`/`Recv` entries recorded by the native boundary must
/// reproduce bit-exactly through the Wasm boundary.
#[test]
fn wasm_pingpong_matches_native_twin() {
    let (native_output, native_journal) = native_pingpong();

    let wasm = common::guest_wasm_bytes();
    let mut backend = WasmBackend::from_wasm(SeedTree::new(SEED), &wasm).unwrap();
    let wasm_output = backend.run_export("run_pingpong").unwrap();
    let wasm_journal = backend.journal_snapshot();

    assert_eq!(
        wasm_output, native_output,
        "observable output must be byte-identical across backends"
    );
    assert_eq!(
        wasm_journal.root_hash(),
        native_journal.root_hash(),
        "journal roots must match on the send/recv workload"
    );
    assert!(
        JournalCorrectnessMonitor::audit(&wasm_journal).is_empty(),
        "wasm pingpong journal must be causally sound"
    );
    assert!(
        JournalCorrectnessMonitor::audit(&native_journal).is_empty(),
        "native pingpong journal must be causally sound"
    );
}
