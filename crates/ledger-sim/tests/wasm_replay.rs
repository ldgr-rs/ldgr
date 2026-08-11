//! A Wasm guest compiled to `wasm32-wasip1` replays bit-exactly.
//!
//! The guest `run` entry draws from a fixed seed embedded in the guest and
//! writes deterministic lines to stdout through WASI `fd_write`. This test
//! instantiates the guest twice under the deterministic wasmtime config and
//! asserts the captured stdout is byte-identical, and that it matches a golden
//! output computed on the host from the same algorithm.
//!
//! Determinism comes from the guest-side fixed seed plus host-side NaN
//! canonicalization and relaxed-SIMD determinism, with no ambient randomness
//! anywhere.
#![cfg(feature = "backend-wasm")]

mod common;

use std::sync::Mutex;
use wasmtime::{Caller, Config, Engine, Error, Linker, Module, Store};
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::p2::pipe::MemoryOutputPipe;

/// Run the guest `run` entry once and return the captured WASI stdout.
fn run_w0_guest() -> Vec<u8> {
    let mut config = Config::new();
    config.cranelift_nan_canonicalization(true);
    config.relaxed_simd_deterministic(true);
    let engine = Engine::new(&config).unwrap();
    let module = Module::new(&engine, common::guest_wasm_bytes()).unwrap();

    let pipe = MemoryOutputPipe::new(64 * 1024);
    let wasi = WasiCtxBuilder::new().stdout(pipe.clone()).build_p1();
    let mut store = Store::new(&engine, Mutex::new(wasi));

    let mut linker = Linker::<Mutex<WasiP1Ctx>>::new(&engine);
    p1::add_to_linker_sync(&mut linker, |state: &mut Mutex<WasiP1Ctx>| {
        state.get_mut().unwrap()
    })
    .unwrap();

    // Stub `ledger` funcs: the module imports them because `run_boundary`
    // lives in the same cdylib. The `run` entry never invokes them.
    linker
        .func_wrap(
            "ledger",
            "ledger_log",
            |_: Caller<'_, Mutex<WasiP1Ctx>>, _ptr: u32, _len: u32| -> Result<(), Error> { Ok(()) },
        )
        .unwrap();
    linker
        .func_wrap(
            "ledger",
            "ledger_rng_u64",
            |_: Caller<'_, Mutex<WasiP1Ctx>>, _stream: u32| -> u64 { 0 },
        )
        .unwrap();
    linker
        .func_wrap(
            "ledger",
            "ledger_sleep",
            |_: Caller<'_, Mutex<WasiP1Ctx>>, _ticks: u64| {},
        )
        .unwrap();
    linker
        .func_wrap(
            "ledger",
            "ledger_send",
            |_: Caller<'_, Mutex<WasiP1Ctx>>, _peer: u32, _payload: u64| -> i32 { 1 },
        )
        .unwrap();
    linker
        .func_wrap(
            "ledger",
            "ledger_recv",
            |_: Caller<'_, Mutex<WasiP1Ctx>>, _peer: u32| -> i64 { -1 },
        )
        .unwrap();

    let instance = linker.instantiate(&mut store, &module).unwrap();
    let run = instance
        .get_typed_func::<(), ()>(&mut store, "run")
        .unwrap();
    run.call(&mut store, ()).unwrap();

    pipe.contents().to_vec()
}

/// One SplitMix64 step, replicated on the host to derive the golden output.
fn splitmix64_next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

/// The expected stdout, computed host-side from the guest's fixed seed.
fn expected_w0_output() -> String {
    let seed = [0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15];
    let mut state = u64::from_le_bytes(seed);
    let mut output = String::new();
    for index in 0..8u32 {
        let value = splitmix64_next(&mut state) % 1000;
        output.push_str(&format!("draw[{index}]={value}\n"));
    }
    output
}

#[test]
fn w0_guest_replays_bit_exactly() {
    let first = run_w0_guest();
    let second = run_w0_guest();
    assert_eq!(
        first, second,
        "two instantiations must emit byte-identical stdout"
    );
    assert!(!first.is_empty(), "guest must emit stdout");
}

#[test]
fn w0_guest_matches_golden_seed_output() {
    let output = run_w0_guest();
    let expected = expected_w0_output();
    assert_eq!(
        String::from_utf8(output).unwrap(),
        expected,
        "guest output must match the fixed-seed golden output"
    );
}
