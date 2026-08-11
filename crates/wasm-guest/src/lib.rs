//! Deterministic Wasm guest for the ledger journaling engine.
//!
//! This `cdylib` targets `wasm32-wasip1`. Entry points:
//!
//! - `run`: draws from a fixed seed embedded in the guest and writes
//!   deterministic lines to stdout through WASI `fd_write`. The host captures
//!   stdout and asserts bit-exact replay across instantiations.
//! - `run_boundary`: crosses the ledger host-function boundary
//!   (`ledger_rng_u64`, `ledger_log`, `ledger_sleep`). Each call is a WASI
//!   scheduling point forwarded to the same `SimBackend` effects the native
//!   backend uses.
//! - `run_virtualized`: reads WASI `random_get` and `clock_time_get`, which
//!   the host serves from the seed tree and virtual time.
//! - `run_forever`: burns fuel until the host budget traps it.
//! - `run_throughput`: journals one `RngDraw` per compute loop.
//! - `run_stale`: the planted stale-read bug workload.
//!
//! The guest never reads ambient randomness, the wall clock, or the ambient
//! filesystem. Its only nondeterminism risk is host-side WASI behavior, which
//! the ledger backend virtualizes.

use std::fmt::Write as _;

/// Fixed seed embedded in the guest. The workload tests determinism, not
/// seed-tree integration.
const SEED: [u8; 8] = [0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15];
const DRAW_COUNT: u32 = 8;
#[cfg(target_arch = "wasm32")]
const BOUNDARY_DRAW_COUNT: u32 = 4;
/// Stream id shared with the native twin workload.
#[cfg(target_arch = "wasm32")]
const BOUNDARY_STREAM: u32 = 7;
/// Virtual-time sleep shared with the native twin workload.
#[cfg(target_arch = "wasm32")]
const BOUNDARY_SLEEP_TICKS: u64 = 3;

/// SplitMix64: a tiny deterministic PRNG that needs no ambient randomness.
struct SplitMix64(u64);

impl SplitMix64 {
    fn from_seed(seed: [u8; 8]) -> Self {
        Self(u64::from_le_bytes(seed))
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}

/// Entry point: deterministic replay through WASI stdout.
#[unsafe(no_mangle)]
pub extern "C" fn run() {
    let mut rng = SplitMix64::from_seed(SEED);
    let mut line = String::new();
    for index in 0..DRAW_COUNT {
        let value = rng.next_u64() % 1000;
        let _ = writeln!(line, "draw[{index}]={value}");
        let _ = std::io::Write::write_all(&mut std::io::stdout(), line.as_bytes());
        line.clear();
    }
}

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "ledger")]
unsafe extern "C" {
    /// Draw a deterministic value from a labeled stream. The host serves this
    /// from the seed tree and journals an `RngDraw` entry.
    fn ledger_rng_u64(stream: u32) -> u64;
    /// Emit `len` bytes at `ptr` as observable guest output.
    fn ledger_log(ptr: *const u8, len: u32);
    /// Sleep for virtual-time ticks. The host advances the virtual clock.
    fn ledger_sleep(ticks: u64);
    /// Send `payload` to `peer` through the host network boundary.
    ///
    /// Returns 0 on acceptance, nonzero when the message is refused
    /// (partitioned link or journal failure).
    fn ledger_send(peer: u32, payload: u64) -> i32;
    /// Receive one message addressed to `peer` if one is immediately
    /// deliverable. Returns the payload, or -1 when no message is available.
    fn ledger_recv(peer: u32) -> i64;
}

/// Send `payload` to `peer` through the host network boundary.
///
/// Returns true when the host accepted the message. The host journals the
/// `Send` entry at the sender.
#[cfg(target_arch = "wasm32")]
pub fn send(peer: u32, payload: u64) -> bool {
    unsafe { ledger_send(peer, payload) == 0 }
}

/// Receive one message addressed to this guest if one is immediately
/// deliverable.
///
/// This guest always runs as actor 0 in the host backend, so the inbox polled
/// is actor 0's. The host journals the `Recv` entry at the receiver, parenting
/// it to the matching `Send`.
#[cfg(target_arch = "wasm32")]
pub fn recv() -> Option<u64> {
    let value = unsafe { ledger_recv(0) };
    if value < 0 { None } else { Some(value as u64) }
}

/// Entry point: cross the ledger host-function boundary deterministically.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn run_boundary() {
    let mut line = String::new();
    for index in 0..BOUNDARY_DRAW_COUNT {
        let value = unsafe { ledger_rng_u64(BOUNDARY_STREAM) };
        let _ = writeln!(line, "draw[{index}]={value}");
        unsafe { ledger_log(line.as_ptr(), line.len() as u32) };
        line.clear();
    }
    unsafe { ledger_sleep(BOUNDARY_SLEEP_TICKS) };
    let tail = b"after-sleep\n";
    unsafe { ledger_log(tail.as_ptr(), tail.len() as u32) };
}

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "wasi_snapshot_preview1")]
// WASI imports virtualized by the host: `random_get` (served from the seed
// tree) and `clock_time_get` (served from virtual time).
unsafe extern "C" {
    fn random_get(buf: *mut u8, len: usize) -> i32;
    fn clock_time_get(clock_id: u32, precision: u64, time: *mut u64) -> i32;
}

/// Entry point: read WASI random_get and clock_time_get, both host-virtualized.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn run_virtualized() {
    let mut buf = [0u8; 16];
    let err = unsafe { random_get(buf.as_mut_ptr(), buf.len()) };
    assert_eq!(err, 0, "random_get must succeed");
    let mut line = String::new();
    let _ = writeln!(line, "random={:02x?}", buf);
    let _ = std::io::Write::write_all(&mut std::io::stdout(), line.as_bytes());
    line.clear();
    let mut now = 0u64;
    let err = unsafe { clock_time_get(1, 0, &mut now) }; // Monotonic
    assert_eq!(err, 0, "clock_time_get must succeed");
    let _ = writeln!(line, "monotonic={now}");
    let _ = std::io::Write::write_all(&mut std::io::stdout(), line.as_bytes());
}

/// A guest that loops forever; the host's fuel budget must trap it.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn run_forever() {
    loop {
        unsafe { ledger_rng_u64(0) };
        let buf = [0u8; 1];
        let _ = std::io::Write::write_all(&mut std::io::stdout(), &buf);
    }
}

/// Throughput workload: one `RngDraw` per compute loop of ~10,000 instructions.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn run_throughput() {
    let mut accumulator: u64 = 0;
    for _index in 0..THROUGHPUT_DRAWS {
        let value = unsafe { ledger_rng_u64(THROUGHPUT_STREAM) };
        // Dependency-preserving loop the compiler cannot elide.
        let mut working = value;
        for _ in 0..THROUGHPUT_LOOP_ITERS {
            working = working.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1);
        }
        accumulator = accumulator.wrapping_add(working);
    }
    unsafe { ledger_log(accumulator.to_le_bytes().as_ptr(), 8) };
}

#[cfg(target_arch = "wasm32")]
const THROUGHPUT_DRAWS: u32 = 2_000;
#[cfg(target_arch = "wasm32")]
const THROUGHPUT_LOOP_ITERS: u32 = 1_500;
#[cfg(target_arch = "wasm32")]
const THROUGHPUT_STREAM: u32 = 9;

/// Planted stale-read divergence reproduced through a Wasm guest.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn run_stale() {
    const STALE_STREAM: u32 = 11;
    let fresh = unsafe { ledger_rng_u64(STALE_STREAM) };
    let fresh_second = unsafe { ledger_rng_u64(STALE_STREAM) };
    let stale = fresh; // planted bug: second read serves the cached value
    let mut line = String::new();
    let _ = writeln!(line, "fresh={fresh_second} stale={stale}");
    unsafe { ledger_log(line.as_ptr(), line.len() as u32) };
    line.clear();
    if stale != fresh_second {
        let marker = b"STALE_DIVERGENCE\n";
        unsafe { ledger_log(marker.as_ptr(), marker.len() as u32) };
    }
}

/// Message-passing workload: send a message to self and receive it back.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn run_pingpong() {
    const PING_PAYLOAD: u64 = 0xCAFE_F00D;
    let sent = send(0, PING_PAYLOAD);
    let received = recv();
    let mut line = String::new();
    let _ = writeln!(line, "sent={sent} received={received:?}");
    unsafe { ledger_log(line.as_ptr(), line.len() as u32) };
    line.clear();
    if sent && received == Some(PING_PAYLOAD) {
        let marker = b"PINGPONG_OK\n";
        unsafe { ledger_log(marker.as_ptr(), marker.len() as u32) };
    }
}
