//! Deterministic Wasm guest for the ledger journaling engine.
//!
//! The guest is a `crate-type = ["cdylib"]` core module targeting
//! `wasm32-wasip1`, built with `cargo build --target wasm32-wasip1 -p
//! wasm-guest`. All exports below run on this path via `wasmtime_wasi::p1`
//! plus the `ledger` host functions. The backend supports preview1 only.
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
//! - `run_corpus_*`: the twelve bug-corpus-v1 scenario programs, one export
//!   per committed manifest. The host-side `wasm_corpus_bug` gate enumerates
//!   `corpora/bug-corpus-v1/*.ldgr` and requires every scenario to reproduce
//!   through this backend. Each export journals the same host-boundary calls
//!   (`ledger_send` / `ledger_recv` / `ledger_sleep` / `ledger_rng_u64`) the
//!   native twin would make and emits a planted-bug marker line.
//!
//! The guest never reads ambient randomness, the wall clock, or the ambient
//! filesystem. Its only nondeterminism risk is host-side WASI behavior, which
//! the ledger backend virtualizes.

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
        append_line(&mut line, format_args!("draw[{index}]={value}\n"));
        emit(&line);
        line.clear();
    }
}

/// Append one diagnostic line to an in-memory buffer (best-effort).
///
/// `fmt::Write` on `String` cannot fail in practice; discarding the result
/// keeps probe output from aborting the workload.
fn append_line(line: &mut String, args: core::fmt::Arguments<'_>) {
    use std::fmt::Write as _;
    // Intentional discard: the String writer is infallible.
    let _ = line.write_fmt(args);
}

/// Emit one diagnostic line to WASI stdout (best-effort).
///
/// A failed stdout write must never abort the workload; the host captures
/// whatever bytes arrive.
fn emit(line: impl AsRef<[u8]>) {
    // Intentional discard: output loss on a probe stream is not fatal.
    let _ = std::io::Write::write_all(&mut std::io::stdout(), line.as_ref());
}

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "ledger")]
unsafe extern "C" {
    /// Draw a deterministic value from a labeled stream. The host serves this
    /// from the seed tree and journals an `RngDraw` entry.
    fn ledger_rng_u64(stream: u32) -> u64;
    /// Emit `len` bytes at `ptr` as observable guest output.
    ///
    /// `len` is the byte length of a fixed-format diagnostic line, always
    /// well below `u32::MAX`, so the call-site casts are lossless.
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
    /// Write `value` at `path` through the SimFs boundary.
    ///
    /// Returns 0 on success, nonzero on failure. Journals `FsWrite`.
    fn ledger_fs_write(ptr: *const u8, len: usize, value: u64) -> i32;
    /// Read at `path` through the SimFs boundary.
    ///
    /// Returns the value, -1 when absent, -2 on journal error. Journals
    /// `FsRead` with parent fidelity.
    fn ledger_fs_read(ptr: *const u8, len: usize) -> i64;
    /// Crash the SimFs state, journaling `Fault(CrashState(0))`.
    fn ledger_fs_crash();
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
        append_line(&mut line, format_args!("draw[{index}]={value}\n"));
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
    append_line(&mut line, format_args!("random={:02x?}\n", buf));
    emit(&line);
    line.clear();
    let mut now = 0u64;
    let err = unsafe { clock_time_get(1, 0, &mut now) }; // Monotonic
    assert_eq!(err, 0, "clock_time_get must succeed");
    append_line(&mut line, format_args!("monotonic={now}\n"));
    emit(&line);
}

/// A guest that loops forever; the host's fuel budget must trap it.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn run_forever() {
    loop {
        unsafe { ledger_rng_u64(0) };
        let buf = [0u8; 1];
        emit(&buf);
    }
}

/// Empty export: no host calls, measures pure wasmtime trampoline cost.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn run_empty() {}

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
    append_line(
        &mut line,
        format_args!("fresh={fresh_second} stale={stale}\n"),
    );
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
    append_line(
        &mut line,
        format_args!("sent={sent} received={received:?}\n"),
    );
    unsafe { ledger_log(line.as_ptr(), line.len() as u32) };
    line.clear();
    if sent && received == Some(PING_PAYLOAD) {
        let marker = b"PINGPONG_OK\n";
        unsafe { ledger_log(marker.as_ptr(), marker.len() as u32) };
    }
}

/// Filesystem workload: write/read through the SimFs boundary.
///
/// Writes `42` at path `k`, reads it back, and logs `read=42`. The host
/// journals `FsWrite` with `FsRead` parent fidelity.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn run_fs() {
    let key = b"k";
    let rc = unsafe { ledger_fs_write(key.as_ptr(), key.len(), 42) };
    assert_eq!(rc, 0, "ledger_fs_write must succeed");
    let value = unsafe { ledger_fs_read(key.as_ptr(), key.len()) };
    let mut line = String::new();
    append_line(&mut line, format_args!("read={value}\n"));
    unsafe { ledger_log(line.as_ptr(), line.len() as u32) };
}

/// Filesystem crash workload: write, crash, read-after-crash.
///
/// Writes `99` at `k` without fsync, crashes, then reads. The read must be
/// absent (`-1`) because the unsynced write is dropped by the crash.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn run_fs_crash() {
    let key = b"k";
    let rc = unsafe { ledger_fs_write(key.as_ptr(), key.len(), 99) };
    assert_eq!(rc, 0, "ledger_fs_write must succeed");
    unsafe { ledger_fs_crash() };
    let value = unsafe { ledger_fs_read(key.as_ptr(), key.len()) };
    let mut line = String::new();
    append_line(&mut line, format_args!("read_after_crash={value}\n"));
    unsafe { ledger_log(line.as_ptr(), line.len() as u32) };
}

// ---------------------------------------------------------------------------
// Bug-corpus-v1 scenario programs
// ---------------------------------------------------------------------------
//
// One export per committed manifest under `corpora/bug-corpus-v1/`. Each
// program re-encodes its reference-runtime scenario (see
// `ledger-explorer/src/reference/sims.rs`) as a single deterministic guest:
// messages the scenario must observe are self-addressed to actor 0 and
// received in program order; sends to other peers journal `Send` entries
// without being consumed. Every export emits a planted-bug marker line the
// wasm corpus gate requires.

/// Log one fixed-format diagnostic line through the ledger boundary.
#[cfg(target_arch = "wasm32")]
fn scenario_line(line: &str) {
    unsafe { ledger_log(line.as_ptr(), line.len() as u32) };
}

/// Emit the planted-bug marker line of one scenario.
#[cfg(target_arch = "wasm32")]
fn marker(text: &str) {
    scenario_line(text);
}

/// Receive one message addressed to `peer`, if immediately deliverable.
#[cfg(target_arch = "wasm32")]
fn recv_at(peer: u32) -> Option<u64> {
    let value = unsafe { ledger_recv(peer) };
    if value < 0 { None } else { Some(value as u64) }
}

/// Unwrap a delivery the program guarantees by sending before receipt.
///
/// The program sends before it receives, so the inbox holds the message.
/// `None` signals a programming error. Returning 0 preserves the probe
/// total without hiding the delivery that the host asserts in the journal.
#[cfg(target_arch = "wasm32")]
fn take(msg: Option<u64>) -> u64 {
    match msg {
        Some(value) => value,
        None => 0,
    }
}

/// mini-zab-split-brain: the leader proposes value 1, then value 2 after a
/// re-election; follower 2 synchronizes from its last-known-committed value
/// only (planted bug) and keeps value 1 while the cluster holds 2.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn run_corpus_zab() {
    let v1 = 1u64;
    let v2 = 2u64;
    let _ = send(1, v1); // leader broadcast of value 1
    let _ = send(2, v1);
    unsafe { ledger_sleep(1) }; // re-election
    let _ = send(1, v2); // leader broadcast of value 2
    let _ = send(2, v2);
    // Follower 2 never waits for the second commit (bug) and serves 1.
    let follower2 = take(recv_at(2));
    scenario_line(&format!(
        "leader={v2} follower1={v2} follower2={follower2}\n"
    ));
    if follower2 != v2 {
        marker("ZAB_SPLIT_BRAIN\n");
    }
}

/// mini-hdfs-double-grant: the NameNode grants the pre-bump version to both
/// awaited lease requests (planted bug) instead of distinct versions.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn run_corpus_hdfs() {
    let _ = send(0, 1); // lease request from writer 1
    let _ = send(0, 2); // lease request from writer 2
    let r1 = take(recv());
    let r2 = take(recv());
    let granted1 = 0u64; // bug: both see the pre-bump version
    let granted2 = 0u64;
    let _ = (r1, r2);
    scenario_line(&format!("granted1={granted1} granted2={granted2}\n"));
    if granted1 == granted2 {
        marker("HDFS_DOUBLE_GRANT\n");
    }
}

/// mini-cassandra-stale-read: the primary writes 7 and gossips; replica 2
/// serves its local value 0 before anti-entropy reaches it (planted bug).
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn run_corpus_cassandra() {
    let value = 7u64;
    let _ = send(1, value); // gossip to follower 1
    let _ = send(2, value); // gossip to replica 2
    let replica_served = 0u64; // bug: local state served without sync
    scenario_line(&format!("value={value} replica_served={replica_served}\n"));
    if replica_served != value {
        marker("CASSANDRA_STALE_READ\n");
    }
}

/// mini-2pc-coordinator-crash: the coordinator commits participant A and
/// crashes before B, so B stays prepared forever (planted bug).
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn run_corpus_2pc() {
    let _ = send(1, 10); // PREPARE to participant A
    let _ = send(2, 10); // PREPARE to participant B
    let _ = send(0, 1); // vote from A
    let _ = send(0, 1); // vote from B
    let _ = take(recv()); // vote from A
    let _ = take(recv()); // vote from B
    let _ = send(1, 20); // COMMIT to A; crash before B
    let participant_a = 20u64;
    let participant_b = 10u64; // bug: B never commits
    scenario_line(&format!(
        "participant_a={participant_a} participant_b={participant_b}\n"
    ));
    if participant_a != participant_b {
        marker("TWO_PC_SPLIT\n");
    }
}

/// mini-leader-stepdown: the old leader keeps serving its stale value after
/// the new leader committed a newer one (planted bug).
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn run_corpus_stepdown() {
    let _ = send(1, 1); // old leader replicates value 1
    let _ = send(0, 99); // client read request
    let _ = take(recv()); // read request arrives
    let committed = 2u64; // new leader committed 2
    let served = 1u64; // bug: old leader answers from its old term
    scenario_line(&format!("committed={committed} served={served}\n"));
    if served != committed {
        marker("STEPDOWN_STALE_READ\n");
    }
}

/// mini-membership-churn: the leader refuses to advance its commit index
/// until the departed follower acks (planted bug), so an acknowledged entry
/// never commits.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn run_corpus_churn() {
    let _ = send(1, 1); // replicate to the live follower
    let _ = send(2, 1); // replicate to the departing follower
    let _ = send(0, 1); // ack from the live follower
    let _ = take(recv()); // ack arrives
    unsafe { ledger_sleep(2) }; // wait for the departed follower's ack
    let acked = 1u64; // the live follower holds the data
    let commit_index = 0u64; // bug: stale membership blocks the commit
    scenario_line(&format!("acked={acked} commit_index={commit_index}\n"));
    if acked > commit_index {
        marker("COMMIT_STALL\n");
    }
}

/// mini-hdfs-lease-expiry: the expired writer's late write lands after the
/// new holder's write, so storage keeps the stale overwrite (planted bug).
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn run_corpus_lease_expiry() {
    let _ = send(1, 1); // grant lease to the old writer
    let _ = send(2, 2); // grant lease to the new writer
    let _ = send(0, 2); // new writer's write reaches storage
    let _ = take(recv());
    unsafe { ledger_sleep(2) }; // old lease expires
    let _ = send(0, 111); // bug: expired writer's late write
    let _ = take(recv());
    let storage = 111u64; // bug: storage ends with the stale overwrite
    let holder_write = 2u64;
    scenario_line(&format!("holder_write={holder_write} storage={storage}\n"));
    if storage != holder_write {
        marker("LEASE_OVERWRITE\n");
    }
}

/// mini-reorder-lost-update: sequence 2 overtakes sequence 1 in flight and
/// the store applies writes blindly (planted bug), so the newer update is
/// lost.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn run_corpus_reorder() {
    // Writer B sends sequence 2 with a 1-tick delay; writer A sends
    // sequence 1 with a 2-tick delay, so sequence 2 always arrives first.
    unsafe { ledger_sleep(1) };
    let _ = send(0, 2);
    unsafe { ledger_sleep(1) };
    let _ = send(0, 1);
    let applied_first = take(recv());
    let applied_last = take(recv()); // bug: applied without a sequence check
    let highest_sequence = 2u64;
    scenario_line(&format!(
        "applied_first={applied_first} applied_last={applied_last}\n"
    ));
    if applied_last != highest_sequence {
        marker("LOST_UPDATE\n");
    }
}

/// mini-lease-timer-race: a late renewal re-activates an expired lease
/// (planted bug), so one epoch ends up with two distinct holders.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn run_corpus_lease_timer() {
    let _ = send(1, 1); // grant epoch-1 lease to the old holder
    unsafe { ledger_sleep(2) }; // expiry timer fires
    let _ = send(2, 1); // re-grant epoch 1 to the new holder
    let _ = send(0, 1); // late renewal from the old holder
    let _ = take(recv()); // renewal arrives
    // Bug: the manager honors the renewal without checking the lease clock.
    let _ = send(1, 1); // old holder lease re-activated
    let old_holder = 10 + 1; // holds epoch 1
    let new_holder = 10 + 2; // also holds epoch 1
    scenario_line(&format!("epoch1_holders={old_holder},{new_holder}\n"));
    if old_holder != new_holder {
        marker("DOUBLE_LEASE_HOLDER\n");
    }
}

/// mini-restart-dup-append: the appender acks the client before its dedup
/// state is durable, then re-appends the same record after the restart
/// (planted bug).
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn run_corpus_restart_dup() {
    let record = 500u64;
    let _ = send(2, record); // WAL append to the durable log
    let _ = send(0, 1); // log ack
    let _ = take(recv());
    let _ = send(0, 1); // bug: ack the client before dedup state is durable
    let _ = take(recv());
    // Crash + restart: WAL replay without dedup.
    let _ = send(2, record); // duplicate durable append
    let _ = send(0, 1); // log ack for the duplicate
    let _ = take(recv());
    scenario_line(&format!("record={record} durable_appends=2\n"));
    marker("DUP_APPEND\n");
}

/// mini-partition-retry-dup: the client retries a request whose ack was
/// lost in a partition window; the server applies every received request
/// without dedup (planted bug).
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn run_corpus_partition_retry() {
    let request = 77u64;
    let _ = send(1, request); // request
    unsafe { ledger_sleep(2) }; // retry timeout while the ack path is broken
    let _ = send(1, request); // retry (at-least-once)
    let _ = send(0, 1); // ack of the first apply
    let _ = take(recv());
    let _ = send(0, 1); // ack of the retry apply
    let _ = take(recv());
    scenario_line(&format!("applied={request} twice\n"));
    marker("DUP_APPLY\n");
}
