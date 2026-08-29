//! Wasm backend: wasmtime host boundary forwarding to the sim Effects.
//!
//! WASI host calls are the scheduling points. A guest compiled to
//! `wasm32-wasip1` crosses the effect boundary through the `ledger` host
//! function module implemented here, which forwards every crossing to the same
//! `SimBackend` that the native backend drives. The journal, seed tree,
//! virtual clock, and observable output stay identical across backends.
//!
//! WASI determinism virtualization:
//! - `random_get` is served from a seed-tree-derived ChaCha20 stream via
//!   `WasiCtxBuilder::secure_random`.
//! - `clock_time_get` serves virtual time via custom `HostWallClock` /
//!   `HostMonotonicClock` implementations reading the shared tick sink that
//!   `SimBackend` publishes on every clock read and time advance.
//! - Guest `fd_write` to stdout is captured deterministically into the output
//!   buffer so host-side output stays byte-identical across backends; byte
//!   identity is pinned by the differential oracle, not folded into journal
//!   hashes (no `Output` entry kind exists).
//! - Bounded execution via fuel: a runaway guest traps at the fuel budget
//!   instead of looping forever.
//! - NaN canonicalization and relaxed-SIMD determinism close the two CPU
//!   nondeterminism sources.
//!
//! The wasmtime engine runs with `Config::rr(RRConfig::Recording)`, which
//! enables engine-enforced execution-trace determinism
//! (`validate_rr_determinism_conflicts` rejects settings that allow
//! nondeterminism).
//!
//! The backend is preview1-only: all workloads (`run`, `run_boundary`,
//! `run_virtualized`, ...) run `wasm32-wasip1` core modules. The former
//! WASIp2 component-model scaffold was removed because no component guest
//! consumes it; the wasmtime component-model feature is enabled only
//! transitively (wasmtime-wasi preview1 depends on it) and no component
//! API is used directly.
//!
//! Backend-portable decision-trace replay (a journal recorded on native
//! replaying on Wasm) is deferred. Replay in the native path pins scheduler
//! ready-list choices (`Simulation::with_replay`); mirroring that on the Wasm
//! backend would require a decision-trace replay protocol inside the guest,
//! which is not yet specified. The differential port-validation oracle covers
//! the same ground: the same workload runs natively and in the guest with one
//! seed, and the journals must hash identically.

use crate::backend_sim::{SimBackend, record_first_journal_error};
use crate::effects::{Effects, Fs, Net};
use crate::net::Message;
use crate::seedtree::SeedTree;
use crate::time::Clock;
use crate::wasi_fs::{WasiFdTable, bytes_to_u64};
use futures::executor::block_on;
use ledger_format::{ActorId, EntryKind, EntryPayload, Hash, StreamId};
use ledger_journal::{Journal, JournalError};
use rand_chacha::ChaCha20Rng;
use rand_core::Rng;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use wasmtime::{Caller, Config, Engine, Error, Instance, Linker, Module, Store};
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::cli::{IsTerminal, StdoutStream};
use wasmtime_wasi::p1::{self, WasiP1Ctx};

/// Nanoseconds per virtual-time tick, mapping ticks to the WASI monotonic
/// clock's nanosecond scale.
const NS_PER_TICK: u64 = 1_000;

/// Dedicated stream id for WASI `random_get` crossings.
///
/// Every `random_get` call journals one `RngDraw` entry on this stream; the
/// payload records the number of bytes requested. The value is high enough to
/// stay clear of application streams.
pub const WASI_RANDOM_STREAM: StreamId = 0xF000;

/// Upper bound on the iovec count of one wasm `fd_write` or `fd_read` call.
///
/// WASI guests that violate the cap observe `WASI_ERRNO_INVAL`. The cap only
/// applies to the error path: valid guests never reach it, so byte-identical
/// journaling is preserved.
const MAX_WASI_IOVECS: u32 = 4096;

/// Upper bound on the aggregate payload bytes of one wasm `fd_write` call.
///
/// Guards the host-side gather buffer against a guest that claims huge
/// iovec lengths while the memory backs them. Violations return
/// `WASI_ERRNO_INVAL`; the cap never applies to a valid run.
const MAX_WASI_WRITE_BYTES: usize = 16 << 20;

/// WASI preview1 errno for an invalid argument (`EINVAL`).
const WASI_ERRNO_INVAL: u32 = 28;

/// WASI preview1 errno for an I/O failure (`EIO`).
const WASI_ERRNO_IO: u32 = 29;

/// Validate and gather the payload of one `fd_write` call.
///
/// Applies the iovec-count and payload-size caps. A memory out-of-bounds
/// keeps the wasmtime-trap convention and maps to `Err(None)`; a cap
/// violation reports the WASI errno in `Err(Some(errno))`. The result never
/// depends on host state, so the valid path is byte-identical.
fn gather_write_payload(
    memory: &[u8],
    iovs_ptr: u32,
    iovs_len: u32,
) -> Result<Vec<u8>, Option<u32>> {
    if iovs_len > MAX_WASI_IOVECS {
        return Err(Some(WASI_ERRNO_INVAL));
    }
    let mut collected = Vec::new();
    for index in 0..iovs_len {
        let iov_off = (iovs_ptr as usize)
            .checked_add((index as usize) * 8)
            .ok_or(None)?;
        let iov_end = iov_off.checked_add(8).ok_or(None)?;
        let iov_bytes = memory.get(iov_off..iov_end).ok_or(None)?;
        let mut buf_ptr_bytes = [0u8; 4];
        buf_ptr_bytes.copy_from_slice(&iov_bytes[..4]);
        let mut buf_len_bytes = [0u8; 4];
        buf_len_bytes.copy_from_slice(&iov_bytes[4..]);
        let buf_ptr = u32::from_le_bytes(buf_ptr_bytes) as usize;
        let buf_len = u32::from_le_bytes(buf_len_bytes) as usize;
        if collected.len().saturating_add(buf_len) > MAX_WASI_WRITE_BYTES {
            return Err(Some(WASI_ERRNO_INVAL));
        }
        let end = buf_ptr.checked_add(buf_len).ok_or(None)?;
        let bytes = memory.get(buf_ptr..end).ok_or(None)?;
        collected.extend_from_slice(bytes);
    }
    Ok(collected)
}

/// Record a journaled-write failure and map it to the guest-visible errno.
///
/// The typed error lands on the backend's shared slot so `journal_error()`
/// reports it; the guest observes `WASI_ERRNO_IO` instead of a silent
/// success. The mapping only fires on the error path.
fn record_write_failure(
    journal_error_slot: &Mutex<Option<JournalError>>,
    error: JournalError,
) -> u32 {
    record_first_journal_error(journal_error_slot, &error);
    WASI_ERRNO_IO
}

/// Result alias for the Wasm backend.
pub type WasmResult<T> = Result<T, WasmError>;

/// Failure modes of the Wasm backend.
#[derive(Debug)]
pub enum WasmError {
    /// wasmtime failed.
    Wasmtime(wasmtime::Error),
    /// The guest artifact could not be read.
    Io(std::io::Error),
    /// No guest module has been loaded.
    NoGuest,
    /// The guest exhausted its fuel budget (bounded execution).
    FuelExhausted,
}

impl fmt::Display for WasmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wasmtime(error) => write!(f, "wasmtime error: {error}"),
            Self::Io(error) => write!(f, "guest I/O error: {error}"),
            Self::NoGuest => write!(f, "no guest module loaded; call load_guest first"),
            Self::FuelExhausted => write!(f, "guest exhausted its fuel budget"),
        }
    }
}

impl std::error::Error for WasmError {}

impl From<wasmtime::Error> for WasmError {
    fn from(error: wasmtime::Error) -> Self {
        Self::Wasmtime(error)
    }
}

impl From<std::io::Error> for WasmError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Shared journaling path for WASI boundary crossings.
///
/// Holds the same journal, error slot, and actor as the inner `SimBackend`,
/// so WASI `clock_time_get` entries land in the same causal DAG the native
/// boundary writes and failures surface through the same error slot.
#[derive(Clone)]
struct WasiJournal {
    journal: Arc<Mutex<Journal>>,
    journal_error: Arc<Mutex<Option<JournalError>>>,
    actor: ActorId,
}

impl WasiJournal {
    /// Append one entry through the shared journaling path.
    fn append(
        &self,
        kind: EntryKind,
        parents: impl IntoIterator<Item = Hash>,
        payload: EntryPayload,
    ) {
        let mut journal = self.journal.lock().unwrap_or_else(|e| e.into_inner());
        match journal.append(kind, self.actor, parents, payload) {
            Ok(_) => {}
            Err(error) => {
                record_first_journal_error(&self.journal_error, &error);
            }
        }
    }
}

/// WASI wall clock backed by virtual time.
///
/// Reports virtual time in nanosecond ticks, so `clock_time_get(Realtime)` is
/// deterministic across runs. Each read journals one `ClockRead` entry
/// because WASI `clock_time_get` is an observable cross-boundary effect;
/// `SimBackend::clock()` stays non-journaled (see its docs) to keep the
/// native send path byte-identical.
struct VirtualWallClock {
    ticks: Arc<Mutex<u64>>,
    journal: WasiJournal,
}

impl wasmtime_wasi::HostWallClock for VirtualWallClock {
    fn resolution(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(NS_PER_TICK)
    }

    fn now(&self) -> std::time::Duration {
        let ticks = *self.ticks.lock().unwrap_or_else(|e| e.into_inner());
        self.journal
            .append(EntryKind::ClockRead, [], EntryPayload::ClockRead { ticks });
        std::time::Duration::from_nanos(ticks * NS_PER_TICK)
    }
}

/// WASI monotonic clock backed by virtual time.
///
/// Each read journals one `ClockRead` entry carrying the tick count. This
/// matches `Boundary::read_clock` journaling; `SimBackend::clock()` and
/// `Boundary::clock()` stay non-journaled by design.
struct VirtualMonotonicClock {
    ticks: Arc<Mutex<u64>>,
    journal: WasiJournal,
}

impl wasmtime_wasi::HostMonotonicClock for VirtualMonotonicClock {
    fn resolution(&self) -> u64 {
        NS_PER_TICK
    }

    fn now(&self) -> u64 {
        let ticks = *self.ticks.lock().unwrap_or_else(|e| e.into_inner());
        self.journal
            .append(EntryKind::ClockRead, [], EntryPayload::ClockRead { ticks });
        ticks * NS_PER_TICK
    }
}

/// A stdout sink that appends guest `fd_write` output to a shared buffer.
///
/// The shared buffer is drained into the store's output after each call, so
/// guest-observable output is deterministic across backends; its byte identity
/// is pinned by the differential oracle, not by journal hashes.
struct CapturedStdout {
    sink: Arc<Mutex<Vec<u8>>>,
}

impl IsTerminal for CapturedStdout {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdoutStream for CapturedStdout {
    fn async_stream(&self) -> Box<dyn tokio::io::AsyncWrite + Send + Sync> {
        Box::new(SinkWriter(self.sink.clone()))
    }
}

/// A minimal `AsyncWrite` appending to a shared buffer.
struct SinkWriter(Arc<Mutex<Vec<u8>>>);

impl tokio::io::AsyncWrite for SinkWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Store data for the wasmtime store.
///
/// The type must be `Send + Sync` because wasmtime host functions require it.
/// The inner `SimBackend` is the same effects implementation the native
/// backend uses; `SimBackend` is `Send + Sync` because all mutable state sits
/// behind an uncontended `Mutex`.
struct WasmStoreData {
    effects: SimBackend,
    wasi: Mutex<WasiP1Ctx>,
    output: Vec<u8>,
    stdout_sink: Arc<Mutex<Vec<u8>>>,
    /// Seed-tree-derived stream serving WASI `random_get`.
    ///
    /// The guest's `random_get` import is shadowed by a host function that
    /// draws here and journals one `RngDraw` per crossing, so WASI randomness
    /// is deterministic and the crossing is journaled exactly once.
    wasi_random: ChaCha20Rng,
    /// Virtual filesystem fd table: deterministic fd -> SimFs path key.
    wasi_fs: Mutex<WasiFdTable>,
}

/// Wasm backend: wraps a wasmtime engine, store, and guest instances.
///
/// Implements the `Effects` surface by delegating to the inner `SimBackend`.
/// The guest crosses the boundary through the `ledger` host functions, which
/// forward to the same effects; WASI `random_get`, `clock_time_get`, and
/// stdout are virtualized onto the seed tree, virtual clock, and output
/// buffer respectively.
///
/// Mixed topology (W2): the backend can host multiple named guest instances
/// in one `Store`. All instances share the same `SeedTree` derivation and
/// virtual clock, so a mixed run (e.g. Go + Zig) remains deterministic:
/// same seed produces byte-identical journal roots. Scheduling points remain
/// host-call boundaries; interleaving across guests is host-driven via
/// sequential `run_export_on` calls, not preemptive threads.
pub struct WasmBackend {
    engine: Engine,
    store: Store<WasmStoreData>,
    instance: Option<Instance>,
    // ledger-lint:allow:HashMap (name-keyed instance lookups; never iterated)
    instances: HashMap<String, Instance>,
    fuel_budget: u64,
}

impl WasmBackend {
    /// Create a backend with an empty store for the given seed tree.
    pub fn new(seed_tree: SeedTree) -> WasmResult<Self> {
        Self::with_engine(Self::new_engine()?, seed_tree)
    }

    /// Build a wasmtime engine with the backend's deterministic configuration.
    ///
    /// Compiling a guest against this engine and instantiating it with
    /// [`Self::from_module`] moves module compilation out of the measured path
    /// of throughput benchmarks.
    pub fn new_engine() -> WasmResult<Engine> {
        Engine::new(&Self::deterministic_config()).map_err(WasmError::from)
    }

    /// Create a backend from a module built by [`Self::new_engine`].
    ///
    /// The module and engine are prebuilt once and reused across runs, so the
    /// steady-state throughput of the guest is measured without recompiling.
    pub fn from_module(seed_tree: SeedTree, module: &wasmtime::Module) -> WasmResult<Self> {
        let mut backend = Self::with_engine(module.engine().clone(), seed_tree)?;
        let linker = Self::build_linker(&backend.engine)?;
        let instance = linker.instantiate(&mut backend.store, module)?;
        backend.instances.insert("main".to_string(), instance);
        backend.instance = Some(instance);
        Ok(backend)
    }

    /// Build the store scaffolding against an existing engine.
    fn with_engine(engine: Engine, seed_tree: SeedTree) -> WasmResult<Self> {
        let stdout_sink = Arc::new(Mutex::new(Vec::new()));
        let tick_sink = Arc::new(Mutex::new(0));
        let mut effects = SimBackend::new(seed_tree.clone());
        effects.attach_tick_sink(Arc::clone(&tick_sink));

        // WASI crossings share the inner backend's journaling path.
        let wasi_journal = WasiJournal {
            journal: Arc::clone(&effects.journal),
            journal_error: Arc::clone(&effects.journal_error),
            actor: effects.actor(),
        };

        // Serve WASI random_get from a seed-tree-derived stream. The built-in
        // preview1 `random_get` import is shadowed (see `build_linker`); the
        // context copy stays deterministic as a defensive default.
        let wasi_ctx = WasiCtxBuilder::new()
            .secure_random(seed_tree.rng("wasi.random"))
            .wall_clock(VirtualWallClock {
                ticks: Arc::clone(&tick_sink),
                journal: wasi_journal.clone(),
            })
            .monotonic_clock(VirtualMonotonicClock {
                ticks: Arc::clone(&tick_sink),
                journal: wasi_journal,
            })
            .stdout(CapturedStdout {
                sink: Arc::clone(&stdout_sink),
            })
            .build_p1();

        let store = Store::new(
            &engine,
            WasmStoreData {
                effects,
                wasi: Mutex::new(wasi_ctx),
                output: Vec::new(),
                stdout_sink,
                wasi_random: seed_tree.rng("wasi.random"),
                wasi_fs: Mutex::new(WasiFdTable::new()),
            },
        );
        Ok(Self {
            engine,
            store,
            instance: None,
            instances: HashMap::new(),
            fuel_budget: 10_000_000,
        })
    }

    /// Create a backend and load a guest module in one step.
    pub fn from_wasm(seed_tree: SeedTree, wasm: &[u8]) -> WasmResult<Self> {
        let mut backend = Self::new(seed_tree)?;
        backend.load_guest(wasm)?;
        Ok(backend)
    }

    /// Set the fuel budget per guest call (bounded execution).
    pub fn with_fuel_budget(mut self, budget: u64) -> Self {
        self.fuel_budget = budget;
        self
    }

    /// Compile and instantiate a guest module against this backend.
    ///
    /// The guest is registered under the default name "main" so existing
    /// single-instance callers continue to work. Mixed-topology callers
    /// should prefer [`Self::load_guest_multi`].
    pub fn load_guest(&mut self, wasm: &[u8]) -> WasmResult<()> {
        self.load_guest_multi("main", wasm)
    }

    /// Compile and instantiate a named guest module for mixed topology.
    ///
    /// Stores the instance under `name` in a `HashMap<String, Instance>`.
    /// The default `load_guest` / `run_export` API stays intact and is
    /// backed by the "main" entry. All named instances share one `Store`,
    /// one `SeedTree`, and one virtual clock, so a run that executes
    /// `run_export_on("go", "run")` then `run_export_on("zig", "run")`
    /// journals deterministically: the same seed produces the same journal
    /// root. Scheduling points remain host-call boundaries; concurrency
    /// across guests is cooperative via sequential host calls.
    pub fn load_guest_multi(&mut self, name: &str, wasm: &[u8]) -> WasmResult<()> {
        let module = Module::new(&self.engine, wasm)?;
        let linker = Self::build_linker(&self.engine)?;
        let instance = linker.instantiate(&mut self.store, &module)?;
        self.instances.insert(name.to_string(), instance);
        // Keep the legacy single-instance field in sync when the primary
        // guest is (re)loaded so `run_export` without an explicit name
        // keeps working.
        if name == "main" {
            self.instance = Some(instance);
        } else if self.instance.is_none() {
            // First guest loaded under a non-main name also populates the
            // legacy field so single-guest callers that use `run_export`
            // after a `load_guest_multi("go", ...)` do not see NoGuest.
            // Mixed callers should use `run_export_on` explicitly.
            self.instance = Some(instance);
        }
        Ok(())
    }

    /// Run the `run_boundary` guest entry point and return its logged output.
    pub fn run_guest(&mut self) -> WasmResult<Vec<u8>> {
        self.run_export("run_boundary")
    }

    /// Run a guest entry point by name and return its logged output.
    ///
    /// The output buffer is cleared before the call, so the returned bytes are
    /// exactly what this invocation logged (both the `ledger.log` boundary and
    /// WASI stdout). Delegates to [`Self::run_export_on`] with the default
    /// instance name "main".
    pub fn run_export(&mut self, entry: &str) -> WasmResult<Vec<u8>> {
        self.run_export_on("main", entry)
    }

    /// Run an entry point on a named guest instance and return its logged output.
    ///
    /// Reuses the same `Store` fuel and output logic as [`Self::run_export`],
    /// so fuel budgeting and output capture behave identically across named
    /// instances. The journal is shared across instances, so cross-guest runs
    /// append to one deterministic causal DAG.
    pub fn run_export_on(&mut self, name: &str, entry: &str) -> WasmResult<Vec<u8>> {
        // Prefer the named map; fall back to the legacy single-instance field
        // so callers that only used `load_guest` keep working even if the map
        // lookup would miss due to ordering.
        let instance = if let Some(inst) = self.instances.get(name) {
            *inst
        } else if name == "main" {
            *self.instance.as_ref().ok_or(WasmError::NoGuest)?
        } else {
            return Err(WasmError::NoGuest);
        };
        self.store.data_mut().output.clear();
        self.store
            .data_mut()
            .stdout_sink
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.store.set_fuel(self.fuel_budget)?;
        let func = instance.get_typed_func::<(), ()>(&mut self.store, entry)?;
        match func.call(&mut self.store, ()) {
            Ok(()) => {}
            Err(_) => {
                if self.store.get_fuel()? == 0 {
                    return Err(WasmError::FuelExhausted);
                }
                return Err(WasmError::Wasmtime(wasmtime::Error::msg("guest trapped")));
            }
        }
        let stdout = self
            .store
            .data()
            .stdout_sink
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        self.store.data_mut().output.extend_from_slice(&stdout);
        Ok(self.store.data().output.clone())
    }

    /// Return the bytes logged by the guest since the last call.
    pub fn output(&self) -> Vec<u8> {
        self.store.data().output.clone()
    }

    /// Return an immutable snapshot of the journaled history of the inner
    /// sim backend.
    ///
    /// The snapshot is a full copy taken under the backend's internal lock;
    /// it never aliases live state and never changes the run.
    pub fn journal_snapshot(&self) -> Journal {
        self.store.data().effects.journal_snapshot()
    }

    /// Return the first journaling failure recorded by the inner backend, if any.
    pub fn journal_error(&self) -> Option<JournalError> {
        self.store.data().effects.journal_error()
    }

    /// Build the deterministic wasmtime configuration.
    ///
    /// NaN canonicalization and relaxed-SIMD determinism close the two CPU
    /// nondeterminism sources. Fuel
    /// enables bounded execution: a runaway guest traps at the budget. The rr
    /// recording mode enables wasmtime's engine-enforced execution-trace
    /// determinism (`validate_rr_determinism_conflicts` rejects settings that
    /// allow nondeterminism, and the compiled trace checksum detects drift).
    fn deterministic_config() -> Config {
        let mut config = Config::new();
        config.cranelift_nan_canonicalization(true);
        config.relaxed_simd_deterministic(true);
        config.consume_fuel(true);
        config.rr(wasmtime::RRConfig::Recording);
        config
    }

    /// Build the linker binding WASI preview1 and the `ledger` host functions.
    fn build_linker(engine: &Engine) -> WasmResult<Linker<WasmStoreData>> {
        let mut linker = Linker::<WasmStoreData>::new(engine);
        p1::add_to_linker_sync(&mut linker, |state: &mut WasmStoreData| {
            match state.wasi.get_mut() {
                Ok(ctx) => ctx,
                Err(poisoned) => poisoned.into_inner(),
            }
        })?;

        linker.func_wrap(
            "ledger",
            "ledger_rng_u64",
            |mut caller: Caller<'_, WasmStoreData>, stream: u32| -> u64 {
                caller.data_mut().effects.rng(stream).next_u64()
            },
        )?;

        linker.func_wrap(
            "ledger",
            "ledger_log",
            |mut caller: Caller<'_, WasmStoreData>, ptr: u32, len: u32| -> Result<(), Error> {
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or_else(|| Error::msg("guest has no exported memory"))?;
                let start = ptr as usize;
                let end = start
                    .checked_add(len as usize)
                    .ok_or_else(|| Error::msg("ledger_log length overflow"))?;
                let bytes = memory
                    .data(&caller)
                    .get(start..end)
                    .ok_or_else(|| Error::msg("ledger_log read out of bounds"))?
                    .to_vec();
                caller.data_mut().output.extend_from_slice(&bytes);
                Ok(())
            },
        )?;

        linker.func_wrap(
            "ledger",
            "ledger_sleep",
            |caller: Caller<'_, WasmStoreData>, ticks: u64| {
                block_on(
                    caller
                        .data()
                        .effects
                        .sleep(core::time::Duration::from_micros(ticks)),
                );
            },
        )?;

        linker.func_wrap(
            "ledger",
            "ledger_send",
            |caller: Caller<'_, WasmStoreData>, peer: u32, payload: u64| -> i32 {
                let now = caller.data().effects.clock().now();
                let from = caller.data().effects.actor();
                let accepted = caller.data().effects.net().send(Message {
                    from: from as usize,
                    to: peer as usize,
                    content: payload.to_le_bytes().to_vec(),
                    message_id: ledger_format::MessageId::new(from, 0),
                    send_id: [0; 32],
                    deliver_at: now,
                });
                if accepted { 0 } else { 1 }
            },
        )?;

        linker.func_wrap(
            "ledger",
            "ledger_recv",
            |caller: Caller<'_, WasmStoreData>, peer: u32| -> i64 {
                let now = caller.data().effects.clock().now();
                match caller.data().effects.net().recv(peer as usize, now) {
                    Some(message) => message.payload() as i64,
                    None => -1,
                }
            },
        )?;

        linker.func_wrap(
            "ledger",
            "ledger_fs_write",
            |mut caller: Caller<'_, WasmStoreData>, ptr: u32, len: u32, value: u64| -> u32 {
                let memory = match caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                {
                    Some(memory) => memory,
                    None => return 1,
                };
                let start = ptr as usize;
                let end = match start.checked_add(len as usize) {
                    Some(end) => end,
                    None => return 1,
                };
                let path_bytes = match memory.data(&caller).get(start..end) {
                    Some(bytes) => bytes.to_vec(),
                    None => return 1,
                };
                let path = match String::from_utf8(path_bytes) {
                    Ok(path) => path,
                    Err(_) => return 1,
                };
                let key = path.trim_start_matches('/');
                let key = if key.is_empty() { &path } else { key };
                match caller.data().effects.fs().write(key, value) {
                    Ok(_) => 0,
                    Err(_) => 1,
                }
            },
        )?;

        linker.func_wrap(
            "ledger",
            "ledger_fs_read",
            |mut caller: Caller<'_, WasmStoreData>, ptr: u32, len: u32| -> i64 {
                let memory = match caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                {
                    Some(memory) => memory,
                    None => return -2,
                };
                let start = ptr as usize;
                let end = match start.checked_add(len as usize) {
                    Some(end) => end,
                    None => return -2,
                };
                let path_bytes = match memory.data(&caller).get(start..end) {
                    Some(bytes) => bytes.to_vec(),
                    None => return -2,
                };
                let path = match String::from_utf8(path_bytes) {
                    Ok(path) => path,
                    Err(_) => return -2,
                };
                let key = path.trim_start_matches('/');
                let key = if key.is_empty() { &path } else { key };
                match caller.data().effects.fs().read(key) {
                    Ok(Some(value)) => value as i64,
                    Ok(None) => -1,
                    Err(_) => -2,
                }
            },
        )?;

        linker.func_wrap(
            "ledger",
            "ledger_fs_crash",
            |caller: Caller<'_, WasmStoreData>| {
                caller.data().effects.fs().crash();
            },
        )?;

        // Shadow the preview1 `random_get` import so each WASI randomness
        // crossing journals exactly one `RngDraw` entry. The built-in preview1
        // handler draws through the context RNG without journaling, which would
        // leave the WASI random effect invisible to the journal.
        linker.allow_shadowing(true);
        linker.func_wrap(
            "wasi_snapshot_preview1",
            "random_get",
            |mut caller: Caller<'_, WasmStoreData>, buf: u32, len: u32| -> Result<u32, Error> {
                caller.data_mut().effects.journal_append(
                    EntryKind::RngDraw,
                    [],
                    EntryPayload::RngDraw(ledger_format::RngDrawPayload {
                        stream: WASI_RANDOM_STREAM,
                        draw_index: 0,
                        content: (len as u64).to_le_bytes().to_vec(),
                    }),
                );
                // One u32 word per byte, matching the per-byte sampling the
                // built-in preview1 handler applied, so the guest-visible bytes
                // stay identical to the pre-journaling behavior.
                let mut wasi_random = caller.data_mut().wasi_random.clone();
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or_else(|| Error::msg("guest has no exported memory"))?;
                let start = buf as usize;
                let end = start
                    .checked_add(len as usize)
                    .ok_or_else(|| Error::msg("random_get length overflow"))?;
                let bytes = memory
                    .data_mut(&mut caller)
                    .get_mut(start..end)
                    .ok_or_else(|| Error::msg("random_get buffer out of bounds"))?;
                for byte in bytes {
                    *byte = wasi_random.next_u32() as u8;
                }
                caller.data_mut().wasi_random = wasi_random;
                Ok(0)
            },
        )?;

        // SimFs-backed preview1 filesystem shadow. Deterministic and journaled
        // through the same `SimBackend::fs` that native code uses.

        linker.func_wrap(
            "wasi_snapshot_preview1",
            "path_open",
            |mut caller: Caller<'_, WasmStoreData>,
             _dirfd: u32,
             _dirflags: u32,
             path_ptr: u32,
             path_len: u32,
             _oflags: u32,
             fs_rights_base: u64,
             _fs_rights_inh: u64,
             fdflags: u32,
             opened_fd_ptr: u32|
             -> Result<u32, Error> {
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or_else(|| Error::msg("guest has no exported memory"))?;
                let start = path_ptr as usize;
                let end = start
                    .checked_add(path_len as usize)
                    .ok_or_else(|| Error::msg("path_open length overflow"))?;
                let path_bytes = memory
                    .data(&caller)
                    .get(start..end)
                    .ok_or_else(|| Error::msg("path_open read out of bounds"))?
                    .to_vec();
                let path = String::from_utf8(path_bytes)
                    .map_err(|_| Error::msg("path_open path not utf8"))?;
                let key = path.trim_start_matches('/').to_owned();
                let key = if key.is_empty() { path.clone() } else { key };
                // Preview1 rights bits the u64-cell store can honor.
                const RIGHT_FD_READ: u64 = 1 << 1;
                const RIGHT_FD_SEEK: u64 = 1 << 3;
                const RIGHT_FD_WRITE: u64 = 1 << 6;
                const FDFLAGS_APPEND: u32 = 0x0001;
                let rights = crate::wasi_fs::FdRights {
                    read: fs_rights_base & RIGHT_FD_READ != 0,
                    write: fs_rights_base & RIGHT_FD_WRITE != 0,
                    seek: fs_rights_base & RIGHT_FD_SEEK != 0,
                };
                let flags = crate::wasi_fs::FdFlags {
                    append: fdflags & FDFLAGS_APPEND != 0,
                };
                let opened = caller
                    .data()
                    .wasi_fs
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .open_with_flags(&key, rights, flags);
                let fd_to_write = match opened {
                    Ok(fd) => fd,
                    Err(_) => return Ok(24), // EBADF: table full or invalid.
                };
                let mem = memory.data_mut(&mut caller);
                let dst = opened_fd_ptr as usize;
                if dst.checked_add(4).is_none() || dst + 4 > mem.len() {
                    return Err(Error::msg("path_open opened_fd out of bounds"));
                }
                mem[dst..dst + 4].copy_from_slice(&fd_to_write.to_le_bytes());
                Ok(0)
            },
        )?;

        linker.func_wrap(
            "wasi_snapshot_preview1",
            "fd_write",
            |mut caller: Caller<'_, WasmStoreData>,
             fd: u32,
             iovs_ptr: u32,
             iovs_len: u32,
             nwritten_ptr: u32|
             -> Result<u32, Error> {
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or_else(|| Error::msg("guest has no exported memory"))?;
                // Collect bytes from iovecs under hard caps; a cap violation is
                // a WASI errno, a memory violation is a trap.
                let collected = match gather_write_payload(memory.data(&caller), iovs_ptr, iovs_len)
                {
                    Ok(payload) => payload,
                    Err(Some(errno)) => return Ok(errno),
                    Err(None) => return Err(Error::msg("fd_write iovec out of bounds")),
                };
                let total = u32::try_from(collected.len())
                    .map_err(|_| Error::msg("fd_write payload exceeds u32"))?;
                if fd == 1 {
                    // stdout: capture deterministically.
                    let sink = caller.data().stdout_sink.clone();
                    sink.lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .extend_from_slice(&collected);
                    let mem = memory.data_mut(&mut caller);
                    let dst = nwritten_ptr as usize;
                    if dst.checked_add(4).is_none() || dst + 4 > mem.len() {
                        return Err(Error::msg("fd_write nwritten out of bounds"));
                    }
                    mem[dst..dst + 4].copy_from_slice(&total.to_le_bytes());
                    return Ok(0);
                }
                if fd == 2 {
                    let mem = memory.data_mut(&mut caller);
                    let dst = nwritten_ptr as usize;
                    if dst.checked_add(4).is_none() || dst + 4 > mem.len() {
                        return Err(Error::msg("fd_write nwritten out of bounds"));
                    }
                    mem[dst..dst + 4].copy_from_slice(&total.to_le_bytes());
                    return Ok(0);
                }
                let path_opt = {
                    let table = caller
                        .data()
                        .wasi_fs
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    // Closed or non-granted handles fail before any path is
                    // resolved, so a revoked capability cannot reach the store.
                    match table.check_io(fd, true) {
                        Ok(()) => table.get(fd).map(|description| description.path.clone()),
                        Err(_) => None,
                    }
                };
                let path = match path_opt {
                    Some(path) => path,
                    None => return Ok(8),
                };
                let value = bytes_to_u64(&collected);
                if let Err(error) = caller.data().effects.fs().write(&path, value) {
                    // A journal failure must never disappear on a replay path:
                    // record the typed error and surface an I/O errno to the
                    // guest instead of a silent success.
                    return Ok(record_write_failure(
                        &caller.data().effects.journal_error,
                        error.into_journal(),
                    ));
                }
                let mem = memory.data_mut(&mut caller);
                let dst = nwritten_ptr as usize;
                if dst.checked_add(4).is_none() || dst + 4 > mem.len() {
                    return Err(Error::msg("fd_write nwritten out of bounds"));
                }
                mem[dst..dst + 4].copy_from_slice(&total.to_le_bytes());
                Ok(0)
            },
        )?;

        linker.func_wrap(
            "wasi_snapshot_preview1",
            "fd_read",
            |mut caller: Caller<'_, WasmStoreData>,
             fd: u32,
             iovs_ptr: u32,
             iovs_len: u32,
             nread_ptr: u32|
             -> Result<u32, Error> {
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or_else(|| Error::msg("guest has no exported memory"))?;
                let path_opt = {
                    let table = caller
                        .data()
                        .wasi_fs
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    // A read requires the read right on an open handle.
                    match table.check_io(fd, false) {
                        Ok(()) => table.get(fd).map(|description| description.path.clone()),
                        Err(_) => None,
                    }
                };
                let path = match path_opt {
                    Some(path) => path,
                    None => return Ok(8),
                };
                let value_opt = caller
                    .data()
                    .effects
                    .fs()
                    .read(&path)
                    .map_err(|error| Error::msg(format!("fs read: {error}")))?;
                let bytes = match value_opt {
                    Some(value) => value.to_le_bytes().to_vec(),
                    None => Vec::new(),
                };
                // Cap the iovec count like fd_write: a hostile count must not
                // drive an unbounded host-side loop.
                if iovs_len > MAX_WASI_IOVECS {
                    return Ok(WASI_ERRNO_INVAL);
                }
                let mut written: u32 = 0;
                let mut remaining = bytes.as_slice();
                for index in 0..iovs_len {
                    if remaining.is_empty() {
                        break;
                    }
                    let iov_off = (iovs_ptr as usize)
                        .checked_add((index as usize) * 8)
                        .ok_or_else(|| Error::msg("fd_read iov overflow"))?;
                    let iov_end = iov_off
                        .checked_add(8)
                        .ok_or_else(|| Error::msg("fd_read iov end overflow"))?;
                    let iov_bytes = memory
                        .data(&caller)
                        .get(iov_off..iov_end)
                        .ok_or_else(|| Error::msg("fd_read iov out of bounds"))?
                        .to_vec();
                    let buf_ptr = u32::from_le_bytes([
                        iov_bytes[0],
                        iov_bytes[1],
                        iov_bytes[2],
                        iov_bytes[3],
                    ]) as usize;
                    let buf_len = u32::from_le_bytes([
                        iov_bytes[4],
                        iov_bytes[5],
                        iov_bytes[6],
                        iov_bytes[7],
                    ]) as usize;
                    let to_copy = core::cmp::min(remaining.len(), buf_len);
                    if to_copy == 0 {
                        continue;
                    }
                    let end = buf_ptr
                        .checked_add(to_copy)
                        .ok_or_else(|| Error::msg("fd_read buf overflow"))?;
                    let mem = memory.data_mut(&mut caller);
                    if end > mem.len() {
                        return Err(Error::msg("fd_read buf out of bounds"));
                    }
                    mem[buf_ptr..buf_ptr + to_copy].copy_from_slice(&remaining[..to_copy]);
                    remaining = &remaining[to_copy..];
                    // buf_len derives from wasm32 iovec u32 fields, so to_copy
                    // always fits u32 without truncation.
                    written = written.saturating_add(to_copy as u32);
                }
                let mem = memory.data_mut(&mut caller);
                let dst = nread_ptr as usize;
                if dst.checked_add(4).is_none() || dst + 4 > mem.len() {
                    return Err(Error::msg("fd_read nread out of bounds"));
                }
                mem[dst..dst + 4].copy_from_slice(&written.to_le_bytes());
                Ok(0)
            },
        )?;

        linker.func_wrap(
            "wasi_snapshot_preview1",
            "fd_close",
            |caller: Caller<'_, WasmStoreData>, fd: u32| -> Result<u32, Error> {
                let removed = caller
                    .data()
                    .wasi_fs
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .close(fd);
                if removed || fd == 0 || fd == 1 || fd == 2 {
                    Ok(0)
                } else {
                    Ok(8)
                }
            },
        )?;

        linker.func_wrap(
            "wasi_snapshot_preview1",
            "fd_filestat_get",
            |mut caller: Caller<'_, WasmStoreData>, fd: u32, buf_ptr: u32| -> Result<u32, Error> {
                let is_virtual = caller
                    .data()
                    .wasi_fs
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains(fd);
                if !is_virtual {
                    return Ok(8);
                }
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or_else(|| Error::msg("guest has no exported memory"))?;
                let start = buf_ptr as usize;
                let end = start
                    .checked_add(64)
                    .ok_or_else(|| Error::msg("filestat overflow"))?;
                let mem = memory.data_mut(&mut caller);
                if end > mem.len() {
                    return Err(Error::msg("filestat out of bounds"));
                }
                for byte in &mut mem[start..end] {
                    *byte = 0;
                }
                Ok(0)
            },
        )?;

        Ok(linker)
    }
}

impl Effects for WasmBackend {
    fn clock(&self) -> Clock {
        self.store.data().effects.clock()
    }

    fn rng(&mut self, stream: StreamId) -> &mut impl rand_core::Rng {
        self.store.data_mut().effects.rng(stream)
    }

    async fn sleep(&self, d: core::time::Duration) {
        self.store.data().effects.sleep(d).await
    }

    fn net(&self) -> &dyn Net {
        self.store.data().effects.net()
    }

    fn fs(&self) -> &dyn Fs {
        self.store.data().effects.fs()
    }
}

#[cfg(test)]
mod fd_write_boundary_tests {
    use super::*;

    #[test]
    fn gather_write_payload_boundaries() {
        let mut memory = vec![0u8; 512];
        // iovec[0] at [32..40]: buf_ptr 100, len 4.
        memory[32..36].copy_from_slice(&100u32.to_le_bytes());
        memory[36..40].copy_from_slice(&4u32.to_le_bytes());
        memory[100..104].copy_from_slice(&[0x2a, 0x2b, 0x2c, 0x2d]);
        // iovec[1] at [40..48]: buf_ptr 200, len 2.
        memory[40..44].copy_from_slice(&200u32.to_le_bytes());
        memory[44..48].copy_from_slice(&2u32.to_le_bytes());
        memory[200..202].copy_from_slice(&[0x0e, 0x0f]);

        let payload = gather_write_payload(&memory, 32, 2).expect("gather");
        assert_eq!(payload, [0x2a, 0x2b, 0x2c, 0x2d, 0x0e, 0x0f]);
        // An empty iovec list gathers nothing.
        assert!(
            gather_write_payload(&memory, 32, 0)
                .expect("empty")
                .is_empty()
        );

        // Oversized iovec count is a WASI errno, not a trap and not a hang.
        assert_eq!(
            gather_write_payload(&memory, 32, MAX_WASI_IOVECS + 1),
            Err(Some(WASI_ERRNO_INVAL))
        );
        // Aggregate payload over the byte cap is a WASI errno, checked before
        // the buffer bounds are consulted.
        memory[36..40].copy_from_slice(&((MAX_WASI_WRITE_BYTES + 1) as u32).to_le_bytes());
        assert_eq!(
            gather_write_payload(&memory, 32, 1),
            Err(Some(WASI_ERRNO_INVAL))
        );
        // A buffer beyond guest memory stays a trap-class violation.
        memory[36..40].copy_from_slice(&500u32.to_le_bytes());
        assert_eq!(gather_write_payload(&memory, 32, 1), Err(None));
        // An iovec array beyond guest memory is a trap-class violation.
        assert_eq!(gather_write_payload(&memory, 500, 2), Err(None));
        // An iovec pointer whose stride overflows is a trap-class violation.
        assert_eq!(gather_write_payload(&memory, u32::MAX, 1), Err(None));
        // The total written byte count stays within u32 by the byte cap.
        let payload = gather_write_payload(&memory, 32, 0).expect("gather");
        u32::try_from(payload.len()).expect("bounded payload fits u32");
    }

    /// The journal-failure path must map to `EIO` and keep the typed error
    /// on the backend slot, never a silent success.
    #[test]
    fn record_write_failure_maps_to_io_errno_and_keeps_typed_error() {
        let slot = Mutex::new(None);
        let errno = record_write_failure(
            &slot,
            JournalError::InvariantViolation("injected".to_string()),
        );
        assert_eq!(errno, WASI_ERRNO_IO);
        match slot.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            Some(JournalError::InvariantViolation(cause)) => assert_eq!(cause, "injected"),
            other => panic!("typed error must be recorded, got {other:?}"),
        }
        // A second failure never overwrites: the slot reports the first
        // typed cause, matching the executor's first-wins contract (a second
        // broken append does not change which failure invalidated the run).
        let second = record_write_failure(&slot, JournalError::MissingParent([3u8; 32]));
        assert_eq!(second, WASI_ERRNO_IO);
        match slot.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            Some(JournalError::InvariantViolation(cause)) => assert_eq!(cause, "injected"),
            other => panic!("first failure must win, got {other:?}"),
        }
    }

    /// A minimal core module that imports `fd_write` and `path_open`, exports
    /// a 1-page `memory`, and forwards its own arguments to the imports. The
    /// exports let a test drive the host functions through real guest
    /// execution, so `Caller::get_export` resolves the instance memory.
    fn forwarder_module(engine: &Engine) -> Module {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
        // Type section: fd_write (i32x4 -> i32), path_open (i32x5,i64x2,i32x2 -> i32).
        bytes.extend_from_slice(&[
            0x01, 0x16, 0x02, 0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f, 0x60, 0x09, 0x7f,
            0x7f, 0x7f, 0x7f, 0x7f, 0x7e, 0x7e, 0x7f, 0x7f, 0x01, 0x7f,
        ]);
        // Import section: wasi fd_write (type 0), wasi path_open (type 1).
        let module_name = b"wasi_snapshot_preview1";
        let mut imports = vec![0x02u8];
        for (name, type_index) in [
            (b"fd_write".as_slice(), 0u32),
            (b"path_open".as_slice(), 1u32),
        ] {
            imports.push(module_name.len() as u8);
            imports.extend_from_slice(module_name);
            imports.push(name.len() as u8);
            imports.extend_from_slice(name);
            imports.push(0x00);
            imports.push(type_index as u8);
        }
        bytes.push(0x02);
        bytes.push(imports.len() as u8);
        bytes.extend_from_slice(&imports);
        // Function section: write_test (type 0), open_test (type 1).
        bytes.extend_from_slice(&[0x03, 0x03, 0x02, 0x00, 0x01]);
        // Memory section: 1 page, exported below.
        bytes.extend_from_slice(&[0x05, 0x03, 0x01, 0x00, 0x01]);
        // Export section: memory, write_test, open_test.
        let mut exports = vec![0x03u8];
        exports.extend_from_slice(&[0x06]);
        exports.extend_from_slice(b"memory");
        exports.extend_from_slice(&[0x02, 0x00]);
        exports.extend_from_slice(&[0x0a]);
        exports.extend_from_slice(b"write_test");
        exports.extend_from_slice(&[0x00, 0x02]);
        exports.extend_from_slice(&[0x09]);
        exports.extend_from_slice(b"open_test");
        exports.extend_from_slice(&[0x00, 0x03]);
        bytes.push(0x07);
        bytes.push(exports.len() as u8);
        bytes.extend_from_slice(&exports);
        // Code section: write_test forwards 4 i32s, open_test forwards 9.
        let mut code = vec![0x02u8];
        let write_body = [
            0x00, 0x20, 0x00, 0x20, 0x01, 0x20, 0x02, 0x20, 0x03, 0x10, 0x00, 0x0b,
        ];
        code.push(write_body.len() as u8);
        code.extend_from_slice(&write_body);
        let open_body = [
            0x00, 0x20, 0x00, 0x20, 0x01, 0x20, 0x02, 0x20, 0x03, 0x20, 0x04, 0x20, 0x05, 0x20,
            0x06, 0x20, 0x07, 0x20, 0x08, 0x10, 0x01, 0x0b,
        ];
        code.push(open_body.len() as u8);
        code.extend_from_slice(&open_body);
        bytes.push(0x0a);
        bytes.push(code.len() as u8);
        bytes.extend_from_slice(&code);
        Module::new(engine, &bytes).expect("forwarder module")
    }

    /// The real host plumbing: a valid stdout write, the oversized-iovec
    /// errno, and a full path_open + fd_write file write that journals an
    /// `FsWrite` on the valid path. The guest forwarders drive the host
    /// functions through real execution, so the instance memory stays the
    /// export the host functions see.
    #[test]
    fn fd_write_host_error_and_valid_paths() {
        let engine = WasmBackend::new_engine().expect("engine");
        let mut backend = WasmBackend::with_engine(engine.clone(), SeedTree::new([0x42; 32]))
            .expect("store scaffolding");
        let linker = WasmBackend::build_linker(&engine).expect("linker");
        let module = forwarder_module(&engine);
        let instance = linker
            .instantiate(&mut backend.store, &module)
            .expect("instantiate forwarder module");
        backend.store.set_fuel(1 << 20).expect("fuel for the guest");
        let memory = instance
            .get_memory(&mut backend.store, "memory")
            .expect("exported memory");

        let write_via_guest = |store: &mut Store<WasmStoreData>,
                               fd: u32,
                               iovs_ptr: u32,
                               iovs_len: u32,
                               nwritten_ptr: u32|
         -> u32 {
            instance
                .get_typed_func::<(u32, u32, u32, u32), u32>(&mut *store, "write_test")
                .expect("write_test export")
                .call(&mut *store, (fd, iovs_ptr, iovs_len, nwritten_ptr))
                .expect("write_test call")
        };
        let open_via_guest = |store: &mut Store<WasmStoreData>,
                              path_ptr: u32,
                              path_len: u32,
                              opened_fd_ptr: u32|
         -> u32 {
            instance
                .get_typed_func::<(u32, u32, u32, u32, u32, u64, u64, u32, u32), u32>(
                    &mut *store,
                    "open_test",
                )
                .expect("open_test export")
                .call(
                    &mut *store,
                    // dirfd, dirflags, path, len, oflags, rights_base
                    // (read+write granted), rights_inheriting, fdflags, out.
                    (
                        3,
                        0,
                        path_ptr,
                        path_len,
                        0,
                        (1 << 1) | (1 << 6),
                        0,
                        0,
                        opened_fd_ptr,
                    ),
                )
                .expect("open_test call")
        };

        // Valid stdout write through a real iovec array.
        let iovs = 32usize;
        let nwritten = 64usize;
        {
            let mem = memory.data_mut(&mut backend.store);
            mem[iovs..iovs + 8]
                .copy_from_slice(&[100u32.to_le_bytes(), 4u32.to_le_bytes()].concat());
            mem[100..104].copy_from_slice(&[1, 2, 3, 4]);
        }
        let errno = write_via_guest(&mut backend.store, 1, iovs as u32, 1, nwritten as u32);
        assert_eq!(errno, 0);
        {
            let mem = memory.data(&backend.store);
            assert_eq!(&mem[nwritten..nwritten + 4], &4u32.to_le_bytes());
        }
        assert_eq!(
            backend
                .store
                .data()
                .stdout_sink
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_slice(),
            &[1, 2, 3, 4]
        );

        // Oversized iovec count returns an errno without touching the buffer.
        let errno = write_via_guest(
            &mut backend.store,
            1,
            iovs as u32,
            MAX_WASI_IOVECS + 1,
            nwritten as u32,
        );
        assert_eq!(errno, WASI_ERRNO_INVAL);

        // Valid file write: path_open then fd_write journals an FsWrite and
        // reports the exact byte count on the valid path.
        let path_ptr = 200usize;
        let opened_fd_ptr = 208usize;
        {
            let mem = memory.data_mut(&mut backend.store);
            mem[path_ptr..path_ptr + 5].copy_from_slice(b"/data");
        }
        let open_errno =
            open_via_guest(&mut backend.store, path_ptr as u32, 5, opened_fd_ptr as u32);
        assert_eq!(open_errno, 0);
        let fd = {
            let mem = memory.data(&backend.store);
            u32::from_le_bytes(
                mem[opened_fd_ptr..opened_fd_ptr + 4]
                    .try_into()
                    .expect("opened fd bytes"),
            )
        };
        assert!(fd >= 3, "deterministic fd must avoid stdio fds");
        {
            let mem = memory.data_mut(&mut backend.store);
            mem[iovs..iovs + 8]
                .copy_from_slice(&[64u32.to_le_bytes(), 8u32.to_le_bytes()].concat());
            mem[64..72].copy_from_slice(&[7u8; 8]);
        }
        let errno = write_via_guest(&mut backend.store, fd, iovs as u32, 1, nwritten as u32);
        assert_eq!(errno, 0);
        {
            let mem = memory.data(&backend.store);
            assert_eq!(&mem[nwritten..nwritten + 4], &8u32.to_le_bytes());
        }
        let kinds: Vec<EntryKind> = backend
            .store
            .data()
            .effects
            .journal_snapshot()
            .entries()
            .map(|entry| entry.data.kind)
            .collect();
        assert!(
            kinds.iter().any(|kind| matches!(kind, EntryKind::FsWrite)),
            "journal must contain FsWrite on the valid path, got {kinds:?}"
        );

        // A read-only open (read right only) must fail fd_write with EBADF
        // before any path is resolved or journaled.
        {
            let mem = memory.data_mut(&mut backend.store);
            mem[path_ptr..path_ptr + 3].copy_from_slice(b"/rd");
        }
        let open_errno = instance
            .get_typed_func::<(u32, u32, u32, u32, u32, u64, u64, u32, u32), u32>(
                &mut backend.store,
                "open_test",
            )
            .expect("open_test export")
            .call(
                &mut backend.store,
                (
                    3,
                    0,
                    path_ptr as u32,
                    3,
                    0,
                    1 << 1,
                    0,
                    0,
                    opened_fd_ptr as u32,
                ),
            )
            .expect("open_test call");
        assert_eq!(open_errno, 0);
        let rd_fd = {
            let mem = memory.data(&backend.store);
            u32::from_le_bytes(
                mem[opened_fd_ptr..opened_fd_ptr + 4]
                    .try_into()
                    .expect("opened fd bytes"),
            )
        };
        let errno = write_via_guest(&mut backend.store, rd_fd, iovs as u32, 1, nwritten as u32);
        assert_eq!(errno, 8, "a write on a read-only handle must fail closed");
    }
}
