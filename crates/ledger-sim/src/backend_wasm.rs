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
//!   buffer; the observable output is part of the journal.
//! - Bounded execution via fuel: a runaway guest traps at the fuel budget
//!   instead of looping forever.
//! - NaN canonicalization and relaxed-SIMD determinism close the two CPU
//!   nondeterminism sources.
//!
//! The wasmtime engine runs with `Config::rr(RRConfig::Recording)`, which
//! enables engine-enforced execution-trace determinism
//! (`validate_rr_determinism_conflicts` rejects settings that allow
//! nondeterminism). Full WASI filesystem virtualization onto SimFs is not
//! implemented: wasmtime-wasi 47's preview1 surface is cap-std-bound (no
//! pluggable in-memory filesystem trait; see wasmtime issue 8963), and the
//! WASIp2 `Host` filesystem trait requires the guest to be a component, not a
//! preview1 core module.
//!
//! Backend-portable decision-trace replay (a journal recorded on native
//! replaying on Wasm) is deferred. Replay in the native path pins scheduler
//! ready-list choices (`Simulation::with_replay`); mirroring that on the Wasm
//! backend would require a decision-trace replay protocol inside the guest,
//! which is not yet specified. The differential port-validation oracle covers
//! the same ground: the same workload runs natively and in the guest with one
//! seed, and the journals must hash identically.

use crate::backend_sim::SimBackend;
use crate::effects::{Effects, Fs, Net};
use crate::net::Message;
use crate::seedtree::SeedTree;
use crate::time::Clock;
use futures::executor::block_on;
use ledger_format::{ActorId, EntryKind, Hash, Payload, StreamId};
use ledger_journal::{Journal, JournalError};
use rand_chacha::ChaCha20Rng;
use rand_core::Rng;
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
    fn append(&self, kind: EntryKind, parents: impl IntoIterator<Item = Hash>, payload: Payload) {
        let mut journal = self.journal.lock().unwrap_or_else(|e| e.into_inner());
        match journal.append(kind, self.actor, parents, payload) {
            Ok(_) => {}
            Err(error) => {
                *self.journal_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(error);
            }
        }
    }
}

/// WASI wall clock backed by virtual time.
///
/// Reports virtual time in nanosecond ticks, so `clock_time_get(Realtime)` is
/// deterministic across runs. Each read journals one `ClockRead` entry.
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
            .append(EntryKind::ClockRead, [], Payload::Number(ticks));
        std::time::Duration::from_nanos(ticks * NS_PER_TICK)
    }
}

/// WASI monotonic clock backed by virtual time.
///
/// Each read journals one `ClockRead` entry carrying the tick count, matching
/// the executor's clock-read journaling.
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
            .append(EntryKind::ClockRead, [], Payload::Number(ticks));
        ticks * NS_PER_TICK
    }
}

/// A stdout sink that appends guest `fd_write` output to a shared buffer.
///
/// The shared buffer is drained into the store's output after each call, so
/// guest-observable output is deterministic and journaled with the run.
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
}

/// Wasm backend: wraps a wasmtime engine, store, and guest instance.
///
/// Implements the `Effects` surface by delegating to the inner `SimBackend`.
/// The guest crosses the boundary through the `ledger` host functions, which
/// forward to the same effects; WASI `random_get`, `clock_time_get`, and
/// stdout are virtualized onto the seed tree, virtual clock, and output
/// buffer respectively.
pub struct WasmBackend {
    engine: Engine,
    store: Store<WasmStoreData>,
    instance: Option<Instance>,
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
            journal: Arc::clone(effects.journal()),
            journal_error: Arc::clone(effects.journal_error_slot()),
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
            },
        );
        Ok(Self {
            engine,
            store,
            instance: None,
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
    pub fn load_guest(&mut self, wasm: &[u8]) -> WasmResult<()> {
        let module = Module::new(&self.engine, wasm)?;
        let linker = Self::build_linker(&self.engine)?;
        let instance = linker.instantiate(&mut self.store, &module)?;
        self.instance = Some(instance);
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
    /// WASI stdout).
    pub fn run_export(&mut self, entry: &str) -> WasmResult<Vec<u8>> {
        let instance = self.instance.as_ref().ok_or(WasmError::NoGuest)?;
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
                // A trap may be a genuine guest fault or fuel exhaustion; a
                // zero fuel remainder pinpoints the latter.
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

    /// Return the journaled history of the inner sim backend.
    pub fn journal(&self) -> &Mutex<Journal> {
        self.store.data().effects.journal()
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
                    payload,
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
                    Some(message) => message.payload as i64,
                    None => -1,
                }
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
                    EntryKind::RngDraw {
                        stream: WASI_RANDOM_STREAM,
                    },
                    [],
                    Payload::Number(len as u64),
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
