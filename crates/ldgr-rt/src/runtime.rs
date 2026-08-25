// ledger-lint:allow - test-only probe; verifies thread-local registry isolation
//! Runtime facade entrypoint.
//!
//! Why: the SUT should not name `ledger-sim` types. `Handle` is the single
//! porting seam. The same async body runs under `Simulation` in sim and under
//! `tokio` otherwise.
//!
//! Public contract: every item here has one name, one signature, and one
//! bound set under every feature combination (none, `sim`, `sim-link`).
//! Feature-specific behavior lives in private backends behind `run_main`.
//!
//! In production `sim` is IPC-only: `run()` delegates to the `ledger
//! rt-server` process over a Unix socket so the SUT crate stays Apache-2.0.
//! The `sim-link` feature keeps the old direct `ledger-sim` link for
//! workspace tests and examples. It is not for SUT crates published outside
//! the workspace.
//!
//! Program transport: caller programs run in this process on the direct
//! backends (none, `sim-link`). Programs do not cross the IPC boundary, so
//! under `sim`-only `run(closure)` returns [`RuntimeError::ProgramNotTransportable`]
//! instead of running anything else, and named execution goes through
//! [`register_workload`] (direct backends) or `run_named` (server workloads
//! such as `"kv"`). See the README for the per-feature truth table.

use core::future::Future;
use core::pin::Pin;
use core::time::Duration;
use std::cell::RefCell;

use ledger_format::ActorId;
use thiserror::Error;

#[cfg(all(feature = "sim", not(feature = "sim-link")))]
use crate::ipc::EngineProcess;
use crate::net::{Conn, shared_network};
use crate::rng::{DetRng, StreamId};
#[cfg(feature = "sim-link")]
use ledger_sim::{Effects as _, RunConfig as SimRunConfig, SeedTree, Simulation};

// ---------------------------------------------------------------------------
// Thread-local current handle
// ---------------------------------------------------------------------------

thread_local! {
    static CURRENT: RefCell<Option<Handle>> = const { RefCell::new(None) };
}

#[cfg(any(feature = "sim-link", not(any(feature = "sim", feature = "sim-link"))))]
fn set_current(handle: Handle) {
    CURRENT.with(|c| *c.borrow_mut() = Some(handle));
}

#[cfg(any(feature = "sim-link", not(any(feature = "sim", feature = "sim-link"))))]
fn clear_current() {
    CURRENT.with(|c| *c.borrow_mut() = None);
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for `run`.
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// Root seed for deterministic runs. Ignored outside `sim`.
    pub seed: [u8; 32],
    /// Maximum executor steps before `StepLimit`.
    ///
    /// Enforced by the simulation backends (`sim`, `sim-link`) only; the
    /// direct tokio backend runs programs to completion without a step
    /// budget.
    pub max_steps: usize,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            seed: [0u8; 32],
            max_steps: 10_000,
        }
    }
}

impl RunConfig {
    /// Return a builder initialized from [`RunConfig::default`].
    pub fn builder() -> RunConfigBuilder {
        RunConfigBuilder::default()
    }

    /// Root seed for deterministic runs.
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    /// Maximum executor steps before `StepLimit`.
    pub fn max_steps(&self) -> usize {
        self.max_steps
    }
}

/// Builder for [`RunConfig`] with stable, additive setters.
///
/// Defaults mirror [`RunConfig::default`]. Call [`RunConfigBuilder::build`]
/// to finish.
#[derive(Debug, Clone)]
pub struct RunConfigBuilder {
    seed: [u8; 32],
    max_steps: usize,
}

impl Default for RunConfigBuilder {
    fn default() -> Self {
        Self {
            seed: [0u8; 32],
            max_steps: 10_000,
        }
    }
}

impl RunConfigBuilder {
    /// Create a new builder from defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the root seed.
    pub fn seed(mut self, seed: [u8; 32]) -> Self {
        self.seed = seed;
        self
    }

    /// Set the instruction budget.
    pub fn max_steps(mut self, max_steps: usize) -> Self {
        self.max_steps = max_steps;
        self
    }

    /// Build the [`RunConfig`].
    pub fn build(self) -> RunConfig {
        RunConfig {
            seed: self.seed,
            max_steps: self.max_steps,
        }
    }
}

impl From<RunConfigBuilder> for RunConfig {
    fn from(builder: RunConfigBuilder) -> Self {
        builder.build()
    }
}

// ---------------------------------------------------------------------------
// Result / error
// ---------------------------------------------------------------------------

/// Whether a run reached completion, and why it stopped when it did not.
///
/// Facade-local carrier: liveness detail requires the simulation backend;
/// other builds report [`RunCompletion::Completed`] for their runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunCompletion {
    /// Every task finished.
    Completed,
    /// The step budget ran out while tasks were still ready or blocked.
    BudgetExhausted,
    /// No task was ready and at least one task was still pending.
    Blocked,
}

#[cfg(feature = "sim")]
impl From<ledger_sim::RunOutcome> for RunCompletion {
    fn from(outcome: ledger_sim::RunOutcome) -> Self {
        match outcome {
            ledger_sim::RunOutcome::Completed => Self::Completed,
            ledger_sim::RunOutcome::BudgetExhausted => Self::BudgetExhausted,
            ledger_sim::RunOutcome::Blocked => Self::Blocked,
        }
    }
}

/// Outcome of a completed run.
#[derive(Debug, Clone)]
pub struct RunResult {
    /// Root hash of the journal the backend produced. `None` when the run
    /// produced no journal (non-sim builds).
    pub journal_root: Option<[u8; 32]>,
    /// Number of executor steps consumed.
    pub steps: usize,
    /// Whether the run completed, and the liveness reason when it did not.
    pub outcome: RunCompletion,
}

/// Journal invariant failure raised by a simulation backend.
///
/// Why a facade-local carrier: `RuntimeError` must expose one variant set
/// under every feature combination, but the typed `ledger-journal` error
/// links only under `sim-link`. There the typed cause stays reachable via
/// [`core::error::Error::source`]; other builds carry the message only.
#[derive(Debug)]
pub struct JournalFault {
    message: Box<str>,
    source: Option<Box<dyn core::error::Error + Send + Sync>>,
}

impl JournalFault {
    /// Build from a description when the typed cause is unavailable.
    pub fn from_message(message: impl Into<Box<str>>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Preserve the typed journal cause (available only under `sim-link`).
    #[cfg(feature = "sim-link")]
    pub(crate) fn from_journal_error(error: ledger_journal::JournalError) -> Self {
        Self {
            message: error.to_string().into(),
            source: Some(Box::new(error)),
        }
    }

    /// Description carried by this fault.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl core::fmt::Display for JournalFault {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl core::error::Error for JournalFault {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        let source: &(dyn core::error::Error + 'static) = self.source.as_deref()?;
        Some(source)
    }
}

/// Engine-process transport failure (spawn, connect, wire, timeout).
///
/// Same rationale as [`JournalFault`]: the typed [`crate::ipc::IpcError`]
/// cause links only with `sim` or `sim-link` and is preserved as `source`
/// there; other builds carry messages only.
#[derive(Debug)]
pub struct IpcFault {
    message: Box<str>,
    source: Option<Box<dyn core::error::Error + Send + Sync>>,
}

impl IpcFault {
    /// Build from a description when the typed cause is unavailable.
    pub fn from_message(message: impl Into<Box<str>>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Description carried by this fault.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl core::fmt::Display for IpcFault {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl core::error::Error for IpcFault {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        let source: &(dyn core::error::Error + 'static) = self.source.as_deref()?;
        Some(source)
    }
}

/// Errors from [`run`] and [`run_named`].
#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("simulation exceeded {limit} steps")]
    StepLimit { limit: usize },
    /// Journal invariant failed during a simulated run.
    #[error("journal error: {0}")]
    Journal(JournalFault),
    /// Engine-process transport failure (spawn, connect, wire, timeout).
    #[error("ipc error: {0}")]
    Ipc(IpcFault),
    /// The engine run completed without reporting a journal root.
    #[error("engine returned no journal root")]
    MissingRoot,
    /// A named workload was requested that no backend registry holds.
    #[error("no workload registered under {name:?}")]
    UnknownWorkload { name: Box<str> },
    /// A caller program cannot cross the IPC process boundary. Rebuild with
    /// `sim-link` for in-process deterministic execution, or run a registered
    /// server workload by name with [`run_named`] (for example `"kv"`).
    #[error(
        "caller programs do not cross the IPC boundary: rebuild with feature \
         `sim-link` for in-process execution, or run a registered server \
         workload by name via run_named (for example \"kv\")"
    )]
    ProgramNotTransportable,
    /// The tokio runtime for this build path failed to start.
    #[error("tokio runtime build failed: {0}")]
    Runtime(#[from] std::io::Error),
}

#[cfg(any(feature = "sim", feature = "sim-link"))]
impl From<crate::ipc::IpcError> for RuntimeError {
    fn from(error: crate::ipc::IpcError) -> Self {
        RuntimeError::Ipc(IpcFault {
            message: error.to_string().into(),
            source: Some(Box::new(error)),
        })
    }
}

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

/// Capability handle handed to the SUT main future.
///
/// The handle is the only way to touch time, RNG, net, and task spawning so
/// the surface cannot drift between the sim and non-sim paths.
///
/// The `actor` field pins the logical actor identity for multi-actor non-sim
/// routing. In `sim-link` mode the `Boundary` actor is authoritative for
/// journaling; `actor` mirrors the task id for convenience and `with_actor`
/// rebinds the non-sim queue only. Use `Handle::conn(from, to)` for arbitrary
/// pairs when full fan-out is needed.
pub struct Handle {
    #[cfg(feature = "sim-link")]
    boundary: Option<ledger_sim::Boundary>,
    // Only sim backends consume the seed today; the field stays on every
    // build so Handle literals keep one shape across feature combos.
    #[cfg_attr(not(feature = "sim-link"), allow(dead_code))]
    seed: [u8; 32],
    shared_net: crate::net::SharedNetwork,
    actor: ActorId,
}

impl Clone for Handle {
    fn clone(&self) -> Self {
        Self {
            #[cfg(feature = "sim-link")]
            boundary: self.boundary.clone(),
            seed: self.seed(),
            shared_net: self.shared_net.clone(),
            actor: self.actor,
        }
    }
}

impl Handle {
    /// Logical actor id this handle sends as.
    pub fn actor(&self) -> ActorId {
        self.actor
    }

    /// Root seed for the deterministic stream of this handle's draws.
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    /// Return a handle bound to `actor`.
    ///
    /// The new handle shares the same seed and shared network but sends and
    /// receives as `actor`. This enables multi-actor non-sim tests without
    /// reaching for the full `SimNet` outside simulation. In `sim-link` mode the
    /// journaling path still uses the `Boundary` task id; `with_actor` only
    /// affects the non-sim in-process net. For true multi-actor journaling,
    /// spawn separate tasks under `sim-link` instead.
    pub fn with_actor(&self, actor: ActorId) -> Self {
        Self {
            #[cfg(feature = "sim-link")]
            boundary: self.boundary.clone(),
            seed: self.seed(),
            shared_net: self.shared_net.clone(),
            actor,
        }
    }

    /// Try to fetch the thread-local handle set by `run`.
    ///
    /// Returns `None` when called outside a `run` context (for example in host
    /// setup code).
    pub fn current() -> Option<Self> {
        CURRENT.with(|c| c.borrow().clone())
    }

    /// Return a deterministic clock snapshot.
    ///
    /// Under `sim-link` with a live boundary this reads virtual time.
    /// Without a boundary the sim-link path is unreachable in normal runs
    /// and returns zero; non-sim builds read ambient time.
    pub fn clock(&self) -> crate::time::SimClock {
        #[cfg(feature = "sim-link")]
        {
            if let Some(b) = &self.boundary {
                return crate::time::SimClock::from_ticks(b.clock().now());
            }
            crate::time::SimClock::from_ticks(0)
        }
        #[cfg(not(feature = "sim-link"))]
        {
            crate::time::SimClock::ambient()
        }
    }

    /// Sleep for `duration`.
    ///
    /// Deterministic under `sim-link` with a live boundary (journaled
    /// `TimerSet` plus virtual time advance). Without a boundary the
    /// sim-link path is unreachable in normal runs and falls back to
    /// `tokio::time::sleep`. Under `sim` (IPC) this sleeps locally; the
    /// remote execution stays deterministic server-side via `rt-server`.
    pub async fn sleep(&self, duration: Duration) {
        #[cfg(feature = "sim-link")]
        {
            if let Some(b) = &self.boundary {
                b.sleep(duration).await;
                return;
            }
        }
        tokio::time::sleep(duration).await;
    }

    /// Return a deterministic RNG for `stream`.
    ///
    /// Each draw advances the stream and is journaled when a live
    /// `sim-link` boundary is present, so successive draws yield successive
    /// values and do not repeat. Hold the `DetRng` to draw repeatedly.
    /// Outside `sim-link` the stream is seeded from ambient entropy, so it
    /// is deterministic only per-handle, not across runs.
    pub fn rng(&mut self, stream: StreamId) -> DetRng {
        #[cfg(feature = "sim-link")]
        {
            if let Some(b) = &self.boundary {
                return DetRng::from_boundary(stream, b.clone());
            }
            let label = format!("app/{stream}");
            DetRng::from_chacha(stream, SeedTree::new(self.seed()).rng(&label))
        }
        #[cfg(not(feature = "sim-link"))]
        {
            DetRng::from_seed(stream)
        }
    }

    /// Convenience: next u64 from `stream`.
    ///
    /// Each call advances the stream, so successive calls yield successive
    /// values. This delegates to [`Handle::rng`] and journals the draw
    /// under `sim-link`.
    pub fn rng_next_u64(&mut self, stream: StreamId) -> u64 {
        self.rng(stream).next_u64()
    }

    /// Send a payload from `self.actor` to `to` via the facade net.
    ///
    /// Under `sim-link` this delegates to `Boundary::send` when a boundary is
    /// present. Outside `sim-link` it uses the shared in-process net bound to
    /// `self.actor`. Use `with_actor` to fan out as different actors without
    /// rebuilding the handle from scratch. Returns `false` when the link is
    /// partitioned or `to` exceeds the actor id range, mirroring an
    /// undeliverable link rather than truncating the id.
    #[track_caller]
    pub fn net_send(&self, to: usize, payload: u64) -> bool {
        let Ok(to_id) = u32::try_from(to) else {
            return false;
        };
        #[cfg(feature = "sim-link")]
        {
            if let Some(b) = &self.boundary {
                return b.send_tracked(to_id as usize, payload);
            }
        }
        Conn::new(self.actor, to_id, self.shared_net.clone()).send(payload)
    }

    /// Receive a payload addressed to `self.actor` from any sender via the facade net.
    ///
    /// Outside `sim-link` this polls the shared in-process net for messages whose
    /// destination equals `self.actor`. In `sim-link` it delegates to the boundary.
    pub async fn net_recv(&self) -> u64 {
        #[cfg(feature = "sim-link")]
        {
            if let Some(b) = &self.boundary {
                return b.recv().await;
            }
        }
        // Non-sim (and sim IPC): destination-based receive over the shared
        // in-process net; sender ids are never scanned or bounded here.
        loop {
            let payload = match self.shared_net.inner().lock() {
                Ok(mut net) => net.recv_for(self.actor),
                Err(_) => None,
            };
            if let Some(payload) = payload {
                return payload;
            }
            tokio::task::yield_now().await;
        }
    }

    /// Spawn a child task running `f(child_handle)`.
    ///
    /// One bound set under every feature combination: the erased future is
    /// non-`Send` on purpose, because every executor behind this facade polls
    /// tasks on one thread. Under `sim-link` with a live boundary the task
    /// joins the deterministic schedule. Otherwise it runs through
    /// `spawn_local` on the `LocalSet` installed by [`run`]; spawning outside
    /// `run` panics, mirroring bare `tokio::spawn` misuse.
    ///
    /// Interim limitation under `sim` (IPC): a locally spawned task would sit
    /// outside the journaled remote run, so meaningful spawns reach the engine
    /// only once programs cross the process boundary; see the README tradeoff
    /// note.
    pub fn spawn<F>(&self, f: F) -> crate::task::TaskId
    where
        F: FnOnce(Handle) -> Pin<Box<dyn Future<Output = ()>>> + 'static,
    {
        #[cfg(feature = "sim-link")]
        if let Some(boundary) = &self.boundary {
            let seed = self.seed();
            let net = self.shared_net.clone();
            let parent_actor = self.actor;
            let id = boundary.spawn_task(move |child_boundary| {
                let handle = Handle {
                    boundary: Some(child_boundary),
                    seed,
                    shared_net: net,
                    actor: parent_actor,
                };
                f(handle)
            });
            return crate::task::TaskId(id);
        }
        #[cfg(feature = "sim-link")]
        {
            // Without a boundary there is no scheduler to join; callers see
            // the historical sentinel id rather than a silent failure later.
            crate::task::TaskId(0)
        }
        #[cfg(not(feature = "sim-link"))]
        {
            static NEXT_TASK_ID: core::sync::atomic::AtomicU64 =
                core::sync::atomic::AtomicU64::new(1);
            let id_val = NEXT_TASK_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let handle = Handle {
                seed: self.seed(),
                shared_net: self.shared_net.clone(),
                actor: self.actor,
            };
            tokio::task::spawn_local(f(handle));
            crate::task::TaskId(id_val)
        }
    }

    /// Convenience: build a `Conn` from `from` to `to` sharing this handle's net.
    pub fn conn(&self, from: ActorId, to: ActorId) -> Conn {
        Conn::new(from, to, self.shared_net.clone())
    }
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

/// Caller program accepted by `run`, identical under every feature set.
///
/// The future is erased and deliberately non-`Send`: all executors behind the
/// facade poll tasks on one thread, so requiring `Send` would make SUT
/// sources non-portable across feature sets.
pub type TaskMain = Box<dyn FnOnce(Handle) -> Pin<Box<dyn Future<Output = ()>>> + 'static>;

/// What a backend executes.
///
/// Why an enum: keeping "caller program" and "registered workload name"
/// distinct types makes it impossible to conflate them or to discard a
/// program silently while claiming to run a workload. Each backend resolves
/// only the arm it can honestly execute and rejects the other with a typed
/// error.
enum Main {
    /// A caller program captured at the public seam.
    Closure(TaskMain),
    /// A workload registered under a name on the execution side.
    Named(&'static str),
}

impl Main {
    /// Resolve to a caller program on direct-executor backends: closures
    /// pass through; names look up the [`register_workload`] registry.
    #[cfg(any(feature = "sim-link", not(any(feature = "sim", feature = "sim-link"))))]
    fn into_program(self) -> Result<TaskMain, RuntimeError> {
        match self {
            Main::Closure(program) => Ok(program),
            Main::Named(name) => resolve_workload(name),
        }
    }

    /// Resolve to a server workload name on the IPC backend. Caller programs
    /// cannot cross the process boundary, so they are consumed and refused
    /// loudly instead of being substituted with some other program.
    #[cfg(all(feature = "sim", not(feature = "sim-link")))]
    fn into_workload(self) -> Result<&'static str, RuntimeError> {
        match self {
            // Consuming the program here is the refusal: nothing else runs.
            Main::Closure(program) => {
                drop(program);
                Err(RuntimeError::ProgramNotTransportable)
            }
            Main::Named(name) => Ok(name),
        }
    }
}

/// Factory producing a fresh program per run; programs are consume-once by
/// contract, so the registry stores factories rather than programs.
type WorkloadFactory = fn() -> TaskMain;

thread_local! {
    /// Named caller programs for direct-executor backends. Thread-local by
    /// contract: programs may capture non-`Send` state, and every backend
    /// polls on the calling thread.
    static WORKLOADS: RefCell<std::collections::HashMap<&'static str, WorkloadFactory>> =
        RefCell::new(std::collections::HashMap::new());
}

/// Register a named caller program for the direct-executor backends
/// (default build and `sim-link`).
///
/// `build` is a factory so each run gets a fresh [`TaskMain`]; programs are
/// consume-once by contract. Re-registering a name replaces its factory.
/// Thread-local scope: the registration is visible to `run_named` on the
/// same thread only, matching where programs execute. Under `sim` (IPC) the
/// engine resolves its own server-side workloads; client registrations have
/// no effect there.
pub fn register_workload(name: &'static str, build: fn() -> TaskMain) {
    WORKLOADS.with(|workloads| {
        workloads.borrow_mut().insert(name, build);
    });
}

#[cfg(any(feature = "sim-link", not(any(feature = "sim", feature = "sim-link"))))]
fn resolve_workload(name: &'static str) -> Result<TaskMain, RuntimeError> {
    WORKLOADS.with(|workloads| match workloads.borrow().get(name) {
        Some(build) => Ok(build()),
        None => Err(RuntimeError::UnknownWorkload {
            name: Box::from(name),
        }),
    })
}

/// Run a registered workload by name.
///
/// Direct-executor backends resolve `name` against [`register_workload`]
/// and execute the resulting caller program; an unknown name returns
/// [`RuntimeError::UnknownWorkload`]. Under `sim` (IPC) the name goes to the
/// engine, which runs its own registered server workload (for example `"kv"`),
/// returning the server-computed journal root.
pub fn run_named(config: RunConfig, name: &'static str) -> Result<RunResult, RuntimeError> {
    run_main(config, Main::Named(name))
}

/// Run `main` to completion.
///
/// Backend by feature set: `sim-link` drives the program on the deterministic
/// in-process executor; with neither sim feature it blocks a current-thread
/// tokio runtime on the program; under `sim` (IPC) caller programs cannot
/// cross the process boundary, so this returns
/// [`RuntimeError::ProgramNotTransportable`] - use `run_named` with a server
/// workload or rebuild with `sim-link`. All backends poll on one thread, so
/// futures may hold non-`Send` state.
///
/// The handle is installed into a thread-local for the duration of the run so
/// host helpers can reach it via [`Handle::current`]; SUT code should take
/// the handle passed to `main` and spawn through [`Handle::spawn`].
pub fn run<F, Fut>(config: RunConfig, main: F) -> Result<RunResult, RuntimeError>
where
    F: FnOnce(Handle) -> Fut + 'static,
    Fut: Future<Output = ()> + 'static,
{
    let program: TaskMain = Box::new(move |handle| Box::pin(main(handle)));
    run_main(config, Main::Closure(program))
}

/// Backend dispatch. One definition per feature combo; identical signature.
#[cfg(feature = "sim-link")]
fn run_main(config: RunConfig, main: Main) -> Result<RunResult, RuntimeError> {
    run_with_sim(config, main)
}

#[cfg(all(feature = "sim", not(feature = "sim-link")))]
fn run_main(config: RunConfig, main: Main) -> Result<RunResult, RuntimeError> {
    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime.block_on(run_via_ipc(config, main)),
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(any(feature = "sim", feature = "sim-link")))]
fn run_main(config: RunConfig, main: Main) -> Result<RunResult, RuntimeError> {
    run_with_tokio(config, main)
}

#[cfg(feature = "sim-link")]
fn run_with_sim(config: RunConfig, main: Main) -> Result<RunResult, RuntimeError> {
    let task_main = main.into_program()?;
    let seed = config.seed();
    let max_steps = config.max_steps();
    let shared_net = shared_network();
    let net_for_sim = shared_net.clone();
    let sim_cfg = SimRunConfig::builder()
        .seed(seed)
        .max_steps(max_steps)
        .build();
    let sim = Simulation::with_tasks(
        sim_cfg,
        vec![Box::new(move |boundary: ledger_sim::Boundary| {
            let handle = Handle {
                boundary: Some(boundary),
                seed,
                shared_net: net_for_sim,
                actor: 0,
            };
            set_current(handle.clone());
            let erased: Pin<Box<dyn Future<Output = ()>>> = Box::pin(async move {
                (task_main)(handle).await;
                clear_current();
            });
            erased
        }) as ledger_sim::TaskBuilder],
    );
    let res = sim.run().map_err(|e| match e {
        ledger_sim::RuntimeError::StepLimit { limit } => RuntimeError::StepLimit { limit },
        ledger_sim::RuntimeError::Journal(err) => {
            RuntimeError::Journal(JournalFault::from_journal_error(err))
        }
    })?;
    clear_current();
    Ok(RunResult {
        journal_root: Some(res.journal.root_hash()),
        steps: res.steps,
        outcome: res.outcome.into(),
    })
}

#[cfg(all(feature = "sim", not(feature = "sim-link")))]
async fn run_via_ipc(config: RunConfig, main: Main) -> Result<RunResult, RuntimeError> {
    // Resolve engine binary from env or PATH and run a server-registered
    // workload. Server workloads are deterministic for a given seed, so equal
    // seeds yield equal roots across calls.
    let workload = main.into_workload()?;
    // Spawn the engine process. The child is killed on drop.
    let mut engine = EngineProcess::spawn(None).await?;
    let outcome = engine.run_workload_with_steps(workload, config.seed(), config.max_steps(), 1)?;
    let root = outcome.journal_root().ok_or(RuntimeError::MissingRoot)?;
    Ok(RunResult {
        outcome: RunCompletion::Completed,
        journal_root: Some(root),
        steps: outcome.steps,
    })
}

#[cfg(not(any(feature = "sim", feature = "sim-link")))]
fn run_with_tokio(config: RunConfig, main: Main) -> Result<RunResult, RuntimeError> {
    let task_main = main.into_program()?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    // The LocalSet lets child tasks spawned via `Handle::spawn` carry
    // non-Send futures, matching the single-threaded executor contract.
    let local = tokio::task::LocalSet::new();
    let handle = Handle {
        seed: config.seed(),
        shared_net: shared_network(),
        actor: 0,
    };
    set_current(handle.clone());
    local.block_on(&rt, async move {
        (task_main)(handle).await;
    });
    clear_current();
    Ok(RunResult {
        outcome: RunCompletion::Completed,
        journal_root: None,
        steps: 0,
    })
}

// ---------------------------------------------------------------------------
// Surface probe
// ---------------------------------------------------------------------------
// One trait, one bound set: any drift between feature combinations fails to
// compile right here. Per-combo `cargo check` plus the `public_contract`
// integration test pin the contract; `probe()` keeps the gate visible in
// test output.

#[allow(dead_code)] // compile-time surface probe; see the block comment above
trait Surface {
    fn clock(&self) -> crate::time::SimClock;
    fn actor(&self) -> ActorId;
    fn with_actor(&self, actor: ActorId) -> Handle;
    fn net_send(&self, to: usize, payload: u64) -> bool;
    fn conn(&self, from: ActorId, to: ActorId) -> Conn;
    fn spawn<F>(&self, f: F) -> crate::task::TaskId
    where
        F: FnOnce(Handle) -> Pin<Box<dyn Future<Output = ()>>> + 'static;
}

impl Surface for Handle {
    fn clock(&self) -> crate::time::SimClock {
        Handle::clock(self)
    }
    fn actor(&self) -> ActorId {
        Handle::actor(self)
    }
    fn with_actor(&self, actor: ActorId) -> Handle {
        Handle::with_actor(self, actor)
    }
    fn net_send(&self, to: usize, payload: u64) -> bool {
        Handle::net_send(self, to, payload)
    }
    fn conn(&self, from: ActorId, to: ActorId) -> Conn {
        Handle::conn(self, from, to)
    }
    fn spawn<F>(&self, f: F) -> crate::task::TaskId
    where
        F: FnOnce(Handle) -> Pin<Box<dyn Future<Output = ()>>> + 'static,
    {
        Handle::spawn(self, f)
    }
}

pub(crate) fn assert_surface() {
    fn needs_surface<T: Surface>(_: &T) {}
    let h = Handle {
        #[cfg(feature = "sim-link")]
        boundary: None,
        seed: [0u8; 32],
        shared_net: shared_network(),
        actor: 0,
    };
    needs_surface(&h);
    let _ = h.with_actor(1).actor();
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;

    /// Assert `res` matches the per-combo contract for `run(closure)`:
    /// the caller program executes on direct-executor backends, while
    /// IPC-only builds refuse it loudly without needing an engine.
    fn assert_run_program_outcome(res: Result<RunResult, RuntimeError>) {
        #[cfg(all(feature = "sim", not(feature = "sim-link")))]
        {
            let error = res.expect_err("IPC-only builds must refuse caller programs");
            assert!(
                matches!(error, RuntimeError::ProgramNotTransportable),
                "{error}"
            );
        }
        #[cfg(not(all(feature = "sim", not(feature = "sim-link"))))]
        assert!(res.is_ok(), "{:?}", res.err());
    }

    #[test]
    fn run_completes_without_sim() {
        let cfg = RunConfig::builder().seed([1u8; 32]).max_steps(1024).build();
        let res = run(cfg, |handle| async move {
            let c = handle.clock();
            let _ = c.now();
            handle.sleep(Duration::from_millis(1)).await;
        });
        assert_run_program_outcome(res);
    }

    #[test]
    fn run_rng_is_deterministic_in_sim() {
        let cfg = RunConfig::builder().seed([9u8; 32]).max_steps(1024).build();
        let a = run(cfg.clone(), |mut h| async move {
            let _ = h.rng_next_u64(1);
        });
        let b = run(cfg, |mut h| async move {
            let _ = h.rng_next_u64(1);
        });
        #[cfg(all(feature = "sim", not(feature = "sim-link")))]
        {
            assert_run_program_outcome(a);
            assert_run_program_outcome(b);
        }
        #[cfg(feature = "sim-link")]
        {
            assert_eq!(a.unwrap().journal_root, b.unwrap().journal_root);
        }
        #[cfg(not(any(feature = "sim", feature = "sim-link")))]
        {
            assert!(a.is_ok());
            assert!(b.is_ok());
        }
    }

    #[test]
    fn net_send_recv_roundtrip_without_sim() {
        let cfg = RunConfig::builder().seed([2u8; 32]).max_steps(1024).build();
        let res = run(cfg, |handle| async move {
            let c = handle.conn(0, 1);
            assert!(c.send(99));
            assert_eq!(c.recv(), Some(99));
        });
        assert_run_program_outcome(res);
    }

    #[test]
    fn spawn_returns_distinct_ids() {
        let cfg = RunConfig::builder().seed([3u8; 32]).max_steps(1024).build();
        let res = run(cfg, |handle| async move {
            let first = handle.spawn(|_child| Box::pin(async move {}));
            let second = handle.spawn(|_child| Box::pin(async move {}));
            assert_ne!(first, second, "spawned tasks must receive distinct ids");
        });
        assert_run_program_outcome(res);
    }

    #[test]
    fn with_actor_binds_non_sim_send_recv() {
        let cfg = RunConfig::builder().seed([5u8; 32]).max_steps(1024).build();
        let res = run(cfg, |handle| async move {
            let a = handle.with_actor(3);
            let b = handle.with_actor(7);
            assert_eq!(a.actor(), 3);
            assert_eq!(b.actor(), 7);
            assert!(a.net_send(7, 42));
            let payload = b.net_recv().await;
            assert_eq!(payload, 42);
            assert!(!handle.conn(3, 0).has_ready());
        });
        assert_run_program_outcome(res);
    }

    #[cfg(feature = "sim-link")]
    #[test]
    fn sim_determinism_same_seed_same_root() {
        let cfg = RunConfig::builder()
            .seed([42u8; 32])
            .max_steps(2048)
            .build();
        let a = run(cfg.clone(), |handle| async move {
            handle.sleep(Duration::from_micros(5)).await;
        })
        .unwrap();
        let b = run(cfg, |handle| async move {
            handle.sleep(Duration::from_micros(5)).await;
        })
        .unwrap();
        assert_eq!(a.journal_root, b.journal_root);
    }

    #[cfg(feature = "sim-link")]
    #[test]
    fn sim_net_send_is_journaled_and_deterministic() {
        let run_once = |payload| {
            run(
                RunConfig::builder().seed([7u8; 32]).max_steps(2048).build(),
                move |handle| async move {
                    let _ = handle.net_send(1, payload);
                },
            )
            .unwrap()
        };
        let a = run_once(123);
        let b = run_once(123);
        assert_eq!(a.journal_root, b.journal_root);
        let c = run_once(124);
        assert_ne!(a.journal_root, c.journal_root);
    }

    /// A bare workload name must be rejected loudly via the public `run_named`
    /// path instead of being confused with a program. IPC-only builds forward
    /// names to the engine instead of consulting this registry, so they are
    /// out of scope here.
    #[cfg(not(all(feature = "sim", not(feature = "sim-link"))))]
    #[test]
    fn unknown_named_workload_is_a_typed_error() {
        let RuntimeError::UnknownWorkload { name } =
            run_named(RunConfig::default(), "nope").unwrap_err()
        else {
            panic!("an unregistered workload must be rejected as UnknownWorkload");
        };
        assert_eq!(name.as_ref(), "nope");
    }

    #[cfg(not(all(feature = "sim", not(feature = "sim-link"))))]
    thread_local! {
        static PROGRAM_RAN: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    }

    #[cfg(not(all(feature = "sim", not(feature = "sim-link"))))]
    fn mark_program_ran() -> TaskMain {
        Box::new(|_handle| {
            Box::pin(async {
                PROGRAM_RAN.with(|ran| ran.set(true));
            })
        })
    }

    /// Factories are consume-once-per-run by contract, so the registry must
    /// hand out a fresh program for every named run: two sequential
    /// `run_named` calls fire the factory exactly twice.
    #[cfg(not(all(feature = "sim", not(feature = "sim-link"))))]
    #[test]
    fn registered_workload_runs_by_name_on_direct_backends() {
        static FACTORY_CALLS: core::sync::atomic::AtomicUsize =
            core::sync::atomic::AtomicUsize::new(0);
        use core::sync::atomic::Ordering as AtomicOrdering;

        fn counting_factory() -> TaskMain {
            FACTORY_CALLS.fetch_add(1, AtomicOrdering::Relaxed);
            mark_program_ran()
        }

        PROGRAM_RAN.with(|ran| ran.set(false));
        register_workload("probe-wl", counting_factory);
        let config = RunConfig::builder()
            .seed([13u8; 32])
            .max_steps(1024)
            .build();
        let first = run_named(config.clone(), "probe-wl");
        let second = run_named(config, "probe-wl");
        assert!(first.is_ok(), "{:?}", first.err());
        assert!(second.is_ok(), "{:?}", second.err());
        assert_eq!(
            FACTORY_CALLS.load(AtomicOrdering::Relaxed),
            2,
            "each named run must build a fresh program"
        );
        assert!(
            PROGRAM_RAN.with(core::cell::Cell::get),
            "the registered program itself must execute"
        );
    }

    /// The registry is deliberately thread-local (programs may capture
    /// non-`Send` state), so registrations from another thread must be
    /// invisible here and fail loudly instead of silently succeeding.
    #[cfg(not(all(feature = "sim", not(feature = "sim-link"))))]
    #[test]
    fn registrations_on_other_threads_are_invisible() {
        let spawner = std::thread::spawn(|| {
            register_workload("thread-local-wl", || Box::new(|_handle| Box::pin(async {})));
        });
        spawner.join().expect("registration thread must not panic");
        let RuntimeError::UnknownWorkload { name } =
            run_named(RunConfig::default(), "thread-local-wl").unwrap_err()
        else {
            panic!("cross-thread registration must not resolve");
        };
        assert_eq!(name.as_ref(), "thread-local-wl");
    }

    /// Actor ids beyond the u32 range are undeliverable rather than
    /// truncated to a different actor: send reports false and no queue for
    /// any plausible destination gains a message.
    #[test]
    fn net_send_rejects_ids_beyond_actor_range() {
        const BEYOND_RANGE: usize = u32::MAX as usize + 1;
        let res = run(
            RunConfig::builder()
                .seed([19u8; 32])
                .max_steps(1024)
                .build(),
            |handle| async move {
                assert!(!handle.net_send(BEYOND_RANGE, 7));
                // A wrapping truncation would land on actor 0; the real id
                // space top must stay empty too. Both probes are
                // non-blocking receives over the shared queue.
                assert_eq!(handle.conn(0, 0).recv(), None);
                assert_eq!(handle.conn(0, u32::MAX).recv(), None);
                // Positive control: an in-range high id still delivers.
                assert!(handle.net_send(u32::MAX as usize, 7));
                let receiver = handle.with_actor(u32::MAX);
                assert_eq!(receiver.net_recv().await, 7);
            },
        );
        assert_run_program_outcome(res);
    }

    /// Under IPC-only builds, `run(closure)` must fail loudly and fast with
    /// the instructive typed error - before any engine spawn - instead of
    /// silently running some other program.
    #[cfg(all(feature = "sim", not(feature = "sim-link")))]
    #[test]
    fn ipc_closure_run_reports_program_not_transportable() {
        let error = run(RunConfig::default(), |_handle| async {}).unwrap_err();
        assert!(
            matches!(error, RuntimeError::ProgramNotTransportable),
            "{error}"
        );
    }

    /// Anti-substitution proof for the deterministic backend: the journal
    /// root comes from THIS program (same closure + seed reproduce it; any
    /// change to the program changes it), so a silent swap for another
    /// workload cannot go unnoticed.
    #[cfg(feature = "sim-link")]
    #[test]
    fn sim_link_closure_roots_are_deterministic_and_program_sensitive() {
        let cfg = RunConfig::builder()
            .seed([17u8; 32])
            .max_steps(2048)
            .build();
        let run_once = |payload| {
            run(cfg.clone(), move |handle| async move {
                let _ = handle.net_send(1, payload);
            })
            .unwrap()
        };
        let a = run_once(100);
        let b = run_once(100);
        let c = run_once(101);
        assert_eq!(a.journal_root, b.journal_root, "same program same seed");
        assert_ne!(a.journal_root, c.journal_root, "program change moves root");
    }

    /// Probe that every build exposes an identical `Handle` surface.
    ///
    /// Each compilation pins one feature combo; per-combo `cargo check`
    /// invocations are the real proof, and the `public_contract` integration
    /// test pins every signature. This test keeps the gate visible in
    /// `cargo nextest` output alongside [`crate::probe`].
    #[test]
    fn surface_probe_compiles() {
        crate::runtime::assert_surface();
        crate::probe();
        let _seed = RunConfig::default().seed;
    }

    /// Receives must work across the full actor id space, not a bounded
    /// sender scan: a high-id receiver gets mail from a high-id sender with
    /// no polling of intermediate ids. Deterministic on direct executors;
    /// under `sim` (IPC) only the refusal contract applies.
    #[test]
    fn high_actor_ids_receive_across_full_id_space() {
        let res = run(
            RunConfig::builder()
                .seed([11u8; 32])
                .max_steps(1024)
                .build(),
            |handle| async move {
                let sender = handle.with_actor(u32::MAX - 1);
                let receiver = handle.with_actor(u32::MAX);
                assert!(sender.net_send(u32::MAX as usize, 4242));
                assert_eq!(receiver.net_recv().await, 4242);
            },
        );
        assert_run_program_outcome(res);
    }
}
