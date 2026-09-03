// ledger-lint:allow:thread::spawn - test-only probe; verifies thread-local registry isolation
//! Runtime facade entrypoint: `Handle` is the single porting seam.
//! Same async body runs under `Simulation` (sim) or `tokio`.
//! One name, signature, and bound set per item under every feature combo.
//! `sim` is IPC-only (`ledger rt-server` over Unix socket); `sim-link`
//! keeps the direct link for workspace tests only.
//! Caller programs never cross IPC: `sim`-only `run(closure)` returns
//! [`RuntimeError::ProgramNotTransportable`]; use `run_named`.

use core::future::Future;
use core::pin::Pin;
use core::time::Duration;
use std::cell::RefCell;

use ledger_format::{ActorId, EntryHash, StreamId};
use thiserror::Error;

#[cfg(all(feature = "sim", not(feature = "sim-link")))]
use crate::ipc::EngineProcess;
use crate::net::{Conn, shared_network};
use crate::rng::{DetRng, RngError};
use crate::time::ClockError;
#[cfg(feature = "sim-link")]
use ledger_sim::{Effects as _, RunConfig as SimRunConfig, Simulation};

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
    pub seed: EntryHash,
    /// Maximum executor steps before `StepLimit` (sim backends only).
    pub max_steps: usize,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            seed: EntryHash([0u8; 32]),
            max_steps: 10_000,
        }
    }
}

impl RunConfig {
    pub fn builder() -> RunConfigBuilder {
        RunConfigBuilder::default()
    }

    /// Root seed for deterministic runs.
    pub fn seed(&self) -> EntryHash {
        self.seed
    }

    pub fn max_steps(&self) -> usize {
        self.max_steps
    }
}

/// Builder for [`RunConfig`]; defaults mirror [`RunConfig::default`].
#[derive(Debug, Clone)]
pub struct RunConfigBuilder {
    seed: EntryHash,
    max_steps: usize,
}

impl Default for RunConfigBuilder {
    fn default() -> Self {
        Self {
            seed: EntryHash([0u8; 32]),
            max_steps: 10_000,
        }
    }
}

impl RunConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seed(mut self, seed: EntryHash) -> Self {
        self.seed = seed;
        self
    }

    pub fn max_steps(mut self, max_steps: usize) -> Self {
        self.max_steps = max_steps;
        self
    }

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
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunCompletion {
    /// Every task finished.
    Completed,
    /// The step budget ran out while tasks were still ready or blocked.
    BudgetExhausted,
    /// No task was ready and at least one task was still pending.
    Blocked,
}

#[cfg(feature = "sim-link")]
impl From<ledger_sim::RunOutcome> for RunCompletion {
    fn from(outcome: ledger_sim::RunOutcome) -> Self {
        match outcome {
            ledger_sim::RunOutcome::Completed => Self::Completed,
            ledger_sim::RunOutcome::BudgetExhausted => Self::BudgetExhausted,
            ledger_sim::RunOutcome::Blocked => Self::Blocked,
            ledger_sim::RunOutcome::MonitorHalt(_) => Self::Blocked,
        }
    }
}

/// Outcome of a completed run.
#[derive(Debug, Clone)]
pub struct RunResult {
    /// Root hash of the journal the backend produced. `None` when the run
    /// produced no journal (non-sim builds).
    pub journal_root: Option<EntryHash>,
    /// Number of executor steps consumed.
    pub steps: usize,
    /// Whether the run completed, and the liveness reason when it did not.
    pub outcome: RunCompletion,
}

/// Journal invariant failure raised by a simulation backend.
/// Facade-local carrier: typed cause links only under `sim-link` (via
/// `source`); other builds carry the message only.
#[derive(Debug)]
pub struct JournalFault {
    message: Box<str>,
    source: Option<Box<dyn core::error::Error + Send + Sync>>,
}

impl JournalFault {
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
/// Same facade-local rationale as [`JournalFault`].
#[derive(Debug)]
pub struct IpcFault {
    message: Box<str>,
    source: Option<Box<dyn core::error::Error + Send + Sync>>,
}

impl IpcFault {
    pub fn from_message(message: impl Into<Box<str>>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

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

/// Belt activation failed or the belt is not active while required.
#[derive(Debug)]
pub struct BeltFault {
    message: Box<str>,
    source: Option<Box<dyn core::error::Error + Send + Sync>>,
}

impl BeltFault {
    pub fn from_message(message: impl Into<Box<str>>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Preserve the typed belt status.
    #[cfg(feature = "sim-link")]
    pub(crate) fn from_belt_status(status: ledger_sim::BeltStatus) -> Self {
        Self {
            message: status.to_string().into(),
            source: None,
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl core::fmt::Display for BeltFault {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl core::error::Error for BeltFault {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        let source: &(dyn core::error::Error + 'static) = self.source.as_deref()?;
        Some(source)
    }
}

/// Local mirror of the engine strict-replay violation. Keeps the engine
/// type out of this crate's public API outside `sim-link`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StrictReplayViolation {
    /// Decision value is outside the ready set.
    #[error("decision {value} at step {step} is outside the ready set of {ready_len} tasks")]
    OutOfRange {
        step: usize,
        value: usize,
        ready_len: usize,
    },
    /// Replay stream exhausted before the run finished.
    #[error("replay exhausted at step {step} after {replay_len} decisions")]
    Exhausted { step: usize, replay_len: usize },
    /// Replay is longer than the run; leftover decisions remain.
    #[error("replay carries {trailing} trailing decisions for {steps} steps")]
    Trailing { trailing: usize, steps: usize },
}

#[cfg(feature = "sim-link")]
impl From<ledger_sim::ReplayViolation> for StrictReplayViolation {
    fn from(violation: ledger_sim::ReplayViolation) -> Self {
        match violation {
            ledger_sim::ReplayViolation::OutOfRange {
                step,
                value,
                ready_len,
            } => Self::OutOfRange {
                step,
                value,
                ready_len,
            },
            ledger_sim::ReplayViolation::Exhausted { step, replay_len } => {
                Self::Exhausted { step, replay_len }
            }
            ledger_sim::ReplayViolation::Trailing { trailing, steps } => {
                Self::Trailing { trailing, steps }
            }
        }
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
    /// Belt activation failed or the belt is not active while required.
    #[error("belt error: {0}")]
    Belt(BeltFault),
    /// Engine-process transport failure (spawn, connect, wire, timeout).
    #[error("ipc error: {0}")]
    Ipc(IpcFault),
    /// The engine run completed without reporting a journal root.
    #[error("engine returned no journal root")]
    MissingRoot,
    /// A named workload was requested that no backend registry holds.
    #[error("no workload registered under {name:?}")]
    UnknownWorkload { name: Box<str> },
    /// Strict replay rejected the recorded decisions instead of
    /// normalizing or falling back.
    #[error("strict replay rejected: {0}")]
    StrictReplay(#[source] StrictReplayViolation),
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
/// Only way to touch time, RNG, net, and task spawning.
pub struct Handle {
    #[cfg(feature = "sim-link")]
    boundary: Option<ledger_sim::Boundary>,
    // Only sim backends consume the seed today; the field stays on every
    // build so Handle literals keep one shape across feature combos.
    #[cfg_attr(not(feature = "sim-link"), allow(dead_code))]
    seed: EntryHash,
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
    pub fn actor(&self) -> ActorId {
        self.actor
    }

    pub fn seed(&self) -> EntryHash {
        self.seed
    }

    /// Return a handle bound to `actor` (shares seed and net).
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
    /// Returns `None` outside a `run` context.
    pub fn current() -> Option<Self> {
        CURRENT.with(|c| c.borrow().clone())
    }

    /// Return a deterministic clock snapshot.
    /// Fails with [`ClockError::NoContext`] without a boundary (`sim-link`),
    /// [`ClockError::IpcLocal`] under `sim` IPC; default builds read ambient time.
    pub fn clock(&self) -> Result<crate::time::SimClock, ClockError> {
        #[cfg(feature = "sim-link")]
        {
            if let Some(b) = &self.boundary {
                return Ok(crate::time::SimClock::from_ticks(b.clock().now()));
            }
            Err(ClockError::NoContext)
        }
        #[cfg(all(feature = "sim", not(feature = "sim-link")))]
        {
            Err(ClockError::IpcLocal)
        }
        #[cfg(not(any(feature = "sim", feature = "sim-link")))]
        {
            Ok(crate::time::SimClock::ambient())
        }
    }

    /// Sleep for `duration` (journaled under `sim-link`).
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
    /// Fails with [`RngError::NoContext`] without a boundary, [`RngError::IpcLocal`]
    /// under `sim` IPC; default builds seed from host entropy.
    pub fn rng(&mut self, stream: StreamId) -> Result<DetRng, RngError> {
        #[cfg(feature = "sim-link")]
        {
            if let Some(b) = &self.boundary {
                return Ok(DetRng::from_boundary(stream, b.clone()));
            }
            Err(RngError::NoContext)
        }
        #[cfg(all(feature = "sim", not(feature = "sim-link")))]
        {
            let _ = stream;
            Err(RngError::IpcLocal)
        }
        #[cfg(not(any(feature = "sim", feature = "sim-link")))]
        {
            DetRng::from_seed(stream)
        }
    }

    /// Convenience: next u64 from `stream`.
    pub fn rng_next_u64(&mut self, stream: StreamId) -> Result<u64, RngError> {
        self.rng(stream).map(|mut rng| rng.next_u64())
    }

    /// Send a payload from `self.actor` to `to`. Returns `false` when
    /// partitioned or `to` exceeds the actor id range.
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
        Conn::new(self.actor, ActorId(to_id), self.shared_net.clone()).send(payload)
    }

    /// Receive a payload addressed to `self.actor`.
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
            let notified = {
                let mut net = match self.shared_net.inner().lock() {
                    Ok(g) => g,
                    Err(_) => return 0,
                };
                if let Some(payload) = net.recv_for(self.actor) {
                    return payload;
                }
                self.shared_net.notify().notified()
            };
            notified.await;
        }
    }

    /// Spawn a child task running `f(child_handle)`.
    /// Non-`Send` by design: every executor polls on one thread.
    /// Under `sim` IPC spawns stay local and outside the journaled run.
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

    /// Convenience: build a `Conn` from `from` to `to` on this handle's net.
    pub fn conn(&self, from: ActorId, to: ActorId) -> Conn {
        Conn::new(from, to, self.shared_net.clone())
    }
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

/// Caller program accepted by `run`, identical under every feature set.
/// Erased non-`Send` future: all executors poll on one thread.
pub type TaskMain = Box<dyn FnOnce(Handle) -> Pin<Box<dyn Future<Output = ()>>> + 'static>;

/// What a backend executes: caller program or registered workload name.
enum Main {
    /// A caller program captured at the public seam.
    Closure(TaskMain),
    /// A workload registered under a name on the execution side.
    Named(&'static str),
}

impl Main {
    /// Resolve to a caller program on direct-executor backends.
    #[cfg(any(feature = "sim-link", not(any(feature = "sim", feature = "sim-link"))))]
    fn into_program(self) -> Result<TaskMain, RuntimeError> {
        match self {
            Main::Closure(program) => Ok(program),
            Main::Named(name) => resolve_workload(name),
        }
    }

    /// Resolve to a server workload name on the IPC backend.
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

/// Factory producing a fresh program per run (programs are consume-once).
type WorkloadFactory = fn() -> TaskMain;

thread_local! {
    /// Named caller programs for direct-executor backends. Thread-local by
    /// contract: programs may capture non-`Send` state, and every backend
    /// polls on the calling thread. A `BTreeMap` keeps iteration order
    /// deterministic across builds.
    static WORKLOADS: RefCell<std::collections::BTreeMap<&'static str, WorkloadFactory>> =
        RefCell::new(std::collections::BTreeMap::new());
}

/// Register a named caller program for the direct-executor backends.
/// Thread-local: visible to `run_named` on the same thread only.
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
pub fn run_named(config: RunConfig, name: &'static str) -> Result<RunResult, RuntimeError> {
    run_main(config, Main::Named(name))
}

/// Run `main` to completion.
/// Under `sim` IPC caller programs are refused with
/// [`RuntimeError::ProgramNotTransportable`]; use `run_named`.
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
                actor: ActorId(0),
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
        ledger_sim::RuntimeError::StrictReplay(violation) => {
            RuntimeError::StrictReplay(violation.into())
        }
        ledger_sim::RuntimeError::Belt(status) => {
            RuntimeError::Belt(BeltFault::from_belt_status(status))
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
    let workload = main.into_workload()?;
    let mut engine = EngineProcess::spawn(None).await?;
    let outcome = engine.run_workload_with_steps(
        workload,
        config.seed(),
        config.max_steps(),
        1,
        ActorId(0),
    )?;
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
        actor: ActorId(0),
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
// Surface probe: one trait, one bound set per feature combo.
// ---------------------------------------------------------------------------
// Per-combo `cargo check` plus `public_contract` pin the contract.

#[allow(dead_code)] // compile-time surface probe
trait Surface {
    fn clock(&self) -> Result<crate::time::SimClock, ClockError>;
    fn actor(&self) -> ActorId;
    fn with_actor(&self, actor: ActorId) -> Handle;
    fn net_send(&self, to: usize, payload: u64) -> bool;
    fn conn(&self, from: ActorId, to: ActorId) -> Conn;
    fn spawn<F>(&self, f: F) -> crate::task::TaskId
    where
        F: FnOnce(Handle) -> Pin<Box<dyn Future<Output = ()>>> + 'static;
}

impl Surface for Handle {
    fn clock(&self) -> Result<crate::time::SimClock, ClockError> {
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
        seed: EntryHash([0u8; 32]),
        shared_net: shared_network(),
        actor: ActorId(0),
    };
    needs_surface(&h);
    let _ = h.with_actor(ActorId(1)).actor();
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;

    /// Per-combo contract for `run(closure)`.
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
        let cfg = RunConfig::builder()
            .seed(EntryHash([1u8; 32]))
            .max_steps(1024)
            .build();
        let res = run(cfg, |handle| async move {
            // Local clocks are unavailable under sim IPC; direct backends
            // must produce one.
            #[cfg(all(feature = "sim", not(feature = "sim-link")))]
            {
                let _ = handle;
            }
            #[cfg(not(all(feature = "sim", not(feature = "sim-link"))))]
            {
                let c = handle.clock().expect("direct backends provide a clock");
                let _ = c.now();
            }
            handle.sleep(Duration::from_millis(1)).await;
        });
        assert_run_program_outcome(res);
    }

    #[test]
    fn run_rng_is_deterministic_in_sim() {
        let cfg = RunConfig::builder()
            .seed(EntryHash([9u8; 32]))
            .max_steps(1024)
            .build();
        let a = run(cfg.clone(), |mut h| async move {
            #[cfg(all(feature = "sim", not(feature = "sim-link")))]
            {
                let _ = h.rng_next_u64(StreamId(1));
            }
            #[cfg(not(all(feature = "sim", not(feature = "sim-link"))))]
            {
                h.rng_next_u64(StreamId(1))
                    .expect("direct backends provide RNG");
            }
        });
        let b = run(cfg, |mut h| async move {
            #[cfg(all(feature = "sim", not(feature = "sim-link")))]
            {
                let _ = h.rng_next_u64(StreamId(1));
            }
            #[cfg(not(all(feature = "sim", not(feature = "sim-link"))))]
            {
                h.rng_next_u64(StreamId(1))
                    .expect("direct backends provide RNG");
            }
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
        let cfg = RunConfig::builder()
            .seed(EntryHash([2u8; 32]))
            .max_steps(1024)
            .build();
        let res = run(cfg, |handle| async move {
            let c = handle.conn(ActorId(0), ActorId(1));
            assert!(c.send(99));
            assert_eq!(c.recv(), Some(99));
        });
        assert_run_program_outcome(res);
    }

    #[test]
    fn spawn_returns_distinct_ids() {
        let cfg = RunConfig::builder()
            .seed(EntryHash([3u8; 32]))
            .max_steps(1024)
            .build();
        let res = run(cfg, |handle| async move {
            let first = handle.spawn(|_child| Box::pin(async move {}));
            let second = handle.spawn(|_child| Box::pin(async move {}));
            assert_ne!(first, second, "spawned tasks must receive distinct ids");
        });
        assert_run_program_outcome(res);
    }

    #[test]
    fn with_actor_binds_non_sim_send_recv() {
        let cfg = RunConfig::builder()
            .seed(EntryHash([5u8; 32]))
            .max_steps(1024)
            .build();
        let res = run(cfg, |handle| async move {
            let a = handle.with_actor(ActorId(3));
            let b = handle.with_actor(ActorId(7));
            assert_eq!(a.actor(), ActorId(3));
            assert_eq!(b.actor(), ActorId(7));
            assert!(a.net_send(7, 42));
            let payload = b.net_recv().await;
            assert_eq!(payload, 42);
            assert!(!handle.conn(ActorId(3), ActorId(0)).has_ready());
        });
        assert_run_program_outcome(res);
    }

    #[cfg(feature = "sim-link")]
    #[test]
    fn sim_determinism_same_seed_same_root() {
        let cfg = RunConfig::builder()
            .seed(EntryHash([42u8; 32]))
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
                RunConfig::builder()
                    .seed(EntryHash([7u8; 32]))
                    .max_steps(2048)
                    .build(),
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

    /// Unknown names fail as `UnknownWorkload` (direct backends only).
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

    /// Registry hands out a fresh program per named run.
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
            .seed(EntryHash([13u8; 32]))
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

    /// Registry is thread-local: cross-thread registrations stay invisible.
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

    /// Out-of-range actor ids are undeliverable, never truncated.
    #[test]
    fn net_send_rejects_ids_beyond_actor_range() {
        const BEYOND_RANGE: usize = u32::MAX as usize + 1;
        let res = run(
            RunConfig::builder()
                .seed(EntryHash([19u8; 32]))
                .max_steps(1024)
                .build(),
            |handle| async move {
                assert!(!handle.net_send(BEYOND_RANGE, 7));
                // A wrapping truncation would land on actor 0; the real id
                // space top must stay empty too. Both probes are
                // non-blocking receives over the shared queue.
                assert_eq!(handle.conn(ActorId(0), ActorId(0)).recv(), None);
                assert_eq!(handle.conn(ActorId(0), ActorId(u32::MAX)).recv(), None);
                // Positive control: an in-range high id still delivers.
                assert!(handle.net_send(u32::MAX as usize, 7));
                let receiver = handle.with_actor(ActorId(u32::MAX));
                assert_eq!(receiver.net_recv().await, 7);
            },
        );
        assert_run_program_outcome(res);
    }

    /// IPC-only `run(closure)` fails with `ProgramNotTransportable` pre-spawn.
    #[cfg(all(feature = "sim", not(feature = "sim-link")))]
    #[test]
    fn ipc_closure_run_reports_program_not_transportable() {
        let error = run(RunConfig::default(), |_handle| async {}).unwrap_err();
        assert!(
            matches!(error, RuntimeError::ProgramNotTransportable),
            "{error}"
        );
    }

    /// Journal root comes from this program: same seed reproduces it.
    #[cfg(feature = "sim-link")]
    #[test]
    fn sim_link_closure_roots_are_deterministic_and_program_sensitive() {
        let cfg = RunConfig::builder()
            .seed(EntryHash([17u8; 32]))
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
    #[test]
    fn surface_probe_compiles() {
        crate::runtime::assert_surface();
        crate::probe();
        let _seed = RunConfig::default().seed;
    }

    /// Receives work across the full actor id space.
    #[test]
    fn high_actor_ids_receive_across_full_id_space() {
        let res = run(
            RunConfig::builder()
                .seed(EntryHash([11u8; 32]))
                .max_steps(1024)
                .build(),
            |handle| async move {
                let sender = handle.with_actor(ActorId(u32::MAX - 1));
                let receiver = handle.with_actor(ActorId(u32::MAX));
                assert!(sender.net_send(u32::MAX as usize, 4242));
                assert_eq!(receiver.net_recv().await, 4242);
            },
        );
        assert_run_program_outcome(res);
    }

    /// Handles without a run context fail closed typed instead of ambient.
    #[test]
    fn handle_without_context_fails_closed() {
        let handle = Handle {
            #[cfg(feature = "sim-link")]
            boundary: None,
            seed: EntryHash([0u8; 32]),
            shared_net: shared_network(),
            actor: ActorId(0),
        };
        #[cfg(feature = "sim-link")]
        {
            assert!(matches!(
                handle.clock(),
                Err(crate::time::ClockError::NoContext)
            ));
            let mut handle = handle;
            assert!(matches!(
                handle.rng(StreamId(0)),
                Err(crate::rng::RngError::NoContext)
            ));
            assert!(matches!(
                handle.rng_next_u64(StreamId(0)),
                Err(crate::rng::RngError::NoContext)
            ));
        }
        #[cfg(all(feature = "sim", not(feature = "sim-link")))]
        {
            assert!(matches!(
                handle.clock(),
                Err(crate::time::ClockError::IpcLocal)
            ));
            let mut handle = handle;
            assert!(matches!(
                handle.rng(StreamId(0)),
                Err(crate::rng::RngError::IpcLocal)
            ));
        }
        #[cfg(not(any(feature = "sim", feature = "sim-link")))]
        {
            assert!(handle.clock().is_ok());
            let mut handle = handle;
            // Host entropy succeeds on test machines or fails typed; it
            // never falls back to wall time.
            match handle.rng_next_u64(StreamId(0)) {
                Ok(_) => {}
                Err(error) => assert!(matches!(
                    error,
                    crate::rng::RngError::EntropyUnavailable { .. }
                )),
            }
        }
    }
}
