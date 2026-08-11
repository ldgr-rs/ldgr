//! Deterministic single-threaded poll-based async executor.
//!
//! The executor drives real async tasks against the causal journal with the
//! same run-loop discipline as the instruction VM in [`crate::runtime`]: a
//! scheduler chooses among ready tasks, each scheduling decision is journaled
//! as an `RngDraw` entry, and the chosen task is polled exactly once per step.
//! Blocking effects (`sleep`, `recv`) park the task until a timer fires or a
//! message arrives; the executor journals the corresponding `TimerFire`,
//! `Wake`, and delivery entries in the same order the VM would.
//!
//! The executor is intentionally not `Send`: it is a single-threaded,
//! cooperative runtime and uses `Rc`-based interior mutability. Driving real
//! OS threads would break the determinism invariant.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use futures::task::noop_waker;

use crate::config::{FaultInjection, Policy, RunConfig};
use crate::effects::{Effects, Fs, Net, TaskId};
use crate::net::{DnsTable, Message, SimNet};
use crate::runtime::{RunResult, RuntimeError, SCHED_ACTOR, SCHED_STREAM};
use crate::scheduler::Scheduler;
use crate::seedtree::SeedTree;
use crate::simfs::SimFs;
use crate::time::{Clock, VirtualTime};
use core::convert::Infallible;
use ledger_format::{ActorId, EntryKind, FaultSpec, GenId, Hash, InputKey, Payload, StreamId};
use ledger_journal::{Journal, JournalCorrectnessMonitor};
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, TryRng};

/// Why a task is currently parked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockedOn {
    Timer,
    Message,
}

/// Build a fresh task entry wrapping a root future (adapter helper).
pub(crate) fn make_task_entry(future: Pin<Box<dyn Future<Output = ()> + 'static>>) -> TaskEntry {
    TaskEntry {
        future: Some(future),
        blocked_on: None,
        done: false,
        register: 0,
        timer_fired: false,
        stream_rngs: Vec::new(),
    }
}

/// One running or parked task in the executor.
pub(crate) struct TaskEntry {
    /// The task body. `None` while the task is being polled.
    future: Option<Pin<Box<dyn Future<Output = ()> + 'static>>>,
    /// Why the task is parked, or `None` when runnable.
    blocked_on: Option<BlockedOn>,
    /// Whether the task finished.
    done: bool,
    /// Task-local register, mirrored from the adapter instruction model.
    register: u64,
    /// Set when the task's most recent sleep timer fired.
    timer_fired: bool,
    /// One ChaCha20 stream per (task, stream), seeded lazily from the seed
    /// tree. Each stream is independent, so adding or reordering draws in one
    /// stream never perturbs another. State lives in the task table so cloning
    /// a boundary never duplicates draw state.
    stream_rngs: Vec<Option<ChaCha20Rng>>,
}

/// Shared executor state reachable from task boundaries.
///
/// Interior mutability via `RefCell` keeps the boundary `&self`-callable while
/// the executor mutates the journal, timers, network, and task table.
pub(crate) struct ExecutorShared {
    journal: RefCell<Journal>,
    time: RefCell<VirtualTime>,
    net: RefCell<SimNet>,
    fs: RefCell<SimFs>,
    /// Config-driven hostname-to-actor table for deterministic resolution.
    dns: DnsTable,
    scheduler: RefCell<Scheduler>,
    pub(crate) tasks: RefCell<Vec<TaskEntry>>,
    ready: RefCell<Vec<usize>>,
    dropped_events: Vec<Hash>,
    seed_tree: SeedTree,
    /// Swarm probabilities consumed by the boundary.
    swarm: crate::config::SwarmConfig,
    /// Monotonic offset for the `net` seed stream.
    net_offset: RefCell<u64>,
    /// Monotonic offset for the `fs` seed stream.
    fs_offset: RefCell<u64>,
    /// Per-actor count of journaled entries, for the coverage check.
    ///
    /// Every journal write funnels through [`Self::journal_append`], so the
    /// journal can never gain an entry the boundary did not report.
    coverage: RefCell<HashMap<ActorId, u64>>,
    /// Distinct crash-state classes applied this run (campaign budget).
    fault_classes_used: RefCell<HashSet<u64>>,
    /// Event ids whose scheduled fault injections took effect.
    applied_faults: RefCell<Vec<Hash>>,
    /// Fault schedule applied at exact causal positions.
    fault_schedule: Vec<FaultInjection>,
    /// Configured journaling-FS crash model, or `None` for the black-box
    /// `DropAllUnsynced` default.
    #[cfg(feature = "sim-fs-journaling")]
    fs_journaling: Option<crate::simfs::JournalingMode>,
}

impl ExecutorShared {
    /// Append one entry and count it against the actor's coverage.
    fn journal_append(
        &self,
        actor: ActorId,
        kind: EntryKind,
        parents: impl IntoIterator<Item = Hash>,
        payload: Payload,
    ) -> Result<Hash, ledger_journal::JournalError> {
        let id = self
            .journal
            .borrow_mut()
            .append(kind, actor, parents, payload)?;
        let mut coverage = self.coverage.borrow_mut();
        *coverage.entry(actor).or_insert(0) += 1;
        Ok(id)
    }

    /// Hash the vector-clock shape of a journaled entry into a stable u64.
    ///
    /// Returns `None` when the entry is absent from the journal.
    fn entry_vc_signature(&self, id: Hash) -> Option<u64> {
        let journal = self.journal.borrow();
        let entry = journal.get(&id)?;
        let digest = blake3::hash(&entry.vector_clock.encode());
        let bytes: [u8; 8] = digest.as_bytes()[..8].try_into().ok()?;
        Some(u64::from_le_bytes(bytes))
    }

    /// Forward an entry emission to the scheduler novelty model.
    ///
    /// The vector-clock signature is derived from the journaled entry, so the
    /// bandit can reward novel VC branch patterns. Only the bandit policy
    /// consumes novelty, so the signature hash is skipped under every other
    /// policy. Journal contents are unaffected by the skip.
    fn notify_entry(
        &self,
        actor: ActorId,
        kind: EntryKind,
        task_id: usize,
        entry_id: Option<Hash>,
    ) {
        let bandit_active = self.scheduler.borrow().novelty_active();
        let signature = if bandit_active {
            entry_id.and_then(|id| self.entry_vc_signature(id))
        } else {
            None
        };
        self.scheduler
            .borrow_mut()
            .on_entry_emitted(actor, kind, task_id, signature);
    }
}

/// Deterministic single-threaded poll-based executor.
pub struct Executor {
    shared: Rc<ExecutorShared>,
    config: RunConfig,
    steps: usize,
}

/// The executor itself drives all wakeups: a fired timer or a deliverable
/// message pushes the task onto the ready set. The waker passed to `poll` is
/// therefore a no-op; the future must never rely on the waker to resume it.
/// Using a no-op waker keeps the executor free of `Send`/`Sync` bounds on its
/// `Rc`-shared state.
impl Executor {
    /// Create an executor from a config and a set of root task futures.
    ///
    /// All tasks are inserted up front with their ids equal to their index.
    pub fn new(config: RunConfig, tasks: Vec<Pin<Box<dyn Future<Output = ()> + 'static>>>) -> Self {
        Self::with_shared(config, |shared| {
            for future in tasks {
                let mut tasks = shared.tasks.borrow_mut();
                tasks.push(make_task_entry(future));
            }
        })
    }

    /// Create an executor whose root futures are built from the shared state.
    ///
    /// The builder runs after the shared state exists, so root futures can
    /// capture [`Boundary`] handles (which need the shared state) before any
    /// task is inserted. Each boundary must use `task` values equal to the
    /// index the future will occupy in the task table.
    pub(crate) fn with_shared(
        config: RunConfig,
        builder: impl FnOnce(&Rc<ExecutorShared>),
    ) -> Self {
        Self::with_shared_and_replay(config, Vec::new(), builder)
    }

    /// Create an executor with a recorded replay decision sequence.
    ///
    /// The replay-exhaustion fallback defaults to [`Policy::Random`].
    pub(crate) fn with_shared_and_replay(
        config: RunConfig,
        replay: Vec<usize>,
        builder: impl FnOnce(&Rc<ExecutorShared>),
    ) -> Self {
        Self::with_shared_and_replay_and_fallback(config, replay, Policy::Random, builder)
    }

    /// Create an executor with a replay sequence and an explicit fallback policy.
    pub(crate) fn with_shared_and_replay_and_fallback(
        config: RunConfig,
        replay: Vec<usize>,
        fallback: Policy,
        builder: impl FnOnce(&Rc<ExecutorShared>),
    ) -> Self {
        let seed_tree = config.seed_tree();
        let scheduler =
            Scheduler::with_fallback(config.policy, seed_tree.clone(), replay, fallback);
        let mut net = SimNet::new();
        for &(from, to, cfg) in &config.links {
            net.set_link(from, to, cfg);
        }
        for injection in &config.fault_schedule {
            if let FaultInjection::Partition { src, dst } = injection {
                net.partition(*src as usize, *dst as usize);
            }
        }
        let shared = Rc::new(ExecutorShared {
            journal: RefCell::new(Journal::new()),
            time: RefCell::new(VirtualTime::default()),
            net: RefCell::new(net),
            fs: RefCell::new(SimFs::new()),
            dns: config.dns.clone(),
            scheduler: RefCell::new(scheduler),
            tasks: RefCell::new(Vec::new()),
            ready: RefCell::new(Vec::new()),
            dropped_events: config.dropped_events.clone(),
            seed_tree,
            swarm: config.swarm.clone(),
            net_offset: RefCell::new(0),
            fs_offset: RefCell::new(0),
            coverage: RefCell::new(HashMap::new()),
            fault_classes_used: RefCell::new(HashSet::new()),
            applied_faults: RefCell::new(Vec::new()),
            fault_schedule: config.fault_schedule.clone(),
            #[cfg(feature = "sim-fs-journaling")]
            fs_journaling: config.fs_journaling,
        });
        #[cfg(feature = "sim-fs-journaling")]
        if let Some(mode) = shared.fs_journaling {
            shared.fs.borrow_mut().set_journaling_mode(mode);
        }
        builder(&shared);
        let task_count = shared.tasks.borrow().len();
        let ready = (0..task_count).collect::<Vec<_>>();
        *shared.ready.borrow_mut() = ready;
        Self {
            shared,
            config,
            steps: 0,
        }
    }

    /// Run until all tasks finish or the step budget is reached.
    pub fn run(mut self) -> Result<RunResult, RuntimeError> {
        self.journal_spawns()?;
        while self.steps < self.config.max_steps {
            self.wake_blocked_with_messages()?;
            if self.shared.ready.borrow().is_empty() {
                self.advance_quiescent()?;
                if self.shared.ready.borrow().is_empty() {
                    if self.all_tasks_done() {
                        break;
                    }
                    if let Some(earliest) = self.shared.net.borrow().earliest_delivery_time()
                        && earliest > self.shared.time.borrow().now()
                    {
                        self.shared.time.borrow_mut().advance_to(earliest);
                        self.wake_blocked_with_messages()?;
                    }
                    if self.shared.ready.borrow().is_empty() {
                        break;
                    }
                }
            }
            let choice = {
                let ready = self.shared.ready.borrow();
                let step = self.steps;
                let choice = self.shared.scheduler.borrow_mut().choose(&ready, step);
                self.journal_rng_draw(choice)?;
                choice
            };
            let task_id = self.shared.ready.borrow_mut().swap_remove(choice);
            self.poll_task(task_id)?;
            // The DPOR driver is the only consumer of the per-step journal
            // boundary; skip the bookkeeping under every other policy.
            let trace_active = self.shared.scheduler.borrow().trace_active();
            if trace_active {
                let journal_len = self.shared.journal.borrow().len();
                self.shared
                    .scheduler
                    .borrow_mut()
                    .note_step_journal_len(journal_len);
            }
        }
        if self.steps == self.config.max_steps {
            return Err(RuntimeError::StepLimit {
                limit: self.config.max_steps,
            });
        }
        let journal = self.shared.journal.borrow().clone();
        let mut monitor_issues = if self.config.monitor {
            JournalCorrectnessMonitor::audit(&journal)
        } else {
            Vec::new()
        };
        if self.config.monitor {
            let coverage = self.shared.coverage.borrow();
            let boundary_entries = coverage
                .iter()
                .map(|(actor, count)| (*actor, *count))
                .collect::<Vec<_>>();
            drop(coverage);
            monitor_issues.extend(JournalCorrectnessMonitor::check_coverage(
                &journal,
                &boundary_entries,
            ));
        }
        let decisions = self.shared.scheduler.borrow().decisions().to_vec();
        let trace = self.shared.scheduler.borrow().trace().to_vec();
        let registers = self
            .shared
            .tasks
            .borrow()
            .iter()
            .map(|task| task.register)
            .collect::<Vec<_>>();
        Ok(RunResult {
            journal,
            decisions,
            trace,
            registers,
            steps: self.steps,
            monitor_issues,
            applied_faults: self.shared.applied_faults.borrow().clone(),
        })
    }

    /// Journal a `Spawn` entry for every task before the first scheduling step.
    fn journal_spawns(&self) -> Result<(), RuntimeError> {
        let tasks = self.shared.tasks.borrow();
        for (task_id, _) in tasks.iter().enumerate() {
            self.shared
                .journal_append(task_id as ActorId, EntryKind::Spawn, [], Payload::Empty)?;
        }
        Ok(())
    }

    /// Journal the scheduling draw that resolved to `choice`.
    fn journal_rng_draw(&self, choice: usize) -> Result<(), RuntimeError> {
        self.shared.journal_append(
            SCHED_ACTOR,
            EntryKind::RngDraw {
                stream: SCHED_STREAM,
            },
            [],
            Payload::Number(choice as u64),
        )?;
        Ok(())
    }

    /// Wake tasks parked on a message that became deliverable at the current time.
    fn wake_blocked_with_messages(&self) -> Result<(), RuntimeError> {
        let now = self.shared.time.borrow().now();
        let to_wake = {
            let net = self.shared.net.borrow();
            self.shared
                .tasks
                .borrow()
                .iter()
                .enumerate()
                .filter(|(task_id, task)| {
                    task.blocked_on == Some(BlockedOn::Message)
                        && net.has_ready_message(*task_id, now)
                })
                .map(|(task_id, _)| task_id)
                .collect::<Vec<_>>()
        };
        for task_id in to_wake {
            let send_id = self.shared.net.borrow().peek_ready_send_id(task_id, now);
            let wake_id = self.shared.journal_append(
                task_id as ActorId,
                EntryKind::Wake,
                send_id.into_iter().collect::<Vec<_>>(),
                Payload::Empty,
            )?;
            self.shared
                .notify_entry(task_id as ActorId, EntryKind::Wake, task_id, Some(wake_id));
            let mut tasks = self.shared.tasks.borrow_mut();
            tasks[task_id].blocked_on = None;
            self.shared.ready.borrow_mut().push(task_id);
        }
        Ok(())
    }

    /// Fire timers at quiescence and wake the released tasks, exactly as the
    /// VM does, including a post-fire message wake.
    fn advance_quiescent(&self) -> Result<(), RuntimeError> {
        let fired = self.shared.time.borrow_mut().advance_with_enablers();
        for fired in fired {
            let parents = fired.enabler.into_iter().collect::<Vec<_>>();
            let timer_fire = self.shared.journal_append(
                fired.task as ActorId,
                EntryKind::TimerFire,
                parents,
                Payload::Empty,
            )?;
            self.shared.notify_entry(
                fired.task as ActorId,
                EntryKind::TimerFire,
                fired.task,
                Some(timer_fire),
            );
            let wake_id = self.shared.journal_append(
                fired.task as ActorId,
                EntryKind::Wake,
                [timer_fire],
                Payload::Empty,
            )?;
            self.shared.notify_entry(
                fired.task as ActorId,
                EntryKind::Wake,
                fired.task,
                Some(wake_id),
            );
            let mut tasks = self.shared.tasks.borrow_mut();
            tasks[fired.task].timer_fired = true;
            tasks[fired.task].blocked_on = None;
            self.shared.ready.borrow_mut().push(fired.task);
        }
        self.wake_blocked_with_messages()
    }

    /// Poll one task once.
    fn poll_task(&mut self, task_id: usize) -> Result<(), RuntimeError> {
        {
            let tasks = self.shared.tasks.borrow();
            if tasks[task_id].done || tasks[task_id].blocked_on.is_some() {
                return Ok(());
            }
        }
        let mut future = {
            let mut tasks = self.shared.tasks.borrow_mut();
            match tasks[task_id].future.take() {
                Some(future) => future,
                None => return Ok(()),
            }
        };
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        let polled = Pin::new(&mut future).poll(&mut context);
        self.steps += 1;
        let mut tasks = self.shared.tasks.borrow_mut();
        match polled {
            Poll::Ready(()) => {
                tasks[task_id].done = true;
                tasks[task_id].future = Some(future);
            }
            Poll::Pending => {
                tasks[task_id].future = Some(future);
                if tasks[task_id].blocked_on.is_none() && !tasks[task_id].done {
                    self.shared.ready.borrow_mut().push(task_id);
                }
            }
        }
        Ok(())
    }

    fn all_tasks_done(&self) -> bool {
        self.shared.tasks.borrow().iter().all(|task| task.done)
    }
}

/// Outcome of a swarm network policy decision.
enum SwarmAction {
    /// Deliver the message (possibly with an extra delay).
    Deliver,
    /// Delay delivery by the given tick count.
    Delay(u64),
    /// Drop the message; a `Drop` fault was already journaled.
    Drop,
}

/// Boundary through which a task calls deterministic effects.
///
/// A task owns one boundary for the duration of its body. The boundary is
/// `Clone` and `Rc`-shared, so child tasks spawned through it keep accessing
/// the same journal, timers, network, and storage.
#[derive(Clone)]
pub struct Boundary {
    shared: Rc<ExecutorShared>,
    task: usize,
    /// Live RNG handles, one slot per stream id.
    ///
    /// Each handle clones the shared state, so cloning a boundary never
    /// duplicates draw state: every stream's ChaCha20 lives in the shared task
    /// table, keyed by stream id.
    rng_streams: Vec<Option<StreamRng>>,
}

impl Boundary {
    /// Create a boundary for a task id inside a shared executor.
    pub(crate) fn for_task(shared: Rc<ExecutorShared>, task: usize) -> Self {
        Self {
            shared,
            task,
            rng_streams: Vec::new(),
        }
    }

    /// Journal one entry with this task as the actor.
    fn append(
        &self,
        kind: EntryKind,
        parents: impl IntoIterator<Item = Hash>,
        payload: Payload,
    ) -> Result<Hash, ledger_journal::JournalError> {
        let id = self
            .shared
            .journal_append(self.task as ActorId, kind, parents, payload)?;
        self.shared
            .notify_entry(self.task as ActorId, kind, self.task, Some(id));
        Ok(id)
    }

    /// Count one journaled entry against the actor's coverage.
    ///
    /// The storage layer journals through `SimFs` directly (it cannot reach
    /// the executor's coverage counter), so the boundary records the write
    /// after the fact to keep the coverage ledger exact.
    fn note_journaled(&self, actor: ActorId) {
        let mut coverage = self.shared.coverage.borrow_mut();
        *coverage.entry(actor).or_insert(0) += 1;
    }

    /// Draw a probability in `0.0 .. 1.0` from the `net` seed stream.
    ///
    /// The draw consumes the next monotonic offset so two draws never collide
    /// and the sequence is deterministic per run.
    fn net_draw(&self) -> f64 {
        let mut offset = self.shared.net_offset.borrow_mut();
        let value = self.shared.seed_tree.draw_u64("net", *offset);
        *offset += 1;
        value as f64 / u64::MAX as f64
    }

    /// Draw a probability in `0.0 .. 1.0` from the `fs` seed stream.
    fn fs_draw(&self) -> f64 {
        let mut offset = self.shared.fs_offset.borrow_mut();
        let value = self.shared.seed_tree.draw_u64("fs", *offset);
        *offset += 1;
        value as f64 / u64::MAX as f64
    }

    /// Apply a swarm drop or delay decision to a send, journaling a `Drop`
    /// fault when the message is lost.
    ///
    /// With the default zero-probability swarm this consumes no draws and
    /// returns [`SwarmAction::Deliver`] unchanged, keeping journals
    /// byte-identical to the pre-swarm path.
    fn swarm_send_policy(&self, send_id: Hash) -> SwarmAction {
        let swarm = &self.shared.swarm;
        if swarm.drop_probability > 0.0 && self.net_draw() < swarm.drop_probability {
            let _ = self.append(
                EntryKind::Fault {
                    fault: FaultSpec::Drop,
                },
                [send_id],
                Payload::Empty,
            );
            return SwarmAction::Drop;
        }
        if swarm.delay_probability > 0.0
            && swarm.max_delay_ticks > 0
            && self.net_draw() < swarm.delay_probability
        {
            let delay = self.net_draw_delay(swarm.max_delay_ticks);
            return SwarmAction::Delay(delay);
        }
        SwarmAction::Deliver
    }

    /// Draw a swarm delay in `0 ..= max_delay_ticks` from the `net` stream.
    fn net_draw_delay(&self, max_delay_ticks: u64) -> u64 {
        let mut offset = self.shared.net_offset.borrow_mut();
        let value = self.shared.seed_tree.draw_u64("net", *offset);
        *offset += 1;
        value % (max_delay_ticks + 1)
    }

    /// Apply a swarm crash-state sample after a storage write, when configured.
    ///
    /// With `crash_probability == 0.0` this consumes no draws and returns
    /// `Ok(())`, keeping journals byte-identical to the pre-swarm path. On a
    /// sampled crash it applies a deterministic crash operator and journals
    /// `Fault { CrashState(k) }`.
    fn maybe_crash_on_write(
        &self,
        path: &str,
        value: u64,
    ) -> Result<(), ledger_journal::JournalError> {
        let swarm = &self.shared.swarm;
        if swarm.crash_probability <= 0.0 {
            return Ok(());
        }
        if self.fs_draw() >= swarm.crash_probability {
            return Ok(());
        }
        // The probability and choice draws above always happen so the fs
        // stream offsets stay stable; only the application is gated.
        let mut offset = self.shared.fs_offset.borrow_mut();
        let choice = self.shared.seed_tree.draw_u64("fs", *offset);
        *offset += 1;
        let operator = match choice % 4 {
            0 => crate::simfs::CrashOperator::DropAllUnsynced,
            1 => {
                let mut dropped = HashSet::new();
                dropped.insert(path.to_owned());
                crate::simfs::CrashOperator::DropSubset(dropped)
            }
            2 => crate::simfs::CrashOperator::TornWrite {
                path: path.to_owned(),
                partial_value: value.saturating_div(2),
            },
            _ => crate::simfs::CrashOperator::BitFlipCorruption {
                path: path.to_owned(),
                xor_mask: 1,
            },
        };
        let state_index = match operator {
            crate::simfs::CrashOperator::DropAllUnsynced => 0,
            crate::simfs::CrashOperator::DropSubset(_) => 1,
            crate::simfs::CrashOperator::TornWrite { .. } => 2,
            crate::simfs::CrashOperator::BitFlipCorruption { .. } => 3,
            crate::simfs::CrashOperator::TornWriteSectors { .. } => 4,
            crate::simfs::CrashOperator::CorruptRange { .. } => 5,
        };
        let mut fault_classes = self.shared.fault_classes_used.borrow_mut();
        if fault_classes.len() >= swarm.fault_classes_per_run.max(1) {
            return Ok(());
        }
        fault_classes.insert(state_index);
        drop(fault_classes);
        self.shared.fs.borrow_mut().apply_crash_operator(&operator);
        self.append(
            EntryKind::Fault {
                fault: FaultSpec::CrashState(state_index),
            },
            [],
            Payload::Empty,
        )?;
        Ok(())
    }

    /// Apply the configured crash model to the simulated storage.
    ///
    /// With a journaling mode configured the write-ahead journal replays
    /// before the crash operator drops unsynced state; without one the
    /// black-box `DropAllUnsynced` operator applies. The default (no mode)
    /// stays byte-identical to the historical crash path.
    fn fs_crash(&self) {
        #[cfg(feature = "sim-fs-journaling")]
        if self.shared.fs_journaling.is_some() {
            self.shared.fs.borrow_mut().crash_journaled();
            return;
        }
        self.shared.fs.borrow_mut().crash();
    }

    /// Journal one entry with an explicit actor, without scheduler notification.
    fn append_for_actor(
        &self,
        actor: ActorId,
        kind: EntryKind,
        parents: impl IntoIterator<Item = Hash>,
        payload: Payload,
    ) -> Result<Hash, ledger_journal::JournalError> {
        self.shared.journal_append(actor, kind, parents, payload)
    }

    /// Receive a message, journaling `Recv` or parking with a `Block` entry.
    ///
    /// This is an inherent method (not on the `Effects` trait): only the
    /// executor boundary can suspend on a message, so `SimBackend` and
    /// `TokioBackend` do not need to implement it.
    pub async fn recv(&self) -> u64 {
        RecvFuture {
            shared: Rc::clone(&self.shared),
            task: self.task,
        }
        .await
    }

    /// Journal an `Outcome` entry carrying the task register (test helper).
    pub fn outcome(&self, value: u64) -> Result<Hash, ledger_journal::JournalError> {
        self.append(EntryKind::Outcome, [], Payload::Number(value))
    }

    /// Return whether a message is currently deliverable to this task.
    pub fn has_ready_message(&self) -> bool {
        let now = self.shared.time.borrow().now();
        self.shared.net.borrow().has_ready_message(self.task, now)
    }

    /// Resolve a hostname to a task id from the deterministic DNS table.
    ///
    /// The table is config-driven, so the result is identical across runs
    /// that share the config. An unknown name resolves to `None`. Resolution
    /// is a pure lookup: it journals nothing and never touches the ambient
    /// host.
    pub fn resolve(&self, name: &str) -> Option<usize> {
        self.shared.dns.resolve(name)
    }

    /// Send a message immediately, journaling a `Send` entry.
    pub fn send(&self, to: usize, payload: u64) -> bool {
        Net::send(
            self,
            Message {
                from: self.task,
                to,
                payload,
                send_id: [0; 32],
                deliver_at: self.shared.time.borrow().now(),
            },
        )
    }

    /// Toggle a directed partition at the current point of the run.
    ///
    /// The toggle journals a `Fault { Partition { src, dst } }` entry and
    /// applies it to the live network immediately: subsequent sends on the
    /// (src, dst) link are refused until the same pair is toggled again. The
    /// journaled entry is the causal record of the matrix change, so a replay
    /// applies the same faults in causal order. A config-scheduled partition
    /// seeds the same matrix from run start.
    pub fn apply_partition(
        &self,
        src: usize,
        dst: usize,
    ) -> Result<Hash, ledger_journal::JournalError> {
        let fault = FaultSpec::Partition {
            src: src as ActorId,
            dst: dst as ActorId,
        };
        let id = self.append(EntryKind::Fault { fault }, [], Payload::Empty)?;
        let applied = self
            .shared
            .net
            .borrow_mut()
            .apply_fault(&FaultSpec::Partition {
                src: src as ActorId,
                dst: dst as ActorId,
            });
        debug_assert!(applied, "a partition fault always applies");
        Ok(id)
    }

    /// Send a message with a virtual-time delivery delay (adapter helper).
    pub(crate) fn send_timed(&self, to: usize, payload: u64, delay: u64) -> bool {
        let now = self.shared.time.borrow().now();
        let Some(id) = self
            .append(
                EntryKind::Send,
                [],
                Payload::Pair {
                    left: to as u64,
                    right: payload,
                },
            )
            .ok()
        else {
            return false;
        };
        if self.shared.dropped_events.contains(&id) {
            let _ = self.append(
                EntryKind::Fault {
                    fault: FaultSpec::Drop,
                },
                [id],
                Payload::Empty,
            );
            return true;
        }
        let injected_delay = match self.inject_send_fault(id) {
            Some(None) => return true,
            Some(Some(ticks)) => ticks,
            None => 0,
        };
        let total_delay = match self.swarm_send_policy(id) {
            SwarmAction::Drop => return true,
            SwarmAction::Delay(extra) => delay.saturating_add(extra).saturating_add(injected_delay),
            SwarmAction::Deliver => delay.saturating_add(injected_delay),
        };
        let delivered = if self.shared.net.borrow().link_configured(self.task, to) {
            self.send_via_link(self.task, to, payload, id, now, total_delay)
        } else {
            self.shared
                .net
                .borrow_mut()
                .send_at(self.task, to, payload, id, now, total_delay)
        };
        if !delivered {
            self.journal_net_loss(id, to);
        }
        delivered
    }

    /// Journal the fault class for a message the network refused: a partition
    /// when the link is partitioned, otherwise a loss drop.
    fn journal_net_loss(&self, send_id: Hash, to: usize) {
        let partitioned = self.shared.net.borrow().is_partitioned(self.task, to);
        let fault = if partitioned {
            FaultSpec::Partition {
                src: self.task as ActorId,
                dst: to as ActorId,
            }
        } else {
            FaultSpec::Drop
        };
        let _ = self.append(EntryKind::Fault { fault }, [send_id], Payload::Empty);
    }

    /// Send a message through a configured link, drawing jitter and loss from
    /// the shared `net` seed stream offset.
    fn send_via_link(
        &self,
        from: usize,
        to: usize,
        payload: u64,
        send_id: Hash,
        now: u64,
        base_delay: u64,
    ) -> bool {
        self.shared.net.borrow_mut().send_via_link(
            Message {
                from,
                to,
                payload,
                send_id,
                deliver_at: now,
            },
            now,
            base_delay,
            |bound| {
                let mut offset = self.shared.net_offset.borrow_mut();
                let value = self.shared.seed_tree.draw_u64("net", *offset);
                *offset += 1;
                value % bound.max(1)
            },
        )
    }

    /// Return the scheduled fault injection targeting `id`, if any.
    fn schedule_injection_for(&self, id: Hash) -> Option<&FaultInjection> {
        self.shared
            .fault_schedule
            .iter()
            .find(|injection| match injection {
                FaultInjection::Drop(target)
                | FaultInjection::Delay { send: target, .. }
                | FaultInjection::Crash(target)
                | FaultInjection::Corrupt { write: target, .. }
                | FaultInjection::CrashState { write: target, .. } => *target == id,
                FaultInjection::Partition { .. } => false,
            })
    }

    /// Record that the fault injection for `id` took effect.
    fn mark_fault_applied(&self, id: Hash) {
        let mut applied = self.shared.applied_faults.borrow_mut();
        if !applied.contains(&id) {
            applied.push(id);
        }
    }

    /// Apply a scheduled fault to an outgoing message, returning the extra
    /// delay ticks in the delivered case.
    ///
    /// Returns `None` when the fault drops the message or when no fault
    /// targets it.
    fn inject_send_fault(&self, send_id: Hash) -> Option<Option<u64>> {
        match self.schedule_injection_for(send_id) {
            Some(FaultInjection::Drop(_)) => {
                self.mark_fault_applied(send_id);
                let _ = self.append(
                    EntryKind::Fault {
                        fault: FaultSpec::Drop,
                    },
                    [send_id],
                    Payload::Empty,
                );
                Some(None)
            }
            Some(FaultInjection::Delay { send, ticks }) => {
                self.mark_fault_applied(*send);
                Some(Some(*ticks))
            }
            _ => None,
        }
    }

    /// Apply a scheduled fault to a completed storage write.
    fn inject_write_fault(&self, write_id: Hash, path: &str) {
        match self.schedule_injection_for(write_id) {
            Some(FaultInjection::Crash(_)) => {
                self.mark_fault_applied(write_id);
                self.fs_crash();
                let _ = self.append(
                    EntryKind::Fault {
                        fault: FaultSpec::CrashState(0),
                    },
                    [],
                    Payload::Empty,
                );
            }
            Some(FaultInjection::Corrupt { write, xor_mask }) => {
                self.mark_fault_applied(*write);
                let operator = crate::simfs::CrashOperator::BitFlipCorruption {
                    path: path.to_owned(),
                    xor_mask: *xor_mask,
                };
                self.shared.fs.borrow_mut().apply_crash_operator(&operator);
                let _ = self.append(
                    EntryKind::Fault {
                        fault: FaultSpec::CrashState(3),
                    },
                    [],
                    Payload::Empty,
                );
            }
            Some(FaultInjection::CrashState { write, state }) => {
                self.mark_fault_applied(*write);
                let operator =
                    match *state {
                        0 => crate::simfs::CrashOperator::DropAllUnsynced,
                        1 => crate::simfs::CrashOperator::DropSubset(
                            std::collections::HashSet::from([path.to_owned()]),
                        ),
                        2 => crate::simfs::CrashOperator::TornWrite {
                            path: path.to_owned(),
                            partial_value: 0,
                        },
                        _ => crate::simfs::CrashOperator::DropAllUnsynced,
                    };
                self.shared.fs.borrow_mut().apply_crash_operator(&operator);
                let _ = self.append(
                    EntryKind::Fault {
                        fault: FaultSpec::CrashState(*state),
                    },
                    [],
                    Payload::Empty,
                );
            }
            _ => {}
        }
    }

    /// Park the task on a sleep timer, journaling a `TimerSet` entry.
    ///
    /// The timer carries the `TimerSet` entry as its enabler so the fired
    /// `TimerFire` journals with the correct parent. Any stale `timer_fired`
    /// flag from a prior sleep is cleared so a later park cannot short-circuit.
    pub(crate) fn park_sleep(&self, ticks: u64) -> Result<(), ledger_journal::JournalError> {
        let timer_set = self.append(EntryKind::TimerSet, [], Payload::Number(ticks))?;
        self.shared
            .time
            .borrow_mut()
            .set_with_enabler(ticks, self.task, Some(timer_set));
        let mut tasks = self.shared.tasks.borrow_mut();
        tasks[self.task].timer_fired = false;
        tasks[self.task].blocked_on = Some(BlockedOn::Timer);
        Ok(())
    }

    /// Park the task waiting for a message, journaling a `Block` entry.
    pub(crate) fn park_message(&self) -> Result<(), ledger_journal::JournalError> {
        self.append(EntryKind::Block, [], Payload::Empty)?;
        self.shared.tasks.borrow_mut()[self.task].blocked_on = Some(BlockedOn::Message);
        Ok(())
    }

    /// Journal a `Block` entry for an explicit yield without parking.
    pub(crate) fn yield_block(&self) -> Result<(), ledger_journal::JournalError> {
        self.append(EntryKind::Block, [], Payload::Empty)?;
        Ok(())
    }

    /// Journal a `ClockRead` entry carrying the current virtual time, returning it.
    pub(crate) fn read_clock(&self) -> Result<u64, ledger_journal::JournalError> {
        let now = self.shared.time.borrow().now();
        self.append(EntryKind::ClockRead, [], Payload::Number(now))?;
        Ok(now)
    }

    /// Take the first deliverable message for this task, journaling a `Recv`
    /// entry, and return its payload.
    pub(crate) fn recv_now(&self) -> Option<u64> {
        let now = self.shared.time.borrow().now();
        let message = self.shared.net.borrow_mut().recv_at(self.task, now)?;
        self.append(
            EntryKind::Recv,
            [message.send_id],
            Payload::Number(message.payload),
        )
        .ok()?;
        Some(message.payload)
    }

    /// Journal an `InputStep` entry carrying a generator identity, a replay
    /// key, and the input value.
    pub(crate) fn input_step(
        &self,
        generator: GenId,
        replay: InputKey,
        value: u64,
    ) -> Result<(), ledger_journal::JournalError> {
        self.append(
            EntryKind::InputStep { generator, replay },
            [],
            Payload::Number(value),
        )?;
        Ok(())
    }

    /// Journal an `Assert` entry carrying a boolean as 1 or 0.
    pub(crate) fn assert_entry(&self, passed: bool) -> Result<(), ledger_journal::JournalError> {
        self.append(EntryKind::Assert, [], Payload::Number(u64::from(passed)))?;
        Ok(())
    }

    /// Journal the terminal `Outcome` entry of a finished program.
    pub(crate) fn outcome_done(&self) -> Result<(), ledger_journal::JournalError> {
        self.append(EntryKind::Outcome, [], Payload::Text("done".into()))?;
        Ok(())
    }

    pub fn set_register(&self, value: u64) {
        self.shared.tasks.borrow_mut()[self.task].register = value;
    }

    pub fn register(&self) -> u64 {
        self.shared.tasks.borrow()[self.task].register
    }
    /// Spawn a child task, giving it a boundary bound to its own task id.
    ///
    /// The child body receives a fresh [`Boundary`] so its journaled entries
    /// use the child's actor and sequence. The parent keeps its own boundary.
    pub fn spawn_task(
        &self,
        body: impl FnOnce(Boundary) -> Pin<Box<dyn Future<Output = ()> + 'static>>,
    ) -> TaskId {
        let (id, _) = {
            let mut tasks = self.shared.tasks.borrow_mut();
            let id = tasks.len() as u64;
            let child_boundary = Boundary::for_task(Rc::clone(&self.shared), id as usize);
            let future = body(child_boundary);
            tasks.push(TaskEntry {
                future: Some(future),
                blocked_on: None,
                done: false,
                register: 0,
                timer_fired: false,
                stream_rngs: Vec::new(),
            });
            (id, ())
        };
        let _ = self.append_for_actor(id as ActorId, EntryKind::Spawn, [], Payload::Empty);
        self.shared.ready.borrow_mut().push(id as usize);
        id
    }
}

/// One deterministic RNG stream handle sharing the boundary's draw state.
///
/// The handle clones the executor shared state, so the returned `&mut` handle
/// lives inside the boundary while the per-stream ChaCha20 state stays in the
/// task table. No `Weak` is needed: the boundary owns the handle, and the
/// shared state never points back to the boundary. Cloning a handle clones the
/// `Rc`, never the draw state.
#[derive(Clone)]
struct StreamRng {
    shared: Rc<ExecutorShared>,
    task: usize,
    stream: StreamId,
    /// Precomputed seed-tree label for this stream, built once per handle so
    /// the hot draw path never re-formats it.
    label: String,
}

impl TryRng for StreamRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let value = {
            let mut tasks = self.shared.tasks.borrow_mut();
            let entry = &mut tasks[self.task];
            if entry.stream_rngs.len() <= self.stream as usize {
                entry.stream_rngs.resize(self.stream as usize + 1, None);
            }
            let rng = entry.stream_rngs[self.stream as usize]
                .get_or_insert_with(|| self.shared.seed_tree.rng(&self.label));
            rng.next_u64()
        };
        let kind = EntryKind::RngDraw {
            stream: self.stream,
        };
        if let Ok(id) =
            self.shared
                .journal_append(self.task as ActorId, kind, [], Payload::Number(value))
        {
            self.shared
                .notify_entry(self.task as ActorId, kind, self.task, Some(id));
        }
        Ok(value)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        rand_core::utils::fill_bytes_via_next_word(dst, || self.try_next_u64())
    }
}

impl Effects for Boundary {
    fn clock(&self) -> Clock {
        Clock::new(self.shared.time.borrow().now())
    }

    fn rng(&mut self, stream: StreamId) -> &mut impl rand_core::Rng {
        let idx = stream as usize;
        while self.rng_streams.len() <= idx {
            self.rng_streams.push(None);
        }
        self.rng_streams[idx].get_or_insert_with(|| StreamRng {
            shared: Rc::clone(&self.shared),
            task: self.task,
            stream,
            label: format!("app/{stream}"),
        })
    }

    async fn sleep(&self, d: core::time::Duration) {
        let ticks = d.as_micros() as u64;
        let timer_set = self
            .append(EntryKind::TimerSet, [], Payload::Number(ticks))
            .ok();
        self.shared
            .time
            .borrow_mut()
            .set_with_enabler(ticks, self.task, timer_set);
        self.shared.tasks.borrow_mut()[self.task].blocked_on = Some(BlockedOn::Timer);
        SleepFuture {
            shared: Rc::clone(&self.shared),
            task: self.task,
        }
        .await;
    }

    fn net(&self) -> &dyn Net {
        self
    }

    fn fs(&self) -> &dyn Fs {
        self
    }
}

impl Net for Boundary {
    fn send(&self, message: Message) -> bool {
        let Some(id) = self
            .append(
                EntryKind::Send,
                [],
                Payload::Pair {
                    left: message.to as u64,
                    right: message.payload,
                },
            )
            .ok()
        else {
            return false;
        };
        if self.shared.dropped_events.contains(&id) {
            let _ = self.append(
                EntryKind::Fault {
                    fault: FaultSpec::Drop,
                },
                [id],
                Payload::Empty,
            );
            return true;
        }
        let injected_delay = match self.inject_send_fault(id) {
            Some(None) => return true,
            Some(Some(ticks)) => ticks,
            None => 0,
        };
        match self.swarm_send_policy(id) {
            SwarmAction::Drop => return true,
            SwarmAction::Delay(extra) => {
                let extra = extra.saturating_add(injected_delay);
                let now = self.shared.time.borrow().now();
                let link_configured = self
                    .shared
                    .net
                    .borrow()
                    .link_configured(message.from, message.to);
                let delivered = if link_configured {
                    self.send_via_link(message.from, message.to, message.payload, id, now, extra)
                } else {
                    self.shared.net.borrow_mut().send_at(
                        message.from,
                        message.to,
                        message.payload,
                        id,
                        now,
                        extra,
                    )
                };
                if !delivered {
                    self.journal_net_loss(id, message.to);
                }
                return delivered;
            }
            SwarmAction::Deliver => {}
        }
        let delivered = if self
            .shared
            .net
            .borrow()
            .link_configured(message.from, message.to)
        {
            let now = self.shared.time.borrow().now();
            self.send_via_link(
                message.from,
                message.to,
                message.payload,
                id,
                now,
                injected_delay,
            )
        } else {
            self.shared.net.borrow_mut().send(Message {
                send_id: id,
                ..message
            })
        };
        if !delivered {
            self.journal_net_loss(id, message.to);
        }
        delivered
    }

    fn recv(&self, task: usize, now: u64) -> Option<Message> {
        let message = self.shared.net.borrow_mut().recv_at(task, now)?;
        let _ = self.append(
            EntryKind::Recv,
            [message.send_id],
            Payload::Number(message.payload),
        );
        Some(message)
    }

    fn has_ready_message(&self, task: usize, now: u64) -> bool {
        self.shared.net.borrow().has_ready_message(task, now)
    }
}

impl Fs for Boundary {
    fn write(&self, path: &str, value: u64) -> Result<Hash, ledger_journal::JournalError> {
        let mut journal = self.shared.journal.borrow_mut();
        let mut fs = self.shared.fs.borrow_mut();
        let id = fs.write(&mut journal, self.task as ActorId, path, value)?;
        self.note_journaled(self.task as ActorId);
        drop(fs);
        drop(journal);
        self.shared.notify_entry(
            self.task as ActorId,
            EntryKind::FsWrite,
            self.task,
            Some(id),
        );
        self.inject_write_fault(id, path);
        self.maybe_crash_on_write(path, value)?;
        Ok(id)
    }

    fn fsync(&self) -> Result<Hash, ledger_journal::JournalError> {
        let mut journal = self.shared.journal.borrow_mut();
        let mut fs = self.shared.fs.borrow_mut();
        let id = fs.fsync(&mut journal, self.task as ActorId)?;
        self.note_journaled(self.task as ActorId);
        drop(fs);
        drop(journal);
        self.shared.notify_entry(
            self.task as ActorId,
            EntryKind::FsFsync,
            self.task,
            Some(id),
        );
        Ok(id)
    }

    fn read(&self, path: &str) -> Result<Option<u64>, ledger_journal::JournalError> {
        let mut journal = self.shared.journal.borrow_mut();
        let fs = self.shared.fs.borrow();
        let value = fs.read(&mut journal, self.task as ActorId, path)?;
        self.note_journaled(self.task as ActorId);
        drop(fs);
        drop(journal);
        // The FsRead entry is the actor's head; derive its signature directly.
        let read_id = self
            .shared
            .journal
            .borrow()
            .head_for_actor(self.task as ActorId);
        self.shared
            .notify_entry(self.task as ActorId, EntryKind::FsRead, self.task, read_id);
        Ok(value)
    }

    fn crash(&self) {
        let _ = self.append(
            EntryKind::Fault {
                fault: FaultSpec::CrashState(0),
            },
            [],
            Payload::Empty,
        );
        self.fs_crash();
    }
}

/// A sleep future that resolves when the executor fires the task's timer.
struct SleepFuture {
    shared: Rc<ExecutorShared>,
    task: usize,
}

impl Future for SleepFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<()> {
        let mut tasks = self.shared.tasks.borrow_mut();
        if tasks[self.task].timer_fired {
            tasks[self.task].timer_fired = false;
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// A receive future that parks the task until a message is deliverable.
struct RecvFuture {
    shared: Rc<ExecutorShared>,
    task: usize,
}

impl Future for RecvFuture {
    type Output = u64;

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<u64> {
        let now = self.shared.time.borrow().now();
        if let Some(message) = self.shared.net.borrow_mut().recv_at(self.task, now) {
            if let Ok(id) = self.shared.journal_append(
                self.task as ActorId,
                EntryKind::Recv,
                [message.send_id],
                Payload::Number(message.payload),
            ) {
                self.shared.notify_entry(
                    self.task as ActorId,
                    EntryKind::Recv,
                    self.task,
                    Some(id),
                );
            }
            Poll::Ready(message.payload)
        } else {
            if let Ok(id) = self.shared.journal_append(
                self.task as ActorId,
                EntryKind::Block,
                [],
                Payload::Empty,
            ) {
                self.shared.notify_entry(
                    self.task as ActorId,
                    EntryKind::Block,
                    self.task,
                    Some(id),
                );
            }
            self.shared.tasks.borrow_mut()[self.task].blocked_on = Some(BlockedOn::Message);
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::time::Duration;

    fn config(seed: u8, max_steps: usize) -> RunConfig {
        RunConfig {
            seed: [seed; 32],
            policy: crate::config::Policy::Random,
            max_steps,
            ..RunConfig::default()
        }
    }

    fn boxed(
        future: impl Future<Output = ()> + 'static,
    ) -> Pin<Box<dyn Future<Output = ()> + 'static>> {
        Box::pin(future)
    }

    /// A root task body: a function building a boxed future from a boundary.
    type TaskBody = fn(Boundary) -> Pin<Box<dyn Future<Output = ()> + 'static>>;

    /// Build an executor where root task `i` runs `bodies[i]` with a boundary.
    fn executor_with<const N: usize>(
        seed: u8,
        max_steps: usize,
        bodies: [TaskBody; N],
    ) -> Executor {
        Executor::with_shared(config(seed, max_steps), |shared| {
            for (task_id, body) in bodies.iter().enumerate() {
                let boundary = Boundary::for_task(Rc::clone(shared), task_id);
                let future = body(boundary);
                let mut tasks = shared.tasks.borrow_mut();
                tasks.push(TaskEntry {
                    future: Some(future),
                    blocked_on: None,
                    done: false,
                    register: 0,
                    timer_fired: false,
                    stream_rngs: Vec::new(),
                });
            }
        })
    }

    #[test]
    fn async_tasks_sleep_and_advance_virtual_time() {
        let executor = executor_with::<2>(
            1,
            1024,
            [
                |boundary| {
                    boxed(async move {
                        boundary.sleep(Duration::from_micros(5)).await;
                        let _ = boundary.outcome(1);
                    })
                },
                |boundary| {
                    boxed(async move {
                        boundary.sleep(Duration::from_micros(1)).await;
                        let _ = boundary.outcome(2);
                    })
                },
            ],
        );
        let run = executor.run().unwrap();
        let kinds = run
            .journal
            .entries()
            .map(|entry| entry.data.kind)
            .collect::<Vec<_>>();
        assert!(kinds.iter().any(|kind| matches!(kind, EntryKind::TimerSet)));
        assert!(
            kinds
                .iter()
                .any(|kind| matches!(kind, EntryKind::TimerFire))
        );
        assert!(kinds.iter().any(|kind| matches!(kind, EntryKind::Wake)));
        assert!(kinds.iter().any(|kind| matches!(kind, EntryKind::Outcome)));
        assert!(run.steps > 0);
        assert!(
            run.monitor_issues.is_empty(),
            "monitor issues: {:?}",
            run.monitor_issues
        );
    }

    #[test]
    fn async_tasks_exchange_messages() {
        let executor = executor_with::<2>(
            2,
            1024,
            [
                |boundary| {
                    boxed(async move {
                        let _ = boundary.send(1, 42);
                    })
                },
                |boundary| {
                    boxed(async move {
                        let value = boundary.recv().await;
                        assert_eq!(value, 42);
                        let _ = boundary.outcome(value);
                    })
                },
            ],
        );
        let run = executor.run().unwrap();
        let kinds = run
            .journal
            .entries()
            .map(|entry| entry.data.kind)
            .collect::<Vec<_>>();
        assert!(kinds.iter().any(|kind| matches!(kind, EntryKind::Send)));
        assert!(kinds.iter().any(|kind| matches!(kind, EntryKind::Recv)));
        assert!(kinds.iter().any(|kind| matches!(kind, EntryKind::Outcome)));
        assert!(
            run.monitor_issues.is_empty(),
            "monitor issues: {:?}",
            run.monitor_issues
        );
    }

    #[test]
    fn spawned_child_task_is_executed() {
        let executor = Executor::with_shared(config(3, 1024), |shared| {
            let boundary = Boundary::for_task(Rc::clone(shared), 0);
            let root = boxed(async move {
                let child = boundary.spawn_task(|child_boundary| {
                    boxed(async move {
                        let _ = child_boundary.outcome(7);
                    })
                });
                assert_eq!(child, 1);
            });
            let mut tasks = shared.tasks.borrow_mut();
            tasks.push(TaskEntry {
                future: Some(root),
                blocked_on: None,
                done: false,
                register: 0,
                timer_fired: false,
                stream_rngs: Vec::new(),
            });
        });
        let run = executor.run().unwrap();
        let kinds = run
            .journal
            .entries()
            .map(|entry| entry.data.kind)
            .collect::<Vec<_>>();
        assert!(
            kinds
                .iter()
                .filter(|kind| matches!(kind, EntryKind::Spawn))
                .count()
                >= 2
        );
        assert!(kinds.iter().any(|kind| matches!(kind, EntryKind::Outcome)));
        assert!(
            run.monitor_issues.is_empty(),
            "monitor issues: {:?}",
            run.monitor_issues
        );
    }

    #[test]
    fn app_streams_are_independent_across_tasks_and_streams() {
        let extract_stream_one = |run: &RunResult| -> Vec<u64> {
            run.journal
                .entries()
                .filter_map(|entry| match (&entry.data.kind, &entry.data.payload) {
                    (EntryKind::RngDraw { stream: 1 }, Payload::Number(value)) => Some(*value),
                    _ => None,
                })
                .collect()
        };

        let sparse = executor_with::<1>(
            7,
            2048,
            [|mut boundary| {
                boxed(async move {
                    for _ in 0..3 {
                        let _ = boundary.rng(0).next_u64();
                    }
                    let _ = boundary.rng(1).next_u64();
                    let _ = boundary.rng(1).next_u64();
                    let _ = boundary.outcome(0);
                })
            }],
        );
        let dense = executor_with::<1>(
            7,
            2048,
            [|mut boundary| {
                boxed(async move {
                    for _ in 0..7 {
                        let _ = boundary.rng(0).next_u64();
                    }
                    let _ = boundary.rng(1).next_u64();
                    let _ = boundary.rng(1).next_u64();
                    let _ = boundary.outcome(0);
                })
            }],
        );

        let sparse_values = extract_stream_one(&sparse.run().unwrap());
        let dense_values = extract_stream_one(&dense.run().unwrap());
        assert_eq!(
            dense_values, sparse_values,
            "stream-1 draws must be identical regardless of stream-0 consumption"
        );
    }

    #[test]
    fn executor_is_deterministic() {
        let first = executor_with::<2>(
            5,
            1024,
            [
                |boundary| {
                    boxed(async move {
                        boundary.sleep(Duration::from_micros(3)).await;
                        let _ = boundary.outcome(1);
                    })
                },
                |boundary| {
                    boxed(async move {
                        let _ = boundary.send(0, 9);
                    })
                },
            ],
        );
        let second = executor_with::<2>(
            5,
            1024,
            [
                |boundary| {
                    boxed(async move {
                        boundary.sleep(Duration::from_micros(3)).await;
                        let _ = boundary.outcome(1);
                    })
                },
                |boundary| {
                    boxed(async move {
                        let _ = boundary.send(0, 9);
                    })
                },
            ],
        );
        let a = first.run().unwrap();
        let b = second.run().unwrap();
        assert_eq!(a.decisions, b.decisions);
        assert_eq!(a.journal.root_hash(), b.journal.root_hash());
    }

    #[test]
    fn step_limit_is_enforced() {
        let executor = executor_with::<1>(
            6,
            4,
            [|boundary| {
                boxed(async move {
                    loop {
                        boundary.sleep(Duration::from_micros(1)).await;
                    }
                })
            }],
        );
        let error = executor.run().unwrap_err();
        assert!(matches!(error, RuntimeError::StepLimit { .. }));
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use ledger_journal::MonitorIssue;

    #[test]
    fn boundary_leak_is_detected_by_coverage_check() {
        let executor = Executor::with_shared(config_for_coverage(), |shared| {
            let boundary = Boundary::for_task(Rc::clone(shared), 0);
            let leak_shared = Rc::clone(shared);
            let root = Box::pin(async move {
                let _ = boundary.outcome(1);
                // Leak: write to the journal directly, skipping the boundary
                // ledger. The coverage check must flag it.
                leak_shared
                    .journal
                    .borrow_mut()
                    .append(EntryKind::Outcome, 0, [], Payload::Number(99))
                    .unwrap();
            });
            shared.tasks.borrow_mut().push(make_task_entry(root));
        });
        let run = executor.run().unwrap();
        assert!(
            run.monitor_issues
                .iter()
                .any(|issue| matches!(issue, MonitorIssue::CoverageMismatch { .. })),
            "a direct journal write must be flagged as a coverage leak; issues: {:?}",
            run.monitor_issues
        );
    }

    fn config_for_coverage() -> RunConfig {
        RunConfig {
            seed: [6; 32],
            policy: crate::config::Policy::Random,
            max_steps: 256,
            ..RunConfig::default()
        }
    }
}

#[cfg(test)]
mod swarm_tests {
    use super::*;
    use crate::config::SwarmConfig;
    use crate::runtime::Simulation;

    fn base_config(seed: u8) -> RunConfig {
        RunConfig {
            seed: [seed; 32],
            policy: crate::config::Policy::Random,
            max_steps: 512,
            ..RunConfig::default()
        }
    }

    fn two_task_programs() -> Vec<Vec<crate::runtime::Instruction>> {
        use crate::runtime::Instruction;
        vec![
            vec![Instruction::Send { to: 1, payload: 42 }, Instruction::Done],
            vec![
                Instruction::Receive,
                Instruction::Outcome,
                Instruction::Done,
            ],
        ]
    }

    #[test]
    fn swarm_drop_probability_one_drops_every_message() {
        let mut config = base_config(10);
        config.swarm = SwarmConfig {
            drop_probability: 1.0,
            ..SwarmConfig::default()
        };
        let run = Simulation::new(config, two_task_programs()).run().unwrap();
        let kinds = run
            .journal
            .entries()
            .map(|entry| entry.data.kind)
            .collect::<Vec<_>>();
        assert!(
            kinds.iter().any(|kind| matches!(
                kind,
                EntryKind::Fault {
                    fault: FaultSpec::Drop
                }
            )),
            "a Drop fault must be journaled"
        );
        assert!(
            !kinds.iter().any(|kind| matches!(kind, EntryKind::Recv)),
            "a dropped message must never be received"
        );
        assert!(run.monitor_issues.is_empty());
    }

    #[test]
    fn crash_budget_one_journals_exactly_one_crash_state() {
        use crate::runtime::Instruction;
        let mut config = base_config(13);
        config.swarm = SwarmConfig {
            crash_probability: 1.0,
            fault_classes_per_run: 1,
            ..SwarmConfig::default()
        };
        let programs = vec![vec![
            Instruction::FsWrite {
                path: "a".into(),
                value: 1,
            },
            Instruction::FsWrite {
                path: "b".into(),
                value: 2,
            },
            Instruction::FsWrite {
                path: "c".into(),
                value: 3,
            },
            Instruction::FsWrite {
                path: "d".into(),
                value: 4,
            },
            Instruction::Done,
        ]];
        let run = Simulation::new(config, programs).run().unwrap();
        let crash_states = run
            .journal
            .entries()
            .filter_map(|entry| match entry.data.kind {
                EntryKind::Fault {
                    fault: FaultSpec::CrashState(index),
                } => Some(index),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            crash_states.len(),
            1,
            "a budget of 1 must journal exactly one CrashState fault"
        );
        assert!(run.monitor_issues.is_empty());
    }

    #[test]
    fn crash_budget_two_is_deterministic_and_bounded() {
        use crate::runtime::Instruction;
        let mut config = base_config(14);
        config.swarm = SwarmConfig {
            crash_probability: 1.0,
            fault_classes_per_run: 2,
            ..SwarmConfig::default()
        };
        let programs = vec![vec![
            Instruction::FsWrite {
                path: "a".into(),
                value: 1,
            },
            Instruction::FsWrite {
                path: "b".into(),
                value: 2,
            },
            Instruction::FsWrite {
                path: "c".into(),
                value: 3,
            },
            Instruction::FsWrite {
                path: "d".into(),
                value: 4,
            },
            Instruction::Done,
        ]];
        let a = Simulation::new(config.clone(), programs.clone())
            .run()
            .unwrap();
        let b = Simulation::new(config, programs).run().unwrap();
        assert_eq!(a.journal.root_hash(), b.journal.root_hash());
        let distinct = a
            .journal
            .entries()
            .filter_map(|entry| match entry.data.kind {
                EntryKind::Fault {
                    fault: FaultSpec::CrashState(index),
                } => Some(index),
                _ => None,
            })
            .collect::<HashSet<_>>();
        assert!(
            distinct.len() <= 2,
            "a budget of 2 must keep distinct crash classes at most 2"
        );
        assert!(a.monitor_issues.is_empty());
    }

    #[test]
    fn swarm_zero_is_byte_identical_to_default() {
        let default = Simulation::new(base_config(10), two_task_programs())
            .run()
            .unwrap();
        let mut with_swarm = base_config(10);
        with_swarm.swarm = SwarmConfig::default();
        let swarm = Simulation::new(with_swarm, two_task_programs())
            .run()
            .unwrap();
        assert_eq!(default.journal.root_hash(), swarm.journal.root_hash());
        assert_eq!(default.decisions, swarm.decisions);
    }

    #[test]
    fn swarm_crash_on_write_journals_crash_state() {
        use crate::runtime::Instruction;
        let mut config = base_config(11);
        config.swarm = SwarmConfig {
            crash_probability: 1.0,
            ..SwarmConfig::default()
        };
        let programs = vec![vec![
            Instruction::FsWrite {
                path: "k".into(),
                value: 7,
            },
            Instruction::Done,
        ]];
        let run = Simulation::new(config, programs).run().unwrap();
        let kinds = run
            .journal
            .entries()
            .map(|entry| entry.data.kind)
            .collect::<Vec<_>>();
        assert!(
            kinds.iter().any(|kind| matches!(
                kind,
                EntryKind::Fault {
                    fault: FaultSpec::CrashState(_)
                }
            )),
            "a CrashState fault must be journaled after a sampled crash"
        );
        assert!(run.monitor_issues.is_empty());
    }

    #[test]
    fn swarm_features_are_deterministic() {
        let mut config = base_config(12);
        config.swarm = SwarmConfig {
            drop_probability: 0.3,
            delay_probability: 0.3,
            max_delay_ticks: 5,
            crash_probability: 0.2,
            fault_classes_per_run: 2,
        };
        let programs = vec![
            vec![
                crate::runtime::Instruction::Send { to: 1, payload: 1 },
                crate::runtime::Instruction::Send { to: 1, payload: 2 },
                crate::runtime::Instruction::FsWrite {
                    path: "k".into(),
                    value: 3,
                },
                crate::runtime::Instruction::Done,
            ],
            vec![
                crate::runtime::Instruction::Receive,
                crate::runtime::Instruction::Receive,
                crate::runtime::Instruction::Done,
            ],
        ];
        let a = Simulation::new(config.clone(), programs.clone())
            .run()
            .unwrap();
        let b = Simulation::new(config, programs).run().unwrap();
        assert_eq!(a.journal.root_hash(), b.journal.root_hash());
        assert_eq!(a.decisions, b.decisions);
    }

    #[test]
    fn reorder_window_serves_newest_deliverable_first() {
        use crate::net::SimNet;
        let mut net = SimNet::new();
        net.set_reorder_window(4);
        let now = 0u64;
        let send_id = |n: u8| [n; 32];
        let first = net.send_at(0, 1, 10, send_id(1), now, 0);
        let second = net.send_at(0, 1, 20, send_id(2), now, 0);
        assert!(first && second);
        let msg = net.recv_at(1, now).unwrap();
        assert_eq!(msg.payload, 20);
        let msg = net.recv_at(1, now).unwrap();
        assert_eq!(msg.payload, 10);
    }

    #[test]
    fn fifo_default_serves_oldest_first() {
        use crate::net::SimNet;
        let mut net = SimNet::new();
        let now = 0u64;
        let send_id = |n: u8| [n; 32];
        let _ = net.send_at(0, 1, 10, send_id(1), now, 0);
        let _ = net.send_at(0, 1, 20, send_id(2), now, 0);
        let msg = net.recv_at(1, now).unwrap();
        assert_eq!(msg.payload, 10);
    }
}

#[cfg(test)]
mod link_integration_tests {
    use crate::config::RunConfig;
    use crate::net::LinkConfig;
    use crate::runtime::{Instruction, Simulation};

    fn two_task_programs() -> Vec<Vec<Instruction>> {
        vec![
            vec![Instruction::Send { to: 1, payload: 7 }, Instruction::Done],
            vec![Instruction::Receive, Instruction::Done],
        ]
    }

    #[test]
    fn configured_link_changes_journal_root() {
        let seed = [3; 32];
        let base = RunConfig {
            seed,
            max_steps: 512,
            ..RunConfig::default()
        };
        let default_root = Simulation::new(base.clone(), two_task_programs())
            .run()
            .unwrap()
            .journal
            .root_hash();
        let linked = RunConfig {
            links: vec![(
                0,
                1,
                LinkConfig {
                    base_delay: 5,
                    ..LinkConfig::default()
                },
            )],
            ..base
        };
        let linked_root = Simulation::new(linked, two_task_programs())
            .run()
            .unwrap()
            .journal
            .root_hash();
        assert_ne!(
            default_root, linked_root,
            "a configured link must change the schedule"
        );
    }

    #[test]
    fn link_and_swarm_draws_are_deterministic() {
        let make = || RunConfig {
            seed: [9; 32],
            max_steps: 512,
            swarm: crate::config::SwarmConfig {
                delay_probability: 0.5,
                max_delay_ticks: 3,
                ..crate::config::SwarmConfig::default()
            },
            links: vec![(
                0,
                1,
                LinkConfig {
                    jitter: 4,
                    loss_probability: 0.2,
                    ..LinkConfig::default()
                },
            )],
            ..RunConfig::default()
        };
        let a = Simulation::new(make(), two_task_programs()).run().unwrap();
        let b = Simulation::new(make(), two_task_programs()).run().unwrap();
        assert_eq!(a.journal.root_hash(), b.journal.root_hash());
        assert_eq!(a.decisions, b.decisions);
    }
}
