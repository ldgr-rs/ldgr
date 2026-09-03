//! Deterministic single-threaded poll-based async executor.
//!
//! One scheduling decision per step is journaled as `RngDraw`; blocking
//! effects park until a timer or message wakes them. Intentionally not
//! `Send`: `Rc` state plus OS threads would break determinism.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use futures::task::noop_waker;

use crate::config::{Policy, RunConfig, SimFault};
use crate::net::{DnsTable, SimNet};
use crate::runtime::{RunResult, RuntimeError, SCHED_ACTOR, SCHED_STREAM};
use crate::scheduler::Scheduler;
use crate::seedtree::SeedTree;
use crate::simfs::SimFs;
use crate::time::VirtualTime;
use ledger_format::MessageId;
use ledger_format::{ActorId, EntryHash, EntryKind, EntryPayload, StreamId};
use ledger_journal::{BatchEntry, Journal, JournalCorrectnessMonitor};
use rand_chacha::ChaCha20Rng;

mod effects;
mod storage;
pub use effects::Boundary;

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
        stream_rngs: BTreeMap::new(),
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
    stream_rngs: BTreeMap<StreamId, ChaCha20Rng>,
}

/// Shared state; `RefCell` keeps the `&self` boundary callable.
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
    dropped_events: Vec<EntryHash>,
    seed_tree: SeedTree,
    /// Swarm probabilities consumed by the boundary.
    swarm: crate::config::SwarmConfig,
    /// Monotonic offset for the `net` seed stream.
    net_offset: RefCell<u64>,
    /// Monotonic offset for the `fs` seed stream.
    fs_offset: RefCell<u64>,
    /// Serve a seeded draw inside the configured reorder window.
    reorder_draw: bool,
    /// Per-task count of journaled Send entries; feeds
    /// `MessageId.sender_sequence` (the sender entry sequence).
    send_seq: RefCell<Vec<u64>>,
    /// Per-actor entry counts for the coverage check; all writes funnel
    /// through append so the ledger stays exact.
    // ledger-lint:allow:HashMap ledger-lint:allow:HashSet (coverage is keyed
    // lookup and collected in sorted order at the run tail; fault classes are
    // membership and len only)
    coverage: RefCell<HashMap<ActorId, u64>>,
    /// Distinct crash-state classes applied this run (campaign budget).
    fault_classes_used: RefCell<HashSet<u64>>,
    /// Event ids whose scheduled fault injections took effect.
    applied_faults: RefCell<Vec<EntryHash>>,
    /// Effect origins side channel keyed by entry hash (crate::origin).
    origins: RefCell<crate::origin::OriginLog>,
    /// Fault schedule applied at exact causal positions.
    fault_schedule: Vec<SimFault>,
    /// Configured journaling-FS crash model, or `None` for the black-box
    /// `DropAllUnsynced` default.
    #[cfg(feature = "sim-fs-journaling")]
    fs_journaling: Option<crate::simfs::JournalingMode>,
    /// First append failure from a non-`Err` path; surfaces via `journal_error`.
    journal_error: RefCell<Option<ledger_journal::JournalError>>,
}

/// Deterministic single-threaded poll-based executor.
pub struct Executor {
    shared: Rc<ExecutorShared>,
    config: RunConfig,
    steps: usize,
    step_monitor: Option<crate::runtime::StepMonitor>,
    protection_mode: Option<crate::sentinel::ProtectionMode>,
}

/// Wakeups come from the executor itself, so `poll` gets a no-op waker and
/// futures must never rely on it; this keeps `Rc` state free of `Send` bounds.
impl Executor {
    /// Create an executor from root futures; task ids equal their indices.
    pub fn new(config: RunConfig, tasks: Vec<Pin<Box<dyn Future<Output = ()> + 'static>>>) -> Self {
        Self::with_shared(config, |shared| {
            for future in tasks {
                let mut tasks = shared.tasks.borrow_mut();
                tasks.push(make_task_entry(future));
            }
        })
    }

    /// Build roots from shared state; each boundary `task` must equal its
    /// future index in the task table.
    pub(crate) fn with_shared(
        config: RunConfig,
        builder: impl FnOnce(&Rc<ExecutorShared>),
    ) -> Self {
        Self::with_shared_and_replay(config, Vec::new(), builder)
    }

    /// Create a replay executor; the fallback defaults to `Random`.
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
        Self::with_shared_and_replay_and_fallback_inner(config, replay, fallback, false, builder)
    }

    /// Strict replay executor; exhausted/out-of-range surfaces as `StrictReplay`.
    pub(crate) fn with_shared_and_replay_strict(
        config: RunConfig,
        replay: Vec<usize>,
        builder: impl FnOnce(&Rc<ExecutorShared>),
    ) -> Self {
        // Force Replay policy for strict mode: a strict executor must replay,
        // otherwise the policy would be silently ignored.
        let mut forced = config;
        forced.policy = Policy::Replay;
        Self::with_shared_and_replay_and_fallback_inner(
            forced,
            replay,
            Policy::Random,
            true,
            builder,
        )
    }

    /// Attach a mid-run step monitor.
    pub fn with_step_monitor(mut self, monitor: crate::runtime::StepMonitor) -> Self {
        self.step_monitor = Some(monitor);
        self
    }

    /// Set the host-side protection mode for this run.
    ///
    /// Host option overrides env. `None` falls back to env; `Disabled` env with no host keeps not-armed.
    pub fn with_protection_mode(mut self, mode: crate::sentinel::ProtectionMode) -> Self {
        self.protection_mode = Some(mode);
        self
    }

    /// Effective protection for this run: host if set, else env.
    pub(crate) fn effective_protection(&self) -> crate::sentinel::EffectiveProtection {
        if let Some(mode) = self.protection_mode {
            return mode.into();
        }
        crate::sentinel::belt_env_mode_from_env().into()
    }

    fn with_shared_and_replay_and_fallback_inner(
        config: RunConfig,
        replay: Vec<usize>,
        fallback: Policy,
        strict: bool,
        builder: impl FnOnce(&Rc<ExecutorShared>),
    ) -> Self {
        let seed_tree = config.seed_tree();
        let scheduler = if strict {
            Scheduler::with_fallback_strict(config.policy(), seed_tree.clone(), replay, fallback)
        } else {
            Scheduler::with_fallback(config.policy(), seed_tree.clone(), replay, fallback)
        };
        let mut net = SimNet::new();
        for &(from, to, cfg) in config.links() {
            net.set_link(from, to, cfg);
        }
        for injection in config.fault_schedule() {
            if let SimFault::Partition { src, dst } = injection {
                net.partition(src.0 as usize, dst.0 as usize);
            }
        }
        let shared = Rc::new(ExecutorShared {
            journal: RefCell::new(Journal::new()),
            time: RefCell::new(VirtualTime::default()),
            net: RefCell::new(net),
            fs: RefCell::new(SimFs::with_budgets(
                config
                    .max_file_extent()
                    .unwrap_or(ledger_format::limits::MAX_FILE_EXTENT_HARD),
                config.max_resident_bytes(),
            )),
            dns: (*config.dns()).clone(),
            scheduler: RefCell::new(scheduler),
            tasks: RefCell::new(Vec::new()),
            ready: RefCell::new(Vec::new()),
            dropped_events: config.dropped_events().to_vec(),
            seed_tree,
            swarm: (*config.swarm()).clone(),
            net_offset: RefCell::new(0),
            fs_offset: RefCell::new(0),
            reorder_draw: config.reorder_draw(),
            send_seq: RefCell::new(Vec::new()),
            coverage: RefCell::new(HashMap::new()),
            fault_classes_used: RefCell::new(HashSet::new()),
            applied_faults: RefCell::new(Vec::new()),
            origins: RefCell::new(crate::origin::OriginLog::default()),
            fault_schedule: config.fault_schedule().to_vec(),
            #[cfg(feature = "sim-fs-journaling")]
            fs_journaling: config.fs_journaling(),
            journal_error: RefCell::new(None),
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
            step_monitor: None,
            protection_mode: None,
        }
    }

    /// Run until all tasks finish, the budget is reached, or a monitor halts.
    pub fn run(mut self) -> Result<RunResult, RuntimeError> {
        // Common execution boundary: belt activation + enforcement.
        // Effective policy drives attempt regardless of env gate; Required rejects incomplete.
        let effective = self.effective_protection();
        // Tsc trap: attempt when effective Some, else no trap.
        let tsc_guard = crate::sentinel::TscTrapGuard::arm_for_effective(effective);
        if let Some(error) = tsc_guard.activation_error() {
            if effective.is_required() {
                return Err(RuntimeError::Belt(crate::sentinel::BeltStatus::Failed(
                    error.clone(),
                )));
            }
            eprintln!("ledger-sim sentinel: RDTSC trap activation failed: {error}");
        }
        // Keep guard alive for whole run.
        let _guard = tsc_guard;
        let belt_status = crate::sentinel::activate_process_belt_for_effective(effective);
        if effective.is_required()
            && !matches!(belt_status, crate::sentinel::BeltStatus::Active { .. })
        {
            return Err(RuntimeError::Belt(belt_status));
        }
        // BestEffort continues and reports status via RunResult.protection.
        let run_protection = belt_status.clone();
        self.journal_spawns()?;
        // Feed initial prefix (spawn entries) to monitor so it observes entry 0.
        let mut early_halt: Option<crate::RunOutcome> = None;
        if let Some(monitor) = self.step_monitor.as_mut() {
            let journal = self.shared.journal.borrow();
            if !journal.is_empty() {
                match monitor(&journal, 0) {
                    crate::runtime::OnlineAction::Continue => {}
                    crate::runtime::OnlineAction::Halt { reason } => {
                        early_halt = Some(crate::RunOutcome::MonitorHalt(reason));
                    }
                }
            }
        }
        let mut outcome = if let Some(h) = early_halt.clone() {
            h
        } else {
            crate::RunOutcome::BudgetExhausted
        };
        if early_halt.is_none() {
            // The while-condition exit means the budget ran out; the breaks in
            // the loop record the earlier liveness outcomes.
            while self.steps < self.config.max_steps() {
                // Capture journal delta start for the mid-run monitor. The
                // callback is read-only and consumes no seed draws, so it never
                // perturbs determinism.
                let monitor_start = if self.step_monitor.is_some() {
                    Some(self.shared.journal.borrow().len())
                } else {
                    None
                };
                self.wake_blocked_with_messages()?;
                if self.shared.ready.borrow().is_empty() {
                    self.advance_quiescent()?;
                    if self.shared.ready.borrow().is_empty() {
                        if self.all_tasks_done() {
                            outcome = crate::RunOutcome::Completed;
                            break;
                        }
                        if let Some(earliest) = self.shared.net.borrow().earliest_delivery_time()
                            && earliest > self.shared.time.borrow().now()
                        {
                            self.shared.time.borrow_mut().advance_to(earliest);
                            self.wake_blocked_with_messages()?;
                        }
                        if self.shared.ready.borrow().is_empty() {
                            outcome = crate::RunOutcome::Blocked;
                            break;
                        }
                    }
                }
                let choice = {
                    let ready_snapshot = self.shared.ready.borrow().clone();
                    let step = self.steps;
                    let choice = {
                        let mut scheduler = self.shared.scheduler.borrow_mut();
                        let choice = scheduler.choose(&ready_snapshot, step);
                        if let Some(violation) = scheduler.take_violation() {
                            return Err(RuntimeError::StrictReplay(violation));
                        }
                        choice
                    };
                    self.journal_rng_draw(choice)?;
                    choice
                };
                let task_id = self.shared.ready.borrow_mut().swap_remove(choice);
                self.poll_task(task_id)?;
                // Invoke the mid-run monitor over the step delta, if any. Halt
                // stops the run with a deterministic partial journal.
                if let Some(start) = monitor_start
                    && let Some(monitor) = self.step_monitor.as_mut()
                {
                    let journal = self.shared.journal.borrow();
                    match monitor(&journal, start) {
                        crate::runtime::OnlineAction::Continue => {}
                        crate::runtime::OnlineAction::Halt { reason } => {
                            outcome = crate::RunOutcome::MonitorHalt(reason);
                            break;
                        }
                    }
                }
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
        }
        // Strict replay must not have leftover decisions, measured against
        // decisions consumed rather than poll count.
        {
            let mut scheduler = self.shared.scheduler.borrow_mut();
            let consumed = scheduler.decisions().len();
            if let Some(violation) = scheduler.check_trailing(consumed) {
                return Err(RuntimeError::StrictReplay(violation));
            }
        }
        // A recorded append failure means the DAG is incomplete: reject the
        // run here so no caller can build findings, certificates, or
        // minimized repros from a knowingly broken journal.
        if let Some(error) = self.shared.journal_error.borrow().clone() {
            return Err(RuntimeError::Journal(error));
        }
        // The last step can complete every task exactly as the budget runs
        // out; completion wins over the budget default in that case.
        if outcome == crate::RunOutcome::BudgetExhausted && self.all_tasks_done() {
            outcome = crate::RunOutcome::Completed;
        }
        let journal = self.shared.journal.borrow().clone();
        let mut monitor_issues = if self.config.monitor() {
            JournalCorrectnessMonitor::audit(&journal)
        } else {
            Vec::new()
        };
        if self.config.monitor() {
            let coverage = self.shared.coverage.borrow();
            let mut boundary_entries = coverage
                .iter()
                .map(|(actor, count)| (*actor, *count))
                .collect::<Vec<_>>();
            // Deterministic monitor input order: the map itself is
            // lookup-only, but this vector feeds issue enumeration.
            boundary_entries.sort_unstable();
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
            outcome,
            monitor_issues,
            applied_faults: self.shared.applied_faults.borrow().clone(),
            origins: self.shared.origins.borrow().snapshot(),
            journal_error: self.shared.journal_error.borrow().clone(),
            protection: run_protection,
        })
    }

    /// Journal a `Spawn` entry for every task before the first scheduling step.
    fn journal_spawns(&self) -> Result<(), RuntimeError> {
        let tasks = self.shared.tasks.borrow();
        for (task_id, _) in tasks.iter().enumerate() {
            self.shared.journal_append(
                ActorId(task_id as u32),
                EntryKind::Spawn,
                [],
                EntryPayload::Spawn {
                    child_actor: ActorId(task_id as u32),
                },
            )?;
        }
        Ok(())
    }

    /// Journal the scheduling draw that resolved to `choice`.
    fn journal_rng_draw(&self, choice: usize) -> Result<(), RuntimeError> {
        self.shared.journal_append(
            SCHED_ACTOR,
            EntryKind::RngDraw,
            [],
            EntryPayload::RngDraw(ledger_format::RngDrawPayload {
                stream: SCHED_STREAM,
                draw_index: 0,
                content: (choice as u64).to_le_bytes().to_vec(),
            }),
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
                ActorId(task_id as u32),
                EntryKind::Wake,
                send_id.into_iter().collect::<Vec<_>>(),
                EntryPayload::Wake(ledger_format::WakePayload::MessageReady {
                    message_id: MessageId::new(ActorId(task_id as u32), 0),
                }),
            )?;
            self.shared.notify_entry(
                ActorId(task_id as u32),
                EntryKind::Wake,
                task_id,
                Some(wake_id),
            );
            let mut tasks = self.shared.tasks.borrow_mut();
            tasks[task_id].blocked_on = None;
            self.shared.ready.borrow_mut().push(task_id);
        }
        Ok(())
    }

    /// Fire timers at quiescence; batches stay byte-identical to per-entry
    /// appends and journal the same chain as `SimBackend::sleep`.
    fn advance_quiescent(&self) -> Result<(), RuntimeError> {
        let timer_deadline = self.shared.time.borrow().next_deadline();
        let net_deadline = self.shared.net.borrow().earliest_delivery_time();

        let target_time = match (timer_deadline, net_deadline) {
            (Some(t), Some(n)) => Some(t.min(n)),
            (Some(t), None) => Some(t),
            (None, Some(n)) => Some(n),
            (None, None) => None,
        };

        let Some(target) = target_time else {
            return self.wake_blocked_with_messages();
        };

        let now = self.shared.time.borrow().now();
        let fired = if target > now {
            self.shared
                .time
                .borrow_mut()
                .advance_to_with_enablers(target)
        } else {
            self.shared.time.borrow_mut().advance_with_enablers()
        };
        if !fired.is_empty() {
            let mut batch = Vec::with_capacity(fired.len() * 2);
            for timer in &fired {
                let mut timer_entry = BatchEntry::new(
                    EntryKind::TimerFire,
                    ActorId(timer.task as u32),
                    EntryPayload::TimerFire {
                        timer_id: 0,
                        deadline_ticks: 0,
                    },
                );
                timer_entry.observed_parents.extend(timer.enabler);
                batch.push(timer_entry);
                batch.push(
                    BatchEntry::new(
                        EntryKind::Wake,
                        ActorId(timer.task as u32),
                        EntryPayload::Wake(ledger_format::WakePayload::TimerReady { timer_id: 0 }),
                    )
                    .chained(),
                );
            }
            let ids = self.shared.journal_append_batch(batch)?;
            for (timer, id_pair) in fired.iter().zip(ids.chunks_exact(2)) {
                self.shared.notify_entry(
                    ActorId(timer.task as u32),
                    EntryKind::TimerFire,
                    timer.task,
                    Some(id_pair[0]),
                );
                self.shared.notify_entry(
                    ActorId(timer.task as u32),
                    EntryKind::Wake,
                    timer.task,
                    Some(id_pair[1]),
                );
                let mut tasks = self.shared.tasks.borrow_mut();
                tasks[timer.task].timer_fired = true;
                tasks[timer.task].blocked_on = None;
                self.shared.ready.borrow_mut().push(timer.task);
            }
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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::effects::Effects;
    use rand_core::Rng;
    use std::future::Future;
    use std::time::Duration;

    fn config(seed: u8, max_steps: usize) -> RunConfig {
        RunConfig {
            seed: ledger_format::EntryHash([seed; 32]),
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

    #[test]
    fn send_tracked_records_origin_in_the_shared_log() {
        let executor = executor_with(
            9,
            256,
            [|b| {
                boxed(async move {
                    b.send_tracked(1, 42);
                })
            }],
        );
        let run = executor.run().expect("run succeeds");
        assert_eq!(run.origins.len(), 1, "tracked send must record one origin");
        match &run.origins[0].1 {
            crate::origin::OriginSource::Source(origin) => {
                assert!(
                    origin.file.ends_with("mod.rs"),
                    "origin must point at the test call site, got {}",
                    origin.file
                );
            }
            other => panic!("expected a Source origin, got {other:?}"),
        }
    }

    #[test]
    fn recv_inherits_the_origin_of_its_send() {
        let executor = executor_with(
            9,
            256,
            [
                |b| {
                    boxed(async move {
                        b.send_tracked(1, 42);
                    })
                },
                |b| {
                    boxed(async move {
                        let _ = b.recv().await;
                    })
                },
            ],
        );
        let run = executor.run().expect("run succeeds");
        assert_eq!(run.origins.len(), 2, "recv must inherit the send origin");
        assert_eq!(
            run.origins[0].1, run.origins[1].1,
            "inherited origin must match the send"
        );
    }

    #[test]
    fn tracked_storage_write_records_origin() {
        use crate::effects::FsExt;
        let executor = executor_with(
            9,
            256,
            [|b| {
                boxed(async move {
                    let _ = b.fs().write_tracked("k", 7);
                })
            }],
        );
        let run = executor.run().expect("run succeeds");
        assert_eq!(run.origins.len(), 1, "tracked write must record one origin");
    }

    #[test]
    fn untracked_send_leaves_origins_empty() {
        let executor = executor_with(
            9,
            256,
            [|b| {
                boxed(async move {
                    b.send(1, 42);
                })
            }],
        );
        let run = executor.run().expect("run succeeds");
        assert!(
            run.origins.is_empty(),
            "plain sends must not record origins"
        );
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
                    stream_rngs: BTreeMap::new(),
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

    /// The swarm delay draw must stay defined at the `u64::MAX` bound, where
    /// the modulus `max + 1` does not fit `u64`. The raw draw is returned
    /// unchanged there (`value % (u64::MAX + 1) == value`); smaller bounds
    /// keep the plain remainder on the same stream offsets.
    #[test]
    fn net_draw_delay_handles_max_u64_modulus_bound() {
        let boundary = {
            let mut holder = None;
            drop(Executor::with_shared(config(7, 64), |shared| {
                holder = Some(Boundary::for_task(Rc::clone(shared), 0));
            }));
            holder.expect("builder ran")
        };
        // The raw draw at stream offset 0; the first call consumes it.
        let raw = boundary.shared.seed_tree.draw_u64("net", 0);
        let drawn = boundary.net_draw_delay(u64::MAX);
        assert_eq!(drawn, raw, "u64::MAX bound must return the raw draw");
        let value = boundary.shared.seed_tree.draw_u64("net", 1);
        assert_eq!(boundary.net_draw_delay(7), value % 8);
        let value = boundary.shared.seed_tree.draw_u64("net", 2);
        assert_eq!(
            boundary.net_draw_delay(u64::MAX - 1),
            value % u64::MAX,
            "the largest representable modulus must use the plain remainder"
        );
        // Zero and one-tick bounds keep drawing deterministically.
        assert_eq!(
            boundary.net_draw_delay(0),
            0,
            "a zero bound always delays zero"
        );
    }

    /// A full run with a maxed delay bound and 100% delay probability
    /// exercises the swarm draw on every send without overflowing the
    /// delivery path.
    #[test]
    fn swarm_max_u64_delay_bound_run_completes() {
        let mut cfg = config(11, 2048);
        cfg.swarm.delay_probability = crate::config::Probability::ONE;
        cfg.swarm.max_delay_ticks = u64::MAX;
        let executor = Executor::with_shared(cfg, |shared| {
            for (task_id, body) in [
                (|boundary: Boundary| {
                    boxed(async move {
                        let _ = boundary.send(1, 42);
                    })
                }) as TaskBody,
                (|boundary: Boundary| {
                    boxed(async move {
                        let value = boundary.recv().await;
                        let _ = boundary.outcome(value);
                    })
                }) as TaskBody,
            ]
            .into_iter()
            .enumerate()
            {
                let boundary = Boundary::for_task(Rc::clone(shared), task_id);
                let future = body(boundary);
                let mut tasks = shared.tasks.borrow_mut();
                tasks.push(TaskEntry {
                    future: Some(future),
                    blocked_on: None,
                    done: false,
                    register: 0,
                    timer_fired: false,
                    stream_rngs: BTreeMap::new(),
                });
            }
        });
        let run = executor
            .run()
            .expect("run must not panic at the u64::MAX bound");
        let kinds = run
            .journal
            .entries()
            .map(|entry| entry.data.kind)
            .collect::<Vec<_>>();
        assert!(kinds.iter().any(|kind| matches!(kind, EntryKind::Send)));
        assert!(kinds.iter().any(|kind| matches!(kind, EntryKind::Recv)));
        assert!(
            run.monitor_issues.is_empty(),
            "monitor issues: {:?}",
            run.monitor_issues
        );
        assert!(
            run.journal_error.is_none(),
            "journal must stay clean: {:?}",
            run.journal_error
        );
    }

    /// A maxed link jitter (`u64::MAX`) exercises the saturated draw modulus
    /// on every send through the builder path: no panic, byte-identical
    /// roots across runs, clean journal. The canonical codec rejects the
    /// value outright; this test guards the direct-construction fallback.
    #[test]
    fn max_u64_link_jitter_run_is_deterministic() {
        let with_jitter = |seed: u8| {
            let mut cfg = config(seed, 2048);
            cfg.links = vec![(
                0,
                1,
                crate::net::LinkConfig {
                    jitter: u64::MAX,
                    ..crate::net::LinkConfig::default()
                },
            )];
            let executor = Executor::with_shared(cfg, |shared| {
                for (task_id, body) in [
                    (|boundary: Boundary| {
                        boxed(async move {
                            let _ = boundary.send(1, 7);
                        })
                    }) as TaskBody,
                    (|boundary: Boundary| {
                        boxed(async move {
                            let _ = boundary.recv().await;
                        })
                    }) as TaskBody,
                ]
                .into_iter()
                .enumerate()
                {
                    let boundary = Boundary::for_task(Rc::clone(shared), task_id);
                    let future = body(boundary);
                    let mut tasks = shared.tasks.borrow_mut();
                    tasks.push(TaskEntry {
                        future: Some(future),
                        blocked_on: None,
                        done: false,
                        register: 0,
                        timer_fired: false,
                        stream_rngs: BTreeMap::new(),
                    });
                }
            });
            executor.run()
        };
        let first = with_jitter(13).expect("run with maxed jitter must not panic");
        let second = with_jitter(13).expect("second run");
        assert_eq!(
            first.journal.root_hash(),
            second.journal.root_hash(),
            "maxed jitter must stay deterministic"
        );
        assert_eq!(first.steps, second.steps);
        assert!(
            first.journal_error.is_none(),
            "journal must stay clean: {:?}",
            first.journal_error
        );
        assert!(
            first.monitor_issues.is_empty(),
            "monitor issues: {:?}",
            first.monitor_issues
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
                stream_rngs: BTreeMap::new(),
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
                .filter_map(|entry| match &entry.data.payload {
                    EntryPayload::RngDraw(draw)
                        if entry.data.kind == EntryKind::RngDraw
                            && draw.stream == ledger_format::StreamId(1) =>
                    {
                        Some(u64::from_le_bytes(
                            draw.content[..8].try_into().expect("8-byte content"),
                        ))
                    }
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
                        let _ = boundary.rng(ledger_format::StreamId(0)).next_u64();
                    }
                    let _ = boundary.rng(ledger_format::StreamId(1)).next_u64();
                    let _ = boundary.rng(ledger_format::StreamId(1)).next_u64();
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
                        let _ = boundary.rng(ledger_format::StreamId(0)).next_u64();
                    }
                    let _ = boundary.rng(ledger_format::StreamId(1)).next_u64();
                    let _ = boundary.rng(ledger_format::StreamId(1)).next_u64();
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
        let run = executor
            .run()
            .expect("budget exhaustion is an outcome, not an error");
        assert_eq!(run.outcome, crate::RunOutcome::BudgetExhausted);
        assert!(
            run.steps > 0,
            "a budget-exhausted run must have executed steps"
        );
    }

    #[test]
    fn quiesced_pending_tasks_report_blocked_outcome() {
        let executor = executor_with(
            9,
            64,
            [|b| {
                boxed(async move {
                    let _ = b.recv().await;
                })
            }],
        );
        let run = executor
            .run()
            .expect("quiescence with pending tasks is an outcome, not an error");
        assert_eq!(run.outcome, crate::RunOutcome::Blocked);
    }

    #[test]
    fn finished_run_reports_completed_outcome() {
        let executor = executor_with(9, 64, [|_b| boxed(async {})]);
        let run = executor.run().expect("empty task completes");
        assert_eq!(run.outcome, crate::RunOutcome::Completed);
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
                    .append(
                        EntryKind::Outcome,
                        ActorId(0),
                        [],
                        EntryPayload::Outcome(ledger_format::OutcomePayload {
                            schema: super::effects::OUTCOME_SCHEMA,
                            value: ledger_format::CanonicalValue::Unsigned(99),
                        }),
                    )
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
            seed: ledger_format::EntryHash([6; 32]),
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
    use ledger_format::{EntryPayload, FaultPayload};

    fn base_config(seed: u8) -> RunConfig {
        RunConfig {
            seed: ledger_format::EntryHash([seed; 32]),
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
        let config = base_config(10).with_swarm(SwarmConfig {
            drop_probability: crate::config::Probability::ONE,
            ..SwarmConfig::default()
        });
        let run = Simulation::new(config, two_task_programs()).run().unwrap();
        let drops = run
            .journal
            .entries()
            .filter(|entry| {
                matches!(
                    &entry.data.payload,
                    EntryPayload::Fault(FaultPayload::DropMessage { .. })
                )
            })
            .count();
        assert!(drops >= 1, "a Drop fault must be journaled");
        assert!(
            !run.journal
                .entries()
                .any(|entry| entry.data.kind == EntryKind::Recv),
            "a dropped message must never be received"
        );
        assert!(run.monitor_issues.is_empty());
    }

    #[test]
    fn crash_budget_one_journals_exactly_one_crash_state() {
        use crate::runtime::Instruction;
        let config = base_config(13).with_swarm(SwarmConfig {
            crash_probability: crate::config::Probability::ONE,
            fault_classes_per_run: 1,
            ..SwarmConfig::default()
        });
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
            .filter(|entry| {
                matches!(
                    &entry.data.payload,
                    EntryPayload::Fault(FaultPayload::CrashActor { .. })
                )
            })
            .count();
        assert_eq!(
            crash_states, 1,
            "a budget of 1 must journal exactly one CrashState fault"
        );
        assert!(run.monitor_issues.is_empty());
    }

    #[test]
    fn unknown_crash_state_identifier_fails_closed() {
        use crate::runtime::Instruction;
        // A probe run locates the FsWrite entry; the injected fault then
        // targets it with a state identifier outside the canonical 0..=2 set.
        let probe = Simulation::new(
            base_config(15),
            vec![vec![
                Instruction::FsWrite {
                    path: "a".into(),
                    value: 1,
                },
                Instruction::Done,
            ]],
        )
        .run()
        .unwrap();
        let write = probe
            .journal
            .entries()
            .find(|entry| matches!(entry.data.kind, ledger_format::EntryKind::FsWrite))
            .map(|entry| entry.id)
            .expect("the probe journals one FsWrite");
        let config =
            base_config(15).with_fault_schedule(vec![crate::config::SimFault::CrashState {
                write,
                state: 3,
            }]);
        let error = Simulation::new(
            config,
            vec![vec![
                Instruction::FsWrite {
                    path: "a".into(),
                    value: 1,
                },
                Instruction::Done,
            ]],
        )
        .run()
        .unwrap_err();
        assert!(
            matches!(
                error,
                RuntimeError::Journal(ledger_journal::JournalError::InvalidPayload(_))
            ),
            "an unknown crash-state identifier must fail the run closed"
        );
    }

    #[test]
    fn reorder_draw_is_selectable_and_deterministic() {
        use crate::net::LinkConfig;
        use crate::runtime::Instruction;
        let programs = vec![
            vec![
                Instruction::Send { to: 1, payload: 10 },
                Instruction::Send { to: 1, payload: 20 },
                Instruction::Send { to: 1, payload: 30 },
                Instruction::Done,
            ],
            vec![
                Instruction::Receive,
                Instruction::Receive,
                Instruction::Receive,
                Instruction::Done,
            ],
        ];
        let make = |seed: u8, draw: bool| {
            base_config(seed)
                .with_links(vec![(
                    0,
                    1,
                    LinkConfig {
                        reorder_window: 2,
                        ..LinkConfig::default()
                    },
                )])
                .with_reorder_draw(draw)
        };
        let run_root = |seed: u8, draw: bool| {
            Simulation::new(make(seed, draw), programs.clone())
                .run()
                .unwrap()
                .journal
                .root_hash()
        };
        let mut differing = 0usize;
        for seed in 0..16u8 {
            let newest = run_root(seed, false);
            let drawn = run_root(seed, true);
            let drawn_again = run_root(seed, true);
            assert_eq!(
                drawn, drawn_again,
                "the drawn window must be deterministic for one seed"
            );
            if drawn != newest {
                differing += 1;
            }
        }
        assert!(
            differing > 0,
            "the seeded draw must sometimes differ from newest-first inside the window"
        );
    }

    #[test]
    fn crash_budget_two_is_deterministic_and_bounded() {
        use crate::runtime::Instruction;
        let config = base_config(14).with_swarm(SwarmConfig {
            crash_probability: crate::config::Probability::ONE,
            fault_classes_per_run: 2,
            ..SwarmConfig::default()
        });
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
        let distinct_ops = a
            .journal
            .entries()
            .filter_map(|entry| match &entry.data.payload {
                EntryPayload::Fault(FaultPayload::CrashActor {
                    crash_operation, ..
                }) => Some(crash_operation.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let mut seen: Vec<ledger_format::CrashOperation> = Vec::new();
        for op in &distinct_ops {
            if !seen.contains(op) {
                seen.push(op.clone());
            }
        }
        assert!(
            seen.len() <= 2,
            "a budget of 2 must keep distinct crash classes at most 2"
        );
        assert!(a.monitor_issues.is_empty());
    }

    /// Append failure in a program future must reject the run.
    #[test]
    fn program_future_append_failure_rejects_the_run() {
        use crate::adapter::program_future;
        use crate::runtime::Instruction;
        let config = base_config(77);
        let shared_holder: Rc<RefCell<Option<Rc<ExecutorShared>>>> = Rc::new(RefCell::new(None));
        let holder = Rc::clone(&shared_holder);
        let executor = Executor::with_shared(config, |shared| {
            let boundary = Boundary::for_task(Rc::clone(shared), 0);
            let future = program_future(boundary, vec![Instruction::Receive, Instruction::Done]);
            shared.tasks.borrow_mut().push(make_task_entry(future));
            *holder.borrow_mut() = Some(Rc::clone(shared));
        });
        // Deliver a message whose send_id is not journaled: the Receive
        // append then fails and must reject the run.
        let shared = shared_holder.borrow().clone().expect("shared captured");
        shared
            .net
            .borrow_mut()
            .send_at(9, 0, 99, ledger_format::EntryHash([0xAA; 32]), 0, 0);

        let run = executor.run();
        assert!(
            matches!(
                run,
                Err(RuntimeError::Journal(
                    ledger_journal::JournalError::MissingParent(_)
                ))
            ),
            "a poisoned run must be rejected, got: {run:?}"
        );
    }

    /// The error sink fills the run slot with the exact typed error.
    #[test]
    fn boundary_record_journal_error_fills_slot() {
        let config = base_config(78);
        let shared_holder: Rc<RefCell<Option<Rc<ExecutorShared>>>> = Rc::new(RefCell::new(None));
        let holder = Rc::clone(&shared_holder);
        let _executor = Executor::with_shared(config, |shared| {
            *holder.borrow_mut() = Some(Rc::clone(shared));
        });
        let shared = shared_holder.borrow().clone().expect("shared captured");
        let boundary = Boundary::for_task(Rc::clone(&shared), 0);
        let error = ledger_journal::JournalError::NonMonotonicSequence {
            actor: ActorId(0),
            expected: 1,
            actual: 2,
        };
        // The exact call the adapter Poll arm makes on an execute_one error.
        boundary.record_journal_error(error.clone());
        assert_eq!(
            shared.journal_error.borrow().as_ref(),
            Some(&error),
            "the sink must preserve the typed error"
        );
    }

    #[test]
    fn swarm_zero_is_byte_identical_to_default() {
        let default = Simulation::new(base_config(10), two_task_programs())
            .run()
            .unwrap();
        let with_swarm = base_config(10).with_swarm(SwarmConfig::default());
        let swarm = Simulation::new(with_swarm, two_task_programs())
            .run()
            .unwrap();
        assert_eq!(default.journal.root_hash(), swarm.journal.root_hash());
        assert_eq!(default.decisions, swarm.decisions);
    }

    #[test]
    fn swarm_crash_on_write_journals_crash_state() {
        use crate::runtime::Instruction;
        let config = base_config(11).with_swarm(SwarmConfig {
            crash_probability: crate::config::Probability::ONE,
            ..SwarmConfig::default()
        });
        let programs = vec![vec![
            Instruction::FsWrite {
                path: "k".into(),
                value: 7,
            },
            Instruction::Done,
        ]];
        let run = Simulation::new(config, programs).run().unwrap();
        assert!(
            run.journal.entries().any(|entry| {
                matches!(
                    &entry.data.payload,
                    EntryPayload::Fault(FaultPayload::CrashActor { .. })
                )
            }),
            "a CrashState fault must be journaled after a sampled crash"
        );
        assert!(run.monitor_issues.is_empty());
    }

    #[test]
    fn swarm_features_are_deterministic() {
        let config = base_config(12).with_swarm(SwarmConfig {
            drop_probability: crate::config::Probability::new(0.3).unwrap(),
            delay_probability: crate::config::Probability::new(0.3).unwrap(),
            max_delay_ticks: 5,
            crash_probability: crate::config::Probability::new(0.2).unwrap(),
            fault_classes_per_run: 2,
        });
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
        let send_id = |n: u8| ledger_format::EntryHash([n; 32]);
        let first = net.send_at(0, 1, 10, send_id(1), now, 0);
        let second = net.send_at(0, 1, 20, send_id(2), now, 0);
        assert!(first && second);
        let msg = net.recv_at(1, now).unwrap();
        assert_eq!(msg.payload(), 20);
        let msg = net.recv_at(1, now).unwrap();
        assert_eq!(msg.payload(), 10);
    }

    #[test]
    fn fifo_default_serves_oldest_first() {
        use crate::net::SimNet;
        let mut net = SimNet::new();
        let now = 0u64;
        let send_id = |n: u8| ledger_format::EntryHash([n; 32]);
        let _ = net.send_at(0, 1, 10, send_id(1), now, 0);
        let _ = net.send_at(0, 1, 20, send_id(2), now, 0);
        let msg = net.recv_at(1, now).unwrap();
        assert_eq!(msg.payload(), 10);
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
        let seed = ledger_format::EntryHash([3; 32]);
        let base = RunConfig::builder().seed(seed).max_steps(512).build();
        let default_root = Simulation::new(base.clone(), two_task_programs())
            .run()
            .unwrap()
            .journal
            .root_hash();
        let linked = RunConfig::builder()
            .seed(seed)
            .max_steps(512)
            .links(vec![(
                0,
                1,
                LinkConfig {
                    base_delay: 5,
                    ..LinkConfig::default()
                },
            )])
            .build();
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
        let make = || {
            RunConfig::builder()
                .seed(ledger_format::EntryHash([9; 32]))
                .max_steps(512)
                .swarm(crate::config::SwarmConfig {
                    delay_probability: crate::config::Probability::new(0.5).unwrap(),
                    max_delay_ticks: 3,
                    ..crate::config::SwarmConfig::default()
                })
                .links(vec![(
                    0,
                    1,
                    LinkConfig {
                        jitter: 4,
                        loss_probability: crate::config::Probability::new(0.2).unwrap(),
                        ..LinkConfig::default()
                    },
                )])
                .build()
        };
        let a = Simulation::new(make(), two_task_programs()).run().unwrap();
        let b = Simulation::new(make(), two_task_programs()).run().unwrap();
        assert_eq!(a.journal.root_hash(), b.journal.root_hash());
        assert_eq!(a.decisions, b.decisions);
    }

    #[test]
    fn bounded_drop_link_journals_a_drop_fault() {
        use crate::net::QueueFullPolicy;
        use ledger_format::{EntryKind, EntryPayload, FaultPayload};
        // One receiver that never drains fast enough: two sends race one
        // capacity-1 link with a delay so both queue before delivery.
        let config = RunConfig::builder()
            .seed(ledger_format::EntryHash([31; 32]))
            .max_steps(512)
            .links(vec![(
                0,
                1,
                LinkConfig {
                    capacity: Some(1),
                    queue_policy: QueueFullPolicy::Drop,
                    ..LinkConfig::default()
                },
            )])
            .build();
        let programs = vec![
            vec![
                Instruction::Send { to: 1, payload: 1 },
                Instruction::Send { to: 1, payload: 2 },
                Instruction::Send { to: 1, payload: 3 },
                Instruction::Done,
            ],
            vec![
                Instruction::Receive,
                Instruction::Receive,
                Instruction::Receive,
                Instruction::Done,
            ],
        ];
        let run = Simulation::new(config, programs).run().unwrap();
        let drops = run
            .journal
            .entries()
            .filter(|entry| {
                matches!(
                    &entry.data.payload,
                    EntryPayload::Fault(FaultPayload::DropMessage { .. })
                ) && entry.data.kind == EntryKind::Fault
            })
            .count();
        assert!(
            drops >= 1,
            "a full drop-policy queue must journal a Drop fault"
        );
        assert!(run.monitor_issues.is_empty());
    }

    #[test]
    fn bounded_block_link_journals_backpressure_without_a_drop() {
        use crate::net::QueueFullPolicy;
        use ledger_format::{EntryKind, EntryPayload, FaultPayload};
        let config = RunConfig::builder()
            .seed(ledger_format::EntryHash([32; 32]))
            .max_steps(512)
            .links(vec![(
                0,
                1,
                LinkConfig {
                    capacity: Some(1),
                    queue_policy: QueueFullPolicy::Block,
                    ..LinkConfig::default()
                },
            )])
            .build();
        let programs = vec![
            vec![
                Instruction::Send { to: 1, payload: 1 },
                Instruction::Send { to: 1, payload: 2 },
                Instruction::Send { to: 1, payload: 3 },
                Instruction::Done,
            ],
            vec![
                Instruction::Receive,
                Instruction::Receive,
                Instruction::Receive,
                Instruction::Done,
            ],
        ];
        let run = Simulation::new(config, programs).run().unwrap();
        let drops = run
            .journal
            .entries()
            .filter(|entry| {
                matches!(
                    &entry.data.payload,
                    EntryPayload::Fault(FaultPayload::DropMessage { .. })
                )
            })
            .count();
        let blocks = run
            .journal
            .entries()
            .filter(|entry| entry.data.kind == EntryKind::Block)
            .count();
        assert_eq!(
            drops, 0,
            "a block-policy queue must never journal a Drop fault"
        );
        assert!(
            blocks >= 1,
            "a full block-policy queue must journal backpressure"
        );
        assert!(run.monitor_issues.is_empty());
    }
}

#[cfg(test)]
mod delay_fault_regression {
    use crate::config::{Policy, RunConfig, SimFault};
    use crate::runtime::{Instruction, Simulation};
    use ledger_format::EntryKind;

    fn two_task_send_recv_programs() -> Vec<Vec<Instruction>> {
        vec![
            vec![Instruction::Send { to: 1, payload: 99 }, Instruction::Done],
            vec![
                Instruction::Receive,
                Instruction::ReadClock,
                Instruction::Outcome,
                Instruction::Done,
            ],
        ]
    }

    #[test]
    fn delay_fault_on_send_changes_deliver_at_and_marks_applied() {
        // First run without faults to capture the Send entry id.
        let base = RunConfig::builder()
            .seed(ledger_format::EntryHash([42; 32]))
            .policy(Policy::Random)
            .max_steps(256)
            .build();
        let first = Simulation::new(base.clone(), two_task_send_recv_programs())
            .run()
            .expect("first run");
        let send_id = first
            .journal
            .entries()
            .find(|e| matches!(e.data.kind, EntryKind::Send))
            .expect("Send entry exists")
            .id;
        assert!(
            !first.applied_faults.contains(&send_id),
            "first run must not mark delay as applied"
        );
        // Replay the same decision sequence with the Delay fault targeting that Send.
        let delayed_cfg = RunConfig::builder()
            .seed(ledger_format::EntryHash([42; 32]))
            .policy(Policy::Replay)
            .max_steps(256)
            .fault_schedule(vec![SimFault::Delay {
                send: send_id,
                ticks: 7,
            }])
            .build();
        // Keep the builder's Replay policy; inject the recorded decisions at run time.
        let delayed = Simulation::with_replay(
            delayed_cfg,
            two_task_send_recv_programs(),
            first.decisions.clone(),
        )
        .run()
        .expect("delayed replay run");
        assert!(
            delayed.applied_faults.contains(&send_id),
            "Delay fault must be marked applied, not a lie"
        );
        assert!(
            delayed.monitor_issues.is_empty(),
            "monitor issues: {:?}",
            delayed.monitor_issues
        );
        // The injected delay must shift virtual time at the receiver.
        assert_eq!(first.registers.len(), 2);
        assert_eq!(delayed.registers.len(), 2);
        assert!(
            delayed.registers[1] > first.registers[1],
            "delayed clock {} must exceed baseline {}",
            delayed.registers[1],
            first.registers[1]
        );
        assert_eq!(
            delayed.registers[1], 7,
            "exact injected delay must be visible at ReadClock"
        );
        assert_ne!(
            first.journal.root_hash(),
            delayed.journal.root_hash(),
            "delay changes the causal DAG"
        );
        // Delay 0 must keep journals byte-identical for unfaulted runs.
        let zero_cfg = RunConfig::builder()
            .seed(ledger_format::EntryHash([42; 32]))
            .policy(Policy::Replay)
            .max_steps(256)
            .fault_schedule(vec![SimFault::Delay {
                send: send_id,
                ticks: 0,
            }])
            .build();
        let zero = Simulation::with_replay(
            zero_cfg,
            two_task_send_recv_programs(),
            first.decisions.clone(),
        )
        .run()
        .expect("zero-delay replay");
        assert!(
            zero.applied_faults.contains(&send_id),
            "zero delay still counts as applied"
        );
        assert_eq!(
            zero.journal.root_hash(),
            first.journal.root_hash(),
            "delay 0 keeps byte-identical journals"
        );
    }
}

#[cfg(test)]
mod duplicate_fault_regression {
    use crate::config::{Policy, RunConfig, SimFault};
    use crate::runtime::{Instruction, Simulation};
    use ledger_format::{EntryKind, EntryPayload, FaultPayload};

    fn dup_programs() -> Vec<Vec<Instruction>> {
        vec![
            vec![Instruction::Send { to: 1, payload: 99 }, Instruction::Done],
            vec![
                Instruction::Receive,
                Instruction::Receive,
                Instruction::Done,
            ],
        ]
    }

    #[test]
    fn duplicate_send_yields_two_recvs_and_one_fault() {
        let base = RunConfig::builder()
            .seed(ledger_format::EntryHash([42; 32]))
            .policy(Policy::Random)
            .max_steps(512)
            .build();
        let probe = Simulation::new(base, dup_programs())
            .run()
            .expect("probe run");
        let send_id = probe
            .journal
            .entries()
            .find(|e| matches!(e.data.kind, EntryKind::Send))
            .expect("Send entry exists")
            .id;
        let dup_cfg = RunConfig::builder()
            .seed(ledger_format::EntryHash([42; 32]))
            .policy(Policy::Random)
            .max_steps(512)
            .fault_schedule(vec![SimFault::Duplicate { send: send_id }])
            .build();
        let first = Simulation::new(dup_cfg.clone(), dup_programs())
            .run()
            .expect("duplicate run");
        assert!(
            first.applied_faults.contains(&send_id),
            "Duplicate fault must be marked applied"
        );
        assert!(
            first.monitor_issues.is_empty(),
            "monitor issues: {:?}",
            first.monitor_issues
        );
        assert!(
            first.journal_error.is_none(),
            "journal must stay clean: {:?}",
            first.journal_error
        );
        let recvs = first
            .journal
            .entries()
            .filter(|e| matches!(e.data.kind, EntryKind::Recv))
            .count();
        assert_eq!(recvs, 2, "duplicate must deliver two copies");
        let mut dup_faults = first.journal.entries().filter(|e| {
            matches!(
                &e.data.payload,
                EntryPayload::Fault(FaultPayload::DuplicateMessage { .. })
            )
        });
        let fault = dup_faults.next().expect("one DuplicateMessage fault");
        assert!(dup_faults.next().is_none(), "exactly one duplicate fault");
        match &fault.data.payload {
            EntryPayload::Fault(FaultPayload::DuplicateMessage {
                message_id,
                copy_ordinal,
            }) => {
                assert_eq!(*copy_ordinal, 1);
                assert_eq!(fault.data.parents.as_slice(), &[send_id]);
                let send = probe
                    .journal
                    .entries()
                    .find(|e| e.id == send_id)
                    .expect("probe send");
                match &send.data.payload {
                    EntryPayload::Send(frame) => assert_eq!(*message_id, frame.message_id),
                    other => panic!("send entry has wrong payload: {other:?}"),
                }
            }
            other => panic!("expected DuplicateMessage, got {other:?}"),
        }
        assert_eq!(
            first.outcome,
            crate::RunOutcome::Completed,
            "two receives must complete"
        );
        let second = Simulation::new(dup_cfg.clone(), dup_programs())
            .run()
            .expect("second duplicate run");
        assert_eq!(
            first.journal.root_hash(),
            second.journal.root_hash(),
            "duplicate must stay deterministic"
        );
        assert_eq!(first.decisions, second.decisions);
        let strict = Simulation::with_replay_strict(
            RunConfig::builder()
                .seed(ledger_format::EntryHash([42; 32]))
                .policy(Policy::Replay)
                .max_steps(512)
                .fault_schedule(vec![SimFault::Duplicate { send: send_id }])
                .build(),
            dup_programs(),
            first.decisions.clone(),
        )
        .run()
        .expect("strict replay of duplicate must pass");
        assert_eq!(
            strict.journal.root_hash(),
            first.journal.root_hash(),
            "strict replay must match"
        );
    }
}

#[cfg(test)]
mod lane_s_direct_executor_protection {
    use crate::config::RunConfig;
    use crate::executor::Executor;
    use crate::sentinel::ProtectionMode;

    #[test]
    fn direct_executor_required_enforces_belt() {
        let config = RunConfig::builder()
            .seed(ledger_format::EntryHash([9; 32]))
            .max_steps(16)
            .build();
        let executor = Executor::new(config, vec![]).with_protection_mode(ProtectionMode::Required);
        let result = executor.run();
        // On non-linux, Required without belt must be Belt error; on linux with belt, may succeed
        #[cfg(not(all(feature = "sentinel", target_os = "linux")))]
        assert!(
            matches!(result, Err(crate::runtime::RuntimeError::Belt(_))),
            "direct Executor Required must enforce belt, got {result:?}"
        );
        #[cfg(all(feature = "sentinel", target_os = "linux"))]
        {
            match result {
                Ok(run) => assert!(matches!(
                    run.protection,
                    crate::sentinel::BeltStatus::Active { .. }
                )),
                Err(crate::runtime::RuntimeError::Belt(_)) => {}
                Err(other) => panic!("unexpected {other:?}"),
            }
        }
    }

    #[test]
    fn direct_executor_best_effort_reports_protection() {
        let config = RunConfig::builder()
            .seed(ledger_format::EntryHash([10; 32]))
            .max_steps(16)
            .build();
        let executor =
            Executor::new(config, vec![]).with_protection_mode(ProtectionMode::BestEffort);
        let run = executor
            .run()
            .expect("BestEffort direct executor must succeed");
        // Protection field must be present and structured
        let _ = run.protection.clone();
        assert!(matches!(
            run.protection,
            crate::sentinel::BeltStatus::Active { .. }
                | crate::sentinel::BeltStatus::NotArmed
                | crate::sentinel::BeltStatus::Unavailable
                | crate::sentinel::BeltStatus::Failed(_)
        ));
    }
}

#[cfg(test)]
mod lane_s_monitor_prefix {
    use crate::config::RunConfig;
    use crate::executor::Executor;
    use crate::runtime::{OnlineAction, RunResult};
    use ledger_format::EntryKind;
    use std::cell::Cell;
    use std::rc::Rc;

    #[test]
    fn monitor_sees_initial_spawn_entries() {
        let config = RunConfig::builder()
            .seed(ledger_format::EntryHash([11; 32]))
            .max_steps(32)
            .build();
        let saw_spawn = Rc::new(Cell::new(false));
        let saw = saw_spawn.clone();
        let executor = Executor::with_shared(config, |shared| {
            // Create two tasks to get two Spawn entries
            for task_id in 0..2 {
                let boundary = crate::executor::Boundary::for_task(shared.clone(), task_id);
                let fut = Box::pin(async move {
                    let _ = boundary.outcome(42);
                });
                shared
                    .tasks
                    .borrow_mut()
                    .push(crate::executor::make_task_entry(fut));
            }
        })
        .with_step_monitor(Box::new(move |journal, start| {
            if start == 0 {
                for entry in journal.entries() {
                    if entry.data.kind == EntryKind::Spawn {
                        saw.set(true);
                        break;
                    }
                }
            }
            OnlineAction::Continue
        }));
        let _result: RunResult = executor.run().expect("run with prefix monitor");
        assert!(saw_spawn.get(), "monitor must see Spawn at entry 0");
    }
}
