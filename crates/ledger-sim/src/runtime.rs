//! Deterministic single-threaded simulation runtime.
//!
//! [`Simulation`] is the public entry point for instruction-program workloads.
//! It is a thin wrapper over the async [`Executor`]: each instruction program
//! becomes a cooperative future driven by the executor's poll loop, which
//! reproduces the classic one-scheduling-decision-per-instruction discipline
//! (see [`crate::adapter`]).

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use crate::config::{Policy, RunConfig};
use crate::executor::{Boundary, Executor};
use crate::scheduler::StepTrace;
use ledger_format::{GenId, InputKey};
use ledger_journal::{Journal, JournalError, MonitorIssue};

/// Stream id journaled for scheduler-owned scheduling draws.
///
/// The `sched` stream is reserved for scheduling; every scheduler decision
/// consumes one draw from it. The journaled `RngDraw` entry records the
/// resolved ready-list position, not the raw draw, so a replayed run journal
/// stays hash-identical to the original.
pub const SCHED_STREAM: ledger_format::StreamId = 0;

/// Actor id reserved for scheduler-owned journal entries.
pub const SCHED_ACTOR: ledger_format::ActorId = u32::MAX;

/// One cooperative instruction executed by a simulated task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction {
    /// Yield to the scheduler.
    Yield,
    /// Sleep for virtual time units.
    Sleep(u64),
    /// Send a payload to another task immediately.
    Send { to: usize, payload: u64 },
    /// Send a payload with simulated network delay.
    SendTimed { to: usize, payload: u64, delay: u64 },
    /// Receive a message or block.
    Receive,
    /// Record a value in the task-local register.
    ///
    /// Shorthand for [`Instruction::Input`] with zeroed generator and replay
    /// keys. Kept for compatibility: existing workloads and golden journals
    /// use this legacy form, and it journals byte-identically.
    Set(u64),
    /// Record a value in the task-local register under real PBT keys.
    ///
    /// Journaled as an `InputStep { generator, replay }` entry carrying the
    /// value. The keys pin the input axis: `generator` selects the PBT
    /// generator, `replay` indexes the value within that generator's stream.
    Input {
        generator: GenId,
        replay: InputKey,
        value: u64,
    },
    /// Read the current virtual time into the task-local register.
    ReadClock,
    /// Write a key-value entry into SimFs.
    FsWrite { path: String, value: u64 },
    /// Persist dirty entries in SimFs.
    FsFsync,
    /// Read a key-value entry from SimFs.
    FsRead { path: String },
    /// Trigger a storage crash in SimFs.
    ///
    /// Journaled as `Fault { fault: FaultSpec::CrashState(0) }`: the crash
    /// operator (DropAllUnsynced) has exactly one deterministic post-crash
    /// state, indexed 0.
    FsCrash,
    /// Record an assertion.
    Assert(bool),
    /// Emit an outcome entry using the task-local register.
    Outcome,
    /// Stop this task.
    Done,
}

/// Typed halt reason for monitor halts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HaltReason(pub Box<str>);

impl HaltReason {
    /// Create a reason from a string.
    pub fn new(reason: impl Into<Box<str>>) -> Self {
        Self(reason.into())
    }

    /// View as str.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for HaltReason {
    fn from(value: String) -> Self {
        Self(value.into_boxed_str())
    }
}

impl From<&str> for HaltReason {
    fn from(value: &str) -> Self {
        Self(value.into())
    }
}

impl From<Box<str>> for HaltReason {
    fn from(value: Box<str>) -> Self {
        Self(value)
    }
}

impl core::fmt::Display for HaltReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether a run reached completion, and why it stopped when it did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    /// Every task finished.
    Completed,
    /// The step budget ran out while tasks were still ready or blocked.
    BudgetExhausted,
    /// No task was ready and at least one task was still pending.
    Blocked,
    /// A mid-run monitor halted execution.
    MonitorHalt(HaltReason),
}

/// Action returned by a mid-run step monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnlineAction {
    /// Continue execution.
    Continue,
    /// Halt execution with a reason.
    Halt { reason: HaltReason },
}

/// Mid-run monitor called after each scheduling step.
///
/// The callback is read-only over the journal and consumes no seed draws;
/// it receives the journal and the start index of the delta for this step.
pub type StepMonitor = Box<dyn FnMut(&Journal, usize) -> OnlineAction>;

/// Result of a completed deterministic run.
#[derive(Debug, Clone)]
pub struct RunResult {
    /// Causal journal.
    pub journal: Journal,
    /// Scheduler decisions by step.
    pub decisions: Vec<usize>,
    /// Scheduler step traces (ready snapshot plus chosen position).
    ///
    /// Consumed by the source-DPOR driver ([`crate::dpor::run_dpor`]) to find
    /// alternative schedules; recording-only, it never perturbs decisions.
    /// Recorded only when the run's policy is `Dpor` (the driver's base run);
    /// every other policy leaves this empty.
    pub trace: Vec<StepTrace>,
    /// Final task registers.
    pub registers: Vec<u64>,
    /// Number of executed instructions.
    pub steps: usize,
    /// Whether the run completed, and the liveness reason when it did not.
    pub outcome: RunOutcome,
    /// Defects found by the journal-correctness monitor.
    ///
    /// The run does not fail on monitor issues by default; callers decide how
    /// to react to them.
    pub monitor_issues: Vec<MonitorIssue>,
    /// Event ids whose scheduled fault injections took effect.
    pub applied_faults: Vec<ledger_format::Hash>,
    /// Effect origins keyed by entry hash, in append order. Empty unless the
    /// run flowed through origin-capturing calls (crate::origin).
    pub origins: Vec<(ledger_format::Hash, crate::origin::OriginSource)>,
    /// First journal-append failure observed on a path that cannot propagate.
    ///
    /// Append failures on non-`Result` surfaces (send helpers, spawn, crash)
    /// cannot abort the run mid-flight, so the first one is recorded here and
    /// the executor rejects the finished run with [`RuntimeError::Journal`].
    /// A populated slot means the journal is incomplete and byte-identical
    /// replay is broken; on the `Ok` path this field is always `None` (kept
    /// for API stability and inspection).
    pub journal_error: Option<JournalError>,
    /// Belt protection status for this run.
    ///
    /// Reports the per-run `BeltStatus` even for `BestEffort` where the run
    /// continues despite `NotArmed` or `Failed`. `Required` runs that fail
    /// never produce a `RunResult`; the error carries the status.
    pub protection: crate::sentinel::BeltStatus,
}

/// Runtime errors that preserve the failed run context.
#[derive(Debug)]
pub enum RuntimeError {
    /// Journal invariant failed.
    Journal(JournalError),
    /// The instruction budget was exhausted.
    ///
    /// No longer produced: budget exhaustion is now reported through
    /// [`RunResult::outcome`] so the partial journal stays inspectable.
    /// The variant remains because the runtime facade maps it in its
    /// public contract.
    StepLimit { limit: usize },
    /// Strict replay rejected a decision or trailing leftover.
    StrictReplay(crate::scheduler::ReplayViolation),
    /// Belt activation failed or the belt is not active while required.
    Belt(crate::sentinel::BeltStatus),
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(error) => write!(f, "journal error: {error}"),
            Self::StepLimit { limit } => write!(f, "simulation exceeded {limit} steps"),
            Self::StrictReplay(violation) => write!(f, "strict replay violation: {violation}"),
            Self::Belt(status) => write!(f, "belt not active while required: {status}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<JournalError> for RuntimeError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

/// Deterministic cooperative simulator backed by the async executor.
pub struct Simulation {
    executor: Executor,
}

fn install_programs(
    shared: &std::rc::Rc<crate::executor::ExecutorShared>,
    programs: Vec<Vec<Instruction>>,
) {
    for (task_id, program) in programs.into_iter().enumerate() {
        let boundary = crate::executor::Boundary::for_task(std::rc::Rc::clone(shared), task_id);
        let future = crate::adapter::program_future(boundary, program);
        shared
            .tasks
            .borrow_mut()
            .push(crate::executor::make_task_entry(future));
    }
}

impl Simulation {
    /// Create a simulation from task programs.
    pub fn new(config: RunConfig, programs: Vec<Vec<Instruction>>) -> Self {
        Self::with_replay(config, programs, Vec::new())
    }

    /// Create a simulation that follows recorded ready-list choices.
    ///
    /// A complete `replay` never exhausts, so the fallback policy is unused.
    pub fn with_replay(
        config: RunConfig,
        programs: Vec<Vec<Instruction>>,
        replay: Vec<usize>,
    ) -> Self {
        Self::with_replay_and_fallback(config, programs, replay, Policy::Random)
    }

    /// Create a strict simulation that follows recorded choices exactly.
    ///
    /// Out-of-range, exhausted, or trailing decisions surface as
    /// [`RuntimeError::StrictReplay`] and never fall back to a seeded policy.
    pub fn with_replay_strict(
        config: RunConfig,
        programs: Vec<Vec<Instruction>>,
        replay: Vec<usize>,
    ) -> Self {
        let executor = Executor::with_shared_and_replay_strict(config.clone(), replay, |shared| {
            install_programs(shared, programs);
        });
        Self { executor }
    }

    /// Create a simulation with an explicit replay-exhaustion fallback policy.
    ///
    /// Used by the source-DPOR driver: a partial replay pins the forced prefix,
    /// then the fallback continues the schedule deterministically.
    pub fn with_replay_and_fallback(
        config: RunConfig,
        programs: Vec<Vec<Instruction>>,
        replay: Vec<usize>,
        fallback: Policy,
    ) -> Self {
        let executor = Executor::with_shared_and_replay_and_fallback(
            config.clone(),
            replay,
            fallback,
            |shared| {
                install_programs(shared, programs);
            },
        );
        Self { executor }
    }

    /// Attach a mid-run step monitor.
    ///
    /// The monitor is invoked after each scheduling step with the journal and
    /// the start index of the delta. A `Halt` stops the run with
    /// `MonitorHalt`.
    pub fn with_step_monitor(mut self, monitor: StepMonitor) -> Self {
        self.executor = self.executor.with_step_monitor(monitor);
        self
    }

    /// Set host-side protection mode for this run.
    ///
    /// Host option overrides env; default is `BestEffort` when set, else env fallback.
    /// Env `Disabled` with no host option keeps not-armed behavior.
    pub fn with_protection_mode(mut self, mode: crate::sentinel::ProtectionMode) -> Self {
        self.executor = self.executor.with_protection_mode(mode);
        self
    }

    /// Run until all tasks finish, the budget is reached, or a monitor halts.
    ///
    /// Belt activation is enforced in the common executor boundary.
    pub fn run(self) -> Result<RunResult, RuntimeError> {
        self.executor.run()
    }
}

/// Builder for one async system-under-test task.
///
/// Receives the task's [`Boundary`] (the `Effects` handle for this actor) and
/// returns the cooperative future that implements the protocol.
pub type TaskBuilder = Box<dyn FnOnce(Boundary) -> Pin<Box<dyn Future<Output = ()>>>>;

impl Simulation {
    /// Create a simulation from real async SUT task futures.
    ///
    /// Each builder receives the boundary for its task index; the returned
    /// future runs cooperatively on the deterministic executor. This is the
    /// reference-sim surface: protocol code in Rust, not instruction programs.
    pub fn with_tasks(config: RunConfig, builders: Vec<TaskBuilder>) -> Self {
        let executor = Executor::with_shared_and_replay_and_fallback(
            config.clone(),
            Vec::new(),
            Policy::Random,
            |shared| {
                for (task_id, builder) in builders.into_iter().enumerate() {
                    let boundary = Boundary::for_task(shared.clone(), task_id);
                    let future = builder(boundary);
                    let mut tasks = shared.tasks.borrow_mut();
                    tasks.push(crate::executor::make_task_entry(future));
                }
            },
        );
        Self { executor }
    }

    /// Set host-side protection mode for task-based simulation.
    pub fn with_protection_mode_tasks(mut self, mode: crate::sentinel::ProtectionMode) -> Self {
        self.executor = self.executor.with_protection_mode(mode);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_format::EntryKind;

    /// A run whose journal-error slot is populated is rejected end to end:
    /// no [`RunResult`] (and therefore no finding, certificate, or minimized
    /// repro) can derive from a poisoned journal. Every explorer run helper
    /// propagates the `?` on `Simulation::run`, so the rejection reaches
    /// search, campaign, quad, bandit, joint, minimizer, and the corpus
    /// probe without per-helper gates.
    #[test]
    fn poisoned_journal_cannot_yield_a_run() {
        use crate::executor::Boundary;
        let error = ledger_journal::JournalError::InvalidPayload("test poison".to_string());
        let config = RunConfig::builder()
            .seed([23; 32])
            .policy(Policy::Random)
            .max_steps(64)
            .build();
        let run = Simulation::with_tasks(
            config,
            vec![Box::new(|b: Boundary| {
                Box::pin(async move {
                    // Poison the slot the way a failed append would.
                    b.record_journal_error(error);
                })
            })],
        )
        .run();
        assert!(
            matches!(run, Err(RuntimeError::Journal(_))),
            "a poisoned run must not yield a RunResult: {run:?}"
        );
    }

    fn mini_kv_programs() -> Vec<Vec<Instruction>> {
        vec![
            vec![
                Instruction::Send { to: 1, payload: 42 },
                Instruction::Send {
                    to: 2,
                    payload: 100,
                },
                Instruction::Done,
            ],
            vec![
                Instruction::Receive,
                Instruction::Send { to: 2, payload: 42 },
                Instruction::Done,
            ],
            vec![
                Instruction::Receive,
                Instruction::Outcome,
                Instruction::Done,
            ],
        ]
    }

    #[test]
    fn clean_mini_kv_run_produces_zero_monitor_issues() {
        let config = RunConfig::builder()
            .seed([7; 32])
            .policy(Policy::Random)
            .max_steps(256)
            .build();
        let run = Simulation::new(config, mini_kv_programs()).run().unwrap();
        assert!(
            run.monitor_issues.is_empty(),
            "monitor issues: {:?}",
            run.monitor_issues
        );
    }

    #[test]
    fn runtime_journals_spawn_wake_timer_and_clock_read_entries() {
        let config = RunConfig::builder()
            .seed([8; 32])
            .policy(Policy::Random)
            .max_steps(128)
            .build();
        let programs = vec![
            vec![
                Instruction::ReadClock,
                Instruction::Sleep(5),
                Instruction::Done,
            ],
            vec![
                Instruction::Sleep(1),
                Instruction::ReadClock,
                Instruction::Done,
            ],
        ];
        let run = Simulation::new(config, programs).run().unwrap();
        let kinds = run
            .journal
            .entries()
            .map(|entry| entry.data.kind)
            .collect::<Vec<_>>();
        assert!(kinds.iter().any(|kind| matches!(kind, EntryKind::Spawn)));
        assert!(
            kinds
                .iter()
                .any(|kind| matches!(kind, EntryKind::ClockRead))
        );
        assert!(
            kinds
                .iter()
                .any(|kind| matches!(kind, EntryKind::TimerFire))
        );
        assert!(kinds.iter().any(|kind| matches!(kind, EntryKind::Wake)));
        assert!(run.monitor_issues.is_empty());
    }

    #[test]
    fn replay_follows_recorded_decision_sequence() {
        let config = RunConfig::builder()
            .seed([9; 32])
            .policy(Policy::Random)
            .max_steps(256)
            .build();
        let programs = mini_kv_programs();
        let original = Simulation::new(config.clone(), programs.clone())
            .run()
            .unwrap();
        let decisions = original.decisions.clone();
        let replay_config = config.with_policy(Policy::Replay);
        let replayed = Simulation::with_replay(replay_config, programs, decisions)
            .run()
            .unwrap();
        assert_eq!(replayed.journal.root_hash(), original.journal.root_hash());
        assert!(replayed.monitor_issues.is_empty());
    }

    #[test]
    fn input_step_journals_real_generator_and_replay_keys() {
        let config = RunConfig::builder()
            .seed([10; 32])
            .policy(Policy::Random)
            .max_steps(128)
            .build();
        let programs = vec![vec![
            Instruction::Input {
                generator: 7,
                replay: 3,
                value: 99,
            },
            Instruction::Done,
        ]];
        let run = Simulation::new(config, programs).run().unwrap();
        let inputs = run
            .journal
            .entries()
            .filter_map(|entry| match entry.data.kind {
                EntryKind::InputStep { generator, replay } => {
                    Some((generator, replay, entry.data.payload.clone()))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].0, 7);
        assert_eq!(inputs[0].1, 3);
        assert_eq!(inputs[0].2, ledger_format::Payload::Number(99));
        assert!(run.monitor_issues.is_empty());
    }

    #[test]
    fn set_still_journals_zeroed_keys_compatibly() {
        let config = RunConfig::builder()
            .seed([11; 32])
            .policy(Policy::Random)
            .max_steps(128)
            .build();
        let programs = vec![vec![Instruction::Set(42), Instruction::Done]];
        let run = Simulation::new(config, programs).run().unwrap();
        let inputs = run
            .journal
            .entries()
            .filter_map(|entry| match entry.data.kind {
                EntryKind::InputStep { generator, replay } => {
                    Some((generator, replay, entry.data.payload.clone()))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].0, 0);
        assert_eq!(inputs[0].1, 0);
        assert_eq!(inputs[0].2, ledger_format::Payload::Number(42));
        assert!(run.monitor_issues.is_empty());
    }

    /// Without the `sentinel` feature the belt hook must be a pure no-op.
    #[cfg(not(all(feature = "sentinel", target_os = "linux")))]
    #[test]
    fn belt_hook_is_unavailable_without_the_feature() {
        assert_eq!(
            crate::sentinel::activate_process_belt(),
            crate::sentinel::BeltStatus::Unavailable
        );
    }

    #[test]
    fn required_protection_fails_when_belt_not_active() {
        // Require the belt via host option; on platforms without a belt the status
        // is Unavailable, so the run must be rejected with Belt.
        let config = RunConfig::builder().seed([1; 32]).max_steps(16).build();
        let programs = vec![vec![Instruction::Done]];
        let result = Simulation::new(config, programs)
            .with_protection_mode(crate::sentinel::ProtectionMode::Required)
            .run();
        #[cfg(not(all(feature = "sentinel", target_os = "linux")))]
        assert!(
            matches!(
                result,
                Err(RuntimeError::Belt(crate::sentinel::BeltStatus::Unavailable))
            ),
            "Required + Unavailable must be Belt, got {result:?}"
        );
        #[cfg(all(feature = "sentinel", target_os = "linux"))]
        {
            match result {
                Ok(_) => {}
                Err(RuntimeError::Belt(_)) => {}
                Err(other) => panic!("unexpected error for Required: {other:?}"),
            }
        }
    }

    #[test]
    fn best_effort_with_any_belt_succeeds() {
        let config = RunConfig::builder().seed([2; 32]).max_steps(16).build();
        let programs = vec![vec![Instruction::Done]];
        let result = Simulation::new(config, programs)
            .with_protection_mode(crate::sentinel::ProtectionMode::BestEffort)
            .run();
        assert!(
            result.is_ok(),
            "BestEffort must not fail on belt, got {result:?}"
        );
    }

    #[test]
    fn monitor_halts_violating_run_and_is_deterministic() {
        // Monitor that halts when an Outcome entry with value 99 appears.
        let halt_on_99 = |journal: &ledger_journal::Journal, start: usize| {
            for entry in journal.entries().skip(start) {
                if entry.data.kind == ledger_format::EntryKind::Outcome
                    && matches!(&entry.data.payload, ledger_format::Payload::Number(99))
                {
                    return crate::runtime::OnlineAction::Halt {
                        reason: HaltReason::from("outcome 99 forbidden"),
                    };
                }
            }
            crate::runtime::OnlineAction::Continue
        };
        let programs = vec![vec![
            Instruction::Set(99),
            Instruction::Outcome,
            Instruction::Set(1),
            Instruction::Outcome,
            Instruction::Done,
        ]];
        let config = RunConfig::builder().seed([11; 32]).max_steps(64).build();
        let halted = Simulation::new(config.clone(), programs.clone())
            .with_step_monitor(Box::new(halt_on_99))
            .run()
            .expect("halted run should succeed as MonitorHalt, not error");
        assert!(
            matches!(halted.outcome, RunOutcome::MonitorHalt(ref reason) if reason.as_str() == "outcome 99 forbidden"),
            "outcome must be MonitorHalt, got {:?}",
            halted.outcome
        );
        assert!(
            halted.steps < 64,
            "halted run must stop before max_steps, steps {}",
            halted.steps
        );
        // No-monitor run with same seed and programs must complete without
        // MonitorHalt and must produce a different (longer) journal.
        let full = Simulation::new(config.clone(), programs.clone())
            .run()
            .expect("full run");
        assert_eq!(full.outcome, RunOutcome::Completed);
        assert!(full.steps > halted.steps);
        assert_ne!(full.journal.root_hash(), halted.journal.root_hash());
        // Partial journal must replay byte-identically: replay the halted
        // decisions with max_steps capped to the halt point yields the same
        // root. This proves the monitor consumed no seed draws.
        let replay_cfg = RunConfig::builder()
            .seed([11; 32])
            .policy(Policy::Replay)
            .max_steps(halted.steps)
            .build();
        let replayed =
            Simulation::with_replay(replay_cfg, programs.clone(), halted.decisions.clone())
                .run()
                .expect("replay should succeed");
        assert_eq!(
            replayed.journal.root_hash(),
            halted.journal.root_hash(),
            "partial journal must be byte-identical on replay"
        );
        // Also replay with the same monitor must halt identically.
        let halt_again = Simulation::with_replay(
            RunConfig::builder()
                .seed([11; 32])
                .policy(Policy::Replay)
                .max_steps(64)
                .build(),
            programs.clone(),
            halted.decisions.clone(),
        )
        .with_step_monitor(Box::new(|journal, start| {
            for entry in journal.entries().skip(start) {
                if entry.data.kind == ledger_format::EntryKind::Outcome
                    && matches!(&entry.data.payload, ledger_format::Payload::Number(99))
                {
                    return crate::runtime::OnlineAction::Halt {
                        reason: HaltReason::from("outcome 99 forbidden"),
                    };
                }
            }
            crate::runtime::OnlineAction::Continue
        }))
        .run()
        .expect("replay with monitor");
        assert_eq!(halt_again.journal.root_hash(), halted.journal.root_hash());
        assert!(matches!(halt_again.outcome, RunOutcome::MonitorHalt(_)));
    }

    #[test]
    fn no_monitor_run_unchanged() {
        let programs = vec![vec![
            Instruction::Set(7),
            Instruction::Outcome,
            Instruction::Done,
        ]];
        let config = RunConfig::builder().seed([13; 32]).max_steps(32).build();
        let without = Simulation::new(config.clone(), programs.clone())
            .run()
            .expect("without monitor");
        let with_never_halt = Simulation::new(config, programs)
            .with_step_monitor(Box::new(|_, _| crate::runtime::OnlineAction::Continue))
            .run()
            .expect("with never-halt monitor");
        assert_eq!(
            without.journal.root_hash(),
            with_never_halt.journal.root_hash()
        );
        assert_eq!(without.decisions, with_never_halt.decisions);
        assert_eq!(without.outcome, with_never_halt.outcome);
    }

    #[test]
    fn with_replay_strict_forces_replay_policy() {
        // Non-Replay policy with strict must be forced to Replay.
        let config = RunConfig::builder()
            .seed([99; 32])
            .policy(Policy::Random)
            .max_steps(16)
            .build();
        let programs = vec![vec![Instruction::Done]];
        // Strict should force Replay and then validate replay length.
        let strict_ok =
            Simulation::with_replay_strict(config.clone(), programs.clone(), vec![]).run();
        // Empty replay with strict and zero steps: trailing check passes (replay len 0).
        assert!(
            strict_ok.is_ok() || matches!(strict_ok, Err(RuntimeError::StrictReplay(_))),
            "strict with forced Replay must not silently ignore policy, got {strict_ok:?}"
        );
        // Non-empty replay that matches run should succeed after forcing.
        let base = Simulation::new(config.clone(), programs.clone())
            .run()
            .unwrap();
        let strict_replay = Simulation::with_replay_strict(
            config.clone(),
            programs.clone(),
            base.decisions.clone(),
        )
        .run()
        .expect("strict replay with forced Replay must succeed");
        assert_eq!(strict_replay.journal.root_hash(), base.journal.root_hash());
    }

    #[test]
    fn with_replay_strict_rejects_trailing_via_violation() {
        let config = RunConfig::builder().seed([11; 32]).max_steps(64).build();
        let programs = vec![vec![
            Instruction::Set(1),
            Instruction::Outcome,
            Instruction::Done,
        ]];
        let base = Simulation::new(config.clone(), programs.clone())
            .run()
            .unwrap();
        let mut trailing = base.decisions.clone();
        trailing.push(0);
        trailing.push(1);
        let err = Simulation::with_replay_strict(config, programs, trailing)
            .run()
            .expect_err("trailing replay must be StrictReplay");
        assert!(matches!(err, RuntimeError::StrictReplay(_)));
    }

    #[test]
    fn best_effort_reports_protection_status() {
        let config = RunConfig::builder().seed([5; 32]).max_steps(16).build();
        let programs = vec![vec![Instruction::Done]];
        let run = Simulation::new(config, programs)
            .with_protection_mode(crate::sentinel::ProtectionMode::BestEffort)
            .run()
            .expect("BestEffort must succeed");
        // Protection field is additive and always present.
        let _ = run.protection.clone();
        assert!(
            matches!(
                run.protection,
                crate::sentinel::BeltStatus::Active { .. }
                    | crate::sentinel::BeltStatus::NotArmed
                    | crate::sentinel::BeltStatus::Unavailable
                    | crate::sentinel::BeltStatus::Failed(_)
            ),
            "protection must be structured, got {:?}",
            run.protection
        );
    }

    #[test]
    fn required_rejects_incomplete_installation() {
        let config = RunConfig::builder().seed([6; 32]).max_steps(16).build();
        let programs = vec![vec![Instruction::Done]];
        let result = Simulation::new(config, programs)
            .with_protection_mode(crate::sentinel::ProtectionMode::Required)
            .run();
        // On non-linux or without belt, Required must error with Belt status.
        #[cfg(not(all(feature = "sentinel", target_os = "linux")))]
        assert!(
            matches!(result, Err(RuntimeError::Belt(_))),
            "Required without belt must be Belt error, got {result:?}"
        );
        #[cfg(all(feature = "sentinel", target_os = "linux"))]
        {
            match result {
                Ok(run) => assert!(matches!(
                    run.protection,
                    crate::sentinel::BeltStatus::Active { .. }
                )),
                Err(RuntimeError::Belt(_)) => {}
                Err(other) => panic!("unexpected error {other:?}"),
            }
        }
    }

    #[test]
    fn monitor_sees_initial_spawn_prefix() {
        let config = RunConfig::builder().seed([7; 32]).max_steps(32).build();
        let programs = vec![vec![Instruction::Done], vec![Instruction::Done]];
        let saw_spawn = std::cell::Cell::new(false);
        let saw = std::rc::Rc::new(std::cell::Cell::new(false));
        let saw_clone = saw.clone();
        let run = Simulation::new(config, programs)
            .with_step_monitor(Box::new(move |journal, start| {
                if start == 0 {
                    for entry in journal.entries() {
                        if entry.data.kind == ledger_format::EntryKind::Spawn {
                            saw_clone.set(true);
                            break;
                        }
                    }
                }
                crate::runtime::OnlineAction::Continue
            }))
            .run()
            .expect("run with prefix monitor");
        assert!(saw.get(), "monitor must observe Spawn at entry 0");
        let _ = saw_spawn;
        let _ = run.journal.len();
    }
}
