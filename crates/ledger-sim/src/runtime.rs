//! Deterministic single-threaded simulation runtime.
//!
//! [`Simulation`] is the public entry point for instruction-program workloads.
//! It is a thin wrapper over the async [`Executor`]: each instruction program
//! becomes a cooperative future driven by the executor's poll loop, which
//! reproduces the classic one-scheduling-decision-per-instruction discipline
//! (see [`crate::adapter`]).

use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

use crate::adapter::program_future;
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
    /// Defects found by the journal-correctness monitor.
    ///
    /// The run does not fail on monitor issues by default; callers decide how
    /// to react to them.
    pub monitor_issues: Vec<MonitorIssue>,
    /// Event ids whose scheduled fault injections took effect.
    pub applied_faults: Vec<ledger_format::Hash>,
}

/// Runtime errors that preserve the failed run context.
#[derive(Debug)]
pub enum RuntimeError {
    /// Journal invariant failed.
    Journal(JournalError),
    /// The instruction budget was exhausted.
    StepLimit { limit: usize },
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(error) => write!(f, "journal error: {error}"),
            Self::StepLimit { limit } => write!(f, "simulation exceeded {limit} steps"),
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
                for (task_id, program) in programs.into_iter().enumerate() {
                    let boundary = Boundary::for_task(shared.clone(), task_id);
                    let future = program_future(boundary, program);
                    let mut tasks = shared.tasks.borrow_mut();
                    tasks.push(crate::executor::make_task_entry(future));
                }
            },
        );
        Self { executor }
    }

    /// Run until all tasks finish or the instruction budget is reached.
    pub fn run(self) -> Result<RunResult, RuntimeError> {
        let _tsc_guard = crate::sentinel::TscTrapGuard::arm_if_armed();
        crate::sentinel::activate_process_belt();
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
}

/// Legacy task shape retained for API compatibility; the executor does not use
/// it. Kept so the public `Task` type name continues to resolve.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct Task {
    /// Task identity.
    pub id: usize,
    /// Remaining instructions.
    pub program: VecDeque<Instruction>,
    /// Last received or assigned value.
    pub register: u64,
    /// Whether the task is blocked on a receive or timer.
    pub blocked: bool,
    /// Whether the task completed.
    pub done: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_format::EntryKind;

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
        let config = RunConfig {
            seed: [7; 32],
            policy: Policy::Random,
            max_steps: 256,
            ..RunConfig::default()
        };
        let run = Simulation::new(config, mini_kv_programs()).run().unwrap();
        assert!(
            run.monitor_issues.is_empty(),
            "monitor issues: {:?}",
            run.monitor_issues
        );
    }

    #[test]
    fn runtime_journals_spawn_wake_timer_and_clock_read_entries() {
        let config = RunConfig {
            seed: [8; 32],
            policy: Policy::Random,
            max_steps: 128,
            ..RunConfig::default()
        };
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
        let config = RunConfig {
            seed: [9; 32],
            policy: Policy::Random,
            max_steps: 256,
            ..RunConfig::default()
        };
        let programs = mini_kv_programs();
        let original = Simulation::new(config.clone(), programs.clone())
            .run()
            .unwrap();
        let decisions = original.decisions.clone();
        let mut replay_config = config;
        replay_config.policy = Policy::Replay;
        let replayed = Simulation::with_replay(replay_config, programs, decisions)
            .run()
            .unwrap();
        assert_eq!(replayed.journal.root_hash(), original.journal.root_hash());
        assert!(replayed.monitor_issues.is_empty());
    }

    #[test]
    fn input_step_journals_real_generator_and_replay_keys() {
        let config = RunConfig {
            seed: [10; 32],
            policy: Policy::Random,
            max_steps: 128,
            ..RunConfig::default()
        };
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
        let config = RunConfig {
            seed: [11; 32],
            policy: Policy::Random,
            max_steps: 128,
            ..RunConfig::default()
        };
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
}
