//! Explicit single-threaded deterministic simulation runtime.

use std::collections::VecDeque;
use std::fmt;

use crate::config::RunConfig;
use crate::format::{EntryKind, Payload};
use crate::journal::{Journal, JournalError};
use crate::net::{Message, SimNet};
use crate::scheduler::Scheduler;
use crate::time::VirtualTime;

/// One cooperative instruction executed by a simulated task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction {
    /// Yield to the scheduler.
    Yield,
    /// Sleep for virtual time units.
    Sleep(u64),
    /// Send a payload to another task.
    Send { to: usize, payload: u64 },
    /// Receive a message or block.
    Receive,
    /// Record a value in the task-local register.
    Set(u64),
    /// Emit an outcome entry using the task-local register.
    Outcome,
    /// Stop this task.
    Done,
}

/// State of one simulated task.
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

/// Result of a completed deterministic run.
#[derive(Debug, Clone)]
pub struct RunResult {
    /// Causal journal.
    pub journal: Journal,
    /// Scheduler decisions by step.
    pub decisions: Vec<usize>,
    /// Final task registers.
    pub registers: Vec<u64>,
    /// Number of executed instructions.
    pub steps: usize,
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

/// Deterministic cooperative simulator.
pub struct Simulation {
    config: RunConfig,
    tasks: Vec<Task>,
    ready: Vec<usize>,
    scheduler: Scheduler,
    journal: Journal,
    time: VirtualTime,
    net: SimNet,
}

impl Simulation {
    /// Create a simulation from task programs.
    pub fn new(config: RunConfig, programs: Vec<Vec<Instruction>>) -> Self {
        Self::with_replay(config, programs, Vec::new())
    }

    /// Create a simulation that follows recorded ready-list choices.
    pub fn with_replay(
        config: RunConfig,
        programs: Vec<Vec<Instruction>>,
        replay: Vec<usize>,
    ) -> Self {
        let tasks = programs
            .into_iter()
            .enumerate()
            .map(|(id, program)| Task {
                id,
                program: program.into(),
                register: 0,
                blocked: false,
                done: false,
            })
            .collect::<Vec<_>>();
        let ready = (0..tasks.len()).collect::<Vec<_>>();
        let scheduler = Scheduler::new(config.policy, config.seed_tree(), replay);
        Self {
            config,
            tasks,
            ready,
            scheduler,
            journal: Journal::new(),
            time: VirtualTime::default(),
            net: SimNet::default(),
        }
    }

    /// Run until all tasks finish or the instruction budget is reached.
    pub fn run(mut self) -> Result<RunResult, RuntimeError> {
        let mut steps = 0;
        while steps < self.config.max_steps {
            self.wake_receivers();
            if self.ready.is_empty() {
                let released = self.time.advance();
                self.ready.extend(released);
                self.wake_receivers();
                if self.ready.is_empty() {
                    if self.tasks.iter().all(|task| task.done) {
                        break;
                    }
                    break;
                }
            }
            let ready_index = self.scheduler.choose(self.ready.len(), steps);
            let task_id = self.ready.swap_remove(ready_index);
            if self.tasks[task_id].done || self.tasks[task_id].blocked {
                continue;
            }
            let Some(instruction) = self.tasks[task_id].program.pop_front() else {
                self.tasks[task_id].done = true;
                continue;
            };
            self.execute(task_id, instruction)?;
            steps += 1;
            if !self.tasks[task_id].done && !self.tasks[task_id].blocked {
                self.ready.push(task_id);
            }
        }
        if steps == self.config.max_steps {
            return Err(RuntimeError::StepLimit {
                limit: self.config.max_steps,
            });
        }
        Ok(RunResult {
            journal: self.journal,
            decisions: self.scheduler.decisions().to_vec(),
            registers: self.tasks.iter().map(|task| task.register).collect(),
            steps,
        })
    }

    fn execute(&mut self, task_id: usize, instruction: Instruction) -> Result<(), RuntimeError> {
        let actor = task_id as u32;
        match instruction {
            Instruction::Yield => {
                self.journal
                    .append(EntryKind::Block, actor, [], Payload::Empty)?;
            }
            Instruction::Sleep(delay) => {
                self.journal
                    .append(EntryKind::TimerSet, actor, [], Payload::Number(delay))?;
                self.time.set(delay, task_id);
                self.tasks[task_id].blocked = true;
            }
            Instruction::Send { to, payload } => {
                let id = self.journal.append(
                    EntryKind::Send,
                    actor,
                    [],
                    Payload::Pair {
                        left: to as u64,
                        right: payload,
                    },
                )?;
                let delivered = self.net.send(Message {
                    from: task_id,
                    to,
                    payload,
                    send_id: id,
                });
                if !delivered {
                    self.journal.append(
                        EntryKind::Fault,
                        actor,
                        [id],
                        Payload::Text("partition".into()),
                    )?;
                }
            }
            Instruction::Receive => {
                if let Some(message) = self.net.recv(task_id) {
                    self.tasks[task_id].register = message.payload;
                    self.journal.append(
                        EntryKind::Recv,
                        actor,
                        [message.send_id],
                        Payload::Number(message.payload),
                    )?;
                } else {
                    self.tasks[task_id].blocked = true;
                    self.journal
                        .append(EntryKind::Block, actor, [], Payload::Empty)?;
                }
            }
            Instruction::Set(value) => {
                self.tasks[task_id].register = value;
                self.journal
                    .append(EntryKind::InputStep, actor, [], Payload::Number(value))?;
            }
            Instruction::Outcome => {
                let value = self.tasks[task_id].register;
                self.journal
                    .append(EntryKind::Outcome, actor, [], Payload::Number(value))?;
            }
            Instruction::Done => {
                self.tasks[task_id].done = true;
                self.journal
                    .append(EntryKind::Outcome, actor, [], Payload::Text("done".into()))?;
            }
        }
        Ok(())
    }

    fn wake_receivers(&mut self) {
        for task in &mut self.tasks {
            if task.blocked && self.net.has_message(task.id) {
                task.blocked = false;
                self.ready.push(task.id);
            }
        }
    }
}
