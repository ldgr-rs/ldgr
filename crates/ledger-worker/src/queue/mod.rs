//! Task queue backends and their shared contracts.
//!
//! The module root keeps the task model ([`Task`], [`TaskStatus`]) and the
//! [`TaskQueue`] trait. [`wire`] owns the queue-file serde projections,
//! [`memory`] owns the lease-accounting in-memory backend, and `pg`
//! (feature-gated) owns the River/Postgres backend. The root re-exports
//! every public item so the historical `queue` API surface is unchanged.

use ledger_format::Hash;
use ledger_sim::RunConfig;

mod memory;
#[cfg(feature = "pg")]
pub mod pg;
mod wire;

pub use memory::InMemoryQueue;
pub use wire::{FlatQueueFileLine, QueueFileError, QueueFileLine, TaskSpecError, WorkerTaskSpec};

/// Default execution budget before a task is retired as failed.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 3;

/// Lifecycle state of a [`Task`].
///
/// `Queued` and `Leased` are transient; `Failed`, `Cancelled`, and `Done`
/// are terminal. Terminal tasks never re-enter the queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    /// Waiting in the queue for a worker lease.
    Queued,
    /// Held by a worker under a live lease deadline.
    Leased,
    /// Attempts exhausted; retired to the failed list.
    Failed,
    /// Cancelled before completion; terminal.
    Cancelled,
    /// Executed successfully and acknowledged; terminal.
    Done,
}

impl TaskStatus {
    /// Whether the state ends the task's lifecycle.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Failed | Self::Cancelled | Self::Done)
    }
}

/// One campaign task handed to the worker.
#[derive(Debug, Clone)]
pub struct Task {
    /// Unique task identifier.
    pub id: String,
    /// Deterministic simulation configuration.
    pub run_config: RunConfig,
    /// Workload name that selects the instruction programs.
    pub workload: String,
    /// Optional deterministic hash of run_config, computed at queue push.
    pub run_config_hash: Option<Hash>,
    /// Execution attempts charged against this task.
    pub attempts: u32,
    /// Attempt budget; exhaustion moves the task to the failed list.
    pub max_attempts: u32,
    /// Current lifecycle state.
    pub status: TaskStatus,
}

impl Task {
    /// Create a new task in the [`TaskStatus::Queued`] state with
    /// [`DEFAULT_MAX_ATTEMPTS`].
    pub fn new(id: impl Into<String>, run_config: RunConfig, workload: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            run_config,
            workload: workload.into(),
            run_config_hash: None,
            attempts: 0,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            status: TaskStatus::Queued,
        }
    }
}

/// Outcome of charging one failed attempt against a leased task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// The task was requeued; attempts remain in the budget.
    Retried { attempts: u32, max_attempts: u32 },
    /// The budget was exhausted; the task is terminally failed.
    Exhausted { attempts: u32 },
}

/// Abstract task queue consumed by the worker.
pub trait TaskQueue {
    /// Pull the next available task, if any.
    fn pull(&mut self) -> Option<Task>;

    /// Number of tasks waiting in the queue.
    fn len(&self) -> usize;

    /// Whether the queue is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Acknowledge completion and release the lease.
    ///
    /// Default no-op keeps trait object compatible for stubs. Real queues
    /// (Postgres/River) delete or complete the job; [`InMemoryQueue`] moves
    /// the task to the terminal done list.
    fn ack(&mut self, _task_id: &str) {}

    /// Charge one failed execution attempt against a leased task.
    ///
    /// Default no-op returns `None` so stub queues keep old behavior.
    /// Lease-accounting queues requeue while attempts remain and retire the
    /// task once [`Task::max_attempts`] is exhausted.
    fn report_failure(&mut self, _task_id: &str) -> Option<AttemptOutcome> {
        None
    }
}
