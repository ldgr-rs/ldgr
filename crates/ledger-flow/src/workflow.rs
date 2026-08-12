//! Durable execution step-logging workflow engine.

use ledger_format::{ActorId, EntryKind, Hash, Payload};
use ledger_journal::{Journal, JournalError};

/// Status of an individual workflow step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepStatus {
    Pending,
    InProgress { start_entry: Hash },
    Completed { end_entry: Hash, result: u64 },
}

/// A durable execution workflow instance.
#[derive(Debug, Clone)]
pub struct WorkflowExecution {
    pub actor: ActorId,
    pub step_counter: u64,
    pub completed_steps: Vec<(String, u64)>,
}

impl WorkflowExecution {
    /// Create a new durable workflow for an actor.
    pub fn new(actor: ActorId) -> Self {
        Self {
            actor,
            step_counter: 0,
            completed_steps: Vec::new(),
        }
    }

    /// Record the beginning of a durable step in the journal.
    pub fn step_begin(
        &mut self,
        journal: &mut Journal,
        step_name: &str,
    ) -> Result<Hash, JournalError> {
        self.step_counter += 1;
        journal.append(
            EntryKind::StepBegin,
            self.actor,
            [],
            Payload::Text(step_name.to_string()),
        )
    }

    /// Record the successful completion of a durable step in the journal.
    pub fn step_end(
        &mut self,
        journal: &mut Journal,
        step_name: &str,
        begin_hash: Hash,
        result_value: u64,
    ) -> Result<Hash, JournalError> {
        self.completed_steps
            .push((step_name.to_string(), result_value));
        journal.append(
            EntryKind::StepEnd,
            self.actor,
            [begin_hash],
            Payload::Number(result_value),
        )
    }

    /// Recover workflow state from a journal.
    pub fn recover_from_journal(actor: ActorId, journal: &Journal) -> Self {
        let mut completed_steps = Vec::new();
        let mut count = 0;

        for entry in journal.entries() {
            if entry.data.actor == actor {
                if entry.data.kind == EntryKind::StepBegin {
                    count += 1;
                } else if entry.data.kind == EntryKind::StepEnd
                    && let Payload::Number(val) = entry.data.payload
                {
                    completed_steps.push(("step".into(), val));
                }
            }
        }

        Self {
            actor,
            step_counter: count,
            completed_steps,
        }
    }
}
