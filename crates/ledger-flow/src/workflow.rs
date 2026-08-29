//! Durable execution step-logging workflow engine.
//!
//! Each step journals a `StepBegin` before the external effect and a
//! `StepEnd` after it completes. If an effect does not complete (crash
//! between begin and end leaves an unpaired begin), the next `resume`
//! reruns that effect. This is an at-least-once retry contract for
//! incomplete external effects: an unpaired begin is evidence the effect
//! may not have committed, so it is retried until a paired end appears.
//! Completed steps (paired begin and end) are skipped. Callers must make
//! external effects idempotent or safe to retry.
//!
//! A typed `StepBeginPayload` v2 is deferred to stage E2; the v1 text-name payload is the current contract. This documents the approved G1 contract and its E2 evolution, not a pending plan marker.

use std::collections::{HashMap, HashSet};

use ledger_format::{ActorId, EntryKind, EntryPayload, Hash};
use ledger_journal::{Journal, JournalError};
use thiserror::Error;

/// Errors surfaced by durable workflow planning and resumption.
#[derive(Debug, Error)]
pub enum FlowError {
    /// A journal append failed.
    #[error("journal error: {0}")]
    Journal(#[from] JournalError),
    /// The plan repeats a step name; skip detection would be ambiguous.
    #[error("duplicate step name in plan: {0}")]
    DuplicateStep(String),
    /// Resume was called without an attached plan.
    #[error("resume called without an attached WorkflowPlan")]
    NoPlan,
}

/// How [`WorkflowExecution::resume`] handled one planned step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeStatus {
    /// Begin and end were both journaled; execution was skipped.
    Skipped,
    /// Only an unpaired begin existed (crash mid-step); the effect re-ran.
    Rerun,
    /// No journal evidence existed; the effect ran once.
    Executed,
}

/// Result of one resumed step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepOutcome {
    /// Planned step name.
    pub name: String,
    /// How resume handled the step.
    pub status: ResumeStatus,
    /// Effect result, recorded or freshly produced.
    pub result: u64,
}

/// Ordered step names a durable workflow intends to run.
///
/// The plan is the resumption intent: `resume` consults it against journal
/// evidence to decide skip, rerun, or execute per step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowPlan {
    steps: Vec<String>,
}

impl WorkflowPlan {
    /// Build a plan from ordered step names.
    ///
    /// # Errors
    /// Returns [`FlowError::DuplicateStep`] when a name appears more than
    /// once; repeated names make journal skip detection ambiguous.
    pub fn plan(steps: Vec<String>) -> Result<Self, FlowError> {
        let mut seen: HashSet<&str> = HashSet::with_capacity(steps.len());
        for name in &steps {
            if !seen.insert(name.as_str()) {
                return Err(FlowError::DuplicateStep(name.clone()));
            }
        }
        Ok(Self { steps })
    }

    /// Ordered step names.
    pub fn steps(&self) -> &[String] {
        &self.steps
    }
}

/// Durable workflow instance that journals step evidence for crash recovery.
///
/// One active workflow per actor id; concurrent workflows require distinct
/// actors.
#[derive(Debug, Clone)]
pub struct WorkflowExecution {
    /// Actor that owns all step entries in the journal.
    pub actor: ActorId,
    /// Count of StepBegin entries observed for this actor (includes unpaired).
    pub step_counter: u64,
    /// Completed steps as (name, result) in journal order.
    pub completed_steps: Vec<(String, u64)>,
    /// Ordered step intent consulted by [`Self::resume`].
    plan: Option<WorkflowPlan>,
}

impl WorkflowExecution {
    /// Create a new durable workflow for an actor.
    pub fn new(actor: ActorId) -> Self {
        Self {
            actor,
            step_counter: 0,
            completed_steps: Vec::new(),
            plan: None,
        }
    }

    /// Attach the ordered step intent used by [`Self::resume`].
    ///
    /// Replaces any previously attached plan.
    pub fn set_plan(&mut self, plan: WorkflowPlan) {
        self.plan = Some(plan);
    }

    /// The attached plan, if any.
    pub fn plan(&self) -> Option<&WorkflowPlan> {
        self.plan.as_ref()
    }

    /// Record the beginning of a durable step in the journal.
    pub fn step_begin(
        &mut self,
        journal: &mut Journal,
        step_name: &str,
    ) -> Result<Hash, JournalError> {
        let hash = journal.append(
            EntryKind::StepBegin,
            self.actor,
            [],
            EntryPayload::StepBegin(ledger_format::StepBeginPayload {
                step_id: self.step_counter,
                name: step_name.as_bytes().to_vec(),
                idempotency_key: None,
            }),
        )?;
        self.step_counter += 1;
        Ok(hash)
    }

    /// Record the successful completion of a durable step in the journal.
    pub fn step_end(
        &mut self,
        journal: &mut Journal,
        step_name: &str,
        begin_hash: Hash,
        result_value: u64,
    ) -> Result<Hash, JournalError> {
        let end_hash = journal.append(
            EntryKind::StepEnd,
            self.actor,
            [begin_hash],
            EntryPayload::StepEnd(ledger_format::StepEndPayload::Completed {
                step_id: self.step_counter,
                result: ledger_format::CanonicalValue::Unsigned(result_value),
            }),
        )?;
        // Push only after the append succeeded: a failed append must not
        // leave a completed step that the journal does not contain.
        self.completed_steps
            .push((step_name.to_string(), result_value));
        Ok(end_hash)
    }

    /// Recover workflow state from a journal.
    ///
    /// Pairs each `StepEnd` with its `StepBegin` parent to restore the
    /// recorded step name. Unpaired `StepBegin` entries contribute to
    /// `step_counter` but do not appear in `completed_steps`.
    pub fn recover_from_journal(actor: ActorId, journal: &Journal) -> Self {
        let evidence = scan_step_evidence(journal, actor);
        let mut completed_steps = Vec::new();
        for entry in journal.entries() {
            if entry.data.actor != actor {
                continue;
            }
            if entry.data.kind == EntryKind::StepEnd
                && let EntryPayload::StepEnd(ledger_format::StepEndPayload::Completed {
                    result: ledger_format::CanonicalValue::Unsigned(val),
                    ..
                }) = entry.data.payload
                && let Some(parent) = entry.data.parents.first().copied()
                && let Some(name) = evidence.begin_names.get(&parent)
            {
                completed_steps.push((name.clone(), val));
            }
        }
        Self {
            actor,
            step_counter: evidence.begin_names.len() as u64,
            completed_steps,
            plan: None,
        }
    }

    /// Resume a planned workflow with Temporal-style at-most-once skip.
    ///
    /// For every planned step, journal evidence decides the action:
    ///
    /// - The step's begin has a paired end: skip execution and report the
    ///   recorded result ([`ResumeStatus::Skipped`]).
    /// - Only an unpaired begin exists (crash between begin and end):
    ///   re-execute and pair the new end against that existing begin
    ///   ([`ResumeStatus::Rerun`]).
    /// - No entries exist: execute once and append a fresh begin-end pair
    ///   ([`ResumeStatus::Executed`]).
    ///
    /// The begin entry lands before the effect runs, so a crash during the
    /// effect leaves an unpaired begin that classifies the step as
    /// [`ResumeStatus::Rerun`] on the next resume. Re-running a completed
    /// plan is idempotent: every outcome is [`ResumeStatus::Skipped`] with
    /// identical results.
    ///
    /// # Errors
    /// Returns [`FlowError::NoPlan`] when no plan is attached via
    /// [`Self::set_plan`], [`FlowError::Journal`] when an append fails, and
    /// propagates errors from `exec` (the journal keeps the unpaired begin).
    pub fn resume(
        &mut self,
        journal: &mut Journal,
        mut exec: impl FnMut(&str) -> Result<u64, FlowError>,
    ) -> Result<Vec<StepOutcome>, FlowError> {
        // Owned copy so `self` stays free for step_begin/step_end below.
        let steps: Vec<String> = self
            .plan
            .as_ref()
            .ok_or(FlowError::NoPlan)?
            .steps()
            .to_vec();
        let evidence = scan_step_evidence(journal, self.actor);

        let mut outcomes = Vec::with_capacity(steps.len());
        for name in &steps {
            let outcome = match classify(name, &evidence) {
                StepPrior::Skipped { result } => StepOutcome {
                    name: name.clone(),
                    status: ResumeStatus::Skipped,
                    result,
                },
                StepPrior::InProgress(begin_hash) => {
                    // Pair against the orphaned begin; never append a second.
                    let value = exec(name)?;
                    self.step_end(journal, name, begin_hash, value)?;
                    StepOutcome {
                        name: name.clone(),
                        status: ResumeStatus::Rerun,
                        result: value,
                    }
                }
                StepPrior::Pending => {
                    // Begin lands before the effect so a crash mid-effect
                    // leaves an unpaired begin as rerun evidence.
                    let begin_hash = self.step_begin(journal, name)?;
                    let value = exec(name)?;
                    self.step_end(journal, name, begin_hash, value)?;
                    StepOutcome {
                        name: name.clone(),
                        status: ResumeStatus::Executed,
                        result: value,
                    }
                }
            };
            outcomes.push(outcome);
        }
        Ok(outcomes)
    }
}

/// Journal evidence about durable steps, keyed by step name.
struct StepEvidence {
    /// Latest begin hash per step name.
    begins: HashMap<String, Hash>,
    /// Begin hash to step name for recovery.
    begin_names: HashMap<Hash, String>,
    /// Recorded end values keyed by their paired begin hash.
    ends: HashMap<Hash, u64>,
}

/// Classification of one planned step against journal evidence.
enum StepPrior {
    /// No entries; run fresh and journal begin then end.
    Pending,
    /// Unpaired begin at this hash; re-run and pair the end against it.
    InProgress(Hash),
    /// Paired begin and end; skip with the recorded result.
    Skipped { result: u64 },
}

fn classify(name: &str, evidence: &StepEvidence) -> StepPrior {
    match evidence.begins.get(name) {
        Some(begin_hash) => match evidence.ends.get(begin_hash) {
            Some(result) => StepPrior::Skipped { result: *result },
            None => StepPrior::InProgress(*begin_hash),
        },
        None => StepPrior::Pending,
    }
}

/// Collect latest-begin and paired-end evidence for one actor.
///
/// A later unpaired begin supersedes an earlier completed pair: the crash
/// happened while the step was mid-flight again, so the step must re-run.
fn scan_step_evidence(journal: &Journal, actor: ActorId) -> StepEvidence {
    let mut evidence = StepEvidence {
        begins: HashMap::new(),
        begin_names: HashMap::new(),
        ends: HashMap::new(),
    };
    for entry in journal.entries() {
        if entry.data.actor != actor {
            continue;
        }
        match entry.data.kind {
            EntryKind::StepBegin => {
                if let EntryPayload::StepBegin(begin) = &entry.data.payload {
                    let name = String::from_utf8_lossy(&begin.name).to_string();
                    evidence.begins.insert(name.clone(), entry.id);
                    evidence.begin_names.insert(entry.id, name.clone());
                }
            }
            EntryKind::StepEnd => {
                if let EntryPayload::StepEnd(ledger_format::StepEndPayload::Completed {
                    result: ledger_format::CanonicalValue::Unsigned(value),
                    ..
                }) = entry.data.payload
                    && let Some(parent) = entry.data.parents.first().copied()
                {
                    evidence.ends.insert(parent, value);
                }
            }
            _ => {}
        }
    }
    evidence
}
