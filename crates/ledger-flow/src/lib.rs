#![deny(unsafe_code)]

//! Durable execution step logging built on the Ledger causal journal.
//!
//! EXPERIMENTAL: the API is usable for evaluation but has no production
//! consumers yet. The step-begin/end entries, recovery rules, and plan
//! semantics are fixed by the eight unit tests in this crate; treat any
//! wider compatibility promise as pending.
//!
//! One active workflow per actor id; use distinct actors for concurrent
//! workflows.
//!
//! [`WorkflowPlan`] fixes the ordered step names. [`WorkflowExecution`]
//! journals a begin entry per step and pairs it with an end entry carrying
//! the effect result; [`WorkflowExecution::resume`] replays the journal and
//! skips, reruns, or executes each planned step based on the recorded
//! evidence.
//!
//! # Durable step logging and retry contract
//!
//! Each step journals a `StepBegin` before the external effect runs and a
//! `StepEnd` after it completes. If a step's external effect does not
//! complete (crash between begin and end leaves an unpaired begin), the next
//! `resume` reruns that effect. This gives at-least-once execution for
//! incomplete external effects: a begin without a paired end is evidence
//! that the effect may not have committed, so it is retried. Completed steps
//! (paired begin and end) are skipped. Callers must make external effects
//! idempotent or safe to retry.
//!
//! A typed `StepBeginPayload` v2 is deferred to stage E2; the v1 text-name payload is the current contract. This documents the approved G1 contract and its E2 evolution, not a pending plan marker.

pub mod workflow;
pub use workflow::{FlowError, ResumeStatus, StepOutcome, WorkflowExecution, WorkflowPlan};

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_format::{EntryKind, Payload};
    use ledger_journal::Journal;

    #[test]
    fn workflow_logs_and_recovers_steps() {
        let mut journal = Journal::new();
        let mut wf = WorkflowExecution::new(1);

        let begin_h = wf.step_begin(&mut journal, "charge_card").unwrap();
        wf.step_end(&mut journal, "charge_card", begin_h, 4200)
            .unwrap();

        let recovered = WorkflowExecution::recover_from_journal(1, &journal);
        assert_eq!(recovered.completed_steps.len(), 1);
        assert_eq!(recovered.completed_steps[0].0, "charge_card");
        assert_eq!(recovered.completed_steps[0].1, 4200);
    }

    #[test]
    fn workflow_recovery_pairs_names_and_ignores_in_progress() {
        let mut journal = Journal::new();
        let mut wf = WorkflowExecution::new(1);
        let h1 = wf.step_begin(&mut journal, "charge_card").unwrap();
        wf.step_end(&mut journal, "charge_card", h1, 4200).unwrap();
        let _h2 = wf.step_begin(&mut journal, "refund").unwrap();
        let h3 = wf.step_begin(&mut journal, "notify").unwrap();
        wf.step_end(&mut journal, "notify", h3, 99).unwrap();

        let recovered = WorkflowExecution::recover_from_journal(1, &journal);
        assert_eq!(recovered.step_counter, 3);
        assert_eq!(recovered.completed_steps.len(), 2);
        assert_eq!(recovered.completed_steps[0].0, "charge_card");
        assert_eq!(recovered.completed_steps[1].0, "notify");
        assert!(
            !recovered
                .completed_steps
                .iter()
                .any(|(name, _)| name == "refund")
        );
    }

    #[test]
    fn plan_rejects_duplicate_steps() {
        let plan = WorkflowPlan::plan(vec!["a".into(), "b".into(), "a".into()]);
        assert!(matches!(
            plan.unwrap_err(),
            FlowError::DuplicateStep(name) if name == "a"
        ));

        let plan = WorkflowPlan::plan(vec!["a".into(), "b".into()]).unwrap();
        assert_eq!(plan.steps(), &["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn resume_without_plan_errors() {
        let mut journal = Journal::new();
        let mut wf = WorkflowExecution::new(1);
        assert!(matches!(
            wf.resume(&mut journal, |_| Ok(0)),
            Err(FlowError::NoPlan)
        ));
    }

    #[test]
    fn resume_fresh_plan_is_idempotent() {
        let mut journal = Journal::new();
        let mut wf = WorkflowExecution::new(1);
        wf.set_plan(WorkflowPlan::plan(vec!["charge".into(), "notify".into()]).unwrap());

        // Deterministic effect: result equals the step-name length.
        let first = wf
            .resume(&mut journal, |name| Ok(name.len() as u64))
            .unwrap();
        assert_eq!(
            first,
            vec![
                StepOutcome {
                    name: "charge".into(),
                    status: ResumeStatus::Executed,
                    result: 6,
                },
                StepOutcome {
                    name: "notify".into(),
                    status: ResumeStatus::Executed,
                    result: 6,
                },
            ]
        );

        // Second resume re-runs nothing and reports the recorded results.
        let second = wf.resume(&mut journal, |_| {
            Err(FlowError::DuplicateStep("exec must not run".into()))
        });
        assert_eq!(
            second.unwrap(),
            vec![
                StepOutcome {
                    name: "charge".into(),
                    status: ResumeStatus::Skipped,
                    result: 6,
                },
                StepOutcome {
                    name: "notify".into(),
                    status: ResumeStatus::Skipped,
                    result: 6,
                },
            ]
        );
    }

    #[test]
    fn resume_after_crash_between_steps_reruns_in_progress() {
        // Journal prefix left by a crash between steps 2 and 3:
        // begin1+end1, begin2 with no end2, nothing for step 3.
        let mut journal = Journal::new();
        let mut crashed = WorkflowExecution::new(1);
        let h1 = crashed.step_begin(&mut journal, "s1").unwrap();
        crashed.step_end(&mut journal, "s1", h1, 10).unwrap();
        let _h2 = crashed.step_begin(&mut journal, "s2").unwrap();

        let mut wf = WorkflowExecution::recover_from_journal(1, &journal);
        assert_eq!(wf.completed_steps.len(), 1);
        wf.set_plan(WorkflowPlan::plan(vec!["s1".into(), "s2".into(), "s3".into()]).unwrap());

        let mut exec_calls: Vec<String> = Vec::new();
        let outcomes = wf
            .resume(&mut journal, |name| {
                exec_calls.push(name.to_string());
                Ok(100 + name.len() as u64)
            })
            .unwrap();

        assert_eq!(
            outcomes,
            vec![
                StepOutcome {
                    name: "s1".into(),
                    status: ResumeStatus::Skipped,
                    result: 10,
                },
                StepOutcome {
                    name: "s2".into(),
                    status: ResumeStatus::Rerun,
                    result: 102,
                },
                StepOutcome {
                    name: "s3".into(),
                    status: ResumeStatus::Executed,
                    result: 102,
                },
            ]
        );
        assert_eq!(exec_calls, vec!["s2".to_string(), "s3".to_string()]);
        // The rerun pairs its end against the pre-crash begin; no duplicate
        // begin lands for s2.
        let s2_begins = journal
            .entries()
            .filter(|entry| {
                entry.data.actor == 1
                    && entry.data.kind == EntryKind::StepBegin
                    && matches!(&entry.data.payload, Payload::Text(name) if name == "s2")
            })
            .count();
        assert_eq!(s2_begins, 1);

        // Full idempotence after recovery: every step skips with the same
        // results.
        let again = wf.resume(&mut journal, |_| {
            Err(FlowError::DuplicateStep("exec must not run".into()))
        });
        assert_eq!(
            again.unwrap(),
            vec![
                StepOutcome {
                    name: "s1".into(),
                    status: ResumeStatus::Skipped,
                    result: 10,
                },
                StepOutcome {
                    name: "s2".into(),
                    status: ResumeStatus::Skipped,
                    result: 102,
                },
                StepOutcome {
                    name: "s3".into(),
                    status: ResumeStatus::Skipped,
                    result: 102,
                },
            ]
        );
    }

    /// Count one actor's step-begin entries carrying `name` as their text
    /// payload; used to pin exact journal shapes.
    fn count_begins(journal: &Journal, name: &str) -> usize {
        journal
            .entries()
            .filter(|entry| {
                entry.data.actor == 1
                    && entry.data.kind == EntryKind::StepBegin
                    && matches!(&entry.data.payload, Payload::Text(text) if text == name)
            })
            .count()
    }

    /// Count one actor's step-end entries paired against `begin`.
    ///
    /// End entries carry the result as a number payload, so pairing goes
    /// through the recorded parent hash, never the text name.
    fn count_ends_paired(journal: &Journal, begin: &[u8; 32]) -> usize {
        journal
            .entries()
            .filter(|entry| {
                entry.data.actor == 1
                    && entry.data.kind == EntryKind::StepEnd
                    && entry.data.parents.first() == Some(begin)
            })
            .count()
    }

    #[test]
    fn resume_exec_failure_propagates_typed_error_and_keeps_crash_evidence() {
        let mut journal = Journal::new();
        let mut wf = WorkflowExecution::new(1);
        wf.set_plan(WorkflowPlan::plan(vec!["s1".into(), "boom".into(), "s3".into()]).unwrap());

        // The second step's effect fails with a typed error; the resume
        // must propagate exactly that error instead of swallowing it.
        let error = wf
            .resume(&mut journal, |name| {
                if name == "boom" {
                    Err(FlowError::DuplicateStep("boom".into()))
                } else {
                    Ok(100 + name.len() as u64)
                }
            })
            .expect_err("the exec error must propagate");
        assert!(
            matches!(error, FlowError::DuplicateStep(ref name) if name == "boom"),
            "{error}"
        );

        // Partial-state contract: s1 committed completely; the failed step
        // left exactly one unpaired begin (the crash evidence the next
        // resume uses); the unstarted s3 left nothing.
        assert_eq!(count_begins(&journal, "s1"), 1);
        assert_eq!(count_begins(&journal, "boom"), 1);
        assert_eq!(count_begins(&journal, "s3"), 0);
        let s1_begin = journal
            .entries()
            .find(|entry| {
                entry.data.actor == 1
                    && entry.data.kind == EntryKind::StepBegin
                    && matches!(&entry.data.payload, Payload::Text(text) if text == "s1")
            })
            .expect("s1 begin must exist")
            .id;
        let boom_begin = journal
            .entries()
            .find(|entry| {
                entry.data.actor == 1
                    && entry.data.kind == EntryKind::StepBegin
                    && matches!(&entry.data.payload, Payload::Text(text) if text == "boom")
            })
            .expect("boom begin must exist")
            .id;
        assert_eq!(count_ends_paired(&journal, &s1_begin), 1);
        assert_eq!(count_ends_paired(&journal, &boom_begin), 0);
        // In-memory state mirrors the journal: only s1 completed.
        assert_eq!(wf.completed_steps, vec![("s1".to_string(), 102)]);

        // Recovery sees the unpaired begin as an in-progress step.
        let recovered = WorkflowExecution::recover_from_journal(1, &journal);
        assert_eq!(recovered.step_counter, 2);
        assert_eq!(recovered.completed_steps, vec![("s1".to_string(), 102)]);

        // A later resume re-executes only the failed step and commits the
        // remainder; the completed s1 is skipped with its recorded result.
        let outcomes = wf
            .resume(&mut journal, |name| Ok(200 + name.len() as u64))
            .unwrap();
        assert_eq!(
            outcomes,
            vec![
                StepOutcome {
                    name: "s1".into(),
                    status: ResumeStatus::Skipped,
                    result: 102,
                },
                StepOutcome {
                    name: "boom".into(),
                    status: ResumeStatus::Rerun,
                    result: 204,
                },
                StepOutcome {
                    name: "s3".into(),
                    status: ResumeStatus::Executed,
                    result: 202,
                },
            ]
        );
        assert_eq!(count_begins(&journal, "boom"), 1);
        assert_eq!(count_ends_paired(&journal, &boom_begin), 1);
    }

    #[test]
    fn step_end_rejects_unknown_parent_without_partial_state() {
        let mut journal = Journal::new();
        let mut wf = WorkflowExecution::new(1);
        let begin = wf.step_begin(&mut journal, "s1").unwrap();

        // An end joined to a begin the journal does not hold is a typed
        // journal error, never a silent append.
        let bogus = [0x42u8; 32];
        let error = wf
            .step_end(&mut journal, "s1", bogus, 7)
            .expect_err("unknown begin hash must be rejected");
        assert!(
            matches!(error, ledger_journal::JournalError::MissingParent(h) if h == bogus),
            "{error}"
        );

        // No partial state: neither the journal nor the in-memory
        // completed list carries the failed end.
        assert_eq!(journal.len(), 1, "only the begin may be journaled");
        assert_eq!(wf.completed_steps, Vec::new());

        // The same end against the real begin commits atomically.
        let end = wf.step_end(&mut journal, "s1", begin, 7).unwrap();
        assert_ne!(end, bogus);
        assert_eq!(journal.len(), 2);
        assert_eq!(wf.completed_steps, vec![("s1".to_string(), 7)]);
        let recovered = WorkflowExecution::recover_from_journal(1, &journal);
        assert_eq!(recovered.completed_steps, vec![("s1".to_string(), 7)]);
    }

    #[test]
    fn recovery_ignores_non_text_begin_and_unpaired_end() {
        let mut journal = Journal::new();
        // Non-text begin must not produce a "step" fallback entry.
        let non_text_begin = journal
            .append(EntryKind::StepBegin, 1, [], Payload::Number(99))
            .unwrap();
        let _paired_end = journal
            .append(EntryKind::StepEnd, 1, [non_text_begin], Payload::Number(1))
            .unwrap();
        // Orphan end with a parent that exists but is not a recognized begin
        // must be ignored. The parent is a real journal entry (journal append
        // rejects fabricated hashes), it simply is not a step begin.
        let real_non_begin = journal
            .append(EntryKind::Send, 1, [], Payload::Text("marker".into()))
            .unwrap();
        let _orphan_end = journal
            .append(EntryKind::StepEnd, 1, [real_non_begin], Payload::Number(2))
            .unwrap();
        let recovered = WorkflowExecution::recover_from_journal(1, &journal);
        assert_eq!(recovered.step_counter, 0);
        assert!(recovered.completed_steps.is_empty());
        // Valid text begin is still recovered.
        let mut wf = WorkflowExecution::new(1);
        let begin = wf.step_begin(&mut journal, "ok").unwrap();
        wf.step_end(&mut journal, "ok", begin, 5).unwrap();
        let recovered2 = WorkflowExecution::recover_from_journal(1, &journal);
        assert_eq!(recovered2.completed_steps, vec![("ok".to_string(), 5)]);
        assert_eq!(recovered2.step_counter, 1);
    }
}
