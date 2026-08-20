#![deny(unsafe_code)]
#![allow(missing_docs)]

//! Durable execution step logging built on the Ledger causal journal.

pub mod workflow;
pub use workflow::{StepStatus, WorkflowExecution};

#[cfg(test)]
mod tests {
    use super::*;
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
}
