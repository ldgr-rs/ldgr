//! Two-Phase Commit (2PC) distributed transaction workload.

use crate::oracle::HistoryOperation;
use crate::search::Workload;
use ledger_sim::{Instruction, RunResult};

/// Two-Phase Commit transaction workload modeling atomic commit or abort under faults.
#[derive(Debug, Clone, Copy, Default)]
pub struct TwoPhaseCommitWorkload;

impl Workload for TwoPhaseCommitWorkload {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        vec![
            // Node 0: Transaction Coordinator.
            vec![
                // Phase 1: Send Prepare (tag 10) to participants 1 and 2.
                Instruction::Send { to: 1, payload: 10 },
                Instruction::Send { to: 2, payload: 10 },
                Instruction::Receive,
                Instruction::Receive,
                Instruction::Assert(true),
                // Phase 2: Send Commit (tag 20) to both participants.
                Instruction::Send { to: 1, payload: 20 },
                Instruction::Send { to: 2, payload: 20 },
                Instruction::Outcome,
                Instruction::Done,
            ],
            // Node 1: Participant A, votes commit.
            vec![
                Instruction::Receive,
                Instruction::FsWrite {
                    path: "p1.wal".into(),
                    value: 1,
                },
                Instruction::FsFsync,
                Instruction::Send { to: 0, payload: 1 },
                Instruction::Receive,
                Instruction::Outcome,
                Instruction::Done,
            ],
            // Node 2: Participant B, votes commit.
            vec![
                Instruction::Receive,
                Instruction::FsWrite {
                    path: "p2.wal".into(),
                    value: 1,
                },
                Instruction::FsFsync,
                Instruction::Send { to: 0, payload: 1 },
                Instruction::Receive,
                Instruction::Outcome,
                Instruction::Done,
            ],
        ]
    }

    fn history(&self, _run: &RunResult) -> Vec<HistoryOperation> {
        Vec::new()
    }
}
