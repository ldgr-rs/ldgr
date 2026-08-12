//! Storage crash consistency workload modeling write-ahead log recovery.

use crate::oracle::HistoryOperation;
use crate::search::Workload;
use ledger_sim::{Instruction, RunResult};

/// Storage crash consistency workload testing durable fsync barriers.
#[derive(Debug, Clone, Copy, Default)]
pub struct StorageCrashWorkload;

impl Workload for StorageCrashWorkload {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        vec![vec![
            Instruction::FsWrite {
                path: "state.db".into(),
                value: 42,
            },
            Instruction::FsFsync,
            Instruction::FsWrite {
                path: "state.db".into(),
                value: 999,
            },
            Instruction::FsCrash,
            Instruction::FsRead {
                path: "state.db".into(),
            },
            Instruction::Outcome,
            Instruction::Done,
        ]]
    }

    fn history(&self, _run: &RunResult) -> Vec<HistoryOperation> {
        Vec::new()
    }
}
