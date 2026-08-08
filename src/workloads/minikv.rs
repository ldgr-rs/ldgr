//! Two-node replicated key-value workload with a planted stale-read race.

use crate::explorer::Workload;
use crate::runtime::Instruction;

/// Mini-KV workload.
#[derive(Debug, Default, Clone, Copy)]
pub struct MiniKv;

impl Workload for MiniKv {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        vec![
            // Client writes 42 to A, then asks B for a read. The two sends
            // are separate scheduling points so replication can race the read.
            vec![
                Instruction::Send { to: 1, payload: 42 },
                Instruction::Send {
                    to: 2,
                    payload: 100,
                },
                Instruction::Done,
            ],
            // A receives the write and asynchronously replicates it to B.
            vec![
                Instruction::Receive,
                Instruction::Send { to: 2, payload: 42 },
                Instruction::Done,
            ],
            // B returns 100 when it handles the read before replication.
            vec![
                Instruction::Receive,
                Instruction::Outcome,
                Instruction::Done,
            ],
        ]
    }
}
