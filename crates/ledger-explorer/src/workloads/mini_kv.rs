//! Mini-KV stale-read campaign workload.

use crate::oracle::HistoryOperation;
use crate::pbt::gen_id;
use crate::search::Workload;
use ledger_format::{EntryKind, EntryPayload};
use ledger_sim::{Instruction, RunResult};

/// Mini-KV workload with client write and asynchronous node replication race.
#[derive(Debug, Clone, Copy, Default)]
pub struct MiniKvWorkload;

/// Input-axis generator name for the Mini-KV producer.
pub const MINI_KV_GENERATOR: &str = "mini-kv";

impl Workload for MiniKvWorkload {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        vec![
            // Node 0 (Client/Leader).
            vec![
                Instruction::Send { to: 1, payload: 42 },
                Instruction::Send {
                    to: 2,
                    payload: 100,
                },
                Instruction::Done,
            ],
            // Node 1 (Storage Master).
            vec![
                Instruction::Receive,
                Instruction::Send { to: 2, payload: 42 },
                Instruction::Done,
            ],
            // Node 2 (Storage Replica).
            vec![
                Instruction::Receive,
                Instruction::Outcome,
                Instruction::Done,
            ],
        ]
    }

    fn history(&self, run: &RunResult) -> Vec<HistoryOperation> {
        run.journal
            .entries()
            .filter_map(|entry| match (&entry.data.kind, &entry.data.payload) {
                (EntryKind::Send, EntryPayload::Send(frame)) if frame.to == 1 => {
                    let value = u64::from_le_bytes(
                        frame.original_content[..8]
                            .try_into()
                            .expect("8-byte payload"),
                    );
                    if entry.data.actor == 0 && value == 42 {
                        Some(HistoryOperation::Write {
                            key: "k".into(),
                            value: 42,
                            witness: entry.id,
                        })
                    } else {
                        None
                    }
                }
                (EntryKind::Outcome, EntryPayload::Outcome(outcome)) if entry.data.actor == 2 => {
                    let value = match outcome.value {
                        ledger_format::CanonicalValue::Unsigned(v) => v,
                        _ => return None,
                    };
                    Some(HistoryOperation::Read {
                        key: "k".into(),
                        value,
                        witness: entry.id,
                    })
                }
                _ => None,
            })
            .collect()
    }

    fn with_inputs(&self, inputs: &[u64]) -> Box<dyn Workload> {
        let generator = gen_id(MINI_KV_GENERATOR);
        let mut producer = Vec::with_capacity(inputs.len() + 3);
        for (index, value) in inputs.iter().enumerate() {
            producer.push(Instruction::Input {
                generator,
                replay: index as u64,
                value: *value,
            });
        }
        producer.push(Instruction::Send { to: 1, payload: 42 });
        producer.push(Instruction::Send {
            to: 2,
            payload: 100,
        });
        producer.push(Instruction::Done);
        let programs = vec![
            producer,
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
        ];
        Box::new(crate::pbt::InputsWorkload::new(programs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_sim::{Policy, RunConfig, Simulation};

    #[test]
    fn with_inputs_journals_input_steps_with_real_keys() {
        let workload = MiniKvWorkload.with_inputs(&[7, 8, 9]);
        let config = RunConfig::builder()
            .seed([6; 32])
            .policy(Policy::Random)
            .max_steps(256)
            .build();
        let run = Simulation::new(config, workload.programs()).run().unwrap();
        let inputs = run
            .journal
            .entries()
            .filter_map(|entry| match &entry.data.payload {
                EntryPayload::InputStep(step) => {
                    Some((step.generator, step.replay, step.value.clone()))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let expected_generator = gen_id(MINI_KV_GENERATOR);
        let expected = vec![
            (
                expected_generator,
                0u64,
                ledger_format::CanonicalValue::Unsigned(7),
            ),
            (
                expected_generator,
                1u64,
                ledger_format::CanonicalValue::Unsigned(8),
            ),
            (
                expected_generator,
                2u64,
                ledger_format::CanonicalValue::Unsigned(9),
            ),
        ];
        assert_eq!(inputs, expected);
        assert!(run.monitor_issues.is_empty());
    }
}
