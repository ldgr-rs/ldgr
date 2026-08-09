//! Run the mini-KV stale-read campaign.

use ldgr::config::{Policy, RunConfig};
use ldgr::explorer::{Workload, replay_with_faults, search};
use ldgr::format::{EntryKind, Payload};
use ldgr::ldfi::suggest_cut;
use ldgr::oracle::{HistoryOperation, HistoryOracle, KeyValueSpec, Oracle};
use ldgr::runtime::Instruction;

#[derive(Debug, Clone, Copy)]
struct MiniKv;

impl Workload for MiniKv {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        vec![
            vec![
                Instruction::Send { to: 1, payload: 42 },
                Instruction::Send {
                    to: 2,
                    payload: 100,
                },
                Instruction::Done,
            ],
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
        ]
    }

    fn history(&self, run: &ldgr::runtime::RunResult) -> Vec<HistoryOperation> {
        run.journal
            .entries()
            .filter_map(|entry| match (&entry.data.kind, &entry.data.payload) {
                (EntryKind::Send, Payload::Pair { left: 1, right: 42 })
                    if entry.data.actor == 0 =>
                {
                    Some(HistoryOperation::Write {
                        key: "k".into(),
                        value: 42,
                        witness: entry.id,
                    })
                }
                (EntryKind::Outcome, Payload::Number(value)) if entry.data.actor == 2 => {
                    Some(HistoryOperation::Read {
                        key: "k".into(),
                        value: *value,
                        witness: entry.id,
                    })
                }
                _ => None,
            })
            .collect()
    }
}

fn main() {
    let config = RunConfig {
        seed: [0; 32],
        policy: Policy::Random,
        max_steps: 256,
        dropped_events: Vec::new(),
    };
    let workload = MiniKv;
    let oracle = HistoryOracle::new(&workload, KeyValueSpec::default());

    match search(&workload, &oracle, config, 256) {
        Ok(Some(finding)) => {
            println!("violation: {}", finding.verdict.reason);
            println!("seed: {:02x?}", finding.seed);
            println!("journal root: {:02x?}", finding.run.journal.root_hash());
            println!("steps: {}", finding.run.steps);
            for cut in suggest_cut(&finding.run.journal, &finding.verdict) {
                let replayed = replay_with_faults(
                    &workload,
                    finding.seed,
                    finding.run.decisions.clone(),
                    vec![cut.event],
                );
                let flips = replayed
                    .as_ref()
                    .map(|run| !oracle.check(run).violated)
                    .unwrap_or(false);
                println!(
                    "fault candidate {:02x?}, cost {}, flips: {flips}",
                    &cut.event[..4],
                    cut.cost
                );
            }
        }
        Ok(None) => println!("no violation found"),
        Err(error) => eprintln!("simulation failed: {error}"),
    }
}
