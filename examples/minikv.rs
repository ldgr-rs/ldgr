//! Run the mini-KV stale-read campaign.

use ldgr::config::{Policy, RunConfig};
use ldgr::explorer::Workload;
use ldgr::explorer::search;
use ldgr::ldfi::suggest_cut;
use ldgr::oracle::LinearizabilityOracle;
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
}

fn main() {
    let config = RunConfig {
        seed: [0; 32],
        policy: Policy::Random,
        max_steps: 256,
    };
    let workload = MiniKv;
    let oracle = LinearizabilityOracle;

    match search(&workload, &oracle, config, 256) {
        Ok(Some(finding)) => {
            println!("violation: {}", finding.verdict.reason);
            println!("seed: {:02x?}", finding.seed);
            println!("journal root: {:02x?}", finding.run.journal.root_hash());
            println!("steps: {}", finding.run.steps);
            for cut in suggest_cut(&finding.run.journal, &finding.verdict) {
                println!(
                    "fault candidate {:02x?}, cost {}",
                    &cut.event[..4],
                    cut.cost
                );
            }
        }
        Ok(None) => println!("no violation found"),
        Err(error) => eprintln!("simulation failed: {error}"),
    }
}
