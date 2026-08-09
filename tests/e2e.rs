use ldgr::config::{Policy, RunConfig};
use ldgr::explorer::Workload;
use ldgr::explorer::replay;
use ldgr::explorer::search;
use ldgr::ldfi::suggest_cut;
use ldgr::minimizer::ddmin;
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

#[test]
fn mini_kv_finds_and_reproduces_stale_read() {
    let config = RunConfig {
        seed: [0; 32],
        policy: Policy::Random,
        max_steps: 256,
    };
    let finding = search(&MiniKv, &LinearizabilityOracle, config, 256)
        .unwrap()
        .expect("campaign should find planted race");
    assert!(finding.verdict.violated);
    assert!(!finding.verdict.witnesses.is_empty());
    assert!(!suggest_cut(&finding.run.journal, &finding.verdict).is_empty());
    let replayed = replay(&MiniKv, finding.seed, finding.run.decisions.clone()).unwrap();
    assert_eq!(
        finding.run.journal.root_hash(),
        replayed.journal.root_hash()
    );
}

#[test]
fn same_seed_produces_identical_journal_root() {
    let config = RunConfig {
        seed: [9; 32],
        policy: Policy::Pct {
            priority_changes: 2,
        },
        max_steps: 256,
    };
    let left = ldgr::runtime::Simulation::new(config.clone(), MiniKv.programs())
        .run()
        .unwrap();
    let right = ldgr::runtime::Simulation::new(config, MiniKv.programs())
        .run()
        .unwrap();
    assert_eq!(left.journal.root_hash(), right.journal.root_hash());
    assert_eq!(left.decisions, right.decisions);
}

#[test]
fn ddmin_keeps_the_two_required_schedule_markers() {
    let result = ddmin(&[1, 2, 3, 4, 5], |items| {
        items.contains(&2) && items.contains(&5)
    });
    assert_eq!(result, [2, 5]);
}
