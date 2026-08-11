//! Determinism self-check: 10^4 consecutive runs of the same seed must produce
//! byte-identical journal roots.
//!
//! Every CI run of a sim test is already a determinism check; this test makes
//! the bound explicit and large. A single divergence anywhere in the executor,
//! scheduler, seed tree, or journaling breaks the root equality.

use ledger_sim::{Instruction, Policy, RunConfig, Simulation};

/// The reference mini-kv stale-read race, the same workload the CLI campaigns.
fn mini_kv_programs() -> Vec<Vec<Instruction>> {
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

#[test]
fn ten_thousand_same_seed_runs_produce_identical_journal_root() {
    const RUNS: u32 = 10_000;
    let config = RunConfig {
        seed: [7; 32],
        policy: Policy::Random,
        max_steps: 256,
        ..RunConfig::default()
    };
    let programs = mini_kv_programs();

    let baseline = Simulation::new(config.clone(), programs.clone())
        .run()
        .expect("baseline run must succeed")
        .journal
        .root_hash();

    for _ in 0..RUNS {
        let run = Simulation::new(config.clone(), programs.clone())
            .run()
            .expect("run must succeed");
        assert_eq!(
            run.journal.root_hash(),
            baseline,
            "journal root drifted across identical seeds"
        );
        assert!(
            run.monitor_issues.is_empty(),
            "monitor issues: {:?}",
            run.monitor_issues
        );
    }
}

#[test]
fn self_check_covers_each_scheduling_policy() {
    // The self-check must hold under every policy, not just random.
    let policies = [
        Policy::Random,
        Policy::Pct {
            priority_changes: 3,
        },
        Policy::Bandit {
            exploration_constant: 1.414,
            pct_mix: 0.1,
        },
    ];
    let programs = mini_kv_programs();
    for policy in policies {
        let config = RunConfig {
            seed: [9; 32],
            policy,
            max_steps: 256,
            ..RunConfig::default()
        };
        let a = Simulation::new(config.clone(), programs.clone())
            .run()
            .unwrap();
        let b = Simulation::new(config.clone(), programs.clone())
            .run()
            .unwrap();
        assert_eq!(
            a.journal.root_hash(),
            b.journal.root_hash(),
            "self-check diverged under {policy:?}"
        );
        assert_eq!(
            a.decisions, b.decisions,
            "decisions diverged under {policy:?}"
        );
    }
}
