//! Executor/VM parity: identical roots, steps, and decisions on goldens.

use ledger_sim::{Instruction, Policy, RunConfig, Simulation};

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

fn run(seed_byte: u8) -> ledger_sim::RunResult {
    let config = RunConfig::builder()
        .seed(ledger_format::EntryHash([seed_byte; 32]))
        .policy(Policy::Random)
        .max_steps(256)
        .build();
    Simulation::new(config, mini_kv_programs()).run().unwrap()
}

#[test]
fn executor_matches_golden_roots_at_all_seeds() {
    struct Case {
        seed: u8,
        root: [u8; 32],
        steps: usize,
        decisions: Vec<usize>,
    }

    let cases = [
        Case {
            seed: 0,
            // Regenerated after EntryHash wire framing (34-byte multihash):
            // journal roots change because entry bytes carry framed hashes.
            root: [
                0xbc, 0x5e, 0x41, 0x5c, 0xae, 0x7c, 0xf7, 0x04, 0x0d, 0xde, 0x6a, 0x97, 0x87, 0x57,
                0x36, 0x28, 0x14, 0x5d, 0x98, 0x31, 0x05, 0x04, 0xc7, 0x4a, 0xc8, 0x52, 0xfa, 0xbe,
                0x0c, 0xf8, 0x47, 0x51,
            ],
            steps: 10,
            decisions: vec![0, 1, 0, 0, 2, 2, 2, 0, 0, 0],
        },
        Case {
            seed: 1,
            root: [
                0xba, 0xec, 0x3f, 0xbf, 0xbc, 0x5b, 0x05, 0xba, 0x68, 0x57, 0x55, 0xca, 0x24, 0x8c,
                0x5b, 0x24, 0x4e, 0x09, 0x05, 0x30, 0xb7, 0x61, 0x45, 0xce, 0x7b, 0xf8, 0xac, 0xd6,
                0x0b, 0x6c, 0x0f, 0xb2,
            ],
            steps: 11,
            decisions: vec![1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0],
        },
        Case {
            seed: 7,
            root: [
                0x49, 0x55, 0x44, 0x95, 0xf5, 0x96, 0x22, 0xa1, 0x9b, 0xb4, 0xf7, 0x74, 0xe4, 0x9e,
                0x96, 0x31, 0x0e, 0x92, 0x6e, 0xaf, 0xdc, 0x38, 0x63, 0xf4, 0xd7, 0x5a, 0x16, 0x36,
                0x6b, 0xdd, 0x3a, 0xb6,
            ],
            steps: 11,
            decisions: vec![2, 1, 0, 0, 2, 0, 0, 2, 0, 0, 0],
        },
        Case {
            seed: 42,
            root: [
                0x90, 0x82, 0xbd, 0xd0, 0x9d, 0xf6, 0x51, 0xd6, 0x7c, 0xab, 0x54, 0x17, 0xae, 0x02,
                0x5e, 0x4e, 0x44, 0xe8, 0x22, 0x30, 0x96, 0xce, 0x6f, 0x6f, 0x85, 0x16, 0xec, 0x43,
                0xad, 0x32, 0x41, 0x55,
            ],
            steps: 10,
            decisions: vec![0, 1, 0, 0, 2, 2, 1, 1, 0, 0],
        },
    ];

    for case in cases {
        let run = run(case.seed);
        assert_eq!(
            run.journal.root_hash().0,
            case.root,
            "journal root diverged for seed {}",
            case.seed
        );
        assert_eq!(
            run.steps, case.steps,
            "step count diverged for seed {}",
            case.seed
        );
        assert_eq!(
            run.decisions, case.decisions,
            "decision sequence diverged for seed {}",
            case.seed
        );
        assert!(
            run.monitor_issues.is_empty(),
            "monitor issues for seed {}: {:?}",
            case.seed,
            run.monitor_issues
        );
    }
}

#[test]
fn timed_delivery_jumps_time_and_delivers() {
    let config = RunConfig::builder()
        .seed(ledger_format::EntryHash([3; 32]))
        .policy(Policy::Random)
        .max_steps(256)
        .build();
    let programs = vec![
        vec![
            Instruction::SendTimed {
                to: 1,
                payload: 42,
                delay: 5,
            },
            Instruction::Done,
        ],
        vec![
            Instruction::Receive,
            Instruction::Outcome,
            Instruction::Done,
        ],
    ];
    let run = Simulation::new(config, programs).run().unwrap();
    let kinds = run
        .journal
        .entries()
        .map(|entry| entry.data.kind)
        .collect::<Vec<_>>();
    assert!(
        kinds
            .iter()
            .any(|kind| matches!(kind, ledger_format::EntryKind::Send))
    );
    assert!(
        kinds
            .iter()
            .any(|kind| matches!(kind, ledger_format::EntryKind::Wake))
    );
    assert!(
        kinds
            .iter()
            .any(|kind| matches!(kind, ledger_format::EntryKind::Recv))
    );
    assert!(run.monitor_issues.is_empty());
}

#[test]
fn drop_fault_journals_against_send() {
    // Capture the Send entry id from a clean run, then drop it on replay.
    let config = RunConfig::builder()
        .seed(ledger_format::EntryHash([4; 32]))
        .policy(Policy::Random)
        .max_steps(256)
        .build();
    let programs = vec![
        vec![Instruction::Send { to: 1, payload: 42 }, Instruction::Done],
        vec![Instruction::Receive, Instruction::Done],
    ];
    let clean = Simulation::new(config.clone(), programs.clone())
        .run()
        .unwrap();
    let send_id = clean
        .journal
        .entries()
        .find(|entry| matches!(entry.data.kind, ledger_format::EntryKind::Send))
        .map(|entry| entry.id)
        .expect("a Send entry must exist");
    let dropped = RunConfig::builder()
        .seed(ledger_format::EntryHash([4; 32]))
        .policy(Policy::Random)
        .max_steps(256)
        .dropped_events(vec![send_id])
        .build();
    let run = Simulation::new(dropped, programs).run().unwrap();
    assert!(
        run.journal.entries().any(|entry| {
            matches!(
                &entry.data.payload,
                ledger_format::EntryPayload::Fault(ledger_format::FaultPayload::DropMessage { .. })
            )
        }),
        "a Drop fault must be journaled"
    );
    assert!(run.monitor_issues.is_empty());
}

#[test]
fn fs_crash_journals_crash_state_fault() {
    let config = RunConfig::builder()
        .seed(ledger_format::EntryHash([5; 32]))
        .policy(Policy::Random)
        .max_steps(256)
        .build();
    let programs = vec![vec![
        Instruction::FsWrite {
            path: "k".into(),
            value: 1,
        },
        Instruction::FsFsync,
        Instruction::FsCrash,
        Instruction::Done,
    ]];
    let run = Simulation::new(config, programs).run().unwrap();
    assert!(
        run.journal.entries().any(|entry| {
            matches!(
                &entry.data.payload,
                ledger_format::EntryPayload::Fault(ledger_format::FaultPayload::CrashActor { .. })
            )
        }),
        "a CrashState fault must be journaled"
    );
    assert!(run.monitor_issues.is_empty());
}
