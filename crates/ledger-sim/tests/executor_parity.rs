//! Byte-identical journal parity between the async executor and the
//! instruction VM's golden output.
//!
//! These goldens were captured from the instruction VM before the executor
//! rewiring. The executor must reproduce them exactly: identical journal root,
//! identical step count, and identical scheduler decision sequence. Any
//! divergence here is a determinism break and fails the build.

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
        .seed([seed_byte; 32])
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
            root: [
                0x54, 0x13, 0x07, 0xe1, 0xf3, 0x37, 0xf7, 0x74, 0xf3, 0xb0, 0x56, 0x8f, 0x6f, 0xf5,
                0x12, 0x44, 0x88, 0xcf, 0x1c, 0x70, 0x5b, 0x07, 0x33, 0xc5, 0x70, 0xc6, 0x97, 0xf9,
                0x36, 0x5f, 0x3c, 0xac,
            ],
            steps: 10,
            decisions: vec![0, 1, 0, 0, 2, 2, 2, 0, 0, 0],
        },
        Case {
            seed: 1,
            root: [
                0x10, 0xb1, 0x25, 0x03, 0x7d, 0x50, 0xad, 0xed, 0xa1, 0x3d, 0x0f, 0x5f, 0xc5, 0x01,
                0x80, 0x35, 0xc0, 0x60, 0x1b, 0xa5, 0xf6, 0xd6, 0xa7, 0xb3, 0x73, 0x5f, 0x47, 0x93,
                0x5a, 0x8d, 0xba, 0x2b,
            ],
            steps: 11,
            decisions: vec![1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0],
        },
        Case {
            seed: 7,
            root: [
                0xca, 0x00, 0x31, 0x01, 0x5c, 0x1b, 0x88, 0xcd, 0x10, 0xb4, 0x2b, 0xb2, 0x3b, 0xf8,
                0x85, 0xcc, 0x5c, 0x1b, 0xcb, 0x18, 0x66, 0x49, 0x0f, 0x8a, 0x6e, 0xe9, 0xd7, 0x7b,
                0x70, 0x0a, 0x1e, 0x00,
            ],
            steps: 11,
            decisions: vec![2, 1, 0, 0, 2, 0, 0, 2, 0, 0, 0],
        },
        Case {
            seed: 42,
            root: [
                0x93, 0x88, 0x3d, 0xde, 0x60, 0x81, 0xac, 0xe3, 0xe8, 0xbe, 0xc3, 0x8b, 0xd6, 0xc3,
                0x19, 0xeb, 0x08, 0xa7, 0x9e, 0x96, 0x10, 0xc8, 0x90, 0x60, 0x9c, 0xbd, 0xed, 0x9b,
                0x21, 0x75, 0x72, 0xfc,
            ],
            steps: 10,
            decisions: vec![0, 1, 0, 0, 2, 2, 1, 1, 0, 0],
        },
    ];

    for case in cases {
        let run = run(case.seed);
        assert_eq!(
            run.journal.root_hash(),
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
        .seed([3; 32])
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
        .seed([4; 32])
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
        .seed([4; 32])
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
        .seed([5; 32])
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
