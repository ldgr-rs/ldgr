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
            // Regenerated after the sim outcome schema bound its real
            // domain digest (ldgr.sim.outcome.v1) instead of zeroed bytes.
            root: [
                0x15, 0x23, 0x09, 0x3c, 0xea, 0x59, 0x86, 0xe3, 0x5c, 0x6c, 0x5e, 0xfe, 0xb5, 0x13,
                0x20, 0xa2, 0x99, 0x57, 0x91, 0xe5, 0x0a, 0xaa, 0x38, 0xb7, 0xbc, 0x01, 0xfa, 0xf0,
                0x96, 0xcf, 0x26, 0x52,
            ],
            steps: 10,
            decisions: vec![0, 1, 0, 0, 2, 2, 2, 0, 0, 0],
        },
        Case {
            seed: 1,
            root: [
                0xa3, 0xbb, 0xd3, 0x5b, 0x8d, 0x8f, 0x0b, 0xb3, 0x28, 0x2a, 0x3f, 0x59, 0x99, 0xf4,
                0x98, 0xa1, 0x16, 0x81, 0xdf, 0xd2, 0x5c, 0xa9, 0x1a, 0x7b, 0x89, 0x1c, 0xa9, 0x2c,
                0x43, 0x7e, 0x21, 0x64,
            ],
            steps: 11,
            decisions: vec![1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0],
        },
        Case {
            seed: 7,
            root: [
                0x07, 0x30, 0xd9, 0xd1, 0x40, 0xcc, 0x5d, 0xc8, 0x98, 0x02, 0x35, 0x29, 0xed, 0x37,
                0x9e, 0x2f, 0x16, 0x54, 0xc8, 0xd6, 0x80, 0x63, 0x9e, 0x18, 0x23, 0x9d, 0xa3, 0xc8,
                0xc2, 0x8a, 0x38, 0x05,
            ],
            steps: 11,
            decisions: vec![2, 1, 0, 0, 2, 0, 0, 2, 0, 0, 0],
        },
        Case {
            seed: 42,
            root: [
                0x53, 0x42, 0x41, 0x10, 0xbe, 0xd0, 0x1b, 0xe4, 0xb6, 0xa4, 0xc6, 0xf8, 0x3f, 0x49,
                0x93, 0xa2, 0xad, 0x49, 0x1a, 0xbb, 0x9d, 0x1b, 0x24, 0x2d, 0xf8, 0x83, 0x4c, 0xa1,
                0x97, 0xbd, 0x46, 0xa6,
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
