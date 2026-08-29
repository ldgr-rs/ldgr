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
                0x5b, 0x9a, 0x43, 0x6e, 0x27, 0xb2, 0x29, 0x11, 0x78, 0x2b, 0xf9, 0xce, 0x25, 0xc6,
                0x53, 0x39, 0x9c, 0xc6, 0xf1, 0x3e, 0x35, 0x36, 0x59, 0x54, 0x84, 0xac, 0xb6, 0xee,
                0xc2, 0xe9, 0xf5, 0x8d,
            ],
            steps: 10,
            decisions: vec![0, 1, 0, 0, 2, 2, 2, 0, 0, 0],
        },
        Case {
            seed: 1,
            root: [
                0xc6, 0xce, 0xcf, 0xb3, 0x40, 0xdf, 0xf0, 0x33, 0x96, 0xfb, 0x3b, 0x39, 0xde, 0xac,
                0xaf, 0xf3, 0x50, 0x7f, 0xb5, 0xfb, 0x7d, 0x79, 0x64, 0x44, 0x16, 0x33, 0x51, 0x55,
                0xb7, 0xbc, 0xf1, 0xb0,
            ],
            steps: 11,
            decisions: vec![1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0],
        },
        Case {
            seed: 7,
            root: [
                0x43, 0x32, 0x86, 0xce, 0xbe, 0x99, 0x31, 0x89, 0x5b, 0x21, 0xeb, 0x15, 0xeb, 0xd6,
                0x68, 0x52, 0x5e, 0xd8, 0x0e, 0xdf, 0xf5, 0x08, 0x05, 0x62, 0x6e, 0x08, 0xfd, 0xff,
                0xf6, 0xbc, 0xa9, 0x5b,
            ],
            steps: 11,
            decisions: vec![2, 1, 0, 0, 2, 0, 0, 2, 0, 0, 0],
        },
        Case {
            seed: 42,
            root: [
                0x5a, 0x21, 0xba, 0x46, 0xc2, 0x7d, 0xe1, 0x41, 0xcb, 0x60, 0xa6, 0x2b, 0xca, 0xd6,
                0xcf, 0x4e, 0x6f, 0xe4, 0x16, 0x1f, 0x75, 0x29, 0x77, 0xbd, 0x38, 0xcf, 0xa8, 0xb6,
                0x78, 0x26, 0xb8, 0xf5,
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
