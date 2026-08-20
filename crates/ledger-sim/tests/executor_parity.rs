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
                0xec, 0xe0, 0x0e, 0xd2, 0x12, 0x23, 0x61, 0x99, 0x0b, 0x99, 0x2d, 0x9c, 0xa9, 0x66,
                0x3e, 0x67, 0xf4, 0x03, 0xe2, 0x92, 0x0e, 0xd2, 0x84, 0x34, 0xe4, 0xa2, 0x3e, 0x1d,
                0xda, 0x34, 0x88, 0x79,
            ],
            steps: 10,
            decisions: vec![0, 1, 0, 0, 2, 2, 2, 0, 0, 0],
        },
        Case {
            seed: 1,
            root: [
                0xb9, 0xc7, 0xaa, 0xb5, 0x51, 0x0d, 0xcb, 0x0c, 0x4e, 0x2a, 0x9c, 0x30, 0x4e, 0xed,
                0xc5, 0x30, 0x79, 0x90, 0xf6, 0x1b, 0x15, 0x46, 0xbd, 0x49, 0xf1, 0x13, 0xcc, 0x99,
                0x25, 0xbf, 0xa8, 0xad,
            ],
            steps: 11,
            decisions: vec![1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0],
        },
        Case {
            seed: 7,
            root: [
                0x6e, 0x39, 0x17, 0x21, 0xb9, 0x43, 0xf6, 0x19, 0x13, 0xad, 0x15, 0x33, 0xef, 0xf5,
                0x50, 0x80, 0x2d, 0xfe, 0x25, 0x69, 0x95, 0x51, 0xb1, 0x72, 0x49, 0x9d, 0x51, 0x45,
                0x77, 0x21, 0x8b, 0xcb,
            ],
            steps: 11,
            decisions: vec![2, 1, 0, 0, 2, 0, 0, 2, 0, 0, 0],
        },
        Case {
            seed: 42,
            root: [
                0x88, 0x60, 0xaf, 0x44, 0x80, 0x00, 0x97, 0xed, 0x4c, 0xb5, 0xd1, 0x55, 0x78, 0x94,
                0xf7, 0x3e, 0xd9, 0x09, 0x51, 0x75, 0xc7, 0x4d, 0x93, 0x15, 0x43, 0x1c, 0x8b, 0x1f,
                0x60, 0xe9, 0x1d, 0xaa,
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
    let kinds = run
        .journal
        .entries()
        .map(|entry| entry.data.kind)
        .collect::<Vec<_>>();
    assert!(
        kinds.iter().any(|kind| matches!(
            kind,
            ledger_format::EntryKind::Fault {
                fault: ledger_format::FaultSpec::Drop
            }
        )),
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
    let kinds = run
        .journal
        .entries()
        .map(|entry| entry.data.kind)
        .collect::<Vec<_>>();
    assert!(
        kinds.iter().any(|kind| matches!(
            kind,
            ledger_format::EntryKind::Fault {
                fault: ledger_format::FaultSpec::CrashState(0)
            }
        )),
        "a CrashState fault must be journaled"
    );
    assert!(run.monitor_issues.is_empty());
}
