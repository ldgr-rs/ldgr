//! Journaling-FS crash model wired through the executor's crash path.
//!
//! The crash model is selected per run through `RunConfig::fs_journaling`.
//! With a mode configured the executor's crash path replays the write-ahead
//! journal before dropping unsynced state; without one it keeps the black-box
//! `DropAllUnsynced` operator byte-identical to the historical path.
#![cfg(feature = "sim-fs-journaling")]

use ledger_format::{CanonicalValue, EntryKind, EntryPayload, OutcomePayload};
use ledger_sim::{Instruction, JournalingMode, Policy, RunConfig, Simulation};

/// Run a write (optionally fsynced), crash, then read the value back into the
/// task register and journal it as the outcome.
fn post_crash_value(
    mode: Option<JournalingMode>,
    write: bool,
    fsync: bool,
    seed: ledger_format::EntryHash,
) -> Option<u64> {
    let mut program = Vec::new();
    if write {
        program.push(Instruction::FsWrite {
            path: "k".into(),
            value: 7,
        });
    }
    if fsync {
        program.push(Instruction::FsFsync);
    }
    program.push(Instruction::FsCrash);
    program.push(Instruction::FsRead { path: "k".into() });
    program.push(Instruction::Outcome);
    program.push(Instruction::Done);
    let config = RunConfig::builder()
        .seed(seed)
        .policy(Policy::Random)
        .max_steps(256)
        .fs_journaling(mode)
        .build();
    let run = Simulation::new(config, vec![program]).run().unwrap();
    run.journal
        .entries()
        .find_map(|entry| match (&entry.data.kind, &entry.data.payload) {
            (
                EntryKind::Outcome,
                EntryPayload::Outcome(OutcomePayload {
                    value: CanonicalValue::Unsigned(value),
                    ..
                }),
            ) => Some(*value),
            _ => None,
        })
}

/// A configured journaling crash is fsync-bounded and distinct from the
/// black-box drop: in Data mode only fsynced writes survive, and in Writeback
/// mode even an unfsynced write survives while the black-box default drops it.
#[test]
fn journaled_crash_is_fsync_bounded_and_distinct_from_black_box() {
    let seed = ledger_format::EntryHash([21; 32]);
    assert_eq!(
        post_crash_value(Some(JournalingMode::Data), true, false, seed),
        Some(0),
        "Data mode must lose an unfsynced write on crash"
    );
    assert_eq!(
        post_crash_value(Some(JournalingMode::Data), true, true, seed),
        Some(7),
        "Data mode must keep an fsynced write across a crash"
    );
    assert_eq!(
        post_crash_value(Some(JournalingMode::Writeback), true, false, seed),
        Some(7),
        "Writeback mode must persist a journaled write even without fsync"
    );
    assert_eq!(
        post_crash_value(None, true, false, seed),
        Some(0),
        "the black-box default must drop the unfsynced write"
    );
}

/// The journaled crash is deterministic: the same seed and mode reproduce the
/// same post-crash state and journal root.
#[test]
fn journaled_crash_is_deterministic() {
    let config = |mode: JournalingMode| {
        RunConfig::builder()
            .seed(ledger_format::EntryHash([22; 32]))
            .policy(Policy::Random)
            .max_steps(256)
            .fs_journaling(Some(mode))
            .build()
    };
    let programs = || {
        vec![vec![
            Instruction::FsWrite {
                path: "k".into(),
                value: 7,
            },
            Instruction::FsCrash,
            Instruction::FsRead { path: "k".into() },
            Instruction::Outcome,
            Instruction::Done,
        ]]
    };
    let first = Simulation::new(config(JournalingMode::Writeback), programs())
        .run()
        .unwrap();
    let second = Simulation::new(config(JournalingMode::Writeback), programs())
        .run()
        .unwrap();
    assert_eq!(
        first.journal.root_hash(),
        second.journal.root_hash(),
        "the same seed and mode must replay byte-identically"
    );
}
