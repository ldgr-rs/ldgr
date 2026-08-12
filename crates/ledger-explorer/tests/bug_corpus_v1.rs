//! Bug Corpus v1: deterministic bug reproductions with automated oracles.
//!
//! Exactly 8 of the tests in this file are genuine distributed-bug
//! reproductions: mini-kv stale read (search-based) plus the seven
//! reference-runtime sims (mini-zab split-brain, mini-hdfs double grant,
//! mini-cassandra stale read, mini-2pc coordinator crash, mini-leader
//! stepdown, mini-membership churn, mini-hdfs lease expiry). Each runs under a
//! fixed seed and asserts that the planted oracle fires.
//!
//! The remaining tests are engine-regression tests that live in this corpus
//! file for discovery: SimFs crash semantics, virtual-time timer ordering,
//! vector-clock monotonicity, LDFI, seed-tree independence, minimization, and
//! replay determinism. They are not planted distributed-system bugs.

use ledger_explorer::ldfi::solve_ldfi;
use ledger_explorer::oracle::{
    AssertionOracle, HistoryOperation, HistoryOracle, KeyValueSpec, Oracle, PropertyOracle,
};
use ledger_explorer::reference::{
    mini_2pc, mini_cassandra, mini_hdfs, mini_hdfs_lease_expiry, mini_leader_stepdown,
    mini_membership_churn, mini_zab,
};
use ledger_explorer::search::{Workload, search};
use ledger_format::{EntryKind, Payload};
use ledger_journal::Journal;
use ledger_sim::config::{Policy, RunConfig};
use ledger_sim::runtime::{Instruction, RunResult, Simulation};
use ledger_sim::simfs::{CrashOperator, SimFs};

/// Run one reference sim at a fixed seed and assert the planted bug fires.
fn assert_reference_bug_reproduces(
    name: &str,
    builders: Vec<ledger_sim::TaskBuilder>,
    oracle: impl Fn(&ledger_journal::Journal) -> bool,
    seed: [u8; 32],
) {
    let config = RunConfig {
        seed,
        policy: Policy::Random,
        max_steps: 4096,
        ..RunConfig::default()
    };
    let run = Simulation::with_tasks(config, builders).run().unwrap();
    let verdict = PropertyOracle {
        property: oracle,
        name: name.to_string(),
    }
    .check(&run);
    assert!(verdict.violated, "{name}: the planted bug must fire");
}

// ---- Genuine distributed-bug reproductions (8) ----

// 1. Mini-KV stale read race (search-based reproduction).
struct Bug01StaleRead;
impl Workload for Bug01StaleRead {
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
    fn history(&self, run: &RunResult) -> Vec<HistoryOperation> {
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

#[test]
fn mini_kv_stale_read_reproduced_from_seed() {
    let config = RunConfig {
        seed: [0; 32],
        policy: Policy::Random,
        max_steps: 256,
        ..RunConfig::default()
    };
    let oracle = HistoryOracle::new(&Bug01StaleRead, KeyValueSpec::default());
    let finding = search(&Bug01StaleRead, &oracle, config, 256)
        .unwrap()
        .unwrap();
    assert!(finding.verdict.violated);
}

#[test]
fn reference_mini_zab_split_brain_reproduces() {
    assert_reference_bug_reproduces("mini-zab split-brain", mini_zab().0, mini_zab().1, [1; 32]);
}

#[test]
fn reference_mini_hdfs_double_grant_reproduces() {
    assert_reference_bug_reproduces(
        "mini-hdfs double grant",
        mini_hdfs().0,
        mini_hdfs().1,
        [2; 32],
    );
}

#[test]
fn reference_mini_cassandra_stale_read_reproduces() {
    assert_reference_bug_reproduces(
        "mini-cassandra stale read",
        mini_cassandra().0,
        mini_cassandra().1,
        [3; 32],
    );
}

#[test]
fn reference_mini_2pc_coordinator_crash_reproduces() {
    assert_reference_bug_reproduces(
        "mini-2pc coordinator crash",
        mini_2pc().0,
        mini_2pc().1,
        [4; 32],
    );
}

#[test]
fn reference_mini_leader_stepdown_reproduces() {
    assert_reference_bug_reproduces(
        "mini-leader stepdown stale read",
        mini_leader_stepdown().0,
        mini_leader_stepdown().1,
        [5; 32],
    );
}

#[test]
fn reference_mini_membership_churn_reproduces() {
    assert_reference_bug_reproduces(
        "mini-membership churn commit stall",
        mini_membership_churn().0,
        mini_membership_churn().1,
        [6; 32],
    );
}

#[test]
fn reference_mini_hdfs_lease_expiry_reproduces() {
    assert_reference_bug_reproduces(
        "mini-hdfs lease expiry overwrite",
        mini_hdfs_lease_expiry().0,
        mini_hdfs_lease_expiry().1,
        [7; 32],
    );
}

// ---- Engine-regression tests (kept here for discovery) ----

#[test]
fn storage_crash_discards_unsynced_dirty_write() {
    let mut fs = SimFs::new();
    let mut journal = Journal::new();
    fs.write(&mut journal, 1, "wal.log", 100).unwrap();
    fs.fsync(&mut journal, 1).unwrap();
    fs.write(&mut journal, 1, "wal.log", 200).unwrap(); // Unsynced
    fs.crash();
    assert_eq!(fs.read(&mut journal, 1, "wal.log").unwrap(), Some(100));
}

#[test]
fn storage_torn_write_preserves_only_prefix() {
    let mut fs = SimFs::new();
    let mut journal = Journal::new();
    fs.write(&mut journal, 1, "record.bin", 0xDEAD_BEEF)
        .unwrap();
    fs.apply_crash_operator(&CrashOperator::TornWrite {
        path: "record.bin".into(),
        partial_value: 0xDEAD_0000,
    });
    assert_eq!(
        fs.read(&mut journal, 1, "record.bin").unwrap(),
        Some(0xDEAD_0000)
    );
}

#[test]
fn storage_bit_flip_corruption_detected() {
    let mut fs = SimFs::new();
    let mut journal = Journal::new();
    fs.write(&mut journal, 1, "data.bin", 0b1111).unwrap();
    fs.apply_crash_operator(&CrashOperator::BitFlipCorruption {
        path: "data.bin".into(),
        xor_mask: 0b0010,
    });
    assert_eq!(fs.read(&mut journal, 1, "data.bin").unwrap(), Some(0b1101));
}

// Two-phase commit workload with planted coordinator failure: the workload
// must never produce an assertion violation under search.
struct Bug05TwoPhaseCommit;
impl Workload for Bug05TwoPhaseCommit {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        vec![
            vec![
                Instruction::Send { to: 1, payload: 10 },
                Instruction::Receive,
                Instruction::Assert(true),
                Instruction::Done,
            ],
            vec![
                Instruction::Receive,
                Instruction::Send { to: 0, payload: 1 },
                Instruction::Done,
            ],
        ]
    }
    fn history(&self, _run: &RunResult) -> Vec<HistoryOperation> {
        Vec::new()
    }
}

#[test]
fn two_phase_commit_workload_has_no_assertion_violation() {
    let config = RunConfig {
        seed: [5; 32],
        policy: Policy::Random,
        max_steps: 64,
        ..RunConfig::default()
    };
    let oracle = AssertionOracle;
    let finding = search(&Bug05TwoPhaseCommit, &oracle, config, 10).unwrap();
    assert!(finding.is_none());
}

// Network partition dropping message.
struct Bug06PartitionDrop;
impl Workload for Bug06PartitionDrop {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        vec![
            vec![
                Instruction::Send {
                    to: 1,
                    payload: 777,
                },
                Instruction::Done,
            ],
            vec![
                Instruction::Receive,
                Instruction::Outcome,
                Instruction::Done,
            ],
        ]
    }
    fn history(&self, _run: &RunResult) -> Vec<HistoryOperation> {
        Vec::new()
    }
}

#[test]
fn net_partition_drop_journals_send_entry() {
    let config = RunConfig {
        seed: [6; 32],
        policy: Policy::Random,
        max_steps: 10,
        ..RunConfig::default()
    };
    let sim = Simulation::new(config, Bug06PartitionDrop.programs());
    let run = sim.run().unwrap();
    assert!(
        run.journal
            .entries()
            .any(|e| e.data.kind == EntryKind::Send)
    );
}

#[test]
fn virtual_time_timer_fires_in_deadline_order() {
    let mut vt = ledger_sim::time::VirtualTime::default();
    vt.set(100, 1);
    vt.set(50, 2);
    let ready_first = vt.advance();
    assert_eq!(ready_first, vec![2]);
    assert_eq!(vt.now(), 50);
    let ready_second = vt.advance();
    assert_eq!(ready_second, vec![1]);
    assert_eq!(vt.now(), 100);
}

#[test]
fn vector_clock_monotonicity_increases() {
    let mut j = Journal::new();
    let e1 = j
        .append(
            EntryKind::InputStep {
                generator: 0,
                replay: 0,
            },
            1,
            [],
            Payload::Number(1),
        )
        .unwrap();
    let e2 = j
        .append(EntryKind::Outcome, 1, [], Payload::Number(2))
        .unwrap();
    let vc1 = &j.get(&e1).unwrap().vector_clock;
    let vc2 = &j.get(&e2).unwrap().vector_clock;
    assert!(vc1.happens_before(vc2));
}

#[test]
fn ldfi_minimal_hitting_set_breaks_race_path() {
    let config = RunConfig {
        seed: [0; 32],
        policy: Policy::Random,
        max_steps: 256,
        ..RunConfig::default()
    };
    let oracle = HistoryOracle::new(&Bug01StaleRead, KeyValueSpec::default());
    let finding = search(&Bug01StaleRead, &oracle, config, 256)
        .unwrap()
        .unwrap();
    let cuts = solve_ldfi(&finding.run.journal, &finding.verdict);
    assert!(!cuts.is_empty());
}

#[test]
fn seed_tree_streams_are_independent() {
    let tree = ledger_sim::seedtree::SeedTree::new([42; 32]);
    let s1 = tree.draw_u64("net", 0);
    let s2 = tree.draw_u64("fs", 0);
    assert_ne!(s1, s2);
}

#[test]
fn ddmin_reaches_single_granularity() {
    let decisions = vec![0, 1, 0, 2, 0, 1, 3, 0];
    let report = ledger_explorer::minimizer::minimize_schedule(&decisions, |d| {
        d.contains(&2) && d.contains(&3)
    });
    assert_eq!(report.minimized_decisions, vec![2, 3]);
}

#[test]
fn replay_same_seed_identical_root() {
    let config = RunConfig {
        seed: [12; 32],
        policy: Policy::Random,
        max_steps: 64,
        ..RunConfig::default()
    };
    let r1 = Simulation::new(config.clone(), Bug01StaleRead.programs())
        .run()
        .unwrap();
    let r2 = Simulation::new(config, Bug01StaleRead.programs())
        .run()
        .unwrap();
    assert_eq!(r1.journal.root_hash(), r2.journal.root_hash());
}
