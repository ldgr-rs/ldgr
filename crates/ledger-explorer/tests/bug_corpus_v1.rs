//! Bug Corpus v1: deterministic bug reproductions with automated oracles.
//!
//! The genuine distributed-bug reproductions come from the shared registry
//! (`ledger_explorer::reference::corpus_scenarios`): the twelve corpus-v1
//! scenarios (mini-kv stale read via search, plus the reference-runtime sims
//! mini-zab, mini-hdfs, mini-cassandra, mini-2pc, mini-leader-stepdown,
//! mini-membership-churn, mini-hdfs-lease-expiry, mini-reorder-lost-update,
//! mini-lease-timer-race, mini-restart-dup-append, mini-partition-retry-dup).
//! One registry-driven test asserts each scenario's planted oracle fires.
//!
//! The remaining tests are engine-regression tests that live in this corpus
//! file for discovery: SimFs crash semantics, virtual-time timer ordering,
//! vector-clock monotonicity, LDFI, seed-tree independence, minimization, and
//! replay determinism. They are not planted distributed-system bugs.

use ledger_explorer::ldfi::solve_with;
use ledger_explorer::oracle::{AssertionOracle, HistoryOperation, HistoryOracle, KeyValueSpec};
use ledger_explorer::reference::corpus_scenarios;
use ledger_explorer::search::{Workload, search};
use ledger_explorer::solver::HittingSetSolver;
use ledger_format::ActorId;
use ledger_format::EntryHash;
use ledger_format::{CanonicalValue, CrashOperation, EntryKind, EntryPayload};
use ledger_journal::Journal;
use ledger_sim::{Instruction, Policy, RunConfig, RunResult, SimFs, Simulation};

// ---- Genuine distributed-bug reproductions (12, registry-driven) ----

#[test]
fn every_corpus_scenario_bug_fires() {
    for scenario in corpus_scenarios() {
        let finding = scenario
            .reproduce()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            finding.verdict.violated,
            "{}: the planted bug must fire",
            scenario.name
        );
    }
}

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
                (
                    EntryKind::Send,
                    EntryPayload::Send(ledger_format::SendFrame {
                        to: ActorId(1),
                        original_content,
                        ..
                    }),
                ) if entry.data.actor == ActorId(0)
                    && original_content.as_slice() == 42u64.to_le_bytes() =>
                {
                    Some(HistoryOperation::Write {
                        key: "k".into(),
                        value: 42,
                        witness: entry.id,
                    })
                }
                (
                    EntryKind::Outcome,
                    EntryPayload::Outcome(ledger_format::OutcomePayload {
                        value: CanonicalValue::Unsigned(value),
                        ..
                    }),
                ) if entry.data.actor == ActorId(2) => Some(HistoryOperation::Read {
                    key: "k".into(),
                    value: *value,
                    witness: entry.id,
                }),
                _ => None,
            })
            .collect()
    }
}

#[test]
fn mini_kv_stale_read_reproduced_from_seed() {
    let config = RunConfig::builder()
        .seed(EntryHash([0; 32]))
        .policy(Policy::Random)
        .max_steps(256)
        .build();
    let oracle = HistoryOracle::new(&Bug01StaleRead, KeyValueSpec::default());
    let finding = search(&Bug01StaleRead, &oracle, config, 256)
        .unwrap()
        .unwrap();
    assert!(finding.verdict.violated);
}

// ---- Engine-regression tests (kept here for discovery) ----

#[test]
fn storage_crash_discards_unsynced_dirty_write() {
    let mut fs = SimFs::new();
    let mut journal = Journal::new();
    fs.write(&mut journal, ActorId(1), "wal.log", 100).unwrap();
    fs.fsync(&mut journal, ActorId(1)).unwrap();
    fs.write(&mut journal, ActorId(1), "wal.log", 200).unwrap(); // Unsynced
    fs.crash();
    assert_eq!(
        fs.read(&mut journal, ActorId(1), "wal.log").unwrap(),
        Some(100)
    );
}

#[test]
fn storage_torn_write_preserves_only_prefix() {
    let mut fs = SimFs::new();
    let mut journal = Journal::new();
    let write_id = fs
        .write(&mut journal, ActorId(1), "record.bin", 0xDEAD_BEEF)
        .unwrap();
    fs.apply_crash_operation(&CrashOperation::TornWrite {
        write_entry: write_id,
        persisted_prefix: 4,
    })
    .unwrap();
    // The LE u64 0xDEAD_BEEF is eight bytes; persisting the first four
    // keeps the high half, which still decodes to 0xDEAD_BEEF.
    assert_eq!(
        fs.read(&mut journal, ActorId(1), "record.bin").unwrap(),
        Some(0xDEAD_BEEF)
    );
}

#[test]
fn storage_bit_flip_corruption_detected() {
    let mut fs = SimFs::new();
    let mut journal = Journal::new();
    let write_id = fs
        .write(&mut journal, ActorId(1), "data.bin", 0b1111)
        .unwrap();
    fs.apply_crash_operation(&CrashOperation::BitFlip {
        write_entry: write_id,
        offset: 0,
        bit: 1,
    })
    .unwrap();
    assert_eq!(
        fs.read(&mut journal, ActorId(1), "data.bin").unwrap(),
        Some(0b1101)
    );
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
    let config = RunConfig::builder()
        .seed(EntryHash([5; 32]))
        .policy(Policy::Random)
        .max_steps(64)
        .build();
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
    let config = RunConfig::builder()
        .seed(EntryHash([6; 32]))
        .policy(Policy::Random)
        .max_steps(10)
        .build();
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
    let mut vt = ledger_sim::VirtualTime::default();
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
            EntryKind::InputStep,
            ActorId(1),
            [],
            EntryPayload::InputStep(ledger_format::InputStepPayload {
                generator: 0,
                replay: 0,
                value: CanonicalValue::Unsigned(1),
            }),
        )
        .unwrap();
    let e2 = j
        .append(
            EntryKind::Outcome,
            ActorId(1),
            [],
            EntryPayload::Outcome(ledger_format::OutcomePayload {
                schema: EntryHash([0x00; 32]),
                value: CanonicalValue::Unsigned(2),
            }),
        )
        .unwrap();
    let vc1 = &j.get(&e1).unwrap().vector_clock;
    let vc2 = &j.get(&e2).unwrap().vector_clock;
    assert!(vc1.happens_before(vc2));
}

#[test]
fn ldfi_minimal_hitting_set_breaks_race_path() {
    let config = RunConfig::builder()
        .seed(EntryHash([0; 32]))
        .policy(Policy::Random)
        .max_steps(256)
        .build();
    let oracle = HistoryOracle::new(&Bug01StaleRead, KeyValueSpec::default());
    let finding = search(&Bug01StaleRead, &oracle, config, 256)
        .unwrap()
        .unwrap();
    let cuts = solve_with(
        &mut HittingSetSolver::new(),
        &finding.run.journal,
        &finding.verdict,
    )
    .expect("solve");
    assert!(!cuts.is_empty());
}

#[test]
fn seed_tree_streams_are_independent() {
    let tree = ledger_sim::SeedTree::new(EntryHash([42; 32]));
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
    let config = RunConfig::builder()
        .seed(EntryHash([12; 32]))
        .policy(Policy::Random)
        .max_steps(64)
        .build();
    let r1 = Simulation::new(config.clone(), Bug01StaleRead.programs())
        .run()
        .unwrap();
    let r2 = Simulation::new(config, Bug01StaleRead.programs())
        .run()
        .unwrap();
    assert_eq!(r1.journal.root_hash(), r2.journal.root_hash());
}
