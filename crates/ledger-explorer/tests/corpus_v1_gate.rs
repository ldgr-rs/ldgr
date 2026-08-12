//! Corpus-v1 bit-exact gate: the reference-runtime reproductions must be
//! deterministic (identical journal root across runs) AND the planted bug must
//! fire under the oracle.
//!
//! The reference sims are real async protocols on the effect boundary
//! (mini-zab, mini-hdfs, mini-cassandra, mini-2pc, mini-leader-stepdown,
//! mini-membership-churn, mini-hdfs-lease-expiry); the mini-kv stale read is
//! the schedule-dependent search-based entry. Together they pin the corpus-v1
//! gate at 8 of 12 reproductions bit-exact from seed.

use ledger_explorer::Workload;
use ledger_explorer::oracle::{HistoryOracle, KeyValueSpec, Oracle, PropertyOracle};
use ledger_explorer::reference::{
    mini_2pc, mini_cassandra, mini_hdfs, mini_hdfs_lease_expiry, mini_leader_stepdown,
    mini_membership_churn, mini_zab,
};
use ledger_explorer::search::{replay, search};
use ledger_explorer::workloads::MiniKvWorkload;
use ledger_sim::{Policy, RunConfig, Simulation};
use std::fs;
use std::path::Path;

fn config(seed: [u8; 32]) -> RunConfig {
    RunConfig {
        seed,
        policy: Policy::Random,
        max_steps: 4096,
        ..RunConfig::default()
    }
}

/// Run one async reference sim twice with the same seed and check (a) the
/// planted bug fires under the oracle and (b) the journal root is bit-identical.
fn assert_bit_exact_reproduction(
    name: &str,
    builders: impl Fn() -> Vec<ledger_sim::TaskBuilder>,
    oracle: impl Fn(&ledger_journal::Journal) -> bool,
    seed: [u8; 32],
) {
    let oracle = PropertyOracle {
        property: oracle,
        name: name.to_string(),
    };
    let first = Simulation::with_tasks(config(seed), builders())
        .run()
        .unwrap();
    let second = Simulation::with_tasks(config(seed), builders())
        .run()
        .unwrap();
    assert_eq!(
        first.journal.root_hash(),
        second.journal.root_hash(),
        "{name}: journal root must be bit-identical across runs"
    );
    let verdict = oracle.check(&first);
    assert!(
        verdict.violated,
        "{name}: the planted bug must fire under the oracle"
    );
}

#[test]
fn mini_zab_split_brain_reproduces_bit_exact() {
    let (_, oracle) = mini_zab();
    assert_bit_exact_reproduction("mini-zab split-brain", || mini_zab().0, oracle, [1; 32]);
}

#[test]
fn mini_hdfs_double_grant_reproduces_bit_exact() {
    let (_, oracle) = mini_hdfs();
    assert_bit_exact_reproduction("mini-hdfs double grant", || mini_hdfs().0, oracle, [2; 32]);
}

#[test]
fn mini_cassandra_stale_read_reproduces_bit_exact() {
    let (_, oracle) = mini_cassandra();
    assert_bit_exact_reproduction(
        "mini-cassandra stale read",
        || mini_cassandra().0,
        oracle,
        [3; 32],
    );
}

#[test]
fn mini_2pc_coordinator_crash_reproduces_bit_exact() {
    let (_, oracle) = mini_2pc();
    assert_bit_exact_reproduction(
        "mini-2pc coordinator crash",
        || mini_2pc().0,
        oracle,
        [4; 32],
    );
}

#[test]
fn mini_leader_stepdown_reproduces_bit_exact() {
    let (_, oracle) = mini_leader_stepdown();
    assert_bit_exact_reproduction(
        "mini-leader stepdown stale read",
        || mini_leader_stepdown().0,
        oracle,
        [5; 32],
    );
}

#[test]
fn mini_membership_churn_reproduces_bit_exact() {
    let (_, oracle) = mini_membership_churn();
    assert_bit_exact_reproduction(
        "mini-membership churn commit stall",
        || mini_membership_churn().0,
        oracle,
        [6; 32],
    );
}

#[test]
fn mini_hdfs_lease_expiry_reproduces_bit_exact() {
    let (_, oracle) = mini_hdfs_lease_expiry();
    assert_bit_exact_reproduction(
        "mini-hdfs lease expiry overwrite",
        || mini_hdfs_lease_expiry().0,
        oracle,
        [7; 32],
    );
}

#[test]
fn mini_kv_stale_read_reproduces_from_seed() {
    // Schedule-dependent entry: the search finds a violating seed, then the
    // same seed reproduces the same root bit-exactly.
    let oracle = HistoryOracle::new(&MiniKvWorkload, KeyValueSpec::default());
    let finding = search(&MiniKvWorkload, &oracle, config([0; 32]), 256)
        .unwrap()
        .expect("mini-kv stale read must be found");
    let replayed = replay(&MiniKvWorkload, finding.seed, finding.run.decisions.clone()).unwrap();
    assert_eq!(
        finding.run.journal.root_hash(),
        replayed.journal.root_hash(),
        "mini-kv: the found seed must reproduce bit-exactly"
    );
    assert!(finding.verdict.violated);
}

/// Fingerprint-pin the committed corpus manifests (fuzzer-corpus pattern):
/// each `.ldgr` must decode as a `RunManifest`, and a fresh run at the stored
/// seed must reproduce the stored journal root and entry count, with the
/// planted bug still firing. This makes the corpus files read-only fixtures:
/// any drift in the executor, scheduler, seed tree, or journal hashing that
/// orphans a manifest fails the gate.
#[test]
fn corpus_manifests_are_pinned_and_reproduce() {
    use ledger_explorer::reference::*;
    use ledger_format::RunManifest;

    /// Run one reference sim at the manifest seed and assert the oracle fires.
    fn reference_run(
        name: &str,
        builders: Vec<ledger_sim::TaskBuilder>,
        oracle: impl Fn(&ledger_journal::Journal) -> bool,
        seed: [u8; 32],
    ) -> ledger_sim::RunResult {
        let run = Simulation::with_tasks(config(seed), builders)
            .run()
            .unwrap();
        assert!(
            PropertyOracle {
                property: oracle,
                name: name.to_string()
            }
            .check(&run)
            .violated,
            "{name}: the planted bug must fire"
        );
        run
    }

    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpora/bug-corpus-v1");
    let mut checked = 0usize;
    for entry in fs::read_dir(&corpus).expect("corpus dir must exist") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("ldgr") {
            continue;
        }
        let bytes = fs::read(&path).unwrap();
        let manifest = RunManifest::from_canonical_bytes(&bytes).unwrap_or_else(|error| {
            panic!(
                "{}: manifest must decode as a RunManifest: {error}",
                path.display()
            )
        });
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();

        let run = match name.as_str() {
            "mini-zab-split-brain" => {
                reference_run(&name, mini_zab().0, mini_zab().1, manifest.root_seed)
            }
            "mini-hdfs-double-grant" => {
                reference_run(&name, mini_hdfs().0, mini_hdfs().1, manifest.root_seed)
            }
            "mini-cassandra-stale-read" => reference_run(
                &name,
                mini_cassandra().0,
                mini_cassandra().1,
                manifest.root_seed,
            ),
            "mini-2pc-coordinator-crash" => {
                reference_run(&name, mini_2pc().0, mini_2pc().1, manifest.root_seed)
            }
            "mini-leader-stepdown" => reference_run(
                &name,
                mini_leader_stepdown().0,
                mini_leader_stepdown().1,
                manifest.root_seed,
            ),
            "mini-membership-churn" => reference_run(
                &name,
                mini_membership_churn().0,
                mini_membership_churn().1,
                manifest.root_seed,
            ),
            "mini-hdfs-lease-expiry" => reference_run(
                &name,
                mini_hdfs_lease_expiry().0,
                mini_hdfs_lease_expiry().1,
                manifest.root_seed,
            ),
            "mini-kv-stale-read" => {
                let oracle = HistoryOracle::new(&MiniKvWorkload, KeyValueSpec::default());
                let run = Simulation::new(config(manifest.root_seed), MiniKvWorkload.programs())
                    .run()
                    .unwrap();
                assert!(
                    oracle.check(&run).violated,
                    "{name}: the planted bug must fire"
                );
                run
            }
            other => panic!("unexpected corpus manifest: {other}"),
        };

        assert_eq!(
            run.journal.root_hash(),
            manifest.journal_root,
            "{name}: the committed manifest root must match a fresh run"
        );
        assert_eq!(
            run.journal.len() as u64,
            manifest.entry_count,
            "{name}: the committed manifest entry count must match a fresh run"
        );
        checked += 1;
    }
    assert_eq!(checked, 8, "all eight corpus manifests must be pinned");
}
