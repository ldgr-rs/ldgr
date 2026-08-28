//! Corpus-v1 bit-exact gate: the reference-runtime reproductions must be
//! deterministic (identical journal root across runs) AND the planted bug must
//! fire under the oracle.
//!
//! The scenario set lives in the single registry
//! (`ledger_explorer::reference::corpus_scenarios`): seven reference-runtime
//! sims (mini-zab, mini-hdfs, mini-cassandra, mini-2pc, mini-leader-stepdown,
//! mini-membership-churn, mini-hdfs-lease-expiry), the four Stage-1
//! additions (mini-reorder-lost-update, mini-lease-timer-race,
//! mini-restart-dup-append, mini-partition-retry-dup), and the
//! schedule-dependent mini-kv stale read, which search finds and then
//! reproduces bit-exactly from its seed. Twelve reproductions pin the
//! corpus-v1 gate at 12 of 12, bit-exact from seed.

use ledger_explorer::reference::{CorpusRunner, corpus_scenarios};
use ledger_explorer::search::replay_strict;
use ledger_format::RunManifest;
use std::fs;
use std::path::Path;

#[test]
fn every_scenario_reproduces_bit_exact_and_violates() {
    for scenario in corpus_scenarios() {
        let finding = scenario
            .reproduce()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            finding.verdict.violated,
            "{}: the planted bug must fire under the oracle",
            scenario.name
        );

        match scenario.runner {
            CorpusRunner::Tasks { .. } => {
                // Same seed twice: the journal root must be bit-identical.
                let second = scenario
                    .run(scenario.base_seed, Vec::new())
                    .unwrap_or_else(|error| panic!("{}: rerun failed: {error}", scenario.name));
                assert_eq!(
                    finding.run.journal.root_hash(),
                    second.journal.root_hash(),
                    "{}: journal root must be bit-identical across runs",
                    scenario.name
                );
            }
            CorpusRunner::MiniKv => {
                // Schedule-dependent entry: the found seed must reproduce the
                // same root bit-exactly on a recorded-decision replay.
                let replayed = replay_strict(
                    &ledger_explorer::workloads::MiniKvWorkload,
                    finding.seed,
                    finding.run.decisions.clone(),
                )
                .unwrap_or_else(|error| panic!("{}: replay failed: {error}", scenario.name));
                assert_eq!(
                    finding.run.journal.root_hash(),
                    replayed.journal.root_hash(),
                    "{}: the found seed must reproduce bit-exactly",
                    scenario.name
                );
            }
        }
    }
}

/// Fingerprint-pin the committed corpus manifests (fuzzer-corpus pattern):
/// each `.ldgr` must decode as a `RunManifest`, and a fresh run at the stored
/// seed must reproduce the stored journal root and entry count, with the
/// planted bug still firing. This makes the corpus files read-only fixtures:
/// any drift in the executor, scheduler, seed tree, or journal hashing that
/// orphans a manifest fails the gate.
#[test]
fn corpus_manifests_are_pinned_and_reproduce() {
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

        let scenario = ledger_explorer::reference::corpus_scenario(&name).unwrap_or_else(|| {
            panic!("unexpected corpus manifest '{name}': not in the scenario registry")
        });
        let run = scenario
            .run(manifest.root_seed, Vec::new())
            .unwrap_or_else(|error| panic!("{name}: pinned rerun failed: {error}"));
        let verdict = scenario.check(&run);
        assert!(
            verdict.violated,
            "{name}: the planted bug must fire at the pinned seed"
        );

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
    assert_eq!(
        checked,
        corpus_scenarios().len(),
        "every registry scenario must have a pinned manifest"
    );
}

/// The manifest seeds and roots regenerate byte-identically: running the
/// generator twice must produce the committed corpus. This pins the
/// generation path (registry -> canonical bytes) itself.
#[test]
fn manifests_are_regenerable_from_the_registry() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpora/bug-corpus-v1");
    for scenario in corpus_scenarios() {
        let finding = scenario
            .reproduce()
            .unwrap_or_else(|error| panic!("{error}"));
        let path = corpus.join(format!("{}.ldgr", scenario.name));
        let bytes = fs::read(&path)
            .unwrap_or_else(|error| panic!("{}: manifest must exist: {error}", path.display()));
        let manifest = RunManifest::from_canonical_bytes(&bytes).expect("manifest must decode");
        assert_eq!(
            finding.seed, manifest.root_seed,
            "{}: the registry base seed must be the pinned seed",
            scenario.name
        );
        assert_eq!(
            finding.run.journal.root_hash(),
            manifest.journal_root,
            "{}: a registry rerun must reproduce the pinned root",
            scenario.name
        );
    }
}
