//! Corpus-bug reproduction through Wasm guests; every registered scenario
//! must fire its marker and replay byte-identically.
#![cfg(feature = "backend-wasm")]

mod common;

use ledger_format::RunManifest;
use ledger_sim::{Effects, SeedTree, SimBackend, WasmBackend};
use rand_core::Rng;
use std::fs;
use std::path::Path;

const SEED: ledger_format::EntryHash = ledger_format::EntryHash([11; 32]);
const STALE_STREAM: ledger_format::StreamId = ledger_format::StreamId(11);

/// Native twin of the guest's stale-read workload, drawing the same stream.
fn native_twin() -> (Vec<u8>, ledger_journal::Journal) {
    let mut backend = SimBackend::new(SeedTree::new(SEED));
    let fresh = backend.rng(STALE_STREAM).next_u64();
    let fresh_second = backend.rng(STALE_STREAM).next_u64();
    let stale = fresh;
    let mut output = Vec::new();
    output.extend_from_slice(format!("fresh={fresh_second} stale={stale}\n").as_bytes());
    if stale != fresh_second {
        output.extend_from_slice(b"STALE_DIVERGENCE\n");
    }
    (output, backend.journal_snapshot())
}

#[test]
fn corpus_bug_reproduced_through_wasm_guest() {
    let wasm = common::guest_wasm_bytes();
    let mut backend = WasmBackend::from_wasm(SeedTree::new(SEED), &wasm)
        .unwrap()
        .with_fuel_budget(10_000_000);
    let output = backend.run_export("run_stale").unwrap().to_vec();
    let output_text = String::from_utf8_lossy(&output);
    assert!(
        output_text.contains("STALE_DIVERGENCE"),
        "the planted stale-read bug must fire in the guest: {output_text}"
    );
}

#[test]
fn corpus_bug_native_wasm_zero_false_divergence() {
    let (native_output, native_journal) = native_twin();

    let wasm = common::guest_wasm_bytes();
    let mut backend = WasmBackend::from_wasm(SeedTree::new(SEED), &wasm)
        .unwrap()
        .with_fuel_budget(10_000_000);
    let wasm_output = backend.run_export("run_stale").unwrap().to_vec();
    let wasm_journal = backend.journal_snapshot();

    assert_eq!(native_output, wasm_output, "output must be byte-identical");
    assert_eq!(
        native_journal.root_hash(),
        wasm_journal.root_hash(),
        "native and Wasm journals must be byte-identical on the bug workload"
    );
}

/// One corpus scenario: manifest, guest entry, marker, and pinned entry count.
const CORPUS_TO_GUEST: &[(&str, &str, &str, u64)] = &[
    (
        "mini-zab-split-brain",
        "run_corpus_zab",
        "ZAB_SPLIT_BRAIN\n",
        8,
    ),
    (
        "mini-hdfs-double-grant",
        "run_corpus_hdfs",
        "HDFS_DOUBLE_GRANT\n",
        4,
    ),
    (
        "mini-cassandra-stale-read",
        "run_corpus_cassandra",
        "CASSANDRA_STALE_READ\n",
        2,
    ),
    (
        "mini-2pc-coordinator-crash",
        "run_corpus_2pc",
        "TWO_PC_SPLIT\n",
        7,
    ),
    (
        "mini-leader-stepdown",
        "run_corpus_stepdown",
        "STEPDOWN_STALE_READ\n",
        3,
    ),
    (
        "mini-membership-churn",
        "run_corpus_churn",
        "COMMIT_STALL\n",
        7,
    ),
    (
        "mini-hdfs-lease-expiry",
        "run_corpus_lease_expiry",
        "LEASE_OVERWRITE\n",
        9,
    ),
    ("mini-kv-stale-read", "run_stale", "STALE_DIVERGENCE\n", 2),
    (
        "mini-reorder-lost-update",
        "run_corpus_reorder",
        "LOST_UPDATE\n",
        10,
    ),
    (
        "mini-lease-timer-race",
        "run_corpus_lease_timer",
        "DOUBLE_LEASE_HOLDER\n",
        8,
    ),
    (
        "mini-restart-dup-append",
        "run_corpus_restart_dup",
        "DUP_APPEND\n",
        8,
    ),
    (
        "mini-partition-retry-dup",
        "run_corpus_partition_retry",
        "DUP_APPLY\n",
        9,
    ),
];

/// Run one scenario through the Wasm backend under `seed`, returning the
/// output text and the journal, or the reason it could not reproduce.
fn reproduce_through_wasm(
    scenario: &str,
    export: &str,
    wasm: &[u8],
    seed: ledger_format::EntryHash,
) -> Result<(String, ledger_journal::Journal), String> {
    let mut backend = WasmBackend::from_wasm(SeedTree::new(seed), wasm)
        .map_err(|error| format!("{scenario}: Wasm instantiation failed: {error}"))?
        .with_fuel_budget(10_000_000);
    let output = backend
        .run_export(export)
        .map_err(|error| format!("{scenario}: guest export {export} failed: {error}"))?;
    Ok((
        String::from_utf8_lossy(&output).into_owned(),
        backend.journal_snapshot(),
    ))
}

/// Gate: every committed bug-corpus-v1 manifest must reproduce through the
/// Wasm backend at its pinned seed. Failures are collected and reported
/// together; nothing skips.
#[test]
fn corpus_manifests_reproduce_through_wasm_backend() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpora/bug-corpus-v1");
    let wasm = common::guest_wasm_bytes();
    let mut failures: Vec<String> = Vec::new();
    let mut matched_manifests = 0usize;

    for entry in fs::read_dir(&corpus).expect("corpus dir must exist") {
        let path = entry.expect("corpus entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("ldgr") {
            continue;
        }
        let bytes = fs::read(&path).expect("read manifest");
        let manifest = RunManifest::from_canonical_bytes(&bytes)
            .unwrap_or_else(|error| panic!("{}: manifest must decode: {error}", path.display()));
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        let Some(&(scenario, export, marker, pinned_entries)) =
            CORPUS_TO_GUEST.iter().find(|(n, ..)| *n == name)
        else {
            failures.push(format!(
                "{name}: no Wasm guest export registered for this corpus manifest"
            ));
            continue;
        };
        // A table row matched a committed manifest regardless of whether
        // its reproduction below succeeds; only then is a missing manifest
        // distinguishable from a broken scenario.
        matched_manifests += 1;
        // Snapshot before ANY check so the success line prints only when the
        // whole scenario is clean (marker, shape, and byte-identity).
        let failures_before = failures.len();

        // First instantiation under the pinned manifest seed.
        let (output, journal) =
            match reproduce_through_wasm(scenario, export, &wasm, manifest.root_seed) {
                Ok(result) => result,
                Err(reason) => {
                    failures.push(reason);
                    continue;
                }
            };
        if !output.contains(marker) {
            failures.push(format!(
                "{name}: planted-bug marker {marker:?} did not fire; output: {output:?}"
            ));
        }
        let root = journal.root_hash();
        let entries = journal.len() as u64;
        if entries != pinned_entries {
            failures.push(format!(
                "{name}: journal entry count drifted from the pinned shape \
                 (expected {pinned_entries}, observed {entries}); \
                 the guest program changed its host-boundary calls"
            ));
        }

        // Second instantiation under the same seed must be byte-identical.
        let (output2, journal2) =
            match reproduce_through_wasm(scenario, export, &wasm, manifest.root_seed) {
                Ok(result) => result,
                Err(reason) => {
                    failures.push(reason);
                    continue;
                }
            };
        if output2 != output {
            failures.push(format!(
                "{name}: second instantiation output diverged\nfirst:  {output:?}\nsecond: {output2:?}"
            ));
        }
        if journal2.root_hash() != root {
            failures.push(format!(
                "{name}: second instantiation journal root diverged ({} vs {})",
                hex(&root),
                hex(&journal2.root_hash())
            ));
        }
        if journal2.len() as u64 != entries {
            failures.push(format!(
                "{name}: second instantiation entry count diverged ({entries} vs {})",
                journal2.len()
            ));
        }
        if failures.len() == failures_before {
            println!(
                "{name}: wasm reproduction ok, entries={entries} root={}",
                hex(&root)
            );
        }
    }

    // Two-way export bijection against the compiled module: every table
    // row must name an export that exists, and every corpus export in the
    // module must be named by a table row. A dead guest export (or a table
    // row orphaned by a guest rename) fails here instead of silently
    // drifting.
    let engine = WasmBackend::new_engine().unwrap();
    let module = wasmtime::Module::new(&engine, &wasm).unwrap();
    let module_exports: std::collections::HashSet<String> = module
        .exports()
        .filter(|export| matches!(export.ty(), wasmtime::ExternType::Func(_)))
        .map(|export| export.name().to_string())
        .collect();
    let table_exports: std::collections::HashSet<String> = CORPUS_TO_GUEST
        .iter()
        .map(|(_, export, _, _)| (*export).to_string())
        .collect();
    for missing in table_exports.difference(&module_exports) {
        failures.push(format!(
            "{missing}: table row names an export the wasm guest module does not provide"
        ));
    }
    // Corpus exports follow the `run_corpus_` prefix convention plus the
    // shared stale-read entry `run_stale`.
    let corpus_exports: std::collections::HashSet<String> = module_exports
        .iter()
        .filter(|name| name.starts_with("run_corpus_") || name.as_str() == "run_stale")
        .cloned()
        .collect();
    for dead in corpus_exports.difference(&table_exports) {
        failures.push(format!(
            "{dead}: wasm guest export without a corpus-gate table row"
        ));
    }

    // Manifest-side drift report: only when no other failure exists does a
    // shortfall mean a registered scenario lacks a committed manifest. A
    // scenario that matched a manifest but failed reproduction is already
    // named above, so no misleading secondary line is emitted.
    if failures.is_empty() && matched_manifests != CORPUS_TO_GUEST.len() {
        failures.push(format!(
            "registered scenarios without a committed manifest: {} of {} (matched {matched_manifests})",
            CORPUS_TO_GUEST.len() - matched_manifests,
            CORPUS_TO_GUEST.len()
        ));
    }

    assert!(
        failures.is_empty(),
        "corpus-v1 Wasm reproductions failed:\n{}",
        failures.join("\n")
    );
}

fn hex(hash: &ledger_format::EntryHash) -> String {
    hash.0.iter().map(|b| format!("{b:02x}")).collect()
}
