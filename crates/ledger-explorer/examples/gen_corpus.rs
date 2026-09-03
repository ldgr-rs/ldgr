// ledger-lint:allow (host-side corpus manifest generator; it is not simulation code)
//! Generate the pinned `corpora/bug-corpus-v1` manifests from the shared
//! scenario registry (`ledger_explorer::reference::corpus_scenarios`).
//!
//! Run from the workspace root with `cargo run -p ledger-explorer --example
//! gen_corpus`. Each manifest pins the scenario's canonical violating run:
//! root seed, journal root, entry count, and actor heads. The corpus gates
//! re-run every scenario at the pinned seed and require bit-exact
//! reproduction.
use ledger_explorer::reference::{CorpusRunner, corpus_scenarios};
use ledger_format::RunManifest;
use std::collections::BTreeMap;

fn hex(h: &ledger_format::EntryHash) -> String {
    h.0.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let mut written = 0usize;
    for scenario in corpus_scenarios() {
        // The registry's canonical violating run IS the pinned run.
        let finding = scenario
            .reproduce()
            .unwrap_or_else(|error| panic!("{error}"));
        let mut actor_heads = BTreeMap::new();
        for entry in finding.run.journal.entries() {
            actor_heads.insert(entry.data.actor, entry.id);
        }
        let manifest = RunManifest {
            format_version: ledger_format::FORMAT_VERSION,
            crash_semantics_version: ledger_format::CRASH_SEMANTICS_VERSION,
            root_seed: finding.seed,
            policy_tag: "random".to_string(),
            journal_root: finding.run.journal.root_hash(),
            entry_count: finding.run.journal.len() as u64,
            actor_heads,
            execution_identity: None,
        };
        let bytes = manifest.to_canonical_bytes().expect("manifest encodes");
        let path = format!("corpora/bug-corpus-v1/{}.ldgr", scenario.name);
        std::fs::write(&path, &bytes).expect("manifest write");
        println!(
            "wrote {path} ({} bytes, root {}, {})",
            bytes.len(),
            hex(&manifest.journal_root),
            match scenario.runner {
                CorpusRunner::Tasks { .. } => "reference sim",
                CorpusRunner::MiniKv => "search-based",
            }
        );
        written += 1;
    }
    println!("generated {written} corpus-v1 manifest fixtures");
}
