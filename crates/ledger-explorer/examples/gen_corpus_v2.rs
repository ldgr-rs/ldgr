// ledger-lint:allow (host-side corpus manifest generator; it is not simulation code)
//! Generate the pinned `corpora/bug-corpus-v2` manifests from the
//! fault-triggered scenario registry
//! (`ledger_explorer::reference::faultdep_scenarios`).
//!
//! Run from the workspace root with `cargo run -p ledger-explorer --example
//! gen_corpus_v2`. Each manifest pins the scenario's canonical WITNESS run:
//! the run at the pinned seed with the pinned trigger schedule injected. The
//! no-fault baseline at the same seed passes; only the trigger causes the
//! violation. The trigger schedule itself is derived deterministically from
//! the no-fault baseline journal of the pinned seed, so the manifest bytes
//! plus the registry fully determine the witness run without storing a
//! fault schedule in the manifest format.

use ledger_explorer::reference::faultdep_scenarios;
use ledger_format::RunManifest;
use std::collections::BTreeMap;
use std::path::Path;

fn hex(h: &ledger_format::Hash) -> String {
    h.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let out_dir = Path::new("corpora/bug-corpus-v2");
    std::fs::create_dir_all(out_dir).expect("create v2 dir");
    let mut written = 0usize;
    for scenario in faultdep_scenarios() {
        let finding = scenario.witness().unwrap_or_else(|error| panic!("{error}"));
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
        let path = out_dir.join(format!("{}.ldgr", scenario.name));
        std::fs::write(&path, &bytes).expect("manifest write");
        println!(
            "wrote {} ({} bytes, root {}, fault-triggered witness)",
            path.display(),
            bytes.len(),
            hex(&manifest.journal_root),
        );
        written += 1;
    }
    println!("generated {written} fault-triggered corpus-v2 manifest fixtures");
}
