// ledger-lint:allow (host-side corpus manifest generator; it is not simulation code)
//! Generate the pinned `corpora/bug-corpus-v2` manifests from the v2 scenario
//! registry (`ledger_explorer::reference::corpus_v2_scenarios`).

use ledger_explorer::reference::corpus_v2_scenarios;
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
    for scenario in corpus_v2_scenarios() {
        let finding = scenario
            .reproduce()
            .unwrap_or_else(|error| panic!("{error}"));
        let mut actor_heads = BTreeMap::new();
        for entry in finding.run.journal.entries() {
            actor_heads.insert(entry.data.actor, entry.id);
        }
        let manifest = RunManifest {
            format_version: 1,
            root_seed: finding.seed,
            policy_tag: "random".to_string(),
            journal_root: finding.run.journal.root_hash(),
            entry_count: finding.run.journal.len() as u64,
            actor_heads,
            execution_identity: None,
            extensions: BTreeMap::new(),
        };
        let bytes = manifest.to_canonical_bytes().expect("manifest encodes");
        let path = out_dir.join(format!("{}.ldgr", scenario.name));
        std::fs::write(&path, &bytes).expect("manifest write");
        println!(
            "wrote {} ({} bytes, root {}, cloud-infra)",
            path.display(),
            bytes.len(),
            hex(&manifest.journal_root),
        );
        written += 1;
    }
    println!("generated {written} corpus-v2 manifest fixtures");
}
