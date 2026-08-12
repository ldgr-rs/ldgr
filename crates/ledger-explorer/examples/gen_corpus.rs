// ledger-lint:allow (host-side corpus manifest generator; it is not simulation code)
use ledger_explorer::oracle::{HistoryOracle, KeyValueSpec, Oracle, PropertyOracle};
use ledger_explorer::reference::{
    mini_2pc, mini_cassandra, mini_hdfs, mini_hdfs_lease_expiry, mini_leader_stepdown,
    mini_membership_churn, mini_zab,
};
use ledger_explorer::search::search;
use ledger_explorer::workloads::MiniKvWorkload;
use ledger_format::{Hash, RunManifest};
use ledger_sim::{Policy, RunConfig, Simulation};
use std::collections::BTreeMap;

fn write_manifest(
    name: &str,
    builders: impl Fn() -> Vec<ledger_sim::TaskBuilder>,
    oracle: impl Fn(&ledger_journal::Journal) -> bool,
    seed: [u8; 32],
) {
    let cfg = RunConfig {
        seed,
        policy: Policy::Random,
        max_steps: 4096,
        ..RunConfig::default()
    };
    let run = Simulation::with_tasks(cfg, builders()).run().unwrap();
    let oracle = PropertyOracle {
        property: oracle,
        name: name.to_string(),
    };
    assert!(oracle.check(&run).violated, "{name}: bug must fire");
    let mut actor_heads = BTreeMap::new();
    for entry in run.journal.entries() {
        actor_heads.insert(entry.data.actor, entry.id);
    }
    let manifest = RunManifest {
        format_version: 1,
        root_seed: seed,
        policy_tag: "random".to_string(),
        journal_root: run.journal.root_hash(),
        entry_count: run.journal.len() as u64,
        actor_heads,
        extensions: BTreeMap::new(),
    };
    let bytes = manifest.to_canonical_bytes().expect("manifest encodes");
    let path = format!("corpora/bug-corpus-v1/{name}.ldgr");
    std::fs::write(&path, &bytes).unwrap();
    println!(
        "wrote {} ({} bytes, root {})",
        path,
        bytes.len(),
        hex(&run.journal.root_hash())
    );
}

fn hex(h: &Hash) -> String {
    h.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

fn main() {
    write_manifest(
        "mini-zab-split-brain",
        || mini_zab().0,
        mini_zab().1,
        [1; 32],
    );
    write_manifest(
        "mini-hdfs-double-grant",
        || mini_hdfs().0,
        mini_hdfs().1,
        [2; 32],
    );
    write_manifest(
        "mini-cassandra-stale-read",
        || mini_cassandra().0,
        mini_cassandra().1,
        [3; 32],
    );
    write_manifest(
        "mini-2pc-coordinator-crash",
        || mini_2pc().0,
        mini_2pc().1,
        [4; 32],
    );
    write_manifest(
        "mini-leader-stepdown",
        || mini_leader_stepdown().0,
        mini_leader_stepdown().1,
        [5; 32],
    );
    write_manifest(
        "mini-membership-churn",
        || mini_membership_churn().0,
        mini_membership_churn().1,
        [6; 32],
    );
    write_manifest(
        "mini-hdfs-lease-expiry",
        || mini_hdfs_lease_expiry().0,
        mini_hdfs_lease_expiry().1,
        [7; 32],
    );
    // mini-kv is schedule-dependent: search finds the violating seed, then
    // a manifest persists for that exact seed.
    let mk_oracle = HistoryOracle::new(&MiniKvWorkload, KeyValueSpec::default());
    let cfg = RunConfig {
        seed: [0; 32],
        policy: Policy::Random,
        max_steps: 4096,
        ..RunConfig::default()
    };
    let finding = search(&MiniKvWorkload, &mk_oracle, cfg, 256)
        .unwrap()
        .expect("mini-kv stale read");
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
        extensions: BTreeMap::new(),
    };
    let bytes = manifest.to_canonical_bytes().expect("manifest encodes");
    std::fs::write("corpora/bug-corpus-v1/mini-kv-stale-read.ldgr", &bytes).unwrap();
    println!(
        "wrote corpora/bug-corpus-v1/mini-kv-stale-read.ldgr ({} bytes, root {})",
        bytes.len(),
        hex(&finding.run.journal.root_hash())
    );
    println!("generated 8 corpus-v1 manifest fixtures");
}
