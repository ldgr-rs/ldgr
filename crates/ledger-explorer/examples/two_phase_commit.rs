//! Two-Phase Commit distributed transaction campaign example.

use ledger_explorer::oracle::AssertionOracle;
use ledger_explorer::search::run_campaign;
use ledger_explorer::workloads::TwoPhaseCommitWorkload;
use ledger_sim::{Policy, RunConfig};

fn main() {
    println!("=== Ledger Engine: Two-Phase Commit Exploration ===");
    let config = RunConfig::builder()
        .seed([100; 32])
        .policy(Policy::Bandit {
            exploration_constant: 1.414,
            pct_mix: ledger_sim::Probability::new(0.1).unwrap(),
        })
        .max_steps(256)
        .build();
    let workload = TwoPhaseCommitWorkload;
    let oracle = AssertionOracle;

    println!("Running 50-seed bandit campaign...");
    let report = run_campaign(&workload, &oracle, config, 50).unwrap();
    println!("Total runs: {}", report.runs_executed);
    println!("Distinct DAG root hashes: {}", report.distinct_roots);
    println!("Violations discovered: {}", report.findings.len());
    println!("Two-Phase Commit invariant verification complete.");
}
