//! Composed minimization pipeline gate: causal slice, event ddmin, and
//! schedule-delta debugging over the mini-KV stale read.

use ledger_explorer::minimizer::minimize_full;
use ledger_explorer::oracle::{HistoryOracle, KeyValueSpec, Oracle};
use ledger_explorer::search::search;
use ledger_explorer::workloads::MiniKvWorkload;
use ledger_sim::{Policy, RunConfig, RunResult};

#[test]
fn full_pipeline_minimizes_stale_read_and_preserves_violation() {
    let config = RunConfig {
        seed: [0; 32],
        policy: Policy::Random,
        max_steps: 256,
        ..RunConfig::default()
    };
    let workload = MiniKvWorkload;
    let oracle = HistoryOracle::new(&workload, KeyValueSpec::default());
    let finding = search(&workload, &oracle, config, 256)
        .expect("search must run")
        .expect("campaign should find the planted stale read");

    let repro =
        minimize_full(&workload, &oracle, &finding, "").expect("the pipeline must complete");

    assert!(
        !repro.journal.is_empty(),
        "the minimized repro journal must not be empty"
    );
    assert!(
        repro.slice_kept < repro.slice_total,
        "the causal slice must drop entries: kept {} of {}",
        repro.slice_kept,
        repro.slice_total
    );
    assert!(
        repro.violations_preserved,
        "the pipeline must preserve the oracle violation"
    );
    assert!(
        repro.decisions.len() <= finding.run.decisions.len(),
        "schedule minimization must not grow the decision sequence"
    );

    let run = RunResult {
        journal: repro.journal.clone(),
        decisions: Vec::new(),
        trace: Vec::new(),
        registers: Vec::new(),
        steps: 0,
        monitor_issues: Vec::new(),
        applied_faults: Vec::new(),
    };
    assert!(
        oracle.check(&run).violated,
        "the final repro journal must still violate the history oracle"
    );
}
