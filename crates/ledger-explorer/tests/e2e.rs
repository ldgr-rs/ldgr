use ledger_explorer::ldfi::solve_with;
use ledger_explorer::minimizer::{causal_slice, minimize_schedule};
use ledger_explorer::oracle::{AssertionOracle, HistoryOracle, KeyValueSpec, Oracle};
use ledger_explorer::search::{Workload, diff, replay, run_campaign, search};
use ledger_explorer::solver::HittingSetSolver;
use ledger_explorer::workloads::{MiniKvWorkload, StorageCrashWorkload, TwoPhaseCommitWorkload};
use ledger_sim::{Policy, RunConfig};

#[test]
fn mini_kv_finds_and_reproduces_stale_read() {
    let config = RunConfig::builder()
        .seed([0; 32])
        .policy(Policy::Random)
        .max_steps(256)
        .dropped_events(Vec::new())
        .build();
    let workload = MiniKvWorkload;
    let oracle = HistoryOracle::new(&workload, KeyValueSpec::default());
    let finding = search(&workload, &oracle, config, 256)
        .unwrap()
        .expect("campaign should find planted race");

    assert!(finding.verdict.violated);
    assert!(!finding.verdict.witnesses.is_empty());

    let hypotheses = solve_with(
        &mut HittingSetSolver::new(),
        &finding.run.journal,
        &finding.verdict,
    )
    .expect("solve");
    assert!(!hypotheses.is_empty());

    let replayed = replay(&MiniKvWorkload, finding.seed, finding.run.decisions.clone()).unwrap();
    assert_eq!(
        finding.run.journal.root_hash(),
        replayed.journal.root_hash()
    );
    assert!(diff(&finding.run, &replayed).is_none());
}

#[test]
fn bandit_scheduler_discovers_diverse_journal_roots() {
    let config = RunConfig::builder()
        .seed([1; 32])
        .policy(Policy::Bandit {
            exploration_constant: 1.414,
            pct_mix: 0.1,
        })
        .max_steps(256)
        .dropped_events(Vec::new())
        .build();
    let workload = MiniKvWorkload;
    let oracle = HistoryOracle::new(&workload, KeyValueSpec::default());

    let report = run_campaign(&workload, &oracle, config, 30).unwrap();
    assert_eq!(report.runs_executed, 30);
    assert!(report.distinct_roots >= 2);
}

#[test]
fn two_phase_commit_passes_assertion_oracle() {
    let config = RunConfig::builder()
        .seed([2; 32])
        .policy(Policy::Random)
        .max_steps(256)
        .dropped_events(Vec::new())
        .build();
    let workload = TwoPhaseCommitWorkload;
    let oracle = AssertionOracle;

    let report = run_campaign(&workload, &oracle, config, 20).unwrap();
    assert_eq!(report.runs_executed, 20);
    assert!(report.findings.is_empty());
}

#[test]
fn storage_crash_consistency_preserves_fsynced_state() {
    let config = RunConfig::builder()
        .seed([3; 32])
        .policy(Policy::Random)
        .max_steps(64)
        .dropped_events(Vec::new())
        .build();
    let workload = StorageCrashWorkload;
    let oracle = AssertionOracle;

    let run = ledger_sim::Simulation::new(config, workload.programs())
        .run()
        .unwrap();
    assert_eq!(run.registers[0], 42);
    assert!(!oracle.check(&run).violated);
}

#[test]
fn causal_slice_preserves_witness_provenance() {
    let config = RunConfig::builder()
        .seed([0; 32])
        .policy(Policy::Random)
        .max_steps(256)
        .dropped_events(Vec::new())
        .build();
    let workload = MiniKvWorkload;
    let oracle = HistoryOracle::new(&workload, KeyValueSpec::default());
    let finding = search(&workload, &oracle, config, 256).unwrap().unwrap();

    let witness = finding.verdict.witnesses[0];
    let slice_hashes = causal_slice(&finding.run.journal, witness).unwrap();
    assert!(!slice_hashes.is_empty());
    assert!(slice_hashes.contains(&witness));

    let subgraph = finding.run.journal.subgraph(&slice_hashes).unwrap();
    assert_eq!(subgraph.len(), slice_hashes.len());
}

#[test]
fn schedule_minimizer_reduces_decision_sequence() {
    let config = RunConfig::builder()
        .seed([0; 32])
        .policy(Policy::Random)
        .max_steps(256)
        .dropped_events(Vec::new())
        .build();
    let workload = MiniKvWorkload;
    let oracle = HistoryOracle::new(&workload, KeyValueSpec::default());
    let finding = search(&workload, &oracle, config, 256).unwrap().unwrap();

    let report = minimize_schedule(&finding.run.decisions, |decisions| {
        let replayed = replay(&workload, finding.seed, decisions.to_vec());
        replayed
            .as_ref()
            .map(|run| oracle.check(run).violated)
            .unwrap_or(false)
    });

    assert!(report.minimized_count <= report.original_count);
    assert!(report.reduction_percent >= 0.0);
}

#[test]
fn same_seed_produces_identical_journal_root() {
    let config = RunConfig::builder()
        .seed([42; 32])
        .policy(Policy::Random)
        .max_steps(100)
        .build();
    let w = MiniKvWorkload;
    let r1 = ledger_sim::Simulation::new(config.clone(), w.programs())
        .run()
        .unwrap();
    let r2 = ledger_sim::Simulation::new(config, w.programs())
        .run()
        .unwrap();

    assert_eq!(r1.journal.root_hash(), r2.journal.root_hash());
    assert_eq!(r1.decisions, r2.decisions);
}
