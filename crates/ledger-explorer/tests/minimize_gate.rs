//! Minimization gate: at least 90% of entries removed off a failing
//! 10^6-entry run, violation preserved.
//!
//! The failing workload is a 10^6-entry journal whose violation depends on a
//! tiny causal slice: actor 0 journals a million causally-unrelated noise
//! `Set` entries while actor 1 journals `Set(42)`, `Assert(false)`. The
//! minimizer must (1) produce the failing run, (2) causal-slice from the
//! violating `Assert` entry, and (3) remove at least 90% of entries while the
//! slice still contains the failing assertion.

use ledger_explorer::causal_slice;
use ledger_explorer::oracle::{AssertionOracle, Oracle};
use ledger_sim::{Instruction, Policy, RunConfig, RunResult, Simulation};

/// Build the failing workload: one million noise entries plus a tiny failing
/// chain on a separate actor.
fn noise_plus_failing_programs() -> Vec<Vec<Instruction>> {
    let mut noise = Vec::with_capacity(1_000_001);
    for value in 0..1_000_000u64 {
        noise.push(Instruction::Set(value));
    }
    noise.push(Instruction::Done);
    vec![
        noise,
        vec![
            Instruction::Set(42),
            Instruction::Assert(false),
            Instruction::Done,
        ],
    ]
}

#[test]
fn minimize_removes_90_percent_of_a_million_entry_failure() {
    let programs = noise_plus_failing_programs();
    let config = RunConfig {
        seed: [1; 32],
        policy: Policy::Random,
        max_steps: 2_000_000,
        ..RunConfig::default()
    };

    let run = Simulation::new(config.clone(), programs)
        .run()
        .expect("the failing run must execute");
    let total_entries = run.journal.len();
    assert!(
        total_entries >= 1_000_000,
        "gate requires a 10^6-entry run, got {total_entries}"
    );

    let verdict = AssertionOracle.check(&run);
    assert!(
        verdict.violated,
        "the run must violate the assertion oracle"
    );
    assert_eq!(verdict.witnesses.len(), 1, "one violating Assert entry");
    let witness = verdict.witnesses[0];

    let slice = causal_slice(&run.journal, witness).expect("slice must succeed");
    assert!(
        !slice.is_empty(),
        "the causal slice of the witness must not be empty"
    );

    // The slice must preserve the violation: reconstruct a subgraph journal
    // and re-check the oracle on it.
    let sliced_journal = run
        .journal
        .subgraph(&slice)
        .expect("subgraph reconstruction must succeed");
    let sliced_run = RunResult {
        journal: sliced_journal,
        decisions: Vec::new(),
        trace: Vec::new(),
        registers: Vec::new(),
        steps: 0,
        monitor_issues: Vec::new(),
        applied_faults: Vec::new(),
    };
    let sliced_verdict = AssertionOracle.check(&sliced_run);
    assert!(
        sliced_verdict.violated,
        "the minimized slice must still violate the assertion oracle"
    );

    // At least 90% reduction.
    let reduction = (total_entries - slice.len()) as f64 / total_entries as f64 * 100.0;
    assert!(
        reduction >= 90.0,
        "gate requires >= 90% reduction, got {reduction:.1}% ({} -> {})",
        total_entries,
        slice.len()
    );
}
