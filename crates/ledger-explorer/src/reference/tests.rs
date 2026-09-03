use super::*;
use crate::search::Workload as _;
use ledger_format::EntryHash;
use ledger_sim::{Policy, RunConfig, Simulation};

fn run_with_seed(seed_byte: u8) -> (Journal, bool) {
    let (builders, oracle) = mini_raft();
    let config = RunConfig::builder()
        .seed(EntryHash([seed_byte; 32]))
        .policy(Policy::Random)
        .max_steps(4096)
        .build();
    let run = Simulation::with_tasks(config, builders).run().unwrap();
    let holds = oracle(&run.journal);
    (run.journal, holds)
}

#[test]
fn corpus_scenarios_all_reproduce_and_violate() {
    let scenarios = corpus_scenarios();
    assert_eq!(
        scenarios.len(),
        12,
        "the corpus-v1 registry holds 12 scenarios"
    );
    for scenario in &scenarios {
        let finding = scenario
            .reproduce()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            finding.verdict.violated,
            "{}: the canonical run must violate",
            scenario.name
        );
        assert!(
            !finding.run.journal.is_empty(),
            "{}: the canonical run must journal",
            scenario.name
        );
    }
}

#[test]
fn every_scenario_exposes_an_explicit_support_model() {
    // v1: evaluate each model on the scenario's own no-fault probe journal;
    // the expression ids are content hashes of that journal's entries.
    for scenario in corpus_scenarios() {
        let probe_seed = EntryHash([0u8; 32]);
        let journal = match &scenario.runner {
            CorpusRunner::Tasks { builders, .. } => {
                let config = RunConfig::builder()
                    .seed(probe_seed)
                    .policy(Policy::Random)
                    .max_steps(4096)
                    .build();
                Simulation::with_tasks(config, builders())
                    .run()
                    .unwrap_or_else(|error| panic!("{}: probe run failed: {error}", scenario.name))
                    .journal
            }
            CorpusRunner::MiniKv => {
                let config = RunConfig::builder()
                    .seed(probe_seed)
                    .policy(Policy::Random)
                    .max_steps(4096)
                    .build();
                Simulation::new(config, crate::workloads::MiniKvWorkload.programs())
                    .run()
                    .unwrap_or_else(|error| panic!("{}: probe run failed: {error}", scenario.name))
                    .journal
            }
        };
        let provider = scenario.support_provider(&journal);
        assert!(
            provider.version() >= 1,
            "{}: the support provider must carry a version",
            scenario.name
        );
        assert_support_shape(scenario.name, provider.expression());
        let again = scenario.support_provider(&journal);
        assert_eq!(
            provider.digest(),
            again.digest(),
            "{}: the provider digest must be deterministic",
            scenario.name
        );
    }
    // Fault-triggered v2: evaluate each model on the scenario's baseline
    // journal; the derived AllOf sets must be non-empty there.
    for scenario in super::faultdep_scenarios() {
        let baseline = scenario
            .baseline()
            .unwrap_or_else(|error| panic!("{}: baseline failed: {error}", scenario.name));
        let provider = scenario.support_provider(&baseline.journal);
        assert_eq!(
            provider.version(),
            super::faultdep::FAULTDEP_SUPPORT_VERSION,
            "{}: the faultdep provider must carry the faultdep version",
            scenario.name
        );
        assert_support_shape(scenario.name, provider.expression());
    }
}

/// Shared shape assertions for one declared support model.
fn assert_support_shape(name: &str, expression: &crate::support::SupportExpr) {
    match expression {
        crate::support::SupportExpr::AllOf(ids) => {
            assert!(!ids.is_empty(), "{name}: AllOf must be non-empty");
        }
        crate::support::SupportExpr::AnyOf(branches) => {
            assert!(!branches.is_empty(), "{name}: AnyOf must be non-empty");
        }
        crate::support::SupportExpr::Opaque => {}
    }
}

#[test]
fn mini_raft_double_leader_fires_for_some_seed() {
    let mut found: Option<u8> = None;
    let mut holds_for_seed = Vec::new();
    for seed in 0u8..64 {
        let (_, holds) = run_with_seed(seed);
        holds_for_seed.push((seed, holds));
        if !holds {
            found = Some(seed);
            break;
        }
    }
    assert!(
        found.is_some(),
        "mini_raft must violate single-leader per term for some seed 0..64, got: {holds_for_seed:?}"
    );
    let seed = found.unwrap();
    // Verify the triggering seed indeed has two leaders for term 2.
    let (journal, holds) = run_with_seed(seed);
    assert!(!holds, "seed {seed} must trigger double-leader");
    let outcomes: Vec<u64> = journal
        .entries()
        .filter_map(|e| match e.data.kind {
            ledger_format::EntryKind::Outcome => match &e.data.payload {
                ledger_format::EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: _,
                    value: ledger_format::CanonicalValue::Unsigned(v),
                }) => Some(*v),
                _ => None,
            },
            _ => None,
        })
        .collect();
    // Outcomes contain term 2 leader 0 and leader 2 at least.
    let term2_leaders: std::collections::HashSet<u64> = outcomes
        .iter()
        .filter(|v| *v / 10 == 2)
        .map(|v| v % 10)
        .collect();
    assert!(
        term2_leaders.len() > 1,
        "term 2 must have distinct leaders, got outcomes {outcomes:?} seed {seed}"
    );
}
