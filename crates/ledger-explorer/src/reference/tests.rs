use super::*;
use ledger_sim::{Policy, RunConfig, Simulation};

fn run_with_seed(seed_byte: u8) -> (Journal, bool) {
    let (builders, oracle) = mini_raft();
    let config = RunConfig::builder()
        .seed([seed_byte; 32])
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
                ledger_format::Payload::Number(v) => Some(*v),
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
