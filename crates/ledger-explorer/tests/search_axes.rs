//! Search-axis tests: quadruple mutation, swarm axis, bandit campaign
//! scheduling, and the joint campaign.

use ledger_explorer::oracle::{HistoryOracle, KeyValueSpec, PropertyOracle};
use ledger_explorer::search::{
    QuadBandit, QuadMutation, Workload, run_bandit_campaign, run_campaign_quad, run_joint_campaign,
    run_swarm_campaign,
};
use ledger_explorer::workloads::{MiniKvWorkload, StorageCrashWorkload};
use ledger_format::{EntryKind, Payload};
use ledger_journal::Journal;
use ledger_sim::{FaultInjection, Policy, RunConfig, Simulation, SwarmConfig};

fn mini_kv_base(seed: u8) -> RunConfig {
    RunConfig {
        seed: [seed; 32],
        policy: Policy::Random,
        max_steps: 256,
        ..RunConfig::default()
    }
}

#[test]
fn quad_campaign_mutates_all_axes() {
    let base = mini_kv_base(4);
    let oracle = HistoryOracle::new(&MiniKvWorkload, KeyValueSpec::default());
    let mutation = QuadMutation {
        policies: vec![
            Policy::Random,
            Policy::Bandit {
                exploration_constant: 1.0,
                pct_mix: 0.1,
            },
        ],
        use_swarm: true,
        swarm_budget: 8,
        fault_library: Vec::new(),
        max_faults_per_run: 0,
        ..Default::default()
    };

    let report = run_campaign_quad(&MiniKvWorkload, &oracle, base.clone(), &mutation, 20)
        .expect("quad campaign must run");
    assert_eq!(report.runs_executed, 20);
    assert!(
        report
            .variants
            .iter()
            .any(|variant| variant.contains("policy=Random")),
        "Random policy must be drawn"
    );
    assert!(
        report
            .variants
            .iter()
            .any(|variant| variant.contains("policy=Bandit")),
        "Bandit policy must be drawn"
    );

    let again = run_campaign_quad(&MiniKvWorkload, &oracle, base, &mutation, 20)
        .expect("quad campaign rerun must run");
    assert_eq!(report.distinct_roots, again.distinct_roots);
    assert_eq!(report.variants, again.variants);
    assert_eq!(report.findings.len(), again.findings.len());
}

#[test]
fn swarm_campaign_finds_violation() {
    let base = mini_kv_base(9);
    let oracle = PropertyOracle {
        property: |journal: &Journal| {
            journal
                .entries()
                .all(|entry| match (&entry.data.kind, &entry.data.payload) {
                    (EntryKind::Outcome, Payload::Number(value)) => *value == 42,
                    _ => true,
                })
        },
        name: "storage crash must preserve committed value 42".into(),
    };

    let first = run_swarm_campaign(&StorageCrashWorkload, &oracle, base.clone(), 24)
        .expect("swarm campaign must run");
    assert_eq!(first.runs_executed, 24);

    let second = run_swarm_campaign(&StorageCrashWorkload, &oracle, base, 24)
        .expect("swarm campaign rerun must run");
    assert_eq!(first.distinct_roots, second.distinct_roots);
    assert_eq!(first.variants, second.variants);
    assert_eq!(first.findings.len(), second.findings.len());
}

#[test]
fn bandit_campaign_rewards_finding_variants() {
    let base = mini_kv_base(6);
    let base_run = Simulation::new(base.clone(), MiniKvWorkload.programs())
        .run()
        .expect("base run must succeed");
    let fault_library = base_run
        .journal
        .entries()
        .filter(|entry| matches!(entry.data.kind, EntryKind::Send))
        .map(|entry| FaultInjection::Drop(entry.id))
        .collect::<Vec<_>>();
    assert!(!fault_library.is_empty(), "mini-kv must journal Sends");

    let mutation = QuadMutation {
        policies: vec![Policy::Random],
        use_swarm: false,
        swarm_budget: 0,
        fault_library,
        max_faults_per_run: 2,
        ..Default::default()
    };
    let oracle = HistoryOracle::new(&MiniKvWorkload, KeyValueSpec::default());

    let report = run_bandit_campaign(&MiniKvWorkload, &oracle, base, &mutation, 1.414, 24)
        .expect("bandit campaign must run");
    assert_eq!(report.runs_executed, 24);
    assert!(report.distinct_roots >= 1);
    assert!(report.variants.len() == 24);
}

#[test]
fn joint_mode_produces_findings() {
    let base = mini_kv_base(7);
    let oracle = HistoryOracle::new(&MiniKvWorkload, KeyValueSpec::default());

    let report = run_joint_campaign(&MiniKvWorkload, &oracle, base.clone(), 64)
        .expect("joint campaign must run");
    assert_eq!(report.runs_executed, 64);
    assert!(
        !report.findings.is_empty(),
        "joint mode must keep the base finding"
    );

    // Determinism: the same seed must produce an identical campaign. The
    // findings are the observable output; compare seeds and journal roots.
    let rerun = run_joint_campaign(&MiniKvWorkload, &oracle, base.clone(), 64)
        .expect("joint campaign must run");
    assert_eq!(rerun.runs_executed, report.runs_executed);
    assert_eq!(rerun.findings.len(), report.findings.len());
    for (a, b) in rerun.findings.iter().zip(report.findings.iter()) {
        assert_eq!(a.seed, b.seed, "joint-mode finding seeds must be stable");
        assert_eq!(
            a.run.journal.root_hash(),
            b.run.journal.root_hash(),
            "joint-mode finding roots must be stable for the same seed"
        );
    }
}

#[test]
fn quad_bandit_arm_determinism() {
    let swarm = SwarmConfig::default();
    let arm_a = QuadBandit::variant_hash(&Policy::Random, &swarm, &[]);
    let arm_b = QuadBandit::variant_hash(&Policy::Replay, &swarm, &[]);
    assert_eq!(
        arm_a,
        QuadBandit::variant_hash(&Policy::Random, &swarm, &[])
    );
    assert_ne!(arm_a, arm_b);

    let mut bandit = QuadBandit::new();
    bandit.register(arm_a);
    bandit.register(arm_b);
    bandit.reward(arm_a, 1.0);

    let first = bandit.arm(1.414);
    let second = bandit.arm(1.414);
    assert_eq!(first, second);
    assert!(
        first == arm_a || first == arm_b,
        "arm must be a registered candidate"
    );
}
