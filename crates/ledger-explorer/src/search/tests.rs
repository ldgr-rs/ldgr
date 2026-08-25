use super::input_axis::{INPUT_AXIS_SAMPLE, draw_inputs};
use super::*;
use crate::monitor::{MonitorOracle, OnlineMonitor, SafetyMonitor};
use crate::oracle::{HistoryOperation, HistoryOracle, KeyValueSpec, PropertyOracle, Verdict};
use crate::pbt::{EnergyDistribution, InputsWorkload};
use crate::solver_state::load as load_solver_state;
use crate::workloads::MiniKvWorkload;
use ledger_format::{EntryKind, Payload};
use ledger_journal::Journal;
use ledger_sim::{Instruction, Policy, RunConfig, RunResult, SeedTree, SimFault};

/// Workload whose behavior depends on the first input value.
///
/// The producer stores each input in a task-local register via `Input`
/// steps; the final outcome registers the count of even inputs.
struct InputSensitiveWorkload;

impl Workload for InputSensitiveWorkload {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        vec![vec![
            Instruction::Set(0),
            Instruction::Outcome,
            Instruction::Done,
        ]]
    }

    fn history(&self, _run: &RunResult) -> Vec<HistoryOperation> {
        Vec::new()
    }

    fn with_inputs(&self, inputs: &[u64]) -> Box<dyn Workload> {
        let generator = crate::pbt::gen_id("input-sensitive");
        let mut program = Vec::with_capacity(inputs.len() + 2);
        for (index, value) in inputs.iter().enumerate() {
            program.push(Instruction::Input {
                generator,
                replay: index as u64,
                value: *value,
            });
        }
        program.push(Instruction::Outcome);
        program.push(Instruction::Done);
        Box::new(InputsWorkload::new(vec![program]))
    }
}

fn journal_contains_input_value(run: &RunResult, target: u64) -> bool {
    run.journal.entries().any(|entry| {
        matches!(entry.data.kind, EntryKind::InputStep { .. })
            && matches!(&entry.data.payload, Payload::Number(value) if *value == target)
    })
}

#[test]
fn search_input_finds_violation_only_for_specific_input_sample() {
    let base = RunConfig::builder()
        .seed([5; 32])
        .policy(Policy::Random)
        .max_steps(512)
        .build();
    let workload = InputSensitiveWorkload;
    let oracle = PropertyOracle {
        property: |journal: &Journal| {
            !journal.entries().any(|entry| {
                matches!(entry.data.kind, EntryKind::InputStep { .. })
                    && matches!(&entry.data.payload, Payload::Number(42))
            })
        },
        name: "no input value equals 42".into(),
    };

    let finding = search_input(&workload, &oracle, base.clone(), "input-sensitive", 64)
        .unwrap()
        .expect("a specific input sample must violate the oracle");
    assert!(finding.verdict.violated);
    assert!(
        journal_contains_input_value(&finding.run, 42),
        "the violating sample must journal the triggering input"
    );

    let again = search_input(&workload, &oracle, base.clone(), "input-sensitive", 64)
        .unwrap()
        .expect("deterministic search must find the same violation");
    assert_eq!(finding.seed, again.seed);
    assert_eq!(
        finding.run.journal.root_hash(),
        again.run.journal.root_hash()
    );
}

fn swarm_knob(variant: &str, knob: &str) -> f64 {
    variant
        .split(&format!("{knob}="))
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .expect("variant must carry the knob")
}

#[test]
fn swarm_axis_distribution_matches_across_campaign_types() {
    let base = RunConfig::builder()
        .seed([3; 32])
        .policy(Policy::Random)
        .max_steps(256)
        .build();
    let mutation = QuadMutation {
        policies: vec![Policy::Random],
        use_swarm: true,
        swarm_budget: SWARM_CAMPAIGN_MAX_DELAY_BUDGET,
        fault_library: Vec::new(),
        max_faults_per_run: 0,
        ..Default::default()
    };
    let oracle = PropertyOracle {
        property: |_journal: &Journal| true,
        name: "always passes".into(),
    };

    let quad = run_campaign_quad(&InputSensitiveWorkload, &oracle, base.clone(), &mutation, 8)
        .expect("quad campaign must run");
    let swarm = run_swarm_campaign(&InputSensitiveWorkload, &oracle, base, 8)
        .expect("swarm campaign must run");

    for variant in quad.variants.iter().chain(swarm.variants.iter()) {
        assert!(
            swarm_knob(variant, "crash") <= SWARM_CRASH_CEILING,
            "crash draws must respect the shared ceiling: {variant}"
        );
        assert_eq!(
            swarm_knob(variant, "classes") as usize,
            SWARM_FAULT_CLASSES_PER_RUN,
            "fault-class budget must match the shared constant: {variant}"
        );
        assert!(
            swarm_knob(variant, "max_delay") <= SWARM_CAMPAIGN_MAX_DELAY_BUDGET as f64,
            "max-delay draws must respect the shared budget: {variant}"
        );
    }
}

#[test]
fn input_axis_draws_distinct_values_per_attempt_seed() {
    let base = RunConfig::builder().seed([9; 32]).build();
    let first = draw_inputs(
        "quad-test",
        SeedTree::new(base.seed()).derive("quad-input/0"),
        None,
    )
    .expect("uniform draw must succeed");
    let second = draw_inputs(
        "quad-test",
        SeedTree::new(base.seed()).derive("quad-input/1"),
        None,
    )
    .expect("uniform draw must succeed");
    assert_eq!(first.len(), INPUT_AXIS_SAMPLE);
    assert_eq!(second.len(), INPUT_AXIS_SAMPLE);
    assert_ne!(
        first, second,
        "each attempt must draw a fresh, independent input sequence"
    );
}

#[test]
fn input_axis_propagates_invalid_energy_exponent() {
    let base = RunConfig::builder().seed([9; 32]).build();
    let result = draw_inputs(
        "quad-test",
        SeedTree::new(base.seed()).derive("quad-input/0"),
        Some(&EnergyDistribution::Power { exponent: 0.0 }),
    );
    assert!(
        result.is_err(),
        "an invalid exponent must surface as a campaign error, not a panic"
    );
}

#[test]
fn quad_campaign_mutates_input_axis_with_the_other_three() {
    let base = RunConfig::builder()
        .seed([9; 32])
        .policy(Policy::Random)
        .max_steps(256)
        .build();
    let mutation = QuadMutation {
        policies: vec![Policy::Random],
        use_swarm: true,
        swarm_budget: SWARM_CAMPAIGN_MAX_DELAY_BUDGET,
        fault_library: Vec::new(),
        max_faults_per_run: 0,
        input_generator: Some("quad-test".into()),
        input_energy: None,
    };
    let oracle = PropertyOracle {
        property: |_journal: &Journal| true,
        name: "always passes".into(),
    };

    let report = run_campaign_quad(&InputSensitiveWorkload, &oracle, base.clone(), &mutation, 8)
        .expect("quad campaign must run");
    assert_eq!(report.runs_executed, 8);
    assert!(
        report
            .variants
            .iter()
            .any(|variant| variant.contains("input=quad-input/0"))
            && report
                .variants
                .iter()
                .any(|variant| variant.contains("input=quad-input/7")),
        "each attempt must report its per-attempt input stream label"
    );

    let rerun = run_campaign_quad(&InputSensitiveWorkload, &oracle, base, &mutation, 8)
        .expect("quad campaign rerun must run");
    assert_eq!(report.variants, rerun.variants);
    assert_eq!(report.distinct_roots, rerun.distinct_roots);
    assert_eq!(report.findings.len(), rerun.findings.len());
}

#[test]
fn bandit_campaign_mutates_input_axis() {
    let base = RunConfig::builder()
        .seed([11; 32])
        .policy(Policy::Random)
        .max_steps(256)
        .build();
    let mutation = QuadMutation {
        policies: vec![Policy::Random],
        use_swarm: false,
        swarm_budget: 0,
        fault_library: Vec::new(),
        max_faults_per_run: 0,
        input_generator: Some("quad-bandit-test".into()),
        input_energy: None,
    };
    let oracle = PropertyOracle {
        property: |_journal: &Journal| true,
        name: "always passes".into(),
    };

    let report = run_bandit_campaign(
        &InputSensitiveWorkload,
        &oracle,
        base.clone(),
        &mutation,
        1.414,
        8,
    )
    .expect("bandit campaign must run");
    assert_eq!(report.runs_executed, 8);
    assert!(
        report
            .variants
            .iter()
            .any(|variant| variant.contains("input=bandit-input/0")),
        "the bandit must report the per-attempt input stream label"
    );

    let rerun = run_bandit_campaign(&InputSensitiveWorkload, &oracle, base, &mutation, 1.414, 8)
        .expect("bandit campaign rerun must run");
    assert_eq!(report.variants, rerun.variants);
    assert_eq!(report.distinct_roots, rerun.distinct_roots);
}

#[test]
fn quad_campaign_with_power_energy_reruns_equal_variants() {
    let base = RunConfig::builder()
        .seed([13; 32])
        .policy(Policy::Random)
        .max_steps(256)
        .build();
    let mutation = QuadMutation {
        policies: vec![Policy::Random],
        use_swarm: false,
        swarm_budget: 0,
        fault_library: Vec::new(),
        max_faults_per_run: 0,
        input_generator: Some("quad-power".into()),
        input_energy: Some(EnergyDistribution::Power { exponent: 2.0 }),
    };
    let oracle = PropertyOracle {
        property: |_journal: &Journal| true,
        name: "always passes".into(),
    };
    let first = run_campaign_quad(&InputSensitiveWorkload, &oracle, base.clone(), &mutation, 8)
        .expect("quad campaign must run");
    let second = run_campaign_quad(&InputSensitiveWorkload, &oracle, base, &mutation, 8)
        .expect("quad campaign rerun must run");
    assert_eq!(first.variants, second.variants);
    assert_eq!(first.distinct_roots, second.distinct_roots);
    assert_eq!(first.findings.len(), second.findings.len());
}

// Feedback reproduction tests.

struct KvVariant {
    fw: u64,
    direct: u64,
}

impl Workload for KvVariant {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        vec![
            vec![
                Instruction::Send {
                    to: 1,
                    payload: self.fw,
                },
                Instruction::SendTimed {
                    to: 2,
                    payload: self.direct,
                    delay: 10,
                },
                Instruction::Done,
            ],
            vec![
                Instruction::Receive,
                Instruction::Send {
                    to: 2,
                    payload: self.fw,
                },
                Instruction::Done,
            ],
            vec![
                Instruction::Receive,
                Instruction::Outcome,
                Instruction::Done,
            ],
        ]
    }

    fn history(&self, _run: &RunResult) -> Vec<HistoryOperation> {
        Vec::new()
    }
}

fn kv_oracle(fw: u64) -> PropertyOracle<impl Fn(&Journal) -> bool> {
    PropertyOracle {
        property: move |journal: &Journal| {
            let outcome = journal
                .entries()
                .filter(|entry| entry.data.kind == EntryKind::Outcome)
                .find_map(|entry| match &entry.data.payload {
                    Payload::Number(value) => Some(*value),
                    _ => None,
                });
            outcome == Some(fw)
        },
        name: format!("outcome == {fw}"),
    }
}

fn parse_variant_field(variant: &str, field: &str) -> Option<usize> {
    variant
        .split(&format!("{field}="))
        .nth(1)?
        .split_whitespace()
        .next()?
        .split(',')
        .next()?
        .parse()
        .ok()
}

#[test]
fn feedback_campaign_reproduces_violation_and_reports_escalation() {
    let workload = KvVariant {
        fw: 42,
        direct: 100,
    };
    let oracle = kv_oracle(42);
    // Fault-dependent: base carries the triggering partition so Phase 0 finds quickly.
    let base = RunConfig::builder()
        .seed([17; 32])
        .policy(Policy::Random)
        .max_steps(512)
        .fault_schedule(vec![SimFault::Partition { src: 1, dst: 2 }])
        .build();
    let report =
        run_feedback_campaign(&workload, &oracle, base, 8).expect("feedback campaign must run");
    assert!(
        !report.findings.is_empty(),
        "feedback must reproduce at least one violation"
    );
    assert!(
        report
            .variants
            .iter()
            .any(|variant| variant.contains("round=")),
        "variants must describe rounds"
    );
    assert!(
        report
            .variants
            .iter()
            .any(|variant| variant.contains("applied=") && variant.contains("voided=")),
        "variants must report applied/voided counts"
    );
    // At least one variant must carry escalated info (even if none, string contains escalated=)
    assert!(
        report
            .variants
            .iter()
            .any(|variant| variant.contains("escalated=")),
        "variants must report escalated ladder"
    );
    assert!(
        report.runs_executed >= report.findings.len(),
        "runs must count executed replays"
    );
}

#[test]
fn feedback_voided_faults_shrink_schedule() {
    let workload = KvVariant {
        fw: 42,
        direct: 100,
    };
    let oracle = kv_oracle(42);
    let base = RunConfig::builder()
        .seed([17; 32])
        .policy(Policy::Random)
        .max_steps(512)
        .fault_schedule(vec![SimFault::Partition { src: 1, dst: 2 }])
        .build();
    let report =
        run_feedback_campaign(&workload, &oracle, base, 6).expect("feedback campaign must run");
    let feedback_variants: Vec<&String> = report
        .variants
        .iter()
        .filter(|variant| variant.starts_with("round="))
        .collect();
    assert!(
        !feedback_variants.is_empty(),
        "need at least one feedback round: {feedback_variants:?}"
    );
    if feedback_variants.len() >= 2 {
        let first_applied = parse_variant_field(feedback_variants[0], "applied").unwrap_or(0);
        let first_voided = parse_variant_field(feedback_variants[0], "voided").unwrap_or(0);
        let first_suppressed = parse_variant_field(feedback_variants[0], "suppressed").unwrap_or(0);
        let last_applied =
            parse_variant_field(feedback_variants.last().expect("at least one"), "applied")
                .unwrap_or(0);
        let last_voided =
            parse_variant_field(feedback_variants.last().expect("at least one"), "voided")
                .unwrap_or(0);
        let last_suppressed = parse_variant_field(
            feedback_variants.last().expect("at least one"),
            "suppressed",
        )
        .unwrap_or(0);
        let shrink = last_applied < first_applied
            || last_voided < first_voided
            || last_suppressed > first_suppressed;
        assert!(
            shrink,
            "later round must show fewer applied/voided or larger suppressed: first applied={first_applied} voided={first_voided} suppressed={first_suppressed} last applied={last_applied} voided={last_voided} suppressed={last_suppressed} variants={feedback_variants:?}"
        );
    } else {
        // Single round still demonstrates voided feedback via suppressed growth.
        let first_voided = parse_variant_field(feedback_variants[0], "voided").unwrap_or(0);
        let first_suppressed = parse_variant_field(feedback_variants[0], "suppressed").unwrap_or(0);
        assert!(
            first_voided > 0 || first_suppressed > 0,
            "single round must still report voided or suppressed to prove loop: {feedback_variants:?}"
        );
    }
}

#[test]
fn feedback_campaign_is_deterministic() {
    let workload = KvVariant {
        fw: 42,
        direct: 100,
    };
    let oracle = kv_oracle(42);
    let base = RunConfig::builder()
        .seed([17; 32])
        .policy(Policy::Random)
        .max_steps(512)
        .fault_schedule(vec![SimFault::Partition { src: 1, dst: 2 }])
        .build();
    let first = run_feedback_campaign(&workload, &oracle, base.clone(), 8).expect("first run");
    let second = run_feedback_campaign(&workload, &oracle, base, 8).expect("second run");
    assert_eq!(
        first.variants, second.variants,
        "variants must be deterministic"
    );
    assert_eq!(
        first.runs_executed, second.runs_executed,
        "runs_executed must be deterministic"
    );
    assert_eq!(
        first.distinct_roots, second.distinct_roots,
        "distinct roots must be deterministic"
    );
    let first_roots: Vec<_> = first
        .findings
        .iter()
        .map(|finding| finding.run.journal.root_hash())
        .collect();
    let second_roots: Vec<_> = second
        .findings
        .iter()
        .map(|finding| finding.run.journal.root_hash())
        .collect();
    assert_eq!(
        first_roots, second_roots,
        "finding roots must be deterministic"
    );
}

// Monitor-campaign wiring (A1) and coverage export (A5).

/// Single-actor workload whose outcome payload is fixed at construction.
struct OutcomeWorkload(u64);

impl Workload for OutcomeWorkload {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        vec![vec![
            Instruction::Set(self.0),
            Instruction::Outcome,
            Instruction::Done,
        ]]
    }

    fn history(&self, _run: &RunResult) -> Vec<HistoryOperation> {
        Vec::new()
    }
}

fn outcome_halt_monitor(payload: u64) -> Box<dyn OnlineMonitor> {
    Box::new(SafetyMonitor::new(
        move |entry: &ledger_journal::Entry| {
            if entry.data.kind == EntryKind::Outcome {
                !matches!(&entry.data.payload, Payload::Number(value) if *value == payload)
            } else {
                true
            }
        },
        format!("outcome {payload} forbidden"),
    ))
}

#[test]
fn monitored_campaign_records_names_and_prefixes_monitor_reasons() {
    let base = RunConfig::builder()
        .seed([21; 32])
        .policy(Policy::Random)
        .max_steps(128)
        .build();
    let user_oracle = PropertyOracle {
        property: |_journal: &Journal| true,
        name: "always passes".into(),
    };
    let monitors: Vec<Box<dyn OnlineMonitor>> = vec![
        outcome_halt_monitor(99),
        Box::new(SafetyMonitor::new(
            |_: &ledger_journal::Entry| true,
            "never halts",
        )),
    ];

    let report = run_monitored_campaign(
        &OutcomeWorkload(99),
        &user_oracle,
        base.clone(),
        monitors,
        3,
    )
    .expect("monitored campaign must run");
    assert_eq!(report.runs_executed, 3);
    assert_eq!(report.findings.len(), 3, "every run carries outcome 99");
    assert_eq!(
        report.monitors,
        vec!["safety".to_string(), "safety".to_string()],
        "monitor names must be listed in attach order"
    );
    for finding in &report.findings {
        assert!(finding.verdict.violated);
        assert!(
            finding.verdict.reason.contains("monitor: safety"),
            "monitor-caused reason must carry the monitor: prefix and name: {}",
            finding.verdict.reason
        );
        assert!(
            finding.verdict.reason.contains("outcome 99 forbidden"),
            "the halt message must survive the merge: {}",
            finding.verdict.reason
        );
        assert!(
            !finding.verdict.witnesses.is_empty(),
            "the halted entry must witness the violation"
        );
    }

    // A clean workload under the same monitors must produce no findings.
    let monitors: Vec<Box<dyn OnlineMonitor>> = vec![outcome_halt_monitor(99)];
    let clean = run_monitored_campaign(&OutcomeWorkload(7), &user_oracle, base, monitors, 2)
        .expect("clean monitored campaign must run");
    assert!(clean.findings.is_empty());
    assert_eq!(clean.monitors, vec!["safety".to_string()]);
}

#[test]
fn compose_oracle_feeds_run_campaign_on_violating_workload() {
    use crate::oracle::compose_oracles;

    let base = RunConfig::builder()
        .seed([22; 32])
        .policy(Policy::Random)
        .max_steps(128)
        .build();
    // User oracle passes; only the monitor side violates.
    let passing = PropertyOracle {
        property: |_journal: &Journal| true,
        name: "always passes".into(),
    };
    let mut monitor_oracle = MonitorOracle::new();
    monitor_oracle = monitor_oracle.with_monitor(outcome_halt_monitor(99));
    let composed = compose_oracles(vec![Box::new(passing), Box::new(monitor_oracle)]);

    let report = crate::search::run_campaign(&OutcomeWorkload(99), &composed, base, 2)
        .expect("campaign with a composed oracle must run");
    assert_eq!(report.runs_executed, 2);
    assert_eq!(
        report.findings.len(),
        2,
        "the composite must fire when any sub-oracle fires"
    );
    for finding in &report.findings {
        assert!(finding.verdict.violated);
        assert!(
            finding.verdict.reason.contains("outcome 99 forbidden"),
            "the composite must merge the violating sub-oracle's reason"
        );
    }
}

#[test]
fn campaign_report_renders_ndjson_coverage_records() {
    use crate::certs::hash_to_hex;

    let mut journal = Journal::new();
    journal
        .append(EntryKind::Outcome, 1, [], Payload::Number(5))
        .expect("append must succeed");
    let root_hex = hash_to_hex(&journal.root_hash());
    let run = RunResult {
        journal_error: None,
        journal,
        decisions: Vec::new(),
        trace: Vec::new(),
        registers: Vec::new(),
        steps: 0,
        monitor_issues: Vec::new(),
        applied_faults: Vec::new(),
        origins: Vec::new(),
    };
    let report = CampaignReport {
        runs_executed: 9,
        distinct_roots: 4,
        findings: vec![Finding {
            seed: [3u8; 32],
            run,
            verdict: Verdict::fail(vec![[3u8; 32]], "test"),
        }],
        variants: Vec::new(),
        monitors: Vec::new(),
        memo_hits: 0,
    };

    let records = report.to_coverage_records();
    let lines: Vec<&str> = records.lines().collect();
    assert_eq!(lines.len(), 2, "one finding record plus one summary line");
    assert_eq!(
        lines[0],
        format!("{{\"root_hex\":\"{root_hex}\",\"run_index\":0,\"finding\":true}}")
    );
    assert_eq!(lines[1], "# runs=9 distinct=4");

    // An empty report renders only the summary line.
    let empty = CampaignReport {
        runs_executed: 6,
        distinct_roots: 6,
        findings: Vec::new(),
        variants: Vec::new(),
        monitors: Vec::new(),
        memo_hits: 0,
    };
    assert_eq!(empty.to_coverage_records(), "# runs=6 distinct=6\n");
}

// Joint memo hits and feedback solver-state persistence (A2, A4).

#[test]
fn joint_campaign_second_stateful_run_hits_memo_for_identical_rounds() {
    crate::solver_cache::global_clear();
    let base = RunConfig::builder()
        .seed([7; 32])
        .policy(Policy::Random)
        .max_steps(256)
        .build();
    let oracle = HistoryOracle::new(&MiniKvWorkload, KeyValueSpec::default());
    let mut state = CampaignPersist::new();

    let first =
        run_joint_campaign_with_state(&MiniKvWorkload, &oracle, base.clone(), 16, Some(&mut state))
            .expect("first joint campaign must run");
    assert_eq!(first.runs_executed, 16);
    assert_eq!(first.memo_hits, 0, "a fresh memo has no entries to hit");
    let first_joint_rounds = first
        .variants
        .iter()
        .filter(|variant| variant.contains("policy=joint-perturbed"))
        .count();

    let second =
        run_joint_campaign_with_state(&MiniKvWorkload, &oracle, base, 16, Some(&mut state))
            .expect("second joint campaign must run");
    assert_eq!(
        second.variants.len(),
        first.variants.len(),
        "identical reruns must produce identical variant counts"
    );
    assert_eq!(
        second.memo_hits, first_joint_rounds,
        "every replayed round of the rerun must hit the shared memo"
    );
    assert_eq!(
        second.distinct_roots, first.distinct_roots,
        "memo-cached roots must reproduce the distinct-root set"
    );
    assert_eq!(second.runs_executed, 16);
}

#[test]
fn feedback_campaign_with_state_matches_plain_and_persists_artifacts() {
    crate::solver_cache::global_clear();
    let workload = KvVariant {
        fw: 42,
        direct: 100,
    };
    let oracle = kv_oracle(42);
    let base = RunConfig::builder()
        .seed([17; 32])
        .policy(Policy::Random)
        .max_steps(512)
        .fault_schedule(vec![SimFault::Partition { src: 1, dst: 2 }])
        .build();

    let plain = run_feedback_campaign(&workload, &oracle, base.clone(), 8)
        .expect("plain feedback campaign must run");

    let mut state = CampaignPersist::new();
    let stateful =
        run_feedback_campaign_with_state(&workload, &oracle, base.clone(), 8, Some(&mut state))
            .expect("stateful feedback campaign must run");
    assert_eq!(
        stateful.variants, plain.variants,
        "solver-state resume must not change campaign decisions"
    );
    assert_eq!(stateful.runs_executed, plain.runs_executed);
    assert_eq!(stateful.distinct_roots, plain.distinct_roots);
    let plain_roots: Vec<_> = plain
        .findings
        .iter()
        .map(|finding| finding.run.journal.root_hash())
        .collect();
    let stateful_roots: Vec<_> = stateful
        .findings
        .iter()
        .map(|finding| finding.run.journal.root_hash())
        .collect();
    assert_eq!(
        plain_roots, stateful_roots,
        "finding roots must be identical with persisted solver state"
    );

    // A second stateful campaign over the same handle resumes the stored
    // artifacts and stays byte-identical to the plain path.
    let rerun = run_feedback_campaign_with_state(&workload, &oracle, base, 8, Some(&mut state))
        .expect("rerun with resumed state must run");
    assert_eq!(rerun.variants, plain.variants);
    assert_eq!(rerun.distinct_roots, plain.distinct_roots);

    let artifacts = load_solver_state(&state.journal).expect("stored artifacts must decode");
    assert!(
        !artifacts.is_empty(),
        "the campaign must persist solver state into the internal journal"
    );
}
