//! PBT-in-sim corpus gate: planted falsifying inputs found by the input
//! axis.
//!
//! Six input-triggered planted workloads across the three documented
//! property classes (exactly-once, quorum/consistency, linearizability)
//! plus one joint (input, fault) plant. Each scenario:
//!
//! 1. holds under a non-triggering input vector (negative precondition);
//! 2. is found by `search_input` within the declared budget at the pinned
//!    search seed;
//! 3. reproduces bit-exactly under strict replay of the recovered inputs
//!    (the finding pins input and schedule jointly);
//! 4. survives `minimize_input` with the planted trigger values retained;
//! 5. for the joint scenario, requires BOTH the trigger input and the
//!    injected crash fault, so neither axis alone violates.
//!
//! A negative control proves non-vacuity: a sanitized workload that can
//! never violate must NOT be found within the same budget.
//!
//! The scenario table lives in this gate (the only consumer). The bug-corpus
//! registries stay in `reference`; PBT workloads need `&'static` templates
//! for borrowed-history oracles, and their manifests pin the FINDING run
//! (seed, root, entry count) under `corpora/pbt-corpus/`.

use ledger_explorer::minimizer::minimize_input_with_faults;
use ledger_explorer::oracle::{
    ExactlyOnceValueOracle, HistoryOracle, KeyValueSpec, Oracle, PropertyOracle,
};
use ledger_explorer::pbt::gen_id;
use ledger_explorer::search::{Workload, search_input};
use ledger_format::EntryHash;
use ledger_format::{EntryKind, RunManifest};
use ledger_journal::Journal;
use ledger_sim::{Instruction, RunConfig, RunResult, Simulation};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const BUDGET: usize = 64;
const TRIGGER: u64 = 42;

/// A workload whose program is the closure over the generated inputs.
struct ProgramsWorkload(Vec<Vec<Instruction>>);
impl Workload for ProgramsWorkload {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        self.0.clone()
    }
    fn history(&self, _run: &RunResult) -> Vec<ledger_explorer::oracle::HistoryOperation> {
        Vec::new()
    }
}

/// A unit template carrying the scenario's generator label:
/// `with_inputs` builds the whole program under `gen/<label>`.
struct Template(&'static str);
impl Workload for Template {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        Vec::new()
    }
    fn with_inputs(&self, inputs: &[u64]) -> Box<dyn Workload> {
        Box::new(program_for(inputs, self.0))
    }
    fn history(&self, _run: &RunResult) -> Vec<ledger_explorer::oracle::HistoryOperation> {
        Vec::new()
    }
}

/// The linearizability template: a borrowed-history oracle needs a
/// `'static` workload.
struct LinTemplate(&'static str);
impl Workload for LinTemplate {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        Vec::new()
    }
    fn with_inputs(&self, inputs: &[u64]) -> Box<dyn Workload> {
        Box::new(program_for(&inputs[..inputs.len().min(8)], self.0))
    }
    /// The planted bug: with the trigger value in the writes, the workload
    /// serves a read of a value that was never written, so the sequential
    /// key-value check fails.
    fn history(&self, run: &RunResult) -> Vec<ledger_explorer::oracle::HistoryOperation> {
        let inputs = journal_input_values(&run.journal);
        let mut ops = Vec::new();
        for value in &inputs {
            ops.push(ledger_explorer::oracle::HistoryOperation::Write {
                key: "cfg".into(),
                value: *value,
                witness: input_witness(&run.journal, *value),
            });
        }
        if let Some(last) = inputs.last().copied()
            && inputs.contains(&TRIGGER)
        {
            ops.push(ledger_explorer::oracle::HistoryOperation::Read {
                key: "cfg".into(),
                value: 99,
                witness: input_witness(&run.journal, last),
            });
        }
        ops
    }
}

/// The joint plant's template: the leading `FsWrite` precedes every input,
/// so its entry id is input-independent and the pinned crash fault applies
/// on every attempt.
struct JointTemplate(&'static str);
impl Workload for JointTemplate {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        Vec::new()
    }
    fn with_inputs(&self, inputs: &[u64]) -> Box<dyn Workload> {
        let mut program = vec![Instruction::FsWrite {
            path: "promote".into(),
            value: 7,
        }];
        let mut inner = program_for(inputs, self.0);
        program.extend(inner.0.remove(0));
        Box::new(ProgramsWorkload(vec![program]))
    }
    fn history(&self, _run: &RunResult) -> Vec<ledger_explorer::oracle::HistoryOperation> {
        Vec::new()
    }
}

/// The scenario program: `apply` inputs journalled as Input + Outcome.
fn program_for(inputs: &[u64], label: &str) -> ProgramsWorkload {
    let generator = gen_id(label);
    let mut program = Vec::with_capacity(inputs.len() * 2);
    for (index, value) in inputs.iter().enumerate() {
        program.push(Instruction::Input {
            generator,
            replay: index as u64,
            value: *value,
        });
        program.push(Instruction::Outcome);
    }
    program.push(Instruction::Done);
    ProgramsWorkload(vec![program])
}

/// Every `InputStep` value of a journal, in journal order.
fn journal_input_values(journal: &Journal) -> Vec<u64> {
    journal
        .entries()
        .filter_map(|entry| match &entry.data.payload {
            ledger_format::EntryPayload::InputStep(step) => match step.value {
                ledger_format::CanonicalValue::Unsigned(value) => Some(value),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// The first journal entry id carrying `value` on the input axis.
fn input_witness(journal: &Journal, value: u64) -> ledger_format::EntryHash {
    journal
        .entries()
        .find(|entry| {
            matches!(&entry.data.payload, ledger_format::EntryPayload::InputStep(step)
                if step.value == ledger_format::CanonicalValue::Unsigned(value))
        })
        .map(|entry| entry.id)
        .unwrap_or(EntryHash([0; 32]))
}

/// The joint plant's leading write: written before any input, so its entry
/// id is input-independent and the pinned crash fault applies on every
/// attempt.
fn joint_fault_write(label: &'static str, inputs: &[u64]) -> ledger_format::EntryHash {
    let workload = JointTemplate(label).with_inputs(inputs);
    let config = RunConfig::builder()
        .seed(EntryHash([0; 32]))
        .max_steps(4096)
        .build();
    let run = Simulation::new(config, workload.programs())
        .run()
        .expect("joint probe run must execute");
    run.journal
        .entries()
        .find(|entry| entry.data.kind == EntryKind::FsWrite)
        .map(|entry| entry.id)
        .expect("joint probe must journal the leading write")
}

/// One PBT corpus scenario.
struct PbtCase {
    name: &'static str,
    /// Generator stream label (`gen/<generator>`).
    generator: &'static str,
    /// Pinned search seed.
    search_seed: EntryHash,
    /// Number of generated inputs the workload applies.
    applied: usize,
    /// The oracle judging a run; holds when the system is correct.
    oracle: fn() -> Box<dyn Oracle>,
    /// Negative precondition: the oracle must hold on this input vector.
    benign: &'static [u64],
}

static CASES: [PbtCase; 6] = [
    PbtCase {
        name: "pbt-exactly-once-dup",
        generator: "pbt-dedup",
        search_seed: EntryHash([31; 32]),
        applied: 4,
        // Exactly-once: no input value may be applied twice.
        oracle: || Box::new(ExactlyOnceValueOracle),
        benign: &[1, 2, 3, 4],
    },
    PbtCase {
        name: "pbt-forbidden-value",
        generator: "pbt-forbidden",
        search_seed: EntryHash([32; 32]),
        applied: 16,
        // Safety: the forbidden ticket value must never be applied.
        oracle: || {
            Box::new(PropertyOracle {
                property: |journal: &Journal| !journal_input_values(journal).contains(&TRIGGER),
                name: "forbidden value must never be applied".into(),
            })
        },
        benign: &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
    },
    PbtCase {
        name: "pbt-quorum-conflict",
        generator: "pbt-quorum",
        search_seed: EntryHash([33; 32]),
        applied: 16,
        // Quorum invariant: two conflicting leaders must never both gather
        // support.
        oracle: || {
            Box::new(PropertyOracle {
                property: |journal: &Journal| {
                    let values: BTreeSet<u64> = journal_input_values(journal).into_iter().collect();
                    !(values.contains(&7) && values.contains(&9))
                },
                name: "conflicting leaders 7 and 9 must never both appear".into(),
            })
        },
        benign: &[1, 2, 3, 4, 5, 6, 8, 10, 11, 12, 13, 14, 15, 16, 17, 18],
    },
    PbtCase {
        name: "pbt-rollback-after-promote",
        generator: "pbt-rollback",
        search_seed: EntryHash([34; 32]),
        applied: 16,
        // Consistency: a rolled-back version must never follow the promoted
        // one.
        oracle: || {
            Box::new(PropertyOracle {
                property: |journal: &Journal| {
                    let values = journal_input_values(journal);
                    match values.iter().position(|value| *value == TRIGGER) {
                        None => true,
                        Some(position) => values[position..].iter().all(|value| *value >= 10),
                    }
                },
                name: "no rolled-back version may follow the promotion".into(),
            })
        },
        benign: &[
            42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
        ],
    },
    PbtCase {
        name: "pbt-linearizability",
        generator: "pbt-lin",
        search_seed: EntryHash([35; 32]),
        applied: 8,
        // Linearizability: the planted stale read of an unwritten value.
        oracle: || {
            static LIN: LinTemplate = LinTemplate("pbt-lin");
            Box::new(HistoryOracle::new(&LIN, KeyValueSpec::default()))
        },
        benign: &[1, 2, 3, 4, 5, 6, 7, 8],
    },
    PbtCase {
        name: "pbt-promote-crash-joint",
        generator: "pbt-joint",
        search_seed: EntryHash([36; 32]),
        applied: 8,
        // Joint (input, fault) plant: the torn-promotion bug needs BOTH the
        // trigger input and the injected crash fault; neither axis alone
        // violates.
        oracle: || {
            Box::new(PropertyOracle {
                property: |journal: &Journal| {
                    let triggered = journal_input_values(journal).contains(&TRIGGER);
                    let faulted = journal
                        .entries()
                        .any(|entry| entry.data.kind == EntryKind::Fault);
                    !(triggered && faulted)
                },
                name: "promotion must survive the crash without the trigger".into(),
            })
        },
        benign: &[1, 2, 3, 4, 5, 6, 7, 8],
    },
];

/// The template for one scenario: the joint plant needs the leading
/// crash-target write; every other plant is a plain input program.
fn template_for(scenario: &PbtCase) -> Box<dyn Workload> {
    if scenario.name == "pbt-promote-crash-joint" {
        Box::new(JointTemplate(scenario.generator))
    } else {
        Box::new(Template(scenario.generator))
    }
}

fn search_config(scenario: &PbtCase) -> RunConfig {
    let mut builder = RunConfig::builder()
        .seed(scenario.search_seed)
        .max_steps(4096);
    if scenario.name == "pbt-promote-crash-joint" {
        let write = joint_fault_write(scenario.generator, &vec![0; scenario.applied]);
        builder =
            builder.fault_schedule(vec![ledger_sim::SimFault::CrashState { write, state: 2 }]);
    }
    builder.build()
}

#[test]
fn pbt_corpus_manifests_are_pinned_and_reproduce() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpora/pbt-corpus");
    let mut checked = 0usize;
    for entry in fs::read_dir(&corpus).expect("pbt corpus dir must exist") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("ldgr") {
            continue;
        }
        let bytes = fs::read(&path).unwrap();
        let manifest = RunManifest::from_canonical_bytes(&bytes)
            .unwrap_or_else(|error| panic!("{}: manifest must decode: {error}", path.display()));
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        let scenario = CASES
            .iter()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("unexpected pbt manifest '{name}'"));
        let template = template_for(scenario);
        let oracle = (scenario.oracle)();
        let config = search_config(scenario);
        let finding = search_input(
            template.as_ref(),
            oracle.as_ref(),
            config,
            scenario.generator,
            BUDGET,
        )
        .expect("search must run")
        .unwrap_or_else(|| panic!("{name}: the pinned search must find the plant"));
        assert_eq!(
            finding.seed, manifest.root_seed,
            "{name}: pinned search seed must match the manifest"
        );
        assert_eq!(
            finding.run.journal.root_hash(),
            manifest.journal_root,
            "{name}: pinned root must match the manifest"
        );
        assert_eq!(
            finding.run.journal.len() as u64,
            manifest.entry_count,
            "{name}: pinned entry count must match the manifest"
        );
        checked += 1;
    }
    assert_eq!(
        checked,
        CASES.len(),
        "every pbt scenario must have a pinned manifest"
    );
}

#[test]
fn pbt_axis_finds_every_planted_counterexample() {
    for scenario in &CASES {
        let template = template_for(scenario);
        let oracle = (scenario.oracle)();

        // Negative precondition: benign inputs must hold.
        let benign_workload = template_for(scenario).with_inputs(scenario.benign);
        let config = RunConfig::builder()
            .seed(scenario.search_seed)
            .max_steps(4096)
            .build();
        let benign_run = Simulation::new(config, benign_workload.programs())
            .run()
            .unwrap_or_else(|error| panic!("{}: benign run failed: {error}", scenario.name));
        assert!(
            !oracle.check(&benign_run).violated,
            "{}: benign inputs must not violate the property",
            scenario.name
        );

        // The input axis finds the plant within the budget.
        let config = search_config(scenario);
        let finding = search_input(
            template.as_ref(),
            oracle.as_ref(),
            config,
            scenario.generator,
            BUDGET,
        )
        .unwrap_or_else(|error| panic!("{}: search failed: {error}", scenario.name))
        .unwrap_or_else(|| {
            panic!(
                "{}: the input axis must find the planted counterexample within {BUDGET} attempts",
                scenario.name
            )
        });
        assert!(
            finding.verdict.violated,
            "{}: the finding must violate",
            scenario.name
        );
        let trigger_values = trigger_of(scenario.name, &finding);
        assert!(
            !trigger_values.is_empty(),
            "{}: the finding must carry the planted trigger values",
            scenario.name
        );

        // Strict replay of the recovered inputs pins the finding root: the
        // counterexample pins input and schedule jointly. The joint plant
        // keeps its pinned crash fault in the replay configuration.
        let inputs = journal_input_values(&finding.run.journal);
        let replay_workload = template_for(scenario).with_inputs(&inputs);
        let replayed = strict_replay(scenario, replay_workload.as_ref(), &finding);
        assert_eq!(
            replayed.journal.root_hash(),
            finding.run.journal.root_hash(),
            "{}: strict reproduction must pin the finding root",
            scenario.name
        );

        // Input ddmin reduces the counterexample; the violation and the
        // planted trigger survive.
        let pinned_faults = search_config(scenario).fault_schedule().to_vec();
        let reduction = minimize_input_with_faults(
            template.as_ref(),
            oracle.as_ref(),
            &finding,
            scenario.generator,
            &pinned_faults,
        );
        assert!(
            reduction.violation_preserved,
            "{}: input minimization must preserve the violation",
            scenario.name
        );
        // For the duplicate plant the trigger is ANY repeated value: ddmin
        // may keep a different pair than the finding carried.
        let retained = if scenario.name == "pbt-exactly-once-dup" {
            let mut seen = std::collections::HashSet::new();
            reduction.inputs.iter().any(|value| !seen.insert(*value))
        } else {
            trigger_values
                .iter()
                .all(|value| reduction.inputs.contains(value))
        };
        assert!(
            retained,
            "{}: the minimized input must retain the planted trigger values",
            scenario.name
        );
        assert!(
            reduction.inputs.len() <= inputs.len(),
            "{}: minimization must not grow the input",
            scenario.name
        );
    }
}

/// Strict replay of one finding under its scenario configuration: the
/// recorded decisions plus, for the joint plant, the pinned crash fault.
fn strict_replay(
    scenario: &PbtCase,
    replay_workload: &dyn Workload,
    finding: &ledger_explorer::search::Finding,
) -> RunResult {
    let mut builder = RunConfig::builder()
        .seed(finding.seed)
        .policy(ledger_sim::Policy::Replay)
        .max_steps(finding.run.decisions.len().saturating_add(256));
    if scenario.name == "pbt-promote-crash-joint" {
        let pinned = search_config(scenario);
        builder = builder.fault_schedule(pinned.fault_schedule().to_vec());
    }
    Simulation::with_replay_strict(
        builder.build(),
        replay_workload.programs(),
        finding.run.decisions.clone(),
    )
    .run()
    .unwrap_or_else(|error| panic!("{}: strict replay failed: {error}", scenario.name))
}

/// The planted trigger values a finding must retain after minimization.
fn trigger_of(name: &str, finding: &ledger_explorer::search::Finding) -> Vec<u64> {
    let values = journal_input_values(&finding.run.journal);
    match name {
        // The duplicate pair is the trigger.
        "pbt-exactly-once-dup" => {
            let mut seen = std::collections::HashSet::new();
            let mut duplicated = Vec::new();
            for value in &values {
                if !seen.insert(*value) {
                    duplicated.push(*value);
                }
            }
            duplicated.sort_unstable();
            duplicated.dedup();
            duplicated
        }
        "pbt-forbidden-value" | "pbt-linearizability" | "pbt-promote-crash-joint" => {
            vec![TRIGGER]
        }
        "pbt-quorum-conflict" => vec![7, 9],
        "pbt-rollback-after-promote" => vec![TRIGGER],
        other => panic!("unknown scenario {other}"),
    }
}

/// Non-vacuity: a sanitized workload that filters out the trigger can never
/// violate, and the gate must NOT accept a finding for it within the same
/// budget.
#[test]
fn pbt_negative_control_is_not_found() {
    struct Sanitized;
    impl Workload for Sanitized {
        fn programs(&self) -> Vec<Vec<Instruction>> {
            Vec::new()
        }
        fn with_inputs(&self, inputs: &[u64]) -> Box<dyn Workload> {
            let sanitized: Vec<u64> = inputs
                .iter()
                .map(|v| if *v == TRIGGER { 43 } else { *v })
                .collect();
            Box::new(program_for(&sanitized, "pbt-forbidden"))
        }
        fn history(&self, _run: &RunResult) -> Vec<ledger_explorer::oracle::HistoryOperation> {
            Vec::new()
        }
    }
    let oracle: Box<dyn Oracle> = Box::new(PropertyOracle {
        property: |journal: &Journal| !journal_input_values(journal).contains(&TRIGGER),
        name: "forbidden value must never be applied".into(),
    });
    let config = RunConfig::builder()
        .seed(EntryHash([32; 32]))
        .max_steps(4096)
        .build();
    let finding = search_input(&Sanitized, oracle.as_ref(), config, "pbt-forbidden", BUDGET)
        .expect("search must run");
    assert!(
        finding.is_none(),
        "the sanitized workload must never violate: a finding here means the gate is vacuous"
    );
}

/// Manifest regeneration, gated behind `LEDGR_WRITE_PBT_MANIFESTS=1` so a
/// plain test run never writes. Run from the workspace root with:
/// `LEDGR_WRITE_PBT_MANIFESTS=1 cargo test -p ledger-explorer \
///  --test pbt_corpus_gate regenerate_manifests`
///
/// The CASES table is the single source of truth: this writes the committed
/// bytes the pinning test verifies.
#[test]
fn regenerate_manifests() {
    if std::env::var("LEDGR_WRITE_PBT_MANIFESTS").as_deref() != Ok("1") {
        return;
    }
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpora/pbt-corpus");
    fs::create_dir_all(&corpus).expect("create pbt corpus dir");
    let mut written = 0usize;
    for scenario in &CASES {
        let template = template_for(scenario);
        let oracle = (scenario.oracle)();
        let config = search_config(scenario);
        let finding = search_input(
            template.as_ref(),
            oracle.as_ref(),
            config,
            scenario.generator,
            BUDGET,
        )
        .expect("search must run")
        .unwrap_or_else(|| panic!("{}: pinned search must find the plant", scenario.name));
        let mut actor_heads = std::collections::BTreeMap::new();
        for entry in finding.run.journal.entries() {
            actor_heads.insert(entry.data.actor, entry.id);
        }
        let manifest = RunManifest {
            format_version: ledger_format::FORMAT_VERSION,
            crash_semantics_version: ledger_format::CRASH_SEMANTICS_VERSION,
            root_seed: finding.seed,
            policy_tag: "random".to_string(),
            journal_root: finding.run.journal.root_hash(),
            entry_count: finding.run.journal.len() as u64,
            actor_heads,
            execution_identity: None,
        };
        let bytes = manifest.to_canonical_bytes().expect("manifest encodes");
        let path = corpus.join(format!("{}.ldgr", scenario.name));
        fs::write(&path, &bytes).expect("manifest write");
        println!("wrote {} ({} bytes)", path.display(), bytes.len());
        written += 1;
    }
    assert_eq!(written, CASES.len());
}
