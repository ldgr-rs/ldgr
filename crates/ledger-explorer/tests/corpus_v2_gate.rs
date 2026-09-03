//! Corpus-v2 gate: the fault-triggered cloud-infra scenario set.
//!
//! Unlike corpus v1 (reproduction fixtures whose plants fire unconditionally),
//! every v2 scenario is a fault-dependent plant: the no-fault baseline at the
//! pinned seed PASSES and only an injected fault schedule causes the
//! violation. Scenarios come from the single fault-triggered registry
//! (`ledger_explorer::reference::faultdep_scenarios`); this gate holds no
//! private name-to-builder mapping.
//!
//! For every counted scenario the gate proves the six qualification
//! conditions of the DR-0003 standard:
//!
//! 1. the no-fault baseline passes;
//! 2. the counted schedule applies at least one fault under strict
//!    decision replay;
//! 3. the injected run violates under the scenario oracle;
//! 4. the strict replay does not diverge before the first applied fault and
//!    reproduces the violation;
//! 5. a final no-fault rerun passes;
//! 6. the same workload, fault vocabulary, seed, budget, and oracle serve
//!    every step (structural in this gate: one scenario, one oracle, one
//!    vocabulary).
//!
//! Conditions 1-5 run through `services::qualify_cut`; the qualification
//! result feeds `RecordedSolverData::reproduced` and `::baseline_passed`, and
//! the certificate must then pass support-bound inclusion-minimal validation
//! against the witness journal. A gate that cannot qualify a scenario fails.

use ledger_explorer::MaxSatSolver;
use ledger_explorer::certs::{CampaignCertificate, MAX_EVENT_COST};
use ledger_explorer::ldfi::hypothesis_to_schedule;
use ledger_explorer::reference::{
    FAULTDEP_SUPPORT_VERSION, ScenarioClass, faultdep_scenario, faultdep_scenarios, scenario_class,
};
use ledger_explorer::services::qualify_cut;
use ledger_explorer::solver::HittingSetSolver;
use ledger_format::EntryHash;
use ledger_format::RunManifest;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// The six-condition chain for one scenario, reused by every test below.
/// Returns the qualifying certificate data derived from the witness run.
fn qualify_scenario(
    name: &str,
) -> (
    ledger_explorer::search::Finding,
    ledger_explorer::certs::RecordedSolverData,
) {
    let scenario =
        faultdep_scenario(name).unwrap_or_else(|| panic!("{name}: missing registry entry"));
    let workload = scenario.workload();
    let oracle = scenario.oracle();

    // Condition 1: the no-fault baseline must pass.
    let baseline = scenario
        .baseline()
        .unwrap_or_else(|error| panic!("{name}: baseline run failed: {error}"));
    assert!(
        !scenario.check(&baseline).violated,
        "{name}: the no-fault baseline must pass; unconditional plants never count"
    );

    // Condition 3: the pinned trigger causes the violation.
    let finding = scenario.witness().unwrap_or_else(|error| panic!("{error}"));

    // LDFI: a hypothesis-derived schedule must qualify (conditions 2, 4, 5).
    let mut solver = HittingSetSolver::new();
    let hypotheses =
        ledger_explorer::ldfi::solve_with(&mut solver, &finding.run.journal, &finding.verdict)
            .unwrap_or_else(|error| panic!("{name}: ldfi solve must succeed: {error:?}"));
    assert!(
        !hypotheses.is_empty(),
        "{name}: solver must return at least one hypothesis"
    );
    let mut qualification = None;
    for hypothesis in &hypotheses {
        let schedule = hypothesis_to_schedule(hypothesis, &finding.run.journal);
        if schedule.is_empty() {
            continue;
        }
        match qualify_cut(workload.as_ref(), oracle.as_ref(), &finding, schedule) {
            Ok(result) => {
                qualification = Some(result);
                break;
            }
            // A hypothesis that fails qualification is a rejected candidate,
            // not a gate failure: the next hypothesis may qualify.
            Err(error) => {
                println!("{name}: hypothesis rejected: {error}");
                continue;
            }
        }
    }
    let qualification = qualification
        .unwrap_or_else(|| panic!("{name}: no LDFI hypothesis schedule qualified fault causation"));
    assert!(
        !qualification.applied.is_empty(),
        "{name}: the qualifying schedule must apply at least one fault"
    );

    // Certificate: MaxSAT cut, qualification-fed evidence flags, then
    // support-bound inclusion-minimal validation against the witness journal.
    let mut maxsat = MaxSatSolver::default();
    let (_, data) = maxsat
        .solve_with_certificate(&finding.run.journal, &finding.verdict)
        .unwrap_or_else(|error| panic!("{name}: mcs solve must succeed: {error:?}"));
    let mut data =
        data.unwrap_or_else(|| panic!("{name}: non-empty solve must return recorded solver data"));
    assert!(!data.cut.is_empty(), "{name}: mcs cut must be non-empty");
    assert_eq!(
        data.method, "mcs-lower-bound-v1",
        "{name}: method must be mcs-lower-bound-v1"
    );
    let upper = (data.cut.len() as u64).saturating_mul(MAX_EVENT_COST);
    assert!(
        data.cost <= upper,
        "{name}: recorded cut cost {} must be <= cut.len()*{MAX_EVENT_COST} ({upper})",
        data.cost
    );
    // The evidence flags come from the executed qualification, never from
    // the solver (which always records false).
    data.reproduced = true;
    data.baseline_passed = true;
    data.support_provider_version = Some(FAULTDEP_SUPPORT_VERSION);

    let report = ledger_explorer::search::CampaignReport {
        runs_executed: 1,
        distinct_roots: 1,
        findings: vec![finding.clone()],
        variants: Vec::new(),
        monitors: Vec::new(),
        memo_hits: 0,
    };
    let mut certificate = CampaignCertificate::from_campaign(
        &report,
        "corpus-v2-faultdep",
        Vec::new(),
        EntryHash([9u8; 32]),
        None,
    )
    .unwrap_or_else(|error| panic!("{name}: certificate construction failed: {error}"));
    certificate.solver_data = Some(data.clone());
    certificate.subject.digest = finding.run.journal.root_hash();
    certificate
        .verify_inclusion_minimal_with_support(
            &finding.run.journal,
            ledger_explorer::certs::LineagePolicy::Strict,
            Some(FAULTDEP_SUPPORT_VERSION),
        )
        .unwrap_or_else(|error| panic!("{name}: inclusion-minimal validation must pass: {error}"));
    (finding, data)
}

#[test]
fn every_v2_baseline_passes_and_trigger_violates() {
    for scenario in faultdep_scenarios() {
        let name = scenario.name;
        // Condition 1.
        let baseline = scenario
            .baseline()
            .unwrap_or_else(|error| panic!("{name}: baseline run failed: {error}"));
        assert!(
            !scenario.check(&baseline).violated,
            "{name}: the no-fault baseline must pass"
        );
        // Condition 3 + determinism: two witness runs are bit-identical.
        let finding = scenario.witness().unwrap_or_else(|error| panic!("{error}"));
        let second = scenario.witness().unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            finding.run.journal.root_hash(),
            second.run.journal.root_hash(),
            "{name}: witness runs must be bit-identical at the pinned seed"
        );
        // Conditions 2 and 4 on the trigger schedule itself.
        let baseline_journal = baseline.journal;
        let trigger = (scenario.trigger)(&baseline_journal);
        let report = scenario
            .replay(&finding.run, trigger)
            .unwrap_or_else(|error| panic!("{name}: trigger replay failed: {error}"));
        assert!(
            !report.applied.is_empty(),
            "{name}: the trigger schedule must apply at least one fault"
        );
        assert!(
            report.prefix_ok,
            "{name}: no divergence may precede the first applied fault"
        );
        assert!(
            scenario.check(&report.run).violated,
            "{name}: the trigger replay must violate"
        );
    }
}

#[test]
fn corpus_v2_manifests_are_pinned_and_reproduce() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpora/bug-corpus-v2");
    let mut checked = 0usize;
    for entry in fs::read_dir(&corpus).expect("corpus v2 dir must exist") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("ldgr") {
            continue;
        }
        let bytes = fs::read(&path).unwrap();
        let manifest = RunManifest::from_canonical_bytes(&bytes).unwrap_or_else(|error| {
            panic!(
                "{}: manifest must decode as a RunManifest: {error}",
                path.display()
            )
        });
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        let scenario = faultdep_scenario(&name).unwrap_or_else(|| {
            panic!("unexpected corpus v2 manifest '{name}': not in the fault-triggered registry")
        });
        let finding = scenario.witness().unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            finding.run.journal.root_hash(),
            manifest.journal_root,
            "{name}: the committed manifest root must match the witness run"
        );
        assert_eq!(
            finding.run.journal.len() as u64,
            manifest.entry_count,
            "{name}: the committed manifest entry count must match the witness run"
        );
        assert_eq!(
            scenario_class(&name),
            Some(ScenarioClass::CloudInfra),
            "{name}: v2 scenarios must be CloudInfra"
        );
        checked += 1;
    }
    assert_eq!(
        checked,
        faultdep_scenarios().len(),
        "every fault-triggered scenario must have a pinned manifest"
    );
}

#[test]
fn manifests_are_regenerable_from_the_registry_v2() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpora/bug-corpus-v2");
    for scenario in faultdep_scenarios() {
        let finding = scenario.witness().unwrap_or_else(|error| panic!("{error}"));
        let path = corpus.join(format!("{}.ldgr", scenario.name));
        let bytes = fs::read(&path)
            .unwrap_or_else(|error| panic!("{}: manifest must exist: {error}", path.display()));
        let manifest = RunManifest::from_canonical_bytes(&bytes).expect("manifest must decode");
        assert_eq!(
            finding.seed, manifest.root_seed,
            "{}: the registry base seed must be the pinned seed",
            scenario.name
        );
        assert_eq!(
            finding.run.journal.root_hash(),
            manifest.journal_root,
            "{}: a registry rerun must reproduce the pinned root",
            scenario.name
        );
    }
}

#[test]
fn ldfi_qualifies_every_v2_bug_non_vacuously() {
    for scenario in faultdep_scenarios() {
        let (_, data) = qualify_scenario(scenario.name);
        assert!(
            data.reproduced && data.baseline_passed,
            "{}: qualification evidence must be recorded",
            scenario.name
        );
    }
}

#[test]
fn at_least_ten_fault_triggered_bugs_meet_the_six_conditions() {
    let scenarios = faultdep_scenarios();
    let mut counted = 0usize;
    let mut classes_seen: HashSet<ScenarioClass> = HashSet::new();
    let mut names: Vec<String> = Vec::new();
    for scenario in &scenarios {
        let (_, data) = qualify_scenario(scenario.name);
        counted += 1;
        classes_seen.insert(scenario.class);
        names.push(format!(
            "{} (cut {}, cost {})",
            scenario.name,
            data.cut.len(),
            data.cost
        ));
    }
    names.sort();
    println!("counted {counted} non-vacuous bugs: {}", names.join(", "));
    assert!(
        counted >= 10,
        "the stage-2 criterion needs at least 10 non-vacuous counted bugs, got {counted}"
    );
    assert!(
        classes_seen.contains(&ScenarioClass::CloudInfra),
        "cloud-infra class must be represented among counted bugs"
    );
}
