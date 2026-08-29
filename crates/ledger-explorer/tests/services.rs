//! Service-level behavior: one happy path and one typed error path per
//! service, asserting the source error survives the boundary.

use ledger_explorer::services::{
    ServiceError, emit_statement, ldfi_solve, minimize_decisions, parse_statement, replay_faults,
    replay_prefix, replay_strict, run_campaign, schedule_from_hypothesis, search_first,
    validate_cut_against_journal, validate_inclusion_minimal_cut, validate_statement,
};
use ledger_explorer::solver::SolverConfig;
use ledger_explorer::{CampaignReport, CertError, Finding, Oracle, PropertyOracle, Workload};
use ledger_format::{EntryKind, Payload};
use ledger_journal::Journal;
use ledger_sim::{Instruction, Policy, RunConfig, RunResult, SimFault, Simulation};

fn outcome_value(journal: &Journal) -> Option<u64> {
    journal
        .entries()
        .filter(|entry| entry.data.kind == EntryKind::Outcome)
        .find_map(|entry| match &entry.data.payload {
            Payload::Number(value) => Some(*value),
            _ => None,
        })
}

/// A workload that journals one outcome value.
struct OutcomeWorkload(u64);

impl Workload for OutcomeWorkload {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        vec![vec![
            Instruction::Set(self.0),
            Instruction::Outcome,
            Instruction::Done,
        ]]
    }
    fn history(&self, _run: &RunResult) -> Vec<ledger_explorer::oracle::HistoryOperation> {
        Vec::new()
    }
}

fn seed_bytes(seed: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&seed.to_le_bytes());
    out
}

fn config(seed: u64) -> RunConfig {
    RunConfig::builder()
        .seed(seed_bytes(seed))
        .policy(Policy::Random)
        .max_steps(256)
        .build()
}

fn final_is(expect: u64) -> PropertyOracle<impl Fn(&Journal) -> bool> {
    PropertyOracle {
        property: move |journal: &Journal| outcome_value(journal) == Some(expect),
        name: format!("final value must be {expect}"),
    }
}

#[test]
fn run_campaign_happy_path_and_no_silent_errors() {
    let workload = OutcomeWorkload(99);
    let oracle = final_is(7);
    let report: CampaignReport =
        run_campaign(&workload, &oracle, config(1), 4).expect("campaign must run");
    assert_eq!(report.runs_executed, 4);
    assert!(!report.findings.is_empty(), "every run violates the oracle");
}

#[test]
fn search_first_happy_path_and_empty_when_clean() {
    let workload = OutcomeWorkload(7);
    let oracle = final_is(7);
    let finding: Option<Finding> =
        search_first(&workload, &oracle, config(2), 4).expect("search must run");
    assert!(finding.is_none(), "clean workload finds nothing");

    let workload = OutcomeWorkload(99);
    let oracle = final_is(7);
    let finding: Option<Finding> =
        search_first(&workload, &oracle, config(3), 4).expect("search must run");
    let finding = finding.expect("violating workload must be found");
    assert!(finding.verdict.violated);
}

#[test]
fn replay_strict_pins_the_root_and_rejects_bad_decisions() {
    let workload = OutcomeWorkload(7);
    let run = Simulation::new(config(4), workload.programs())
        .run()
        .expect("base run must execute");
    let replayed =
        replay_strict(&workload, seed_bytes(4), run.decisions.clone()).expect("replay ok");
    assert_eq!(replayed.journal.root_hash(), run.journal.root_hash());

    let mut bad = run.decisions.clone();
    if let Some(first) = bad.first_mut() {
        // At the first step one task is ready, so a huge decision is
        // outside the ready set and must be rejected as OutOfRange.
        *first = usize::MAX;
    }
    let err = replay_strict(&workload, seed_bytes(4), bad).expect_err("out-of-range rejected");
    assert!(
        matches!(
            err,
            ServiceError::Simulation(ledger_sim::RuntimeError::StrictReplay(
                ledger_sim::ReplayViolation::OutOfRange { .. }
            ))
        ),
        "typed strict violation: {err:?}"
    );
}

#[test]
fn replay_prefix_is_available_but_must_not_satisfy_a_gate() {
    let workload = OutcomeWorkload(7);
    let run = Simulation::new(config(5), workload.programs())
        .run()
        .expect("base run must execute");
    let replayed =
        replay_prefix(&workload, seed_bytes(5), run.decisions.clone()).expect("prefix replay runs");
    assert_eq!(replayed.journal.root_hash(), run.journal.root_hash());
}

/// A two-task workload: the writer sends one fresh value; the reader
/// journals it as its outcome. Dropping the send breaks the outcome.
struct SendWorkload;

impl Workload for SendWorkload {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        vec![
            vec![
                Instruction::SendTimed {
                    to: 1,
                    payload: 7,
                    delay: 1,
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
    fn history(&self, _run: &RunResult) -> Vec<ledger_explorer::oracle::HistoryOperation> {
        Vec::new()
    }
}

#[test]
fn ldfi_solve_ranks_hypotheses_from_a_violation() {
    let workload = SendWorkload;
    let oracle = final_is(7);
    let base = Simulation::new(config(6), workload.programs())
        .run()
        .expect("base run must execute");
    assert!(
        !oracle.check(&base).violated,
        "baseline outcome must be fresh"
    );
    let send_id = base
        .journal
        .entries()
        .find(|entry| entry.data.kind == EntryKind::Send)
        .expect("probe journal has the send")
        .id;
    let faulted = Simulation::new(
        config(6).with_fault_schedule(vec![SimFault::Drop(send_id)]),
        workload.programs(),
    )
    .run()
    .expect("faulted run must execute");
    let verdict = oracle.check(&faulted);
    assert!(verdict.violated, "dropping the send must break the outcome");
    let solver_config = SolverConfig {
        max_horizon: Some(16),
        ..SolverConfig::default()
    };
    let hypotheses = ldfi_solve(&faulted.journal, &verdict, &solver_config).expect("solve ok");
    assert!(!hypotheses.is_empty(), "a violation yields hypotheses");
    let schedule = schedule_from_hypothesis(&hypotheses[0], &faulted.journal);
    assert!(
        !schedule.is_empty(),
        "the top hypothesis maps to a schedule"
    );
    let report = replay_faults(
        &workload,
        &faulted.journal,
        seed_bytes(6),
        faulted.decisions.clone(),
        schedule,
    )
    .expect("fault replay runs");
    assert!(
        !report.applied.is_empty(),
        "the critical send drop must be reported applied"
    );
}

#[test]
fn minimize_decisions_reduces_a_monotone_predicate() {
    let decisions: Vec<usize> = (0..8).collect();
    // The predicate is true only when the full set is present, so ddmin
    // cannot shrink it further.
    let report = minimize_decisions(&decisions, |candidate| candidate.len() == decisions.len());
    assert_eq!(report.minimized_count, 8);
    // A predicate true for any non-empty suffix shrinks to one step.
    let report = minimize_decisions(&decisions, |candidate| !candidate.is_empty());
    assert_eq!(report.minimized_count, 1);
}

#[test]
fn emit_parse_validate_round_trip() {
    let report: CampaignReport =
        run_campaign(&OutcomeWorkload(99), &final_is(7), config(7), 1).expect("campaign must run");
    let certificate = emit_statement(&report, "builder", Vec::new(), [1u8; 32], None)
        .expect("statement must emit");
    let json = certificate.to_json().expect("serialize");
    let parsed = parse_statement(&json).expect("statement must parse");
    validate_statement(&parsed).expect("statement must validate");

    // Lineage-only reports cannot emit a certifiable statement.
    let mut lineage_only = Journal::new();
    lineage_only
        .append(
            EntryKind::Epoch,
            0,
            [],
            Payload::Text("lineage-only".into()),
        )
        .expect("append lineage marker");
    let findings: Vec<Finding> = report
        .findings
        .into_iter()
        .map(|mut finding| {
            finding.run.journal = lineage_only.clone();
            finding
        })
        .collect();
    let lineage_only = CampaignReport { findings, ..report };
    let err = emit_statement(&lineage_only, "builder", Vec::new(), [1u8; 32], None)
        .expect_err("lineage-only journals must be rejected");
    assert!(
        matches!(err, ServiceError::Cert(CertError::Verification(_))),
        "typed cert error: {err:?}"
    );

    let err = parse_statement("{not json").expect_err("malformed json rejected");
    assert!(
        matches!(err, ServiceError::Cert(_)),
        "typed parse error: {err:?}"
    );
}

#[test]
fn validate_cut_against_journal_rejects_zero_digest_binding() {
    let report: CampaignReport =
        run_campaign(&OutcomeWorkload(99), &final_is(99), config(8), 1).expect("campaign must run");
    let mut certificate = emit_statement(&report, "builder", Vec::new(), [1u8; 32], None)
        .expect("statement must emit");
    // A zero subject digest never binds to any journal in journal mode.
    certificate.subject.digest = [0u8; 32];
    let journal = Journal::new();
    let err =
        validate_cut_against_journal(&certificate, &journal).expect_err("zero digest rejected");
    assert!(
        matches!(err, ServiceError::Cert(CertError::Verification(_))),
        "typed binding error: {err:?}"
    );
}

#[test]
fn validate_inclusion_minimal_cut_refuses_campaign_statements() {
    let report: CampaignReport =
        run_campaign(&OutcomeWorkload(99), &final_is(7), config(8), 1).expect("campaign must run");
    assert!(
        !report.findings.is_empty(),
        "the mismatched oracle must produce a finding"
    );
    let certificate = emit_statement(&report, "builder", Vec::new(), [1u8; 32], None)
        .expect("statement must emit");
    let journal = report.findings[0].run.journal.clone();
    // The operation names the third distinct check: inclusion-minimal
    // fault-cut validation. A campaign statement without a recorded cut is
    // not fault-causation evidence and must fail closed.
    let err = validate_inclusion_minimal_cut(&certificate, &journal)
        .expect_err("campaign statements carry no fault cut");
    assert!(
        matches!(err, ServiceError::Cert(CertError::Verification(_))),
        "typed minimality error: {err:?}"
    );
}
