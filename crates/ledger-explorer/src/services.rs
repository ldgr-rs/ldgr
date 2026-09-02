//! Stable application services consumed by the CLI and the worker.
//!
//! Each service is one operation with explicit inputs and typed errors that
//! preserve their sources. The services compose the search, solver, and
//! certificate surfaces. Callers outside the explorer crate route through
//! them instead of reaching into implementation modules.

use crate::MaxSatSolver;
use crate::certs::{CampaignCertificate, CertError, LineagePolicy, ResolvedDependency};
use crate::ldfi::{self, FaultHypothesis};
use crate::maxsat;
use crate::minimizer::{self, MinimizationReport, MinimizeError, MinimizedRepro};
use crate::oracle::{Oracle, Verdict};
use crate::search::{
    self, CampaignReport, FaultReplayError, FaultReplayReport, Finding, SearchError, Workload,
};
use crate::solver::{SolverConfig, SolverError};
use ledger_format::Hash;
use ledger_journal::Journal;
use ledger_sim::{RunConfig, RunResult, RuntimeError, SimFault, Simulation};

/// Typed failure of a service operation, preserving the source error.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// A search or campaign step failed.
    #[error(transparent)]
    Search(#[from] SearchError),
    /// Strict replay rejected a decision stream.
    #[error(transparent)]
    Replay(#[from] FaultReplayError),
    /// Fault-hypothesis solving failed.
    #[error(transparent)]
    Solve(#[from] SolverError),
    /// Statement encoding, decoding, or validation failed.
    #[error(transparent)]
    Cert(#[from] CertError),
    /// Minimization failed.
    #[error(transparent)]
    Minimize(#[from] MinimizeError),
    /// A simulation failed outside a search or replay path.
    #[error(transparent)]
    Simulation(Box<RuntimeError>),
    /// A journal could not be read.
    #[error("journal error: {0}")]
    Journal(#[from] ledger_journal::JournalError),
    /// A fault-causation qualification condition failed.
    #[error(transparent)]
    Qualify(#[from] QualifyError),
}

impl From<RuntimeError> for ServiceError {
    fn from(error: RuntimeError) -> Self {
        Self::Simulation(Box::new(error))
    }
}

/// Run a multi-attempt campaign over one workload and oracle.
pub fn run_campaign<W: Workload, O: Oracle>(
    workload: &W,
    oracle: &O,
    config: RunConfig,
    attempts: usize,
) -> Result<CampaignReport, ServiceError> {
    Ok(search::run_campaign(workload, oracle, config, attempts)?)
}

/// Find the first violating run over `attempts` seeded attempts.
pub fn search_first<W: Workload, O: Oracle>(
    workload: &W,
    oracle: &O,
    config: RunConfig,
    attempts: usize,
) -> Result<Option<Finding>, ServiceError> {
    Ok(search::search(workload, oracle, config, attempts)?)
}

/// Strictly replay a recorded decision stream against a workload.
pub fn replay_strict<W: Workload + ?Sized>(
    workload: &W,
    seed: Hash,
    decisions: Vec<usize>,
) -> Result<RunResult, ServiceError> {
    Ok(search::replay_strict(workload, seed, decisions)?)
}

/// Lenient prefix replay for delta debugging only. It never satisfies a
/// reproduction gate.
pub fn replay_prefix<W: Workload + ?Sized>(
    workload: &W,
    seed: Hash,
    decisions: Vec<usize>,
) -> Result<RunResult, ServiceError> {
    Ok(search::replay_prefix(workload, seed, decisions)?)
}

/// Solve the hazard of one verdict into ranked fault hypotheses.
pub fn ldfi_solve(
    journal: &Journal,
    verdict: &Verdict,
    config: &SolverConfig,
) -> Result<Vec<FaultHypothesis>, ServiceError> {
    let encoded = maxsat::encode_hazard(journal, verdict, config)?;
    let mut solver = crate::solver::select_solver(config, &encoded);
    Ok(ldfi::solve_with(solver.as_mut(), journal, verdict)?)
}

/// Convert one hypothesis into an executable fault schedule.
pub fn schedule_from_hypothesis(hypothesis: &FaultHypothesis, journal: &Journal) -> Vec<SimFault> {
    ldfi::hypothesis_to_schedule(hypothesis, journal)
}

/// Replay one fault schedule against a witness run under strict replay.
pub fn replay_faults<W: Workload + ?Sized>(
    workload: &W,
    base: &Journal,
    seed: Hash,
    decisions: Vec<usize>,
    schedule: Vec<SimFault>,
) -> Result<FaultReplayReport, ServiceError> {
    Ok(search::replay_with_faults(
        workload, base, seed, decisions, schedule,
    )?)
}

/// Typed failure of a fault-causation qualification.
///
/// Every variant is one of the six qualification conditions failing; the
/// error names the condition so callers and gates report the exact breach.
#[derive(Debug, thiserror::Error)]
pub enum QualifyError {
    /// The no-fault baseline run violates: the plant is unconditional, so
    /// no fault can be its cause.
    #[error("baseline violates: unconditional plants are not fault-caused")]
    BaselineViolates,
    /// The replayed schedule applied no fault: nothing carried the
    /// violation.
    #[error("schedule applied no fault: the violation has no injected cause")]
    NoAppliedFault,
    /// The replay diverged before the first applied fault.
    #[error("replay diverged before the first applied fault")]
    PrefixDivergence,
    /// The replayed run does not violate: the schedule does not cause the
    /// finding.
    #[error("replayed run does not violate: the schedule is not the cause")]
    NotViolating,
    /// The final no-fault rerun violates: the plant is unconditional.
    #[error("final no-fault rerun violates: unconditional plants never count")]
    FinalRerunViolates,
}

/// Evidence produced by a successful fault-causation qualification.
#[derive(Debug, Clone)]
pub struct CutQualification {
    /// Schedule injections that took effect in the replay.
    pub applied: Vec<SimFault>,
    /// Schedule injections that never fired.
    pub voided: Vec<SimFault>,
    /// No divergence before the first applied fault.
    pub prefix_ok: bool,
    /// Journal root of the replayed (violating) run.
    pub replayed_root: Hash,
}

/// Qualify one fault schedule as the cause of one finding.
///
/// Runs the six-conditions evidence chain for one candidate schedule
/// against the witness run:
///
/// 1. the no-fault baseline rerun passes;
/// 2. the schedule applies at least one fault under strict decision replay;
/// 3. the replayed run violates under the oracle;
/// 4. the replay does not diverge before the first applied fault;
/// 5. a final no-fault rerun passes.
///
/// Condition 6 (the same workload, vocabulary, seeds, budget, and oracle
/// serve every method) is structural and owned by the calling gate. A
/// passing qualification is the raw material for
/// `RecordedSolverData::reproduced` and `::baseline_passed`; callers that
/// record a certificate must set both from this result, never assert them.
pub fn qualify_cut<W: Workload + ?Sized, O: Oracle + ?Sized>(
    workload: &W,
    oracle: &O,
    witness: &Finding,
    schedule: Vec<SimFault>,
) -> Result<CutQualification, ServiceError> {
    let baseline = {
        let config = RunConfig::builder()
            .seed(witness.seed)
            .policy(ledger_sim::Policy::Random)
            .max_steps(4096)
            .build();
        Simulation::new(config, workload.programs()).run()?
    };
    if oracle.check(&baseline).violated {
        return Err(QualifyError::BaselineViolates.into());
    }
    let report = search::replay_with_faults(
        workload,
        &witness.run.journal,
        witness.seed,
        witness.run.decisions.clone(),
        schedule,
    )?;
    if report.applied.is_empty() {
        return Err(QualifyError::NoAppliedFault.into());
    }
    if !report.prefix_ok {
        return Err(QualifyError::PrefixDivergence.into());
    }
    if !oracle.check(&report.run).violated {
        return Err(QualifyError::NotViolating.into());
    }
    let rerun = {
        let config = RunConfig::builder()
            .seed(witness.seed)
            .policy(ledger_sim::Policy::Random)
            .max_steps(4096)
            .build();
        Simulation::new(config, workload.programs()).run()?
    };
    if oracle.check(&rerun).violated {
        return Err(QualifyError::FinalRerunViolates.into());
    }
    Ok(CutQualification {
        applied: report.applied,
        voided: report.voided,
        prefix_ok: report.prefix_ok,
        replayed_root: report.run.journal.root_hash(),
    })
}

/// End-to-end hazard certification for one journal and one verdict.
///
/// Chains the stages the Stage-2 scaling criterion names - witness closure
/// extraction and hazard encoding, solver routing and solve, statement
/// emission, and journal-anchored validation - into one measured call.
///
/// `recorded_witness_cap` bounds the witness list RECORDED in the
/// statement. The solve always runs over every witness; a statement that
/// carried hundreds of thousands of witness ids would exceed
/// `CERT_MAX_BYTES`, so the recorded list is deterministically truncated
/// (sorted, first `cap`). The cap bounds the record, never the analysis.
///
/// The recorded cut is evidence of the hazard structure only: this service
/// executes no campaign, so `reproduced` and `baseline_passed` stay false
/// and inclusion-minimal validation will (correctly) refuse the statement.
/// Pair it with [`qualify_cut`] for fault-causation evidence.
pub fn certify_hazard(
    journal: Journal,
    verdict: &Verdict,
    run_config_digest: Hash,
    recorded_witness_cap: usize,
) -> Result<(Vec<FaultHypothesis>, CampaignCertificate), ServiceError> {
    let mut solver = MaxSatSolver::default();
    let (hypotheses, data) = solver.solve_with_certificate(&journal, verdict)?;
    let mut data = data.ok_or(ServiceError::Cert(CertError::Verification(
        "a non-empty hazard must record solver data".into(),
    )))?;
    if data.witnesses.len() > recorded_witness_cap {
        let mut witnesses = data.witnesses.clone();
        witnesses.sort();
        witnesses.truncate(recorded_witness_cap);
        data.witnesses = witnesses;
    }
    // A statement without findings must carry a zero subject digest, so the
    // hazard journal rides as the single finding: the subject binds the
    // journal root the cut was validated against.
    let root = journal.root_hash();
    let report = CampaignReport {
        runs_executed: 1,
        distinct_roots: 1,
        findings: vec![Finding {
            seed: [0; 32],
            run: ledger_sim::RunResult {
                journal,
                decisions: Vec::new(),
                trace: Vec::new(),
                registers: Vec::new(),
                steps: 0,
                outcome: ledger_sim::RunOutcome::Completed,
                monitor_issues: Vec::new(),
                applied_faults: Vec::new(),
                origins: Vec::new(),
                journal_error: None,
                protection: ledger_sim::BeltStatus::NotArmed,
            },
            verdict: verdict.clone(),
        }],
        variants: Vec::new(),
        monitors: Vec::new(),
        memo_hits: 0,
    };
    let mut certificate = CampaignCertificate::from_campaign(
        &report,
        "hazard-certification",
        Vec::new(),
        run_config_digest,
        None,
    )?;
    certificate.solver_data = Some(data);
    certificate.subject.digest = root;
    certificate.verify_with_journal(&report.findings[0].run.journal)?;
    Ok((hypotheses, certificate))
}

/// Minimize a decision stream under an oracle predicate (delta debugging).
pub fn minimize_decisions(
    decisions: &[usize],
    oracle_check: impl Fn(&[usize]) -> bool,
) -> MinimizationReport {
    minimizer::minimize_schedule(decisions, oracle_check)
}

/// Minimize one finding end to end.
pub fn minimize_finding<W: Workload, O: Oracle>(
    workload: &W,
    oracle: &O,
    finding: &Finding,
    generator: &str,
) -> Result<MinimizedRepro, ServiceError> {
    Ok(minimizer::minimize_full(
        workload, oracle, finding, generator,
    )?)
}

/// Emit a campaign certificate from a report.
pub fn emit_statement(
    report: &CampaignReport,
    builder_id: &str,
    dependencies: Vec<ResolvedDependency>,
    run_config_digest: Hash,
    execution_identity: Option<Hash>,
) -> Result<CampaignCertificate, ServiceError> {
    Ok(CampaignCertificate::from_campaign(
        report,
        builder_id,
        dependencies,
        run_config_digest,
        execution_identity,
    )?)
}

/// Parse a certificate from its JSON statement bytes.
pub fn parse_statement(json: &str) -> Result<CampaignCertificate, ServiceError> {
    Ok(CampaignCertificate::from_json(json)?)
}

/// Validate a statement's internal structure without a journal.
pub fn validate_statement(certificate: &CampaignCertificate) -> Result<(), ServiceError> {
    certificate.verify()?;
    Ok(())
}

/// Bind a statement to a journal and validate the recorded cut.
pub fn validate_cut_against_journal(
    certificate: &CampaignCertificate,
    journal: &Journal,
) -> Result<(), ServiceError> {
    certificate.verify_with_journal(journal)?;
    Ok(())
}

/// Bind a statement to a journal and verify the recorded cut is
/// inclusion-minimal under the strict lineage policy.
///
/// Refuses statements whose cut is not reproduced or whose no-fault baseline
/// violates: those are campaign statements, not fault-causation evidence.
pub fn validate_inclusion_minimal_cut(
    certificate: &CampaignCertificate,
    journal: &Journal,
) -> Result<(), ServiceError> {
    certificate.verify_inclusion_minimal(journal)?;
    Ok(())
}

/// Inclusion-minimal validation bound to the support provider that derived
/// the recorded cut.
///
/// The recorded support-provider version must match the provider actually
/// used; a disagreement fails before traversal, so an altered support binding
/// can never certify a cut.
pub fn validate_inclusion_minimal_cut_with_support(
    certificate: &CampaignCertificate,
    journal: &Journal,
    support_version: u64,
) -> Result<(), ServiceError> {
    certificate.verify_inclusion_minimal_with_support(
        journal,
        LineagePolicy::Strict,
        Some(support_version),
    )?;
    Ok(())
}
