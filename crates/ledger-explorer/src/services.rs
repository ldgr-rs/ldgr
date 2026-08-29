//! Stable application services consumed by the CLI and the worker.
//!
//! Each service is one operation with explicit inputs and typed errors that
//! preserve their sources. The services compose the search, solver, and
//! certificate surfaces. Callers outside the explorer crate route through
//! them instead of reaching into implementation modules.

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
use ledger_sim::{RunConfig, RunResult, RuntimeError, SimFault};

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
    Simulation(#[from] RuntimeError),
    /// A journal could not be read.
    #[error("journal error: {0}")]
    Journal(#[from] ledger_journal::JournalError),
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
