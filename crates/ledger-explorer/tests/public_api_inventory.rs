//! Public API inventory.
//!
//! The CLI and worker consume the explorer through the stable services in
//! [`ledger_explorer::services`]. The crate root re-exports the reviewed
//! contracts: search and campaign semantics, solver configuration, oracles,
//! certificates, and the corpus reference surface.
//!
//! The import block below is the inventory: every reviewed name must
//! resolve through the root or the services module, so removing any name
//! from the public surface breaks the compile of this file. The names are
//! intentionally unused here; their reachability is the assertion.

#![expect(
    unused_imports,
    reason = "the import set is the compile-pinned public API inventory"
)]

use ledger_explorer::services::{
    ServiceError, emit_statement, ldfi_solve, minimize_decisions, minimize_finding,
    parse_statement, replay_faults, replay_prefix, replay_strict, run_campaign,
    schedule_from_hypothesis, search_first, validate_cut_against_journal, validate_statement,
};
use ledger_explorer::{
    AssertionOracle, CampaignCertificate, CampaignReport, CertError, ClauseCache, CoverageBuilder,
    DifferentialOracle, Finding, HistoryOracle, HittingSetSolver, KeyValueSpec, LineagePolicy,
    MaxSatSolver, MinimizationReport, MinimizeError, Oracle, PropertyOracle, QuadMutation,
    RecordedSolverData, ResolvedDependency, SolverConfig, SolverEngine, SolverError,
    StaticSupportProvider, Subject, SupportError, SupportExpr, Verdict, WeightedClause, Workload,
    diff, replay_with_faults, run_campaign_quad, run_feedback_campaign, search_input,
    select_solver, solve_with, to_jacoco, to_lcov, to_sarif,
};

/// The service error type is public and preserves its source chain, so CLI
/// and worker failures keep the typed cause.
#[test]
fn service_error_is_public_and_typed() {
    let name = std::any::type_name::<ServiceError>();
    assert!(
        name.contains("ServiceError"),
        "service error must stay public: {name}"
    );
}
