#![deny(unsafe_code)]
#![allow(missing_docs)]

//! Backward search engine, Lineage-Driven Fault Injection (LDFI), multi-stage minimizer, and oracles.

pub mod attest_uri;
pub mod certs;
pub mod coverage;
pub mod diagnosis;
pub mod faultspec_bridge;
pub mod forensics;
pub mod ldfi;
pub mod lineage;
pub mod maxsat;
#[cfg(feature = "solver-cadical")]
pub mod maxsat_cadical;
pub mod memo;
pub mod minimizer;
pub mod monitor;
pub mod oracle;
pub mod pbt;
pub mod reference;
pub mod search;
pub mod solver;
pub mod solver_cache;
pub mod solver_state;
pub mod support;
pub mod workloads;

pub use attest_uri::{
    DEFAULT_ATTESTATION_BASE, attestation_base, attestation_base_from, build_type_campaign_v1,
    predicate_type_campaign_v1, tool_information_uri,
};
pub use certs::{
    CampaignCertificate, CertError, LineagePolicy, RecordedSolverData, ResolvedDependency,
    StatisticalBound, Subject, check_cert_bytes,
};
pub use coverage::{
    CovError, CoverageBuilder, CoverageReport, RootRecord, to_jacoco, to_lcov, to_sarif,
};
pub use diagnosis::first_divergence;
pub use forensics::{MotifLift, rank_motifs_by_lift};
pub use ldfi::{FaultHypothesis, FaultableEvent, solve_with};
pub use maxsat::LOWER_BOUND_METHOD;
pub use memo::{CampaignMemo, MemoEntry, canonical_variant_bytes, hash_inputs, memo_key};
pub use minimizer::{
    MemoError, MemoizedReplay, MinimizationReport, MinimizeError, MinimizedRepro, causal_slice,
    causal_slice_forward, ddmin, minimize_full, minimize_schedule,
};
pub use monitor::{LivenessMonitor, MonitorAction, MonitorOracle, OnlineMonitor, SafetyMonitor};
pub use oracle::{
    AssertionOracle, CachedPropertyOracle, DifferentialOracle, ExactlyOnceValueOracle,
    HistoryOperation, HistoryOracle, KeyValueSpec, LinOperation, LinearizabilityOracle, Oracle,
    PropertyOracle, SequentialSpec, Verdict, compose_oracles, predicate_version,
};
pub use pbt::{InputsWorkload, PbtBridge};
pub use search::{
    CampaignPersist, CampaignReport, Finding, QuadBandit, QuadMutation, Workload, diff, escalate,
    replay_prefix, replay_strict, replay_with_faults, run_bandit_campaign, run_campaign,
    run_campaign_quad, run_feedback_campaign, run_feedback_campaign_with_state, run_joint_campaign,
    run_joint_campaign_with_state, run_monitored_campaign, run_swarm_campaign, search,
    search_input, search_input_energy,
};
pub use solver::MaxSatSolver;
pub use solver::{
    CADICAL_CUTOFF_HARD_CLAUSES, FaultSolver, HittingSetSolver, SolverConfig, SolverEngine,
    SolverError, cutoff, event_fault_cost, is_faultable, select_solver,
};
pub use solver_cache::{ClauseCache, WeightedClause};
pub use solver_state::{
    COST_MODEL_VERSION, PersistedClosure, PersistedHypothesis, SolverStateArtifact,
    SolverStateError, fingerprint, load as load_solver_state, save as save_solver_state,
};
pub use support::{
    StaticSupportProvider, SupportError, SupportExpr, SupportOutcome, SupportProvider, all_of_ids,
    entry_ids_by,
};
