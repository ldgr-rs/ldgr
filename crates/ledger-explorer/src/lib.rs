#![deny(unsafe_code)]
#![allow(missing_docs)]

//! Backward search engine, Lineage-Driven Fault Injection (LDFI), multi-stage minimizer, and oracles.

pub mod diagnosis;
pub mod forensics;
pub mod ldfi;
pub mod minimizer;
pub mod oracle;
pub mod pbt;
pub mod reference;
pub mod search;
pub mod workloads;

pub use diagnosis::{CausalDivergence, causal_bisect, first_divergence};
pub use forensics::{MotifAnalyzer, MotifLift, rank_motifs_by_lift};
pub use ldfi::{FaultCut, FaultHypothesis, FaultableEvent, solve_ldfi, suggest_cut};
pub use minimizer::{
    MemoizedReplay, MinimizationReport, MinimizedRepro, causal_slice, causal_slice_forward,
    causal_slice_multi, ddmin, minimize_full, minimize_schedule,
};
pub use oracle::{
    AssertionOracle, CachedPropertyOracle, DifferentialOracle, HistoryOperation, HistoryOracle,
    InvariantOracle, KeyValueSpec, LinOperation, LinearizabilityOracle, Oracle, PropertyOracle,
    QueueSpec, SequentialSpec, Verdict, predicate_version,
};
pub use pbt::{InputsWorkload, PbtBridge};
pub use search::{
    CampaignReport, Finding, QuadBandit, QuadMutation, Workload, diff, replay, replay_with_faults,
    run_bandit_campaign, run_campaign, run_campaign_quad, run_joint_campaign, run_swarm_campaign,
    search, search_input,
};
