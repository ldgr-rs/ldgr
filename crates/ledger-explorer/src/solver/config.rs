use crate::ldfi::FaultHypothesis;
use crate::maxsat::HazardEncoding;
use crate::oracle::Verdict;
use crate::solver_cache::WeightedClause;
use ledger_format::Hash;
use ledger_journal::{Journal, JournalError};
use thiserror::Error;

/// Error returned by a fault solver.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SolverError {
    #[error("journal error: {0}")]
    Journal(#[from] JournalError),
    #[error("solver state: {0}")]
    SolverState(#[from] crate::solver_state::SolverStateError),
    #[error("unsupported operation")]
    Unsupported,
}

/// Solver engine requested by the caller.
///
/// The engines behind [`select_solver`]:
///
/// - [`SolverEngine::Auto`] picks the builtin hitting-set engine below the
///   measured crossover point and the CaDiCaL-backed MaxSAT at or above it
///   (only when built with `solver-cadical`).
/// - [`SolverEngine::Builtin`] forces the pure-Rust exact hitting-set engine.
/// - [`SolverEngine::Cadical`] forces the MaxSAT engine. Without the
///   `solver-cadical` feature the forced request still compiles, but the
///   MaxSAT solver falls back to its pure-Rust branch-and-bound at runtime
///   (`name()` keeps reporting the active backend truthfully).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SolverEngine {
    #[default]
    Auto,
    Builtin,
    Cadical,
}

/// Routing sentinel for [`select_solver`] in hard clauses.
///
/// `benches/solver_crossover.rs` swept 8..512 hard clauses and found NO
/// count where the CaDiCaL backend beat the builtin engines; its CNF
/// construction and threshold search cost more than the exact pure-Rust
/// engines on every measured point. `usize::MAX` therefore encodes
/// "crossover not yet observed": `Auto` keeps routing to the builtin
/// engines in every build. Rerun the bench after any encoding or engine
/// change; replace this sentinel with a real measured point only when the
/// bench shows one consistently across runs. See the solver crossover benchmark for the measurement table.
pub const CADICAL_CUTOFF_HARD_CLAUSES: usize = usize::MAX;

/// Routing threshold for [`select_solver`] in hard clauses.
pub fn cutoff() -> usize {
    CADICAL_CUTOFF_HARD_CLAUSES
}

/// Solver horizon and oracle version configuration.
///
/// `max_horizon` limits derivation closure depth for scale; `None` means
/// unbounded (walk until roots). `oracle_version` pins the predicate
/// semantics for content-addressed caching. `input_class` partitions the
/// cache per PBT generator stream (None means no input axis). `max_faults`
/// bounds the cardinality of crash faults for hazard encodings. `engine`
/// selects the solver engine; see [`SolverEngine`] and [`select_solver`].
/// `run_config_hash` is the canonical `RunConfig` hash under which the
/// encoding was produced (see `ledger_sim::canonical_hash`); it joins the
/// cache keys and the solver-state fingerprint so artifacts from different
/// run configs never satisfy each other. `None` keeps callers that do not
/// run a simulation on the historical key space.
///
/// `support_version` and `support_digest` pin the support-provider
/// semantics (see [`crate::support`]). A provider change must never reuse
/// clauses or hypotheses derived under an older model, so both values join
/// the cache keys and the solver-state fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SolverConfig {
    pub max_horizon: Option<usize>,
    pub oracle_version: Option<u64>,
    pub input_class: Option<u64>,
    pub max_faults: Option<usize>,
    pub engine: SolverEngine,
    pub run_config_hash: Option<Hash>,
    pub support_version: Option<u64>,
    pub support_digest: Option<Hash>,
}

impl SolverConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_horizon(mut self, max_depth: usize) -> Self {
        self.max_horizon = Some(max_depth);
        self
    }

    pub fn with_oracle_version(mut self, version: u64) -> Self {
        self.oracle_version = Some(version);
        self
    }

    pub fn with_input_class(mut self, class: u64) -> Self {
        self.input_class = Some(class);
        self
    }

    pub fn with_max_faults(mut self, max_faults: usize) -> Self {
        self.max_faults = Some(max_faults);
        self
    }

    pub fn with_engine(mut self, engine: SolverEngine) -> Self {
        self.engine = engine;
        self
    }

    pub fn with_run_config_hash(mut self, hash: Hash) -> Self {
        self.run_config_hash = Some(hash);
        self
    }

    /// Pin the support-provider version on this config.
    pub fn with_support_version(mut self, version: u64) -> Self {
        self.support_version = Some(version);
        self
    }

    /// Pin the support-provider digest on this config.
    pub fn with_support_digest(mut self, digest: Hash) -> Self {
        self.support_digest = Some(digest);
        self
    }
}

/// Select the fault solver for an already-computed hazard encoding.
///
/// Callers encode first, then route through this factory so every engine
/// construction site shares one post-encode decision. `Auto` resolves to the
/// CaDiCaL-backed MaxSAT when `encoded.hard.len()` reaches [`cutoff()`] and
/// the build has `solver-cadical`, else to the builtin hitting-set engine.
/// Forcing [`SolverEngine::Cadical`] without the feature builds and runs,
/// but the MaxSAT solver then solves via its branch-and-bound fallback, so
/// results stay deterministic in every build. The returned solver carries
/// `config`; clone it before the call if the caller must keep the original.
pub fn select_solver(config: &SolverConfig, encoded: &HazardEncoding) -> Box<dyn FaultSolver> {
    match config.engine {
        SolverEngine::Auto => {
            if encoded.hard.len() >= cutoff() && cfg!(feature = "solver-cadical") {
                Box::new(crate::solver::MaxSatSolver::with_config(
                    config.clone().with_engine(SolverEngine::Cadical),
                ))
            } else {
                Box::new(crate::solver::HittingSetSolver::with_config(config.clone()))
            }
        }
        // Forcing Cadical without the feature falls back to the pure-Rust
        // branch-and-bound inside MaxSatSolver at runtime; name() reports
        // the active backend truthfully.
        SolverEngine::Builtin => {
            Box::new(crate::solver::HittingSetSolver::with_config(config.clone()))
        }
        SolverEngine::Cadical => Box::new(crate::solver::MaxSatSolver::with_config(config.clone())),
    }
}

/// Trait for LDFI fault solvers.
pub trait FaultSolver {
    fn solve(
        &mut self,
        journal: &Journal,
        verdict: &Verdict,
    ) -> Result<Vec<FaultHypothesis>, SolverError>;
    fn name(&self) -> &'static str;

    /// Stateful incremental solve over a content-addressed clause key.
    ///
    /// Checks the per-solver clause cache first, then the global cache,
    /// else computes minimal hitting sets from the supplied clauses.
    /// Deterministic: same closure hash and clause set yield same hypotheses.
    fn solve_incremental(
        &mut self,
        closure_hash: Hash,
        clauses: Vec<WeightedClause>,
    ) -> Vec<FaultHypothesis>;

    /// Snapshot persisted state for cross-round resume.
    ///
    /// Returns `None` when the engine holds no persistable state. Engines
    /// without snapshot support keep the default.
    fn snapshot_state(&self) -> Option<crate::solver_state::SolverStateArtifact> {
        None
    }

    /// Pre-warm caches from a previously snapshotted artifact.
    ///
    /// Engines that cannot consume artifacts keep the default no-op.
    /// Returning an error rejects an artifact whose state key, resolved
    /// engine, or run-config hash does not match this solver, or whose
    /// hypotheses are not covered by their recorded clauses.
    fn warm_from_artifact(
        &mut self,
        _artifact: &crate::solver_state::SolverStateArtifact,
    ) -> Result<(), SolverError> {
        Ok(())
    }
}
