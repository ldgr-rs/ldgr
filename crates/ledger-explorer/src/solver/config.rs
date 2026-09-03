use crate::ldfi::FaultHypothesis;
use crate::maxsat::HazardEncoding;
use crate::oracle::Verdict;
use crate::solver_cache::WeightedClause;
use ledger_format::EntryHash;
use ledger_journal::{Journal, JournalError};
use thiserror::Error;

/// Error returned by a fault solver.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SolverError {
    #[error("journal error: {0}")]
    Journal(#[from] JournalError),
    #[error("solver state: {0}")]
    SolverState(#[from] crate::solver_state::SolverStateError),
    /// No faultable provenance reaches the witnesses under the configured
    /// horizon. The hazard walk derived no hard clause, so no cut can be
    /// claimed. Callers must fail closed instead of ranking an unrelated
    /// event.
    #[error("no faultable provenance for the witnesses under this horizon")]
    EmptyProvenance,
    /// A deterministic solve budget was exhausted. The bound counts clauses,
    /// cost units, or search nodes, never wall-clock time, so the failure is
    /// reproducible.
    #[error("solve budget exhausted: {0}")]
    BudgetExhausted(&'static str),
    #[error("unsupported operation")]
    Unsupported,
}

/// Solver engine requested by the caller.
///
/// `Auto` routes via [`cutoff()`]; `Builtin` forces the pure-Rust engine;
/// `Cadical` forces MaxSAT (falls back to branch-and-bound without the
/// `solver-cadical` feature).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SolverEngine {
    #[default]
    Auto,
    Builtin,
    Cadical,
}

/// Routing sentinel for [`select_solver`]: crossover not yet observed, so
/// `Auto` always routes to builtin. Rerun `benches/solver_crossover.rs`
/// after encoding or engine changes.
pub const CADICAL_CUTOFF_HARD_CLAUSES: usize = usize::MAX;

/// Routing threshold for [`select_solver`] in hard clauses.
pub fn cutoff() -> usize {
    CADICAL_CUTOFF_HARD_CLAUSES
}

/// Solver horizon, oracle, input, fault, engine, and run/support pins.
/// `run_config_hash` and the support pins join cache keys and the
/// solver-state fingerprint so foreign artifacts never satisfy this solver.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SolverConfig {
    pub max_horizon: Option<usize>,
    pub oracle_version: Option<u64>,
    pub input_class: Option<u64>,
    pub max_faults: Option<usize>,
    pub engine: SolverEngine,
    pub run_config_hash: Option<EntryHash>,
    pub support_version: Option<u64>,
    pub support_digest: Option<EntryHash>,
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

    pub fn with_run_config_hash(mut self, hash: EntryHash) -> Self {
        self.run_config_hash = Some(hash);
        self
    }

    /// Pin the support-provider version on this config.
    pub fn with_support_version(mut self, version: u64) -> Self {
        self.support_version = Some(version);
        self
    }

    /// Pin the support-provider digest on this config.
    pub fn with_support_digest(mut self, digest: EntryHash) -> Self {
        self.support_digest = Some(digest);
        self
    }
}

/// Select the solver for an already-computed encoding. Single post-encode
/// routing point; `Auto` applies [`cutoff()`] under the feature gate.
/// Deterministic in every build.
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
    /// Deterministic: same closure hash and clause set yield same hypotheses.
    fn solve_incremental(
        &mut self,
        closure_hash: EntryHash,
        clauses: Vec<WeightedClause>,
    ) -> Vec<FaultHypothesis>;

    /// Snapshot persisted state for cross-round resume.
    ///
    /// Returns `None` when the engine holds no persistable state. Engines
    /// without snapshot support keep the default.
    fn snapshot_state(&self) -> Option<crate::solver_state::SolverStateArtifact> {
        None
    }

    /// Pre-warm caches from a snapshot. Rejects artifacts whose state key,
    /// engine, or run-config hash mismatches, or whose hypotheses are uncovered.
    fn warm_from_artifact(
        &mut self,
        _artifact: &crate::solver_state::SolverStateArtifact,
    ) -> Result<(), SolverError> {
        Ok(())
    }
}
