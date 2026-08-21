use super::{
    FaultSolver, HittingSetSolver, SolverConfig, SolverEngine, SolverError, cutoff,
    event_fault_cost, samc_prune,
};
use crate::ldfi::FaultHypothesis;
use crate::oracle::Verdict;
use crate::solver_cache::{ClauseCache, WeightedClause, engine_tag};
use ledger_format::Hash;
use ledger_journal::Journal;

/// Weighted MaxSAT solver with MCS lower-bound certificates.
///
/// Encodes the hazard as weighted MaxSAT over deduplicated faultable-path disjunctions with per-kind costs. Two
/// engines solve the same encoding behind one API: the default pure-Rust
/// deterministic branch-and-bound in `crate::maxsat`, and the exact
/// ascending-threshold CaDiCaL search behind the `solver-cadical` feature.
///
/// The config's [`SolverEngine`] picks the engine per solve. Resolution
/// happens after encoding, before any cache access: `Auto` routes to CaDiCaL
/// only when the encoding reaches `cutoff()` and the feature is compiled in,
/// so a resolved `Auto` request always produces builtin-tagged cache keys on
/// small encodings and cadical-tagged keys on large ones. Forcing Cadical
/// without the feature runs the branch-and-bound fallback; `name()` reports
/// the active backend truthfully.
#[derive(Debug)]
pub struct MaxSatSolver {
    inner: HittingSetSolver,
    cache_hits: usize,
    resolved_engine: SolverEngine,
}

impl Default for MaxSatSolver {
    fn default() -> Self {
        Self::new()
    }
}

impl MaxSatSolver {
    pub fn new() -> Self {
        Self {
            inner: HittingSetSolver::new(),
            cache_hits: 0,
            resolved_engine: initial_resolution(SolverEngine::Auto),
        }
    }

    pub fn with_config(config: SolverConfig) -> Self {
        let resolved_engine = initial_resolution(config.engine);
        Self {
            inner: HittingSetSolver::with_config(config),
            cache_hits: 0,
            resolved_engine,
        }
    }

    pub fn cache_hits(&self) -> usize {
        self.cache_hits
    }

    /// Borrow the solver configuration backing this solver.
    pub fn config(&self) -> &SolverConfig {
        self.inner.config()
    }

    /// The engine this instance resolved to.
    ///
    /// The resolution of the last solve (or the no-encode resolution before
    /// any solve): Auto and Builtin resolve to the builtin backend at every
    /// measured encoding size, and a forced Cadical request resolves to the
    /// CaDiCaL backend only when the feature is compiled in. The solver-state
    /// key and the reported name are derived from this value, never from the
    /// configured mode.
    pub fn resolved_engine(&self) -> SolverEngine {
        self.resolved_engine
    }

    /// Resolve the concrete backend for an encoding.
    ///
    /// Records the resolution on this solver (it is the engine identity that
    /// participates in cache and state keys) and returns the cache-key engine
    /// tag plus whether the CaDiCaL path runs. `Auto` applies the crossover
    /// rule; forced engines honor the request subject to the feature gate.
    /// Deterministic per build: the decision reads only the encoding size,
    /// the config, and the compile-time flag.
    fn resolve_backend(&mut self, hard_clauses: usize) -> (u8, bool) {
        let cadical = match self.inner.config.engine {
            SolverEngine::Auto => cfg!(feature = "solver-cadical") && hard_clauses >= cutoff(),
            SolverEngine::Cadical => cfg!(feature = "solver-cadical"),
            SolverEngine::Builtin => false,
        };
        self.resolved_engine = if cadical {
            SolverEngine::Cadical
        } else {
            SolverEngine::Builtin
        };
        let tag = if cadical {
            engine_tag::CADICAL
        } else {
            engine_tag::BUILTIN
        };
        (tag, cadical)
    }

    /// Solve and produce a minimality certificate.
    pub fn solve_with_certificate(
        &mut self,
        journal: &Journal,
        verdict: &Verdict,
    ) -> Result<(Vec<FaultHypothesis>, crate::certs::MinimalityExtension), SolverError> {
        if verdict.witnesses.is_empty() && journal.is_empty() {
            return Ok((
                Vec::new(),
                crate::certs::MinimalityExtension {
                    cut: Vec::new(),
                    lower_bound: 0,
                    method: crate::maxsat::LOWER_BOUND_METHOD.into(),
                    horizon: self.inner.config.max_horizon,
                },
            ));
        }
        // Encode first: Auto resolves against the encoding size, so no key
        // may be derived before this point.
        let encoding = crate::maxsat::encode_hazard(journal, verdict, &self.inner.config)?;
        let (tag, use_cadical) = self.resolve_backend(encoding.hard.len());
        let mut witness_ids = verdict.witnesses.clone();
        witness_ids.sort();
        let closure_hash = ClauseCache::closure_hash(&witness_ids);
        let key = self.inner.incremental_key_with_tag(closure_hash, tag);
        if self.inner.hypothesis_cache.contains_key(&key) {
            self.cache_hits += 1;
        }
        let global_hit = crate::solver_cache::global_get(&key).is_some();
        let clauses: Vec<WeightedClause> = encoding
            .hard
            .iter()
            .map(|clause| {
                let weight = clause
                    .iter()
                    .map(|hash| event_fault_cost(journal, hash))
                    .min()
                    .unwrap_or(1);
                WeightedClause::new(clause.clone(), weight)
            })
            .collect();
        self.inner.cache.insert(key, clauses.clone());
        if !global_hit {
            // The global insert returns is_new, not an error.
            crate::solver_cache::global_insert(key, clauses);
        }
        let solution = if use_cadical {
            #[cfg(feature = "solver-cadical")]
            {
                crate::maxsat_cadical::solve_maxsat_incremental(&encoding)?
            }
            #[cfg(not(feature = "solver-cadical"))]
            {
                unreachable!("cadical backend requested without the solver-cadical feature")
            }
        } else {
            crate::maxsat::solve_maxsat_bnb(&encoding)?
        };
        let explanation = format!(
            "Weighted MaxSAT minimum cut with {} fault(s) breaking {} hard clause(s); lower bound {} via {}",
            solution.cut.len(),
            encoding.hard.len(),
            solution.lower_bound_proof.unsat_core_cost,
            solution.lower_bound_proof.method
        );
        let hypothesis = FaultHypothesis {
            events: solution.cut.clone(),
            total_cost: solution.total_cost,
            explanation,
        };
        let mut hypotheses = vec![hypothesis];
        hypotheses = samc_prune(journal, hypotheses);
        self.inner.hypothesis_cache.insert(key, hypotheses.clone());
        let extension = crate::certs::MinimalityExtension {
            cut: solution.cut,
            lower_bound: solution.lower_bound_proof.unsat_core_cost,
            method: solution.lower_bound_proof.method.to_string(),
            // The horizon under which the cut was derived; the verifier
            // re-derives the same hazard at this horizon.
            horizon: self.inner.config.max_horizon,
        };
        Ok((hypotheses, extension))
    }
}

impl Clone for MaxSatSolver {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            cache_hits: self.cache_hits,
            resolved_engine: self.resolved_engine,
        }
    }
}

impl MaxSatSolver {
    /// Backend reported by `name()`.
    ///
    /// Reports the resolved engine, never the configured mode: Auto below the
    /// crossover resolves to the builtin branch-and-bound, and a forced
    /// Cadical request without the feature falls back to the builtin backend
    /// at runtime.
    fn reports_cadical(&self) -> bool {
        self.resolved_engine == SolverEngine::Cadical
    }
}

/// The engine a fresh MaxSat solver resolves to before any encoding exists.
///
/// Auto routes to builtin at every measured encoding size (the crossover
/// sentinel), and a forced Cadical request resolves to the CaDiCaL backend
/// only when the feature is compiled in.
fn initial_resolution(config_engine: SolverEngine) -> SolverEngine {
    match config_engine {
        SolverEngine::Auto | SolverEngine::Builtin => SolverEngine::Builtin,
        SolverEngine::Cadical => {
            if cfg!(feature = "solver-cadical") {
                SolverEngine::Cadical
            } else {
                SolverEngine::Builtin
            }
        }
    }
}

impl FaultSolver for MaxSatSolver {
    fn solve(
        &mut self,
        journal: &Journal,
        verdict: &Verdict,
    ) -> Result<Vec<FaultHypothesis>, SolverError> {
        let (hyps, _) = self.solve_with_certificate(journal, verdict)?;
        Ok(hyps)
    }

    fn name(&self) -> &'static str {
        // Honest about the active backend: the CaDiCaL threshold search only
        // runs under `solver-cadical`; otherwise the pure-Rust
        // branch-and-bound in `crate::maxsat` does the solving.
        if self.reports_cadical() {
            "maxsat-cadical"
        } else {
            "maxsat"
        }
    }

    fn solve_incremental(
        &mut self,
        closure_hash: Hash,
        clauses: Vec<WeightedClause>,
    ) -> Vec<FaultHypothesis> {
        // No encoding exists on this path, so Auto applies the crossover rule
        // to the supplied clause count; callers feed encoding.hard clauses,
        // which makes the tag agree with solve_with_certificate.
        let (tag, _) = self.resolve_backend(clauses.len());
        let key = self.inner.incremental_key_with_tag(closure_hash, tag);
        let hit = self
            .inner
            .hypothesis_cache
            .get(&key)
            .is_some_and(|_| self.inner.cache.get(&key).is_some_and(|c| c == &clauses));
        if hit {
            self.cache_hits += 1;
        }
        self.inner
            .solve_incremental_with_tag(closure_hash, clauses, tag)
    }

    fn snapshot_state(&self) -> Option<crate::solver_state::SolverStateArtifact> {
        Some(self.inner.snapshot_artifact(self.resolved_engine))
    }

    fn warm_from_artifact(
        &mut self,
        artifact: &crate::solver_state::SolverStateArtifact,
    ) -> Result<(), SolverError> {
        self.inner.resume(artifact, self.resolved_engine)
    }
}
