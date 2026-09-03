use super::{
    FaultSolver, HittingSetSolver, SolverConfig, SolverEngine, SolverError, cutoff,
    event_fault_cost, samc_prune,
};
use crate::ldfi::FaultHypothesis;
use crate::oracle::Verdict;
use crate::solver_cache::{ClauseCache, WeightedClause, engine_tag};
use ledger_format::EntryHash;
use ledger_journal::Journal;

/// Weighted MaxSAT solver with MCS lower-bound certificates. Two backends
/// behind one API: builtin branch-and-bound, and CaDiCaL threshold search
/// under `solver-cadical`. Engine resolves post-encode; see [`cutoff()`].
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

    /// Resolved engine of the last solve (or pre-encode default). Drives
    /// state keys and `name()`, never the configured mode.
    pub fn resolved_engine(&self) -> SolverEngine {
        self.resolved_engine
    }

    /// Resolve the backend for an encoding. Deterministic per build.
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

    /// Solve with optional certificate data. Empty cut yields `None`.
    pub fn solve_with_certificate(
        &mut self,
        journal: &Journal,
        verdict: &Verdict,
    ) -> Result<
        (
            Vec<FaultHypothesis>,
            Option<crate::certs::RecordedSolverData>,
        ),
        SolverError,
    > {
        if verdict.witnesses.is_empty() && journal.is_empty() {
            return Ok((Vec::new(), None));
        }
        // Encode first: Auto resolves against encoding size, so no key precedes it.
        let encoding = crate::maxsat::encode_hazard(journal, verdict, &self.inner.config)?;
        let (tag, use_cadical) = self.resolve_backend(encoding.hard.len());
        let mut witness_ids = verdict.witnesses.clone();
        witness_ids.sort();
        let closure_hash = ClauseCache::closure_hash(&witness_ids);
        let key = self.inner.incremental_key_with_tag(closure_hash, tag);
        if self.inner.hypothesis_cache.contains_key(&key) {
            self.cache_hits += 1;
        }
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
        // Per-solver cache only; constructed per campaign.
        self.inner.cache.insert(key, clauses.clone());
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
        let explanation = maxsat_explanation(
            solution.cut.len(),
            encoding.hard.len(),
            solution.lower_bound_proof.unsat_core_cost,
            solution.lower_bound_proof.method,
            &encoding.hard,
            self.inner.config.max_horizon,
        );
        let hypothesis = FaultHypothesis {
            events: solution.cut.clone(),
            total_cost: solution.total_cost,
            explanation,
        };
        let mut hypotheses = vec![hypothesis];
        hypotheses = samc_prune(journal, hypotheses);
        self.inner.hypothesis_cache.insert(key, hypotheses.clone());
        let solver_data = if solution.cut.is_empty() {
            None
        } else {
            Some(crate::certs::RecordedSolverData {
                cut: solution.cut,
                cost: solution.total_cost,
                method: solution.lower_bound_proof.method.to_string(),
                horizon: self.inner.config.max_horizon,
                support_provider_version: self.inner.config.support_version,
                witnesses: verdict.witnesses.clone(),
                reproduced: false,
                baseline_passed: false,
            })
        };
        Ok((hypotheses, solver_data))
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
    /// Reports the resolved engine, never the configured mode.
    fn reports_cadical(&self) -> bool {
        self.resolved_engine == SolverEngine::Cadical
    }
}

/// Wording for the MaxSAT solve, gated on [`SupportExpr::is_strong`].
fn maxsat_explanation(
    faults: usize,
    hard_clauses: usize,
    lower: u64,
    method: &'static str,
    hard: &[Vec<EntryHash>],
    horizon: Option<usize>,
) -> String {
    let truncated = horizon.is_some();
    let support = crate::support::support_from_paths(hard, truncated);
    if support.is_strong() {
        format!(
            "Weighted MaxSAT minimum cut with {faults} fault(s) breaking {hard_clauses} hard clause(s); lower bound {lower} via {method}"
        )
    } else {
        match horizon {
            Some(h) => format!(
                "Weighted MaxSAT bounded heuristic cut with {faults} fault(s) breaking {hard_clauses} hard clause(s) at horizon {h}; lower bound {lower} via {method}"
            ),
            None => format!(
                "Weighted MaxSAT heuristic cut with {faults} fault(s) breaking {hard_clauses} hard clause(s) (unknown support); lower bound {lower} via {method}"
            ),
        }
    }
}

/// Pre-encode resolution: Auto/Builtin to builtin; Cadical per feature gate.
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
        // Reports the active backend truthfully per feature gate.
        if self.reports_cadical() {
            "maxsat-cadical"
        } else {
            "maxsat"
        }
    }

    fn solve_incremental(
        &mut self,
        closure_hash: EntryHash,
        clauses: Vec<WeightedClause>,
    ) -> Vec<FaultHypothesis> {
        // No encoding here: Auto applies the crossover rule to the clause count.
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
