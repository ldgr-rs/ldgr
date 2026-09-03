use super::{FaultSolver, SolverConfig, SolverEngine, SolverError, compute_minimal_hitting_sets};
use crate::ldfi::{FaultHypothesis, FaultableEvent};
use crate::lineage::LineageIndex;
use crate::oracle::Verdict;
use crate::solver_cache::{ClauseCache, WeightedClause, engine_tag};
use ledger_format::{EntryHash, EntryKind};
use ledger_journal::{Journal, JournalError, VectorClock};
use std::collections::HashMap;

/// Deterministic exact hitting-set solver. Sorted literals and `BTreeSet`
/// dedup keep hypotheses byte-identical; clause cache is content-addressed.
#[derive(Debug, Clone)]
pub struct HittingSetSolver {
    pub(crate) cache: ClauseCache,
    pub(crate) hypothesis_cache: HashMap<EntryHash, Vec<FaultHypothesis>>,
    pub(crate) config: SolverConfig,
    lineage: Option<LineageIndex>,
}

impl Default for HittingSetSolver {
    fn default() -> Self {
        Self::new()
    }
}

impl HittingSetSolver {
    /// Production default per §4.4 item 5: bounded horizon 64.
    pub fn new() -> Self {
        Self {
            cache: ClauseCache::new(),
            hypothesis_cache: HashMap::new(),
            config: SolverConfig {
                max_horizon: Some(64),
                ..SolverConfig::default()
            },
            lineage: None,
        }
    }

    /// Unbounded horizon for tests and offline full-journal analysis.
    pub fn unbounded() -> Self {
        Self {
            cache: ClauseCache::new(),
            hypothesis_cache: HashMap::new(),
            config: SolverConfig::default(),
            lineage: None,
        }
    }

    pub fn with_config(config: SolverConfig) -> Self {
        Self {
            cache: ClauseCache::new(),
            hypothesis_cache: HashMap::new(),
            config,
            lineage: None,
        }
    }

    /// Resolves to [`SolverEngine::Builtin`]; derives the solver-state key.
    pub fn resolved_engine(&self) -> SolverEngine {
        SolverEngine::Builtin
    }

    pub fn with_horizon(max_depth: usize) -> Self {
        Self::with_config(SolverConfig::default().with_horizon(max_depth))
    }

    pub fn config(&self) -> &SolverConfig {
        &self.config
    }

    pub fn set_config(&mut self, config: SolverConfig) {
        self.config = config;
    }

    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    pub fn hypothesis_cache_len(&self) -> usize {
        self.hypothesis_cache.len()
    }

    pub(crate) fn incremental_key(&self, closure_hash: EntryHash) -> EntryHash {
        self.incremental_key_with_tag(closure_hash, engine_tag::BUILTIN)
    }

    /// Cache key for an engine tag. Tags plus run-config hash and max-faults
    /// separate the cache namespace per encoding input.
    pub(crate) fn incremental_key_with_tag(
        &self,
        closure_hash: EntryHash,
        engine_tag: u8,
    ) -> EntryHash {
        ClauseCache::compute_key(closure_hash, engine_tag, &self.config)
    }

    pub(crate) fn clause_cache(&self) -> &ClauseCache {
        &self.cache
    }

    pub(crate) fn clause_cache_mut(&mut self) -> &mut ClauseCache {
        &mut self.cache
    }

    pub(crate) fn hypothesis_cache(&self) -> &HashMap<EntryHash, Vec<FaultHypothesis>> {
        &self.hypothesis_cache
    }

    pub(crate) fn hypothesis_cache_mut(&mut self) -> &mut HashMap<EntryHash, Vec<FaultHypothesis>> {
        &mut self.hypothesis_cache
    }

    /// Solve from an explicit support expression, preserving groups. Fails
    /// closed with [`SolverError::EmptyProvenance`]; wording follows
    /// [`crate::support::SupportExpr::is_strong`].
    pub fn solve_with_support(
        &mut self,
        journal: &Journal,
        verdict: &Verdict,
        support: &crate::support::SupportExpr,
    ) -> Result<Vec<FaultHypothesis>, SolverError> {
        use crate::solver::event_fault_cost;
        if verdict.witnesses.is_empty() && journal.is_empty() {
            return Ok(Vec::new());
        }
        let mut witness_ids = verdict.witnesses.clone();
        witness_ids.sort();
        let closure_hash = ClauseCache::closure_hash(&witness_ids);
        let key = self.incremental_key(closure_hash);
        let mut all_paths: Vec<Vec<FaultableEvent>> = Vec::new();
        for mut clause in crate::support::hard_clauses_from_support(support) {
            clause.retain(|h| {
                journal
                    .get(h)
                    .is_some_and(|e| super::is_faultable(e.data.kind))
            });
            if clause.is_empty() {
                continue;
            }
            clause.sort();
            let mut fe_path = Vec::new();
            for h in clause {
                if let Some(entry) = journal.get(&h) {
                    fe_path.push(FaultableEvent {
                        event: h,
                        kind: entry.data.kind,
                        cost: event_fault_cost(journal, &h),
                    });
                }
            }
            if !fe_path.is_empty() {
                all_paths.push(fe_path);
            }
        }
        if all_paths.is_empty() {
            return Err(SolverError::EmptyProvenance);
        }
        let clauses: Vec<WeightedClause> = all_paths
            .iter()
            .map(|path| {
                let lits = path.iter().map(|e| e.event).collect::<Vec<_>>();
                let weight = path.iter().map(|e| e.cost).min().unwrap_or(1);
                WeightedClause::new(lits, weight)
            })
            .collect();
        if let Some(cached) = self.hypothesis_cache.get(&key)
            && self
                .cache
                .get(&key)
                .is_some_and(|cached_clauses| cached_clauses == &clauses)
        {
            return Ok(cached.clone());
        }
        self.cache.insert(key, clauses.clone());
        let hitting_sets = compute_minimal_hitting_sets(&all_paths);
        let hash_paths: Vec<Vec<EntryHash>> = all_paths
            .iter()
            .map(|path| path.iter().map(|event| event.event).collect())
            .collect();
        // Support-gated wording uses the caller-supplied expression directly:
        // only `is_strong` backs a minimum claim.
        let strong = support.is_strong();
        let horizon = self.config.max_horizon;
        let path_count = all_paths.len();
        let mut hypotheses: Vec<FaultHypothesis> = hitting_sets
            .into_iter()
            .map(|events_set| {
                let events: Vec<EntryHash> = events_set.into_iter().collect();
                let total_cost = events
                    .iter()
                    .map(|hash| event_fault_cost(journal, hash))
                    .sum::<u64>();
                let explanation = if strong {
                    format!(
                        "Minimum hitting set cut with {} fault(s) breaking {} causal derivation path(s)",
                        events.len(),
                        path_count
                    )
                } else {
                    match horizon {
                        Some(h) => format!(
                            "Bounded heuristic hitting set cut with {} fault(s) breaking {} causal derivation path(s) at horizon {h}",
                            events.len(),
                            path_count
                        ),
                        None => format!(
                            "Heuristic hitting set cut with {} fault(s) breaking {} causal derivation path(s) (unknown support)",
                            events.len(),
                            path_count
                        ),
                    }
                };
                FaultHypothesis {
                    events,
                    total_cost,
                    explanation,
                }
            })
            .collect();
        hypotheses.sort_by_key(|hypothesis| (hypothesis.total_cost, hypothesis.events.len()));
        hypotheses = samc_prune(journal, hypotheses);
        self.hypothesis_cache.insert(key, hypotheses.clone());
        let _ = hash_paths;
        Ok(hypotheses)
    }

    /// Incremental solve under an explicit engine tag; shares the encode-path namespace.
    pub(crate) fn solve_incremental_with_tag(
        &mut self,
        closure_hash: EntryHash,
        clauses: Vec<WeightedClause>,
        engine_tag: u8,
    ) -> Vec<FaultHypothesis> {
        let key = self.incremental_key_with_tag(closure_hash, engine_tag);
        // Per-solver cache only; no process-global store exists.
        if let Some(cached) = self.hypothesis_cache.get(&key) {
            // A clause mismatch invalidates the cached derivation; fall
            // through to recompute. A missing clause entry is stale or
            // forged state and recomputes as well: the closure hash alone
            // never authorizes a cached hypothesis.
            if let Some(cached_clauses) = self.cache.get(&key)
                && cached_clauses == &clauses
            {
                return cached.clone();
            }
        }

        // No journal here: per-event cost is the minimum clause weight;
        // kind is unavailable so Send stands in (only the hash is read).
        let mut event_costs: HashMap<EntryHash, u64> = HashMap::new();
        let paths: Vec<Vec<FaultableEvent>> = clauses
            .iter()
            .map(|clause| {
                clause
                    .literals
                    .iter()
                    .map(|hash| {
                        let cost = event_costs.entry(*hash).or_insert(u64::MAX);
                        *cost = (*cost).min(clause.weight);
                        FaultableEvent {
                            event: *hash,
                            kind: EntryKind::Send,
                            cost: clause.weight,
                        }
                    })
                    .collect()
            })
            .collect();

        let hitting_sets = if paths.is_empty() {
            Vec::new()
        } else {
            compute_minimal_hitting_sets(&paths)
        };

        let mut hypotheses: Vec<FaultHypothesis> = hitting_sets
            .into_iter()
            .map(|events_set| {
                let events: Vec<EntryHash> = events_set.into_iter().collect();
                // Fallback only for malformed clauses; mirrors minimum weight.
                let total_cost: u64 = events
                    .iter()
                    .map(|hash| event_costs.get(hash).copied().unwrap_or(1))
                    .sum();
                let clause_literals: Vec<Vec<EntryHash>> = clauses
                    .iter()
                    .map(|clause| clause.literals.clone())
                    .collect();
                let explanation = incremental_explanation(
                    events.len(),
                    clauses.len(),
                    &clause_literals,
                    self.config.max_horizon,
                );
                FaultHypothesis {
                    events,
                    total_cost,
                    explanation,
                }
            })
            .collect();
        hypotheses.sort_by_key(|h| (h.total_cost, h.events.len()));

        // Per-solver memo only; each campaign constructs its solver anew.
        self.cache.insert(key, clauses.clone());
        self.hypothesis_cache.insert(key, hypotheses.clone());
        hypotheses
    }
}

/// Wording for the incremental path, gated on support strength: bounded
/// walks report a heuristic with the horizon.
fn incremental_explanation(
    faults: usize,
    clauses: usize,
    clause_literals: &[Vec<EntryHash>],
    horizon: Option<usize>,
) -> String {
    let truncated = horizon.is_some();
    let support = crate::support::support_from_paths(clause_literals, truncated);
    if support.is_strong() {
        format!("Incremental hitting set cut with {faults} fault(s) over {clauses} clause(s)")
    } else {
        match horizon {
            Some(h) => format!(
                "Bounded heuristic hitting set cut with {faults} fault(s) over {clauses} clause(s) at horizon {h}"
            ),
            None => format!(
                "Heuristic hitting set cut with {faults} fault(s) over {clauses} clause(s) (unknown support)"
            ),
        }
    }
}

/// Wording for the full solve, gated on [`SupportExpr::is_strong`].
fn solve_explanation(
    faults: usize,
    paths: usize,
    hash_paths: &[Vec<EntryHash>],
    horizon: Option<usize>,
) -> String {
    let truncated = horizon.is_some();
    let support = crate::support::support_from_paths(hash_paths, truncated);
    if support.is_strong() {
        format!(
            "Minimum hitting set cut with {faults} fault(s) breaking {paths} causal derivation path(s)"
        )
    } else {
        match horizon {
            Some(h) => format!(
                "Bounded heuristic hitting set cut with {faults} fault(s) breaking {paths} causal derivation path(s) at horizon {h}"
            ),
            None => format!(
                "Heuristic hitting set cut with {faults} fault(s) breaking {paths} causal derivation path(s) (unknown support)"
            ),
        }
    }
}

impl FaultSolver for HittingSetSolver {
    fn solve(
        &mut self,
        journal: &Journal,
        verdict: &Verdict,
    ) -> Result<Vec<FaultHypothesis>, SolverError> {
        if verdict.witnesses.is_empty() && journal.is_empty() {
            return Ok(Vec::new());
        }

        // Per-solver cache only; never shared across campaigns.
        let mut witness_ids = verdict.witnesses.clone();
        witness_ids.sort();
        let closure_hash = ClauseCache::closure_hash(&witness_ids);
        let key = self.incremental_key(closure_hash);

        let all_paths: Vec<Vec<FaultableEvent>> = {
            let witnesses_slice: &[EntryHash] = &verdict.witnesses;
            let resolved = self.resolved_engine();
            let lineage = self.lineage.get_or_insert_with(|| {
                LineageIndex::build(journal, witnesses_slice, &self.config, resolved)
            });
            lineage.refresh(journal, witnesses_slice, &self.config, resolved);
            let mut converted: Vec<Vec<FaultableEvent>> = Vec::new();
            for hash_path in lineage.paths().to_vec() {
                let mut fe_path = Vec::new();
                for h in hash_path {
                    if let Some(entry) = journal.get(&h) {
                        fe_path.push(FaultableEvent {
                            event: h,
                            kind: entry.data.kind,
                            cost: event_fault_cost(journal, &h),
                        });
                    }
                }
                if !fe_path.is_empty() {
                    converted.push(fe_path);
                }
            }
            converted
        };

        if all_paths.is_empty() {
            // Fail closed; only empty/empty succeeds (handled above).
            if verdict.witnesses.is_empty() {
                return Ok(Vec::new());
            }
            return Err(SolverError::EmptyProvenance);
        }

        // Encode paths as clauses for caching.
        let clauses: Vec<WeightedClause> = all_paths
            .iter()
            .map(|path| {
                let lits = path.iter().map(|e| e.event).collect::<Vec<_>>();
                let weight = path.iter().map(|e| e.cost).min().unwrap_or(1);
                WeightedClause::new(lits, weight)
            })
            .collect();

        // Cached derivation serves only on clause equality; stale entries recompute.
        if let Some(cached) = self.hypothesis_cache.get(&key)
            && self
                .cache
                .get(&key)
                .is_some_and(|cached_clauses| cached_clauses == &clauses)
        {
            return Ok(cached.clone());
        }

        // Insert clauses into the per-solver cache only. No global store
        // exists; each campaign constructs its solver anew.
        self.cache.insert(key, clauses.clone());

        let hitting_sets = compute_minimal_hitting_sets(&all_paths);
        let hash_paths: Vec<Vec<EntryHash>> = all_paths
            .iter()
            .map(|path| path.iter().map(|event| event.event).collect())
            .collect();
        let horizon = self.config.max_horizon;
        let path_count = all_paths.len();
        let mut hypotheses: Vec<FaultHypothesis> = hitting_sets
            .into_iter()
            .map(|events_set| {
                let events: Vec<EntryHash> = events_set.into_iter().collect();
                let total_cost = events
                    .iter()
                    .map(|hash| event_fault_cost(journal, hash))
                    .sum::<u64>();
                let explanation = solve_explanation(events.len(), path_count, &hash_paths, horizon);
                FaultHypothesis {
                    events,
                    total_cost,
                    explanation,
                }
            })
            .collect();

        hypotheses.sort_by_key(|hypothesis| (hypothesis.total_cost, hypothesis.events.len()));
        hypotheses = samc_prune(journal, hypotheses);
        self.hypothesis_cache.insert(key, hypotheses.clone());
        Ok(hypotheses)
    }

    fn name(&self) -> &'static str {
        "hitting-set"
    }

    fn solve_incremental(
        &mut self,
        closure_hash: EntryHash,
        clauses: Vec<WeightedClause>,
    ) -> Vec<FaultHypothesis> {
        self.solve_incremental_with_tag(closure_hash, clauses, engine_tag::BUILTIN)
    }

    fn snapshot_state(&self) -> Option<crate::solver_state::SolverStateArtifact> {
        Some(self.snapshot_artifact(self.resolved_engine()))
    }

    fn warm_from_artifact(
        &mut self,
        artifact: &crate::solver_state::SolverStateArtifact,
    ) -> Result<(), SolverError> {
        self.resume(artifact, self.resolved_engine())
    }
}

/// Faultable boundary kinds. Single source for solver, encoding, lineage.
pub fn is_faultable(kind: EntryKind) -> bool {
    matches!(
        kind,
        EntryKind::Send
            | EntryKind::Recv
            | EntryKind::FsRead
            | EntryKind::FsWrite
            | EntryKind::TimerFire
            | EntryKind::TimerSet
    )
}

/// Fault-injection cost per event: Send/Recv 2, timer 3, fs 4, other 5,
/// missing 10. Feeds ranking, weights, and the certificate bound.
pub fn event_fault_cost(journal: &Journal, hash: &EntryHash) -> u64 {
    journal
        .get(hash)
        .map(|entry| match entry.data.kind {
            EntryKind::Send | EntryKind::Recv => 2,
            EntryKind::TimerFire | EntryKind::TimerSet => 3,
            EntryKind::FsRead | EntryKind::FsWrite => 4,
            _ => 5,
        })
        .unwrap_or(10)
}

/// Bounded-horizon causal closure in journal order. Deterministic, no time.
pub fn causal_closure_with_horizon(
    journal: &Journal,
    targets: &[EntryHash],
    max_depth: usize,
) -> Result<Vec<EntryHash>, JournalError> {
    for target in targets {
        if journal.get(target).is_none() {
            return Err(JournalError::MissingParent(*target));
        }
    }
    use std::collections::HashSet;
    let mut seen: HashSet<EntryHash> = HashSet::new();
    let mut frontier: Vec<(EntryHash, usize)> = targets.iter().map(|id| (*id, 0)).collect();
    while let Some((id, depth)) = frontier.pop() {
        if !seen.insert(id) {
            continue;
        }
        if depth >= max_depth {
            continue;
        }
        if let Some(entry) = journal.get(&id) {
            for parent in &entry.data.parents {
                if !seen.contains(parent) {
                    frontier.push((*parent, depth + 1));
                }
            }
        }
    }
    Ok(journal
        .entries()
        .filter_map(|entry| {
            if seen.contains(&entry.id) {
                Some(entry.id)
            } else {
                None
            }
        })
        .collect())
}

/// Prune hypotheses differing by one concurrent-event swap; keeps the
/// cheaper. Deterministic: cost, size, then hash order.
pub fn samc_prune(journal: &Journal, hypotheses: Vec<FaultHypothesis>) -> Vec<FaultHypothesis> {
    if hypotheses.len() <= 1 {
        return hypotheses;
    }
    let mut sorted = hypotheses;
    sorted.sort_by(|a, b| {
        a.total_cost
            .cmp(&b.total_cost)
            .then(a.events.len().cmp(&b.events.len()))
            .then(a.events.cmp(&b.events))
    });

    // Build cache of vector clocks for events present in any hypothesis.
    let mut clock_cache: HashMap<EntryHash, VectorClock> = HashMap::new();
    for hyp in &sorted {
        for event in &hyp.events {
            if !clock_cache.contains_key(event)
                && let Some(entry) = journal.get(event)
            {
                clock_cache.insert(*event, entry.vector_clock.clone());
            }
        }
    }

    let mut pruned: Vec<FaultHypothesis> = Vec::new();
    for hyp in sorted {
        let mut dominated = false;
        for existing in &pruned {
            if existing.events.len() != hyp.events.len() {
                continue;
            }
            // Compute symmetric difference.
            let mut diff_existing: Vec<EntryHash> = Vec::new();
            let mut diff_hyp: Vec<EntryHash> = Vec::new();
            for event in &existing.events {
                if !hyp.events.contains(event) {
                    diff_existing.push(*event);
                }
            }
            for event in &hyp.events {
                if !existing.events.contains(event) {
                    diff_hyp.push(*event);
                }
            }
            if diff_existing.len() == 1 && diff_hyp.len() == 1 {
                let a = diff_existing[0];
                let b = diff_hyp[0];
                if let (Some(ca), Some(cb)) = (clock_cache.get(&a), clock_cache.get(&b))
                    && ca.concurrent_with(cb)
                {
                    // Existing is cheaper or equal due to sort; prune hyp.
                    dominated = true;
                    break;
                }
            }
        }
        if !dominated {
            // Avoid inserting duplicates.
            if !pruned.iter().any(|e| e.events == hyp.events) {
                pruned.push(hyp);
            }
        }
    }
    pruned
}
