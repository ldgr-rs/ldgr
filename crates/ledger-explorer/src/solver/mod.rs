//! Fault solver abstraction for LDFI.
//!
//! The `FaultSolver` trait decouples call sites from the concrete engines.
//! `HittingSetSolver` is the deterministic exact hitting-set engine over
//! causal derivation paths. `MaxSatSolver` solves the weighted-MaxSAT hazard
//! encoding from `crate::maxsat` - a deterministic branch-and-bound, or the
//! CaDiCaL ascending-threshold search behind the `solver-cadical` feature -
//! and emits MCS lower-bound certificates alongside its hypotheses. Both
//! engines memoize through the shared content-addressed clause cache.
//!
//! Production call sites do not construct engines directly: they encode the
//! hazard, then route through [`select_solver`], which applies the routing
//! rule in `config::CADICAL_CUTOFF_HARD_CLAUSES`. That constant currently
//! holds the "crossover not yet observed" sentinel: the crossover bench
//! found no clause count where CaDiCaL beat the builtin engines, so `Auto`
//! resolves to builtin in every build until a measured crossover exists.

mod config;
mod hitting_set;
mod maxsat;
#[cfg(test)]
mod tests;

pub use config::{
    CADICAL_CUTOFF_HARD_CLAUSES, FaultSolver, SolverConfig, SolverEngine, SolverError, cutoff,
    select_solver,
};
pub use hitting_set::{
    HittingSetSolver, causal_closure_with_horizon, event_fault_cost, is_faultable, samc_prune,
};
pub use maxsat::MaxSatSolver;

use ledger_format::Hash;
use std::collections::BTreeSet;

use crate::ldfi::FaultableEvent;

/// Compute minimal hitting sets over derivation paths.
///
/// Deterministic: sorts inputs and prunes supersets.
fn compute_minimal_hitting_sets(paths: &[Vec<FaultableEvent>]) -> Vec<BTreeSet<Hash>> {
    let mut candidate_sets: Vec<BTreeSet<Hash>> = vec![BTreeSet::new()];

    for path in paths {
        let path_hashes: BTreeSet<Hash> = path.iter().map(|event| event.event).collect();
        let mut next_candidates: Vec<BTreeSet<Hash>> = Vec::new();

        for current in candidate_sets {
            if current.iter().any(|hash| path_hashes.contains(hash)) {
                next_candidates.push(current);
            } else {
                for hash in &path_hashes {
                    let mut expanded = current.clone();
                    expanded.insert(*hash);
                    next_candidates.push(expanded);
                }
            }
        }

        candidate_sets = prune_supersets(next_candidates);
    }

    candidate_sets
}

fn prune_supersets(mut sets: Vec<BTreeSet<Hash>>) -> Vec<BTreeSet<Hash>> {
    // Deduplicate and order by size so smaller sets prune larger supersets early.
    sets.sort();
    sets.dedup();
    sets.sort_by_key(|set| set.len());

    let mut minimal: Vec<BTreeSet<Hash>> = Vec::new();
    for set in sets {
        if minimal.iter().any(|existing| existing.is_subset(&set)) {
            continue;
        }
        minimal.retain(|existing| !set.is_subset(existing));
        minimal.push(set);
    }
    minimal.sort();
    minimal
}
