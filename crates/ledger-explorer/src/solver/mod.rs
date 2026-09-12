//! Fault solver abstraction for LDFI. Call sites encode, then route via
//! [`select_solver`]; `Auto` resolves to builtin until a measured CaDiCaL
//! crossover exists.

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

use ledger_format::EntryHash;
use std::collections::BTreeSet;

use crate::ldfi::FaultableEvent;

/// Maximum derivation paths the exact hitting-set engine accepts; excess
/// fails closed instead of enumerating a super-polynomial candidate space.
pub const MAX_HITTING_SET_PATHS: usize = 65536;

/// Maximum candidate sets enumerated between pruning rounds; excess fails
/// closed with [`SolverError::BudgetExhausted`].
pub const MAX_HITTING_SET_CANDIDATES: usize = 65536;

/// Minimal hitting sets. Deterministic: sorted inputs, pruned supersets.
/// Fails closed when the path or candidate budget would be exceeded.
fn compute_minimal_hitting_sets(
    paths: &[Vec<FaultableEvent>],
) -> Result<Vec<BTreeSet<EntryHash>>, SolverError> {
    if paths.len() > MAX_HITTING_SET_PATHS {
        return Err(SolverError::BudgetExhausted(
            "derivation paths exceed the hitting-set budget",
        ));
    }
    let mut candidate_sets: Vec<BTreeSet<EntryHash>> = vec![BTreeSet::new()];

    for path in paths {
        let path_hashes: BTreeSet<EntryHash> = path.iter().map(|event| event.event).collect();
        let mut next_candidates: Vec<BTreeSet<EntryHash>> = Vec::new();

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

        if next_candidates.len() > MAX_HITTING_SET_CANDIDATES {
            return Err(SolverError::BudgetExhausted(
                "hitting-set candidate sets exceed the budget",
            ));
        }
        candidate_sets = prune_supersets(next_candidates);
    }

    Ok(candidate_sets)
}

fn prune_supersets(mut sets: Vec<BTreeSet<EntryHash>>) -> Vec<BTreeSet<EntryHash>> {
    // Size order lets smaller sets prune supersets early.
    sets.sort();
    sets.dedup();
    sets.sort_by_key(|set| set.len());

    let mut minimal: Vec<BTreeSet<EntryHash>> = Vec::new();
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
