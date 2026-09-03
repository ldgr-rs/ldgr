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

/// Minimal hitting sets. Deterministic: sorted inputs, pruned supersets.
fn compute_minimal_hitting_sets(paths: &[Vec<FaultableEvent>]) -> Vec<BTreeSet<EntryHash>> {
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

        candidate_sets = prune_supersets(next_candidates);
    }

    candidate_sets
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
