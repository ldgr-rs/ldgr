#![deny(unsafe_code)]

//! CaDiCaL-backed weighted-MaxSAT engine behind `solver-cadical`.
//!
//! Exact optimum via bounded binary threshold search. Each threshold K builds
//! a fresh CaDiCaL instance encoding hard clauses, unit equivalences (event
//! var <-> cost unit copies), and a sequential-counter at-most-K constraint
//! over all unit copies. Feasibility is monotone in K (a larger bound only
//! relaxes the counter), so binary search finds the first SAT K with
//! O(log total_units) probes instead of a linear scan. Each probe is fresh,
//! but the instances are tiny (journal bounded horizon 64, ~10 distinct
//! events) so search is milliseconds. Determinism is via sorted-hash
//! variable numbering.

use crate::maxsat::{LOWER_BOUND_METHOD, LowerBoundProof, MaxSatSolution};
use crate::solver::SolverError;
use ledger_format::EntryHash;
use std::collections::BTreeMap;

/// Upper bound on binary-search probes.
///
/// `total_units` fits in `u64`, so 64 probes always suffice; the loop also
/// breaks on convergence, typically in `log2(total_units)` steps.
const MAX_THRESHOLD_PROBES: usize = 64;

pub(crate) fn solve_maxsat_incremental(
    encoding: &crate::maxsat::HazardEncoding,
) -> Result<MaxSatSolution, SolverError> {
    if encoding.hard.is_empty() {
        return Ok(MaxSatSolution {
            cut: Vec::new(),
            total_cost: 0,
            lower_bound_proof: LowerBoundProof {
                method: LOWER_BOUND_METHOD,
                unsat_core_cost: 0,
            },
        });
    }
    let mut event_cost: BTreeMap<EntryHash, u64> = BTreeMap::new();
    for (lits, w) in &encoding.soft {
        for h in lits {
            event_cost.insert(*h, *w);
        }
    }
    let mut events: Vec<EntryHash> = event_cost.keys().copied().collect();
    events.sort();
    let total_units: u64 = event_cost.values().sum();
    let hard = &encoding.hard;
    // Bounded binary search for the least feasible K. Feasibility is monotone:
    // when K is SAT, every larger K is SAT because the at-most-K counter only
    // relaxes. The probe order is deterministic and the variable numbering
    // inside `try_threshold` is sorted-hash order, so the same encoding
    // yields byte-identical cuts within one build.
    if try_threshold(total_units, hard, &events, &event_cost, encoding).is_none() {
        return Err(SolverError::Unsupported);
    }
    if total_units == 0 {
        let cut = try_threshold(0, hard, &events, &event_cost, encoding)
            .ok_or(SolverError::Unsupported)?;
        return Ok(MaxSatSolution {
            cut,
            total_cost: 0,
            lower_bound_proof: LowerBoundProof {
                method: LOWER_BOUND_METHOD,
                unsat_core_cost: 0,
            },
        });
    }
    let mut lo = 0u64;
    let mut hi = total_units;
    for _ in 0..MAX_THRESHOLD_PROBES {
        if lo >= hi {
            break;
        }
        let mid = lo.saturating_add(hi.saturating_sub(lo) / 2);
        if try_threshold(mid, hard, &events, &event_cost, encoding).is_some() {
            hi = mid;
        } else {
            lo = mid.saturating_add(1);
        }
    }
    let total_cost = hi;
    let cut =
        try_threshold(hi, hard, &events, &event_cost, encoding).ok_or(SolverError::Unsupported)?;
    let lower = crate::maxsat::disjoint_lower(hard, &event_cost).min(total_cost);
    Ok(MaxSatSolution {
        cut,
        total_cost,
        lower_bound_proof: LowerBoundProof {
            method: LOWER_BOUND_METHOD,
            unsat_core_cost: lower,
        },
    })
}

fn try_threshold(
    k: u64,
    hard: &[Vec<EntryHash>],
    events: &[EntryHash],
    event_cost: &BTreeMap<EntryHash, u64>,
    encoding: &crate::maxsat::HazardEncoding,
) -> Option<Vec<EntryHash>> {
    let mut vars: BTreeMap<EntryHash, i32> = BTreeMap::new();
    let mut next_var = 1i32;
    for h in events {
        vars.insert(*h, next_var);
        next_var += 1;
    }
    let mut solver: cadical::Solver = cadical::Solver::new();
    for clause in hard {
        let lits: Vec<i32> = clause.iter().map(|h| vars[h]).collect();
        if lits.is_empty() {
            continue;
        }
        solver.add_clause(lits);
    }
    if let Some(card) = &encoding.cardinality {
        let max_true = card.max_true;
        if events.len() > max_true {
            let xs: Vec<i32> = events.iter().map(|h| vars[h]).collect();
            sequential_at_most(max_true as u64, &xs, &mut solver, &mut next_var);
        }
    }
    let unit_vars: Vec<i32> = {
        let mut units: Vec<i32> = Vec::new();
        for h in events {
            let cost = event_cost[h] as usize;
            let v = vars[h];
            for _ in 0..cost {
                let u = next_var;
                next_var += 1;
                solver.add_clause([-v, u]);
                solver.add_clause([-u, v]);
                units.push(u);
            }
        }
        if k < units.len() as u64 {
            sequential_at_most(k, &units, &mut solver, &mut next_var);
        }
        units
    };
    drop(unit_vars);
    match solver.solve() {
        Some(true) => {
            let mut cut: Vec<EntryHash> = Vec::new();
            for h in events {
                if solver.value(vars[h]).unwrap_or(false) {
                    cut.push(*h);
                }
            }
            Some(cut)
        }
        Some(false) => None,
        None => None,
    }
}

fn sequential_at_most(k: u64, xs: &[i32], solver: &mut cadical::Solver, next_var: &mut i32) {
    let n = xs.len();
    let kk = k as usize;
    if kk >= n {
        return;
    }
    if kk == 0 {
        for &x in xs {
            solver.add_clause([-x]);
        }
        return;
    }
    let mut s: Vec<Vec<i32>> = vec![vec![0; kk + 1]; n + 1];
    for (i, row) in s.iter_mut().enumerate().take(n + 1).skip(1) {
        for cell in row.iter_mut().take(kk.min(i) + 1).skip(1) {
            *cell = *next_var;
            *next_var += 1;
        }
    }
    solver.add_clause([-xs[0], s[1][1]]);
    for i in 2..=n {
        solver.add_clause([-xs[i - 1], s[i][1]]);
        solver.add_clause([-s[i - 1][1], s[i][1]]);
    }
    for i in 2..=n {
        let upper = kk.min(i);
        for kc in 2..=upper {
            solver.add_clause([-xs[i - 1], -s[i - 1][kc - 1], s[i][kc]]);
            if s[i - 1][kc] != 0 {
                solver.add_clause([-s[i - 1][kc], s[i][kc]]);
            }
        }
    }
    for i in 2..=n {
        if kk < i {
            solver.add_clause([-xs[i - 1], -s[i - 1][kk]]);
        }
    }
}
