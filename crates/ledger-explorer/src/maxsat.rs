#![deny(unsafe_code)]
//! Weighted MaxSAT hazard encoding: hitting-set over deduplicated faultable-path disjunctions priced by per-kind costs with a solver-side cardinality bound.
//! Self-contained deterministic branch-and-bound; CaDiCaL wired via solver-cadical feature.
use crate::oracle::Verdict;
use crate::solver::{SolverConfig, SolverError, event_fault_cost, is_faultable};
use ledger_format::Hash;
use ledger_journal::{Journal, JournalError};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardinalityBound {
    pub literals: Vec<Hash>,
    pub max_true: usize,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HazardEncoding {
    pub hard: Vec<Vec<Hash>>,
    pub soft: Vec<(Vec<Hash>, u64)>,
    pub cardinality: Option<CardinalityBound>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LowerBoundProof {
    pub method: &'static str,
    pub unsat_core_cost: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxSatSolution {
    pub cut: Vec<Hash>,
    pub total_cost: u64,
    pub lower_bound_proof: LowerBoundProof,
}
/// Method tag carried by every MCS lower-bound certificate this module emits.
pub const LOWER_BOUND_METHOD: &str = "mcs-lower-bound-v1";
fn collect_memo(
    journal: &Journal,
    cur: Hash,
    memo: &mut BTreeMap<Hash, Vec<Vec<Hash>>>,
) -> Vec<Vec<Hash>> {
    if let Some(cached) = memo.get(&cur) {
        return cached.clone();
    }
    let Some(entry) = journal.get(&cur) else {
        return Vec::new();
    };
    let faultable = is_faultable(entry.data.kind);
    let mut paths: Vec<Vec<Hash>> = Vec::new();
    if entry.data.parents.is_empty() {
        if faultable {
            paths.push(vec![cur]);
        } else {
            paths.push(Vec::new());
        }
    } else {
        for p in &entry.data.parents {
            for sub in collect_memo(journal, *p, memo) {
                let mut path = sub;
                if faultable {
                    path.push(cur);
                }
                paths.push(path);
            }
        }
    }
    memo.insert(cur, paths.clone());
    paths
}

fn collect_bounded_memo(
    journal: &Journal,
    cur: Hash,
    depth: usize,
    limit: usize,
    memo: &mut BTreeMap<(Hash, usize), Vec<Vec<Hash>>>,
) -> Vec<Vec<Hash>> {
    if depth > limit {
        return vec![Vec::new()];
    }
    if let Some(cached) = memo.get(&(cur, depth)) {
        return cached.clone();
    }
    let Some(entry) = journal.get(&cur) else {
        return Vec::new();
    };
    let faultable = is_faultable(entry.data.kind);
    let mut paths: Vec<Vec<Hash>> = Vec::new();
    if entry.data.parents.is_empty() {
        if faultable {
            paths.push(vec![cur]);
        } else {
            paths.push(Vec::new());
        }
    } else {
        for p in &entry.data.parents {
            for sub in collect_bounded_memo(journal, *p, depth + 1, limit, memo) {
                let mut path = sub;
                if faultable {
                    path.push(cur);
                }
                paths.push(path);
            }
        }
    }
    memo.insert((cur, depth), paths.clone());
    paths
}

pub fn encode_hazard(
    journal: &Journal,
    verdict: &Verdict,
    config: &SolverConfig,
) -> Result<HazardEncoding, SolverError> {
    for w in &verdict.witnesses {
        if journal.get(w).is_none() {
            return Err(SolverError::Journal(JournalError::MissingParent(*w)));
        }
    }
    let mut all: Vec<Vec<Hash>> = Vec::new();
    let mut memo = BTreeMap::new();
    let mut bounded_memo = BTreeMap::new();
    for w in &verdict.witnesses {
        if let Some(l) = config.max_horizon {
            for p in collect_bounded_memo(journal, *w, 0, l, &mut bounded_memo) {
                if !p.is_empty() {
                    all.push(p);
                }
            }
        } else {
            for p in collect_memo(journal, *w, &mut memo) {
                if !p.is_empty() {
                    all.push(p);
                }
            }
        }
    }
    if all.is_empty() && !verdict.witnesses.is_empty() {
        let mut fb: Vec<(Hash, u64)> = Vec::new();
        for e in journal.entries() {
            if is_faultable(e.data.kind) {
                fb.push((e.id, event_fault_cost(journal, &e.id)));
            }
        }
        if let Some((id, _)) = fb.iter().max_by_key(|(_, c)| *c) {
            all.push(vec![*id]);
        }
    }
    let mut hard: Vec<Vec<Hash>> = Vec::new();
    for p in &all {
        let s: BTreeSet<Hash> = p.iter().copied().collect();
        if !s.is_empty() {
            hard.push(s.into_iter().collect());
        }
    }
    hard.sort();
    hard.dedup();
    let mut distinct: BTreeSet<Hash> = BTreeSet::new();
    for c in &hard {
        for h in c {
            distinct.insert(*h);
        }
    }
    let mut soft: Vec<(Vec<Hash>, u64)> = Vec::new();
    for h in distinct.iter() {
        soft.push((vec![*h], event_fault_cost(journal, h)));
    }
    soft.sort_by(|a, b| a.0.cmp(&b.0));
    let cardinality = config.max_faults.map(|lim| CardinalityBound {
        literals: distinct.into_iter().collect(),
        max_true: lim,
    });
    Ok(HazardEncoding {
        hard,
        soft,
        cardinality,
    })
}
pub(crate) fn clause_min_cost(c: &[Hash], w: &BTreeMap<Hash, u64>) -> u64 {
    c.iter()
        .filter_map(|h| w.get(h).copied())
        .min()
        .unwrap_or(1)
}
pub(crate) fn disjoint_lower(hard: &[Vec<Hash>], w: &BTreeMap<Hash, u64>) -> u64 {
    let mut s = hard.to_vec();
    s.sort_by(|a, b| {
        clause_min_cost(a, w)
            .cmp(&clause_min_cost(b, w))
            .then(a.len().cmp(&b.len()))
            .then(a.cmp(b))
    });
    let mut used = BTreeSet::new();
    let mut sum = 0u64;
    for cl in s {
        if cl.iter().any(|h| used.contains(h)) {
            continue;
        }
        sum = sum.saturating_add(clause_min_cost(&cl, w));
        for h in cl {
            used.insert(h);
        }
    }
    sum
}
/// Solve the encoding with the default engine for this build.
///
/// With `solver-cadical` this is the exact CaDiCaL threshold search;
/// without it the pure-Rust branch-and-bound runs. See
/// [`solve_maxsat_bnb`] for an engine that is explicit at the call site.
pub fn solve_maxsat(enc: &HazardEncoding) -> Result<MaxSatSolution, SolverError> {
    #[cfg(feature = "solver-cadical")]
    {
        crate::maxsat_cadical::solve_maxsat_incremental(enc)
    }
    #[cfg(not(feature = "solver-cadical"))]
    {
        solve_maxsat_bnb(enc)
    }
}

/// Pure-Rust deterministic branch-and-bound engine, compiled in every build.
///
/// Exists so runtime routing (`crate::solver::select_solver`) and the
/// crossover bench can drive the builtin engine even when the CaDiCaL
/// feature is on. Deterministic: sorted clause and literal orders fix the
/// search order, so the same encoding yields byte-identical solutions.
pub fn solve_maxsat_bnb(enc: &HazardEncoding) -> Result<MaxSatSolution, SolverError> {
    if enc.hard.is_empty() {
        return Ok(MaxSatSolution {
            cut: Vec::new(),
            total_cost: 0,
            lower_bound_proof: LowerBoundProof {
                method: LOWER_BOUND_METHOD,
                unsat_core_cost: 0,
            },
        });
    }
    let mut weights: BTreeMap<Hash, u64> = BTreeMap::new();
    for (lits, w) in &enc.soft {
        for h in lits {
            weights.insert(*h, *w);
        }
    }
    let mut hard_sets: Vec<BTreeSet<Hash>> = enc
        .hard
        .iter()
        .map(|c| c.iter().copied().collect())
        .filter(|s: &BTreeSet<Hash>| !s.is_empty())
        .collect();
    hard_sets.sort_by(|a, b| a.len().cmp(&b.len()).then(a.cmp(b)));
    let mut best_cut = BTreeSet::new();
    let mut best_cost = u64::MAX;
    // Greedy warm start: a deterministic max-coverage incumbent before the
    // exact search. On shared-literal encodings (one event covering every
    // clause) the greedy pick is optimal, and the DFS then prunes every
    // branch at the root instead of walking an exponential literal chain.
    greedy_incumbent(&hard_sets, &weights, &mut best_cut, &mut best_cost);
    let mut cur = BTreeSet::new();
    let mut state = SearchState {
        hard: &hard_sets,
        weights: &weights,
        cardinality: enc.cardinality.as_ref(),
        best_cut,
        best_cost,
    };
    state.dfs(&mut cur, 0, 0);
    if state.best_cost == u64::MAX {
        return Err(SolverError::Unsupported);
    }
    let cut: Vec<Hash> = state.best_cut.into_iter().collect();
    let lower = disjoint_lower(&enc.hard, &weights).min(state.best_cost);
    Ok(MaxSatSolution {
        cut,
        total_cost: state.best_cost,
        lower_bound_proof: LowerBoundProof {
            method: LOWER_BOUND_METHOD,
            unsat_core_cost: lower,
        },
    })
}
/// Deterministic greedy max-coverage incumbent.
///
/// Rounds pick the literal that satisfies the most unsatisfied hard clauses
/// (ties: cheaper cost first, then hash order), until every clause is
/// covered or no literal covers anything new. The result seeds the exact
/// search: on shared-literal encodings the greedy pick is already optimal,
/// so the DFS prunes every branch at the root instead of walking an
/// exponential literal chain. The incumbent never worsens the result: the
/// DFS still runs and only improves on it.
fn greedy_incumbent(
    hard: &[BTreeSet<Hash>],
    weights: &BTreeMap<Hash, u64>,
    best_cut: &mut BTreeSet<Hash>,
    best_cost: &mut u64,
) {
    let mut uncovered: Vec<&BTreeSet<Hash>> = hard.iter().collect();
    let mut chosen = BTreeSet::new();
    let mut cost = 0u64;
    while !uncovered.is_empty() {
        let mut coverage: BTreeMap<Hash, usize> = BTreeMap::new();
        for clause in &uncovered {
            for literal in clause.iter() {
                *coverage.entry(*literal).or_default() += 1;
            }
        }
        let weight_of = |h: &Hash| weights.get(h).copied().unwrap_or(1).max(1);
        let Some((literal, _)) = coverage.into_iter().min_by(|a, b| {
            b.1.cmp(&a.1)
                .then(weight_of(&a.0).cmp(&weight_of(&b.0)))
                .then(a.0.cmp(&b.0))
        }) else {
            break;
        };
        chosen.insert(literal);
        cost = cost.saturating_add(weight_of(&literal));
        uncovered.retain(|clause| !clause.contains(&literal));
    }
    if !uncovered.is_empty() {
        // Some clauses have no faultable literal: leave the exact DFS in
        // charge of reporting the failure.
        return;
    }
    *best_cut = chosen;
    *best_cost = cost;
}

struct SearchState<'a> {
    hard: &'a [BTreeSet<Hash>],
    weights: &'a BTreeMap<Hash, u64>,
    cardinality: Option<&'a CardinalityBound>,
    best_cut: BTreeSet<Hash>,
    best_cost: u64,
}

impl<'a> SearchState<'a> {
    fn dfs(&mut self, cur: &mut BTreeSet<Hash>, cur_cost: u64, start_clause: usize) {
        if cur_cost >= self.best_cost {
            return;
        }
        if let Some(b) = self.cardinality
            && cur.len() > b.max_true
        {
            return;
        }
        let uncovered = self
            .hard
            .iter()
            .enumerate()
            .skip(start_clause)
            .find(|(_, c)| !c.iter().any(|h| cur.contains(h)));
        let Some((clause_idx, clause)) = uncovered else {
            if cur_cost < self.best_cost {
                self.best_cost = cur_cost;
                self.best_cut = cur.clone();
            }
            return;
        };
        let mut lits: Vec<(Hash, u64)> = clause
            .iter()
            .map(|h| (*h, self.weights.get(h).copied().unwrap_or(1)))
            .collect();
        lits.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
        for (h, wt) in lits {
            if cur.contains(&h) {
                continue;
            }
            let nxt = cur_cost.saturating_add(wt);
            if nxt >= self.best_cost {
                continue;
            }
            cur.insert(h);
            self.dfs(cur, nxt, clause_idx + 1);
            cur.remove(&h);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::solver::{FaultSolver, HittingSetSolver, SolverConfig};
    use ledger_format::EntryKind;
    use ledger_format::{CanonicalValue, EntryPayload};
    use ledger_journal::Journal;
    fn cost_of(j: &Journal, hs: &[Hash]) -> u64 {
        hs.iter().map(|h| event_fault_cost(j, h)).sum()
    }
    #[test]
    fn encode_produces_hard_covering_every_path_and_soft_covering_every_faultable() {
        let mut j = Journal::new();
        let a = j
            .append(
                EntryKind::Send,
                1,
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(1, 0),
                    from: 1,
                    to: 2,
                    original_content: 1u64.to_le_bytes().to_vec(),
                }),
            )
            .unwrap();
        let b = j
            .append(
                EntryKind::Send,
                2,
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(2, 0),
                    from: 2,
                    to: 3,
                    original_content: 2u64.to_le_bytes().to_vec(),
                }),
            )
            .unwrap();
        let w = j
            .append(
                EntryKind::Outcome,
                3,
                [a, b],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: [0x00; 32],
                    value: CanonicalValue::Unsigned(0),
                }),
            )
            .unwrap();
        let v = Verdict::fail(vec![w], "two supports");
        let e = encode_hazard(&j, &v, &SolverConfig::default()).unwrap();
        assert_eq!(e.hard.len(), 2);
        let d: BTreeSet<Hash> = e.hard.iter().flat_map(|c| c.iter().copied()).collect();
        assert!(d.contains(&a) && d.contains(&b));
        let s: BTreeSet<Hash> = e.soft.iter().flat_map(|(l, _)| l.iter().copied()).collect();
        assert_eq!(s, d);
        for (l, wt) in &e.soft {
            assert_eq!(l.len(), 1);
            assert_eq!(*wt, event_fault_cost(&j, &l[0]));
        }
    }
    #[test]
    fn solve_returns_subset_minimal_cut_matching_brute_force() {
        let mut j = Journal::new();
        let shared = j
            .append(
                EntryKind::Send,
                1,
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(1, 0),
                    from: 1,
                    to: 2,
                    original_content: 99u64.to_le_bytes().to_vec(),
                }),
            )
            .unwrap();
        let ba = j
            .append(
                EntryKind::Recv,
                2,
                [shared],
                EntryPayload::Recv(ledger_format::RecvFrame {
                    message_id: ledger_format::MessageId::new(2, 0),
                    from: 1,
                    to: 2,
                    observed_content: 0u64.to_le_bytes().to_vec(),
                }),
            )
            .unwrap();
        let bb = j
            .append(
                EntryKind::Recv,
                3,
                [shared],
                EntryPayload::Recv(ledger_format::RecvFrame {
                    message_id: ledger_format::MessageId::new(3, 0),
                    from: 1,
                    to: 3,
                    observed_content: 0u64.to_le_bytes().to_vec(),
                }),
            )
            .unwrap();
        let w = j
            .append(
                EntryKind::Outcome,
                4,
                [ba, bb],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: [0x00; 32],
                    value: CanonicalValue::Unsigned(0),
                }),
            )
            .unwrap();
        let v = Verdict::fail(vec![w], "shared root");
        let e = encode_hazard(&j, &v, &SolverConfig::default()).unwrap();
        let sol = solve_maxsat(&e).unwrap();
        let mut hitting = HittingSetSolver::unbounded();
        let hyps = hitting.solve(&j, &v).unwrap();
        let brute = hyps.iter().map(|h| h.total_cost).min().unwrap_or(0);
        assert_eq!(sol.total_cost, brute);
        assert_eq!(cost_of(&j, &sol.cut), sol.total_cost);
        for elem in sol.cut.clone() {
            let sub: Vec<Hash> = sol.cut.iter().copied().filter(|h| *h != elem).collect();
            assert!(
                !e.hard.iter().all(|c| c.iter().any(|h| sub.contains(h))),
                "cut must be minimal"
            );
        }
    }
    #[test]
    fn lower_bound_le_optimal_and_equals_when_disjoint() {
        let mut j = Journal::new();
        let a = j
            .append(
                EntryKind::Send,
                1,
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(1, 0),
                    from: 1,
                    to: 2,
                    original_content: 1u64.to_le_bytes().to_vec(),
                }),
            )
            .unwrap();
        let b = j
            .append(
                EntryKind::Send,
                2,
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(2, 0),
                    from: 2,
                    to: 3,
                    original_content: 2u64.to_le_bytes().to_vec(),
                }),
            )
            .unwrap();
        let w = j
            .append(
                EntryKind::Outcome,
                3,
                [a, b],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: [0x00; 32],
                    value: CanonicalValue::Unsigned(0),
                }),
            )
            .unwrap();
        let v = Verdict::fail(vec![w], "disjoint");
        let e = encode_hazard(&j, &v, &SolverConfig::default()).unwrap();
        let s = solve_maxsat(&e).unwrap();
        assert!(s.lower_bound_proof.unsat_core_cost <= s.total_cost);
        assert_eq!(s.lower_bound_proof.unsat_core_cost, s.total_cost);
        assert_eq!(s.lower_bound_proof.method, LOWER_BOUND_METHOD);
        let mut j2 = Journal::new();
        let shared = j2
            .append(
                EntryKind::Send,
                1,
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(1, 0),
                    from: 1,
                    to: 2,
                    original_content: 99u64.to_le_bytes().to_vec(),
                }),
            )
            .unwrap();
        let ba = j2
            .append(
                EntryKind::Recv,
                2,
                [shared],
                EntryPayload::Recv(ledger_format::RecvFrame {
                    message_id: ledger_format::MessageId::new(2, 0),
                    from: 1,
                    to: 2,
                    observed_content: 0u64.to_le_bytes().to_vec(),
                }),
            )
            .unwrap();
        let bb = j2
            .append(
                EntryKind::Recv,
                3,
                [shared],
                EntryPayload::Recv(ledger_format::RecvFrame {
                    message_id: ledger_format::MessageId::new(3, 0),
                    from: 1,
                    to: 3,
                    observed_content: 0u64.to_le_bytes().to_vec(),
                }),
            )
            .unwrap();
        let w2 = j2
            .append(
                EntryKind::Outcome,
                4,
                [ba, bb],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: [0x00; 32],
                    value: CanonicalValue::Unsigned(0),
                }),
            )
            .unwrap();
        let v2 = Verdict::fail(vec![w2], "overlap");
        let e2 = encode_hazard(&j2, &v2, &SolverConfig::default()).unwrap();
        let s2 = solve_maxsat(&e2).unwrap();
        assert!(s2.lower_bound_proof.unsat_core_cost <= s2.total_cost);
    }
    #[test]
    fn determinism_same_input_same_solution_bytes() {
        let mut j = Journal::new();
        let s1 = j
            .append(
                EntryKind::Send,
                1,
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(1, 0),
                    from: 1,
                    to: 2,
                    original_content: 1u64.to_le_bytes().to_vec(),
                }),
            )
            .unwrap();
        let s2 = j
            .append(
                EntryKind::Send,
                2,
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(2, 0),
                    from: 2,
                    to: 3,
                    original_content: 2u64.to_le_bytes().to_vec(),
                }),
            )
            .unwrap();
        let w = j
            .append(
                EntryKind::Outcome,
                3,
                [s1, s2],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: [0x00; 32],
                    value: CanonicalValue::Unsigned(0),
                }),
            )
            .unwrap();
        let v = Verdict::fail(vec![w], "det");
        let e1 = encode_hazard(&j, &v, &SolverConfig::default()).unwrap();
        let e2 = encode_hazard(&j, &v, &SolverConfig::default()).unwrap();
        assert_eq!(e1, e2);
        let sol1 = solve_maxsat(&e1).unwrap();
        let sol2 = solve_maxsat(&e2).unwrap();
        assert_eq!(sol1, sol2);
        let mut b1 = Vec::new();
        for h in &sol1.cut {
            b1.extend_from_slice(h);
        }
        let mut b2 = Vec::new();
        for h in &sol2.cut {
            b2.extend_from_slice(h);
        }
        assert_eq!(b1, b2);
    }
}
