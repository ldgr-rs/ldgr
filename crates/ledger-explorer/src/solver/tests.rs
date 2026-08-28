use super::*;
use crate::ldfi::{FaultHypothesis, FaultableEvent};
use crate::oracle::Verdict;
use crate::solver_cache::{ClauseCache, WeightedClause};
use ledger_format::{EntryKind, Hash, Payload};
use ledger_journal::{Journal, JournalError};

#[test]
fn empty_input_has_no_recorded_solver_data() {
    let mut solver = MaxSatSolver::new();
    let (hypotheses, solver_data) = solver
        .solve_with_certificate(&Journal::new(), &Verdict::pass())
        .expect("empty solve must succeed");

    assert!(hypotheses.is_empty());
    assert_eq!(solver_data, None);
}

#[test]
fn hitting_set_solver_detects_two_disjoint_supports() {
    let mut journal = Journal::new();
    let send_a = journal
        .append(EntryKind::Send, 1, [], Payload::Pair { left: 2, right: 1 })
        .expect("append must succeed");
    let send_b = journal
        .append(EntryKind::Send, 2, [], Payload::Pair { left: 3, right: 2 })
        .expect("append must succeed");
    let witness = journal
        .append(EntryKind::Outcome, 3, [send_a, send_b], Payload::Number(0))
        .expect("append must succeed");

    let verdict = Verdict::fail(vec![witness], "two supports");
    let mut solver = HittingSetSolver::new();
    let hypotheses = solver
        .solve(&journal, &verdict)
        .expect("solver must succeed");

    assert!(
        !hypotheses.is_empty(),
        "solver must produce at least one hypothesis"
    );
    let top = &hypotheses[0];
    assert_eq!(
        top.events.len(),
        2,
        "disjoint singleton paths need both faults"
    );
    assert!(top.events.contains(&send_a));
    assert!(top.events.contains(&send_b));
}

#[test]
fn hitting_set_solver_picks_shared_root_over_two_branches() {
    let mut journal = Journal::new();
    let shared = journal
        .append(EntryKind::Send, 1, [], Payload::Pair { left: 2, right: 99 })
        .expect("append must succeed");
    let branch_a = journal
        .append(EntryKind::Recv, 2, [shared], Payload::Number(0))
        .expect("append must succeed");
    let branch_b = journal
        .append(EntryKind::Recv, 3, [shared], Payload::Number(0))
        .expect("append must succeed");
    let witness = journal
        .append(
            EntryKind::Outcome,
            4,
            [branch_a, branch_b],
            Payload::Number(0),
        )
        .expect("append must succeed");

    let verdict = Verdict::fail(vec![witness], "shared root");
    let mut solver = HittingSetSolver::new();
    let hypotheses = solver
        .solve(&journal, &verdict)
        .expect("solver must succeed");

    assert!(!hypotheses.is_empty());
    // Cheapest hitting set is the shared root alone.
    let cheapest = &hypotheses[0];
    assert_eq!(
        cheapest.events.len(),
        1,
        "shared root alone hits both paths"
    );
    assert_eq!(cheapest.events[0], shared);
}

#[test]
fn solver_succeeds_on_small_journal() {
    let mut journal = Journal::new();
    let send = journal
        .append(EntryKind::Send, 1, [], Payload::Pair { left: 2, right: 1 })
        .expect("append must succeed");
    let witness = journal
        .append(EntryKind::Outcome, 1, [send], Payload::Number(0))
        .expect("append must succeed");
    let verdict = Verdict::fail(vec![witness], "small journal check");
    let mut solver = HittingSetSolver::new();
    let result = solver.solve(&journal, &verdict);
    assert!(result.is_ok(), "small journal must solve");
}

#[test]
fn trait_object_dispatch_works() {
    let mut journal = Journal::new();
    let send = journal
        .append(EntryKind::Send, 1, [], Payload::Pair { left: 2, right: 1 })
        .expect("append must succeed");
    let witness = journal
        .append(EntryKind::Outcome, 1, [send], Payload::Number(0))
        .expect("append must succeed");
    let verdict = Verdict::fail(vec![witness], "trait object");

    let mut solver: Box<dyn FaultSolver> = Box::new(HittingSetSolver::new());
    assert_eq!(solver.name(), "hitting-set");
    let hypotheses = solver
        .solve(&journal, &verdict)
        .expect("trait object must solve");
    assert_eq!(hypotheses.len(), 1);
    assert_eq!(hypotheses[0].events, vec![send]);
}

#[test]
fn solver_error_from_journal_error() {
    let journal_err = JournalError::MissingParent([9; 32]);
    let solver_err: SolverError = journal_err.clone().into();
    assert_eq!(solver_err, SolverError::Journal(journal_err));
    assert!(format!("{solver_err}").contains("missing parent"));
}

#[test]
fn weighted_clause_helper() {
    let hash = [1; 32];
    let clause = WeightedClause::new(vec![hash], 5);
    assert!(!clause.is_empty());
    assert_eq!(clause.weight, 5);
    let empty = WeightedClause::new(Vec::new(), 0);
    assert!(empty.is_empty());
}

#[cfg(any(feature = "solver-cadical", test))]
#[test]
fn maxsat_solver_matches_hitting_set_optimum() {
    let mut journal = Journal::new();
    let send = journal
        .append(EntryKind::Send, 1, [], Payload::Pair { left: 2, right: 1 })
        .expect("append must succeed");
    let witness = journal
        .append(EntryKind::Outcome, 1, [send], Payload::Number(0))
        .expect("append must succeed");
    let verdict = Verdict::fail(vec![witness], "maxsat delegate");

    let mut hitting = HittingSetSolver::new();
    let expected = hitting
        .solve(&journal, &verdict)
        .expect("hitting set must succeed");

    let mut maxsat = MaxSatSolver::new();
    assert_eq!(
        maxsat.name(),
        "maxsat",
        "Auto resolves to the builtin branch-and-bound at every measured encoding size"
    );
    let got = maxsat
        .solve(&journal, &verdict)
        .expect("maxsat solve must succeed");
    // Cross-engine contract: both engines reach the same OPTIMAL COST. The
    // argmin cut itself may legitimately differ across engines and builds,
    // so only cost equality plus minimality is asserted here.
    assert_eq!(
        got.iter().map(|hyp| hyp.total_cost).min(),
        expected.iter().map(|hyp| hyp.total_cost).min(),
        "engines must agree on the optimal cut cost"
    );
    let encoded = crate::maxsat::encode_hazard(&journal, &verdict, &SolverConfig::default())
        .expect("encode must succeed");
    let cut = &got[0].events;
    assert!(
        encoded
            .hard
            .iter()
            .all(|clause| clause.iter().any(|event| cut.contains(event))),
        "the returned cut must hit every hard clause"
    );
    for removed in cut {
        let reduced: Vec<Hash> = cut
            .iter()
            .copied()
            .filter(|event| event != removed)
            .collect();
        assert!(
            !encoded
                .hard
                .iter()
                .all(|clause| clause.iter().any(|event| reduced.contains(event))),
            "dropping any event must leave some hard clause unhit: the cut is minimal"
        );
    }
    // Certificate method is present via solve_with_certificate.
    let (_, ext) = maxsat
        .solve_with_certificate(&journal, &verdict)
        .expect("certificate solve must succeed");
    let ext = ext.expect("non-empty solve must return recorded solver data");
    assert_eq!(ext.method, "mcs-lower-bound-v1");
    assert!(ext.recorded_lower_bound <= got[0].total_cost);
}

#[test]
fn cache_memoizes_across_identical_solves() {
    let mut journal = Journal::new();
    let send = journal
        .append(EntryKind::Send, 1, [], Payload::Pair { left: 2, right: 1 })
        .expect("append must succeed");
    let witness = journal
        .append(EntryKind::Outcome, 1, [send], Payload::Number(0))
        .expect("append must succeed");
    let verdict = Verdict::fail(vec![witness], "cache test");
    let mut solver = HittingSetSolver::new();
    let first = solver
        .solve(&journal, &verdict)
        .expect("first must succeed");
    assert_eq!(solver.cache_len(), 1);
    assert_eq!(solver.hypothesis_cache_len(), 1);
    let second = solver
        .solve(&journal, &verdict)
        .expect("second must succeed");
    assert_eq!(first, second);
    assert_eq!(solver.cache_len(), 1);
}

#[test]
fn incremental_solve_uses_cache() {
    let mut solver = HittingSetSolver::new();
    let hash_a = [1; 32];
    let hash_b = [2; 32];
    let closure = ClauseCache::closure_hash(&[hash_a, hash_b]);
    let clauses = vec![
        WeightedClause::new(vec![hash_a], 2),
        WeightedClause::new(vec![hash_b], 2),
    ];
    let first = solver.solve_incremental(closure, clauses.clone());
    assert_eq!(first.len(), 1);
    assert_eq!(solver.cache_len(), 1);
    let second = solver.solve_incremental(closure, clauses.clone());
    assert_eq!(first, second);
    // cache hit does not grow
    assert_eq!(solver.cache_len(), 1);
}

#[test]
fn bounded_closure_limits_depth() {
    let mut journal = Journal::new();
    let root = journal
        .append(EntryKind::Send, 1, [], Payload::Number(0))
        .expect("append must succeed");
    let mid = journal
        .append(EntryKind::Recv, 2, [root], Payload::Number(1))
        .expect("append must succeed");
    let leaf = journal
        .append(EntryKind::Outcome, 3, [mid], Payload::Number(2))
        .expect("append must succeed");
    // horizon 0: only leaf
    let h0 = causal_closure_with_horizon(&journal, &[leaf], 0).expect("h0");
    assert_eq!(h0, vec![leaf]);
    // horizon 1: leaf + mid
    let h1 = causal_closure_with_horizon(&journal, &[leaf], 1).expect("h1");
    assert!(h1.contains(&leaf));
    assert!(h1.contains(&mid));
    assert!(!h1.contains(&root));
    // horizon 2: all
    let h2 = causal_closure_with_horizon(&journal, &[leaf], 2).expect("h2");
    assert!(h2.contains(&root));
}

#[test]
fn solver_respects_horizon() {
    let mut journal = Journal::new();
    let root = journal
        .append(EntryKind::Send, 1, [], Payload::Number(0))
        .expect("append must succeed");
    let mid = journal
        .append(EntryKind::Recv, 2, [root], Payload::Number(1))
        .expect("append must succeed");
    let leaf = journal
        .append(EntryKind::Outcome, 3, [mid], Payload::Number(2))
        .expect("append must succeed");
    let verdict = Verdict::fail(vec![leaf], "horizon");
    let mut unbounded = HittingSetSolver::unbounded();
    let mut bounded = HittingSetSolver::with_horizon(0);
    let unb = unbounded.solve(&journal, &verdict).expect("unb");
    let bou = bounded.solve(&journal, &verdict).expect("bou");
    // bounded with horizon 0 sees no faultable ancestors, falls back.
    // unbounded should find root or mid.
    assert!(!unb.is_empty());
    assert!(!bou.is_empty());
    // They may differ; ensure deterministic.
    let bou2 = bounded.solve(&journal, &verdict).expect("bou2");
    assert_eq!(bou, bou2);
}

#[test]
fn samc_prune_coalesces_concurrent_swaps() {
    let mut journal = Journal::new();
    // Two concurrent sends on different actors, no causal relation.
    let send_a = journal
        .append(EntryKind::Send, 1, [], Payload::Pair { left: 2, right: 1 })
        .expect("append must succeed");
    let send_b = journal
        .append(EntryKind::Send, 2, [], Payload::Pair { left: 3, right: 2 })
        .expect("append must succeed");
    // Witness depends on both, but they are concurrent.
    let _witness = journal
        .append(EntryKind::Outcome, 3, [send_a, send_b], Payload::Number(0))
        .expect("append must succeed");
    let entry_a = journal.get(&send_a).expect("a");
    let entry_b = journal.get(&send_b).expect("b");
    assert!(
        entry_a.vector_clock.concurrent_with(&entry_b.vector_clock),
        "sends on different actors must be concurrent"
    );
    let hyp_a = FaultHypothesis {
        events: vec![send_a],
        total_cost: 2,
        explanation: "a".into(),
    };
    let hyp_b = FaultHypothesis {
        events: vec![send_b],
        total_cost: 3,
        explanation: "b".into(),
    };
    // Same size, differ by swapping concurrent events, keep cheaper.
    let pruned = samc_prune(&journal, vec![hyp_a.clone(), hyp_b.clone()]);
    assert_eq!(pruned.len(), 1);
    assert_eq!(pruned[0], hyp_a);
}

#[test]
fn samc_prune_keeps_non_concurrent() {
    let mut journal = Journal::new();
    let root = journal
        .append(EntryKind::Send, 1, [], Payload::Pair { left: 2, right: 1 })
        .expect("append must succeed");
    let child = journal
        .append(EntryKind::Recv, 1, [root], Payload::Number(0))
        .expect("append must succeed");
    let entry_r = journal.get(&root).expect("root");
    let entry_c = journal.get(&child).expect("child");
    assert!(
        entry_r.vector_clock.happens_before(&entry_c.vector_clock),
        "parent happens before child"
    );
    let hyp_a = FaultHypothesis {
        events: vec![root],
        total_cost: 2,
        explanation: "root".into(),
    };
    let hyp_b = FaultHypothesis {
        events: vec![child],
        total_cost: 2,
        explanation: "child".into(),
    };
    let pruned = samc_prune(&journal, vec![hyp_a.clone(), hyp_b.clone()]);
    assert_eq!(pruned.len(), 2);
}

#[test]
fn solver_config_horizon_builder() {
    let cfg = SolverConfig::default()
        .with_horizon(100)
        .with_oracle_version(42);
    assert_eq!(cfg.max_horizon, Some(100));
    assert_eq!(cfg.oracle_version, Some(42));
    let mut solver = HittingSetSolver::with_config(cfg.clone());
    assert_eq!(solver.config(), &cfg);
    solver.set_config(SolverConfig::default());
    assert_eq!(solver.config().max_horizon, None);
}

#[test]
fn hitting_set_solver_default_has_bounded_horizon() {
    let bounded = HittingSetSolver::new();
    assert_eq!(bounded.config().max_horizon, Some(64));
    let unbounded = HittingSetSolver::unbounded();
    assert_eq!(unbounded.config().max_horizon, None);
}

#[test]
fn solver_config_input_class_partitions_cache() {
    let hash = [7; 32];
    let closure = ClauseCache::closure_hash(&[hash]);
    let clauses = vec![WeightedClause::new(vec![hash], 2)];
    let mut solver_a = HittingSetSolver::with_config(
        SolverConfig::default()
            .with_horizon(64)
            .with_input_class(crate::pbt::gen_id("alpha")),
    );
    let mut solver_b = HittingSetSolver::with_config(
        SolverConfig::default()
            .with_horizon(64)
            .with_input_class(crate::pbt::gen_id("beta")),
    );
    let key_a = solver_a.solve_incremental(closure, clauses.clone());
    let key_b = solver_b.solve_incremental(closure, clauses.clone());
    // Different input classes must not share cache entry (keys differ).
    let ka = ClauseCache::compute_key(
        closure,
        Some(64),
        None,
        Some(crate::pbt::gen_id("alpha")),
        None,
        crate::solver_cache::engine_tag::BUILTIN,
        None,
    );
    let kb = ClauseCache::compute_key(
        closure,
        Some(64),
        None,
        Some(crate::pbt::gen_id("beta")),
        None,
        crate::solver_cache::engine_tag::BUILTIN,
        None,
    );
    assert_ne!(ka, kb);
    assert_eq!(key_a, key_b);
}

#[cfg(any(feature = "solver-cadical", test))]
#[test]
fn maxsat_incremental_logs_cache_hit() {
    let mut solver = MaxSatSolver::new();
    let ha = [5; 32];
    let _hb = [6; 32];
    let closure = ClauseCache::closure_hash(&[ha]);
    let clauses = vec![WeightedClause::new(vec![ha], 2)];
    let _ = solver.solve_incremental(closure, clauses.clone());
    assert_eq!(solver.cache_hits(), 0);
    let _ = solver.solve_incremental(closure, clauses.clone());
    assert_eq!(solver.cache_hits(), 1);
}

fn synthetic_encoding(hard_count: usize) -> crate::maxsat::HazardEncoding {
    crate::maxsat::HazardEncoding {
        hard: (0..hard_count)
            .map(|index| vec![[index as u8; 32]])
            .collect(),
        soft: Vec::new(),
        cardinality: None,
    }
}

#[test]
fn solver_config_default_engine_is_auto() {
    assert_eq!(SolverEngine::default(), SolverEngine::Auto);
    assert_eq!(SolverConfig::default().engine, SolverEngine::Auto);
}

#[test]
fn select_solver_forces_builtin_engine() {
    let cfg = SolverConfig::default().with_engine(SolverEngine::Builtin);
    let solver = select_solver(&cfg, &synthetic_encoding(0));
    assert_eq!(solver.name(), "hitting-set");
}

#[test]
fn select_solver_forced_cadical_reports_active_backend() {
    // Forcing Cadical without the feature still compiles and runs, but the
    // branch-and-bound fallback does the solving; name() stays truthful.
    let cfg = SolverConfig::default().with_engine(SolverEngine::Cadical);
    let solver = select_solver(&cfg, &synthetic_encoding(0));
    let expected = if cfg!(feature = "solver-cadical") {
        "maxsat-cadical"
    } else {
        "maxsat"
    };
    assert_eq!(solver.name(), expected);
}

#[test]
fn select_solver_auto_routes_builtin_below_cutoff() {
    // Any sane threshold sits above a handful of clauses, including the
    // "crossover not yet observed" sentinel.
    let clause_count = 4;
    assert!(cutoff() > clause_count, "sentinel must exceed test sizes");
    let cfg = SolverConfig::default();
    let small = synthetic_encoding(clause_count);
    let solver = select_solver(&cfg, &small);
    assert_eq!(solver.name(), "hitting-set");
}

#[test]
fn select_solver_auto_stays_builtin_for_moderate_encodings() {
    // The bench measured no crossover within its swept range, so Auto keeps
    // routing moderate encodings to the builtin engine in every build.
    let cfg = SolverConfig::default();
    let big = synthetic_encoding(1024);
    assert!(big.hard.len() < cutoff());
    let solver = select_solver(&cfg, &big);
    assert_eq!(solver.name(), "hitting-set");
}

#[cfg(not(feature = "solver-cadical"))]
#[test]
fn select_solver_auto_falls_back_to_builtin_without_cadical_feature() {
    // Without `solver-cadical`, Auto must pick the builtin engine at any
    // encoding size: there the feature gate alone decides.
    let cfg = SolverConfig::default();
    let big = synthetic_encoding(2048);
    let solver = select_solver(&cfg, &big);
    assert_eq!(solver.name(), "hitting-set");
}

#[test]
fn incremental_solve_engine_tags_do_not_share_cache_entries() {
    use crate::solver_cache::engine_tag;
    let mut solver = HittingSetSolver::new();
    let hash = [3u8; 32];
    let closure = ClauseCache::closure_hash(&[hash]);
    let clauses = vec![WeightedClause::new(vec![hash], 2)];
    let _ = solver.solve_incremental_with_tag(closure, clauses.clone(), engine_tag::BUILTIN);
    assert_eq!(solver.cache_len(), 1);
    let _ = solver.solve_incremental_with_tag(closure, clauses.clone(), engine_tag::CADICAL);
    // Distinct tags occupy distinct namespaces; neither entry satisfies the
    // other, so both persist in the per-solver cache.
    assert_eq!(solver.cache_len(), 2);
}

// Proptest for minimal hitting sets.
#[cfg(test)]
mod proptest_hitting_set {
    use super::*;
    use proptest::prelude::*;

    fn hypothesis_covers_all_paths(hyp: &[Hash], paths: &[Vec<Hash>]) -> bool {
        paths
            .iter()
            .all(|path| path.iter().any(|e| hyp.contains(e)))
    }

    proptest! {
        #[test]
        fn random_journals_hitting_set_is_minimal(
            num_paths in 2usize..5,
            path_len in 1usize..3,
        ) {
            // Build a journal with 2-5 disjoint supports, each path 1-3 faults.
            let mut journal = Journal::new();
            let mut all_paths: Vec<Vec<FaultableEvent>> = Vec::new();
            let mut witness_parents: Vec<Hash> = Vec::new();
            for p in 0..num_paths {
                let mut prev: Option<Hash> = None;
                let mut path_events: Vec<FaultableEvent> = Vec::new();
                for _ in 0..path_len {
                    let actor = (p as u32) + 10;
                    let parents = prev.into_iter().collect::<Vec<_>>();
                    let id = journal
                        .append(EntryKind::Send, actor, parents.clone(), Payload::Pair { left: 2, right: 1 })
                        .expect("append must succeed");
                    let cost = event_fault_cost(&journal, &id);
                    path_events.push(FaultableEvent { event: id, kind: EntryKind::Send, cost });
                    prev = Some(id);
                }
                // Last event of path is a parent of witness
                if let Some(last) = path_events.last() {
                    witness_parents.push(last.event);
                }
                if !path_events.is_empty() {
                    all_paths.push(path_events);
                }
            }
            // Witness outcome
            let witness = journal
                .append(EntryKind::Outcome, 99, witness_parents.clone(), Payload::Number(0))
                .expect("append must succeed");
            let path_hashes: Vec<Vec<Hash>> = all_paths.iter().map(|p| p.iter().map(|e| e.event).collect()).collect();
            let hitting_sets = compute_minimal_hitting_sets(&all_paths);
            prop_assert!(!hitting_sets.is_empty(), "must produce at least one hitting set");
            for hs in &hitting_sets {
                let v: Vec<Hash> = hs.iter().copied().collect();
                prop_assert!(hypothesis_covers_all_paths(&v, &path_hashes), "hitting set must cover all paths");
                // Minimality: no proper subset covers all paths.
                for elem in hs.iter() {
                    let mut subset = hs.clone();
                    subset.remove(elem);
                    let subset_vec: Vec<Hash> = subset.into_iter().collect();
                    prop_assert!(!hypothesis_covers_all_paths(&subset_vec, &path_hashes), "hitting set must be minimal");
                }
            }
            // Also via solver API
            let verdict = Verdict::fail(vec![witness], "proptest");
            let mut solver = HittingSetSolver::new();
            let hyps = solver.solve(&journal, &verdict).expect("solve must succeed");
            prop_assert!(!hyps.is_empty());
            for hyp in &hyps {
                prop_assert!(hypothesis_covers_all_paths(&hyp.events, &path_hashes));
            }
        }
    }
}
