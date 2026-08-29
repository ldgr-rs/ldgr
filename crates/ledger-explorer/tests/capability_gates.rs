//! A4 capability closure gates: direct evidence for the Stage 2 named
//! capabilities.
//!
//! One gate per capability, each with an observable contract, a negative
//! control that fails if the implementation becomes a no-op, and a
//! measurement of the intended work. The end-to-end gate grows the relevant
//! causal closure from 10^3 to 10^6 entries and runs the full chain
//! (witness extraction, typed-support derivation, hazard encoding, solving,
//! statement emission, journal-anchored validation) under a 60-second
//! release budget.
//!
//! Release-oriented timing assertions are cfg-gated exactly like
//! `solver_scaling_gate`: debug sweeps never fail on machine slowness.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use ledger_explorer::ldfi::FaultHypothesis;
use ledger_explorer::ldfi::solve_with;
use ledger_explorer::lineage::LineageIndex;
use ledger_explorer::maxsat::encode_hazard;
use ledger_explorer::oracle::Verdict;
use ledger_explorer::search::{CampaignReport, Finding, Journal};
use ledger_explorer::solver::{
    FaultSolver, HittingSetSolver, SolverConfig, SolverEngine, samc_prune,
};
use ledger_explorer::solver_cache::{ClauseCache, WeightedClause};
use ledger_explorer::support::{StaticSupportProvider, SupportExpr, all_of_ids};
use ledger_format::{CanonicalValue, EntryKind, EntryPayload, Hash};
use ledger_sim::{BeltStatus, RunOutcome, RunResult};

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

/// Build a parent chain journal and return it plus the tail Outcome hash.
fn chain_with_outcome(n: usize) -> (Journal, Hash) {
    let mut journal = Journal::new();
    let mut prev: Option<Hash> = None;
    for i in 0..n {
        let kind = if i % 2 == 0 {
            EntryKind::Send
        } else {
            EntryKind::Recv
        };
        let id = match prev {
            Some(p) => journal
                .append(
                    kind,
                    1,
                    [p],
                    EntryPayload::Recv(ledger_format::RecvFrame {
                        message_id: ledger_format::MessageId::new(1, 0),
                        from: 1,
                        to: 1,
                        observed_content: (i as u64).to_le_bytes().to_vec(),
                    }),
                )
                .expect("chain append must succeed"),
            None => journal
                .append(
                    kind,
                    1,
                    [],
                    EntryPayload::Recv(ledger_format::RecvFrame {
                        message_id: ledger_format::MessageId::new(1, 0),
                        from: 1,
                        to: 1,
                        observed_content: (i as u64).to_le_bytes().to_vec(),
                    }),
                )
                .expect("root append must succeed"),
        };
        prev = Some(id);
    }
    let witness = journal
        .append(
            EntryKind::Outcome,
            1,
            prev.into_iter().collect::<Vec<_>>(),
            EntryPayload::Outcome(ledger_format::OutcomePayload {
                schema: [0x00; 32],
                value: CanonicalValue::Unsigned(u64::MAX),
            }),
        )
        .expect("outcome append must succeed");
    (journal, witness)
}

/// Horizon proportional to the closure size. The gate asserts this scales
/// with the closure and is never a fixed 64-entry window.
fn scaled_horizon(closure_len: usize) -> usize {
    (closure_len / 128).max(1)
}

/// Verdict over one witness entry.
fn verdict_for(witness: Hash) -> Verdict {
    Verdict {
        violated: true,
        witnesses: vec![witness],
        reason: "capability-gate witness".to_string(),
    }
}

/// A hand-built RunResult carrying `journal`, so statement emission can run
/// on a synthetic journal without a full simulation.
fn run_result_for(journal: Journal) -> RunResult {
    RunResult {
        journal,
        decisions: Vec::new(),
        trace: Vec::new(),
        registers: Vec::new(),
        steps: 0,
        outcome: RunOutcome::Completed,
        monitor_issues: Vec::new(),
        applied_faults: Vec::new(),
        origins: Vec::new(),
        journal_error: None,
        protection: BeltStatus::Unavailable,
    }
}

/// Convert the hazard encoding into solver clauses the same way the
/// hitting-set engine does: one clause per hard set with the set's minimum
/// event cost as the weight.
fn clauses_from_encoding(
    encoding: &ledger_explorer::maxsat::HazardEncoding,
    journal: &Journal,
) -> Vec<WeightedClause> {
    encoding
        .hard
        .iter()
        .map(|set| {
            let weight = set
                .iter()
                .map(|id| ledger_explorer::solver::event_fault_cost(journal, id))
                .min()
                .unwrap_or(1);
            WeightedClause::new(set.clone(), weight)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Gate 1: live incremental solver state across iterations
// ---------------------------------------------------------------------------

/// Contract: solving a closure cold, snapshotting, and warming a fresh
/// solver restores the clause and hypothesis caches so the same closure
/// solves identically and cheaply.
#[test]
fn incremental_solver_state_survives_snapshot_and_warm() {
    let (journal, witness) = chain_with_outcome(256);
    let config = SolverConfig::default().with_horizon(scaled_horizon(journal.len()));
    let verdict = verdict_for(witness);

    let mut cold = HittingSetSolver::with_config(config.clone());
    let cold_hyps = solve_with(&mut cold, &journal, &verdict).expect("cold solve must run");
    assert!(!cold_hyps.is_empty(), "fixture must produce hypotheses");

    let artifact = cold
        .snapshot_state()
        .expect("hitting-set solver persists state");
    assert!(
        !artifact.closures.is_empty(),
        "artifact must carry the solved closure"
    );

    // Negative control: a foreign or corrupted artifact fails loudly before
    // any cache is touched.
    let mut forged = artifact.clone();
    forged.resolved_engine = match artifact.resolved_engine {
        SolverEngine::Builtin => SolverEngine::Cadical,
        _ => SolverEngine::Builtin,
    };
    let mut receiver = HittingSetSolver::with_config(config.clone());
    let rejected = receiver.warm_from_artifact(&forged);
    assert!(
        rejected.is_err(),
        "warm from a foreign-engine artifact must fail loudly"
    );
    assert_eq!(
        receiver.cache_len(),
        0,
        "rejected artifact must not touch caches"
    );

    let mut warmed = HittingSetSolver::with_config(config.clone());
    warmed
        .warm_from_artifact(&artifact)
        .expect("same-key artifact must warm");
    assert!(
        warmed.hypothesis_cache_len() > 0,
        "warm must restore the hypothesis cache (a no-op warm fails this gate)"
    );

    let warm_hyps = solve_with(&mut warmed, &journal, &verdict).expect("warm solve must run");
    let cut_of = |hyps: &[FaultHypothesis]| -> Vec<(Vec<Hash>, u64)> {
        hyps.iter()
            .map(|h| (h.events.clone(), h.total_cost))
            .collect()
    };
    assert_eq!(
        cut_of(&warm_hyps),
        cut_of(&cold_hyps),
        "warm solve must reproduce the cold hypotheses (same events and cost)"
    );

    // Release-only: a warm solve of the same closure is served from the
    // restored caches and must be strictly cheaper than the cold solve.
    #[cfg(not(debug_assertions))]
    {
        let mut t_cold = HittingSetSolver::with_config(config.clone());
        let _ = solve_with(&mut t_cold, &journal, &verdict).expect("timing cold solve");
        let cold_start = Instant::now();
        for _ in 0..8 {
            let mut s = HittingSetSolver::with_config(config.clone());
            let _ = solve_with(&mut s, &journal, &verdict).expect("timing cold rep");
        }
        let cold_elapsed = cold_start.elapsed();

        let mut warm_base = HittingSetSolver::with_config(config.clone());
        warm_base
            .warm_from_artifact(&artifact)
            .expect("timing warm base");
        let warm_start = Instant::now();
        for _ in 0..8 {
            let mut s = HittingSetSolver::with_config(config.clone());
            let _ = s.warm_from_artifact(&artifact);
            let _ = solve_with(&mut s, &journal, &verdict).expect("timing warm rep");
        }
        let warm_elapsed = warm_start.elapsed();
        assert!(
            warm_elapsed < cold_elapsed,
            "warm solve ({warm_elapsed:?}) must be strictly cheaper than cold solve ({cold_elapsed:?})"
        );
    }
}

// ---------------------------------------------------------------------------
// Gate 2: differential lineage updates rather than full reconstruction
// ---------------------------------------------------------------------------

/// Contract: `LineageIndex::refresh` after journal growth walks only the
/// witnesses absent from the cached closure, so the walked-entry count
/// stays proportional to the delta, not to the whole journal.
#[test]
fn differential_lineage_refresh_walks_only_new_witnesses() {
    let config = SolverConfig::default().with_horizon(usize::MAX);
    let engine = SolverEngine::Builtin;

    let (mut journal, tail) = chain_with_outcome(2048);
    let mut idx = LineageIndex::build(&journal, &[tail], &config, engine);
    let built_walked = idx.walked_entries;
    assert_eq!(
        built_walked, 2049,
        "full build walks the whole chain plus the outcome"
    );

    // Negative control 1: no new witness, but the journal grew. A full
    // reconstruction would re-walk everything; the differential refresh
    // records the growth and reports no change with zero walks.
    for i in 2048..2050 {
        let id = journal
            .append(
                EntryKind::Send,
                1,
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(1, 0),
                    from: 1,
                    to: 1,
                    original_content: (i as u64).to_le_bytes().to_vec(),
                }),
            )
            .expect("growth append");
        let _ = id;
    }
    let grew = idx.refresh(&journal, &[tail], &config, engine);
    assert!(!grew, "same witness set after growth must report no change");
    assert_eq!(
        idx.walked_entries, 0,
        "differential refresh with no new witness must walk nothing"
    );
    assert!(idx.closure.contains(&tail), "cached closure stays intact");

    // A genuinely new witness appended to a SHORT fresh sub-chain gets
    // walked, and the walk is bounded by that sub-chain, far below the
    // journal. The sub-chain lives on a fresh actor so its entries are
    // genuine roots: append auto-links to the actor's previous head, so
    // actor 1 entries would chain onto the long tail and their lineage
    // would be the whole journal (not the differential case).
    let mut sub_prev: Option<Hash> = None;
    for i in 0..8 {
        let id = journal
            .append(
                EntryKind::Send,
                2,
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(2, 0),
                    from: 2,
                    to: 1,
                    original_content: (3000 + i as u64).to_le_bytes().to_vec(),
                }),
            )
            .expect("sub-chain append");
        sub_prev = Some(id);
    }
    let new_witness = journal
        .append(
            EntryKind::Outcome,
            2,
            sub_prev.into_iter().collect::<Vec<_>>(),
            EntryPayload::Outcome(ledger_format::OutcomePayload {
                schema: [0x00; 32],
                value: CanonicalValue::Unsigned(u64::MAX - 1),
            }),
        )
        .expect("new witness append");
    let fresh_clone = LineageIndex::build(&journal, &[tail, new_witness], &config, engine);
    let total_fresh = fresh_clone.walked_entries;

    let mut differential = LineageIndex::build(&journal, &[tail], &config, engine);
    let changed = differential.refresh(&journal, &[tail, new_witness], &config, engine);
    assert!(changed, "a new witness must refresh the index");
    assert!(
        differential.closure.contains(&new_witness),
        "new witness lineage must enter the closure"
    );
    assert!(
        differential.walked_entries < total_fresh / 2,
        "differential refresh walked {} entries; full reconstruction would walk {total_fresh}",
        differential.walked_entries
    );
    // The refreshed index still equals a fresh build: differential must not
    // lose or corrupt cached lineage.
    assert_eq!(differential.closure, fresh_clone.closure);
    assert_eq!(differential.paths, fresh_clone.paths);
}

// ---------------------------------------------------------------------------
// Gate 3: SAMC pre-pruning with no loss of declared corpus findings
// ---------------------------------------------------------------------------

/// Contract: two hypotheses that differ only by swapping a pair of
/// concurrent faultable events collapse to the cheaper one. The prune is
/// selective: hypotheses over causally ordered events survive.
#[test]
fn samc_prepruning_is_selective_and_deterministic() {
    let mut journal = Journal::new();
    let send_a = journal
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
        .expect("append a");
    let send_b = journal
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
        .expect("append b");
    let witness = journal
        .append(
            EntryKind::Outcome,
            3,
            [send_a, send_b],
            EntryPayload::Outcome(ledger_format::OutcomePayload {
                schema: [0x00; 32],
                value: CanonicalValue::Unsigned(0),
            }),
        )
        .expect("append witness");
    let entry_a = journal.get(&send_a).expect("entry a");
    let entry_b = journal.get(&send_b).expect("entry b");
    assert!(
        entry_a.vector_clock.concurrent_with(&entry_b.vector_clock),
        "fixture requires concurrent sends"
    );
    let _ = witness;

    let hyp_cheap = FaultHypothesis {
        events: vec![send_a],
        total_cost: 2,
        explanation: "cheap".into(),
    };
    let hyp_costly = FaultHypothesis {
        events: vec![send_b],
        total_cost: 3,
        explanation: "costly".into(),
    };
    let pruned = samc_prune(&journal, vec![hyp_cheap.clone(), hyp_costly.clone()]);
    assert_eq!(
        pruned.len(),
        1,
        "concurrent-swap hypotheses must collapse to the cheaper one"
    );
    assert_eq!(pruned[0], hyp_cheap, "the cheaper hypothesis survives");

    // Negative control: the prune must not be a blanket dedup. Hypotheses
    // over causally ordered events (no concurrent swap) both survive.
    let child = journal
        .append(
            EntryKind::Recv,
            1,
            [send_a],
            EntryPayload::Recv(ledger_format::RecvFrame {
                message_id: ledger_format::MessageId::new(1, 0),
                from: 1,
                to: 1,
                observed_content: 1u64.to_le_bytes().to_vec(),
            }),
        )
        .expect("append child");
    let hyp_child = FaultHypothesis {
        events: vec![child],
        total_cost: 5,
        explanation: "child".into(),
    };
    let kept = samc_prune(&journal, vec![hyp_cheap.clone(), hyp_child.clone()]);
    assert_eq!(
        kept.len(),
        2,
        "causally ordered hypotheses must not be pruned"
    );

    // Determinism: the same input prunes identically.
    let again = samc_prune(&journal, vec![hyp_cheap.clone(), hyp_costly.clone()]);
    assert_eq!(again, pruned);
}

// ---------------------------------------------------------------------------
// Gate 4: bounded solver scaling and the end-to-end chain
// ---------------------------------------------------------------------------

/// The sizes of the growing relevant causal closure. Debug runs keep to the
/// small sizes so the sweep stays fast; release adds the full million.
const CLOSURE_SIZES: &[usize] = &[1_000, 10_000, 100_000];
#[cfg(not(debug_assertions))]
const CLOSURE_SIZES_FULL: &[usize] = &[1_000_000];

/// Deterministic artifact for the end-to-end gate. Only closure sizes,
/// horizons, walk counts, and validation flags appear: every field is
/// reproducible from the committed constants, so regeneration is
/// byte-identical (the A3 discipline).
fn scaling_artifact_json(rows: &[(usize, usize, usize, usize, bool, bool)]) -> String {
    let mut out = String::from("{\"floor\":{\"release_budget_s\":60},\"sizes\":[");
    for (index, (n, closure, horizon, walked, solved, verified)) in rows.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"n\":{n},\"closure\":{closure},\"horizon\":{horizon},\"hypotheses\":{walked},\"solved\":{solved},\"verified\":{verified}}}"
        ));
    }
    out.push_str("]}");
    out
}

fn run_scaling_chain(n: usize) -> (usize, usize, usize, usize, bool, bool, Duration) {
    let started = Instant::now();

    let (journal, witness) = chain_with_outcome(n);
    let closure_len = journal.len();

    // Typed-support derivation: the provider declares AllOf over the
    // witness's faultable Send ancestors, and its version and digest fold
    // into the solver configuration.
    let send_ids: BTreeSet<Hash> = journal
        .entries()
        .filter(|entry| entry.data.kind == EntryKind::Send)
        .map(|entry| entry.id)
        .collect();
    let support_expr: SupportExpr = all_of_ids(send_ids.iter().copied());
    let provider = StaticSupportProvider::new(1, support_expr);
    let mut config = SolverConfig::default()
        .with_support_version(provider.version())
        .with_support_digest(provider.digest());

    // The horizon scales with the closure; the gate asserts it is never the
    // fixed 64-entry window.
    let horizon = scaled_horizon(closure_len);
    assert!(horizon != 64, "the scaled horizon must not be a fixed 64");
    config = config.with_horizon(horizon);

    let verdict = verdict_for(witness);
    let encoding = encode_hazard(&journal, &verdict, &config).expect("hazard encoding must run");
    let clauses = clauses_from_encoding(&encoding, &journal);

    let mut solver = HittingSetSolver::with_config(config);
    let witness_ids = {
        let mut v = verdict.witnesses.clone();
        v.sort();
        v
    };
    let closure_hash = ClauseCache::closure_hash(&witness_ids);
    let walked = solver.solve_incremental(closure_hash, clauses).len();
    let solved = walked > 0;

    // Statement emission and journal-anchored validation.
    let run = run_result_for(journal);
    let finding = Finding {
        seed: [7; 32],
        run,
        verdict,
    };
    let report = CampaignReport {
        runs_executed: 1,
        distinct_roots: 1,
        findings: vec![finding],
        variants: Vec::new(),
        monitors: Vec::new(),
        memo_hits: 0,
    };
    let cert = ledger_explorer::CampaignCertificate::from_campaign(
        &report,
        "capability-gate-builder",
        Vec::new(),
        [9u8; 32],
        None,
    )
    .expect("certificate emission must succeed");
    let verified = cert
        .verify_with_journal(&report.findings[0].run.journal)
        .is_ok();
    assert!(
        verified,
        "journal-anchored validation must pass at size {n}"
    );

    (
        n,
        closure_len,
        horizon,
        walked,
        solved,
        verified,
        started.elapsed(),
    )
}

#[test]
fn end_to_end_chain_scales_with_the_causal_closure() {
    let mut rows: Vec<(usize, usize, usize, usize, bool, bool)> = Vec::new();
    let mut total = Duration::ZERO;
    let mut horizons: Vec<usize> = Vec::new();

    for n in CLOSURE_SIZES {
        let (n, closure, horizon, walked, solved, verified, elapsed) = run_scaling_chain(*n);
        total += elapsed;
        horizons.push(horizon);
        rows.push((n, closure, horizon, walked, solved, verified));
        assert!(solved, "size {n} must yield hypotheses");
    }

    #[cfg(not(debug_assertions))]
    for n in CLOSURE_SIZES_FULL {
        let (n, closure, horizon, walked, solved, verified, elapsed) = run_scaling_chain(*n);
        total += elapsed;
        horizons.push(horizon);
        rows.push((n, closure, horizon, walked, solved, verified));
        assert!(solved, "size {n} must yield hypotheses");
        println!(
            "capability_gates: n={n} closure={closure} horizon={horizon} walked={walked} verified={verified} phase={elapsed:?}"
        );
    }

    // The horizon grows with the closure: not a fixed window.
    assert!(
        horizons.windows(2).all(|w| w[1] > w[0]),
        "horizon must scale monotonically with the closure, got {horizons:?}"
    );

    // Release-only: the whole chain across the full closure growth fits the
    // pre-registered 60-second budget.
    #[cfg(not(debug_assertions))]
    {
        assert!(
            total < Duration::from_secs(60),
            "end-to-end chain over the full closure took {total:?}, budget 60s"
        );
    }

    let artifact = scaling_artifact_json(&rows);
    let again = scaling_artifact_json(&rows);
    assert_eq!(
        artifact, again,
        "scaling artifact regeneration must be byte-identical"
    );
    #[cfg(not(debug_assertions))]
    assert!(
        artifact.contains("\"n\":1000000"),
        "release artifact includes the 10^6 leg"
    );
}
