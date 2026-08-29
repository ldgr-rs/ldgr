//! Solver scaling gate: incremental solves over a 10^6-entry journal keep
//! their structural guarantees in every profile, and their wall-clock
//! budgets in release.
//!
//! Release-oriented (like `minimize_gate`): run with
//! `cargo test -p ledger-explorer --test solver_scaling_gate --release`.
//! Perf gates are measured locally, not in CI. The timing assertions compile only outside debug
//! builds so a slow debug sweep can never fail them; the deterministic
//! structural assertions run in every profile.
//!
//! The journal fixture reuses the `solver_scaling` bench builder pattern:
//! chain appends of `Send` with every 10th entry a `Recv` observing the
//! previous `Send`, plus a final `Outcome` witness.
//!
//! What is asserted in every profile:
//!
//! 1. The fixture really is 10^6 entries, so it cannot silently shrink.
//! 2. 128 incremental solves with a growing clause set (one more witnessed
//!    clause per step, distinct cache key per step) each yield hypotheses.
//!
//! What is asserted only in release (`cfg(not(debug_assertions))`):
//!
//! 3. Those 128 incremental solves complete in under 60 s total.
//! 4. Monotonicity: one fresh solve over the full 128-clause set takes
//!    measurably longer than one fresh solve over a single clause, so a
//!    complexity regression that makes per-clause work free fails the gate.
//!    Both sides use fresh solvers and distinct cache keys, timed via
//!    `std::time::Instant` (test-side ambient time only).
//!
//! The witnessed clauses alternate between two fixed three-literal sets.
//! Distinct per-step literals would make the number of minimal hitting sets
//! grow combinatorially with the step count (every one-literal-per-clause
//! choice is a transversal), which would turn this into an exponential
//! blast, not a scaling gate. Fixed literal sets keep the transversal family
//! tiny while the clause COUNT still grows, so per-clause work is what the
//! timing measures.

use ledger_explorer::{ClauseCache, FaultSolver, HittingSetSolver, WeightedClause};
use ledger_format::{CanonicalValue, EntryKind, EntryPayload, Hash};
use ledger_journal::Journal;
#[cfg(not(debug_assertions))]
use std::time::Duration;
use std::time::Instant;

const RECV_PERIOD: usize = 10;
const ENTRIES: usize = 1_000_000;
const WITNESSES: usize = 128;
#[cfg(not(debug_assertions))]
const TIMING_REPS: usize = 5;
#[cfg(not(debug_assertions))]
const SOLVE_BUDGET: Duration = Duration::from_secs(60);

/// Bench-pattern journal builder: chain of `Send`s from actor 1 with every
/// `RECV_PERIOD`-th entry a `Recv` observing the previous `Send`, final
/// `Outcome` observing the last two chain entries.
fn build_scaling_journal(n: usize) -> Journal {
    assert!(n >= 2, "scaling journal needs at least witness + one entry");
    let mut journal = Journal::new();
    let mut last_send: Option<Hash> = None;
    let mut last_hash: Option<Hash> = None;
    let mut prev_hash: Option<Hash> = None;

    let chain_len = n - 1;
    for i in 0..chain_len {
        let id = if i != 0 && i % RECV_PERIOD == 0 {
            let observed = last_send.expect("Recv needs a prior Send");
            journal
                .append(
                    EntryKind::Recv,
                    1,
                    [observed],
                    EntryPayload::Recv(ledger_format::RecvFrame {
                        message_id: ledger_format::MessageId::new(1, 0),
                        from: 1,
                        to: 1,
                        observed_content: (i as u64).to_le_bytes().to_vec(),
                    }),
                )
                .expect("Recv append must succeed")
        } else {
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
                .expect("Send append must succeed");
            last_send = Some(id);
            id
        };
        prev_hash = last_hash;
        last_hash = Some(id);
    }

    match (last_hash, prev_hash) {
        (Some(last), Some(prev)) if last != prev => journal
            .append(
                EntryKind::Outcome,
                1,
                [last, prev],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: [0x00; 32],
                    value: CanonicalValue::Unsigned(u64::MAX),
                }),
            )
            .expect("Outcome append must succeed"),
        (Some(last), _) => journal
            .append(
                EntryKind::Outcome,
                1,
                [last],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: [0x00; 32],
                    value: CanonicalValue::Unsigned(u64::MAX),
                }),
            )
            .expect("Outcome append must succeed"),
        (None, _) => journal
            .append(
                EntryKind::Outcome,
                1,
                [],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: [0x00; 32],
                    value: CanonicalValue::Unsigned(u64::MAX),
                }),
            )
            .expect("Outcome append must succeed"),
    };
    journal
}

fn sorted_closure(ids: &[Hash]) -> Hash {
    let mut sorted = ids.to_vec();
    sorted.sort();
    ClauseCache::closure_hash(&sorted)
}

#[cfg(not(debug_assertions))]
fn median(samples: &[Duration]) -> Duration {
    let mut sorted = samples.to_vec();
    sorted.sort();
    sorted[sorted.len() / 2]
}

#[test]
fn incremental_solving_scales_at_one_million_entries() {
    let started = Instant::now();
    let journal = build_scaling_journal(ENTRIES);
    let build_time = started.elapsed();
    assert!(
        journal.len() >= 1_000_000,
        "gate requires a 10^6-entry fixture, got {}",
        journal.len()
    );

    let sends: Vec<Hash> = journal
        .entries()
        .filter(|entry| entry.data.kind == EntryKind::Send)
        .map(|entry| entry.id)
        .collect();
    // 5 clause literals plus one distinct key salt per solve, and one more
    // per timing rep in release.
    let needed = 5 + WITNESSES;
    #[cfg(not(debug_assertions))]
    let needed = needed + TIMING_REPS;
    assert!(
        sends.len() > needed,
        "fixture needs more than {needed} Send literals, got {}",
        sends.len()
    );

    let shared = sends[0];
    let clause_a = WeightedClause::new(vec![shared, sends[1], sends[2]], 2);
    let clause_b = WeightedClause::new(vec![shared, sends[3], sends[4]], 2);
    let clauses: Vec<WeightedClause> = (0..WITNESSES)
        .map(|step| {
            if step % 2 == 0 {
                clause_a.clone()
            } else {
                clause_b.clone()
            }
        })
        .collect();

    // Incremental loop: step i solves over the first i+1 witnessed clauses.
    // The key salt differs per step, so every step is a real (cache-miss)
    // solve and the loop exercises 128 distinct incremental witnesses.
    let mut solver = HittingSetSolver::new();
    let incremental_start = Instant::now();
    let mut hypotheses_total = 0usize;
    for step in 0..WITNESSES {
        let key = sorted_closure(&[shared, sends[5 + step]]);
        let hypotheses = solver.solve_incremental(key, clauses[..=step].to_vec());
        hypotheses_total += hypotheses.len();
        assert!(!hypotheses.is_empty(), "step {step} must yield hypotheses");
    }
    let incremental_elapsed = incremental_start.elapsed();
    assert!(hypotheses_total >= WITNESSES);

    // Wall-clock budget and monotonicity: release only, so the debug CI
    // sweep never fails on machine slowness.
    #[cfg(not(debug_assertions))]
    {
        assert!(
            incremental_elapsed < SOLVE_BUDGET,
            "{WITNESSES} incremental solves over 10^6 entries took {incremental_elapsed:?}, budget {SOLVE_BUDGET:?}"
        );

        // Monotonicity: fresh solve over all 128 clauses vs over one clause.
        // Fresh solvers and distinct keys per rep keep every call a real
        // solve; medians damp scheduler noise.
        let single_samples: Vec<Duration> = (0..TIMING_REPS)
            .map(|rep| {
                let key = sorted_closure(&[shared, sends[5 + WITNESSES + rep]]);
                let mut fresh = HittingSetSolver::new();
                let start = Instant::now();
                let _ = fresh.solve_incremental(key, clauses[..1].to_vec());
                start.elapsed()
            })
            .collect();
        let grown_samples: Vec<Duration> = (0..TIMING_REPS)
            .map(|rep| {
                let mut salted = sends[5 + WITNESSES + rep];
                salted[31] ^= 0x5A;
                let key = sorted_closure(&[shared, salted]);
                let mut fresh = HittingSetSolver::new();
                let start = Instant::now();
                let _ = fresh.solve_incremental(key, clauses.clone());
                start.elapsed()
            })
            .collect();
        let single = median(&single_samples);
        let grown = median(&grown_samples);
        assert!(
            grown > single,
            "solving 128 accumulated clauses ({grown:?}) must take measurably longer than a single fresh clause solve ({single:?}); journal build was {build_time:?}"
        );
        println!(
            "solver_scaling_gate (release): single-clause median {single:?}, 128-clause median {grown:?}"
        );
    }

    println!(
        "solver_scaling_gate: journal build {build_time:?}, {WITNESSES} incremental solves {incremental_elapsed:?} (timing asserts {})",
        if cfg!(debug_assertions) {
            "skipped in debug"
        } else {
            "enforced"
        }
    );
}
