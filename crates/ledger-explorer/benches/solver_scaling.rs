//! Solver scaling benchmark.
// ledger-lint:allow (host-side benchmark drives the solver; it is not simulation code)
//!
//! Scaling curve 10^3 -> 10^6 entries; gate is <60s incremental at 10^6.
//! perf gates are measured
//! locally, not in CI (shared runners are too noisy).
//!
//! Workload: synthetic journal with chain appends of `EntryKind::Send` from
//! actor 1 with `Payload::Number(i)`, plus every k-th entry a `Recv` observing
//! the previous `Send` as parent (creates derivation paths), and a final
//! `Outcome` witness. A `Verdict` with that outcome as witness drives both
//! solvers. Journal is built once per size outside the timed section; the
//! timed section measures `solve` only (`&Journal` not mutated, `&mut Solver`
//! freshly constructed per iteration to avoid cache-hit undercount).
//!
//! Throughput is reported as `Elements(N)` (entries/s) so the curve is
//! entries/s vs N.
//!
//! All sizes including the 10^6 point run unconditionally: the bounded
//! horizon (64) walks at most 64 ancestors per witness, not the full
//! journal, so even 10^6 solves stay cheap and near-flat across N. A former
//! `scaling-full` feature was removed because it did not change this size
//! list. If future encoding changes ever make the 10^6 point exceed ~10 min
//! total, shrink `SIZES` and reintroduce a feature that actually gates the
//! large point.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ledger_explorer::{FaultSolver, HittingSetSolver, MaxSatSolver, Verdict};
use ledger_format::{EntryKind, Payload};
use ledger_journal::Journal;
use std::hint::black_box;

const RECV_PERIOD: usize = 10;

/// Build a synthetic journal of `n` entries (including final Outcome).
///
/// Chain appends `Send` from actor 1 with `Payload::Number(i)`. Every
/// `RECV_PERIOD`-th entry (excluding i==0) a `Recv` observing the previous
/// `Send` is appended instead, creating derivation paths. The final `Outcome`
/// observes the last chain entry (and the previous one when available, to
/// create at least two derivation paths when the chain is long enough).
fn build_scaling_journal(n: usize) -> (Journal, Verdict) {
    assert!(n >= 2, "scaling journal needs at least witness + one entry");
    let mut journal = Journal::new();
    let mut last_send: Option<ledger_format::Hash> = None;
    let mut last_hash: Option<ledger_format::Hash> = None;
    let mut prev_hash: Option<ledger_format::Hash> = None;

    let chain_len = n - 1;
    for i in 0..chain_len {
        let payload = Payload::Number(i as u64);
        let id = if i != 0 && i % RECV_PERIOD == 0 {
            let observed = last_send.expect("Recv needs a prior Send");
            journal
                .append(EntryKind::Recv, 1, [observed], payload)
                .expect("Recv append must succeed")
        } else {
            let id = journal
                .append(EntryKind::Send, 1, [], payload)
                .expect("Send append must succeed");
            last_send = Some(id);
            id
        };
        prev_hash = last_hash;
        last_hash = Some(id);
    }

    let outcome = match (last_hash, prev_hash) {
        (Some(last), Some(prev)) if last != prev && chain_len >= 2 => journal
            .append(
                EntryKind::Outcome,
                1,
                [last, prev],
                Payload::Number(u64::MAX),
            )
            .expect("Outcome append must succeed"),
        (Some(last), _) => journal
            .append(EntryKind::Outcome, 1, [last], Payload::Number(u64::MAX))
            .expect("Outcome append must succeed"),
        (None, _) => journal
            .append(EntryKind::Outcome, 1, [], Payload::Number(u64::MAX))
            .expect("Outcome append must succeed"),
    };
    let verdict = Verdict::fail(vec![outcome], format!("synthetic scaling verdict N={n}"));
    (journal, verdict)
}

const SIZES: &[usize] = &[1_000, 10_000, 100_000, 1_000_000];

fn bench_solver_scaling(c: &mut Criterion) {
    // Build journals once outside the timed section.
    let mut journals: Vec<(usize, Journal, Verdict)> = Vec::new();
    for &n in SIZES {
        let (journal, verdict) = build_scaling_journal(n);
        assert_eq!(
            journal.len(),
            n,
            "synthetic journal must have exactly N entries"
        );
        // Assert solution non-empty outside timing so bench fails loudly if encoding breaks.
        {
            let mut hs = HittingSetSolver::new();
            let hyps = hs
                .solve(&journal, &verdict)
                .expect("hitting-set solve must succeed for scaling journal");
            assert!(
                !hyps.is_empty(),
                "hitting-set solution must be non-empty for N={n}"
            );
        }
        {
            let mut ms = MaxSatSolver::new();
            let hyps = ms
                .solve(&journal, &verdict)
                .expect("maxsat solve must succeed for scaling journal");
            assert!(
                !hyps.is_empty(),
                "maxsat solution must be non-empty for N={n}"
            );
        }
        journals.push((n, journal, verdict));
    }

    let mut group = c.benchmark_group("solver_scaling");
    group.sample_size(10);
    group.warm_up_time(std::time::Duration::from_secs(2));

    for (n, journal, verdict) in &journals {
        let elems = *n as u64;
        group.throughput(Throughput::Elements(elems));

        group.bench_with_input(BenchmarkId::new("hitting_set_bounded", n), n, |b, _| {
            b.iter(|| {
                let mut solver = HittingSetSolver::new();
                let hyps = solver
                    .solve(black_box(journal), black_box(verdict))
                    .expect("solve must succeed");
                black_box(hyps)
            });
        });

        group.bench_with_input(BenchmarkId::new("maxsat_bounded", n), n, |b, _| {
            b.iter(|| {
                let mut solver = MaxSatSolver::new();
                let hyps = solver
                    .solve(black_box(journal), black_box(verdict))
                    .expect("solve must succeed");
                black_box(hyps)
            });
        });
    }
    group.finish();
}

criterion_group!(
    name = solver_scaling_benches;
    config = Criterion::default().sample_size(10).warm_up_time(std::time::Duration::from_secs(2));
    targets = bench_solver_scaling
);
criterion_main!(solver_scaling_benches);
