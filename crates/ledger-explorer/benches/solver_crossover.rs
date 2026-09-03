//! Solver engine crossover benchmark.
// ledger-lint:allow (host-side benchmark drives the solver; it is not simulation code)
//!
//! Measures where the CaDiCaL-backed MaxSAT engine starts beating the builtin
//! engines as the hard-clause count grows. The measured crossover feeds
//! `ledger_explorer::CADICAL_CUTOFF_HARD_CLAUSES`, the routing threshold of
//! `select_solver`.
//!
//! Measurement methodology (recorded 2026-08-24 during Task 7.2):
//! - Command: `taskset -c 0 cargo bench -p ledger-explorer --features
//!   solver-cadical --bench solver_crossover` (bench profile, optimized
//!   release build).
//! - Host: 12th Gen Intel Core i5-12500H (Alder Lake), 16 logical CPUs, CPU
//!   governor `powersave` (400 MHz idle, 4.5 GHz boost ceiling).
//! - Cross-window drift on this host reaches ~15% (thermal and frequency
//!   scaling). Verdicts compare the four variants within one invocation: the
//!   wall-clock table below and the criterion groups below it share one
//!   process. Pin to one P-core with `taskset -c 0`; pinning materially
//!   reduces variance and is required for acceptance data.
//! - Criterion settings: 10 samples, 1 s warm-up per point (group config
//!   below). The wall-clock table is the decisive within-invocation
//!   comparison: median of 3 timed runs per variant per size.
//! - Fresh-data verdicts, 2026-08-24 (median of 3, micro-seconds):
//!   hitting_set 4.0/8.7/19.7/52.8/157.4/469.4/1599.7 vs maxsat_bnb
//!   6.4/14.5/35.5/96.8/307.2/989.0/4001.2 vs maxsat_cadical 663.9/2415.2/
//!   12920.8/100186.3/1007096.5/8140345.8/61986805.8 at 8..512 clauses;
//!   encode_only 1.6/3.2/7.1/15.9/28.6/60.1/117.1 forms the routing-overhead
//!   floor. Criterion confirmation medians (10 samples): cadical/256
//!   6.84 s, cadical/512 65.6 s, hitting_set/512 1.80 ms, bnb/512 4.08 ms,
//!   encode_only/512 137.8 us; the direction holds on both methodologies.
//! - Verdict: NO crossover within 8..512 hard clauses. The cadical/builtin
//!   ratio grows monotonically (166x at 8 clauses to 38,750x at 512), and
//!   cadical's per-doubling cost growth (~3.6x to 10x) exceeds the builtin's
//!   (~2.2x to 3.4x), so the gap diverges; routing to CaDiCaL is a regression
//!   at every measured count. The cadical 512-point costs ~65 s per solve and
//!   grows ~8x per doubling, so counts above 512 are not swept: the trend
//!   direction is already unambiguous, and the sentinel cutoff stays.
//!
//! Swept sizes: 8, 16, 32, 64, 128, 256, 512 hard clauses at a fixed
//! production horizon of 64. Four variants are timed per size:
//!
//! - `hitting_set`: the pure-Rust exact hitting-set engine.
//! - `maxsat_cadical`: MaxSAT forced to the CaDiCaL backend.
//! - `maxsat_bnb`: MaxSAT forced to its pure-Rust branch-and-bound fallback.
//! - `encode_only`: `encode_hazard` alone; the routing-overhead floor that
//!   every post-encode routing decision must pay anyway.
//!
//! Instance shape: N root Sends, one per distinct actor so no implicit head
//! edges chain them, plus one Outcome witness observing all roots. That
//! yields exactly N disjoint singleton hard clauses (`encoded.hard.len() ==
//! N` is asserted), giving exact count control over the swept axis. Journals
//! and encodings are built once outside timed sections; each timed iteration
//! constructs a fresh solver so clause and hypothesis caches cannot turn
//! later iterations into cache hits.
//!
//! The wall-clock table below prints before criterion's formal measurement
//! and derives the crossover: the smallest N where `maxsat_cadical` beats
//! both builtin variants consistently across repetitions. Host timing is
//! noisy by nature; rerun locally and confirm the point holds across runs
//! before moving `CADICAL_CUTOFF_HARD_CLAUSES`.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ledger_explorer::{
    FaultSolver, HittingSetSolver, MaxSatSolver, SolverConfig, SolverEngine, Verdict,
    maxsat::{HazardEncoding, encode_hazard},
};
use ledger_format::ActorId;
use ledger_format::{CanonicalValue, EntryHash, EntryKind, EntryPayload};
use ledger_journal::Journal;
use std::hint::black_box;
use std::time::{Duration, Instant};

const HARD_CLAUSE_COUNTS: &[usize] = &[8, 16, 32, 64, 128, 256, 512];
const HORIZON: usize = 64;
const TABLE_REPS: usize = 3;

/// One timed table row: variant name paired with its median run time (us).
type VariantTiming = (&'static str, f64);
/// A boxed benchmark operation for one engine or encoding variant.
///
/// The explicit lifetime keeps the closures borrowing the loop-local
/// journal, verdict, and config instead of demanding `'static` captures.
type VariantRun<'a> = Box<dyn Fn() + 'a>;
/// Per-size timings plus this run's derived crossover clause count.
type TableResult = (Vec<(usize, Vec<VariantTiming>)>, Option<usize>);

/// Build a journal whose hazard encoding has exactly `n` disjoint singleton
/// hard clauses.
///
/// Root i is a Send from actor `i + 1` (distinct actors keep head edges from
/// chaining the roots). One Outcome witness from a fresh actor observes every
/// root. The bounded collection at horizon [`HORIZON`] then yields one path
/// `[root_i]` per root.
fn build_disjoint_clauses_journal(n: usize) -> (Journal, Verdict) {
    let mut journal = Journal::new();
    let mut roots: Vec<EntryHash> = Vec::with_capacity(n);
    for i in 0..n {
        let id = journal
            .append(
                EntryKind::Send,
                ActorId((i + 1) as u32),
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(ActorId((i + 1) as u32), 0),
                    from: ActorId((i + 1) as u32),
                    to: ActorId(1),
                    original_content: (i as u64).to_le_bytes().to_vec(),
                }),
            )
            .expect("root Send append must succeed");
        roots.push(id);
    }
    // Fresh actor: the witness carries exactly the observed roots as parents.
    let witness = journal
        .append(
            EntryKind::Outcome,
            ActorId(u32::MAX),
            roots.clone(),
            EntryPayload::Outcome(ledger_format::OutcomePayload {
                schema: EntryHash([0x00; 32]),
                value: CanonicalValue::Unsigned(u64::MAX),
            }),
        )
        .expect("witness Outcome append must succeed");
    let verdict = Verdict::fail(vec![witness], format!("crossover journal n_clauses={n}"));
    (journal, verdict)
}

fn bench_config() -> SolverConfig {
    SolverConfig::default().with_horizon(HORIZON)
}

/// One full table sweep with host wall-clock timings.
///
/// Returns the per-size median timings plus this run's derived crossover.
fn measure_table() -> TableResult {
    let mut rows: Vec<(usize, Vec<VariantTiming>)> = Vec::new();
    for &count in HARD_CLAUSE_COUNTS {
        let (journal, verdict) = build_disjoint_clauses_journal(count);
        let config = bench_config();
        let encoded =
            encode_hazard(&journal, &verdict, &config).expect("hazard encoding must succeed");
        assert_eq!(
            encoded.hard.len(),
            count,
            "encoding must yield exactly N hard clauses"
        );

        // Validity checks outside timing so a broken engine fails loudly.
        fn assert_solves(name: &str, journal: &Journal, verdict: &Verdict, config: &SolverConfig) {
            let mut hs = HittingSetSolver::with_config(config.clone());
            assert!(
                !hs.solve(journal, verdict)
                    .unwrap_or_else(|e| panic!("{name} hitting-set solve failed: {e}"))
                    .is_empty()
            );
            let mut bnb =
                MaxSatSolver::with_config(config.clone().with_engine(SolverEngine::Builtin));
            assert!(
                !bnb.solve(journal, verdict)
                    .unwrap_or_else(|e| panic!("{name} bnb solve failed: {e}"))
                    .is_empty()
            );
            let mut cad =
                MaxSatSolver::with_config(config.clone().with_engine(SolverEngine::Cadical));
            assert!(
                !cad.solve(journal, verdict)
                    .unwrap_or_else(|e| panic!("{name} cadical solve failed: {e}"))
                    .is_empty()
            );
        }
        assert_solves("crossover", &journal, &verdict, &config);

        // Homogeneous variant list; each closure runs one full operation and
        // black-boxes its output so it cannot be optimized away.
        let variants: Vec<(&'static str, VariantRun<'_>)> = vec![
            (
                "hitting_set",
                Box::new(|| {
                    let mut solver = HittingSetSolver::with_config(config.clone());
                    black_box(
                        solver
                            .solve(black_box(&journal), black_box(&verdict))
                            .expect("hitting-set solve"),
                    );
                }),
            ),
            (
                "maxsat_bnb",
                Box::new(|| {
                    let mut solver = MaxSatSolver::with_config(
                        config.clone().with_engine(SolverEngine::Builtin),
                    );
                    black_box(
                        solver
                            .solve(black_box(&journal), black_box(&verdict))
                            .expect("bnb solve"),
                    );
                }),
            ),
            (
                "maxsat_cadical",
                Box::new(|| {
                    let mut solver = MaxSatSolver::with_config(
                        config.clone().with_engine(SolverEngine::Cadical),
                    );
                    black_box(
                        solver
                            .solve(black_box(&journal), black_box(&verdict))
                            .expect("cadical solve"),
                    );
                }),
            ),
            (
                "encode_only",
                Box::new(|| {
                    let encoded: HazardEncoding =
                        encode_hazard(black_box(&journal), black_box(&verdict), &config)
                            .expect("encode");
                    black_box(encoded);
                }),
            ),
        ];

        let mut medians: Vec<(&'static str, f64)> = Vec::new();
        for (name, run) in &variants {
            let mut samples: Vec<f64> = Vec::with_capacity(TABLE_REPS);
            for _ in 0..TABLE_REPS {
                let start = Instant::now();
                run();
                samples.push(start.elapsed().as_secs_f64() * 1e6);
            }
            samples.sort_by(|a, b| a.partial_cmp(b).expect("no NaN timings"));
            medians.push((name, samples[samples.len() / 2]));
        }
        rows.push((count, medians));
    }

    // Crossover: smallest count where cadical beats BOTH builtin variants in
    // this run's medians.
    let cutoff = rows
        .iter()
        .filter_map(|(count, medians)| {
            let cadical = medians
                .iter()
                .find(|(name, _)| *name == "maxsat_cadical")
                .map(|(_, v)| *v)?;
            let builtin_best = medians
                .iter()
                .filter(|(name, _)| *name != "maxsat_cadical" && *name != "encode_only")
                .map(|(_, v)| *v)
                .fold(f64::INFINITY, f64::min);
            (cadical < builtin_best).then_some(*count)
        })
        .next();

    println!(
        "\n## solver_crossover wall-clock table (median of {TABLE_REPS} runs, micro-seconds)\n"
    );
    println!("| hard clauses | hitting_set | maxsat_bnb | maxsat_cadical | encode_only |");
    println!("|-------------:|------------:|-----------:|---------------:|------------:|");
    for (count, medians) in &rows {
        let get = |want: &str| {
            medians
                .iter()
                .find(|(name, _)| *name == want)
                .map(|(_, v)| format!("{v:.1}"))
                .unwrap_or_else(|| "-".to_string())
        };
        println!(
            "| {count:>12} | {:>11} | {:>10} | {:>14} | {:>11} |",
            get("hitting_set"),
            get("maxsat_bnb"),
            get("maxsat_cadical"),
            get("encode_only"),
        );
    }
    match cutoff {
        Some(point) => println!(
            "\nMeasured CUTOFF (smallest count where cadical beats both builtin variants): \
             {point} hard clauses\n"
        ),
        None => println!(
            "\nCaDiCaL never beat the builtin variants within the swept sizes; keep the \
             documented sentinel cutoff.\n"
        ),
    }
    (rows, cutoff)
}

fn bench_solver_crossover(c: &mut Criterion) {
    let (_, measured_cutoff) = measure_table();

    let mut group = c.benchmark_group("solver_crossover");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));

    for &count in HARD_CLAUSE_COUNTS {
        let (journal, verdict) = build_disjoint_clauses_journal(count);
        let config = bench_config();
        let encoded =
            encode_hazard(&journal, &verdict, &config).expect("hazard encoding must succeed");
        assert_eq!(encoded.hard.len(), count);

        group.bench_with_input(BenchmarkId::new("hitting_set", count), &count, |b, _| {
            b.iter(|| {
                let mut solver = HittingSetSolver::with_config(config.clone());
                let hyps = solver
                    .solve(black_box(&journal), black_box(&verdict))
                    .expect("solve must succeed");
                black_box(hyps)
            });
        });

        group.bench_with_input(BenchmarkId::new("maxsat_bnb", count), &count, |b, _| {
            b.iter(|| {
                let mut solver =
                    MaxSatSolver::with_config(config.clone().with_engine(SolverEngine::Builtin));
                let hyps = solver
                    .solve(black_box(&journal), black_box(&verdict))
                    .expect("solve must succeed");
                black_box(hyps)
            });
        });

        group.bench_with_input(BenchmarkId::new("maxsat_cadical", count), &count, |b, _| {
            b.iter(|| {
                let mut solver =
                    MaxSatSolver::with_config(config.clone().with_engine(SolverEngine::Cadical));
                let hyps = solver
                    .solve(black_box(&journal), black_box(&verdict))
                    .expect("solve must succeed");
                black_box(hyps)
            });
        });

        group.bench_with_input(BenchmarkId::new("encode_only", count), &count, |b, _| {
            b.iter(|| {
                let encoded = encode_hazard(black_box(&journal), black_box(&verdict), &config)
                    .expect("encode must succeed");
                black_box(encoded)
            });
        });
    }
    group.finish();

    // Keep the measured point visible next to criterion's own summary.
    if let Some(point) = measured_cutoff {
        println!("solver_crossover measured CUTOFF: {point} hard clauses");
    } else {
        println!("solver_crossover measured CUTOFF: none within tested sizes; sentinel applies");
    }
}

criterion_group!(
    name = solver_crossover_benches;
    config = Criterion::default().sample_size(10).warm_up_time(std::time::Duration::from_secs(1));
    targets = bench_solver_crossover
);
criterion_main!(solver_crossover_benches);
