//! Vector clock benchmarks for the persistent representation.

use criterion::{Criterion, criterion_group, criterion_main};
use ledger_format::ActorId;
use ledger_journal::VectorClock;
use std::hint::black_box;

fn build_clock(actors: u32) -> VectorClock {
    let mut clock = VectorClock::new();
    for actor in 1..=actors {
        let actor = ActorId(actor);
        clock = clock.incremented(actor);
    }
    clock
}

fn bench_vc_incremented(c: &mut Criterion) {
    let mut group = c.benchmark_group("vc_incremented");
    for &actors in &[10, 1_000, 10_000] {
        let clock = build_clock(actors);
        group.bench_function(format!("{actors}_actors"), |b| {
            b.iter(|| black_box(clock.incremented(ActorId(1))));
        });
    }
    group.finish();
}

fn bench_vc_merge(c: &mut Criterion) {
    let left = build_clock(1_000);
    let right = build_clock(1_000);
    c.benchmark_group("vc_merge")
        .bench_function("1000_actors", |b| {
            b.iter(|| black_box(left.merge(&right)));
        });
}

fn bench_vc_fork(c: &mut Criterion) {
    let clock = build_clock(10_000);
    c.benchmark_group("vc_fork")
        .bench_function("compact_10000", |b| {
            b.iter(|| black_box(clock.compact()));
        });
}

criterion_group!(
    name = vc_benches;
    config = Criterion::default().sample_size(30).warm_up_time(std::time::Duration::from_secs(2));
    targets = bench_vc_incremented, bench_vc_merge, bench_vc_fork
);
criterion_main!(vc_benches);
