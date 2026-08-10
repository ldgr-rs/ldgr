//! Storage benchmarks.
//!
//! Targets:
//! - Append throughput: >= 1M entries/s/core in-memory.
//! - Fork cost: O(1) Arc clone; post-fork appends not O(manifest).
//! - Segment seal: 1M entries through the segment writer.

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ledger_format::{EntryKind, Payload};
use ledger_journal::{Journal, SegmentWriter};
use std::hint::black_box;

fn bench_append_throughput(c: &mut Criterion) {
    c.bench_function("append_throughput_100k", |b| {
        b.iter_batched(
            Journal::new,
            |mut journal| {
                for i in 0..100_000u64 {
                    black_box(
                        journal
                            .append(EntryKind::Outcome, 1, [], Payload::Number(i))
                            .unwrap(),
                    );
                }
                black_box(journal.root_hash());
            },
            BatchSize::SmallInput,
        );
    });
}

fn build_journal(entries: u64) -> Journal {
    let mut journal = Journal::new();
    for i in 0..entries {
        journal
            .append(EntryKind::Outcome, 1, [], Payload::Number(i))
            .unwrap();
    }
    journal
}

fn bench_fork_cost(c: &mut Criterion) {
    let journal = build_journal(1_000_000);
    c.bench_function("fork_cost_1m", |b| {
        b.iter(|| black_box(journal.fork()));
    });
    c.bench_function("post_fork_append_1000", |b| {
        b.iter_batched(
            || journal.fork(),
            |mut fork| {
                for i in 0..1000u64 {
                    black_box(
                        fork.append(EntryKind::Outcome, 1, [], Payload::Number(i))
                            .unwrap(),
                    );
                }
                black_box(fork.root_hash());
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_segment_seal(c: &mut Criterion) {
    let journal = build_journal(1_000_000);
    let mut writer = SegmentWriter::new();
    for entry in journal.entries() {
        writer.append(entry).unwrap();
    }
    assert!(writer.entry_count() == 1_000_000);
    c.bench_function("segment_seal_1m", |b| {
        b.iter(|| {
            let dir = std::env::temp_dir();
            black_box(writer.seal(&dir, 0).unwrap());
        });
    });
}

criterion_group!(
    name = storage_benches;
    config = Criterion::default().sample_size(30).warm_up_time(std::time::Duration::from_secs(2));
    targets = bench_append_throughput, bench_fork_cost, bench_segment_seal
);
criterion_main!(storage_benches);
