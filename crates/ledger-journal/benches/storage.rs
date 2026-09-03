//! Storage benchmarks: append, batch, durable, fork, and seal.
//!
//! Size series use 1k/10k/100k suffixes from [`append_name`].
// ledger-lint:allow:fs:: (bench harness measures the host storage layer, which ambient fs writes by design; same as persistent.rs and segment/)

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ledger_format::{ActorId, CanonicalValue, EntryHash, EntryKind, EntryPayload, OutcomePayload};
use ledger_journal::{BatchEntry, Journal, PersistentJournal, SegmentWriter};
use std::hint::black_box;

/// Batch chunk size for amortized-cost measurement.
const CHUNK: usize = 512;

fn append_name(count: u64) -> String {
    let suffix = match count {
        1_000 => "1k",
        10_000 => "10k",
        100_000 => "100k",
        _ => return count.to_string(),
    };
    suffix.to_string()
}

fn bench_append_throughput(c: &mut Criterion) {
    for &count in &[1_000u64, 10_000, 100_000] {
        c.bench_function(&format!("append_throughput_{}", append_name(count)), |b| {
            b.iter_batched(
                Journal::new,
                |mut journal| {
                    for i in 0..count {
                        black_box(
                            journal
                                .append(
                                    EntryKind::Outcome,
                                    ActorId(1),
                                    [],
                                    EntryPayload::Outcome(OutcomePayload {
                                        schema: EntryHash([0x00; 32]),
                                        value: CanonicalValue::Unsigned(i),
                                    }),
                                )
                                .unwrap(),
                        );
                    }
                    black_box(journal.root_hash());
                },
                BatchSize::SmallInput,
            );
        });
    }
}

/// Build the chunked batch plan for `count` entries.
fn build_chunked_batches(count: u64) -> Vec<Vec<BatchEntry>> {
    let mut batches: Vec<Vec<BatchEntry>> = Vec::with_capacity(count as usize / CHUNK + 1);
    let mut current: Vec<BatchEntry> = Vec::with_capacity(CHUNK);
    for i in 0..count {
        current.push(BatchEntry::new(
            EntryKind::Outcome,
            ActorId(1),
            EntryPayload::Outcome(OutcomePayload {
                schema: EntryHash([0x00; 32]),
                value: CanonicalValue::Unsigned(i),
            }),
        ));
        if current.len() == CHUNK {
            batches.push(std::mem::replace(&mut current, Vec::with_capacity(CHUNK)));
        }
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

/// Same workload as `append_throughput` through the batch API.
fn bench_append_batch_throughput(c: &mut Criterion) {
    for &count in &[1_000u64, 10_000, 100_000] {
        c.bench_function(
            &format!("append_batch_{}_chunked", append_name(count)),
            |b| {
                b.iter_batched(
                    || (Journal::new(), build_chunked_batches(count)),
                    |(mut journal, batches)| {
                        for batch in batches {
                            black_box(journal.append_batch(batch).unwrap());
                        }
                        black_box(journal.root_hash());
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

/// Durable-append benchmark with snapshots disabled. TMPDIR must be tmpfs.
fn durable_setup(name: &str) -> (PersistentJournal, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("ldgr-bench-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    (
        PersistentJournal::create_with_interval(&dir, u64::MAX).unwrap(),
        dir,
    )
}

fn bench_append_durable(c: &mut Criterion) {
    for &count in &[1_000u64, 10_000, 100_000] {
        c.bench_function(&format!("append_durable_{}", append_name(count)), |b| {
            b.iter_batched(
                || durable_setup("append"),
                |(mut journal, _dir)| {
                    for i in 0..count {
                        black_box(
                            journal
                                .append(
                                    EntryKind::Outcome,
                                    ActorId(1),
                                    [],
                                    EntryPayload::Outcome(OutcomePayload {
                                        schema: EntryHash([0x00; 32]),
                                        value: CanonicalValue::Unsigned(i),
                                    }),
                                )
                                .unwrap(),
                        );
                    }
                    black_box(journal.root_hash());
                },
                BatchSize::SmallInput,
            );
        });
    }
}

fn bench_append_batch_durable(c: &mut Criterion) {
    for &count in &[1_000u64, 10_000, 100_000] {
        c.bench_function(
            &format!("append_batch_durable_{}_chunked", append_name(count)),
            |b| {
                b.iter_batched(
                    || {
                        (
                            durable_setup("append-batch").0,
                            build_chunked_batches(count),
                        )
                    },
                    |(mut journal, batches)| {
                        for batch in batches {
                            black_box(journal.append_batch(batch).unwrap());
                        }
                        black_box(journal.root_hash());
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

fn build_journal(entries: u64) -> Journal {
    let mut journal = Journal::new();
    for i in 0..entries {
        journal
            .append(
                EntryKind::Outcome,
                ActorId(1),
                [],
                EntryPayload::Outcome(OutcomePayload {
                    schema: EntryHash([0x00; 32]),
                    value: CanonicalValue::Unsigned(i),
                }),
            )
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
                        fork.append(
                            EntryKind::Outcome,
                            ActorId(1),
                            [],
                            EntryPayload::Outcome(OutcomePayload {
                                schema: EntryHash([0x00; 32]),
                                value: CanonicalValue::Unsigned(i),
                            }),
                        )
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
            black_box(writer.clone().seal(&dir, 0).unwrap());
        });
    });
}

criterion_group!(
    name = storage_benches;
    config = Criterion::default().sample_size(30).warm_up_time(std::time::Duration::from_secs(2));
    targets = bench_append_throughput, bench_append_batch_throughput, bench_append_durable, bench_append_batch_durable, bench_fork_cost, bench_segment_seal
);
criterion_main!(storage_benches);
