//! Storage benchmarks.
//!
//! Targets:
//! - Append throughput: >= 1M entries/s/core in-memory.
//! - Batch append cost: the amortized append path at 1k, 10k, and
//!   100k entries, chunked in 512-entry calls (the executor shape).
//! - Durable append: hash computation, WAL write, and index update through
//!   the segment store at 1k, 10k, and 100k entries, snapshots disabled.
//! - Fork cost: O(1) Arc clone; post-fork appends not O(manifest).
//! - Segment seal: 1M entries through the segment writer.
//!
//! Measurement methodology (recorded 2026-08-24 during Task 7.1):
//! - Command: `cargo bench -p ledger-journal --bench storage` (bench
//!   profile, optimized release build).
//! - Host: 12th Gen Intel Core i5-12500H (Alder Lake), 16 logical CPUs,
//!   /tmp on tmpfs, CPU governor `powersave` (400 MHz idle, 4.5 GHz boost
//!   ceiling).
//! - Cross-window drift on this host reaches ~15% (thermal and frequency
//!   scaling). Verdicts must compare the per-entry and batch arms within
//!   one invocation, and pin to one P-core with `taskset -c 0`; pinning
//!   materially reduces variance and is required for acceptance data.
//! - Criterion settings: 30 samples, 2 s warm-up (group config below).
//!   Decisive Task 7.1 runs used `--measurement-time 25-30` and
//!   `--sample-size 100-150` on the pinned core.
//! - Fresh-data verdicts, 2026-08-24 (batch vs per-entry, medians):
//!   durable axis (hash + WAL + index): -27.5% at 1k, -22.7% to -28.7% at
//!   10k, -11.0% to -13.1% at 100k; all clear the 10% acceptance bar.
//!   In-memory journal axis: -3.4% to -8.5% at 100k, ~0% at 10k, -4.8% at
//!   1k; below the 10% bar.
//!   Independent confirmation run (pinned, 100 samples, 25-30 s windows)
//!   reproduced both axes' directions: in-memory 1k -9.7% (353.4 vs
//!   319.2 us), durable 100k -7.7% (77.4 vs 71.4 ms). Unpinned quick
//!   sweeps can flip directions on this host; trust only pinned,
//!   within-invocation comparisons.
//! - Target naming: every size-scaled append series uses the 1k/10k/100k suffix from
//!   [`append_name`]. `append_throughput_100k` keeps its historical label,
//!   which coincides with the scheme. Bench filters must therefore spell
//!   suffixes as 1k/10k/100k, for example `--bench "^append_durable_10k$"`.
// ledger-lint:allow:fs:: (bench harness measures the host storage layer, which ambient fs writes by design; same as persistent.rs and segment/)

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ledger_format::{CanonicalValue, EntryKind, EntryPayload, OutcomePayload};
use ledger_journal::{BatchEntry, Journal, PersistentJournal, SegmentWriter};
use std::hint::black_box;

/// Fixed representative chunk of the executor's variable per-advance batch
/// plan (`fired.len() * 2` per quiescent group). Chosen for amortized-cost
/// measurement, not an executor constant.
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
                                    1,
                                    [],
                                    EntryPayload::Outcome(OutcomePayload {
                                        schema: [0x00; 32],
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

/// Build the chunked batch plan for `count` entries before the timed region,
/// so the measurement isolates the journal layer like the per-append bench.
fn build_chunked_batches(count: u64) -> Vec<Vec<BatchEntry>> {
    let mut batches: Vec<Vec<BatchEntry>> = Vec::with_capacity(count as usize / CHUNK + 1);
    let mut current: Vec<BatchEntry> = Vec::with_capacity(CHUNK);
    for i in 0..count {
        current.push(BatchEntry::new(
            EntryKind::Outcome,
            1,
            EntryPayload::Outcome(OutcomePayload {
                schema: [0x00; 32],
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

/// Same workload as `append_throughput` through the batch API in 512-entry
/// calls, the amortization shape the executor uses.
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

/// One durable-append benchmark: hash computation, WAL write, and index
/// update, with snapshots disabled so only the append path is measured.
///
/// Each iteration runs against a fresh directory under the process temp
/// area; setup runs untimed, and the leftover directory is removed at the
/// start of the next setup, so cleanup never lands in the timed region.
/// The final iteration's directory stays until the next process run removes
/// it; that is deliberate (a Drop guard on the directory would run inside
/// the timed region).
///
/// TMPDIR must be memory-backed (tmpfs). On a disk-backed TMPDIR the WAL
/// flush silently measures page-cache writeback instead of the append path.
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
                                    1,
                                    [],
                                    EntryPayload::Outcome(OutcomePayload {
                                        schema: [0x00; 32],
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
                1,
                [],
                EntryPayload::Outcome(OutcomePayload {
                    schema: [0x00; 32],
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
                            1,
                            [],
                            EntryPayload::Outcome(OutcomePayload {
                                schema: [0x00; 32],
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
