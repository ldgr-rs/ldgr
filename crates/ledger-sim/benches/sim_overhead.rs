//! Sim-overhead benchmark.
//!
//! Two measurements:
//!
//! 1. `cpu_at_100k_entries_per_second` (binding gate): the sim is
//!    single-threaded, so one core sustains the measured throughput and the
//!    CPU cost of running at 100k entries/s is `100_000 / events_per_second`
//!    of one core. The target is <= 10% CPU at 100k entries/s, which is
//!    equivalent to >= 10^6 events/s. The CI bench-gate parses this bench and
//!    asserts the throughput.
//!
//! 2. `journal_share_of_sim_cost` (informational): the marginal cost of the
//!    journal layer (canonical encode + BLAKE3 + VC merge + append) against
//!    the full sim, so the overhead-vs-unjournaled split is measured, not
//!    guessed. This number is reported, not gated: per-entry canonical
//!    hashing is a normative design, so the journal is expected to
//!    dominate the sim cost. Future throughput work targets the split.
//!
//! The workload is the 4-task message-passing program from `sim_throughput`
//! (5045 entries at 500 steps/task).
// ledger-lint:allow (host-side benchmark measures the sim; it is not simulation code)

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ledger_format::{EntryKind, Payload};
use ledger_journal::Journal;
use ledger_sim::{Instruction, Policy, RunConfig, Simulation};

/// Journaled entries per full run of the 4-task workload.
pub const ENTRIES_PER_RUN: u64 = 5045;

fn throughput_programs(steps_per_task: u64) -> Vec<Vec<Instruction>> {
    let mut sender = Vec::new();
    let mut receiver = Vec::new();
    let mut reader = Vec::new();
    let mut timer = Vec::new();
    for i in 0..steps_per_task {
        sender.push(Instruction::Send { to: 1, payload: i });
        receiver.push(Instruction::Receive);
        reader.push(Instruction::SendTimed {
            to: 1,
            payload: i,
            delay: 1,
        });
        timer.push(Instruction::Sleep(1));
    }
    sender.push(Instruction::Done);
    receiver.push(Instruction::Done);
    reader.push(Instruction::Done);
    timer.push(Instruction::Done);
    vec![sender, receiver, reader, timer]
}

fn bench_cpu_at_100k(c: &mut Criterion) {
    let programs = throughput_programs(500);
    let config = RunConfig::builder()
        .seed([1; 32])
        .policy(Policy::Random)
        .max_steps(200_000)
        .build();
    let mut group = c.benchmark_group("sim_overhead");
    group
        .bench_function("cpu_at_100k_entries_per_second", |b| {
            b.iter_batched(
                || Simulation::new(config.clone(), programs.clone()),
                |sim| {
                    let result = sim.run().unwrap();
                    let events = result.journal.len() as u64;
                    assert_eq!(events, ENTRIES_PER_RUN);
                    std::hint::black_box(events);
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .throughput(Throughput::Elements(ENTRIES_PER_RUN));
    group.finish();
}

/// Append one representative entry kind of the workload, cycling actors so the
/// journal exercises head churn like the sim does. Recv and TimerFire carry an
/// observed parent (the previous append), matching the sim's read provenance.
fn append_one(
    journal: &mut Journal,
    step: u64,
    last: Option<ledger_format::Hash>,
) -> ledger_format::Hash {
    let actor = (step % 4) as u32;
    let observed = last.into_iter().collect::<Vec<_>>();
    match step % 4 {
        0 => journal
            .append(
                EntryKind::Send,
                actor,
                [],
                Payload::Pair {
                    left: 1,
                    right: step,
                },
            )
            .unwrap(),
        1 => journal
            .append(EntryKind::Recv, actor, observed, Payload::Number(step))
            .unwrap(),
        2 => journal
            .append(EntryKind::TimerSet, actor, [], Payload::Number(step))
            .unwrap(),
        _ => journal
            .append(EntryKind::TimerFire, actor, observed, Payload::Empty)
            .unwrap(),
    }
}

fn bench_journal_share(c: &mut Criterion) {
    let mut group = c.benchmark_group("sim_overhead");
    group.bench_function("journal_share_of_sim_cost", |b| {
        b.iter_batched(
            Journal::new,
            |mut journal| {
                let mut last: Option<ledger_format::Hash> = None;
                for step in 0..2000 {
                    last = Some(append_one(&mut journal, step, last));
                }
                std::hint::black_box(journal.len());
            },
            criterion::BatchSize::SmallInput,
        )
    });
    group.finish();
}

criterion_group!(benches, bench_cpu_at_100k, bench_journal_share);
criterion_main!(benches);
