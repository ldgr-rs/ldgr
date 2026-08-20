//! Sim-throughput benchmark.
// ledger-lint:allow (host-side benchmark drives the sim to measure throughput; it is not simulation code)
//!
//! Target: >= 10^6 events/s single-thread. An "event" is one
//! journaled entry. The workload is a 4-task message-passing program that
//! journals Send/Recv/SendTimed/TimerSet/TimerFire entries.
//!
//! ENTRIES_PER_RUN is the measured journal size for this workload (5045
//! entries at 500 steps/task); the CI bench-gate parses the criterion `time:`
//! and computes events/s = ENTRIES_PER_RUN / time. The batch asserts the run
//! journaled at least this many entries so drift fails loudly.

use criterion::{Criterion, criterion_group, criterion_main};
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

fn bench_sim_throughput(c: &mut Criterion) {
    let programs = throughput_programs(500);
    let config = RunConfig::builder()
        .seed([1; 32])
        .policy(Policy::Random)
        .max_steps(200_000)
        .build();
    let mut group = c.benchmark_group("sim_throughput");
    group
        .bench_function("events_per_second_4_task", |b| {
            b.iter_batched(
                || Simulation::new(config.clone(), programs.clone()),
                |sim| {
                    let result = sim.run().unwrap();
                    let events = result.journal.len() as u64;
                    assert_eq!(
                        events, ENTRIES_PER_RUN,
                        "the workload's journal size must match ENTRIES_PER_RUN; \
                     update the constant when the workload changes"
                    );
                    std::hint::black_box(events);
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .throughput(criterion::Throughput::Elements(ENTRIES_PER_RUN));
    group.finish();
}

criterion_group!(benches, bench_sim_throughput);
criterion_main!(benches);
