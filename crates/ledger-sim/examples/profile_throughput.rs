//! Host-side throughput profiling binary for the 4-task sim workload.
//!
//! Run: `cargo run -p ledger-sim --example profile_throughput --release`,
//! or profile with `cargo flamegraph -p ledger-sim --example profile_throughput --release`.
//! It loops the same workload the `sim_throughput` criterion bench measures so
//! `perf` attributes time to the real hot path.
// ledger-lint:allow (host-side profiling driver; it is not simulation code)

use ledger_sim::{Instruction, Policy, RunConfig, Simulation};
use std::hint::black_box;

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

fn main() {
    let programs = throughput_programs(500);
    let config = RunConfig::builder()
        .seed([1; 32])
        .policy(Policy::Random)
        .max_steps(200_000)
        .build();
    let runs: u64 = std::env::args()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(400);
    let mut total_entries = 0u64;
    let start = std::time::Instant::now();
    for _ in 0..runs {
        let result = Simulation::new(config.clone(), programs.clone())
            .run()
            .expect("sim must run");
        total_entries += result.journal.len() as u64;
    }
    let elapsed = start.elapsed();
    let per_run = elapsed / runs as u32;
    let events_per_sec = total_entries as f64 / elapsed.as_secs_f64();
    eprintln!("runs={runs} total_entries={total_entries} elapsed={elapsed:?} per_run={per_run:?}");
    eprintln!("events_per_sec={events_per_sec:.0}");
    black_box(total_entries);
}
