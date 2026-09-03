//! Solver-scaling curve: end-to-end hazard certification on a closure that
//! grows from 10^3 to 10^6 entries.
//!
//! The fixture is the shared-gate fan-in: one gate `Send`, `paths` witness
//! `Recv`s observing only the gate, so every derivation path runs through
//! the gate and the minimal weighted cut is the gate alone (cost 2) while
//! the clause count grows linearly with `paths`. The measured pipeline is
//! `services::certify_hazard` - witness closure extraction, hazard
//! encoding, solve, statement emission, and journal-anchored validation -
//! the same path the CI gate budgets at 60 seconds for the 10^6 closure.
//!
//! The published axes are the journal size AND the clause count: on this
//! shape the pipeline is linear in clauses, and the previous
//! "10^6 entries, flat curve" fixture (whose solver problem was O(1) in N)
//! was retired as misleading.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ledger_explorer::services::certify_hazard;
use ledger_format::ActorId;
use ledger_format::EntryHash;
use ledger_format::{EntryKind, EntryPayload, MessageId, RecvFrame, SendFrame};
use ledger_journal::Journal;
use std::hint::black_box;

const SIZES: [usize; 4] = [1_000, 10_000, 100_000, 1_000_000];

/// Build the shared-gate fan-in hazard: (journal, verdict, gate-send id).
fn build_fan_in(paths: usize) -> (Journal, ledger_explorer::Verdict, ledger_format::EntryHash) {
    let mut journal = Journal::new();
    let gate = journal
        .append(
            EntryKind::Send,
            ActorId(0),
            [],
            EntryPayload::Send(SendFrame {
                message_id: MessageId::new(ActorId(0), 0),
                from: ActorId(0),
                to: ActorId(1),
                original_content: vec![0],
            }),
        )
        .expect("gate send must append");
    let mut witnesses = Vec::with_capacity(paths);
    for index in 0..paths {
        let actor = 2_000_000_u32 + index as u32;
        let witness = journal
            .append(
                EntryKind::Recv,
                ActorId(actor),
                [gate],
                EntryPayload::Recv(RecvFrame {
                    message_id: MessageId::new(ActorId(actor), index as u64),
                    from: ActorId(0),
                    to: ActorId(actor),
                    observed_content: vec![0],
                }),
            )
            .expect("witness must append");
        witnesses.push(witness);
    }
    let verdict = ledger_explorer::Verdict {
        violated: true,
        witnesses,
        reason: "fan-in hazard fixture".to_string(),
    };
    (journal, verdict, gate)
}

fn scaling_curve(c: &mut Criterion) {
    let mut group = c.benchmark_group("solver_scaling_e2e");
    for &paths in &SIZES {
        let entries = paths + 1;
        let (journal, verdict, _gate) = build_fan_in(paths);
        group.bench_with_input(
            BenchmarkId::new(format!("{entries}_entries"), paths),
            &paths,
            |b, _| {
                b.iter_batched(
                    || (journal.clone(), verdict.clone()),
                    |(journal, verdict)| {
                        let (hypotheses, certificate) =
                            certify_hazard(journal, &verdict, EntryHash([7u8; 32]), 1024)
                                .expect("end-to-end certification must succeed");
                        black_box((hypotheses.len(), certificate));
                    },
                    criterion::BatchSize::LargeInput,
                )
            },
        );
    }
    group.finish();
}

criterion_group!(benches, scaling_curve);
criterion_main!(benches);
