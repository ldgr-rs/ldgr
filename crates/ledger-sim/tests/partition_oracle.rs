//! Live partition oracle: a `Fault` entry applied mid-run toggles the
//! (src, dst) link in the live network, and the journaled Partition state is
//! consistent with the observed delivery behavior.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use ledger_format::{CanonicalValue, EntryKind, EntryPayload, FaultPayload, Hash, OutcomePayload};
use ledger_sim::{Boundary, Effects, Policy, RunConfig, Simulation, TaskBuilder};

fn boxed(
    future: impl Future<Output = ()> + 'static,
) -> Pin<Box<dyn Future<Output = ()> + 'static>> {
    Box::pin(future)
}

fn config(seed: [u8; 32]) -> RunConfig {
    RunConfig::builder()
        .seed(seed)
        .policy(Policy::Random)
        .max_steps(512)
        .build()
}

/// A mid-run partition fault flips the link, refuses subsequent sends, and a
/// later toggle restores delivery. The sleep deadlines pin the injection
/// points, so the interleaving is seed-independent.
#[test]
fn partition_fault_mid_run_flips_link_and_restores_delivery() {
    let builders: Vec<TaskBuilder> = vec![
        Box::new(|boundary: Boundary| {
            boxed(async move {
                let first = boundary.send(1, 1);
                boundary.sleep(Duration::from_micros(10)).await;
                let second = boundary.send(1, 2);
                boundary.sleep(Duration::from_micros(10)).await;
                let third = boundary.send(1, 3);
                let code = u64::from(first) * 4 + u64::from(second) * 2 + u64::from(third);
                let _ = boundary.outcome(code);
            })
        }),
        Box::new(|boundary: Boundary| {
            boxed(async move {
                boundary.sleep(Duration::from_micros(5)).await;
                boundary.apply_partition(0, 1).unwrap();
                boundary.sleep(Duration::from_micros(10)).await;
                boundary.apply_partition(0, 1).unwrap();
            })
        }),
    ];
    let run = Simulation::with_tasks(config([31; 32]), builders)
        .run()
        .unwrap();
    assert!(
        run.monitor_issues.is_empty(),
        "monitor issues: {:?}",
        run.monitor_issues
    );

    // Delivery pattern: before the partition (delivered), during it (refused),
    // after the restore (delivered again).
    let outcome = run
        .journal
        .entries()
        .find_map(|entry| match (&entry.data.kind, &entry.data.payload) {
            (
                EntryKind::Outcome,
                EntryPayload::Outcome(OutcomePayload {
                    value: CanonicalValue::Unsigned(value),
                    ..
                }),
            ) => Some(*value),
            _ => None,
        })
        .expect("the sender must journal an outcome");
    assert_eq!(
        outcome, 5,
        "sends must deliver, then be refused, then deliver"
    );

    // Journaled Partition state: the refused send's witness links back to its
    // Send entry, while the explicit toggles carry only the injector task's
    // own causal history (no send parent).
    let partition_faults = run
        .journal
        .entries()
        .filter_map(|entry| match &entry.data.payload {
            EntryPayload::Fault(FaultPayload::Partition { src: 0, dst: 1, .. }) => {
                Some(entry.data.parents.clone())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let send_ids = run
        .journal
        .entries()
        .filter_map(|entry| matches!(entry.data.kind, EntryKind::Send).then_some(entry.id))
        .collect::<Vec<Hash>>();
    assert_eq!(send_ids.len(), 3, "three sends must be journaled");
    assert_eq!(
        partition_faults.len(),
        3,
        "two explicit toggles plus one witness must be journaled"
    );
    assert!(
        partition_faults[0]
            .iter()
            .all(|parent| !send_ids.contains(parent)),
        "the partition-on toggle must not be parented to any send"
    );
    assert!(
        partition_faults[1].contains(&send_ids[1]),
        "the refused send must journal a Partition witness against its Send entry"
    );
    assert!(
        partition_faults[2]
            .iter()
            .all(|parent| !send_ids.contains(parent)),
        "the partition-off toggle must not be parented to any send"
    );
}

/// The live partition oracle is deterministic: the same seed replays the same
/// delivery pattern and the same journal root.
#[test]
fn partition_fault_is_deterministic() {
    let build = || -> Vec<TaskBuilder> {
        vec![
            Box::new(|boundary: Boundary| {
                boxed(async move {
                    let first = boundary.send(1, 1);
                    boundary.sleep(Duration::from_micros(10)).await;
                    let second = boundary.send(1, 2);
                    let code = u64::from(first) * 2 + u64::from(second);
                    let _ = boundary.outcome(code);
                })
            }),
            Box::new(|boundary: Boundary| {
                boxed(async move {
                    boundary.sleep(Duration::from_micros(5)).await;
                    boundary.apply_partition(0, 1).unwrap();
                })
            }),
        ]
    };
    let first = Simulation::with_tasks(config([32; 32]), build())
        .run()
        .unwrap();
    let second = Simulation::with_tasks(config([32; 32]), build())
        .run()
        .unwrap();
    assert_eq!(
        first.journal.root_hash(),
        second.journal.root_hash(),
        "the same seed must replay the partition lifecycle byte-identically"
    );
}
