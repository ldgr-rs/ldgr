//! Reference-runtime dogfood suite: real async protocols on the effect
//! boundary.
//!
//! Each mini protocol is a miniature of a real distributed system with a
//! planted bug whose root cause matches a documented scenario:
//! - mini-zab: ZK Bug #335 class - a follower synchronizes from its
//!   last-known-committed value only and misses a newer committed value, so
//!   the cluster permanently diverges (split-brain).
//! - mini-hdfs: lease-recovery race (HDFS-4472 class) - the NameNode grants a
//!   block version before the previous write commits, so two writers can
//!   receive the same version.
//! - mini-cassandra: gossip anti-entropy staleness - a node serves a read
//!   before the anti-entropy exchange propagates the latest value.
//! - mini-2pc: blocking two-phase commit - a coordinator crashes after prepare
//!   but before commit for one participant, leaving a committed/uncommitted
//!   split.
//! - mini-leader-stepdown: Raft election-restriction class - a stepped-down
//!   leader keeps serving stale reads from its old term after a new leader
//!   committed a newer value.
//! - mini-membership-churn: a leader refuses to advance its commit index until
//!   a departed member acks, so an entry acknowledged by every live member
//!   never commits.
//! - mini-hdfs-lease-expiry: lease-recovery class - a writer whose lease
//!   expired keeps writing after the lease moved to a new writer, so its late
//!   write overwrites the current holder's data.
//!
//! Each sim returns task builders for `Simulation::with_tasks` plus a
//! deterministic oracle over the journal's `Outcome` entries.

use ledger_journal::Journal;
use ledger_sim::{Boundary, Effects, TaskBuilder};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// Box a task body into the executor's cooperative future shape.
fn task(body: impl Future<Output = ()> + 'static) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(body)
}

fn outcome_values(journal: &Journal) -> Vec<u64> {
    journal
        .entries()
        .filter_map(|entry| match entry.data.kind {
            ledger_format::EntryKind::Outcome => match &entry.data.payload {
                ledger_format::Payload::Number(value) => Some(*value),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// Convergence oracle: every node must record the same final value.
pub fn convergence_oracle() -> impl Fn(&Journal) -> bool {
    |journal: &Journal| {
        let outcomes = outcome_values(journal);
        let Some(first) = outcomes.first() else {
            return true;
        };
        outcomes.iter().all(|value| value == first)
    }
}

/// Distinctness oracle: all recorded outcomes must differ (no double grant).
pub fn distinct_outcomes_oracle() -> impl Fn(&Journal) -> bool {
    |journal: &Journal| {
        let outcomes = outcome_values(journal);
        let mut seen = std::collections::HashSet::new();
        outcomes.iter().all(|value| seen.insert(*value))
    }
}

/// Collect the `Outcome` values journaled by one actor, in journal order.
fn outcome_by_actor(journal: &Journal, actor: u32) -> Vec<u64> {
    journal
        .entries()
        .filter_map(|entry| {
            if entry.data.actor == actor && entry.data.kind == ledger_format::EntryKind::Outcome {
                match &entry.data.payload {
                    ledger_format::Payload::Number(value) => Some(*value),
                    _ => None,
                }
            } else {
                None
            }
        })
        .collect()
}

/// Commit oracle: the leader must commit the entry that the remaining live
/// follower acknowledged. A stalled commit index violates it.
pub fn live_quorum_commit_oracle() -> impl Fn(&Journal) -> bool {
    |journal: &Journal| {
        let leader = outcome_by_actor(journal, 0);
        let live_follower = outcome_by_actor(journal, 1);
        match (leader.last(), live_follower.last()) {
            (Some(committed), Some(acknowledged)) => committed == acknowledged,
            _ => false,
        }
    }
}

/// Lease oracle: the storage's applied value must be the current lease
/// holder's write, not an expired holder's late write.
pub fn current_lease_holder_write_oracle() -> impl Fn(&Journal) -> bool {
    |journal: &Journal| {
        let storage = outcome_by_actor(journal, 3);
        let current_holder = outcome_by_actor(journal, 2);
        match (storage.last(), current_holder.last()) {
            (Some(applied), Some(written)) => applied == written,
            _ => false,
        }
    }
}

/// mini-zab: ZK Bug #335 class.
///
/// Node 0 (leader) proposes value 1, then value 2 after a re-election. Node 1
/// follows both. Node 2 synchronizes from its last-known-committed value only:
/// it records the first commit and never waits for the second, so it ends with
/// value 1 while nodes 0 and 1 hold value 2. The convergence oracle detects the
/// permanent divergence.
pub fn mini_zab() -> (Vec<TaskBuilder>, impl Fn(&Journal) -> bool) {
    let builders: Vec<TaskBuilder> = vec![
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.send(1, 1);
                let _ = b.send(2, 1);
                b.sleep(Duration::from_micros(1)).await;
                let _ = b.send(1, 2);
                let _ = b.send(2, 2);
                let _ = b.outcome(2);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _first = b.recv().await;
                let second = b.recv().await;
                let _ = b.outcome(second);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let first = b.recv().await;
                let _ = b.outcome(first);
            })
        }),
    ];
    (builders, convergence_oracle())
}

/// mini-hdfs: lease-recovery double grant (HDFS-4472 class).
///
/// The NameNode (task 0) grants the pre-bump version to every request it has
/// awaited and bumps only after both grants are issued. Both writers therefore
/// always receive version 0: this is a deterministic planted sequence, not a
/// schedule-dependent race. The distinctness oracle flags the double grant.
pub fn mini_hdfs() -> (Vec<TaskBuilder>, impl Fn(&Journal) -> bool) {
    let builders: Vec<TaskBuilder> = vec![
        Box::new(|b: Boundary| {
            task(async move {
                // NameNode: grant the pre-bump version to both awaited requests,
                // bumping only after both grants are issued.
                let mut version = 0u64;
                let r1 = b.recv().await;
                let r2 = b.recv().await;
                let granted1 = version; // bug: both see the pre-bump version
                let granted2 = version;
                let _ = b.send(r1 as usize, granted1);
                let _ = b.send(r2 as usize, granted2);
                version += 1;
                let _ = b.outcome(version);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.send(0, 1);
                let granted = b.recv().await;
                let _ = b.outcome(granted);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                b.sleep(Duration::from_micros(1)).await;
                let _ = b.send(0, 2);
                let granted = b.recv().await;
                let _ = b.outcome(granted);
            })
        }),
    ];
    (builders, distinct_outcomes_oracle())
}

/// mini-cassandra: gossip anti-entropy staleness.
///
/// Node 0 (primary) writes value 7 and gossips it. Node 1 waits for the
/// gossip. Node 2 serves a read of its local value (0) before the anti-entropy
/// exchange reaches it and never syncs. The convergence oracle detects that
/// node 2 served stale data.
pub fn mini_cassandra() -> (Vec<TaskBuilder>, impl Fn(&Journal) -> bool) {
    let builders: Vec<TaskBuilder> = vec![
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.send(1, 7);
                let _ = b.send(2, 7);
                let _ = b.outcome(7);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let value = b.recv().await;
                let _ = b.outcome(value);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                // Read served from local state before anti-entropy arrives.
                let _ = b.outcome(0);
            })
        }),
    ];
    (builders, convergence_oracle())
}

/// mini-2pc: blocking two-phase commit with a crashed coordinator.
///
/// The coordinator (task 0) sends PREPARE to both participants, collects both
/// votes, then crashes after sending COMMIT to participant A only. Participant
/// B stays prepared and never commits, so the two participants end in
/// different transaction states. The convergence oracle detects the
/// committed/uncommitted split.
pub fn mini_2pc() -> (Vec<TaskBuilder>, impl Fn(&Journal) -> bool) {
    let builders: Vec<TaskBuilder> = vec![
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.send(1, 10); // PREPARE to participant A
                let _ = b.send(2, 10); // PREPARE to participant B
                let _ = b.recv().await; // vote from A
                let _ = b.recv().await; // vote from B
                let _ = b.send(1, 20); // COMMIT to A; crash before B
                let _ = b.outcome(20);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.recv().await; // PREPARE
                let _ = b.send(0, 1); // vote YES
                let decision = b.recv().await; // COMMIT
                let _ = b.outcome(decision);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.recv().await; // PREPARE
                let _ = b.send(0, 1); // vote YES
                b.sleep(Duration::from_micros(2)).await; // blocked on decision
                let _ = b.outcome(10); // prepared, never committed
            })
        }),
    ];
    (builders, convergence_oracle())
}

/// mini-leader-stepdown: stale reads served after a leadership change
/// (Raft election-restriction class).
///
/// Old leader (task 0) replicates value 1 to the follower, then steps down.
/// New leader (task 2) replicates value 2 to the follower and commits it. The
/// old leader keeps serving requests from its old term: it answers the
/// client's (task 3) read with stale value 1 while the current leader
/// committed 2. The convergence oracle detects the stale read.
pub fn mini_leader_stepdown() -> (Vec<TaskBuilder>, impl Fn(&Journal) -> bool) {
    let builders: Vec<TaskBuilder> = vec![
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.send(1, 1); // replicate value 1 before stepdown
                let _ = b.recv().await; // read request from client
                let _ = b.send(3, 1); // serve stale value 1 from old term
                let _ = b.outcome(1);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.recv().await; // value 1 from old leader
                let second = b.recv().await; // value 2 from new leader
                let _ = b.outcome(second);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.send(1, 2); // replicate value 2 after election
                let _ = b.outcome(2);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.send(0, 99); // read request
                let value = b.recv().await; // response from old leader
                let _ = b.outcome(value);
            })
        }),
    ];
    (builders, convergence_oracle())
}

/// mini-membership-churn: commit index stalls for a departed member.
///
/// Leader (task 0) replicates value 1 to followers 1 and 2. Follower 2 churns
/// out of the membership and never acks. The leader refuses to advance its
/// commit index until every member of its stale membership list acks, so the
/// entry stays uncommitted even though the live follower 1 acknowledged it.
/// The commit oracle detects that the leader failed to commit an acknowledged
/// entry.
pub fn mini_membership_churn() -> (Vec<TaskBuilder>, impl Fn(&Journal) -> bool) {
    let builders: Vec<TaskBuilder> = vec![
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.send(1, 1); // replicate to live follower
                let _ = b.send(2, 1); // replicate to departing follower
                let _ = b.recv().await; // ack from follower 1
                b.sleep(Duration::from_micros(2)).await; // wait for departed ack
                let _ = b.outcome(0); // commit index never advanced
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.recv().await; // replicate
                let _ = b.send(0, 1); // ack
                let _ = b.outcome(1); // holds the data
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.outcome(0); // departed, stale last committed
            })
        }),
    ];
    (builders, live_quorum_commit_oracle())
}

/// mini-hdfs-lease-expiry: an expired lease holder keeps writing after the
/// lease moved to a new writer (HDFS lease-recovery class).
///
/// The NameNode (task 0) grants the lease to old writer (task 1) and then to
/// new writer (task 2). The old writer's lease expires but its late write
/// still lands on the storage (task 3) after the new writer's write, so the
/// storage ends with the stale overwrite instead of the current holder's
/// value. The lease oracle detects that storage diverged from the current
/// lease holder's write.
pub fn mini_hdfs_lease_expiry() -> (Vec<TaskBuilder>, impl Fn(&Journal) -> bool) {
    let builders: Vec<TaskBuilder> = vec![
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.send(1, 1); // grant lease to old writer
                let _ = b.send(2, 2); // grant lease to new writer
                let _ = b.outcome(2);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.recv().await; // lease grant
                b.sleep(Duration::from_micros(2)).await; // lease expires
                let _ = b.send(3, 111); // late write after expiry
                let _ = b.outcome(111);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.recv().await; // lease grant
                let _ = b.send(3, 2); // write under current lease
                let _ = b.outcome(2);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _first = b.recv().await; // new writer's write
                let second = b.recv().await; // expired writer's late write
                let _ = b.outcome(second);
            })
        }),
    ];
    (builders, current_lease_holder_write_oracle())
}
