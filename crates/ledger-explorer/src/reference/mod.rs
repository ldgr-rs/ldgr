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
//! - mini-reorder-lost-update: message-reorder class - two sequenced writes
//!   reorder in flight and the store applies in arrival order without
//!   sequence checks, so the newer write is lost.
//! - mini-lease-timer-race: lease-timer class - a renewal that lost the race
//!   with the expiry timer re-activates an expired, reassigned lease, so one
//!   epoch briefly has two active holders.
//! - mini-restart-dup-append: crash-consistency class - an appender acks
//!   before its dedup state is durable, then replays its WAL after a
//!   crash-restart without dedup, so the durable log carries the record
//!   twice.
//! - mini-partition-retry-dup: exactly-once class - a retry across a
//!   partition window reaches a server with no request dedup, so one client
//!   request applies twice.
//!
//! Each sim returns task builders for `Simulation::with_tasks` plus a
//! deterministic oracle over the journal's `Outcome` entries.
//!
//! [`corpus_scenarios`] is the single registry mapping corpus name to
//! runner, oracle, base seed, and fault space; the corpus gates, the manifest
//! generator, and the LDFI efficiency gate all consume it.

mod faultdep;
mod oracles;
mod registry;
mod sims;
#[cfg(test)]
mod tests;

pub use faultdep::{
    FAULTDEP_SUPPORT_VERSION, FaultDepScenario, faultdep_scenario, faultdep_scenarios,
};
pub use oracles::{
    convergence_oracle, current_lease_holder_write_oracle, distinct_outcomes_oracle,
    last_write_wins_oracle, live_quorum_commit_oracle, single_leader_per_term_oracle,
};
pub use registry::{
    CorpusRunner, CorpusScenario, ReferenceReplayError, ScenarioClass, corpus_scenario,
    corpus_scenarios, scenario_class,
};
pub use sims::{
    mini_2pc, mini_cassandra, mini_hdfs, mini_hdfs_lease_expiry, mini_leader_stepdown,
    mini_lease_timer_race, mini_membership_churn, mini_partition_retry_dup, mini_raft,
    mini_reorder_lost_update, mini_restart_dup_append, mini_zab,
};

use ledger_journal::Journal;
use std::future::Future;
use std::pin::Pin;

/// Box a task body into the executor's cooperative future shape.
fn task(body: impl Future<Output = ()> + 'static) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(body)
}

fn outcome_values(journal: &Journal) -> Vec<u64> {
    journal
        .entries()
        .filter_map(|entry| match &entry.data.payload {
            ledger_format::EntryPayload::Outcome(ledger_format::OutcomePayload {
                value: ledger_format::CanonicalValue::Unsigned(value),
                ..
            }) if entry.data.kind == ledger_format::EntryKind::Outcome => Some(*value),
            _ => None,
        })
        .collect()
}

/// Collect the `Outcome` values journaled by one actor, in journal order.
fn outcome_by_actor(journal: &Journal, actor: ledger_format::ActorId) -> Vec<u64> {
    journal
        .entries()
        .filter_map(|entry| {
            if entry.data.actor == actor && entry.data.kind == ledger_format::EntryKind::Outcome {
                match &entry.data.payload {
                    ledger_format::EntryPayload::Outcome(ledger_format::OutcomePayload {
                        value: ledger_format::CanonicalValue::Unsigned(value),
                        ..
                    }) => Some(*value),
                    _ => None,
                }
            } else {
                None
            }
        })
        .collect()
}
