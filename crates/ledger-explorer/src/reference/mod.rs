//! Reference-runtime dogfood suite: real async protocols on the effect
//! boundary.
//!
//! Each mini protocol plants one distributed bug; see `sims.rs` for the
//! per-protocol rationale and oracle.
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
