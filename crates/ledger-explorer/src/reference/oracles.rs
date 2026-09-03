use super::{outcome_by_actor, outcome_values};
use ledger_journal::Journal;
use std::collections::{HashMap, HashSet};

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

/// Commit oracle: the leader must commit the entry that the remaining live
/// follower acknowledged. A stalled commit index violates it.
pub fn live_quorum_commit_oracle() -> impl Fn(&Journal) -> bool {
    |journal: &Journal| {
        let leader = outcome_by_actor(journal, ledger_format::ActorId(0));
        let live_follower = outcome_by_actor(journal, ledger_format::ActorId(1));
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
        let storage = outcome_by_actor(journal, ledger_format::ActorId(3));
        let current_holder = outcome_by_actor(journal, ledger_format::ActorId(2));
        match (storage.last(), current_holder.last()) {
            (Some(applied), Some(written)) => applied == written,
            _ => false,
        }
    }
}

/// Last-write-wins oracle: the actor's applied writes must end on the
/// highest sequence number it applied.
///
/// Each applied write journals its sequence number as an `Outcome`. A final
/// value below the applied maximum means a newer write was overwritten by an
/// older one: a lost update. An actor with no applied writes holds.
pub fn last_write_wins_oracle(actor: ledger_format::ActorId) -> impl Fn(&Journal) -> bool {
    move |journal: &Journal| {
        let applied = outcome_by_actor(journal, actor);
        applied.last().copied() == applied.iter().copied().max()
    }
}

/// Oracle that enforces one leader per term.
///
/// Each `Outcome` value encodes `term * 10 + leader_id`. A term with two
/// distinct leaders indicates the planted double-leader bug fired.
pub fn single_leader_per_term_oracle() -> impl Fn(&Journal) -> bool {
    |journal: &Journal| {
        let outcomes = outcome_values(journal);
        let mut by_term: HashMap<u64, HashSet<u64>> = HashMap::new();
        for value in outcomes {
            let term = value / 10;
            let leader = value % 10;
            by_term.entry(term).or_default().insert(leader);
        }
        by_term.values().all(|leaders| leaders.len() <= 1)
    }
}
