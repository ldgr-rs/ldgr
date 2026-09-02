use super::oracles::{
    convergence_oracle, current_lease_holder_write_oracle, distinct_outcomes_oracle,
    last_write_wins_oracle, live_quorum_commit_oracle, single_leader_per_term_oracle,
};
use super::task;
use ledger_journal::Journal;
use ledger_sim::{Boundary, Effects, TaskBuilder};
use std::time::Duration;

/// Journal one outcome; a failed append is recorded on the boundary so the
/// run's `journal_error` slot surfaces it instead of dropping it.
///
/// `send` and `send_timed` return `bool` with journal failures already
/// recorded inside `Boundary`, so their discards lose nothing; `recv` returns
/// the payload only.
fn outcome(b: &Boundary, value: u64) {
    if let Err(error) = b.outcome(value) {
        b.record_journal_error(error);
    }
}

/// Toggle a partition fault; a failed append is recorded on the boundary.
fn record_partition(b: &Boundary, src: usize, dst: usize) {
    if let Err(error) = b.apply_partition(src, dst) {
        b.record_journal_error(error);
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
                outcome(&b, 2);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _first = b.recv().await;
                let second = b.recv().await;
                outcome(&b, second);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let first = b.recv().await;
                outcome(&b, first);
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
                outcome(&b, version);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.send(0, 1);
                let granted = b.recv().await;
                outcome(&b, granted);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                b.sleep(Duration::from_micros(1)).await;
                let _ = b.send(0, 2);
                let granted = b.recv().await;
                outcome(&b, granted);
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
                outcome(&b, 7);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let value = b.recv().await;
                outcome(&b, value);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                // Read served from local state before anti-entropy arrives.
                outcome(&b, 0);
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
                outcome(&b, 20);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.recv().await; // PREPARE
                let _ = b.send(0, 1); // vote YES
                let decision = b.recv().await; // COMMIT
                outcome(&b, decision);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.recv().await; // PREPARE
                let _ = b.send(0, 1); // vote YES
                b.sleep(Duration::from_micros(2)).await; // blocked on decision
                outcome(&b, 10); // prepared, never committed
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
                outcome(&b, 1);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.recv().await; // value 1 from old leader
                let second = b.recv().await; // value 2 from new leader
                outcome(&b, second);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.send(1, 2); // replicate value 2 after election
                outcome(&b, 2);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.send(0, 99); // read request
                let value = b.recv().await; // response from old leader
                outcome(&b, value);
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
                outcome(&b, 0); // commit index never advanced
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.recv().await; // replicate
                let _ = b.send(0, 1); // ack
                outcome(&b, 1); // holds the data
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                outcome(&b, 0); // departed, stale last committed
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
                outcome(&b, 2);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.recv().await; // lease grant
                b.sleep(Duration::from_micros(2)).await; // lease expires
                let _ = b.send(3, 111); // late write after expiry
                outcome(&b, 111);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.recv().await; // lease grant
                let _ = b.send(3, 2); // write under current lease
                outcome(&b, 2);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _first = b.recv().await; // new writer's write
                let second = b.recv().await; // expired writer's late write
                outcome(&b, second);
            })
        }),
    ];
    (builders, current_lease_holder_write_oracle())
}
/// mini-reorder-lost-update: message-reorder lost update.
///
/// Writer A (task 1) sends sequence 1 with a 2-tick delay; writer B (task 2)
/// sends sequence 2 with a 1-tick delay. Both sends happen at virtual time 0,
/// so sequence 2 always overtakes sequence 1 in flight. The store (task 0)
/// applies writes in arrival order without checking sequence numbers, so the
/// older write lands last and the newer update is lost. The
/// last-write-wins oracle detects that the store's final value is below the
/// highest sequence it applied.
pub fn mini_reorder_lost_update() -> (Vec<TaskBuilder>, impl Fn(&Journal) -> bool) {
    let builders: Vec<TaskBuilder> = vec![
        Box::new(|b: Boundary| {
            task(async move {
                let first = b.recv().await; // sequence 2 arrives first
                outcome(&b, first); // applied blindly
                let second = b.recv().await; // sequence 1 arrives last
                outcome(&b, second); // bug: applied without a sequence check
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.send_timed(0, 1, 2);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.send_timed(0, 2, 1);
            })
        }),
    ];
    (builders, last_write_wins_oracle(0))
}

/// mini-lease-timer-race: a renewal that lost the race with the expiry timer
/// re-activates an expired lease (lease-manager class).
///
/// The manager (task 0) grants the epoch-1 lease to the old holder (task 1),
/// then its expiry timer fires at tick 2 and it grants the same epoch to the
/// new holder (task 2). The old holder's renewal, sent at tick 3, arrives
/// after the lease expired and moved, but the manager checks only for a
/// pending renewal message, not the lease clock, so it honors the late
/// renewal and re-activates the old holder's lease. Both holders record
/// `epoch * 10 + holder` outcomes, so epoch 1 has two distinct holders. The
/// one-owner-per-epoch oracle (the same encoding mini-raft uses for
/// leader-per-term) detects the double grant.
///
/// Distinct from mini-hdfs-lease-expiry: there the bug sits in the expired
/// writer (its late write overwrites storage); here the bug sits in the
/// manager (it re-grants an expired epoch on a late renewal).
#[allow(clippy::identity_op)] // planted-bug arithmetic stays visibly simple
pub fn mini_lease_timer_race() -> (Vec<TaskBuilder>, impl Fn(&Journal) -> bool) {
    let builders: Vec<TaskBuilder> = vec![
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.send(1, 1); // grant epoch-1 lease to the old holder
                b.sleep(Duration::from_micros(2)).await; // expiry timer fires
                let _ = b.send(2, 1); // re-grant epoch 1 to the new holder
                let _ = b.recv().await; // late renewal from the old holder
                // bug: renewal honored without checking the lease clock
                let _ = b.send(1, 1); // re-activate the old holder's lease
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.recv().await; // lease grant
                b.sleep(Duration::from_micros(3)).await; // renewal crosses expiry
                let _ = b.send(0, 1); // renewal
                let _ = b.recv().await; // manager honored it (the bug)
                outcome(&b, 1 * 10 + 1); // holds epoch 1 as holder 1
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.recv().await; // grant after expiry
                outcome(&b, 1 * 10 + 2); // holds epoch 1 as holder 2
            })
        }),
    ];
    (builders, single_leader_per_term_oracle())
}

/// mini-restart-dup-append: crash-restart duplicate append
/// (crash-consistency class).
///
/// The appender (task 1) appends the client's record to the durable log
/// (task 2), then acks the client (task 0) before its dedup state is
/// durable. It crashes and restarts, replays its write-ahead log, and
/// re-appends the same record without deduplicating, so the durable log
/// carries the record twice. The distinctness oracle over the log's applied
/// records detects the duplicate append.
pub fn mini_restart_dup_append() -> (Vec<TaskBuilder>, impl Fn(&Journal) -> bool) {
    let builders: Vec<TaskBuilder> = vec![
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.send(1, 500); // append record 500
                let _ = b.recv().await; // ack arrives before the restart
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let record = b.recv().await;
                let _ = b.send(2, record); // WAL append
                let _ = b.recv().await; // log ack
                let _ = b.send(0, 1); // bug: ack before dedup state is durable
                // crash + restart: WAL replay without dedup
                let _ = b.send(2, record); // duplicate durable append
                let _ = b.recv().await;
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let first = b.recv().await;
                outcome(&b, first); // durable append
                let _ = b.send(1, 1);
                let second = b.recv().await;
                outcome(&b, second); // duplicate: same record again
                let _ = b.send(1, 1);
            })
        }),
    ];
    (builders, distinct_outcomes_oracle())
}

/// mini-partition-retry-dup: partition plus retry duplicate delivery
/// (exactly-once class).
///
/// The client (task 0) sends request 77, then a partition window opens on
/// the server-to-client link so the ack is refused. The client's retry timer
/// fires, it heals the link and retries the request. The server (task 1)
/// applies every received request without request dedup, so the retry
/// applies the same request twice. The distinctness oracle over the server's
/// applied request ids detects the double apply.
pub fn mini_partition_retry_dup() -> (Vec<TaskBuilder>, impl Fn(&Journal) -> bool) {
    let builders: Vec<TaskBuilder> = vec![
        Box::new(|b: Boundary| {
            task(async move {
                let _ = b.send(1, 77); // request
                record_partition(&b, 1, 0); // ack path breaks
                b.sleep(Duration::from_micros(2)).await; // retry timeout
                record_partition(&b, 1, 0); // heal before the retry
                let _ = b.send(1, 77); // retry (at-least-once)
                let _ = b.recv().await; // ack
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let request = b.recv().await;
                outcome(&b, request); // apply
                let _ = b.send(0, 1); // ack: refused by the partition window
                let retry = b.recv().await;
                outcome(&b, retry); // bug: no request dedup, applied twice
                let _ = b.send(0, 1);
            })
        }),
    ];
    (builders, distinct_outcomes_oracle())
}

/// mini-raft: election-restriction double leader.
///
/// 3 actors: leader(0) and followers(1,2). Leader 0 replicates with
///   `AppendEntries` `Send { payload = term * log_index }` and followers reply
///   with `payload = term`. After stepdown, both old leader 0 (stale log
///   index 1) and new candidate 2 (fresh index 2) request votes from follower
///   1 in term 2. The follower's planted bug grants the vote to both without
///   checking log freshness. When the follower's replies reorder with the
///   fixed timed delays, both candidates gather a quorum and claim leadership
///   in the same term. The single-leader-per-term oracle detects the two
///   distinct leaders for term 2.
#[allow(clippy::identity_op)] // planted-bug arithmetic stays visibly simple
pub fn mini_raft() -> (Vec<TaskBuilder>, impl Fn(&Journal) -> bool) {
    let builders: Vec<TaskBuilder> = vec![
        Box::new(|b: Boundary| {
            task(async move {
                let term = 1u64;
                let log_index = 1u64;
                let payload = term * log_index;
                let _ = b.send(1, payload);
                let _ = b.send(2, payload);
                b.sleep(Duration::from_micros(1)).await;
                let _ = b.recv().await;
                let _ = b.recv().await;
                let term2 = 2u64;
                let stale_payload = term2 * 1;
                let _ = b.send_timed(1, stale_payload, 1);
                let vote = b.recv().await;
                if vote == term2 {
                    outcome(&b, term2 * 10 + 0);
                } else {
                    outcome(&b, term * 10 + 0);
                }
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let first = b.recv().await;
                let _ = b.send(0, 1);
                let req_a = b.recv().await;
                let req_b = b.recv().await;
                let term2 = 2u64;
                let _ = b.send(0, term2);
                let _ = b.send(2, term2);
                outcome(&b, 1 * 10 + 1);
                let _ = (req_a, req_b, first);
            })
        }),
        Box::new(|b: Boundary| {
            task(async move {
                let first = b.recv().await;
                let _ = b.send(0, 1);
                b.sleep(Duration::from_micros(1)).await;
                let term2 = 2u64;
                let fresh_payload = term2 * 2;
                let _ = b.send_timed(1, fresh_payload, 1);
                let vote = b.recv().await;
                if vote == term2 {
                    outcome(&b, term2 * 10 + 2);
                } else {
                    outcome(&b, 1 * 10 + 2);
                }
                let _ = first;
            })
        }),
    ];
    (builders, single_leader_per_term_oracle())
}

// ---------------------------------------------------------------------------
// Explicit support models for the corpus fixtures
//
// Each model names the entry roles that jointly support the planted
// violation, using the semantic role described in the fixture doc comment.
// A model whose mechanism is a pure timing interaction with no clean entry
// set is declared Opaque: unknown semantics produce heuristic output only.
// ---------------------------------------------------------------------------

/// mini-zab: the leader's two proposals are jointly required for the split.
pub fn mini_zab_support(journal: &Journal) -> crate::support::SupportExpr {
    crate::support::all_of_ids(crate::support::entry_ids_by(
        journal,
        ledger_format::EntryKind::Send,
        0,
    ))
}

/// mini-hdfs: the NameNode's two grants are jointly required.
pub fn mini_hdfs_support(journal: &Journal) -> crate::support::SupportExpr {
    crate::support::all_of_ids(crate::support::entry_ids_by(
        journal,
        ledger_format::EntryKind::Send,
        0,
    ))
}

/// mini-cassandra: the primary's gossip send plus the stale reader's recv
/// jointly support the anti-entropy staleness.
pub fn mini_cassandra_support(journal: &Journal) -> crate::support::SupportExpr {
    let mut ids = crate::support::entry_ids_by(journal, ledger_format::EntryKind::Send, 0);
    ids.extend(crate::support::entry_ids_by(
        journal,
        ledger_format::EntryKind::Recv,
        2,
    ));
    crate::support::all_of_ids(ids)
}

/// mini-2pc: the coordinator's PREPARE and COMMIT sends are jointly required
/// for the crash-after-commit violation.
pub fn mini_2pc_support(journal: &Journal) -> crate::support::SupportExpr {
    crate::support::all_of_ids(crate::support::entry_ids_by(
        journal,
        ledger_format::EntryKind::Send,
        0,
    ))
}

/// mini-leader-stepdown: both leaders' replication streams jointly support
/// the stale read after the leadership change.
pub fn mini_leader_stepdown_support(journal: &Journal) -> crate::support::SupportExpr {
    let mut ids = crate::support::entry_ids_by(journal, ledger_format::EntryKind::Send, 0);
    ids.extend(crate::support::entry_ids_by(
        journal,
        ledger_format::EntryKind::Send,
        2,
    ));
    crate::support::all_of_ids(ids)
}

/// mini-membership-churn: the leader's replication sends are jointly
/// required for the commit-index stall.
pub fn mini_membership_churn_support(journal: &Journal) -> crate::support::SupportExpr {
    crate::support::all_of_ids(crate::support::entry_ids_by(
        journal,
        ledger_format::EntryKind::Send,
        0,
    ))
}

/// mini-hdfs-lease-expiry: the NameNode grant and the stale writer's sends
/// jointly support the post-expiry write.
pub fn mini_hdfs_lease_expiry_support(journal: &Journal) -> crate::support::SupportExpr {
    let mut ids = crate::support::entry_ids_by(journal, ledger_format::EntryKind::Send, 0);
    ids.extend(crate::support::entry_ids_by(
        journal,
        ledger_format::EntryKind::Send,
        1,
    ));
    crate::support::all_of_ids(ids)
}

/// mini-reorder-lost-update: both writers' sends are jointly required for
/// the reordered lost update.
pub fn mini_reorder_lost_update_support(journal: &Journal) -> crate::support::SupportExpr {
    let mut ids = crate::support::entry_ids_by(journal, ledger_format::EntryKind::Send, 1);
    ids.extend(crate::support::entry_ids_by(
        journal,
        ledger_format::EntryKind::Send,
        2,
    ));
    crate::support::all_of_ids(ids)
}

/// mini-lease-timer-race: a pure timing interaction; no clean entry set.
pub fn mini_lease_timer_race_support(_journal: &Journal) -> crate::support::SupportExpr {
    crate::support::SupportExpr::Opaque
}

/// mini-restart-dup-append: the appender's sends to the durable log are
/// jointly required for the duplicate append.
pub fn mini_restart_dup_append_support(journal: &Journal) -> crate::support::SupportExpr {
    crate::support::all_of_ids(crate::support::entry_ids_by(
        journal,
        ledger_format::EntryKind::Send,
        1,
    ))
}

/// mini-partition-retry-dup: the client's request sends are jointly required
/// for the duplicate delivery under the partition.
pub fn mini_partition_retry_dup_support(journal: &Journal) -> crate::support::SupportExpr {
    crate::support::all_of_ids(crate::support::entry_ids_by(
        journal,
        ledger_format::EntryKind::Send,
        0,
    ))
}

/// mini-kv-stale-read: schedule-dependent stale read with no clean entry
/// set in the shared Mini-Kv workload; declared Opaque.
pub fn mini_kv_stale_read_support(_journal: &Journal) -> crate::support::SupportExpr {
    crate::support::SupportExpr::Opaque
}
