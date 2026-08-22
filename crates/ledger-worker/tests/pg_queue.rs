// ledger-lint:allow - host integration test drives a real Postgres over TCP
#![cfg(feature = "pg")]
//! Postgres/River queue integration tests against a real database.
//!
//! Each test runs in its own uniquely-named database (created and dropped
//! here, so the DSN user needs CREATEDB) and applies [`RIVER_SCHEMA_SQL`],
//! so a plain Postgres instance is enough and parallel test processes
//! cannot interfere. The DSN comes from `LEDGER_TEST_PG_DSN`; a missing
//! variable is a hard failure because these paths cannot be covered by a
//! unit test.

use std::collections::HashSet;
use std::time::Duration;

use ledger_sim::RunConfig;
use ledger_worker::RIVER_SCHEMA_SQL;
use ledger_worker::{PostgresQueue, Task, TaskStatus};

fn test_dsn() -> String {
    match std::env::var("LEDGER_TEST_PG_DSN") {
        Ok(dsn) if !dsn.trim().is_empty() => dsn,
        _ => {
            panic!(
                "LEDGER_TEST_PG_DSN is not set. This suite needs a real Postgres \
                 (any empty database; the tests create and drop their own databases, \
                 so the DSN user needs CREATEDB). Start one with: docker run --rm -d \
                 --name ldgr-pg-test -e POSTGRES_PASSWORD=postgres -p 5432:5432 \
                 postgres:17, then export \
                 LEDGER_TEST_PG_DSN=postgres://postgres:postgres@localhost:5432/postgres \
                 and re-run. The suite never skips."
            );
        }
    }
}

/// Re-point the base DSN at database `db`, preserving any query string.
fn database_dsn(db: &str) -> String {
    let base = test_dsn();
    let (front, query) = match base.split_once('?') {
        Some((f, q)) => (f, Some(q)),
        None => (base.as_str(), None),
    };
    let front = match front.rsplit_once('/') {
        Some((prefix, _old_db)) => format!("{prefix}/{db}"),
        None => format!("{front}/{db}"),
    };
    match query {
        Some(q) => format!("{front}?{q}"),
        None => front,
    }
}

async fn client_on(dsn: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(dsn, tokio_postgres::NoTls)
        .await
        .expect("connect postgres");
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            eprintln!("pg_queue: connection ended: {err}");
        }
    });
    client
}

/// Create a fresh database named after this process and `suffix`, apply the
/// River schema subset, and return its DSN.
///
/// nextest runs test binaries in parallel processes against the same
/// server, so a shared `river.job` table would let one test's reset drop
/// another test's claims. The name is built from process id and a fixed
/// suffix, so it is always a plain identifier and interpolation is safe.
async fn fresh_database(suffix: &str) -> String {
    let admin = client_on(&test_dsn()).await;
    let db = format!("ldgr_wk_test_{}_{}", std::process::id(), suffix);
    admin
        .batch_execute(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)"))
        .await
        .expect("drop stale test database");
    admin
        .batch_execute(&format!("CREATE DATABASE {db}"))
        .await
        .expect("create test database");
    let dsn = database_dsn(&db);
    let client = client_on(&dsn).await;
    client
        .batch_execute(RIVER_SCHEMA_SQL)
        .await
        .expect("apply RIVER_SCHEMA_SQL");
    dsn
}

fn campaign_task(id: &str, max_attempts: u32) -> Task {
    let mut task = Task::new(
        id,
        RunConfig::builder().seed([0x11; 32]).max_steps(128).build(),
        "kv",
    );
    task.max_attempts = max_attempts;
    task
}

async fn connect_worker(dsn: &str, worker_id: &str, lease_timeout: Duration) -> PostgresQueue {
    PostgresQueue::connect(dsn, worker_id, lease_timeout)
        .await
        .expect("connect worker queue")
}

/// One worker drains until the queue reads empty; returns its claims.
async fn drain_all(dsn: &str, worker_id: &str) -> Vec<Task> {
    let mut queue = connect_worker(dsn, worker_id, Duration::from_secs(30)).await;
    let mut claimed = Vec::new();
    while let Some(task) = queue.pull_async().await.expect("pull_async must not fail") {
        claimed.push(task);
    }
    claimed
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_workers_claim_disjoint_sets_and_ack_completes() {
    let dsn = fresh_database("concurrent").await;
    let setup = connect_worker(&dsn, "setup", Duration::from_secs(30)).await;
    for id in ["pg-a", "pg-b", "pg-c"] {
        setup
            .enqueue_async(&campaign_task(id, 3))
            .await
            .expect("enqueue");
    }

    // Two workers on separate connections drain concurrently; their claims
    // must partition the three jobs with no overlap.
    let (claims_a, claims_b) =
        tokio::join!(drain_all(&dsn, "worker-a"), drain_all(&dsn, "worker-b"));
    let all: Vec<&Task> = claims_a.iter().chain(claims_b.iter()).collect();
    assert_eq!(all.len(), 3, "every enqueued job must be claimed");
    let ids: HashSet<&str> = all.iter().map(|t| t.id.as_str()).collect();
    assert_eq!(
        ids,
        HashSet::from(["pg-a", "pg-b", "pg-c"]),
        "claims must cover all jobs exactly once"
    );
    for task in &all {
        assert_eq!(task.attempts, 1, "claim charges one attempt");
        assert_eq!(task.status, TaskStatus::Leased);
        assert_eq!(
            task.workload, "kv",
            "args jsonb must round-trip the workload"
        );
        assert!(
            task.run_config_hash.is_some(),
            "claim derives the boundary hash"
        );
    }

    // Each running row is stamped with exactly one claiming worker.
    let admin = client_on(&dsn).await;
    let rows = admin
        .query(
            "SELECT args->>'task_id' AS tid, attempted_by FROM river.job",
            &[],
        )
        .await
        .expect("select claims");
    let workers = HashSet::from(["worker-a", "worker-b"]);
    for row in &rows {
        let attempted_by: Vec<String> = row.get("attempted_by");
        assert_eq!(
            attempted_by.len(),
            1,
            "row {:?} must carry exactly one worker",
            row.try_get::<_, String>("tid")
        );
        assert!(
            workers.contains(attempted_by[0].as_str()),
            "unknown claimer {attempted_by:?}"
        );
    }

    // Ack finalizes exactly the acked job; unknown or finished ids report
    // false instead of mutating rows.
    let mut acker = connect_worker(&dsn, "acker", Duration::from_secs(30)).await;
    assert!(acker.ack_async("pg-a").await.expect("ack"));
    let row = admin
        .query_one(
            "SELECT state::text AS state, finalized_at IS NOT NULL AS finalized FROM river.job \
             WHERE args->>'task_id' = 'pg-a'",
            &[],
        )
        .await
        .expect("acked row");
    assert_eq!(row.get::<_, String>("state"), "completed");
    assert!(row.get::<_, bool>("finalized"), "ack sets finalized_at");
    assert!(!acker.ack_async("pg-a").await.expect("re-ack"));
    assert!(!acker.ack_async("ghost").await.expect("ghost ack"));
}

#[tokio::test]
async fn fail_discards_once_attempt_budget_exhausted() {
    let dsn = fresh_database("discard").await;
    let admin = client_on(&dsn).await;
    let mut queue = connect_worker(&dsn, "fail-once", Duration::from_secs(30)).await;
    queue
        .enqueue_async(&campaign_task("pg-doomed", 1))
        .await
        .expect("enqueue");

    let task = queue
        .pull_async()
        .await
        .expect("pull")
        .expect("claimed task");
    assert_eq!(task.attempts, 1);
    assert!(queue.fail_async("pg-doomed", "boom").await.expect("fail"));
    let row = admin
        .query_one(
            "SELECT state::text AS state, finalized_at IS NOT NULL AS finalized, errors FROM river.job \
             WHERE args->>'task_id' = 'pg-doomed'",
            &[],
        )
        .await
        .expect("failed row");
    assert_eq!(row.get::<_, String>("state"), "discarded");
    assert!(row.get::<_, bool>("finalized"), "discard sets finalized_at");
    let errors: Vec<serde_json::Value> = row.get("errors");
    assert_eq!(errors.len(), 1, "reason recorded once, got {errors:?}");
    assert_eq!(errors[0]["error"], "boom");
    assert_eq!(errors[0]["attempt"], 1);

    // A discarded job never re-enters the queue.
    assert!(
        queue
            .pull_async()
            .await
            .expect("pull after discard")
            .is_none(),
        "discarded job must not be claimable"
    );
    // No running row remains, so a second fail is a no-op.
    assert!(
        !queue
            .fail_async("pg-doomed", "again")
            .await
            .expect("re-fail")
    );
}

#[tokio::test]
async fn fail_retries_within_budget_then_discards_on_next_attempt() {
    let dsn = fresh_database("retry").await;
    let admin = client_on(&dsn).await;
    // Near-zero lease timeout makes the retry backoff instantaneous.
    let mut queue = connect_worker(&dsn, "retry", Duration::from_millis(1)).await;
    queue
        .enqueue_async(&campaign_task("pg-flaky", 2))
        .await
        .expect("enqueue");

    let first = queue
        .pull_async()
        .await
        .expect("pull")
        .expect("first claim");
    assert_eq!(first.attempts, 1);
    assert!(
        queue
            .fail_async("pg-flaky", "transient")
            .await
            .expect("first fail")
    );
    let row = admin
        .query_one(
            "SELECT state::text AS state, finalized_at IS NOT NULL AS finalized FROM river.job \
             WHERE args->>'task_id' = 'pg-flaky'",
            &[],
        )
        .await
        .expect("retried row");
    assert_eq!(row.get::<_, String>("state"), "available");
    assert!(!row.get::<_, bool>("finalized"), "retry does not finalize");

    // The retried job is claimable again and carries its charged attempt.
    // Poll with a bounded deadline instead of a fixed sleep: the retry
    // schedule is a database timestamp, not a foreground timer.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let second = loop {
        match queue.pull_async().await.expect("pull after retry") {
            Some(task) if task.id == "pg-flaky" => break task,
            Some(other) => panic!("unexpected claim while polling the retry: {}", other.id),
            None => {
                if std::time::Instant::now() >= deadline {
                    panic!(
                        "pg-flaky: retried job not claimable within 10s; \
                         check the fail_async backoff schedule"
                    );
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    };
    assert_eq!(second.attempts, 2, "attempt budget travels with the job");

    // Second failure exhausts the budget of two.
    assert!(
        queue
            .fail_async("pg-flaky", "still broken")
            .await
            .expect("second fail")
    );
    let row = admin
        .query_one(
            "SELECT state::text AS state FROM river.job WHERE args->>'task_id' = 'pg-flaky'",
            &[],
        )
        .await
        .expect("final row");
    assert_eq!(row.get::<_, String>("state"), "discarded");
    assert!(
        queue
            .pull_async()
            .await
            .expect("pull after exhaust")
            .is_none(),
        "exhausted job must not be claimable"
    );
}

#[tokio::test]
async fn extend_lease_refreshes_attempted_by_and_requires_running_job() {
    let dsn = fresh_database("extend").await;
    let admin = client_on(&dsn).await;
    let mut claimer = connect_worker(&dsn, "claimer", Duration::from_secs(30)).await;
    claimer
        .enqueue_async(&campaign_task("pg-hb", 3))
        .await
        .expect("enqueue");
    let task = claimer.pull_async().await.expect("pull").expect("claim");
    assert_eq!(task.id, "pg-hb");

    // The heartbeat may come from a fresh handle (as after a restart); it
    // must re-stamp attempted_by with the heartbeating worker.
    let mut extender = connect_worker(&dsn, "extender", Duration::from_secs(30)).await;
    assert!(
        extender.extend_lease_async("pg-hb").await.expect("extend"),
        "running job must be extendable"
    );
    let row = admin
        .query_one(
            "SELECT attempted_by FROM river.job WHERE args->>'task_id' = 'pg-hb'",
            &[],
        )
        .await
        .expect("heartbeat row");
    let attempted_by: Vec<String> = row.get("attempted_by");
    assert_eq!(attempted_by, vec!["extender".to_string()]);
    assert!(
        !extender
            .extend_lease_async("ghost")
            .await
            .expect("ghost extend"),
        "unknown task must not extend"
    );

    // After ack the job is no longer running, so heartbeats report false.
    assert!(claimer.ack_async("pg-hb").await.expect("ack"));
    assert!(
        !extender
            .extend_lease_async("pg-hb")
            .await
            .expect("post-ack extend"),
        "acked job must not extend"
    );
}
