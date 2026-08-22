/// River-compatible Postgres queue behind the `pg` feature.
///
/// Targets River's documented `river.job` table (riverqueue.com). The
/// authoritative schema migration ships with the Go control plane;
/// [`RIVER_SCHEMA_SQL`] below is the subset this worker needs, so tests and
/// ops can bring up a compatible database without the Go toolchain.
#[cfg(feature = "pg")]
use super::{QueueFileLine, Task, TaskStatus, WorkerTaskSpec};
use std::time::Duration;
use thiserror::Error;

/// Job kind this worker claims; the control plane enqueues the same
/// string when dispatching campaign tasks.
pub const JOB_KIND: &str = "ledger_campaign";

/// River `river.job` subset used by this worker.
///
/// Mirrors River's `002_initial_schema` (+ `004` pending state and
/// `007` max_attempts default). Deviations from River's migration:
/// `updated_at` is carried because our statements maintain it, the
/// notify trigger and leader/queue tables are omitted (this worker
/// polls), and the enum creation is wrapped in a DO block so the
/// statement is idempotent. Apply with `batch_execute`; it holds
/// multiple statements.
pub const RIVER_SCHEMA_SQL: &str = "\
CREATE SCHEMA IF NOT EXISTS river;

DO $$
BEGIN
    CREATE TYPE river.river_job_state AS ENUM (
        'available', 'cancelled', 'completed', 'discarded',
        'pending', 'retryable', 'running', 'scheduled'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END
$$;

CREATE TABLE IF NOT EXISTS river.job (
    id bigserial PRIMARY KEY,
    queue text NOT NULL DEFAULT 'default',
    kind text NOT NULL,
    args jsonb NOT NULL DEFAULT '{}',
    state river.river_job_state NOT NULL DEFAULT 'available',
    priority smallint NOT NULL DEFAULT 1,
    attempt smallint NOT NULL DEFAULT 0,
    max_attempts smallint NOT NULL DEFAULT 25,
    scheduled_at timestamptz NOT NULL DEFAULT now(),
    attempted_at timestamptz,
    attempted_by text[],
    errors jsonb[],
    metadata jsonb NOT NULL DEFAULT '{}',
    finalized_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT river_job_finalized_or_finalized_at_null CHECK (
        (finalized_at IS NULL AND state NOT IN ('cancelled', 'completed', 'discarded'))
        OR (finalized_at IS NOT NULL AND state IN ('cancelled', 'completed', 'discarded'))
    ),
    CONSTRAINT river_job_max_attempts_is_positive CHECK (max_attempts > 0),
    CONSTRAINT river_job_priority_in_range CHECK (priority >= 1 AND priority <= 4),
    CONSTRAINT river_job_queue_length CHECK (char_length(queue) > 0 AND char_length(queue) < 128),
    CONSTRAINT river_job_kind_length CHECK (char_length(kind) > 0 AND char_length(kind) < 128)
);

CREATE INDEX IF NOT EXISTS river_job_prioritized_fetching_index
    ON river.job (state, queue, priority, scheduled_at, id);";

/// Errors from the Postgres queue.
#[derive(Debug, Error)]
pub enum QueueError {
    /// A database statement failed.
    #[error("postgres: {0}")]
    Sql(#[from] tokio_postgres::Error),
    /// Row args did not decode into the queue-file projection.
    #[error("args decode: {0}")]
    Serde(#[from] serde_json::Error),
    /// An enqueued task violated the task contract before insert.
    #[error("invalid task: {0}")]
    InvalidTask(String),
    /// A claimed row's counters or spec violated the task contract.
    #[error("invalid claimed task: {0}")]
    InvalidClaim(#[from] super::TaskSpecError),
    /// A claimed row carried an out-of-range counter.
    #[error("attempt counter {value} out of range: {source}")]
    AttemptOutOfRange {
        /// Raw smallint value stored in the row.
        value: i16,
        #[source]
        source: std::num::TryFromIntError,
    },
    /// A claimed row carried an out-of-range attempt budget.
    #[error("max_attempts {value} out of range: {source}")]
    MaxAttemptsOutOfRange {
        /// Raw smallint value stored in the row.
        value: i16,
        #[source]
        source: std::num::TryFromIntError,
    },
    /// An enqueued task's max_attempts budget exceeded the River smallint range.
    #[error("max_attempts {max_attempts} exceeds the i16 range of river.job: {source}")]
    MaxAttemptsOverflow {
        /// Task budget that overflowed the row column.
        max_attempts: u32,
        #[source]
        source: std::num::TryFromIntError,
    },
}

/// Convert a task budget into the River `smallint` column, rejecting budgets
/// beyond the i16 range with a typed overflow that preserves the conversion
/// error.
fn max_attempts_to_i16(max_attempts: u32) -> Result<i16, QueueError> {
    i16::try_from(max_attempts).map_err(|source| QueueError::MaxAttemptsOverflow {
        max_attempts,
        source,
    })
}

/// Postgres-backed task queue over River's `river.job` table.
///
/// Async-only: the sync [`super::TaskQueue`] seam stays with
/// [`super::InMemoryQueue`]; the daemon's `--pg-dsn` drain loop drives
/// these methods directly. Claims are one atomic
/// `UPDATE ... FOR UPDATE SKIP LOCKED` statement, so concurrent workers
/// on separate connections always claim disjoint rows.
pub struct PostgresQueue {
    client: tokio_postgres::Client,
    worker_id: String,
    lease_timeout: Duration,
}

impl PostgresQueue {
    /// Connect to `dsn` and return a queue handle for `worker_id`.
    ///
    /// The connection driver runs detached on the current tokio
    /// runtime; the handle fails on first use if the connection dies.
    ///
    /// # Errors
    /// Returns the connection error for a bad DSN, unreachable host,
    /// or auth failure.
    pub async fn connect(
        dsn: &str,
        worker_id: &str,
        lease_timeout: Duration,
    ) -> Result<Self, QueueError> {
        let (client, connection) = tokio_postgres::connect(dsn, tokio_postgres::NoTls).await?;
        tokio::spawn(async move {
            if let Err(err) = connection.await {
                eprintln!("ledger-worker: postgres connection ended: {err}");
            }
        });
        Ok(Self {
            client,
            worker_id: worker_id.to_string(),
            lease_timeout,
        })
    }

    /// Claim the next available job and return it as a leased [`Task`].
    ///
    /// One atomic statement flips `state` to `running`, charges the
    /// attempt, and stamps this worker as `attempted_by`. The
    /// `FOR UPDATE SKIP LOCKED` subselect makes concurrent claims
    /// disjoint: a locked head row is skipped, never blocked on or
    /// double-claimed, and the claim predicate only matches
    /// `available` rows.
    ///
    /// # Errors
    /// Returns [`QueueError`] on a database failure or when the claimed
    /// `args` do not decode into a valid task.
    pub async fn pull_async(&mut self) -> Result<Option<Task>, QueueError> {
        let row = self
            .client
            .query_opt(
                "\
UPDATE river.job
SET state = 'running',
    attempted_by = ARRAY[$1]::text[],
    attempt = attempt + 1,
    attempted_at = now(),
    updated_at = now()
WHERE id = (
    SELECT id FROM river.job
    WHERE state = 'available' AND kind = $2 AND scheduled_at <= now()
    ORDER BY scheduled_at, id
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING id, args, attempt, max_attempts",
                &[&self.worker_id, &JOB_KIND],
            )
            .await?;
        let Some(row) = row else { return Ok(None) };
        let args: serde_json::Value = row.try_get("args")?;
        let attempt: i16 = row.try_get("attempt")?;
        let max_attempts: i16 = row.try_get("max_attempts")?;
        let mut task = task_from_args(args)?;
        // smallint -> u32 needs a checked conversion: a corrupted row
        // with negative counters must fail the claim, not wrap around.
        task.attempts = u32::try_from(attempt).map_err(|source| QueueError::AttemptOutOfRange {
            value: attempt,
            source,
        })?;
        task.max_attempts =
            u32::try_from(max_attempts).map_err(|source| QueueError::MaxAttemptsOutOfRange {
                value: max_attempts,
                source,
            })?;
        task.status = TaskStatus::Leased;
        // Same boundary hash contract as InMemoryQueue::push: the hash
        // is derived from the decoded config so execute_task can
        // re-validate it. Dropped only for a config the canonical encoder
        // rejects; execute_task then fails with InvalidConfig.
        task.run_config_hash = crate::proto::run_config_hash(&task.run_config).ok();
        Ok(Some(task))
    }

    /// Acknowledge completion: finalize the job as `completed`.
    ///
    /// Returns false when no `running` job carries the task id, which
    /// mirrors the in-memory ack being a no-op without a live lease.
    ///
    /// # Errors
    /// Returns [`QueueError`] on a database failure.
    pub async fn ack_async(&mut self, task_id: &str) -> Result<bool, QueueError> {
        let rows = self
            .client
            .execute(
                "\
UPDATE river.job
SET state = 'completed', finalized_at = now(), updated_at = now()
WHERE args->>'task_id' = $1 AND state = 'running'",
                &[&task_id],
            )
            .await?;
        Ok(rows > 0)
    }

    /// Charge one failed attempt against a running job.
    ///
    /// Within the attempt budget the job returns to `available` with
    /// `scheduled_at` pushed one lease timeout out (River's rescuer
    /// uses the `retryable` state plus a background promoter; we have
    /// none, so the retry lands directly in `available` behind a
    /// future `scheduled_at`, which both our claim and a real River
    /// client honor). At or past `max_attempts` the job is finalized
    /// as `discarded`. The reason is appended to River's `errors`
    /// array. Returns false when no `running` job carries the task id.
    ///
    /// # Errors
    /// Returns [`QueueError`] on a database failure.
    pub async fn fail_async(&mut self, task_id: &str, reason: &str) -> Result<bool, QueueError> {
        let backoff_secs = self.lease_timeout.as_secs_f64();
        let rows = self
            .client
            .execute(
                "\
UPDATE river.job
SET state = (CASE WHEN attempt >= max_attempts THEN 'discarded' ELSE 'available' END)::river.river_job_state,
    finalized_at = CASE WHEN attempt >= max_attempts THEN now() END,
    scheduled_at = CASE
        WHEN attempt >= max_attempts THEN scheduled_at
        ELSE now() + ($2::float8 * interval '1 second')
    END,
    errors = array_append(
        coalesce(errors, '{}'::jsonb[]),
        jsonb_build_object('error', $3::text, 'at', now(), 'attempt', attempt)
    ),
    updated_at = now()
WHERE args->>'task_id' = $1 AND state = 'running'",
                &[&task_id, &backoff_secs, &reason],
            )
            .await?;
        Ok(rows > 0)
    }

    /// Refresh the lease markers of a running job.
    ///
    /// The heartbeat path calls this before lease expiry; it re-stamps
    /// `attempted_by` with this queue's worker id and `attempted_at`
    /// with the current time. Returns false when the job is not
    /// `running` (already acked, discarded, or reclaimed).
    ///
    /// # Errors
    /// Returns [`QueueError`] on a database failure.
    pub async fn extend_lease_async(&mut self, task_id: &str) -> Result<bool, QueueError> {
        let rows = self
            .client
            .execute(
                "\
UPDATE river.job
SET attempted_by = ARRAY[$1]::text[], attempted_at = now(), updated_at = now()
WHERE args->>'task_id' = $2 AND state = 'running'",
                &[&self.worker_id, &task_id],
            )
            .await?;
        Ok(rows > 0)
    }

    /// Insert a task as an `available` River job (test/ops helper).
    ///
    /// The task travels as the [`QueueFileLine`] serde projection in
    /// River's `args` jsonb, so JSON bytes round-trip a real River
    /// `args` value produced by the control plane.
    ///
    /// # Errors
    /// Returns [`QueueError::InvalidTask`] when the task's policy is
    /// not `random`, [`QueueError::MaxAttemptsOverflow`] when its
    /// max_attempts budget exceeds the River `smallint` range, or
    /// [`QueueError::Sql`] on a database failure.
    pub async fn enqueue_async(&self, task: &Task) -> Result<(), QueueError> {
        let args = task_args(task)?;
        let max_attempts = max_attempts_to_i16(task.max_attempts)?;
        self.client
            .execute(
                "INSERT INTO river.job (kind, args, max_attempts) VALUES ($1, $2, $3)",
                &[&JOB_KIND, &args, &max_attempts],
            )
            .await?;
        Ok(())
    }
}

/// Serialize a task's `args` jsonb via the queue-file projection.
fn task_args(task: &Task) -> Result<serde_json::Value, QueueError> {
    if !matches!(task.run_config.policy(), ledger_sim::Policy::Random) {
        return Err(QueueError::InvalidTask(
            "only the \"random\" policy round-trips through the queue-file projection".to_string(),
        ));
    }
    let line = QueueFileLine {
        task_id: task.id.clone(),
        run_config: WorkerTaskSpec {
            seed_hex: crate::proto::hash_to_hex(&task.run_config.seed()),
            max_steps: task.run_config.max_steps(),
            policy: "random".to_string(),
        },
        workload: task.workload.clone(),
    };
    serde_json::to_value(line).map_err(QueueError::Serde)
}

/// Decode a claimed row's `args` jsonb back into a queued task.
fn task_from_args(args: serde_json::Value) -> Result<Task, QueueError> {
    let line: QueueFileLine = serde_json::from_value(args).map_err(QueueError::Serde)?;
    line.to_task().map_err(QueueError::InvalidClaim)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_sim::RunConfig;

    /// Same seed, steps, and workload must survive the args jsonb
    /// round-trip; RunConfig has no PartialEq, so the canonical hash
    /// pins full equality of the mapped config.
    #[test]
    fn args_json_round_trips_task() {
        let task = Task::new(
            "rt-1",
            RunConfig::builder()
                .seed([0x0a; 32])
                .max_steps(4_242)
                .build(),
            "kv",
        );
        let args = task_args(&task).unwrap();
        let back = task_from_args(args).unwrap();
        assert_eq!(back.id, "rt-1");
        assert_eq!(back.workload, "kv");
        assert_eq!(back.run_config.seed(), task.run_config.seed());
        assert_eq!(back.run_config.max_steps(), task.run_config.max_steps());
        assert_eq!(
            crate::proto::run_config_hash(&back.run_config).unwrap(),
            crate::proto::run_config_hash(&task.run_config).unwrap()
        );
    }

    #[test]
    fn args_projection_rejects_non_random_policy() {
        let mut task = Task::new("rt-2", RunConfig::default(), "kv");
        *task.run_config.policy_mut() = ledger_sim::Policy::Replay;
        let err = task_args(&task).unwrap_err();
        assert!(err.to_string().contains("random"), "got {err}");
    }

    #[test]
    fn args_projection_rejects_bad_seed_hex_in_db_value() {
        let bad = serde_json::json!({
            "task_id": "rt-4",
            "run_config": {
                "seed_hex": "nothex",
                "max_steps": 10,
                "policy": "random"
            },
            "workload": "kv"
        });
        let err = task_from_args(bad).unwrap_err();
        assert!(matches!(err, QueueError::InvalidClaim(_)), "got {err}");
    }

    #[test]
    fn args_projection_rejects_non_object_db_value() {
        let err = task_from_args(serde_json::json!(42)).unwrap_err();
        assert!(matches!(err, QueueError::Serde(_)), "got {err}");
    }

    /// A max_attempts budget beyond the River smallint range must surface as
    /// the typed overflow variant with the conversion error in the source
    /// chain, never as a message-only string.
    #[test]
    fn max_attempts_overflow_is_typed_with_source() {
        let err = max_attempts_to_i16(u32::MAX).unwrap_err();
        let QueueError::MaxAttemptsOverflow {
            max_attempts,
            source,
        } = err
        else {
            panic!("expected MaxAttemptsOverflow, got {err:?}");
        };
        assert_eq!(max_attempts, u32::MAX);
        assert!(
            source.to_string().contains("out of range"),
            "source must be the TryFromIntError: {source}"
        );
        // The Display names the offending budget for operators.
        assert!(
            err.to_string().contains("4294967295"),
            "display must cite the budget: {err}"
        );
    }

    /// The in-range boundary converts cleanly, so the smallint column stays
    /// the only sink for a legal budget.
    #[test]
    fn max_attempts_boundary_fits_smallint() {
        assert_eq!(max_attempts_to_i16(i16::MAX as u32).unwrap(), i16::MAX);
        assert!(max_attempts_to_i16((i16::MAX as u32) + 1).is_err());
    }
}
