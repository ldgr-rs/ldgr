//! Queue-file wire conversion: serde projections and NDJSON parsing.
//!
//! [`QueueFileLine`], [`FlatQueueFileLine`], and [`WorkerTaskSpec`] are the
//! stable on-disk task shapes.

use ledger_sim::RunConfig;
use serde::{Deserialize, Serialize};
use thiserror::Error as ThisError;

use super::Task;

/// Minimal serde projection of a simulation run config for queue files.
///
/// `ledger_sim::RunConfig` does not implement serde, so NDJSON queue files
/// carry this projection. [`WorkerTaskSpec::to_run_config`] maps it back:
/// `seed_hex` fills `RunConfig::seed`, `max_steps` fills
/// `RunConfig::max_steps`, and `"random"` maps to `Policy::Random`. Every
/// other field keeps its `RunConfig::default()` value, so the canonical
/// hash of the mapped config equals the hash of the equivalent in-process
/// config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerTaskSpec {
    /// 64-char lowercase hex root seed.
    pub seed_hex: String,
    /// Instruction budget (`RunConfig::max_steps`).
    pub max_steps: usize,
    /// Scheduling policy name; only `"random"` is supported.
    pub policy: String,
}

/// Errors from the task-spec projection onto a [`RunConfig`].
#[derive(Debug, ThisError, PartialEq, Eq)]
pub enum TaskSpecError {
    /// Only the random policy round-trips through the projection.
    #[error("unsupported policy {policy:?}: only \"random\" is supported")]
    UnsupportedPolicy {
        /// Policy name carried by the spec.
        policy: String,
    },
    /// The seed hex did not decode into a 32-byte hash.
    #[error("seed hex invalid: {source}")]
    SeedHex {
        #[from]
        source: ledger_format::HexError,
    },
}

impl WorkerTaskSpec {
    /// Map the spec onto a [`RunConfig`].
    ///
    /// # Errors
    /// Returns [`TaskSpecError`] when `policy` is not `"random"` or
    /// `seed_hex` is not well-formed 64-char hex.
    pub fn to_run_config(&self) -> Result<RunConfig, TaskSpecError> {
        if self.policy != "random" {
            return Err(TaskSpecError::UnsupportedPolicy {
                policy: self.policy.clone(),
            });
        }
        let seed = crate::proto::hex_to_hash(&self.seed_hex)?;
        Ok(RunConfig::builder()
            .seed(seed)
            .max_steps(self.max_steps)
            .build())
    }
}

/// One NDJSON line of a `--queue-file`.
///
/// Shape: `{"task_id":..,"run_config":{..},"workload":..}` where
/// `run_config` is a [`WorkerTaskSpec`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueFileLine {
    /// Unique task identifier.
    pub task_id: String,
    /// Minimal run-config projection; see [`WorkerTaskSpec`].
    pub run_config: WorkerTaskSpec,
    /// Workload name selecting the instruction programs.
    pub workload: String,
}

impl QueueFileLine {
    /// Convert the line into a queued [`Task`].
    ///
    /// # Errors
    /// Returns the first invalid field of the embedded [`WorkerTaskSpec`].
    pub fn to_task(&self) -> Result<Task, TaskSpecError> {
        Ok(Task::new(
            self.task_id.clone(),
            self.run_config.to_run_config()?,
            self.workload.clone(),
        ))
    }
}

/// One flat NDJSON line of a `ledger-worker --queue-file`.
///
/// The daemon accepts this shape on disk (the `task_id`, `seed_hex`,
/// `max_steps`, and `workload` keys at the top level, no `run_config`
/// nesting). [`From`] maps it onto the canonical [`QueueFileLine`] with the
/// `"random"` policy, and [`QueueFileLine::to_task`] validates the seed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FlatQueueFileLine {
    /// Unique task identifier.
    pub task_id: String,
    /// 64-char lowercase hex root seed.
    pub seed_hex: String,
    /// Instruction budget; the daemon defaults to 4096 when absent.
    #[serde(default = "default_flat_max_steps")]
    pub max_steps: usize,
    /// Workload name; the daemon defaults to `"kv"` when absent.
    #[serde(default = "default_flat_workload")]
    pub workload: String,
}

fn default_flat_max_steps() -> usize {
    4096
}

fn default_flat_workload() -> String {
    "kv".to_string()
}

impl From<FlatQueueFileLine> for QueueFileLine {
    fn from(line: FlatQueueFileLine) -> Self {
        Self {
            task_id: line.task_id,
            run_config: WorkerTaskSpec {
                seed_hex: line.seed_hex,
                max_steps: line.max_steps,
                policy: "random".to_string(),
            },
            workload: line.workload,
        }
    }
}

/// Errors from queue-file parsing. Each variant carries the 1-based
/// number of the offending line.
#[derive(Debug, ThisError)]
pub enum QueueFileError {
    /// A line was not valid NDJSON of a [`QueueFileLine`].
    #[error("queue-file line {line}: {source}")]
    Json {
        /// 1-based line number.
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    /// A decoded line violated the task-spec contract.
    #[error("queue-file line {line}: {source}")]
    Spec {
        /// 1-based line number.
        line: usize,
        #[source]
        source: TaskSpecError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_task_spec_maps_onto_default_shaped_run_config() {
        let spec = WorkerTaskSpec {
            seed_hex: crate::proto::hash_to_hex(&ledger_format::EntryHash([7u8; 32])),
            max_steps: 4_242,
            policy: "random".into(),
        };
        let cfg = spec.to_run_config().unwrap();
        let expected = RunConfig::builder()
            .seed(ledger_format::EntryHash([7u8; 32]))
            .max_steps(4_242)
            .build();
        // RunConfig has no PartialEq; compare the projected fields and pin
        // boundary equality through the canonical hash.
        assert_eq!(cfg.seed(), expected.seed());
        assert_eq!(cfg.max_steps(), expected.max_steps());
        assert_eq!(cfg.dropped_events(), expected.dropped_events());
        assert_eq!(cfg.fault_schedule(), expected.fault_schedule());
        assert_eq!(cfg.monitor(), expected.monitor());
        assert_eq!(
            crate::proto::run_config_hash(&cfg).unwrap(),
            crate::proto::run_config_hash(&expected).unwrap()
        );
    }
    #[test]
    fn worker_task_spec_rejects_unknown_policy_and_bad_seed() {
        let bad_policy = WorkerTaskSpec {
            seed_hex: crate::proto::hash_to_hex(&ledger_format::EntryHash([1u8; 32])),
            max_steps: 10,
            policy: "bandit".into(),
        };
        let err = bad_policy.to_run_config().unwrap_err();
        assert!(err.to_string().contains("unsupported policy"), "got {err}");

        let bad_seed = WorkerTaskSpec {
            seed_hex: "nothex".into(),
            max_steps: 10,
            policy: "random".into(),
        };
        let err = bad_seed.to_run_config().unwrap_err();
        assert!(matches!(err, TaskSpecError::SeedHex { .. }), "got {err}");
    }
    #[test]
    fn flat_line_maps_onto_canonical_with_daemon_defaults() {
        // The daemon's on-disk shape: top-level keys, no run_config nesting.
        // Missing max_steps and workload take the daemon defaults.
        let line: FlatQueueFileLine = serde_json::from_str(
            "{\"task_id\":\"flat-1\",\"seed_hex\":\
             \"0000000000000000000000000000000000000000000000000000000000000000\"}",
        )
        .unwrap();
        let canonical = QueueFileLine::from(line);
        assert_eq!(canonical.task_id, "flat-1");
        assert_eq!(canonical.run_config.seed_hex.len(), 64);
        assert_eq!(canonical.run_config.max_steps, 4096);
        assert_eq!(canonical.run_config.policy, "random");
        assert_eq!(canonical.workload, "kv");
        let task = canonical.to_task().unwrap();
        assert_eq!(task.id, "flat-1");
        assert_eq!(task.run_config.max_steps(), 4096);
        assert_eq!(task.workload, "kv");
    }
    #[test]
    fn flat_line_preserves_explicit_steps_and_workload() {
        let line: FlatQueueFileLine = serde_json::from_str(
            "{\"task_id\":\"flat-2\",\"seed_hex\":\
             \"1111111111111111111111111111111111111111111111111111111111111111\",\
             \"max_steps\":1234,\"workload\":\"trivial\"}",
        )
        .unwrap();
        let canonical = QueueFileLine::from(line);
        assert_eq!(canonical.run_config.max_steps, 1234);
        assert_eq!(canonical.workload, "trivial");
        let task = canonical.to_task().unwrap();
        assert_eq!(task.run_config.max_steps(), 1234);
        assert_eq!(task.workload, "trivial");
    }
    #[test]
    fn flat_line_rejects_bad_seed_through_canonical_validation() {
        let line: FlatQueueFileLine = serde_json::from_str(
            "{\"task_id\":\"flat-3\",\"seed_hex\":\"nothex\",\"max_steps\":10,\"workload\":\"kv\"}",
        )
        .unwrap();
        let err = QueueFileLine::from(line).to_task().unwrap_err();
        assert!(matches!(err, TaskSpecError::SeedHex { .. }), "got {err}");
    }
    #[test]
    fn flat_line_rejects_missing_task_id_and_seed() {
        let err = serde_json::from_str::<FlatQueueFileLine>("{\"max_steps\":10}").unwrap_err();
        assert!(!err.to_string().is_empty());
    }
}
