#![deny(unsafe_code)]

//! Campaign task execution daemon.
//!
//! The worker pulls [`Task`] items from a [`TaskQueue`], runs them through
//! the deterministic simulation, and reports the journal root. Leases carry
//! attempt budgets, extension (heartbeat), cancellation, and terminal states;
//! see [`TaskStatus`]. The runtime profile handshake in [`RuntimeProfile`]
//! binds worker identity to the engine build and host shape. The JSON-lines
//! protocol in [`WorkerRequest`] is the legacy UDS worker path; with the
//! `grpc` feature, [`serve_grpc_uds`] delivers the tonic-generated
//! `ControlPlane` as real gRPC over a Unix domain socket, and the `r#gen`
//! module holds the generated `ledger.control.v1` wire bindings. With the
//! `pg` feature,
//! [`PostgresQueue`] implements the Postgres/River queue backend (schema
//! `river.job`) driven by the daemon's `--pg-dsn` drain loop. Artifact
//! publication is best-effort: the default [`NoopSink`] logs only, and the
//! `control-plane` feature (optional, off by default) swaps in an HTTP sink.
//!
//! The crate exposes a curated root facade: implementation modules stay
//! private and every public contract item is re-exported here. The generated
//! protobuf bindings stay public as `r#gen` because they are the
//! control-plane wire contract.

mod artifact;
mod config;
pub mod r#gen;
mod profile;
mod proto;
mod queue;
mod worker;

#[cfg(feature = "grpc")]
mod transport;

#[cfg(feature = "control-plane")]
pub use artifact::HttpSink;
pub use artifact::{ArtifactError, ArtifactSink, NoopSink, WORKER_BUILDER_ID, checksum_hex};
pub use config::{WorkerConfig, default_uds_path, private_socket_dir};
pub use profile::{DEFAULT_ENV_SANITATION, RuntimeProfile};
pub use proto::{
    MAX_CONCURRENT_UDS_CONNECTIONS, MAX_UDS_LINE_SIZE, UDS_READ_TIMEOUT, WorkerRequest,
    WorkerResponse, canonical_bytes, hash_to_hex, hex_to_hash, profile_pin_matches,
    run_config_hash, serve_uds_real, validate_request, validate_request_hex8,
};
#[cfg(feature = "pg")]
pub use queue::pg::{PostgresQueue, QueueError, RIVER_SCHEMA_SQL};
pub use queue::{
    AttemptOutcome, DEFAULT_MAX_ATTEMPTS, FlatQueueFileLine, InMemoryQueue, QueueFileError,
    QueueFileLine, Task, TaskQueue, TaskSpecError, TaskStatus, WorkerTaskSpec,
};
#[cfg(feature = "grpc")]
pub use transport::{
    ArtifactSvc, MAX_MESSAGE_SIZE, WorkerControlSvc, WorkerSvc, connect_grpc_uds, serve_grpc_uds,
};
pub use worker::{
    Worker, WorkerError, WorkerResult, execute_task, execute_with_heartbeat,
    publish_result_certificate, route_failure, workload_for,
};

/// Drain a single task and render the result as a JSON line.
///
/// Pulls one task via the lease, runs it, prints nothing on empty queue, and
/// otherwise returns `Some(json)` with fields `task_id`, `journal_root` (64-hex
/// lowercase), and `steps`. [`Worker::run_one`] acks the lease on success,
/// marking the task done, and charges failed attempts against the task's
/// budget. [`TaskQueue`] is the sync seam behind this entry point; the
/// Postgres/River backend (`PostgresQueue`, `pg` feature) is async-only and driven
/// directly by the daemon's `--pg-dsn` drain loop.
///
/// This is the in-process entry point used by the `ledger-worker --drain-once`
/// binary and by `tests/standalone.rs`.
pub fn run_drain_once(config: WorkerConfig, queue: Box<dyn TaskQueue>) -> Option<String> {
    let mut worker = Worker::new(config, queue);
    match worker.run_one() {
        Ok(Some(result)) => {
            let journal_root = hash_to_hex(&result.journal_root);
            let task_id = result.task_id.clone();
            let steps = result.steps;
            let campaign_findings = result.campaign_findings;
            let line = serde_json::json!({
                "task_id": task_id,
                "journal_root": journal_root,
                "steps": steps,
                "campaign_findings": campaign_findings,
            })
            .to_string();
            Some(line)
        }
        Ok(None) => None,
        Err(err) => {
            eprintln!("ledger-worker: {err}");
            None
        }
    }
}
