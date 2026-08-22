// ledger-lint:allow - host daemon / non-sim passthrough, like TokioBackend
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::sync::Mutex;

#[cfg(feature = "pg")]
use ledger_worker::Task;
use ledger_worker::{
    FlatQueueFileLine, InMemoryQueue, QueueFileError, QueueFileLine, RuntimeProfile, TaskQueue,
    WorkerConfig, execute_with_heartbeat, hash_to_hex,
};

/// Campaign task execution daemon.
#[derive(Debug, Parser)]
#[command(
    name = "ledger-worker",
    about = "Deterministic simulation worker daemon"
)]
struct LedgerWorker {
    /// Unix domain socket path for the control plane.
    #[arg(long)]
    uds_path: Option<PathBuf>,
    /// How long a pulled task stays leased before it can be re-queued.
    #[arg(long, default_value_t = 30)]
    lease_timeout_secs: u64,
    /// Maximum number of tasks the worker may execute concurrently.
    #[arg(long, default_value_t = 1)]
    max_concurrent: usize,
    /// Pull one task, run it, print JSON, and exit.
    #[arg(long)]
    drain_once: bool,
    /// NDJSON file of task specs loaded into the queue at startup.
    ///
    /// Each line: {"task_id": "...", "seed_hex": "<64 hex>", "max_steps": N,
    /// "workload": "kv"}. The flat line maps onto the canonical queue
    /// projection ([`ledger_worker::FlatQueueFileLine`] -> [`QueueFileLine`]);
    /// the seed and steps map onto a canonical RunConfig and the workload
    /// name selects the server-side program. Missing `max_steps` defaults to
    /// 4096 and missing `workload` to "kv".
    #[arg(long)]
    queue_file: Option<PathBuf>,
    /// Postgres DSN of the River queue backend, e.g.
    /// `postgres://host:5432/db`. When set, the standalone drain loop claims
    /// tasks from the `river.job` table instead of the in-memory queue file.
    /// Requires building with `--features pg`.
    #[arg(long)]
    pg_dsn: Option<String>,
    /// Base URL of the control-plane artifact service, e.g.
    /// `https://control.example.internal`. When set together with the
    /// `control-plane` feature, certificates are published over HTTP;
    /// otherwise the flag is ignored with a warning and the no-op sink
    /// stays active. The bearer token comes from `LEDGER_ARTIFACT_TOKEN`.
    #[arg(long)]
    artifact_base_url: Option<String>,
}

/// Typed failure of queue-file loading. Open and read failures keep the
/// [`std::io::Error`] source; per-line failures keep the line number and
/// their own typed sources via [`QueueFileError`].
#[derive(Debug, thiserror::Error)]
enum QueueLoadError {
    /// The queue file could not be opened.
    #[error("queue file {path}: {source}", path = path.display())]
    Open {
        /// Path passed to the open call.
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// A line could not be read from the open file.
    #[error("queue file read: {0}")]
    Read(#[from] std::io::Error),
    /// A decoded line violated the queue-file projection contract. This
    /// branch carries the 1-based line number through [`QueueFileError`].
    #[error(transparent)]
    Parse(#[from] QueueFileError),
}

/// Load NDJSON task specs into the queue. Malformed lines are reported and
/// skipped so one bad row cannot silence the whole file.
fn load_queue_file(path: &PathBuf, queue: &mut InMemoryQueue) -> Result<usize, QueueLoadError> {
    use std::io::BufRead;
    let file = std::fs::File::open(path).map_err(|source| QueueLoadError::Open {
        path: path.clone(),
        source,
    })?;
    let reader = std::io::BufReader::new(file);
    let mut loaded = 0usize;
    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(QueueLoadError::Read)?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parsed = serde_json::from_str::<FlatQueueFileLine>(trimmed)
            .map_err(|source| QueueFileError::Json {
                line: index + 1,
                source,
            })
            .and_then(|flat| {
                QueueFileLine::from(flat)
                    .to_task()
                    .map_err(|source| QueueFileError::Spec {
                        line: index + 1,
                        source,
                    })
            });
        match parsed {
            Ok(task) => {
                queue.push(task);
                loaded += 1;
            }
            Err(err) => eprintln!("ledger-worker: skipping {err}"),
        }
    }
    Ok(loaded)
}

fn build_config(args: &LedgerWorker) -> WorkerConfig {
    // Default socket lands in a platform-private directory under a
    // randomized per-process name; an explicit --uds-path is honored
    // exactly as given.
    let uds_path = args
        .uds_path
        .clone()
        .unwrap_or_else(ledger_worker::default_uds_path);
    WorkerConfig {
        uds_path,
        lease_timeout: Duration::from_secs(args.lease_timeout_secs),
        max_concurrent: args.max_concurrent,
        // Detected once at startup; every certificate this process publishes
        // binds the same runtime profile.
        profile_hex8: RuntimeProfile::detect().fingerprint_hex8(),
    }
}

/// Resolve the artifact sink from CLI flags and build features.
///
/// Default is the no-op sink. `--artifact-base-url` selects the HTTP sink,
/// but only when the `control-plane` feature is compiled in; without it the
/// flag is ignored with a warning so offline builds keep running.
fn build_sink(args: &LedgerWorker) -> Arc<dyn ledger_worker::ArtifactSink> {
    #[cfg(feature = "control-plane")]
    if let Some(base_url) = args.artifact_base_url.clone() {
        let token = std::env::var("LEDGER_ARTIFACT_TOKEN").ok();
        return Arc::new(ledger_worker::HttpSink::new(base_url, token));
    }
    #[cfg(not(feature = "control-plane"))]
    if args.artifact_base_url.is_some() {
        eprintln!(
            "ledger-worker: --artifact-base-url ignored (built without --features control-plane)"
        );
    }
    Arc::new(ledger_worker::NoopSink)
}

#[tokio::main]
async fn main() {
    let args = LedgerWorker::parse();
    let config = build_config(&args);
    let sink = build_sink(&args);

    if args.drain_once {
        let queue = Box::new(InMemoryQueue::new(config.lease_timeout));
        if let Some(line) = ledger_worker::run_drain_once(config, queue) {
            println!("{line}");
        }
        return;
    }

    // Daemon mode: one shared queue drives both the drain loop and the UDS
    // real-execution server, so leases heartbeated by either path protect the
    // same tasks. InMemoryQueue is the default backend; `--pg-dsn` replaces
    // the loop with the Postgres/River backend (async-only, so the shared
    // in-memory queue and its UDS server do not start).
    #[cfg(feature = "pg")]
    if let Some(dsn) = args.pg_dsn.clone() {
        if let Err(err) = pg_drain_loop(&dsn, &config, Arc::clone(&sink)).await {
            eprintln!("ledger-worker: {err}");
            std::process::exit(1);
        }
        return;
    }
    #[cfg(not(feature = "pg"))]
    if args.pg_dsn.is_some() {
        eprintln!("ledger-worker: --pg-dsn requires building with --features pg");
        std::process::exit(1);
    }
    let queue = Arc::new(Mutex::new(InMemoryQueue::new(config.lease_timeout)));
    if let Some(path) = &args.queue_file {
        match load_queue_file(path, &mut *queue.lock().await) {
            Ok(count) => eprintln!(
                "ledger-worker: loaded {count} task(s) from {}",
                path.display()
            ),
            Err(err) => {
                eprintln!("ledger-worker: {err}");
                std::process::exit(1);
            }
        }
    }

    // The control plane always serves: either the operator's --uds-path or
    // the randomized platform-private default resolved into config.
    let uds_handle = {
        let path = config.uds_path.clone();
        let queue = Arc::clone(&queue);
        let sink = Arc::clone(&sink);
        let profile_hex8 = config.profile_hex8.clone();
        tokio::spawn(async move {
            // With the grpc feature the daemon serves the tonic-generated
            // ledger.control.v1 ControlPlane, WorkerControl, and
            // ArtifactService over UDS; without it the JSON-lines fallback
            // serves the same wire contract and exposes no artifact endpoint.
            #[cfg(feature = "grpc")]
            let result = ledger_worker::serve_grpc_uds(path, queue, sink, &profile_hex8).await;
            #[cfg(not(feature = "grpc"))]
            let result = {
                drop(sink);
                ledger_worker::serve_uds_real(path, queue, Some(profile_hex8)).await
            };
            if let Err(err) = result {
                eprintln!("ledger-worker UDS error: {err}");
            }
        })
    };

    eprintln!(
        "ledger-worker: daemon start uds={} lease={}s max_concurrent={} profile={} sink={}",
        config.uds_path.display(),
        config.lease_timeout.as_secs(),
        config.max_concurrent,
        config.profile_hex8,
        if args.artifact_base_url.is_some() {
            "http"
        } else {
            "noop"
        },
    );

    // Heartbeat cadence: extend every lease/3 so an executing task is never
    // more than a third of a lease away from a fresh deadline.
    let heartbeat = (config.lease_timeout / 3).max(Duration::from_millis(1));

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("ledger-worker: shutdown on ctrl-c");
                break;
            }
            _ = tokio::time::sleep(Duration::from_millis(200)) => {
                // Drain up to max_concurrent tasks per tick, sequentially for
                // determinism. Each task runs on the blocking pool while the
                // async heartbeat extends its lease until completion.
                for _ in 0..config.max_concurrent {
                    let task = queue.lock().await.pull();
                    let Some(task) = task else { break };
                    let result = execute_with_heartbeat(
                        Arc::clone(&queue),
                        task,
                        heartbeat,
                        config.lease_timeout,
                    )
                    .await;
                    match result {
                        Ok(ok) => {
                            // Best-effort publication: outcome is logged,
                            // never fatal to the completed task. The sink
                            // may block on HTTP, so publication runs on
                            // the blocking pool inside this select loop.
                            let publish_sink = Arc::clone(&sink);
                            let publish_result = ok.clone();
                            let publish_profile = config.profile_hex8.clone();
                            let published = tokio::task::spawn_blocking(move || {
                                ledger_worker::publish_result_certificate(
                                    publish_sink.as_ref(),
                                    &publish_result,
                                    Some(ledger_worker::WORKER_BUILDER_ID),
                                    Some(&publish_profile),
                                )
                            })
                            .await;
                            if let Err(join_err) = published {
                                eprintln!(
                                    "ledger-worker: certificate publish task panicked: {join_err}"
                                );
                            }
                            let line = serde_json::json!({
                                "task_id": ok.task_id,
                                "journal_root": hash_to_hex(&ok.journal_root),
                                "steps": ok.steps,
                            }).to_string();
                            println!("{line}");
                        }
                        Err(err) => {
                            eprintln!("ledger-worker: task failed: {err}");
                            break;
                        }
                    }
                }
            }
        }
    }

    // Shutdown aborts the always-running control-plane server.
    uds_handle.abort();
}

/// Standalone drain loop over the Postgres/River queue.
///
/// Mirrors the in-memory loop: poll every 200ms, run up to `max_concurrent`
/// tasks per tick, heartbeat each lease every lease/3 so it is refreshed
/// well before expiry. Attempt budgets are honored by `fail_async`, which
/// retries within budget and discards past `max_attempts`.
#[cfg(feature = "pg")]
async fn pg_drain_loop(
    dsn: &str,
    config: &WorkerConfig,
    sink: Arc<dyn ledger_worker::ArtifactSink>,
) -> Result<(), ledger_worker::QueueError> {
    use ledger_worker::PostgresQueue;

    let worker_id = format!("ledger-worker-{}", std::process::id());
    let mut queue = PostgresQueue::connect(dsn, &worker_id, config.lease_timeout).await?;
    let heartbeat = (config.lease_timeout / 3).max(Duration::from_millis(1));
    eprintln!(
        "ledger-worker: pg drain start worker={worker_id} lease={}s max_concurrent={}",
        config.lease_timeout.as_secs(),
        config.max_concurrent,
    );
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("ledger-worker: shutdown on ctrl-c");
                return Ok(());
            }
            _ = tokio::time::sleep(Duration::from_millis(200)) => {
                for _ in 0..config.max_concurrent {
                    match queue.pull_async().await {
                        Ok(Some(task)) => {
                            match execute_pg_with_heartbeat(&mut queue, task, heartbeat).await {
                                Ok(ok) => {
                                    // Same blocking-pool rule as the
                                    // in-memory loop: publication never
                                    // blocks the drain loop's ticks.
                                    let publish_sink = Arc::clone(&sink);
                                    let publish_result = ok.clone();
                                    let publish_profile = config.profile_hex8.clone();
                                    let published = tokio::task::spawn_blocking(move || {
                                        ledger_worker::publish_result_certificate(
                                            publish_sink.as_ref(),
                                            &publish_result,
                                            Some(ledger_worker::WORKER_BUILDER_ID),
                                            Some(&publish_profile),
                                        )
                                    })
                                    .await;
                                    if let Err(join_err) = published {
                                        eprintln!(
                                            "ledger-worker: certificate publish task panicked: {join_err}"
                                        );
                                    }
                                    let line = serde_json::json!({
                                        "task_id": ok.task_id,
                                        "journal_root": hash_to_hex(&ok.journal_root),
                                        "steps": ok.steps,
                                    })
                                    .to_string();
                                    println!("{line}");
                                }
                                Err(err) => eprintln!("ledger-worker: task failed: {err}"),
                            }
                        }
                        Ok(None) => break,
                        Err(err) => {
                            eprintln!("ledger-worker: queue error: {err}");
                            return Err(err);
                        }
                    }
                }
            }
        }
    }
}

/// Execute one Postgres-claimed task while heartbeating its lease.
///
/// Same contract as the in-memory `execute_with_heartbeat`: the task runs
/// on the blocking pool, and each heartbeat tick (lease/3) refreshes the
/// lease markers before expiry. River tracks no lease deadline column, so
/// the refresh re-stamps `attempted_by`/`attempted_at` instead of extending
/// a timer. Success acks (job completed); failure routes through
/// `fail_async` so the attempt budget is charged in the database.
#[cfg(feature = "pg")]
async fn execute_pg_with_heartbeat(
    queue: &mut ledger_worker::PostgresQueue,
    task: Task,
    heartbeat: Duration,
) -> Result<ledger_worker::WorkerResult, ledger_worker::WorkerError> {
    let task_id = task.id.clone();
    let mut exec = tokio::task::spawn_blocking(move || ledger_worker::execute_task(task));
    let mut ticker = tokio::time::interval(heartbeat.max(Duration::from_millis(1)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let result = loop {
        tokio::select! {
            res = &mut exec => {
                match res {
                    Ok(inner) => break inner,
                    Err(e) => return Err(e.into()),
                }
            }
            _ = ticker.tick() => {
                // Heartbeat failures are logged, not fatal: the lease
                // markers refresh again on the next tick.
                if let Err(err) = queue.extend_lease_async(&task_id).await {
                    eprintln!("ledger-worker: lease heartbeat failed for {task_id}: {err}");
                }
            }
        }
    };
    match result {
        Ok(ok) => {
            if let Err(err) = queue.ack_async(&ok.task_id).await {
                eprintln!("ledger-worker: ack failed for {}: {err}", ok.task_id);
            }
            Ok(ok)
        }
        Err(err) => {
            let reason = err.to_string();
            if let Err(fail_err) = queue.fail_async(&task_id, &reason).await {
                eprintln!("ledger-worker: failure routing failed for {task_id}: {fail_err}");
            }
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;
    use std::io::Write;

    /// A missing queue file must surface as the typed `Open` variant with the
    /// io source in the error chain, never as a bare message.
    #[test]
    fn queue_file_open_failure_is_typed_with_source() {
        let missing = std::env::temp_dir().join(format!(
            "ldgr-worker-queue-missing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let mut queue = InMemoryQueue::new(Duration::from_secs(30));
        let err = load_queue_file(&missing, &mut queue).unwrap_err();
        let QueueLoadError::Open { path, source } = &err else {
            panic!("expected Open, got {err:?}");
        };
        assert_eq!(*path, missing);
        assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
        assert!(
            err.source().is_some(),
            "the io source must stay in the error chain"
        );
        assert!(
            err.to_string().contains(&missing.display().to_string()),
            "display must name the file: {err}"
        );
    }

    /// Valid lines load, and malformed lines or comments are skipped without
    /// aborting the file, so one bad row cannot silence the rest.
    #[test]
    fn queue_file_loads_valid_lines_and_skips_malformed() {
        let path = std::env::temp_dir().join(format!(
            "ldgr-worker-queue-good-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let mut file = std::fs::File::create(&path).expect("create queue file");
        writeln!(
            file,
            r#"{{"task_id":"ok-1","seed_hex":"{}","max_steps":64,"workload":"kv"}}"#,
            "ab".repeat(32)
        )
        .expect("write valid line");
        writeln!(file, "not json at all").expect("write malformed line");
        writeln!(file, "# comment line").expect("write comment");
        let mut queue = InMemoryQueue::new(Duration::from_secs(30));
        let loaded = load_queue_file(&path, &mut queue).expect("file must load");
        assert_eq!(loaded, 1);
        let _ = std::fs::remove_file(&path);
    }
}
