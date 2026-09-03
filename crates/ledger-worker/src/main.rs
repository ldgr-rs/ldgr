// ledger-lint:allow - host daemon / non-sim passthrough, like TokioBackend
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::sync::Mutex;

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
    /// Control-plane endpoint for the outbound session, e.g.
    /// `unix:///run/cp.sock` or `http://[::1]:50051`. When set, the worker
    /// dials the external control plane, opens one authenticated session,
    /// and executes the tasks the control plane assigns over it. Requires
    /// building with `--features grpc`.
    #[arg(long)]
    control_plane_endpoint: Option<String>,
    /// Base URL of the control-plane artifact service, e.g.
    /// `https://control.example.internal`. When set together with the
    /// `control-plane` feature, certificates are published over HTTP;
    /// otherwise the flag is ignored with a warning and the no-op sink
    /// stays active. The bearer token comes from `LEDGER_ARTIFACT_TOKEN`.
    #[arg(long)]
    artifact_base_url: Option<String>,
}

/// Typed failure of queue-file loading.
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
    /// A decoded line violated the queue-file contract.
    #[error(transparent)]
    Parse(#[from] QueueFileError),
}

/// Load NDJSON task specs into the queue (bad rows skipped).
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
    WorkerConfig {
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

/// Run the standalone drain loop over a local in-memory queue.
///
/// Polls every 200ms, runs up to `max_concurrent` tasks per tick, and
/// heartbeats each lease every lease/3. Results are printed as JSON lines.
/// Standalone mode owns only its local queue and makes no control-plane
/// claims.
async fn run_standalone_drain(
    config: &WorkerConfig,
    queue: Arc<Mutex<InMemoryQueue>>,
    sink: Arc<dyn ledger_worker::ArtifactSink>,
) {
    let heartbeat = (config.lease_timeout / 3).max(Duration::from_millis(1));
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("ledger-worker: shutdown on ctrl-c");
                break;
            }
            _ = tokio::time::sleep(Duration::from_millis(200)) => {
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
}

/// Run the outbound control-plane session.
///
/// Dials the endpoint, opens one session, and executes every task the
/// control plane assigns over it. The worker hosts no service; the control
/// plane owns the queue, leases, and attempts.
#[cfg(feature = "grpc")]
async fn run_control_plane(
    endpoint: &str,
    config: &WorkerConfig,
    sink: Arc<dyn ledger_worker::ArtifactSink>,
) -> Result<(), ledger_worker::SessionError> {
    use ledger_worker::r#gen::{session_request, session_response};
    use ledger_worker::{
        SessionError, handle_cancel, next_response, open_session, run_assigned_task,
        session_ack_worker_id, task_from_dispatch, worker_hello,
    };
    let worker_id = format!("ledger-worker-{}", std::process::id());
    let heartbeat = (config.lease_timeout / 3).max(Duration::from_millis(1));
    let (tx, mut rx) = open_session(endpoint).await?;
    let hello = worker_hello(&worker_id, env!("CARGO_PKG_VERSION"))?;
    let hello_msg = ledger_worker::r#gen::SessionRequest {
        message: Some(session_request::Message::Hello(hello)),
    };
    if tx.send(hello_msg).await.is_err() {
        return Err(SessionError::RequestChannelClosed);
    }
    // First inbound message must be the session ack.
    let ack = match next_response(&mut rx).await? {
        Some(resp) => match resp.message {
            Some(session_response::Message::SessionAck(ack)) => ack,
            Some(_) => {
                return Err(SessionError::Rejected {
                    reason: "expected session ack first".to_string(),
                });
            }
            None => {
                return Err(SessionError::Rejected {
                    reason: "empty first session message".to_string(),
                });
            }
        },
        None => {
            return Err(SessionError::Rejected {
                reason: "session closed before ack".to_string(),
            });
        }
    };
    let _assigned_worker_id = session_ack_worker_id(&ack)?;
    eprintln!(
        "ledger-worker: control-plane session accepted worker={worker_id} endpoint={endpoint}"
    );

    // In-flight task ids: a duplicate assignment of the same task fails
    // closed instead of running twice.
    let mut in_flight: std::collections::HashSet<String> = std::collections::HashSet::new();

    while let Some(resp) = next_response(&mut rx).await? {
        match resp.message {
            Some(session_response::Message::Assign(dispatch)) => {
                let task = match task_from_dispatch(dispatch) {
                    Ok(task) => task,
                    Err(err) => {
                        // Invalid dispatches fail closed through the funnel:
                        // upload the failure so the control plane retires or
                        // requeues it.
                        eprintln!("ledger-worker: {err}");
                        if let ledger_worker::SessionError::InvalidDispatch { task_id, .. } = &err {
                            let _ = ledger_worker::upload_failure(
                                &tx,
                                task_id,
                                &ledger_worker::TaskFailure::Execution(
                                    ledger_worker::WorkerError::TaskFailed {
                                        task_id: task_id.clone(),
                                        attempts: 0,
                                        max_attempts: 0,
                                        detail: err.to_string(),
                                    },
                                ),
                            )
                            .await;
                        }
                        continue;
                    }
                };
                if !in_flight.insert(task.id.clone()) {
                    // Duplicate assignment: fail closed through the funnel.
                    eprintln!("ledger-worker: duplicate assignment of {}", task.id);
                    let _ = ledger_worker::upload_failure(
                        &tx,
                        &task.id,
                        &ledger_worker::TaskFailure::Execution(
                            ledger_worker::WorkerError::TaskFailed {
                                task_id: task.id.clone(),
                                attempts: 0,
                                max_attempts: 0,
                                detail: "duplicate assignment".to_string(),
                            },
                        ),
                    )
                    .await;
                    continue;
                }
                let current_task_id = task.id.clone();
                match run_assigned_task(&tx, task, &worker_id, heartbeat).await {
                    Ok(outcome) => {
                        use ledger_worker::TaskOutcome;
                        match outcome {
                            TaskOutcome::Completed(ok) => {
                                in_flight.remove(&ok.task_id);
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
                            TaskOutcome::Failed(err) => {
                                in_flight.remove(&current_task_id);
                                eprintln!("ledger-worker: task failed: {err}");
                            }
                        }
                    }
                    Err(session_err) => {
                        in_flight.remove(&current_task_id);
                        eprintln!("ledger-worker: session error: {session_err}");
                        return Err(session_err);
                    }
                }
            }
            Some(session_response::Message::Cancel(cancel)) => {
                handle_cancel(&tx, cancel).await?;
            }
            Some(session_response::Message::HeartbeatAck(_)) => {}
            Some(session_response::Message::SessionAck(_)) => {}
            None => {}
        }
    }
    Ok(())
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

    if let Some(endpoint) = args.control_plane_endpoint.as_deref() {
        #[cfg(feature = "grpc")]
        {
            if let Err(err) = run_control_plane(endpoint, &config, sink).await {
                eprintln!("ledger-worker: {err}");
                std::process::exit(1);
            }
            return;
        }
        #[cfg(not(feature = "grpc"))]
        {
            // Deliberate discard: without the grpc feature the endpoint is
            // still consumed so the binding stays used in every build.
            let _ = endpoint;
            eprintln!(
                "ledger-worker: --control-plane-endpoint requires building with --features grpc"
            );
            std::process::exit(1);
        }
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

    run_standalone_drain(&config, queue, sink).await;
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
