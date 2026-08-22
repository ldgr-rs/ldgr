// ledger-lint:allow - integration test uses temp UDS and deterministic sim
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ledger_explorer::search::Workload;
use ledger_sim::{RunConfig, Simulation};
use ledger_worker::{
    InMemoryQueue, Task, WorkerConfig, WorkerRequest, WorkerResponse, hash_to_hex, run_config_hash,
    run_drain_once, workload_for,
};
use tokio::sync::Mutex;

/// Bound on how long a freshly spawned server may take to serve a
/// readiness probe. A longer wait is a dead server, not a slow one.
const CONNECT_DEADLINE: Duration = Duration::from_secs(10);
/// Bound on one request/response exchange. A longer wait is a wedged
/// server, not a busy one.
const RESPONSE_DEADLINE: Duration = Duration::from_secs(10);

fn golden_config() -> RunConfig {
    RunConfig::builder().seed([7u8; 32]).build()
}

fn golden_task(id: &str) -> Task {
    Task::new(id, golden_config(), "kv")
}

fn direct_root_hex() -> String {
    let cfg = golden_config();
    let workload = workload_for("kv");
    let run = Simulation::new(cfg, workload.programs())
        .run()
        .expect("direct simulation must succeed");
    hash_to_hex(&run.journal.root_hash())
}

fn drain_once_root(task_id: &str) -> String {
    let cfg = WorkerConfig {
        lease_timeout: Duration::from_secs(30),
        ..WorkerConfig::default()
    };
    let mut q = InMemoryQueue::new(cfg.lease_timeout);
    q.push(golden_task(task_id));
    let line = run_drain_once(cfg, Box::new(q)).expect("drain_once must produce json");
    let v: serde_json::Value = serde_json::from_str(&line).expect("valid json");
    v["journal_root"]
        .as_str()
        .expect("journal_root")
        .to_string()
}

/// Connect to a UDS socket a freshly spawned server is binding, bounded by
/// [`CONNECT_DEADLINE`]. Every connect failure is retried; a deadline miss
/// panics with diagnostics instead of hanging.
async fn uds_connect_ready(sock: &std::path::Path, what: &str) -> tokio::net::UnixStream {
    let mut last_error = String::new();
    tokio::time::timeout(CONNECT_DEADLINE, async {
        loop {
            match tokio::net::UnixStream::connect(sock).await {
                Ok(stream) => return stream,
                Err(error) => {
                    last_error = error.to_string();
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{what}: no listener at {} within {CONNECT_DEADLINE:?}; \
             last connect error: {last_error}. The server task may have exited before binding.",
            sock.display()
        )
    })
}

/// Readiness handshake: wait for the socket, then complete one
/// request/response roundtrip against a task id that cannot exist. The
/// server's error reply proves its accept loop is live and serving, so the
/// caller's next request is handled instead of sitting in a backlog behind
/// a listener that never accepts.
async fn uds_ready(sock: &std::path::Path, what: &str) {
    let probe_id = "readiness-probe";
    let req = WorkerRequest {
        task_id: probe_id.into(),
        run_config_hash: hash_to_hex(&[0xabu8; 32]),
        run_config: None,
        profile_fingerprint: None,
    };
    let json = serde_json::to_string(&req).unwrap();
    let mut stream = uds_connect_ready(sock, what).await;
    {
        use tokio::io::AsyncWriteExt;
        stream
            .write_all(format!("{json}\n").as_bytes())
            .await
            .expect("probe write");
    }
    let line = read_response_line(&mut stream, what).await;
    let value: serde_json::Value =
        serde_json::from_str(line.trim()).expect("probe response must be JSON");
    let expected = format!("task not found: {probe_id}");
    assert_eq!(
        value["error"].as_str(),
        Some(expected.as_str()),
        "{what}: readiness probe must be answered by the server, got {value}"
    );
}

/// Connect a tonic channel to a worker that is still starting up, bounded
/// by [`CONNECT_DEADLINE`]. A deadline miss panics with diagnostics.
#[cfg(feature = "grpc")]
async fn grpc_ready(sock: &std::path::Path, what: &str) -> tonic::transport::Channel {
    let mut last_error = String::new();
    tokio::time::timeout(CONNECT_DEADLINE, async {
        loop {
            match ledger_worker::connect_grpc_uds(sock.to_path_buf()).await {
                Ok(channel) => return channel,
                Err(error) => {
                    last_error = error.to_string();
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{what}: worker never bound its gRPC socket at {} within {CONNECT_DEADLINE:?}; \
             last connect error: {last_error}. Check the binary build or the server task stderr.",
            sock.display()
        )
    })
}

/// Read one response line with [`RESPONSE_DEADLINE`]. An empty reply or a
/// hang fails the test with diagnostics instead of parking forever.
async fn read_response_line(stream: &mut tokio::net::UnixStream, what: &str) -> String {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let bytes = tokio::time::timeout(RESPONSE_DEADLINE, reader.read_line(&mut line))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "{what}: no response within {RESPONSE_DEADLINE:?}; \
                 the server may have stalled or the request was malformed"
            )
        })
        .unwrap_or_else(|error| panic!("{what}: response read failed: {error}"));
    if bytes == 0 {
        panic!("{what}: server closed the connection without a response");
    }
    if line.trim().is_empty() {
        panic!("{what}: server replied with an empty line");
    }
    line
}

/// Bound one gRPC exchange with [`RESPONSE_DEADLINE`].
///
/// The tonic clients have no request timeout of their own, so a server
/// that bound its socket but never enters its accept loop would park the
/// first RPC forever. Mirrors [`uds_ready`]: a missing response fails with
/// diagnostics instead of hanging.
#[cfg(feature = "grpc")]
async fn rpc_ready<T, E>(
    pending: impl std::future::Future<Output = Result<T, E>>,
    what: &str,
) -> Result<T, E> {
    tokio::time::timeout(RESPONSE_DEADLINE, pending)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "{what}: no gRPC response within {RESPONSE_DEADLINE:?}; \
                 the server may have bound its socket without serving its accept loop"
            )
        })
}

async fn uds_real_root(task_id: &str, sock: PathBuf) -> String {
    let queue = Arc::new(Mutex::new(InMemoryQueue::new(Duration::from_secs(30))));
    {
        let mut q = queue.lock().await;
        q.push(golden_task(task_id));
    }
    let queue_clone = Arc::clone(&queue);
    let serve_path = sock.clone();
    let handle = tokio::spawn(async move {
        let _ = ledger_worker::serve_uds_real(serve_path, queue_clone, None).await;
    });
    uds_ready(&sock, "uds_real server").await;

    let cfg = golden_config();
    let hash = run_config_hash(&cfg).unwrap();
    let req = WorkerRequest {
        task_id: task_id.to_string(),
        run_config_hash: hash_to_hex(&hash),
        run_config: None,
        profile_fingerprint: None,
    };
    let json = serde_json::to_string(&req).unwrap();
    let mut stream = uds_connect_ready(&sock, "uds_real client connect").await;
    {
        use tokio::io::AsyncWriteExt;
        stream
            .write_all(format!("{json}\n").as_bytes())
            .await
            .expect("request write");
    }
    let resp_root = {
        let line = read_response_line(&mut stream, "uds_real request").await;
        let resp: WorkerResponse = serde_json::from_str(line.trim()).expect("valid json");
        assert_eq!(resp.task_id, task_id);
        assert!(
            resp.error.is_none(),
            "uds_real leg hit an error: {:?}",
            resp.error
        );
        // The task was preloaded, so the real root must be present.
        resp.journal_root.expect("journal_root for preloaded task")
    };
    handle.abort();
    let _ = std::fs::remove_file(&sock);
    resp_root
}

#[tokio::test]
async fn cross_boundary_real_roots_equal_and_deterministic_twice() {
    // Third direct computation is the source of truth.
    let direct = direct_root_hex();
    assert_eq!(direct.len(), 64);
    assert_eq!(direct, direct.to_ascii_lowercase());

    // Run golden campaign twice, asserting cross-boundary equality each time
    // and determinism across iterations (journal-root equality asserted).
    let mut prev_direct = String::new();
    let mut prev_a = String::new();
    let mut prev_b = String::new();
    for iter in 0..2 {
        let task_id = "golden-task";
        // Use a per-iteration socket to avoid reuse races.
        let dir = std::env::temp_dir().join(format!(
            "ldgr-cross-{}-{}-{}",
            std::process::id(),
            iter,
            task_id
        ));
        let _ = std::fs::create_dir_all(&dir);
        let sock = dir.join("cross.sock");
        if sock.exists() {
            let _ = std::fs::remove_file(&sock);
        }

        let root_a = drain_once_root(task_id);
        let root_b = uds_real_root(task_id, sock.clone()).await;
        let root_bin = binary_uds_root(&dir, task_id, &sock).await;
        let direct_now = direct_root_hex();

        // Determinism: direct recomputed each iteration must equal the first direct.
        assert_eq!(
            direct_now, direct,
            "direct simulation drift across iterations {iter}"
        );
        // Cross-boundary: in-process dispatcher vs UDS real worker.
        assert_eq!(
            root_a, root_b,
            "cross-boundary mismatch iter {iter}: drain_once {root_a} vs uds_real {root_b}"
        );
        // The compiled worker binary over its own UDS must agree too.
        assert_eq!(
            root_bin, direct_now,
            "binary worker root mismatch vs direct iter {iter}"
        );
        // Both must equal the direct simulation root.
        assert_eq!(
            root_a, direct_now,
            "dispatcher root mismatch vs direct iter {iter}"
        );
        assert_eq!(
            root_b, direct_now,
            "uds_real root mismatch vs direct iter {iter}"
        );
        // Real root must not be the stub blake3(task_id).
        let stub = hash_to_hex(blake3::hash(task_id.as_bytes()).as_bytes());
        assert_ne!(
            root_a, stub,
            "real root must not equal stub blake3(task_id) iter {iter}"
        );

        if iter > 0 {
            assert_eq!(prev_direct, direct_now, "hash drift across golden runs");
            assert_eq!(prev_a, root_a, "hash drift across golden runs (drain_once)");
            assert_eq!(prev_b, root_b, "hash drift across golden runs (uds_real)");
        }
        prev_direct = direct_now;
        prev_a = root_a;
        prev_b = root_b;

        let _ = std::fs::remove_dir_all(&dir);
        println!(
            "iter {iter}: cross-boundary ok direct={} drain_once={} uds_real={} binary={root_bin}",
            prev_direct, prev_a, prev_b
        );
    }
}

/// Spawn the compiled `ledger-worker` binary with a queue file and query it
/// over its own UDS. This is the fourth leg: the real process boundary. The
/// probe speaks whichever transport the binary was built with.
async fn binary_uds_root(dir: &std::path::Path, task_id: &str, sock: &std::path::Path) -> String {
    use std::process::{Command, Stdio};

    let bin = env!("CARGO_BIN_EXE_ledger-worker");
    let queue_file = dir.join("queue.ndjson");
    let cfg = golden_config();
    let seed_hex: String = cfg.seed().iter().map(|b| format!("{b:02x}")).collect();
    let spec = serde_json::json!({
        "task_id": task_id,
        "seed_hex": seed_hex,
        "max_steps": 4096u64,
        "workload": "kv",
    });
    std::fs::write(&queue_file, format!("{spec}\n")).expect("write queue file");

    let child_sock = dir.join("bin.sock");
    let mut child = Command::new(bin)
        .arg("--uds-path")
        .arg(&child_sock)
        .arg("--queue-file")
        .arg(&queue_file)
        .arg("--lease-timeout-secs")
        .arg("30")
        .arg("--max-concurrent")
        .arg("0")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ledger-worker binary");

    #[cfg(feature = "grpc")]
    let resp_root = {
        // gRPC leg: lease the golden task from the real binary and upload the
        // direct root; acceptance proves the daemon reproduced it exactly.
        let channel = grpc_ready(&child_sock, "worker binary gRPC").await;
        let mut client =
            ledger_worker::r#gen::control_plane_client::ControlPlaneClient::new(channel);

        // First RPC with a client deadline: a binary that bound its socket
        // but never serves would otherwise park this test forever.
        let lease = rpc_ready(
            client.acquire_lease(ledger_worker::r#gen::LeaseRequest {
                worker_id: "cross".into(),
                max_tasks: 8,
            }),
            "worker binary gRPC acquire_lease",
        )
        .await
        .expect("acquire_lease from binary");
        let lease = lease.into_inner();
        let dispatch = lease
            .tasks
            .iter()
            .find(|t| t.task_id == task_id)
            .expect("golden task must be leased from the binary queue");
        assert_eq!(dispatch.workload, "kv");
        // The queue file pins max_steps=4096, so the hash travels over that
        // exact config, not the RunConfig default budget.
        let file_cfg = RunConfig::builder()
            .seed(cfg.seed())
            .max_steps(4096)
            .build();
        assert_eq!(
            dispatch.run_config_hash_hex,
            hash_to_hex(&run_config_hash(&file_cfg).unwrap())
        );

        let direct = direct_root_hex();
        let ack = client
            .upload_result(ledger_worker::r#gen::ResultUpload {
                task_id: task_id.to_string(),
                journal_root_hex: direct.clone(),
                steps: 4096,
                ok: true,
                error: String::new(),
            })
            .await
            .expect("upload_result to binary")
            .into_inner();
        assert!(ack.accepted, "binary worker rejected the true journal root");
        direct
    };

    #[cfg(not(feature = "grpc"))]
    let resp_root = {
        let mut stream = uds_connect_ready(&child_sock, "worker binary UDS").await;

        // The queue file pins max_steps=4096, so the request must name the
        // hash of that exact config, not the RunConfig default budget.
        let file_cfg = RunConfig::builder()
            .seed(cfg.seed())
            .max_steps(4096)
            .build();
        let hash = run_config_hash(&file_cfg).unwrap();
        let req = WorkerRequest {
            task_id: task_id.to_string(),
            run_config_hash: hash_to_hex(&hash),
            run_config: None,
            profile_fingerprint: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        {
            use tokio::io::AsyncWriteExt;
            stream
                .write_all(format!("{json}\n").as_bytes())
                .await
                .unwrap();
        }
        {
            let line = read_response_line(&mut stream, "worker binary request").await;
            let resp: WorkerResponse = serde_json::from_str(line.trim()).unwrap();
            assert_eq!(resp.task_id, task_id);
            assert!(
                resp.error.is_none(),
                "binary leg hit an error: {:?}",
                resp.error
            );
            resp.journal_root
                .expect("journal_root for preloaded queue-file task")
        }
    };

    child.kill().expect("kill worker binary");
    let _ = child.wait();
    let _ = std::fs::remove_file(&queue_file);
    let _ = std::fs::remove_file(sock);
    resp_root
}

#[tokio::test]
async fn uds_real_unknown_task_returns_error() {
    let dir = std::env::temp_dir().join(format!("ldgr-cross-fallback-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let sock = dir.join("fallback.sock");
    if sock.exists() {
        let _ = std::fs::remove_file(&sock);
    }
    let queue = Arc::new(Mutex::new(InMemoryQueue::new(Duration::from_secs(30))));
    // Do not preload any task: the reply must be an error, never a
    // fabricated root.
    let queue_clone = Arc::clone(&queue);
    let serve_path = sock.clone();
    let handle = tokio::spawn(async move {
        let _ = ledger_worker::serve_uds_real(serve_path, queue_clone, None).await;
    });
    uds_ready(&sock, "fallback uds server").await;

    let req = WorkerRequest {
        task_id: "missing-task".into(),
        run_config_hash: hash_to_hex(&[9u8; 32]),
        run_config: None,
        profile_fingerprint: None,
    };
    let json = serde_json::to_string(&req).unwrap();
    let mut stream = uds_connect_ready(&sock, "fallback client connect").await;
    {
        use tokio::io::AsyncWriteExt;
        stream
            .write_all(format!("{json}\n").as_bytes())
            .await
            .unwrap();
    }
    {
        let line = read_response_line(&mut stream, "fallback request").await;
        let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(v["task_id"], "missing-task");
        assert_eq!(v["error"], "task not found: missing-task");
        assert!(
            !v.as_object().unwrap().contains_key("journal_root"),
            "error response must not carry a journal_root, got {v}"
        );
    }
    handle.abort();
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn direct_simulation_is_deterministic_across_two_runs() {
    let a = direct_root_hex();
    let b = direct_root_hex();
    assert_eq!(a, b);
}

/// In-process gRPC leg: serve the tonic `ControlPlane` over a temp UDS inside
/// this test process, lease the golden kv task, upload the direct root, and
/// require acceptance. Skipped entirely when built without the `grpc`
/// feature; the binary leg then exercises the JSON-lines fallback instead.
#[cfg(feature = "grpc")]
#[tokio::test]
async fn grpc_in_process_root_matches_direct() {
    use ledger_worker::serve_grpc_uds;

    let dir = std::env::temp_dir().join(format!("ldgr-cross-grpc-inproc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let sock = dir.join("grpc-inproc.sock");

    let queue = Arc::new(Mutex::new(InMemoryQueue::new(Duration::from_secs(30))));
    {
        let mut q = queue.lock().await;
        q.push(golden_task("grpc-golden"));
    }
    let serve_handle = {
        let sock = sock.clone();
        tokio::spawn(async move {
            let _ =
                serve_grpc_uds(sock, queue, Arc::new(ledger_worker::NoopSink), "deadbeef").await;
        })
    };

    // Readiness handshake: the Health RPC must answer before the lease
    // exchange starts, so the bind race cannot hide behind a retry. The
    // exchange carries a client deadline: a server that binds without
    // serving would otherwise park this test forever.
    let channel = grpc_ready(&sock, "in-process gRPC server").await;
    let mut health = ledger_worker::r#gen::health_client::HealthClient::new(channel.clone());
    let reply = rpc_ready(
        health.check(ledger_worker::r#gen::HealthCheck {
            service: String::new(),
        }),
        "in-process gRPC health check",
    )
    .await
    .expect("health check must answer on a serving daemon")
    .into_inner();
    assert!(reply.serving, "in-process daemon must report serving");

    let mut client = ledger_worker::r#gen::control_plane_client::ControlPlaneClient::new(channel);

    let lease = client
        .acquire_lease(ledger_worker::r#gen::LeaseRequest {
            worker_id: "cross-grpc".into(),
            max_tasks: 4,
        })
        .await
        .expect("acquire_lease over in-process gRPC")
        .into_inner();
    assert_eq!(lease.tasks.len(), 1);
    assert_eq!(lease.tasks[0].task_id, "grpc-golden");
    assert_eq!(lease.tasks[0].workload, "kv");
    assert_eq!(
        lease.tasks[0].run_config_hash_hex,
        hash_to_hex(&run_config_hash(&golden_config()).unwrap())
    );

    // UploadResult must accept exactly the direct simulation root.
    let direct = direct_root_hex();
    let ack = client
        .upload_result(ledger_worker::r#gen::ResultUpload {
            task_id: "grpc-golden".into(),
            journal_root_hex: direct.clone(),
            steps: 4096,
            ok: true,
            error: String::new(),
        })
        .await
        .expect("upload_result over in-process gRPC")
        .into_inner();
    assert_eq!(ack.task_id, "grpc-golden");
    assert!(
        ack.accepted,
        "in-process gRPC worker rejected the deterministic root"
    );
    assert_eq!(direct.len(), 64);

    serve_handle.abort();
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_dir_all(&dir);
}
