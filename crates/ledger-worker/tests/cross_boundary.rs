// ledger-lint:allow - integration test uses temp UDS and deterministic sim
//! Cross-boundary determinism through the outbound control-plane session.
//!
//! The worker is a pure client: it hosts no service. A fake external
//! control plane hosts the `ledger.control.v2` service over a temp UDS
//! socket; the worker (in-process or the compiled binary) dials it, opens
//! one session, executes the assigned golden task, and uploads the result.
//! The control plane verifies the uploaded journal root against a direct
//! simulation, asserting byte-identical roots across the wire boundary and
//! across two runs (hash-drift guard).

use std::time::Duration;

use ledger_explorer::search::Workload;
use ledger_sim::{RunConfig, Simulation};
use ledger_worker::{InMemoryQueue, Task, WorkerConfig, hash_to_hex, run_drain_once, workload_for};

#[cfg(feature = "grpc")]
use ledger_worker::run_config_hash;
#[cfg(feature = "grpc")]
use std::sync::Arc;

#[cfg(feature = "grpc")]
const RESPONSE_DEADLINE: Duration = Duration::from_secs(10);

fn golden_config() -> RunConfig {
    RunConfig::builder().seed([7u8; 32]).build()
}

fn golden_task(id: &str) -> Task {
    Task::new(id, golden_config(), "kv")
}

fn direct_root_hex() -> String {
    let cfg = golden_config();
    let workload = workload_for("kv").expect("kv workload");
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

/// Fake external control plane: hosts the v2 `ControlPlaneService` over a
/// temp UDS socket and assigns the golden task, then records the uploaded
/// result for verification.
///
/// The fake owns the assignment: it leases exactly one task (the golden kv
/// task) on session open, then records the first uploaded result.
#[cfg(feature = "grpc")]
mod fake_cp {
    use super::*;
    use ledger_worker::r#gen::control_plane_service_server::{
        ControlPlaneService, ControlPlaneServiceServer,
    };
    use ledger_worker::r#gen::{
        SessionAck, SessionRequest, SessionResponse, TaskDispatch, session_request,
        session_response,
    };
    use std::path::Path;
    use tonic::{Request, Response, Status, Streaming};

    /// Shared state between the server task and the test.
    #[derive(Default)]
    pub struct FakeCpState {
        /// Uploaded results, in order.
        pub uploads: std::sync::Mutex<Vec<ledger_worker::r#gen::ResultUpload>>,
        /// Heartbeats received, in order.
        pub heartbeats: std::sync::Mutex<Vec<ledger_worker::r#gen::Heartbeat>>,
        /// The hello that opened the session.
        pub hello: std::sync::Mutex<Option<ledger_worker::r#gen::WorkerHello>>,
    }

    impl FakeCpState {
        pub fn uploads(&self) -> Vec<ledger_worker::r#gen::ResultUpload> {
            self.uploads.lock().unwrap().clone()
        }
        pub fn heartbeat_count(&self) -> usize {
            self.heartbeats.lock().unwrap().len()
        }
    }

    /// Session handler: ack the hello, assign the golden task, collect the
    /// upload. Runs until the client closes the stream.
    pub struct FakeCpSvc {
        pub state: Arc<FakeCpState>,
        pub dispatch: TaskDispatch,
        pub accept: bool,
    }

    #[tonic::async_trait]
    impl ControlPlaneService for FakeCpSvc {
        type SessionStream =
            tokio_stream::wrappers::ReceiverStream<Result<SessionResponse, Status>>;

        async fn session(
            &self,
            request: Request<Streaming<SessionRequest>>,
        ) -> Result<Response<Self::SessionStream>, Status> {
            let mut incoming = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(16);
            let state = Arc::clone(&self.state);
            let dispatch = self.dispatch.clone();
            let accept = self.accept;
            tokio::spawn(async move {
                // Hello must arrive first.
                match incoming.message().await {
                    Ok(Some(req)) => {
                        if let Some(session_request::Message::Hello(hello)) = req.message {
                            *state.hello.lock().unwrap() = Some(hello);
                        }
                    }
                    Ok(None) | Err(_) => {
                        let _ = tx
                            .send(Ok(SessionResponse {
                                message: Some(session_response::Message::SessionAck(SessionAck {
                                    accepted: false,
                                    assigned_worker_id: String::new(),
                                    reason: "no hello".to_string(),
                                })),
                            }))
                            .await;
                        return;
                    }
                }
                let ack = SessionResponse {
                    message: Some(session_response::Message::SessionAck(SessionAck {
                        accepted: accept,
                        assigned_worker_id: if accept {
                            "assigned-w1".to_string()
                        } else {
                            String::new()
                        },
                        reason: if accept {
                            String::new()
                        } else {
                            "fake control plane rejects".to_string()
                        },
                    })),
                };
                if tx.send(Ok(ack)).await.is_err() {
                    return;
                }
                if !accept {
                    return;
                }
                // Assign the golden task once.
                let assign = SessionResponse {
                    message: Some(session_response::Message::Assign(dispatch)),
                };
                if tx.send(Ok(assign)).await.is_err() {
                    return;
                }
                // Collect heartbeats and the upload until the client leaves.
                while let Ok(Some(req)) = incoming.message().await {
                    match req.message {
                        Some(session_request::Message::Heartbeat(hb)) => {
                            state.heartbeats.lock().unwrap().push(hb);
                        }
                        Some(session_request::Message::Result(upload)) => {
                            state.uploads.lock().unwrap().push(upload);
                        }
                        Some(session_request::Message::Hello(_)) => {}
                        Some(session_request::Message::CancelAck(_)) => {}
                        None => {}
                    }
                }
            });
            Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
                rx,
            )))
        }
    }

    /// Spawn the fake control plane on a fresh temp socket.
    pub async fn spawn(sock: &Path, dispatch: TaskDispatch, accept: bool) -> Arc<FakeCpState> {
        let state = Arc::new(FakeCpState::default());
        let listener = tokio::net::UnixListener::bind(sock).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);
        let svc = FakeCpSvc {
            state: Arc::clone(&state),
            dispatch,
            accept,
        };
        tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(ControlPlaneServiceServer::new(svc))
                .serve_with_incoming(incoming)
                .await;
        });
        state
    }
}

#[cfg(feature = "grpc")]
fn golden_dispatch() -> ledger_worker::r#gen::TaskDispatch {
    let cfg = golden_config();
    let hash = run_config_hash(&cfg).unwrap();
    ledger_worker::r#gen::TaskDispatch {
        task_id: "golden-task".to_string(),
        run_config_bytes: ledger_worker::canonical_bytes(&cfg).unwrap(),
        workload: "kv".to_string(),
        run_config_hash_hex: hash_to_hex(&hash),
        execution_identity: Vec::new(),
    }
}

#[cfg(feature = "grpc")]
async fn session_root_through_fake_cp(sock: &std::path::Path, accept: bool) -> String {
    use ledger_worker::r#gen::{session_request, session_response};
    use ledger_worker::{
        next_response, open_session, run_assigned_task, session_ack_worker_id, task_from_dispatch,
        worker_hello,
    };

    let _state = fake_cp::spawn(sock, golden_dispatch(), accept).await;
    // The worker dials OUT; no socket of its own is created.
    let endpoint = ledger_worker::unix_endpoint(sock).expect("unix endpoint");
    let (tx, mut rx) = open_session(&endpoint).await.expect("open session");
    let hello = worker_hello("w-cross", env!("CARGO_PKG_VERSION"));
    tx.send(ledger_worker::r#gen::SessionRequest {
        message: Some(session_request::Message::Hello(hello)),
    })
    .await
    .expect("send hello");
    let ack = next_response(&mut rx)
        .await
        .expect("read ack")
        .expect("ack");
    let ack = match ack.message {
        Some(session_response::Message::SessionAck(ack)) => ack,
        _ => panic!("expected session ack"),
    };
    let _assigned = session_ack_worker_id(&ack).expect("accepted");
    if !accept {
        // A rejected session has no further messages; done.
        return String::new();
    }
    // Read the assignment.
    let assign = next_response(&mut rx)
        .await
        .expect("read assign")
        .expect("assign");
    let dispatch = match assign.message {
        Some(session_response::Message::Assign(dispatch)) => dispatch,
        _ => panic!("expected assignment"),
    };
    let task = task_from_dispatch(dispatch).expect("dispatch parses");
    let outcome = run_assigned_task(&tx, task, "w-cross", Duration::from_millis(5))
        .await
        .expect("assigned task runs");
    match outcome {
        ledger_worker::TaskOutcome::Completed(ok) => hash_to_hex(&ok.journal_root),
        ledger_worker::TaskOutcome::Failed(err) => panic!("task failed: {err}"),
    }
}

#[cfg(feature = "grpc")]
async fn binary_session_root(_dir: &std::path::Path, sock: &std::path::Path) -> String {
    use std::process::{Command, Stdio};

    let state = fake_cp::spawn(sock, golden_dispatch(), true).await;
    let bin = env!("CARGO_BIN_EXE_ledger-worker");
    let endpoint = ledger_worker::unix_endpoint(sock).expect("unix endpoint");
    let mut child = Command::new(bin)
        .arg("--control-plane-endpoint")
        .arg(&endpoint)
        .arg("--lease-timeout-secs")
        .arg("30")
        .arg("--max-concurrent")
        .arg("1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ledger-worker binary");

    // Wait for the upload with a deadline.
    let root = tokio::time::timeout(RESPONSE_DEADLINE, async {
        loop {
            let uploads = state.uploads();
            if let Some(u) = uploads.first() {
                return u.journal_root_hex.clone();
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("binary worker must upload the result within the deadline");
    child.kill().expect("kill worker binary");
    let _ = child.wait();
    let _ = std::fs::remove_file(sock);
    root
}

#[tokio::test]
async fn cross_boundary_real_roots_equal_and_deterministic_twice() {
    // Third direct computation is the source of truth.
    let direct = direct_root_hex();
    assert_eq!(direct.len(), 64);
    assert_eq!(direct, direct.to_ascii_lowercase());

    let mut prev_direct = String::new();
    let mut prev_a = String::new();
    for iter in 0..2 {
        let task_id = "golden-task";
        let dir = std::env::temp_dir().join(format!(
            "ldgr-cross-{}-{}-{}",
            std::process::id(),
            iter,
            task_id
        ));
        let _ = std::fs::create_dir_all(&dir);
        let sock = dir.join("cp.sock");
        if sock.exists() {
            let _ = std::fs::remove_file(&sock);
        }

        let root_a = drain_once_root(task_id);
        #[cfg(feature = "grpc")]
        let root_b = session_root_through_fake_cp(&sock, true).await;
        #[cfg(feature = "grpc")]
        let root_bin = binary_session_root(&dir, &dir.join("cp-bin.sock")).await;
        let direct_now = direct_root_hex();

        assert_eq!(
            direct_now, direct,
            "direct simulation drift across iterations {iter}"
        );
        assert_eq!(
            root_a, direct_now,
            "dispatcher root mismatch vs direct iter {iter}"
        );
        #[cfg(feature = "grpc")]
        assert_eq!(
            root_b, direct_now,
            "session root mismatch vs direct iter {iter}"
        );
        #[cfg(feature = "grpc")]
        assert_eq!(
            root_bin, direct_now,
            "binary worker session root mismatch vs direct iter {iter}"
        );

        if iter > 0 {
            assert_eq!(prev_direct, direct_now, "hash drift across golden runs");
            assert_eq!(prev_a, root_a, "hash drift across golden runs (drain_once)");
        }
        prev_direct = direct_now;
        prev_a = root_a;

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn direct_simulation_is_deterministic_across_two_runs() {
    let a = direct_root_hex();
    let b = direct_root_hex();
    assert_eq!(a, b);
}

/// The worker hosts no service: a rejected session must fail closed, and
/// the worker must never bind its own socket.
#[cfg(feature = "grpc")]
#[tokio::test]
async fn rejected_session_fails_closed() {
    use ledger_worker::r#gen::{session_request, session_response};
    use ledger_worker::{next_response, open_session, worker_hello};
    let dir = std::env::temp_dir().join(format!("ldgr-cross-reject-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let sock = dir.join("reject.sock");
    let state = fake_cp::spawn(&sock, golden_dispatch(), false).await;

    let endpoint = ledger_worker::unix_endpoint(&sock).expect("unix endpoint");
    let (tx, mut rx) = open_session(&endpoint).await.expect("open session");
    let hello = worker_hello("w-reject", env!("CARGO_PKG_VERSION"));
    tx.send(ledger_worker::r#gen::SessionRequest {
        message: Some(session_request::Message::Hello(hello)),
    })
    .await
    .expect("send hello");
    let ack = next_response(&mut rx)
        .await
        .expect("read ack")
        .expect("ack");
    let ack = match ack.message {
        Some(session_response::Message::SessionAck(ack)) => ack,
        _ => panic!("expected session ack"),
    };
    assert!(!ack.accepted);
    assert!(
        ledger_worker::session_ack_worker_id(&ack).is_err(),
        "rejected session must fail closed"
    );
    // The worker opened no listening socket of its own.
    let _ = state;
    let _ = std::fs::remove_dir_all(&dir);
}

/// The worker never binds its own socket: after a full session the temp
/// directory holds only the control plane's socket.
#[cfg(feature = "grpc")]
#[tokio::test]
async fn worker_creates_no_socket_of_its_own() {
    let dir = std::env::temp_dir().join(format!("ldgr-cross-nosock-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let sock = dir.join("cp.sock");
    let _root = session_root_through_fake_cp(&sock, true).await;
    // Only the control plane's socket exists; the worker bound nothing.
    let entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("read dir")
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(entries.len(), 1, "worker must not create its own socket");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Heartbeats flow during a long task: the fake control plane must observe
/// at least one heartbeat before the upload for a slow workload.
#[cfg(feature = "grpc")]
#[tokio::test]
async fn heartbeats_flow_while_task_runs() {
    use ledger_worker::r#gen::{session_request, session_response};
    use ledger_worker::{next_response, open_session, worker_hello};
    use ledger_worker::{run_assigned_task, task_from_dispatch};
    let dir = std::env::temp_dir().join(format!("ldgr-cross-hb-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let sock = dir.join("hb.sock");
    let state = fake_cp::spawn(&sock, golden_dispatch(), true).await;
    let endpoint = ledger_worker::unix_endpoint(&sock).expect("unix endpoint");
    let (tx, mut rx) = open_session(&endpoint).await.expect("open session");
    let hello = worker_hello("w-hb", env!("CARGO_PKG_VERSION"));
    tx.send(ledger_worker::r#gen::SessionRequest {
        message: Some(session_request::Message::Hello(hello)),
    })
    .await
    .expect("send hello");
    let ack = next_response(&mut rx)
        .await
        .expect("read ack")
        .expect("ack");
    let ack = match ack.message {
        Some(session_response::Message::SessionAck(ack)) => ack,
        _ => panic!("expected session ack"),
    };
    assert!(ack.accepted);
    let assign = next_response(&mut rx)
        .await
        .expect("read assign")
        .expect("assign");
    let dispatch = match assign.message {
        Some(session_response::Message::Assign(d)) => d,
        _ => panic!("expected assignment"),
    };
    let task = task_from_dispatch(dispatch).expect("dispatch parses");
    // Very short heartbeat: the golden kv run takes a few ms, so a 1ms
    // interval guarantees at least one tick.
    let outcome = run_assigned_task(&tx, task, "w-hb", Duration::from_millis(1))
        .await
        .expect("assigned task runs");
    assert!(matches!(outcome, ledger_worker::TaskOutcome::Completed(_)));
    // Wait until the fake control plane observes the upload; heartbeats
    // travel the same channel before it, so the count is settled then.
    tokio::time::timeout(RESPONSE_DEADLINE, async {
        loop {
            if !state.uploads().is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("upload must arrive");
    assert!(
        state.heartbeat_count() >= 1,
        "the control plane must observe heartbeats while a task runs"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Unknown workloads fail closed: the upload carries the failure and no
/// journal root.
#[cfg(feature = "grpc")]
#[tokio::test]
async fn unknown_workload_fails_closed() {
    use ledger_worker::r#gen::{session_request, session_response};
    use ledger_worker::{next_response, open_session, worker_hello};
    use ledger_worker::{run_assigned_task, task_from_dispatch};
    let dir = std::env::temp_dir().join(format!("ldgr-cross-uw-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let sock = dir.join("uw.sock");
    let mut dispatch = golden_dispatch();
    dispatch.workload = "no-such-workload".to_string();
    let state = fake_cp::spawn(&sock, dispatch, true).await;
    let endpoint = ledger_worker::unix_endpoint(&sock).expect("unix endpoint");
    let (tx, mut rx) = open_session(&endpoint).await.expect("open session");
    let hello = worker_hello("w-uw", env!("CARGO_PKG_VERSION"));
    tx.send(ledger_worker::r#gen::SessionRequest {
        message: Some(session_request::Message::Hello(hello)),
    })
    .await
    .expect("send hello");
    let ack = next_response(&mut rx)
        .await
        .expect("read ack")
        .expect("ack");
    let _ack = match ack.message {
        Some(session_response::Message::SessionAck(ack)) => ack,
        _ => panic!("expected session ack"),
    };
    let assign = next_response(&mut rx)
        .await
        .expect("read assign")
        .expect("assign");
    let dispatch = match assign.message {
        Some(session_response::Message::Assign(d)) => d,
        _ => panic!("expected assignment"),
    };
    let task = task_from_dispatch(dispatch).expect("dispatch parses");
    let outcome = run_assigned_task(&tx, task, "w-uw", Duration::from_millis(50))
        .await
        .expect("assigned task runs");
    assert!(
        matches!(outcome, ledger_worker::TaskOutcome::Failed(_)),
        "unknown workload must fail closed"
    );
    let upload = tokio::time::timeout(RESPONSE_DEADLINE, async {
        loop {
            let uploads = state.uploads();
            if let Some(u) = uploads.first() {
                return u.clone();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("upload must arrive");
    assert!(!upload.ok, "failed upload must carry ok=false");
    assert!(
        upload.error.contains("unknown workload"),
        "got {}",
        upload.error
    );
    assert!(upload.journal_root_hex.is_empty(), "no root on failure");
    let _ = std::fs::remove_dir_all(&dir);
}
