// ledger-lint:allow - host daemon / non-sim passthrough, like TokioBackend

//! gRPC transport over a Unix domain socket for `ledger.control.v1`.
//!
//! Serves the tonic-generated [`crate::r#gen`] `ControlPlane` service
//! backed by the shared [`InMemoryQueue`], plus the `ArtifactService`
//! upload handshake over the shared [`ArtifactSink`], and connects clients
//! through tonic's built-in `unix://` endpoint support. Execution semantics
//! mirror [`crate::proto::serve_uds_real`]: tasks run through
//! [`crate::worker::execute_task`], so this boundary stays byte-identical to
//! the in-process dispatcher. `UploadResult` additionally rejects a reported
//! root that differs from the deterministic root, which makes the transport
//! itself a cross-boundary determinism gate.

use std::path::PathBuf;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tonic::transport::{Channel, Endpoint, Server};

use crate::artifact::ArtifactSink;
use crate::r#gen::artifact_service_server::{ArtifactService, ArtifactServiceServer};
use crate::r#gen::control_plane_server::{ControlPlane, ControlPlaneServer};
use crate::r#gen::health_server::{Health, HealthServer};
use crate::r#gen::worker_control_server::{WorkerControl, WorkerControlServer};
use crate::r#gen::{
    Ack, CancelAck, CancelTaskRequest, ConfirmUploadRequest, HealthCheck, HealthReply,
    HeartbeatAck, HeartbeatRequest, LeaseExtend, LeaseRequest, LeaseResponse, RegisterAck,
    RegisterWorkerRequest, ResultUpload, TaskAck, TaskDispatch, TaskProgress, UploadUrlRequest,
    UploadUrlResponse,
};
use crate::proto::{hash_to_hex, hex_to_hash, profile_pin_matches};
use crate::queue::{InMemoryQueue, Task, TaskQueue};

/// Hard cap for one protobuf message in either direction, on every service
/// and client this module builds. A dispatch or upload never approaches
/// 1 MiB, so anything larger is hostile input, not data.
pub const MAX_MESSAGE_SIZE: usize = 1 << 20;

/// Connect a tonic [`Channel`] to the worker daemon over the Unix socket at
/// `path`.
///
/// # Errors
/// Returns the tonic transport error when the endpoint is invalid or the
/// socket cannot be reached.
pub async fn connect_grpc_uds(path: PathBuf) -> Result<Channel, tonic::transport::Error> {
    let uri = format!("unix://{}", path.display());
    // tonic 0.14 keys its built-in UDS connector off the `unix://` scheme,
    // so no custom tower connector is needed here. The 1 MiB cap mirrors
    // the per-service limits in `serve_grpc_uds` at the http2 frame layer
    // (message caps live on the generated client stubs, but the frame cap
    // guarantees the same bound on the wire for this helper's channel).
    Endpoint::from_shared(uri)?
        .max_frame_size(Some(MAX_MESSAGE_SIZE as u32))
        .connect()
        .await
}

/// Map a pulled queue task onto the wire `TaskDispatch`.
///
/// The canonical config bytes and their blake3 hex travel with the dispatch
/// so the worker side can re-validate same RunConfigHash -> same root.
fn dispatch_of(task: &Task) -> Result<TaskDispatch, tonic::Status> {
    let config_bytes = crate::proto::canonical_bytes(&task.run_config).map_err(|error| {
        tonic::Status::invalid_argument(format!(
            "task {}: run config cannot be encoded: {error}",
            task.id
        ))
    })?;
    let hash = match task.run_config_hash {
        Some(hash) => hash,
        // A task pushed before hashing (or a legacy record) falls back to the
        // digest of the canonical bytes it carries on the wire.
        None => *blake3::hash(&config_bytes).as_bytes(),
    };
    Ok(TaskDispatch {
        task_id: task.id.clone(),
        run_config_bytes: config_bytes,
        workload: task.workload.clone(),
        run_config_hash_hex: hash_to_hex(&hash),
    })
}

/// tonic `ControlPlane` implementation over the shared lease queue.
pub struct WorkerSvc {
    /// Shared queue preloaded by the daemon or the test harness.
    ///
    /// Private by contract: services attach to the queue through
    /// [`WorkerSvc::new`]; callers never touch the guarded state directly.
    queue: Arc<Mutex<InMemoryQueue>>,
}

impl WorkerSvc {
    /// Create the service over `queue`.
    pub fn new(queue: Arc<Mutex<InMemoryQueue>>) -> Self {
        Self { queue }
    }
}

/// Validate an uploaded result against the deterministic boundary and
/// produce the acceptance verdict.
///
/// The reported root must be well-formed hex, the task must exist in the
/// queue, and `execute_task` must reproduce exactly the reported root;
/// malformed hex fails the RPC, any other outcome is a soft rejection.
///
/// # Errors
/// Returns `Status::InvalidArgument` when `journal_root_hex` is not
/// well-formed hex.
async fn accepted_upload(
    queue: &Arc<Mutex<InMemoryQueue>>,
    upload: ResultUpload,
) -> Result<Ack, tonic::Status> {
    // Handshake-style validation: the reported root must be well-formed
    // 64-char hex before anything is executed or trusted.
    if hex_to_hash(&upload.journal_root_hex).is_err() {
        return Err(tonic::Status::invalid_argument(format!(
            "task {}: journal_root_hex must be 64-char lowercase hex",
            upload.task_id
        )));
    }
    let task_id = upload.task_id;
    let journal_root_hex = upload.journal_root_hex;
    let task = queue.lock().await.take_by_id(&task_id);
    let Some(task) = task else {
        return Ok(Ack {
            task_id,
            accepted: false,
        });
    };
    // execute_task re-validates the queued run_config hash; accepting an
    // upload only when its root equals the deterministic root keeps the
    // gRPC boundary byte-identical to the in-process dispatcher. The
    // simulation runs on the blocking pool, mirroring the drain loop in
    // `execute_with_heartbeat`, so a slow task never stalls the reactor.
    // A wrong root is a failed attempt and must go through the attempt
    // budget instead of silently consuming the task.
    let task_for_requeue = task.clone();
    let accepted =
        match tokio::task::spawn_blocking(move || crate::worker::execute_task(task)).await {
            Ok(Ok(result)) => {
                let ok = journal_root_hex == hash_to_hex(&result.journal_root);
                if !ok {
                    queue
                        .lock()
                        .await
                        .record_taken_task_failure(task_for_requeue);
                }
                ok
            }
            Ok(Err(err)) => {
                eprintln!("ledger-worker: execute failed for {task_id}: {err}");
                false
            }
            Err(join_err) => {
                eprintln!("ledger-worker: execute join failed for {task_id}: {join_err}");
                false
            }
        };
    Ok(Ack { task_id, accepted })
}

#[tonic::async_trait]
impl ControlPlane for WorkerSvc {
    async fn acquire_lease(
        &self,
        request: tonic::Request<LeaseRequest>,
    ) -> Result<tonic::Response<LeaseResponse>, tonic::Status> {
        let req = request.into_inner();
        let mut queue = self.queue.lock().await;
        let mut tasks = Vec::new();
        while tasks.len() < req.max_tasks as usize {
            match queue.pull() {
                Some(task) => tasks.push(dispatch_of(&task)?),
                None => break,
            }
        }
        Ok(tonic::Response::new(LeaseResponse { tasks }))
    }

    async fn upload_result(
        &self,
        request: tonic::Request<ResultUpload>,
    ) -> Result<tonic::Response<Ack>, tonic::Status> {
        Ok(tonic::Response::new(
            accepted_upload(&self.queue, request.into_inner()).await?,
        ))
    }

    async fn extend_lease(
        &self,
        request: tonic::Request<LeaseExtend>,
    ) -> Result<tonic::Response<HeartbeatAck>, tonic::Status> {
        let req = request.into_inner();
        let extended = self
            .queue
            .lock()
            .await
            .extend_lease(&req.task_id, Duration::from_secs(u64::from(req.extra_secs)));
        // The deadline lives inside InMemoryQueue and ambient wall time is
        // off limits here, so only the extension verdict travels back.
        Ok(tonic::Response::new(HeartbeatAck {
            lease_extended: extended,
            new_deadline_unix_s: 0,
        }))
    }

    async fn ack_task(
        &self,
        request: tonic::Request<TaskAck>,
    ) -> Result<tonic::Response<Ack>, tonic::Status> {
        let req = request.into_inner();
        self.queue.lock().await.ack(&req.task_id);
        Ok(tonic::Response::new(Ack {
            task_id: req.task_id,
            accepted: true,
        }))
    }

    async fn cancel_task(
        &self,
        request: tonic::Request<CancelTaskRequest>,
    ) -> Result<tonic::Response<CancelAck>, tonic::Status> {
        let req = request.into_inner();
        let cancelled = self.queue.lock().await.cancel(&req.task_id);
        Ok(tonic::Response::new(CancelAck {
            task_id: req.task_id,
            cancelled,
        }))
    }

    async fn report_progress(
        &self,
        request: tonic::Request<TaskProgress>,
    ) -> Result<tonic::Response<Ack>, tonic::Status> {
        let req = request.into_inner();
        // Progress counters are informational; the queue has no progress
        // store yet, so the report is acknowledged without state changes.
        Ok(tonic::Response::new(Ack {
            task_id: req.task_id,
            accepted: true,
        }))
    }
}

/// Registration and lifecycle service over the shared lease queue.
///
/// Carries the daemon's pinned runtime-profile fingerprint so
/// `RegisterWorker` rejects builds that do not name this daemon's profile.
pub struct WorkerControlSvc {
    /// Shared queue backing heartbeat and failure routing.
    ///
    /// Private by contract: services attach through [`WorkerControlSvc::new`].
    queue: Arc<Mutex<InMemoryQueue>>,
    /// Eight-hex profile pin from [`WorkerConfig`](crate::WorkerConfig).
    expected_profile_hex8: String,
}

impl WorkerControlSvc {
    /// Create the service over `queue`, pinning `expected_profile_hex8`.
    pub fn new(queue: Arc<Mutex<InMemoryQueue>>, expected_profile_hex8: String) -> Self {
        Self {
            queue,
            expected_profile_hex8,
        }
    }
}

#[tonic::async_trait]
impl WorkerControl for WorkerControlSvc {
    async fn register_worker(
        &self,
        request: tonic::Request<RegisterWorkerRequest>,
    ) -> Result<tonic::Response<RegisterAck>, tonic::Status> {
        let req = request.into_inner();
        let assigned_worker_id = req
            .identity
            .as_ref()
            .map(|identity| identity.worker_id.clone())
            .unwrap_or_default();
        // Legacy registrants may omit the profile entirely. A supplied
        // fingerprint must name this daemon's pinned profile; a mismatching
        // build is refused with a reason instead of admitted silently.
        if let Some(profile) = &req.profile
            && !profile.fingerprint_hex.is_empty()
            && !profile_pin_matches(&profile.fingerprint_hex, &self.expected_profile_hex8)
        {
            return Ok(tonic::Response::new(RegisterAck {
                assigned_worker_id: String::new(),
                accepted: false,
                reason: format!(
                    "runtime profile mismatch: worker fingerprint {} does not pin to {}",
                    profile.fingerprint_hex, self.expected_profile_hex8
                ),
            }));
        }
        Ok(tonic::Response::new(RegisterAck {
            assigned_worker_id,
            accepted: true,
            reason: String::new(),
        }))
    }

    async fn heartbeat(
        &self,
        request: tonic::Request<HeartbeatRequest>,
    ) -> Result<tonic::Response<HeartbeatAck>, tonic::Status> {
        let req = request.into_inner();
        // A zero extension reports whether the task still holds a live
        // lease without moving its deadline.
        let lease_extended = self
            .queue
            .lock()
            .await
            .extend_lease(&req.task_id, Duration::ZERO);
        Ok(tonic::Response::new(HeartbeatAck {
            lease_extended,
            new_deadline_unix_s: 0,
        }))
    }

    async fn complete_task(
        &self,
        request: tonic::Request<ResultUpload>,
    ) -> Result<tonic::Response<Ack>, tonic::Status> {
        Ok(tonic::Response::new(
            accepted_upload(&self.queue, request.into_inner()).await?,
        ))
    }

    async fn fail_task(
        &self,
        request: tonic::Request<ResultUpload>,
    ) -> Result<tonic::Response<Ack>, tonic::Status> {
        let req = request.into_inner();
        // Failure routing charges one attempt through the queue's budget;
        // a task without a live lease cannot be failed here.
        let accepted = self
            .queue
            .lock()
            .await
            .report_failure(&req.task_id)
            .is_some();
        Ok(tonic::Response::new(Ack {
            task_id: req.task_id,
            accepted,
        }))
    }
}

/// `Health` service: liveness probe over the same socket.
///
/// `Check` reports `serving = true` while the daemon answers, and refuses
/// names it does not serve with `Status::not_found` so a probe cannot
/// mistake an unrelated service name for daemon liveness.
#[derive(Debug, Clone, Copy, Default)]
pub struct HealthSvc;

/// Full service names this daemon serves, for `Health.Check` validation.
const SERVED_SERVICES: &[&str] = &[
    "ledger.control.v1.ControlPlane",
    "ledger.control.v1.WorkerControl",
    "ledger.control.v1.ArtifactService",
    "ledger.control.v1.Health",
];

#[tonic::async_trait]
impl Health for HealthSvc {
    async fn check(
        &self,
        request: tonic::Request<HealthCheck>,
    ) -> Result<tonic::Response<HealthReply>, tonic::Status> {
        let service = request.into_inner().service;
        if !service.is_empty() && !SERVED_SERVICES.contains(&service.as_str()) {
            return Err(tonic::Status::not_found(format!(
                "unknown service {service:?}"
            )));
        }
        Ok(tonic::Response::new(HealthReply { serving: true }))
    }
}

/// tonic `ArtifactService` implementation over the shared artifact sink.
pub struct ArtifactSvc {
    /// Sink backing GetUploadURL / ConfirmUpload; typically the daemon-wide
    /// [`NoopSink`](crate::artifact::NoopSink) or [`HttpSink`](crate::artifact::HttpSink).
    ///
    /// Private by contract: services attach through [`ArtifactSvc::new`].
    sink: Arc<dyn ArtifactSink>,
}

impl ArtifactSvc {
    /// Create the service over `sink`.
    pub fn new(sink: Arc<dyn ArtifactSink>) -> Self {
        Self { sink }
    }
}

#[tonic::async_trait]
impl ArtifactService for ArtifactSvc {
    async fn get_upload_url(
        &self,
        request: tonic::Request<UploadUrlRequest>,
    ) -> Result<tonic::Response<UploadUrlResponse>, tonic::Status> {
        let req = request.into_inner();
        let url = self
            .sink
            .get_upload_url(&req.task_id, &req.artifact_name)
            .map_err(|e| tonic::Status::internal(e.to_string()))?;
        Ok(tonic::Response::new(UploadUrlResponse {
            url,
            method: "PUT".to_string(),
        }))
    }

    async fn confirm_upload(
        &self,
        request: tonic::Request<ConfirmUploadRequest>,
    ) -> Result<tonic::Response<Ack>, tonic::Status> {
        let req = request.into_inner();
        self.sink
            .confirm(&req.task_id, &req.artifact_name, &req.checksum_hex)
            .map_err(|e| tonic::Status::internal(e.to_string()))?;
        Ok(tonic::Response::new(Ack {
            task_id: req.task_id,
            accepted: true,
        }))
    }
}

/// Serve the `ControlPlane`, `WorkerControl`, `ArtifactService`, and
/// `Health` gRPC services over the Unix socket at `path`.
///
/// The control plane drains the shared lease queue; worker control pins
/// registration to `expected_profile_hex8` and routes lifecycle acks; the
/// artifact service brokers direct-to-storage uploads through `sink`; the
/// health service answers liveness probes. The
/// socket is bound with owner-only mode and every accepted connection is
/// checked against the kernel peer credential: peers with a different uid
/// than the socket owner are dropped before any byte of a request is read.
/// No stale file is removed before bind; callers pass fresh paths and an
/// occupied path fails the bind.
///
/// # Errors
/// Returns the bind error for a bad or occupied socket path, or the tonic
/// serving error mapped onto `std::io::Error`.
pub async fn serve_grpc_uds(
    path: PathBuf,
    queue: Arc<Mutex<InMemoryQueue>>,
    sink: Arc<dyn ArtifactSink>,
    expected_profile_hex8: &str,
) -> Result<(), std::io::Error> {
    let listener = tokio::net::UnixListener::bind(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Owner-only socket: peers outside this uid cannot connect even if
        // they reach the parent directory.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    }
    let incoming = AuthedListener {
        inner: listener,
        // SO_PEERCRED answers with the creator's credentials, so the bound
        // socket file's owner anchors every accept-time check.
        owner_uid: crate::proto::socket_owner_uid(&path),
    };
    Server::builder()
        .add_service(
            ControlPlaneServer::new(WorkerSvc::new(Arc::clone(&queue)))
                .max_decoding_message_size(MAX_MESSAGE_SIZE)
                .max_encoding_message_size(MAX_MESSAGE_SIZE),
        )
        .add_service(
            WorkerControlServer::new(WorkerControlSvc::new(
                Arc::clone(&queue),
                expected_profile_hex8.to_string(),
            ))
            .max_decoding_message_size(MAX_MESSAGE_SIZE)
            .max_encoding_message_size(MAX_MESSAGE_SIZE),
        )
        .add_service(
            ArtifactServiceServer::new(ArtifactSvc::new(sink))
                .max_decoding_message_size(MAX_MESSAGE_SIZE)
                .max_encoding_message_size(MAX_MESSAGE_SIZE),
        )
        .add_service(
            HealthServer::new(HealthSvc)
                .max_decoding_message_size(MAX_MESSAGE_SIZE)
                .max_encoding_message_size(MAX_MESSAGE_SIZE),
        )
        .serve_with_incoming(incoming)
        .await
        .map_err(std::io::Error::other)
}

/// Incoming-connection stream that enforces same-uid peers.
///
/// Wraps the bound listener and drops connections whose kernel credential
/// does not carry the socket owner's uid, so unauthorized peers never reach
/// a service handler.
struct AuthedListener {
    inner: UnixListener,
    /// Owner uid of the bound socket; `None` when the platform cannot stat
    /// it, which rejects every peer (fail closed).
    owner_uid: Option<u32>,
}

impl tokio_stream::Stream for AuthedListener {
    type Item = std::io::Result<tokio::net::UnixStream>;

    fn poll_next(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match this.inner.poll_accept(cx) {
                Poll::Ready(Ok((stream, _addr))) => {
                    if crate::proto::peer_uid_allowed(&stream, this.owner_uid) {
                        return Poll::Ready(Some(Ok(stream)));
                    }
                    eprintln!("ledger-worker: rejected gRPC peer with mismatching uid");
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Some(Err(err))),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r#gen::control_plane_client::ControlPlaneClient;
    use crate::r#gen::worker_control_client::WorkerControlClient;
    use crate::proto::run_config_hash;
    use crate::queue::Task;
    use crate::worker::workload_for;
    use ledger_explorer::search::Workload;
    use ledger_sim::{RunConfig, Simulation};

    use std::path::Path;

    const LEASE_SECS: u64 = 30;

    fn golden_config() -> RunConfig {
        RunConfig::builder().seed([7u8; 32]).build()
    }

    /// Direct simulation root for the golden seed over the kv workload; the
    /// source of truth the UploadResult roundtrip must reproduce.
    fn golden_root_hex() -> String {
        let cfg = golden_config();
        let workload = workload_for("kv");
        let run = Simulation::new(cfg, workload.programs())
            .run()
            .expect("golden simulation must succeed");
        hash_to_hex(&run.journal.root_hash())
    }

    fn temp_socket(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("ldgr-grpc-{name}-{}.sock", std::process::id()))
    }

    struct TestServer {
        sock: std::path::PathBuf,
        handle: tokio::task::JoinHandle<()>,
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.handle.abort();
            let _ = std::fs::remove_file(&self.sock);
        }
    }

    async fn spawn_server(
        name: &str,
        queue: Arc<Mutex<InMemoryQueue>>,
        sink: Arc<dyn crate::artifact::ArtifactSink>,
    ) -> TestServer {
        // Registration pin is arbitrary here: these suites never register,
        // and an unpinnable-looking value keeps them honest about that.
        spawn_server_with_pin(name, queue, sink, "deadbeef").await
    }

    async fn spawn_server_with_pin(
        name: &str,
        queue: Arc<Mutex<InMemoryQueue>>,
        sink: Arc<dyn crate::artifact::ArtifactSink>,
        expected_profile_hex8: &str,
    ) -> TestServer {
        let sock = temp_socket(name);
        let handle = {
            let sock = sock.clone();
            let pin = expected_profile_hex8.to_string();
            tokio::spawn(async move {
                let _ = serve_grpc_uds(sock, queue, sink, &pin).await;
            })
        };
        TestServer { sock, handle }
    }

    async fn connect_retry(sock: &Path) -> Channel {
        for _ in 0..200 {
            match connect_grpc_uds(sock.to_path_buf()).await {
                Ok(channel) => return channel,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
        panic!("gRPC client never connected to {}", sock.display());
    }

    #[test]
    fn dispatch_carries_canonical_bytes_and_hash() {
        let mut q = InMemoryQueue::new(Duration::from_secs(LEASE_SECS));
        q.push(Task::new("d", golden_config(), "kv"));
        let task = q.pull().expect("queued task");
        let dispatch = dispatch_of(&task).expect("dispatch");
        assert_eq!(dispatch.task_id, "d");
        assert_eq!(dispatch.workload, "kv");
        assert_eq!(
            dispatch.run_config_hash_hex,
            hash_to_hex(&run_config_hash(&golden_config()).unwrap())
        );
        assert_eq!(
            dispatch.run_config_bytes,
            crate::proto::canonical_bytes(&golden_config()).unwrap()
        );
    }

    #[tokio::test]
    async fn grpc_acquire_lease_returns_preloaded_task() {
        let mut q = InMemoryQueue::new(Duration::from_secs(LEASE_SECS));
        q.push(Task::new("grpc-task", golden_config(), "kv"));
        let server = spawn_server(
            "acquire",
            Arc::new(Mutex::new(q)),
            Arc::new(crate::artifact::NoopSink),
        )
        .await;
        let channel = connect_retry(&server.sock).await;
        let mut client = ControlPlaneClient::new(channel);

        let lease = client
            .acquire_lease(LeaseRequest {
                worker_id: "w1".into(),
                max_tasks: 4,
            })
            .await
            .expect("acquire_lease must succeed")
            .into_inner();
        assert_eq!(lease.tasks.len(), 1);
        assert_eq!(lease.tasks[0].task_id, "grpc-task");
        assert_eq!(lease.tasks[0].workload, "kv");
        assert_eq!(
            lease.tasks[0].run_config_hash_hex,
            hash_to_hex(&run_config_hash(&golden_config()).unwrap())
        );

        // Queue is drained: a second lease returns nothing.
        let empty = client
            .acquire_lease(LeaseRequest {
                worker_id: "w2".into(),
                max_tasks: 4,
            })
            .await
            .expect("second acquire_lease must succeed")
            .into_inner();
        assert!(empty.tasks.is_empty());
    }

    #[tokio::test]
    async fn grpc_upload_result_roundtrip_matches_direct_root() {
        let direct = golden_root_hex();

        // Three identical tasks drive the accept, tamper-reject, and
        // malformed-hex branches of one server session each.
        let mut q = InMemoryQueue::new(Duration::from_secs(LEASE_SECS));
        for id in ["accept-me", "tamper-me", "malformed-me"] {
            q.push(Task::new(id, golden_config(), "kv"));
        }
        let server = spawn_server(
            "upload",
            Arc::new(Mutex::new(q)),
            Arc::new(crate::artifact::NoopSink),
        )
        .await;
        let mut client = ControlPlaneClient::new(connect_retry(&server.sock).await);

        let lease = client
            .acquire_lease(LeaseRequest {
                worker_id: "w1".into(),
                max_tasks: 3,
            })
            .await
            .expect("acquire_lease must succeed")
            .into_inner();
        assert_eq!(lease.tasks.len(), 3);

        // Roundtrip leg: uploading the direct simulation root is accepted.
        let ack = client
            .upload_result(ResultUpload {
                task_id: "accept-me".into(),
                journal_root_hex: direct.clone(),
                steps: 4096,
                ok: true,
                error: String::new(),
            })
            .await
            .expect("upload_result must succeed")
            .into_inner();
        assert_eq!(ack.task_id, "accept-me");
        assert!(ack.accepted, "true journal root must be accepted");

        // Tamper leg: a well-formed but wrong root is rejected.
        let ack = client
            .upload_result(ResultUpload {
                task_id: "tamper-me".into(),
                journal_root_hex: hash_to_hex(&[0xffu8; 32]),
                steps: 4096,
                ok: true,
                error: String::new(),
            })
            .await
            .expect("upload_result must succeed")
            .into_inner();
        assert!(!ack.accepted, "mismatched root must be rejected");

        // Validation leg: malformed hex fails before execution.
        let status = client
            .upload_result(ResultUpload {
                task_id: "malformed-me".into(),
                journal_root_hex: "not-a-hash".into(),
                steps: 4096,
                ok: true,
                error: String::new(),
            })
            .await
            .expect_err("malformed hex must fail the call");
        assert_eq!(status.code(), tonic::Code::InvalidArgument);

        // Unknown task id reports a soft rejection instead of an error.
        let ack = client
            .upload_result(ResultUpload {
                task_id: "ghost".into(),
                journal_root_hex: direct,
                steps: 4096,
                ok: true,
                error: String::new(),
            })
            .await
            .expect("upload_result must succeed")
            .into_inner();
        assert!(!ack.accepted);
    }

    #[tokio::test]
    async fn grpc_extend_ack_and_cancel_delegate_to_queue() {
        let mut q = InMemoryQueue::new(Duration::from_secs(LEASE_SECS));
        q.push(Task::new("lifecycle", golden_config(), "trivial"));
        q.push(Task::new("cancel-me", golden_config(), "trivial"));
        let server = spawn_server(
            "lifecycle",
            Arc::new(Mutex::new(q)),
            Arc::new(crate::artifact::NoopSink),
        )
        .await;
        let mut client = ControlPlaneClient::new(connect_retry(&server.sock).await);

        let lease = client
            .acquire_lease(LeaseRequest {
                worker_id: "w1".into(),
                max_tasks: 2,
            })
            .await
            .expect("acquire_lease must succeed")
            .into_inner();
        assert_eq!(lease.tasks.len(), 2);

        let heartbeat = client
            .extend_lease(LeaseExtend {
                worker_id: "w1".into(),
                task_id: "lifecycle".into(),
                extra_secs: 10,
            })
            .await
            .expect("extend_lease must succeed")
            .into_inner();
        assert!(heartbeat.lease_extended);

        let missing = client
            .extend_lease(LeaseExtend {
                worker_id: "w1".into(),
                task_id: "ghost".into(),
                extra_secs: 10,
            })
            .await
            .expect("extend_lease must succeed")
            .into_inner();
        assert!(!missing.lease_extended);

        let cancel = client
            .cancel_task(CancelTaskRequest {
                task_id: "cancel-me".into(),
                reason: "test".into(),
            })
            .await
            .expect("cancel_task must succeed")
            .into_inner();
        assert_eq!(cancel.task_id, "cancel-me");
        assert!(cancel.cancelled);

        let ack = client
            .ack_task(TaskAck {
                task_id: "lifecycle".into(),
                worker_id: "w1".into(),
            })
            .await
            .expect("ack_task must succeed")
            .into_inner();
        assert_eq!(ack.task_id, "lifecycle");
        assert!(ack.accepted);

        let progress = client
            .report_progress(TaskProgress {
                task_id: "lifecycle".into(),
                phase: "sim".into(),
                counters: std::collections::HashMap::from([("steps".to_string(), 42)]),
            })
            .await
            .expect("report_progress must succeed")
            .into_inner();
        assert_eq!(progress.task_id, "lifecycle");
        assert!(progress.accepted);
    }

    #[tokio::test]
    async fn grpc_artifact_service_brokers_upload_handshake() {
        let server = spawn_server(
            "artifact",
            Arc::new(Mutex::new(InMemoryQueue::new(Duration::from_secs(
                LEASE_SECS,
            )))),
            Arc::new(crate::artifact::NoopSink),
        )
        .await;
        let mut client = crate::r#gen::artifact_service_client::ArtifactServiceClient::new(
            connect_retry(&server.sock).await,
        );

        let resp = client
            .get_upload_url(UploadUrlRequest {
                task_id: "art-task".into(),
                artifact_name: "certificate.json".into(),
            })
            .await
            .expect("get_upload_url must succeed")
            .into_inner();
        // The wire contract pins the direct-to-storage method.
        assert_eq!(resp.method, "PUT");
        assert!(resp.url.contains("art-task"));
        assert!(resp.url.contains("certificate.json"));

        let ack = client
            .confirm_upload(ConfirmUploadRequest {
                task_id: "art-task".into(),
                artifact_name: "certificate.json".into(),
                checksum_hex: crate::proto::hash_to_hex(&[7u8; 32]),
            })
            .await
            .expect("confirm_upload must succeed")
            .into_inner();
        assert_eq!(ack.task_id, "art-task");
        assert!(ack.accepted);
    }

    #[tokio::test]
    async fn grpc_artifact_service_maps_sink_errors_to_internal_status() {
        struct FailingSink;
        impl crate::artifact::ArtifactSink for FailingSink {
            fn get_upload_url(
                &self,
                _: &str,
                _: &str,
            ) -> Result<String, crate::artifact::ArtifactError> {
                Err(crate::artifact::ArtifactError::Contract(
                    crate::artifact::Phase::UrlFetch,
                    "control plane down",
                ))
            }
            fn confirm(
                &self,
                _: &str,
                _: &str,
                _: &str,
            ) -> Result<(), crate::artifact::ArtifactError> {
                Err(crate::artifact::ArtifactError::Contract(
                    crate::artifact::Phase::Confirm,
                    "rejected",
                ))
            }
            fn upload(
                &self,
                task_id: &str,
                name: &str,
                _bytes: &[u8],
                _checksum_hex: &str,
            ) -> Result<String, crate::artifact::ArtifactError> {
                self.get_upload_url(task_id, name)
            }
        }

        let server = spawn_server(
            "artifact-fail",
            Arc::new(Mutex::new(InMemoryQueue::new(Duration::from_secs(
                LEASE_SECS,
            )))),
            Arc::new(FailingSink),
        )
        .await;
        let mut client = crate::r#gen::artifact_service_client::ArtifactServiceClient::new(
            connect_retry(&server.sock).await,
        );

        let status = client
            .get_upload_url(UploadUrlRequest {
                task_id: "t".into(),
                artifact_name: "certificate.json".into(),
            })
            .await
            .expect_err("sink failure must surface as a gRPC status");
        assert_eq!(status.code(), tonic::Code::Internal);

        let status = client
            .confirm_upload(ConfirmUploadRequest {
                task_id: "t".into(),
                artifact_name: "certificate.json".into(),
                checksum_hex: "ab".into(),
            })
            .await
            .expect_err("sink rejection must surface as a gRPC status");
        assert_eq!(status.code(), tonic::Code::Internal);
    }

    /// The declared `Health.Check` RPC must be registered and answer
    /// `serving`, and must refuse service names this daemon does not serve.
    #[tokio::test]
    async fn grpc_health_check_reports_serving() {
        let server = spawn_server(
            "health",
            Arc::new(Mutex::new(InMemoryQueue::new(Duration::from_secs(
                LEASE_SECS,
            )))),
            Arc::new(crate::artifact::NoopSink),
        )
        .await;
        let mut client =
            crate::r#gen::health_client::HealthClient::new(connect_retry(&server.sock).await);

        // Overall liveness: empty service name answers serving.
        let reply = client
            .check(HealthCheck {
                service: String::new(),
            })
            .await
            .expect("health check must succeed")
            .into_inner();
        assert!(reply.serving, "a serving daemon must report serving");

        // A served service name answers serving too.
        let reply = client
            .check(HealthCheck {
                service: "ledger.control.v1.ControlPlane".into(),
            })
            .await
            .expect("served service name must be accepted")
            .into_inner();
        assert!(reply.serving);

        // An unknown service name is refused, not silently answered.
        let status = client
            .check(HealthCheck {
                service: "ledger.control.v1.NotServed".into(),
            })
            .await
            .expect_err("unknown service must be refused");
        assert_eq!(status.code(), tonic::Code::NotFound);
    }

    /// Same-process gRPC client passes the peer-credential gate: the
    /// kernel reports equal uids for both socket ends, so every roundtrip
    /// in this suite doubles as the authz allow-path proof. This test pins
    /// that behavior explicitly.
    #[tokio::test]
    async fn grpc_same_process_client_passes_uid_gate() {
        let server = spawn_server(
            "uid-gate",
            Arc::new(Mutex::new(InMemoryQueue::new(Duration::from_secs(
                LEASE_SECS,
            )))),
            Arc::new(crate::artifact::NoopSink),
        )
        .await;
        let mut client = ControlPlaneClient::new(connect_retry(&server.sock).await);
        let lease = client
            .acquire_lease(LeaseRequest {
                worker_id: "same-uid".into(),
                max_tasks: 1,
            })
            .await
            .expect("same-process peer must not be rejected by the uid gate");
        assert!(lease.into_inner().tasks.is_empty());
    }

    #[tokio::test]
    async fn grpc_register_worker_rejects_mismatched_profile_pin() {
        let mut q = InMemoryQueue::new(Duration::from_secs(LEASE_SECS));
        q.push(Task::new("leased", golden_config(), "trivial"));
        let server = spawn_server_with_pin(
            "register-pin",
            Arc::new(Mutex::new(q)),
            Arc::new(crate::artifact::NoopSink),
            "deadbeef",
        )
        .await;
        let mut client = WorkerControlClient::new(connect_retry(&server.sock).await);

        // Foreign profile fingerprint: soft refusal with a reason.
        let ack = client
            .register_worker(RegisterWorkerRequest {
                identity: Some(crate::r#gen::WorkerIdentity {
                    worker_id: "impostor".into(),
                    version: "0.1.0".into(),
                }),
                profile: Some(crate::r#gen::RuntimeProfile {
                    fingerprint_hex: hash_to_hex(&[0xaa; 32]),
                    ..Default::default()
                }),
            })
            .await
            .expect("register_worker must answer, not fail");
        let ack = ack.into_inner();
        assert!(!ack.accepted, "mismatched profile must be refused");
        let reason = ack.reason.clone();
        assert!(reason.contains("profile mismatch"), "got {reason}");
        assert_eq!(ack.assigned_worker_id, "");

        // Full digest carrying the pinned prefix is accepted and echoed.
        let pinned_full = format!("deadbeef{}", "00".repeat(28));
        let ack = client
            .register_worker(RegisterWorkerRequest {
                identity: Some(crate::r#gen::WorkerIdentity {
                    worker_id: "honest".into(),
                    version: "0.1.0".into(),
                }),
                profile: Some(crate::r#gen::RuntimeProfile {
                    fingerprint_hex: pinned_full,
                    ..Default::default()
                }),
            })
            .await
            .expect("register_worker must succeed");
        let ack = ack.into_inner();
        assert!(ack.accepted);
        assert_eq!(ack.assigned_worker_id, "honest");

        // Legacy registrant without a profile stays admitted.
        let ack = client
            .register_worker(RegisterWorkerRequest {
                identity: Some(crate::r#gen::WorkerIdentity {
                    worker_id: "legacy".into(),
                    version: String::new(),
                }),
                profile: None,
            })
            .await
            .expect("register_worker must succeed");
        let ack = ack.into_inner();
        assert!(ack.accepted);
        assert_eq!(ack.assigned_worker_id, "legacy");
    }

    #[tokio::test]
    async fn grpc_heartbeat_and_fail_task_delegate_to_queue() {
        let mut q = InMemoryQueue::new(Duration::from_secs(LEASE_SECS));
        q.push(Task::new("hb", golden_config(), "trivial"));
        q.push(Task::new("doomed", golden_config(), "trivial"));
        let queue = Arc::new(Mutex::new(q));
        let server = spawn_server_with_pin(
            "worker-control",
            Arc::clone(&queue),
            Arc::new(crate::artifact::NoopSink),
            "deadbeef",
        )
        .await;
        let mut client = WorkerControlClient::new(connect_retry(&server.sock).await);

        // Lease both tasks so heartbeat and failure routing find live leases.
        let leased: Vec<String> = {
            let mut q = queue.lock().await;
            let mut ids = Vec::new();
            while let Some(task) = q.pull() {
                ids.push(task.id);
            }
            ids
        };
        assert_eq!(leased, vec!["hb".to_string(), "doomed".to_string()]);

        let ack = client
            .heartbeat(HeartbeatRequest {
                worker_id: "w1".into(),
                task_id: "hb".into(),
                attempts: 1,
            })
            .await
            .expect("heartbeat must succeed")
            .into_inner();
        assert!(ack.lease_extended, "live lease must heartbeat true");

        let missing = client
            .heartbeat(HeartbeatRequest {
                worker_id: "w1".into(),
                task_id: "ghost".into(),
                attempts: 0,
            })
            .await
            .expect("heartbeat must succeed")
            .into_inner();
        assert!(!missing.lease_extended);

        let ack = client
            .fail_task(ResultUpload {
                task_id: "doomed".into(),
                journal_root_hex: String::new(),
                steps: 0,
                ok: false,
                error: "sim exploded".into(),
            })
            .await
            .expect("fail_task must succeed")
            .into_inner();
        assert!(
            ack.accepted,
            "leased task must route through failure accounting"
        );

        let unknown = client
            .fail_task(ResultUpload {
                task_id: "ghost".into(),
                journal_root_hex: String::new(),
                steps: 0,
                ok: false,
                error: String::new(),
            })
            .await
            .expect("fail_task must succeed")
            .into_inner();
        assert!(!unknown.accepted);
    }

    #[tokio::test]
    async fn grpc_complete_task_requires_deterministic_root() {
        let direct = golden_root_hex();
        let mut q = InMemoryQueue::new(Duration::from_secs(LEASE_SECS));
        for id in ["complete-me", "tampered"] {
            q.push(Task::new(id, golden_config(), "kv"));
        }
        let server = spawn_server(
            "complete",
            Arc::new(Mutex::new(q)),
            Arc::new(crate::artifact::NoopSink),
        )
        .await;
        let mut client = WorkerControlClient::new(connect_retry(&server.sock).await);

        let ack = client
            .complete_task(ResultUpload {
                task_id: "complete-me".into(),
                journal_root_hex: direct.clone(),
                steps: 4096,
                ok: true,
                error: String::new(),
            })
            .await
            .expect("complete_task must succeed")
            .into_inner();
        assert!(ack.accepted, "true journal root must be accepted");

        let ack = client
            .complete_task(ResultUpload {
                task_id: "tampered".into(),
                journal_root_hex: hash_to_hex(&[0xffu8; 32]),
                steps: 4096,
                ok: true,
                error: String::new(),
            })
            .await
            .expect("complete_task must succeed")
            .into_inner();
        assert!(!ack.accepted, "wrong root must be rejected");
    }

    #[tokio::test]
    async fn grpc_oversized_message_hits_decode_cap() {
        let server = spawn_server(
            "cap",
            Arc::new(Mutex::new(InMemoryQueue::new(Duration::from_secs(
                LEASE_SECS,
            )))),
            Arc::new(crate::artifact::NoopSink),
        )
        .await;
        // First leg builds an uncapped channel deliberately so the 3 MiB
        // body reaches the server and hits its 1 MiB decode cap. The
        // production helper `connect_grpc_uds` caps both directions at 1 MiB.
        let mut uncapped_channel = None;
        for _ in 0..200 {
            let uri = format!("unix://{}", server.sock.display());
            match Endpoint::from_shared(uri)
                .expect("valid uri")
                .connect()
                .await
            {
                Ok(ch) => {
                    uncapped_channel = Some(ch);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
        let uncapped_channel = uncapped_channel.expect("uncapped connect must succeed");
        let mut client = ControlPlaneClient::new(uncapped_channel);

        // A journal_root_hex far beyond 1 MiB exceeds the server decode cap.
        let oversized = "a".repeat(3 * MAX_MESSAGE_SIZE);
        let status = client
            .upload_result(ResultUpload {
                task_id: "cap".into(),
                journal_root_hex: oversized,
                steps: 0,
                ok: true,
                error: String::new(),
            })
            .await
            .expect_err("oversized message must be rejected at decode");
        // tonic 0.14 reports a decode-side size violation as OutOfRange.
        assert_eq!(status.code(), tonic::Code::OutOfRange);

        // Capped clients still pass normal-sized traffic.
        let mut capped_client = ControlPlaneClient::new(connect_retry(&server.sock).await)
            .max_decoding_message_size(MAX_MESSAGE_SIZE)
            .max_encoding_message_size(MAX_MESSAGE_SIZE);
        let lease = capped_client
            .acquire_lease(LeaseRequest {
                worker_id: "cap-ok".into(),
                max_tasks: 1,
            })
            .await
            .expect("capped normal message must pass");
        assert!(lease.into_inner().tasks.is_empty());
    }

    #[tokio::test]
    async fn grpc_upload_result_wrong_root_requeues_via_report_failure() {
        // Wrong root must not silently consume the task; the attempt
        // budget charges one try via `record_taken_task_failure`.
        let mut q = InMemoryQueue::new(Duration::from_secs(LEASE_SECS));
        let mut task = Task::new("requeue-me", golden_config(), "kv");
        task.max_attempts = 2;
        q.push(task);
        let queue = Arc::new(Mutex::new(q));
        let server = spawn_server(
            "requeue",
            Arc::clone(&queue),
            Arc::new(crate::artifact::NoopSink),
        )
        .await;
        let mut client = ControlPlaneClient::new(connect_retry(&server.sock).await);
        // First wrong root: soft rejection but task requeues with attempts=1.
        let ack = client
            .upload_result(ResultUpload {
                task_id: "requeue-me".into(),
                journal_root_hex: hash_to_hex(&[0xffu8; 32]),
                steps: 4096,
                ok: true,
                error: String::new(),
            })
            .await
            .expect("upload_result must answer")
            .into_inner();
        assert!(!ack.accepted, "wrong root must be rejected");
        // Task reappears via the attempt budget.
        let leased = queue.lock().await.failed().len();
        assert_eq!(leased, 0, "first failure must not exhaust budget");
        // Acquire the requeued task to prove it is back in the queue.
        let lease = client
            .acquire_lease(LeaseRequest {
                worker_id: "w1".into(),
                max_tasks: 1,
            })
            .await
            .expect("acquire after requeue must succeed")
            .into_inner();
        assert_eq!(
            lease.tasks.len(),
            1,
            "task must requeue on first wrong root"
        );
        assert_eq!(lease.tasks[0].task_id, "requeue-me");
        // Second wrong root exhausts the budget.
        let ack = client
            .upload_result(ResultUpload {
                task_id: "requeue-me".into(),
                journal_root_hex: hash_to_hex(&[0xeeu8; 32]),
                steps: 4096,
                ok: true,
                error: String::new(),
            })
            .await
            .expect("second upload_result must answer")
            .into_inner();
        assert!(!ack.accepted);
        // After exhaustion the task sits in the failed list, not the queue.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let failed = queue.lock().await.failed();
        assert_eq!(failed.len(), 1, "exhausted task must be in failed list");
        assert_eq!(failed[0].id, "requeue-me");
        assert_eq!(failed[0].attempts, 2);
    }
}
