// ledger-lint:allow - host daemon / non-sim passthrough, like TokioBackend

//! Outbound control-plane session client for `ledger.control.v2`.
//! Pure client: one authenticated session stream; execution mirrors
//! [`crate::worker::execute_task`].

use std::path::Path;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint};

use crate::r#gen::control_plane_service_client::ControlPlaneServiceClient;
use crate::r#gen::{
    CancelTask, Heartbeat, ResultUpload, RuntimeProfile, SessionRequest, SessionResponse,
    TaskDispatch, WorkerHello, session_request,
};
use crate::queue::Task;
use crate::worker::{TaskFailure, WorkerError, WorkerResult, execute_task};

/// Hard cap for one protobuf message either way.
pub const MAX_MESSAGE_SIZE: usize = 1 << 20;

/// Errors from the outbound control-plane session.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The endpoint could not be dialed or the handshake stream failed.
    #[error("control-plane session: {0}")]
    Transport(#[from] tonic::transport::Error),
    /// The session stream broke mid-flight.
    #[error("control-plane session stream: {0}")]
    Stream(#[from] tonic::Status),
    /// The control plane rejected the worker's hello.
    #[error("control-plane rejected session: {reason}")]
    Rejected {
        /// Rejection reason from the control plane.
        reason: String,
    },
    /// The outbound request channel closed.
    #[error("control-plane session request channel closed")]
    RequestChannelClosed,
    /// A task dispatch violated a validation bound; the task fails closed.
    #[error("invalid dispatch for task {task_id}: {reason}")]
    InvalidDispatch {
        /// Identifier of the rejected task.
        task_id: String,
        /// Validation failure reason.
        reason: String,
    },
    /// The worker's own identity failed its encoding caps; the session
    /// cannot open with an unhashable identity.
    #[error("worker identity encoding failed: {0}")]
    IdentityEncoding(#[from] ledger_journal::JournalError),
}

/// Dial the control-plane endpoint and open the session stream.
///
/// # Errors
/// Returns transport/stream errors when unreachable or unopenable.
pub async fn open_session(
    endpoint: &str,
) -> Result<
    (
        mpsc::Sender<SessionRequest>,
        tonic::Streaming<SessionResponse>,
    ),
    SessionError,
> {
    let channel: Channel = Endpoint::from_shared(endpoint.to_string())?
        .max_frame_size(Some(MAX_MESSAGE_SIZE as u32))
        .connect()
        .await?;
    let mut client = ControlPlaneServiceClient::new(channel);
    let (tx, rx) = mpsc::channel::<SessionRequest>(32);
    let response = client
        .session(ReceiverStream::new(rx))
        .await
        .map_err(SessionError::Stream)?;
    Ok((tx, response.into_inner()))
}

/// Wire prefix for a framed `EntryHash`.
pub const FRAMED_HASH_PREFIX: [u8; 2] = [0x1e, 0x20];

/// Wire length of one framed `EntryHash`.
pub const FRAMED_HASH_LEN: usize = 34;

/// Encode an internal digest as framed wire bytes.
fn encode_framed_identity(hash: &ledger_format::EntryHash) -> Vec<u8> {
    let framed = hash.to_framed_bytes();
    debug_assert_eq!(framed.len(), FRAMED_HASH_LEN);
    debug_assert_eq!(&framed[..2], &FRAMED_HASH_PREFIX);
    framed.to_vec()
}

/// Decode framed wire bytes into an internal digest (`None` fails closed).
fn decode_framed_identity(bytes: &[u8]) -> Option<ledger_format::EntryHash> {
    if bytes.len() != FRAMED_HASH_LEN {
        return None;
    }
    ledger_format::EntryHash::from_framed_bytes(bytes).ok()
}

/// Map a [`TaskDispatch`] onto the queue task model. Malformed fails closed.
///
/// # Errors
/// Returns [`SessionError::InvalidDispatch`] for bad bounds or config.
pub fn task_from_dispatch(dispatch: TaskDispatch) -> Result<Task, SessionError> {
    if dispatch.task_id.len() > 4096 {
        return Err(SessionError::InvalidDispatch {
            task_id: dispatch.task_id,
            reason: "task_id exceeds 4096 bytes".to_string(),
        });
    }
    if dispatch.workload.len() > 4096 {
        return Err(SessionError::InvalidDispatch {
            task_id: dispatch.task_id,
            reason: "workload exceeds 4096 bytes".to_string(),
        });
    }
    if dispatch.run_config_hash_hex.len() > 128 {
        return Err(SessionError::InvalidDispatch {
            task_id: dispatch.task_id,
            reason: "run_config_hash_hex exceeds 128 bytes".to_string(),
        });
    }
    crate::proto::hex_to_hash(&dispatch.run_config_hash_hex).map_err(|e| {
        SessionError::InvalidDispatch {
            task_id: dispatch.task_id.clone(),
            reason: format!("run_config_hash_hex: {e}"),
        }
    })?;
    let run_config = ledger_sim::from_canonical_bytes(&dispatch.run_config_bytes).map_err(|e| {
        SessionError::InvalidDispatch {
            task_id: dispatch.task_id.clone(),
            reason: format!("run_config_bytes: {e}"),
        }
    })?;
    let mut task = Task::new(dispatch.task_id, run_config, dispatch.workload);
    task.run_config_hash = crate::proto::hex_to_hash(&dispatch.run_config_hash_hex).ok();
    // The dispatch carries the pinned identity digest (B2) in framed form;
    // the worker compares its own assembly against it before executing.
    if !dispatch.execution_identity.is_empty() {
        let Some(pin) = decode_framed_identity(&dispatch.execution_identity) else {
            return Err(SessionError::InvalidDispatch {
                task_id: task.id,
                reason: "execution_identity must be 34 framed bytes".to_string(),
            });
        };
        task.execution_identity = Some(pin);
    }
    Ok(task)
}

/// Build the worker hello from the compiled identity and runtime profile.
///
/// # Errors
/// Returns [`SessionError::IdentityEncoding`] when unhashable.
pub fn worker_hello(worker_id: &str, version: &str) -> Result<WorkerHello, SessionError> {
    let profile = RuntimeProfile {
        engine_sha: crate::RuntimeProfile::detect().engine_sha.clone(),
        toolchain: crate::RuntimeProfile::detect().toolchain.clone(),
        features: crate::RuntimeProfile::detect().features.clone(),
        sut_hashes: crate::RuntimeProfile::detect().sut_hashes.clone(),
        cpu_topology: crate::RuntimeProfile::detect().cpu_topology.clone(),
        env_sanitation: crate::RuntimeProfile::detect().env_sanitation.clone(),
        fingerprint_hex: crate::RuntimeProfile::detect().fingerprint_hex8(),
    };
    Ok(WorkerHello {
        worker_id: worker_id.to_string(),
        version: version.to_string(),
        // The worker's own build identity in framed form, when the build
        // data is complete.
        execution_identity: worker_build_identity_digest()?
            .map(|h| encode_framed_identity(&h))
            .unwrap_or_default(),
        profile: Some(profile),
    })
}

/// The worker's build-segment identity digest (`None` when incomplete).
fn worker_build_identity_digest() -> Result<Option<ledger_format::EntryHash>, SessionError> {
    use ledger_explorer::identity::{EngineBuild, IdentityContext};
    let build = EngineBuild::detect();
    let context = IdentityContext {
        sut_revision: None,
        sut_dirty: false,
        sut_artifact_digest: None,
        guest_digest: None,
        workload_id: String::new(),
        program_digest: ledger_format::EntryHash(*blake3::hash(b"").as_bytes()),
        input_digests: Vec::new(),
        backend: "sim".to_string(),
        runtime_profile: crate::RuntimeProfile::detect().fingerprint_hex8(),
        run_config_digest: ledger_format::EntryHash([0u8; 32]),
        seed_tree_root: ledger_format::EntryHash([0u8; 32]),
        faultspec_digest: None,
        oracle_version: None,
        support_provider_version: None,
        resource_limits: ledger_journal::ResourceLimits { max_steps: 0 },
    };
    Ok(ledger_explorer::identity::assemble_identity(&build, &context).digest()?)
}

/// Result of running one assigned task over the session.
#[derive(Debug)]
pub enum TaskOutcome {
    /// The task completed and the result was uploaded.
    Completed(WorkerResult),
    /// The task failed and the failure was routed through the funnel.
    Failed(WorkerError),
}

/// Run one assigned task and upload its result, heartbeating while it runs.
///
/// # Errors
/// Returns [`SessionError`] when the session stream itself fails.
pub async fn run_assigned_task(
    tx: &mpsc::Sender<SessionRequest>,
    task: Task,
    worker_id: &str,
    heartbeat: Duration,
) -> Result<TaskOutcome, SessionError> {
    let task_id = task.id.clone();
    let attempts = task.attempts;
    let mut exec = tokio::task::spawn_blocking(move || execute_task(task));
    let mut ticker = tokio::time::interval(heartbeat.max(Duration::from_millis(1)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Send the first heartbeat immediately: the assignment itself proves the
    // worker is live, so a liveness signal is on the wire before any task can
    // finish, no matter how fast it runs.
    let hello_hb = SessionRequest {
        message: Some(session_request::Message::Heartbeat(Heartbeat {
            worker_id: worker_id.to_string(),
            task_id: task_id.clone(),
            attempts,
        })),
    };
    if tx.send(hello_hb).await.is_err() {
        return Err(SessionError::RequestChannelClosed);
    }
    let result = loop {
        tokio::select! {
            biased;
            _ = ticker.tick() => {
                let msg = SessionRequest {
                    message: Some(session_request::Message::Heartbeat(Heartbeat {
                        worker_id: worker_id.to_string(),
                        task_id: task_id.clone(),
                        attempts,
                    })),
                };
                if tx.send(msg).await.is_err() {
                    return Err(SessionError::RequestChannelClosed);
                }
            }
            res = &mut exec => break res,
        }
    };
    let outcome = match result {
        Ok(Ok(ok)) => {
            let upload = ResultUpload {
                task_id: task_id.clone(),
                journal_root_hex: crate::proto::hash_to_hex(&ok.journal_root),
                steps: ok.steps as u64,
                ok: true,
                error: String::new(),
                execution_identity: ok
                    .execution_identity
                    .as_ref()
                    .map(encode_framed_identity)
                    .unwrap_or_default(),
            };
            let msg = SessionRequest {
                message: Some(session_request::Message::Result(upload)),
            };
            if tx.send(msg).await.is_err() {
                return Err(SessionError::RequestChannelClosed);
            }
            eprintln!("WORKER-SENT: upload {task_id}");
            TaskOutcome::Completed(ok)
        }
        Ok(Err(err)) => {
            let failure = TaskFailure::Execution(err);
            upload_failure(tx, &task_id, &failure).await?;
            TaskOutcome::Failed(WorkerError::TaskFailed {
                task_id,
                attempts: 0,
                max_attempts: 0,
                detail: failure.message(),
            })
        }
        Err(join_err) => {
            let failure = TaskFailure::Join(join_err.to_string());
            upload_failure(tx, &task_id, &failure).await?;
            TaskOutcome::Failed(WorkerError::TaskFailed {
                task_id,
                attempts: 0,
                max_attempts: 0,
                detail: failure.message(),
            })
        }
    };
    Ok(outcome)
}

/// Upload a failed task through the session funnel.
pub async fn upload_failure(
    tx: &mpsc::Sender<SessionRequest>,
    task_id: &str,
    failure: &TaskFailure,
) -> Result<(), SessionError> {
    let upload = ResultUpload {
        task_id: task_id.to_string(),
        journal_root_hex: String::new(),
        steps: 0,
        ok: false,
        error: failure.message(),
        execution_identity: Vec::new(),
    };
    let msg = SessionRequest {
        message: Some(session_request::Message::Result(upload)),
    };
    if tx.send(msg).await.is_err() {
        return Err(SessionError::RequestChannelClosed);
    }
    Ok(())
}

/// Read one inbound session message.
pub async fn next_response(
    rx: &mut tonic::Streaming<SessionResponse>,
) -> Result<Option<SessionResponse>, SessionError> {
    rx.message().await.map_err(SessionError::Stream)
}

/// Handle a control-plane cancel through the funnel.
pub async fn handle_cancel(
    tx: &mpsc::Sender<SessionRequest>,
    cancel: CancelTask,
) -> Result<(), SessionError> {
    let failure = TaskFailure::Cancelled(cancel.reason);
    upload_failure(tx, &cancel.task_id, &failure).await
}

/// Resolve the assigned worker id from the hello ack.
pub fn session_ack_worker_id(ack: &crate::r#gen::SessionAck) -> Result<String, SessionError> {
    if !ack.accepted {
        return Err(SessionError::Rejected {
            reason: ack.reason.clone(),
        });
    }
    Ok(ack.assigned_worker_id.clone())
}

/// Default endpoint for a local control plane over a Unix socket.
pub fn unix_endpoint(path: &Path) -> Result<String, SessionError> {
    let uri = format!("unix://{}", path.display());
    Endpoint::from_shared(uri.clone())
        .map(|_| uri)
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_sim::RunConfig;

    fn golden_dispatch() -> TaskDispatch {
        let cfg = RunConfig::builder()
            .seed(ledger_format::EntryHash([7u8; 32]))
            .build();
        let hash = crate::proto::run_config_hash(&cfg).unwrap();
        TaskDispatch {
            task_id: "t1".to_string(),
            run_config_bytes: crate::proto::canonical_bytes(&cfg).unwrap(),
            workload: "kv".to_string(),
            run_config_hash_hex: crate::proto::hash_to_hex(&hash),
            execution_identity: super::encode_framed_identity(&ledger_format::EntryHash(
                [0xabu8; 32],
            )),
        }
    }

    #[test]
    fn dispatch_round_trips_into_task() {
        let task = task_from_dispatch(golden_dispatch()).expect("dispatch must parse");
        assert_eq!(task.id, "t1");
        assert_eq!(task.workload, "kv");
        assert_eq!(
            task.execution_identity,
            Some(ledger_format::EntryHash([0xabu8; 32]))
        );
        assert_eq!(
            task.run_config_hash,
            crate::proto::run_config_hash(&task.run_config).ok()
        );
    }

    #[test]
    fn dispatch_rejects_bad_hash_hex() {
        let mut d = golden_dispatch();
        d.run_config_hash_hex = "zz".repeat(32);
        assert!(matches!(
            task_from_dispatch(d),
            Err(SessionError::InvalidDispatch { .. })
        ));
    }

    #[test]
    fn dispatch_rejects_oversized_task_id() {
        let mut d = golden_dispatch();
        d.task_id = "x".repeat(5000);
        assert!(matches!(
            task_from_dispatch(d),
            Err(SessionError::InvalidDispatch { .. })
        ));
    }

    #[test]
    fn dispatch_rejects_bad_identity_len() {
        let mut d = golden_dispatch();
        d.execution_identity = vec![0u8; 7];
        assert!(matches!(
            task_from_dispatch(d),
            Err(SessionError::InvalidDispatch { .. })
        ));
    }

    #[test]
    fn dispatch_rejects_raw_32_byte_identity_and_bad_prefix() {
        // Raw 32-byte digests no longer decode: the wire carries 34 framed
        // bytes, so a raw digest fails the length check.
        let mut raw = golden_dispatch();
        raw.execution_identity = vec![0xabu8; 32];
        assert!(matches!(
            task_from_dispatch(raw),
            Err(SessionError::InvalidDispatch { .. })
        ));
        // Correct length with a wrong prefix fails as well.
        let mut bad_prefix = golden_dispatch();
        bad_prefix.execution_identity = vec![0u8; 34];
        assert!(matches!(
            task_from_dispatch(bad_prefix),
            Err(SessionError::InvalidDispatch { .. })
        ));
    }

    #[test]
    fn hello_carries_identity_when_build_complete() {
        let hello = worker_hello("w1", "0.1.0").expect("hello builds");
        assert_eq!(hello.worker_id, "w1");
        assert_eq!(hello.version, "0.1.0");
        // The identity is either the complete 34-byte framed digest or empty
        // for an incomplete dev build; both are contract-legal.
        assert!(hello.execution_identity.is_empty() || hello.execution_identity.len() == 34);
        if !hello.execution_identity.is_empty() {
            assert_eq!(&hello.execution_identity[0..2], &super::FRAMED_HASH_PREFIX);
        }
        let profile = hello.profile.expect("profile");
        assert_eq!(profile.fingerprint_hex.len(), 8);
    }

    #[test]
    fn ack_rejects_rejected_session() {
        let ack = crate::r#gen::SessionAck {
            accepted: false,
            assigned_worker_id: String::new(),
            reason: "build rejected".to_string(),
        };
        assert!(matches!(
            session_ack_worker_id(&ack),
            Err(SessionError::Rejected { .. })
        ));
    }
}
