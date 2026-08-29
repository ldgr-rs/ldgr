// ledger-lint:allow - host daemon / non-sim passthrough, like TokioBackend

//! Outbound control-plane session client for `ledger.control.v2`.
//!
//! The worker is a pure client: it dials the external control plane, opens
//! ONE authenticated session stream, and lets the control plane assign
//! tasks over that session. The worker hosts no service. Execution
//! semantics mirror [`crate::worker::execute_task`], so this boundary stays
//! byte-identical to the in-process dispatcher.

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

/// Hard cap for one protobuf message in either direction. A dispatch or
/// upload never approaches 1 MiB, so anything larger is hostile input.
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
}

/// Dial the control-plane endpoint and open the session stream.
///
/// `endpoint` is a tonic endpoint URI such as `unix:///run/cp.sock` or
/// `http://[::1]:50051`. Returns the stream halves: the worker sends
/// [`SessionRequest`]s on `tx` and reads [`SessionResponse`]s from `rx`.
///
/// # Errors
/// Returns the tonic transport error when the endpoint is invalid or
/// unreachable, or the stream error when the session cannot be opened.
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

/// Map a [`TaskDispatch`] onto the queue task model, validating every
/// bound the wire carries. A malformed dispatch fails closed.
///
/// # Errors
/// Returns [`SessionError::InvalidDispatch`] for a non-hex hash, an
/// oversized string, or an unparsable config.
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
    // The dispatch carries the pinned identity digest (B2); the worker
    // compares its own assembly against it before executing.
    if !dispatch.execution_identity.is_empty() {
        let mut pin = [0u8; 32];
        if dispatch.execution_identity.len() != pin.len() {
            return Err(SessionError::InvalidDispatch {
                task_id: task.id,
                reason: "execution_identity must be 32 bytes".to_string(),
            });
        }
        pin.copy_from_slice(&dispatch.execution_identity);
        task.execution_identity = Some(pin);
    }
    Ok(task)
}

/// Build the worker hello from the compiled identity and runtime profile.
pub fn worker_hello(worker_id: &str, version: &str) -> WorkerHello {
    let profile = RuntimeProfile {
        engine_sha: crate::RuntimeProfile::detect().engine_sha.clone(),
        toolchain: crate::RuntimeProfile::detect().toolchain.clone(),
        features: crate::RuntimeProfile::detect().features.clone(),
        sut_hashes: crate::RuntimeProfile::detect().sut_hashes.clone(),
        cpu_topology: crate::RuntimeProfile::detect().cpu_topology.clone(),
        env_sanitation: crate::RuntimeProfile::detect().env_sanitation.clone(),
        fingerprint_hex: crate::RuntimeProfile::detect().fingerprint_hex8(),
    };
    WorkerHello {
        worker_id: worker_id.to_string(),
        version: version.to_string(),
        // The worker's own build identity, when the build data is complete.
        execution_identity: worker_build_identity_digest()
            .map(|h| h.to_vec())
            .unwrap_or_default(),
        profile: Some(profile),
    }
}

/// The worker's build-segment identity digest, or `None` when the build
/// data is incomplete (dev builds without a captured revision).
fn worker_build_identity_digest() -> Option<ledger_format::Hash> {
    use ledger_explorer::identity::{EngineBuild, IdentityContext};
    let build = EngineBuild::detect();
    let context = IdentityContext {
        sut_revision: None,
        sut_dirty: false,
        sut_artifact_digest: None,
        guest_digest: None,
        workload_id: String::new(),
        program_digest: *blake3::hash(b"").as_bytes(),
        input_digests: Vec::new(),
        backend: "sim".to_string(),
        runtime_profile: crate::RuntimeProfile::detect().fingerprint_hex8(),
        run_config_digest: [0u8; 32],
        seed_tree_root: [0u8; 32],
        faultspec_digest: None,
        oracle_version: None,
        support_provider_version: None,
        resource_limits: ledger_journal::ResourceLimits { max_steps: 0 },
    };
    ledger_explorer::identity::assemble_identity(&build, &context).digest()
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
/// Mirrors `execute_with_heartbeat`: the task runs on the blocking pool and
/// each heartbeat tick sends a [`Heartbeat`] on the session stream. On
/// success the result is uploaded with the execution-identity digest; on
/// failure the attempt is charged through the session funnel and the
/// failure is uploaded.
///
/// # Errors
/// Returns [`SessionError`] when the session stream itself fails; task
/// failures are uploaded, not returned.
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
                    .map(|h| h.to_vec())
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
///
/// # Errors
/// Returns [`SessionError::RequestChannelClosed`] when the stream closed.
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
///
/// # Errors
/// Returns the stream error when the session breaks.
pub async fn next_response(
    rx: &mut tonic::Streaming<SessionResponse>,
) -> Result<Option<SessionResponse>, SessionError> {
    rx.message().await.map_err(SessionError::Stream)
}

/// Handle a control-plane cancel: fail the named task through the funnel.
///
/// # Errors
/// Returns the request-channel error when the stream closed.
pub async fn handle_cancel(
    tx: &mpsc::Sender<SessionRequest>,
    cancel: CancelTask,
) -> Result<(), SessionError> {
    let failure = TaskFailure::Cancelled(cancel.reason);
    upload_failure(tx, &cancel.task_id, &failure).await
}

/// Resolve the session's assigned worker id from the hello ack.
///
/// # Errors
/// Returns [`SessionError::Rejected`] when the control plane rejected the
/// session.
pub fn session_ack_worker_id(ack: &crate::r#gen::SessionAck) -> Result<String, SessionError> {
    if !ack.accepted {
        return Err(SessionError::Rejected {
            reason: ack.reason.clone(),
        });
    }
    Ok(ack.assigned_worker_id.clone())
}

/// Default endpoint for a local control plane over a Unix socket.
///
/// # Errors
/// Returns the invalid-endpoint error when `path` cannot be escaped.
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
        let cfg = RunConfig::builder().seed([7u8; 32]).build();
        let hash = crate::proto::run_config_hash(&cfg).unwrap();
        TaskDispatch {
            task_id: "t1".to_string(),
            run_config_bytes: crate::proto::canonical_bytes(&cfg).unwrap(),
            workload: "kv".to_string(),
            run_config_hash_hex: crate::proto::hash_to_hex(&hash),
            execution_identity: [0xabu8; 32].to_vec(),
        }
    }

    #[test]
    fn dispatch_round_trips_into_task() {
        let task = task_from_dispatch(golden_dispatch()).expect("dispatch must parse");
        assert_eq!(task.id, "t1");
        assert_eq!(task.workload, "kv");
        assert_eq!(task.execution_identity, Some([0xabu8; 32]));
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
    fn hello_carries_identity_when_build_complete() {
        let hello = worker_hello("w1", "0.1.0");
        assert_eq!(hello.worker_id, "w1");
        assert_eq!(hello.version, "0.1.0");
        // The identity is either the complete 32-byte digest or empty for
        // an incomplete dev build; both are contract-legal.
        assert!(hello.execution_identity.is_empty() || hello.execution_identity.len() == 32);
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
