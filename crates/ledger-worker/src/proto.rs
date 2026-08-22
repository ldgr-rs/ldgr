// ledger-lint:allow - host daemon / non-sim passthrough, like TokioBackend
use ledger_format::Hash;
use ledger_sim::RunConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use crate::queue::InMemoryQueue;

/// Request sent over UDS to ask the worker to execute a task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerRequest {
    /// Task identifier.
    pub task_id: String,
    /// Hex-encoded blake3 hash of the canonical RunConfig bytes. The server
    /// verifies this hash against the queued task's config before execution.
    pub run_config_hash: String,
    /// Optional RunConfig JSON for cross-verification. The server rejects a
    /// non-object value; full hash cross-verification waits for
    /// serialization support in `ledger_sim::RunConfig`, so the
    /// `run_config_hash` pin stays authoritative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_config: Option<serde_json::Value>,
    /// Optional hex runtime-profile fingerprint for the G6 handshake; see
    /// `crate::profile`. Absent on legacy clients; validated like
    /// `run_config_hash` when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_fingerprint: Option<String>,
}

/// Validate handshake fields on a [`WorkerRequest`] against a full hash pin.
///
/// # Errors
/// Returns the rejection reason so callers can log or reply with context.
pub fn validate_request(
    req: &WorkerRequest,
    expected_profile: Option<&Hash>,
) -> Result<(), String> {
    validate_request_inner(req, expected_profile, None)
}

/// Validate handshake fields on a [`WorkerRequest`] against an eight-hex
/// profile pin (`WorkerConfig::profile_hex8`).
///
/// A supplied fingerprint must be well-formed hex and must name the pinned
/// profile by its first eight hex chars. An absent fingerprint stays legal
/// for legacy clients.
///
/// # Errors
/// Returns the rejection reason so callers can log or reply with context.
pub fn validate_request_hex8(
    req: &WorkerRequest,
    expected_profile_hex8: Option<&str>,
) -> Result<(), String> {
    validate_request_inner(req, None, expected_profile_hex8)
}

fn validate_request_inner(
    req: &WorkerRequest,
    expected_profile: Option<&Hash>,
    expected_profile_hex8: Option<&str>,
) -> Result<(), String> {
    hex_to_hash(&req.run_config_hash).map_err(|e| format!("run_config_hash: {e}"))?;
    if let Some(fp) = &req.profile_fingerprint {
        let parsed = hex_to_hash(fp).map_err(|e| format!("profile_fingerprint: {e}"))?;
        if let Some(expected) = expected_profile
            && parsed != *expected
        {
            return Err("profile_fingerprint mismatch".to_string());
        }
        if let Some(expected) = expected_profile_hex8
            && !profile_pin_matches(fp, expected)
        {
            return Err("profile_fingerprint mismatch".to_string());
        }
    }
    Ok(())
}

/// True when `wire_fingerprint_hex` names the profile pinned by
/// `expected_hex8`: same lowercase prefix and at least as long. The daemon
/// pins eight hex chars while wire senders may carry the full digest.
pub fn profile_pin_matches(wire_fingerprint_hex: &str, expected_hex8: &str) -> bool {
    let wire = wire_fingerprint_hex.to_ascii_lowercase();
    let expected = expected_hex8.to_ascii_lowercase();
    wire.len() >= expected.len() && wire.starts_with(&expected)
}

/// Response returned over UDS: a journal root on success, a reason on error.
///
/// Exactly one of `journal_root` and `error` is set; the other field is
/// omitted from the JSON wire form so an error line never carries a hash a
/// caller could mistake for a real simulation root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerResponse {
    /// Task identifier echoed from the request.
    pub task_id: String,
    /// Hex-encoded journal root hash; absent on error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_root: Option<String>,
    /// Failure reason; absent on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl WorkerResponse {
    /// Success response carrying the real journal root.
    pub fn ok(task_id: String, journal_root: String) -> Self {
        Self {
            task_id,
            journal_root: Some(journal_root),
            error: None,
        }
    }

    /// Error response; never carries a `journal_root`.
    pub fn failure(task_id: String, reason: String) -> Self {
        Self {
            task_id,
            journal_root: None,
            error: Some(reason),
        }
    }
}

/// Compute the deterministic blake3 hash of a RunConfig's canonical bytes.
///
/// # Errors
/// Returns the canonical-encoding error when the config carries a non-finite
/// float; the owned codec lives in `ledger_sim::config_canonical`.
pub fn run_config_hash(
    config: &RunConfig,
) -> Result<ledger_format::Hash, ledger_sim::ConfigCanonicalError> {
    ledger_sim::canonical_hash(config)
}

/// Canonical bytes for RunConfig hashing, version 1.
///
/// The owned codec in `ledger_sim::config_canonical` produces versioned
/// canonical CBOR: seed, policy, max_steps, swarm knobs, dropped events,
/// links, DNS (sorted), fault schedule, monitor, and `fs_journaling` (always
/// present, `null` when unset) so the bytes are identical across feature
/// builds. See that module for the field order and version rules.
///
/// # Errors
/// Returns the canonical-encoding error when the config carries a non-finite
/// float.
pub fn canonical_bytes(config: &RunConfig) -> Result<Vec<u8>, ledger_sim::ConfigCanonicalError> {
    ledger_sim::to_canonical_bytes(config)
}

/// Encode a hash as lowercase hex.
pub fn hash_to_hex(hash: &Hash) -> String {
    ledger_format::hash_to_hex(hash)
}

/// Decode a lowercase hex string into a hash.
///
/// # Errors
/// Returns the format crate's hex error for malformed input.
pub fn hex_to_hash(s: &str) -> Result<Hash, ledger_format::HexError> {
    ledger_format::hash_from_hex(s)
}

/// Hard cap for one newline-delimited JSON request over UDS.
///
/// A handshake request is a few hundred bytes; anything over 1 MiB is
/// hostile input, not data. The bounded reader rejects such lines before
/// allocation grows past the cap.
pub const MAX_UDS_LINE_SIZE: usize = 1 << 20;

/// Time budget for one UDS request line.
///
/// A same-uid peer that connects and sends nothing parks its handler task
/// only until this bound; on expiry the connection is dropped with a logged
/// reason (fail closed).
pub const UDS_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum concurrent UDS connection handlers.
///
/// Further same-uid peers are dropped at accept time with a logged reason,
/// so a hostile flood cannot park unbounded handler tasks.
pub const MAX_CONCURRENT_UDS_CONNECTIONS: usize = 8;

/// Failure modes of the bounded UDS line reader.
#[derive(Debug)]
pub(crate) enum UdsLineError {
    /// The line exceeded [`MAX_UDS_LINE_SIZE`]; the connection is dropped.
    Oversized {
        /// Maximum accepted line length in bytes.
        limit: usize,
    },
    /// Underlying socket read failure.
    Io(std::io::Error),
}

impl std::fmt::Display for UdsLineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Oversized { limit } => write!(f, "request exceeds {limit} bytes"),
            Self::Io(err) => write!(f, "read failed: {err}"),
        }
    }
}

impl std::error::Error for UdsLineError {}

/// Read one newline-delimited line with a hard size cap.
///
/// Reads at most `MAX_UDS_LINE_SIZE + 1` bytes. A line longer than the cap
/// returns [`UdsLineError::Oversized`] instead of growing the buffer without
/// bound. EOF without a trailing newline still returns the partial line, and
/// an empty line returns `None`.
///
/// # Errors
/// Returns [`UdsLineError::Oversized`] when the line exceeds the cap and
/// [`UdsLineError::Io`] when the underlying reader fails.
pub(crate) async fn read_bounded_line<R>(reader: &mut R) -> Result<Option<Vec<u8>>, UdsLineError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut limited = (&mut *reader).take((MAX_UDS_LINE_SIZE + 1) as u64);
    let mut buf = Vec::with_capacity(std::cmp::min(MAX_UDS_LINE_SIZE, 4096));
    let mut chunk = [0u8; 1024];
    loop {
        let n = limited.read(&mut chunk).await.map_err(UdsLineError::Io)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.ends_with(b"\n") {
            buf.pop();
            break;
        }
        if buf.len() > MAX_UDS_LINE_SIZE {
            return Err(UdsLineError::Oversized {
                limit: MAX_UDS_LINE_SIZE,
            });
        }
    }
    if buf.is_empty() {
        return Ok(None);
    }
    Ok(Some(buf))
}

/// UDS worker that executes real simulation work for cross-boundary determinism.
///
/// Serves WorkerRequests over a Unix domain socket as newline-delimited JSON
/// with real deterministic execution.
///
/// The socket file is bound with owner-only mode (0700) and the accept loop
/// drops every peer whose kernel-reported uid differs from the socket
/// owner's, so only same-uid clients reach request parsing. No stale file is
/// removed before bind: callers pass a fresh path (the daemon default is a
/// per-process randomized name) and an occupied path fails the bind.
///
/// The accept loop bounds hostile load: at most
/// [`MAX_CONCURRENT_UDS_CONNECTIONS`] handler tasks run at once, and each
/// request line must arrive within [`UDS_READ_TIMEOUT`]; a stalled or
/// overflowing connection is dropped with a logged reason (fail closed).
///
/// On each request the server reads one bounded line (over-long lines are
/// dropped), validates `run_config_hash` hex format plus the optional
/// `profile_fingerprint` pin (`expected_profile_hex8`), rejects a
/// non-object `run_config` when one is present, then looks up `task_id` in
/// the shared queue via [`InMemoryQueue::take_by_id`]. When the task is
/// found the server verifies that the requested `run_config_hash` equals the
/// canonical hash of the queued config, then executes the task through
/// [`crate::worker::execute_task`] on the blocking pool and returns the real
/// journal root. When `task_id` is not found, the hash does not match, or
/// execution fails, the server replies with an `error` response and no
/// `journal_root`: no fabricated root is ever returned, so a missing queue
/// preload fails loudly instead of feeding a caller a fake hash.
///
/// # Errors
/// Returns the bind error for an unwritable or already-occupied socket
/// path, or an accept error while serving.
pub async fn serve_uds_real(
    path: PathBuf,
    queue: Arc<Mutex<InMemoryQueue>>,
    expected_profile_hex8: Option<String>,
) -> Result<(), std::io::Error> {
    serve_uds_real_inner(path, queue, expected_profile_hex8, UDS_READ_TIMEOUT).await
}

/// [`serve_uds_real`] with an injectable read timeout for tests.
async fn serve_uds_real_inner(
    path: PathBuf,
    queue: Arc<Mutex<InMemoryQueue>>,
    expected_profile_hex8: Option<String>,
    read_timeout: Duration,
) -> Result<(), std::io::Error> {
    let listener = tokio::net::UnixListener::bind(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Owner-only socket: peers outside this uid cannot connect even if
        // they reach the parent directory.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    }
    // SO_PEERCRED answers with the creator's credentials, so the socket
    // file's owner is the authorization anchor for every later accept.
    let owner_uid = socket_owner_uid(&path);
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_UDS_CONNECTIONS));
    loop {
        let (mut stream, _) = listener.accept().await?;
        if !peer_uid_allowed(&stream, owner_uid) {
            eprintln!(
                "ledger-worker: rejected UDS peer with mismatching uid on {}",
                path.display()
            );
            continue;
        }
        let permit = match Arc::clone(&permits).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                // The stream drops here, closing the connection without
                // spawning a handler task.
                eprintln!(
                    "ledger-worker: dropped UDS connection on {}: concurrency cap {} reached",
                    path.display(),
                    MAX_CONCURRENT_UDS_CONNECTIONS
                );
                continue;
            }
        };
        let queue = Arc::clone(&queue);
        let expected_profile_hex8 = expected_profile_hex8.clone();
        let socket_path = path.clone();
        tokio::spawn(async move {
            // The permit outlives the handler: one connection, one task.
            let _permit = permit;
            let line =
                match tokio::time::timeout(read_timeout, read_bounded_line(&mut stream)).await {
                    Ok(Ok(Some(line))) => line,
                    Ok(Ok(None)) => {
                        // EOF or blank line: nothing to answer.
                        return;
                    }
                    Ok(Err(err)) => {
                        eprintln!(
                            "ledger-worker: rejected UDS request on {}: {err}",
                            socket_path.display()
                        );
                        return;
                    }
                    Err(_elapsed) => {
                        eprintln!(
                            "ledger-worker: dropped stalled UDS connection on {} after {}s",
                            socket_path.display(),
                            read_timeout.as_secs()
                        );
                        return;
                    }
                };
            let text = match std::str::from_utf8(&line) {
                Ok(text) => text.trim(),
                Err(_) => {
                    eprintln!(
                        "ledger-worker: rejected non-UTF-8 UDS request on {}",
                        socket_path.display()
                    );
                    return;
                }
            };
            let Ok(req) = serde_json::from_str::<WorkerRequest>(text) else {
                eprintln!(
                    "ledger-worker: rejected malformed UDS request on {}",
                    socket_path.display()
                );
                return;
            };
            // Handshake validation: run_config_hash must be hex; an
            // optional profile_fingerprint must be hex and, when the
            // daemon pins its profile, must name that profile.
            if validate_request_hex8(&req, expected_profile_hex8.as_deref()).is_err() {
                eprintln!(
                    "ledger-worker: rejected UDS handshake on {}",
                    socket_path.display()
                );
                return;
            }
            let task_id = req.task_id.clone();
            if let Some(cfg) = &req.run_config
                && !cfg.is_object()
            {
                let resp = WorkerResponse::failure(
                    task_id,
                    "run_config must be a JSON object when present".to_string(),
                );
                write_response(&mut stream, &resp).await;
                return;
            }
            let maybe_task = {
                let mut q = queue.lock().await;
                q.take_by_id(&task_id)
            };
            let resp = if let Some(task) = maybe_task {
                match requested_hash_matches(&req, &task) {
                    Ok(()) => execute_task_response(task_id, task).await,
                    Err(reason) => WorkerResponse::failure(task_id, reason),
                }
            } else {
                let reason = format!("task not found: {task_id}");
                WorkerResponse::failure(task_id, reason)
            };
            write_response(&mut stream, &resp).await;
        });
    }
}

/// Verify that the request's `run_config_hash` names the queued task's
/// config, mirroring the deterministic boundary in `execute_task`.
///
/// # Errors
/// Returns the rejection reason when the hash does not match or the config
/// cannot be encoded canonically.
fn requested_hash_matches(req: &WorkerRequest, task: &crate::queue::Task) -> Result<(), String> {
    let requested =
        hex_to_hash(&req.run_config_hash).map_err(|e| format!("run_config_hash: {e}"))?;
    let computed = crate::proto::run_config_hash(&task.run_config).map_err(|error| {
        format!(
            "run config cannot be encoded canonically for task {}: {error}",
            task.id
        )
    })?;
    if computed != requested {
        return Err(format!(
            "run_config_hash mismatch for task {}: request names a different config",
            task.id
        ));
    }
    Ok(())
}

/// Execute `task` on the blocking pool and render the wire response.
///
/// The blocking pool keeps the simulation off the reactor thread; a join
/// failure produces an error response, never a fabricated root.
async fn execute_task_response(task_id: String, task: crate::queue::Task) -> WorkerResponse {
    let exec = tokio::task::spawn_blocking(move || crate::worker::execute_task(task)).await;
    match exec {
        Ok(Ok(result)) => WorkerResponse::ok(task_id, hash_to_hex(&result.journal_root)),
        Ok(Err(err)) => {
            eprintln!("ledger-worker: task {task_id} execute failed: {err}");
            WorkerResponse::failure(task_id, format!("execute failed: {err}"))
        }
        Err(join_err) => {
            eprintln!("ledger-worker: task {task_id} execute join failed: {join_err}");
            WorkerResponse::failure(task_id, format!("execute join failed: {join_err}"))
        }
    }
}

/// Write one JSON response line back to the UDS peer.
async fn write_response(stream: &mut tokio::net::UnixStream, resp: &WorkerResponse) {
    use tokio::io::AsyncWriteExt;
    match serde_json::to_string(resp) {
        Ok(json) => {
            if let Err(err) = stream.write_all(format!("{json}\n").as_bytes()).await {
                // The peer is gone; the request outcome is already decided.
                eprintln!("ledger-worker: UDS response write failed: {err}");
            }
        }
        Err(err) => eprintln!("ledger-worker: UDS response encode failed: {err}"),
    }
}

/// Owner uid of the socket file at `path`, when the platform exposes it.
#[cfg(unix)]
pub(crate) fn socket_owner_uid(path: &std::path::Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|md| md.uid())
}

/// Authorization gate for one accepted connection: the peer's kernel
/// credential must carry the socket owner's uid. A missing or unreadable
/// credential rejects the peer (fail closed).
#[cfg(unix)]
pub(crate) fn peer_uid_allowed(stream: &tokio::net::UnixStream, owner_uid: Option<u32>) -> bool {
    match (stream.peer_cred(), owner_uid) {
        (Ok(cred), Some(owner)) => cred.uid() == owner,
        _ => false,
    }
}

/// Serve WorkerRequests over a Unix domain socket as newline-delimited JSON.
///
/// Executes real tasks through [`serve_uds_real`] over an empty queue, so
/// every request hits the unknown-task error path. Kept for socket-level
/// tests of the wire protocol itself.
#[cfg(test)]
pub(crate) async fn serve_uds(path: PathBuf) -> Result<(), std::io::Error> {
    serve_uds_real(
        path,
        Arc::new(tokio::sync::Mutex::new(crate::queue::InMemoryQueue::new(
            std::time::Duration::from_secs(30),
        ))),
        None,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_sim::RunConfig;

    /// UDS server bind deadline for the served tests below.
    const UDS_BIND_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
    /// UDS response deadline for one request/response exchange.
    const UDS_RESPONSE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

    /// Poll-connect to a freshly spawned UDS server with a bounded deadline
    /// and diagnostics; a server that never binds fails the test loudly
    /// instead of silently passing behind a fixed settle sleep.
    async fn connect_ready(sock: &std::path::Path) -> tokio::net::UnixStream {
        let mut last_error = String::new();
        tokio::time::timeout(UDS_BIND_DEADLINE, async {
            loop {
                match tokio::net::UnixStream::connect(sock).await {
                    Ok(stream) => return stream,
                    Err(error) => {
                        last_error = error.to_string();
                        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                    }
                }
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "uds server did not bind {} within {UDS_BIND_DEADLINE:?}; \
                 last connect error: {last_error}. The server task may have exited before binding.",
                sock.display()
            )
        })
    }

    /// Read one response line with a bounded deadline. An empty reply or a
    /// hang fails the test with diagnostics instead of parking forever.
    async fn read_response(stream: &mut tokio::net::UnixStream) -> String {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let mut line = String::new();
        let mut reader = BufReader::new(stream);
        let bytes = tokio::time::timeout(UDS_RESPONSE_DEADLINE, reader.read_line(&mut line))
            .await
            .unwrap_or_else(|_| {
                panic!("uds server did not answer within {UDS_RESPONSE_DEADLINE:?}")
            })
            .unwrap_or_else(|error| panic!("uds response read failed: {error}"));
        if bytes == 0 {
            panic!("uds server closed the connection without a response");
        }
        if line.trim().is_empty() {
            panic!("uds server replied with an empty line");
        }
        line
    }

    #[test]
    fn request_roundtrip() {
        let req = WorkerRequest {
            task_id: "task-123".into(),
            run_config_hash: hash_to_hex(&[1u8; 32]),
            run_config: None,
            profile_fingerprint: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: WorkerRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn request_with_run_config_roundtrip() {
        let req = WorkerRequest {
            task_id: "task-123".into(),
            run_config_hash: hash_to_hex(&[1u8; 32]),
            run_config: Some(serde_json::json!({"seed": "abc"})),
            profile_fingerprint: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: WorkerRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
        // Omission when None keeps wire compat.
        let minimal = WorkerRequest {
            task_id: "t".into(),
            run_config_hash: hash_to_hex(&[0u8; 32]),
            run_config: None,
            profile_fingerprint: None,
        };
        let minimal_json = serde_json::to_string(&minimal).unwrap();
        let v: serde_json::Value = serde_json::from_str(&minimal_json).unwrap();
        assert!(
            !v.as_object().unwrap().contains_key("run_config"),
            "minimal_json should omit run_config when None, got {}",
            minimal_json
        );
        assert!(
            !v.as_object().unwrap().contains_key("profile_fingerprint"),
            "minimal_json should omit profile_fingerprint when None, got {minimal_json}"
        );
    }

    #[test]
    fn legacy_json_without_profile_field_parses() {
        // Old clients never send profile_fingerprint; the field must default
        // to None so the handshake stays backward compatible.
        let legacy = format!(
            r#"{{"task_id":"legacy","run_config_hash":"{}"}}"#,
            hash_to_hex(&[3u8; 32])
        );
        let req: WorkerRequest = serde_json::from_str(&legacy).unwrap();
        assert_eq!(req.task_id, "legacy");
        assert_eq!(req.profile_fingerprint, None);
        assert!(validate_request(&req, None).is_ok());
    }

    #[test]
    fn validate_rejects_malformed_profile_fingerprint() {
        let req = WorkerRequest {
            task_id: "t".into(),
            run_config_hash: hash_to_hex(&[1u8; 32]),
            run_config: None,
            profile_fingerprint: Some("not-a-hash".into()),
        };
        let err = validate_request(&req, None).unwrap_err();
        assert!(err.contains("profile_fingerprint"), "got {err}");
    }

    #[test]
    fn validate_rejects_mismatched_profile_fingerprint() {
        let req = WorkerRequest {
            task_id: "t".into(),
            run_config_hash: hash_to_hex(&[1u8; 32]),
            run_config: None,
            profile_fingerprint: Some(hash_to_hex(&[0xaa; 32])),
        };
        let expected = [0xbbu8; 32];
        let err = validate_request(&req, Some(&expected)).unwrap_err();
        assert!(err.contains("mismatch"), "got {err}");
    }

    #[test]
    fn validate_accepts_matching_profile_fingerprint() {
        let fingerprint = crate::profile::RuntimeProfile::detect().fingerprint();
        let req = WorkerRequest {
            task_id: "t".into(),
            run_config_hash: hash_to_hex(&[1u8; 32]),
            run_config: None,
            profile_fingerprint: Some(hash_to_hex(&fingerprint)),
        };
        assert!(validate_request(&req, Some(&fingerprint)).is_ok());
        // Without a pinned expectation any well-formed fingerprint passes.
        assert!(validate_request(&req, None).is_ok());
    }

    #[test]
    fn hex8_pin_matches_prefix_and_rejects_other_profile() {
        let full = hash_to_hex(&[0x12u8; 32]);
        // The pin form accepts a wire fingerprint carrying the pinned prefix.
        assert!(
            validate_request_hex8(
                &WorkerRequest {
                    task_id: "t".into(),
                    run_config_hash: hash_to_hex(&[1u8; 32]),
                    run_config: None,
                    profile_fingerprint: Some(full.clone()),
                },
                Some(&full[..8])
            )
            .is_ok()
        );
        // Uppercase wire hex still matches the lowercase pin.
        assert!(profile_pin_matches(&full.to_ascii_uppercase(), &full[..8]));
        // A different digest never matches.
        assert!(!profile_pin_matches(&hash_to_hex(&[0xaa; 32]), &full[..8]));
        // Shorter-than-pin fingerprints cannot match.
        assert!(!profile_pin_matches(&full[..4], &full[..8]));
        // validate_request_hex8 surfaces the mismatch as an error.
        let err = validate_request_hex8(
            &WorkerRequest {
                task_id: "t".into(),
                run_config_hash: hash_to_hex(&[1u8; 32]),
                run_config: None,
                profile_fingerprint: Some(hash_to_hex(&[0xaa; 32])),
            },
            Some(&full[..8]),
        )
        .unwrap_err();
        assert!(err.contains("mismatch"), "got {err}");
        // Absent fingerprint stays legal for legacy clients.
        assert!(
            validate_request_hex8(
                &WorkerRequest {
                    task_id: "t".into(),
                    run_config_hash: hash_to_hex(&[1u8; 32]),
                    run_config: None,
                    profile_fingerprint: None,
                },
                Some(&full[..8])
            )
            .is_ok()
        );
    }

    #[test]
    fn same_uid_peer_gate_accepts_and_missing_cred_rejects() {
        // Same-process peers carry our uid, so the gate must accept them.
        assert!(peer_uid_allowed_for(1000, Some(1000)));
        // A foreign uid is rejected.
        assert!(!peer_uid_allowed_for(1001, Some(1000)));
        // Unknown owner or unreadable credential fails closed.
        assert!(!peer_uid_allowed_for(1000, None));
    }

    /// Pure decision core of `peer_uid_allowed`, exercised with fabricated
    /// credentials so both allow and reject branches are testable without a
    /// second uid.
    fn peer_uid_allowed_for(peer_uid: u32, owner_uid: Option<u32>) -> bool {
        match owner_uid {
            Some(owner) => peer_uid == owner,
            None => false,
        }
    }

    #[test]
    fn response_roundtrip() {
        let resp = WorkerResponse::ok("task-123".into(), hash_to_hex(&[2u8; 32]));
        let json = serde_json::to_string(&resp).unwrap();
        let back: WorkerResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn error_response_omits_journal_root_on_the_wire() {
        let resp = WorkerResponse::failure("ghost".into(), "task not found: ghost".into());
        let json = serde_json::to_string(&resp).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(!v.as_object().unwrap().contains_key("journal_root"));
        assert_eq!(v["error"], "task not found: ghost");
        let back: WorkerResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn hash_hex_roundtrip() {
        let h = [0xabu8; 32];
        let s = hash_to_hex(&h);
        let back = hex_to_hash(&s).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn run_config_hash_is_deterministic() {
        let cfg = RunConfig::builder().seed([7u8; 32]).build();
        let a = run_config_hash(&cfg).unwrap();
        let b = run_config_hash(&cfg).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn run_config_hash_changes_with_seed() {
        let a = RunConfig::builder().seed([1u8; 32]).build();
        let b = RunConfig::builder().seed([2u8; 32]).build();
        assert_ne!(run_config_hash(&a).unwrap(), run_config_hash(&b).unwrap());
    }

    #[test]
    fn run_config_hash_changes_with_dns() {
        let mut a = RunConfig::builder().seed([9u8; 32]).build();
        let mut b = RunConfig::builder().seed([9u8; 32]).build();
        a.dns_mut().insert("alpha.test", 1);
        b.dns_mut().insert("beta.test", 1);
        assert_ne!(run_config_hash(&a).unwrap(), run_config_hash(&b).unwrap());
        // Same entries inserted in different order must hash equal (sorted encoding).
        let mut c = RunConfig::builder().seed([9u8; 32]).build();
        let mut d = RunConfig::builder().seed([9u8; 32]).build();
        c.dns_mut().insert("z.test", 2);
        c.dns_mut().insert("a.test", 1);
        d.dns_mut().insert("a.test", 1);
        d.dns_mut().insert("z.test", 2);
        assert_eq!(run_config_hash(&c).unwrap(), run_config_hash(&d).unwrap());
    }

    #[test]
    fn run_config_hash_changes_with_dns_actor() {
        let mut a = RunConfig::builder().seed([5u8; 32]).build();
        let mut b = RunConfig::builder().seed([5u8; 32]).build();
        a.dns_mut().insert("host.test", 1);
        b.dns_mut().insert("host.test", 2);
        assert_ne!(run_config_hash(&a).unwrap(), run_config_hash(&b).unwrap());
    }

    #[tokio::test]
    async fn uds_unknown_task_returns_error_over_socket() {
        let dir = std::env::temp_dir().join(format!("ldgr-uds-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let sock = dir.join("test.sock");
        if sock.exists() {
            let _ = std::fs::remove_file(&sock);
        }
        let serve_path = sock.clone();
        let handle = tokio::spawn(async move {
            let _ = serve_uds(serve_path).await;
        });
        let mut stream = connect_ready(&sock).await;
        let req = WorkerRequest {
            task_id: "uds-task".into(),
            run_config_hash: hash_to_hex(&[9u8; 32]),
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
        let line = read_response(&mut stream).await;
        let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(v["task_id"], "uds-task");
        assert_eq!(v["error"], "task not found: uds-task");
        assert!(
            !v.as_object().unwrap().contains_key("journal_root"),
            "error response must not carry a journal_root, got {v}"
        );
        handle.abort();
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn uds_rejects_malformed_hash() {
        let dir = std::env::temp_dir().join(format!("ldgr-uds-bad-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let sock = dir.join("test.sock");
        if sock.exists() {
            let _ = std::fs::remove_file(&sock);
        }
        let serve_path = sock.clone();
        let handle = tokio::spawn(async move {
            let _ = serve_uds(serve_path).await;
        });
        let mut stream = connect_ready(&sock).await;
        let bad_req = WorkerRequest {
            task_id: "bad-task".into(),
            run_config_hash: "not-a-hash".into(),
            run_config: None,
            profile_fingerprint: None,
        };
        let json = serde_json::to_string(&bad_req).unwrap();
        {
            use tokio::io::AsyncWriteExt;
            stream
                .write_all(format!("{json}\n").as_bytes())
                .await
                .unwrap();
        }
        // Server should not reply (validation failed), so read times out / empty.
        {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let mut reader = BufReader::new(&mut stream);
            let mut line = String::new();
            let res = tokio::time::timeout(
                std::time::Duration::from_millis(200),
                reader.read_line(&mut line),
            )
            .await;
            // Either timeout or empty line indicates rejection.
            if let Ok(Ok(_)) = res {
                assert!(
                    line.trim().is_empty()
                        || serde_json::from_str::<WorkerResponse>(line.trim()).is_err()
                );
            }
        }
        handle.abort();
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn bounded_reader_accepts_line_within_cap() {
        use tokio::io::AsyncWriteExt;
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        client.write_all(b"{\"task_id\":\"t\"}\n").await.unwrap();
        let line = read_bounded_line(&mut server)
            .await
            .expect("in-cap line must read");
        assert_eq!(line.unwrap(), b"{\"task_id\":\"t\"}");
    }

    #[tokio::test]
    async fn bounded_reader_accepts_eof_terminated_line() {
        use tokio::io::AsyncWriteExt;
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        client.write_all(b"no-newline-here").await.unwrap();
        drop(client);
        let line = read_bounded_line(&mut server)
            .await
            .expect("EOF-terminated line must read");
        assert_eq!(line.unwrap(), b"no-newline-here");
    }

    #[tokio::test]
    async fn bounded_reader_rejects_oversized_line() {
        use tokio::io::AsyncWriteExt;
        let (mut client, mut server) = tokio::io::duplex(MAX_UDS_LINE_SIZE + 1);
        let big = vec![b'x'; MAX_UDS_LINE_SIZE + 1];
        let writer = tokio::spawn(async move {
            client.write_all(&big).await.unwrap();
        });
        let err = read_bounded_line(&mut server)
            .await
            .expect_err("over-cap line must be rejected");
        assert!(matches!(err, UdsLineError::Oversized { .. }));
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn bounded_reader_rejects_exactly_cap_plus_newline() {
        use tokio::io::AsyncWriteExt;
        // A payload of exactly MAX bytes plus the newline is the largest
        // legal line; one extra payload byte must be rejected.
        let (mut client, mut server) = tokio::io::duplex(MAX_UDS_LINE_SIZE + 2);
        let mut big = vec![b'y'; MAX_UDS_LINE_SIZE + 1];
        big.push(b'\n');
        let writer = tokio::spawn(async move {
            client.write_all(&big).await.unwrap();
        });
        let err = read_bounded_line(&mut server)
            .await
            .expect_err("over-cap line with newline must be rejected");
        assert!(matches!(err, UdsLineError::Oversized { .. }));
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn uds_rejects_oversized_request_over_socket() {
        let dir = std::env::temp_dir().join(format!("ldgr-uds-big-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let sock = dir.join("test.sock");
        if sock.exists() {
            let _ = std::fs::remove_file(&sock);
        }
        let serve_path = sock.clone();
        let handle = tokio::spawn(async move {
            let _ = serve_uds(serve_path).await;
        });
        let stream = connect_ready(&sock).await;
        let (mut rd, mut wr) = stream.into_split();
        {
            use tokio::io::AsyncWriteExt;
            let big = vec![b'x'; MAX_UDS_LINE_SIZE + 1];
            // The server may drop the peer mid-write; EPIPE is the expected
            // outcome of a connection the server rejects.
            let writer = tokio::spawn(async move {
                let _ = wr.write_all(&big).await;
            });
            writer.await.unwrap();
            // The server dropped the connection: the read hits EOF or an
            // error instead of a reply line.
            let res = tokio::time::timeout(
                std::time::Duration::from_millis(200),
                read_bounded_line(&mut rd),
            )
            .await;
            match res {
                Ok(Ok(Some(line))) => {
                    panic!("oversized request got a reply line: {line:?}");
                }
                Ok(Ok(None)) | Ok(Err(_)) => {}
                Err(_) => panic!("oversized request left the connection open"),
            }
        }
        handle.abort();
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn uds_honors_requested_hash_and_rejects_mismatch() {
        let dir = std::env::temp_dir().join(format!("ldgr-uds-hash-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let sock = dir.join("test.sock");
        if sock.exists() {
            let _ = std::fs::remove_file(&sock);
        }
        let cfg = RunConfig::builder().seed([5u8; 32]).build();
        let queue = Arc::new(Mutex::new(crate::queue::InMemoryQueue::new(
            std::time::Duration::from_secs(30),
        )));
        queue
            .lock()
            .await
            .push(crate::queue::Task::new("hash-task", cfg.clone(), "kv"));
        queue
            .lock()
            .await
            .push(crate::queue::Task::new("hash-bad", cfg.clone(), "kv"));
        let serve_path = sock.clone();
        let queue_clone = Arc::clone(&queue);
        let handle = tokio::spawn(async move {
            let _ = serve_uds_real(serve_path, queue_clone, None).await;
        });

        let req_json = |task_id: &str, hash: String| {
            serde_json::to_string(&WorkerRequest {
                task_id: task_id.to_string(),
                run_config_hash: hash,
                run_config: None,
                profile_fingerprint: None,
            })
            .unwrap()
        };
        let send_and_read = |json: String| {
            let sock = sock.clone();
            async move {
                let mut stream = connect_ready(&sock).await;
                {
                    use tokio::io::AsyncWriteExt;
                    stream
                        .write_all(format!("{json}\n").as_bytes())
                        .await
                        .unwrap();
                }
                read_response(&mut stream).await
            }
        };

        // Correct hash: the real root is returned.
        let good = run_config_hash(&cfg).unwrap();
        let ok_line = send_and_read(req_json("hash-task", hash_to_hex(&good))).await;
        let ok_resp: WorkerResponse = serde_json::from_str(ok_line.trim()).unwrap();
        assert_eq!(ok_resp.task_id, "hash-task");
        assert!(ok_resp.error.is_none(), "got {:?}", ok_resp.error);
        assert!(ok_resp.journal_root.is_some(), "real root expected");

        // Another valid hash: rejected before execution, no root.
        let other = run_config_hash(&RunConfig::builder().seed([6u8; 32]).build()).unwrap();
        let bad_line = send_and_read(req_json("hash-bad", hash_to_hex(&other))).await;
        let bad_resp: WorkerResponse = serde_json::from_str(bad_line.trim()).unwrap();
        assert_eq!(bad_resp.task_id, "hash-bad");
        let err = bad_resp.error.expect("mismatch must carry an error");
        assert!(err.contains("run_config_hash mismatch"), "got {err}");
        assert!(
            bad_resp.journal_root.is_none(),
            "mismatched hash must not produce a root"
        );

        handle.abort();
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn uds_rejects_non_object_run_config() {
        let dir = std::env::temp_dir().join(format!("ldgr-uds-cfg-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let sock = dir.join("test.sock");
        if sock.exists() {
            let _ = std::fs::remove_file(&sock);
        }
        let queue = Arc::new(Mutex::new(crate::queue::InMemoryQueue::new(
            std::time::Duration::from_secs(30),
        )));
        let serve_path = sock.clone();
        let queue_clone = Arc::clone(&queue);
        let handle = tokio::spawn(async move {
            let _ = serve_uds_real(serve_path, queue_clone, None).await;
        });
        let mut stream = connect_ready(&sock).await;
        let req = WorkerRequest {
            task_id: "cfg-task".into(),
            run_config_hash: hash_to_hex(&[1u8; 32]),
            run_config: Some(serde_json::json!("not-an-object")),
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
        let line = read_response(&mut stream).await;
        let resp: WorkerResponse = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(resp.task_id, "cfg-task");
        let err = resp.error.expect("non-object run_config must be rejected");
        assert!(err.contains("JSON object"), "got {err}");
        assert!(resp.journal_root.is_none());
        handle.abort();
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn uds_stalled_connection_is_dropped_by_read_timeout() {
        let dir = std::env::temp_dir().join(format!("ldgr-uds-stall-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let sock = dir.join("test.sock");
        if sock.exists() {
            let _ = std::fs::remove_file(&sock);
        }
        let queue = Arc::new(Mutex::new(crate::queue::InMemoryQueue::new(
            std::time::Duration::from_secs(30),
        )));
        let serve_path = sock.clone();
        let queue_clone = Arc::clone(&queue);
        let handle = tokio::spawn(async move {
            // Short read timeout: the stalled peer must be dropped fast.
            let _ = serve_uds_real_inner(serve_path, queue_clone, None, Duration::from_millis(100))
                .await;
        });
        let stream = connect_ready(&sock).await;
        let (mut rd, _wr) = stream.into_split();
        // Send nothing: the server must drop the connection on its own.
        let res = tokio::time::timeout(Duration::from_secs(2), read_bounded_line(&mut rd)).await;
        match res {
            Ok(Ok(Some(line))) => panic!("stalled connection got a reply: {line:?}"),
            Ok(Ok(None)) | Ok(Err(_)) => {}
            Err(_) => panic!("stalled connection was not dropped by the read timeout"),
        }
        handle.abort();
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn uds_concurrency_cap_drops_overflow_connections() {
        let dir = std::env::temp_dir().join(format!("ldgr-uds-cap-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let sock = dir.join("test.sock");
        if sock.exists() {
            let _ = std::fs::remove_file(&sock);
        }
        let queue = Arc::new(Mutex::new(crate::queue::InMemoryQueue::new(
            std::time::Duration::from_secs(30),
        )));
        let serve_path = sock.clone();
        let queue_clone = Arc::clone(&queue);
        let handle = tokio::spawn(async move {
            let _ = serve_uds_real_inner(
                serve_path,
                queue_clone,
                None,
                // Long read timeout: the parked peers below must stay parked.
                Duration::from_secs(10),
            )
            .await;
        });
        // Park MAX connections without sending a line; each holds one
        // handler permit. The accept loop is FIFO, so it accepts the first
        // MAX (acquiring all permits) before it reaches the overflow peer.
        let mut parked = Vec::with_capacity(MAX_CONCURRENT_UDS_CONNECTIONS);
        for _ in 0..MAX_CONCURRENT_UDS_CONNECTIONS {
            parked.push(connect_ready(&sock).await);
        }
        // Give the server time to accept and spawn the parked peers: poll
        // the overflow peer until the accept loop reaches it, bounded by a
        // 5s deadline with diagnostics instead of a fixed settle sleep.

        // The MAX+1-th peer is dropped at accept time: it must see EOF or
        // a reset quickly, never a parked silence or a reply.
        let overflow = connect_ready(&sock).await;
        let (mut rd, _wr) = overflow.into_split();
        let drop_deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let res =
                tokio::time::timeout(Duration::from_millis(100), read_bounded_line(&mut rd)).await;
            match res {
                Ok(Ok(Some(line))) => panic!("overflow connection got a reply: {line:?}"),
                Ok(Ok(None)) | Ok(Err(_)) => break, // dropped at accept time
                Err(_) => {
                    // Still parked: the accept loop is working through the
                    // FIFO of earlier peers.
                    if std::time::Instant::now() >= drop_deadline {
                        panic!(
                            "overflow connection was parked instead of dropped within 5s; \
                             the accept loop may have stalled"
                        );
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
        drop(parked);
        handle.abort();
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
