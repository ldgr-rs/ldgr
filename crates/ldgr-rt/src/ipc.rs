// ledger-lint:allow (host daemon; IPC transport uses ambient time, env, fs by design)
//! IPC transport to the AGPL engine.
//! `sim` delegates the deterministic run to `ledger rt-server` over a Unix
//! socket. Line-delimited JSON: request `{op:"run", workload, seed_hex,
//! max_steps, attempts}`, response `{roots, findings, steps}` or `{error}`.
//! Caller programs never cross this boundary.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use thiserror::Error;

use ledger_format::{ActorId, EntryHash};

/// Seconds to wait for the engine's socket to accept before giving up.
pub const ENGINE_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Candidate private directories tried before giving up on socket setup.
const SOCKET_DIR_ATTEMPTS: u64 = 3;

/// Maximum engine stderr bytes kept for diagnostics.
const STDERR_CAPTURE_CAP: usize = 8 * 1024;

/// Upper bound for a server-reported step count.
const MAX_SERVER_STEPS: u64 = 1 << 40;

/// Upper bound for a server-reported finding count.
const MAX_SERVER_FINDINGS: u64 = 1 << 24;

/// Maximum bytes for a workload name.
pub const MAX_WORKLOAD_NAME_BYTES: usize = 128;

/// Maximum remote attempts per call.
pub const MAX_IPC_ATTEMPTS: usize = 1024;

/// Maximum actor id accepted on the IPC control path.
pub const MAX_IPC_ACTOR: u32 = 1 << 20;

/// Errors from the engine process transport.
#[derive(Debug, Error)]
pub enum IpcError {
    #[error("failed to spawn engine at {path}: {reason}")]
    Spawn { path: String, reason: String },
    #[error("connect failed to {path}: {reason}")]
    Connect { path: String, reason: String },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// The server replied with a failure reason; the text is server data.
    #[error("server error: {0}")]
    Server(String),
    #[error("timeout waiting for socket {path}: {reason}")]
    Timeout { path: String, reason: String },
    /// The server violated the line protocol (empty or incomplete reply).
    #[error("protocol violation: {0}")]
    Protocol(&'static str),
    /// A root hex field did not decode into a 32-byte digest.
    #[error("invalid root hex: {0}")]
    RootHex(#[from] ledger_format::HexError),
    /// The private socket directory could not be set up as required.
    #[error("socket setup failed at {path}: {reason}")]
    SocketSetup { path: String, reason: String },
    /// A server-reported counter crossed its accepted bounds.
    #[error("server reported {name}={raw} outside accepted bounds")]
    CounterBounds { name: &'static str, raw: u64 },
    /// No engine binary configured: pass an explicit path or set
    /// `LEDGER_ENGINE_BIN` to an existing binary.
    #[error("engine binary not configured: pass explicit path or set LEDGER_ENGINE_BIN")]
    EngineNotConfigured,
    /// `LEDGER_ENGINE_BIN` points at a missing binary.
    #[error("LEDGER_ENGINE_BIN points to missing binary at {path}")]
    MissingEngine { path: String },
}

/// Outcome of a remote workload run.
#[derive(Debug, Clone)]
pub struct RunOutcome {
    /// One root per attempt, in attempt order.
    pub roots: Vec<EntryHash>,
    /// Number of oracle findings (violations) among the attempts.
    pub findings: usize,
    /// Steps reported by the server (max of attempts or first attempt).
    pub steps: usize,
}

impl RunOutcome {
    pub fn journal_root(&self) -> Option<EntryHash> {
        self.roots.first().copied()
    }
}

/// Handle to a running `ledger rt-server` child and its socket.
pub struct EngineProcess {
    child: Option<Child>,
    socket_path: PathBuf,
    engine_path: PathBuf,
    /// Private directory to remove on drop; `None` for caller-pinned sockets.
    cleanup_dir: Option<PathBuf>,
    /// Bounded stderr bytes captured by the drain thread (best-effort).
    stderr_tail: Arc<Mutex<Vec<u8>>>,
}

impl EngineProcess {
    /// Resolve the engine binary path: explicit arg, then `LEDGER_ENGINE_BIN`.
    fn resolve_engine_path(explicit: Option<PathBuf>) -> Result<PathBuf, IpcError> {
        if let Some(path) = explicit {
            return Ok(path);
        }
        match std::env::var("LEDGER_ENGINE_BIN") {
            Ok(env) if !env.trim().is_empty() => {
                let path = PathBuf::from(&env);
                if path.exists() {
                    Ok(path)
                } else {
                    Err(IpcError::MissingEngine { path: env })
                }
            }
            _ => Err(IpcError::EngineNotConfigured),
        }
    }

    /// Spawn the engine `rt-server` on a fresh socket in a private dir (0700).
    pub async fn spawn(engine_path: Option<PathBuf>) -> Result<Self, IpcError> {
        let engine = Self::resolve_engine_path(engine_path)?;
        let (dir, socket_path) = prepare_socket_dir()?;
        Self::spawn_in(engine, socket_path, Some(dir)).await
    }

    /// Spawn with an explicit socket path (tests). Caller owns placement.
    pub async fn spawn_with_socket(
        engine_path: Option<PathBuf>,
        socket_path: PathBuf,
    ) -> Result<Self, IpcError> {
        let engine = Self::resolve_engine_path(engine_path)?;
        Self::spawn_in(engine, socket_path, None).await
    }

    async fn spawn_in(
        engine: PathBuf,
        socket_path: PathBuf,
        cleanup_dir: Option<PathBuf>,
    ) -> Result<Self, IpcError> {
        // Remove a stale socket left by a prior crash so bind does not fail with AlreadyExists.
        let _ = std::fs::remove_file(&socket_path);
        if let Some(parent) = socket_path.parent() {
            // Best-effort: a missing parent (or unwritable temp dir) surfaces
            // later at the first connect attempt.
            let _ = std::fs::create_dir_all(parent);
        }

        let mut child = Command::new(&engine)
            .arg("rt-server")
            .arg("--socket")
            .arg(&socket_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| IpcError::Spawn {
                path: engine.display().to_string(),
                reason: error.to_string(),
            })?;

        // Poll until the socket accepts. A successful connect proves the
        // server is in its accept loop, so no extra sleep is required. The
        // probe stream drops immediately; callers open fresh connections per
        // request.
        let mut last_error = String::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(ENGINE_CONNECT_TIMEOUT_SECS);
        loop {
            if tokio::net::UnixStream::connect(&socket_path).await.is_ok() {
                // Startup succeeded: hand stderr to a bounded OS-thread
                // drainer so later crashes leave evidence without blocking
                // this reactor.
                let stderr_tail: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
                if let Some(stderr) = child.stderr.take() {
                    spawn_stderr_drain(stderr, Arc::clone(&stderr_tail));
                }
                return Ok(Self {
                    child: Some(child),
                    socket_path,
                    engine_path: engine,
                    cleanup_dir,
                    stderr_tail,
                });
            }
            if std::time::Instant::now() >= deadline {
                break;
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut stderr_output = String::new();
                    if let Some(mut stderr) = child.stderr.take() {
                        use std::io::Read as _;
                        // Best-effort capture; the exit status is the primary error.
                        let _ = stderr.read_to_string(&mut stderr_output);
                    }
                    let reason = if stderr_output.trim().is_empty() {
                        format!("exited early with {status}")
                    } else {
                        format!("exited early with {status}: {}", stderr_output.trim())
                    };
                    // Best-effort cleanup of the abandoned socket and its dir.
                    let _ = std::fs::remove_file(&socket_path);
                    if let Some(dir) = &cleanup_dir {
                        let _ = std::fs::remove_dir(dir);
                    }
                    return Err(IpcError::Spawn {
                        path: engine.display().to_string(),
                        reason,
                    });
                }
                Ok(None) => {
                    // Still running, keep waiting.
                }
                Err(error) => {
                    last_error = error.to_string();
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // Timeout: kill child and report.
        // Best-effort cleanup; the timeout error is the primary outcome.
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_file(&socket_path);
        if let Some(dir) = &cleanup_dir {
            let _ = std::fs::remove_dir(dir);
        }
        if !last_error.is_empty() {
            last_error = format!("{last_error}; ");
        }
        Err(IpcError::Timeout {
            path: socket_path.display().to_string(),
            reason: format!("{last_error}no reachable socket after {ENGINE_CONNECT_TIMEOUT_SECS}s"),
        })
    }

    /// Last captured engine stderr bytes (bounded, best-effort).
    pub fn stderr_tail(&self) -> String {
        let slot = match self.stderr_tail.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        String::from_utf8_lossy(&slot).into_owned()
    }

    /// Append the stderr tail to server-reported failures.
    fn attach_tail(&self, mut error: IpcError) -> IpcError {
        let tail = self.stderr_tail();
        if tail.is_empty() {
            return error;
        }
        if let IpcError::Server(text) = &mut error {
            text.push_str("; engine stderr: ");
            text.push_str(tail.trim_end());
        }
        error
    }

    /// Run a named workload remotely with default `max_steps = 256`.
    pub fn run_workload(
        &mut self,
        workload: &str,
        seed: EntryHash,
        attempts: usize,
        actor: ActorId,
    ) -> Result<RunOutcome, IpcError> {
        self.run_workload_with_steps(workload, seed, 256, attempts, actor)
    }

    /// Run a named workload remotely with explicit `max_steps`.
    pub fn run_workload_with_steps(
        &mut self,
        workload: &str,
        seed: EntryHash,
        max_steps: usize,
        attempts: usize,
        actor: ActorId,
    ) -> Result<RunOutcome, IpcError> {
        validate_workload_request(workload, max_steps, attempts, actor)?;
        let seed_hex = hex_encode(&seed);
        let request = serde_json::json!({
            "op": "run",
            "workload": workload,
            "seed_hex": seed_hex,
            "max_steps": max_steps,
            "attempts": attempts,
            "actor": actor.0
        });
        let response = self
            .request(request)
            .map_err(|error| self.attach_tail(error))?;
        if let Some(error) = response.get("error").and_then(|value| value.as_str()) {
            return Err(self.attach_tail(IpcError::Server(error.to_string())));
        }
        parse_run_response(&response)
    }

    /// Perform one request/response exchange over the socket.
    fn request(&mut self, value: serde_json::Value) -> Result<serde_json::Value, IpcError> {
        let mut line = serde_json::to_string(&value)?;
        line.push('\n');
        let stream = connect_with_retry(&self.socket_path)?;
        // Write request.
        {
            let mut writer = stream.try_clone()?;
            writer.write_all(line.as_bytes())?;
            writer.flush()?;
        }
        // Read response line with a timeout. Use blocking read with a simple
        // wall timeout to avoid hanging forever if the server stalls.
        let mut reader = BufReader::new(stream);
        let mut response_line = String::new();
        // Set read timeout if the platform supports it (UnixStream does via
        // set_read_timeout). We try, but continue without it if it fails.
        let _ = reader
            .get_mut()
            .set_read_timeout(Some(Duration::from_secs(5)));
        let bytes = reader.read_line(&mut response_line)?;
        if bytes == 0 {
            return Err(IpcError::Protocol(
                "server closed connection without response",
            ));
        }
        let trimmed = response_line.trim();
        if trimmed.is_empty() {
            return Err(IpcError::Protocol("empty response"));
        }
        serde_json::from_str(trimmed).map_err(Into::into)
    }

    /// Socket path for debugging or manual connects.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Engine binary path this process was spawned from.
    pub fn engine_path(&self) -> &Path {
        &self.engine_path
    }
}

impl Drop for EngineProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // Best-effort teardown; a lingering child is better than a panic
            // from Drop (child.kill returns Err when already exited).
            let _ = child.kill();
            let _ = child.wait();
        }
        // Best-effort socket cleanup; a stale socket is removed on next spawn.
        let _ = std::fs::remove_file(&self.socket_path);
        // Exclusive creation proved this directory is ours, so removing it
        // cannot delete foreign state.
        if let Some(dir) = self.cleanup_dir.take() {
            let _ = std::fs::remove_dir(&dir);
        }
    }
}

/// Create a fresh private directory for the engine socket.
fn prepare_socket_dir() -> Result<(PathBuf, PathBuf), IpcError> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        // Documented default: a clock before the epoch (clock skew) falls
        // back to zero; the value only randomizes a per-process socket dir.
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    prepare_socket_dir_with(|attempt| {
        std::env::temp_dir().join(format!("ldgr-rt-{pid}-{nanos}-{attempt}"))
    })
}

fn prepare_socket_dir_with<G>(mut next_dir: G) -> Result<(PathBuf, PathBuf), IpcError>
where
    G: FnMut(u64) -> PathBuf,
{
    for attempt in 0..SOCKET_DIR_ATTEMPTS {
        let dir = next_dir(attempt);
        match create_private_dir_checked(&dir) {
            Ok(()) => return Ok((dir.clone(), dir.join("engine.sock"))),
            // A pre-existing directory may be planted by another local user;
            // never adopt it, just try the next candidate name.
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(IpcError::SocketSetup {
                    path: dir.display().to_string(),
                    reason: error.to_string(),
                });
            }
        }
    }
    Err(IpcError::SocketSetup {
        path: std::env::temp_dir().display().to_string(),
        reason: format!("no free private socket directory after {SOCKET_DIR_ATTEMPTS} attempts"),
    })
}

/// Exclusively create `dir` with mode 0700 and prove ownership.
/// Returns raw IO error so callers distinguish collision from setup failure.
fn create_private_dir_checked(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    std::fs::DirBuilder::new().mode(0o700).create(dir)?;
    let metadata = std::fs::metadata(dir)?;
    if metadata.permissions().mode() & 0o777 != 0o700 {
        // Best-effort cleanup; the mode error is returned below.
        let _ = std::fs::remove_dir(dir);
        return Err(std::io::Error::other("directory mode is not 0700"));
    }
    // Ownership proof without libc: this process created the marker, so its
    // owner uid equals the current uid; comparing it against the directory
    // detects a swapped directory entry between create and stat.
    let marker = dir.join(".owner-probe");
    let owned = std::fs::write(&marker, b"")
        .and_then(|()| std::fs::metadata(&marker))
        .is_ok_and(|meta| meta.uid() == metadata.uid());
    // Best-effort marker cleanup; the ownership verdict is returned below.
    let _ = std::fs::remove_file(&marker);
    if !owned {
        // Best-effort cleanup; the ownership error is returned below.
        let _ = std::fs::remove_dir(dir);
        return Err(std::io::Error::other(
            "directory owner does not match this process",
        ));
    }
    Ok(())
}

/// Drain engine stderr on a dedicated OS thread (bounded by cap).
fn spawn_stderr_drain(stderr: std::process::ChildStderr, tail: Arc<Mutex<Vec<u8>>>) {
    use std::io::Read as _;

    std::thread::spawn(move || {
        let mut capped = stderr.take(STDERR_CAPTURE_CAP as u64);
        let mut buffer = Vec::new();
        // Best-effort capture: read failures simply shorten the tail.
        let _ = capped.read_to_end(&mut buffer);
        let mut slot = match tail.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        *slot = buffer;
    });
}

/// Validate one outbound workload request before it reaches the socket.
fn validate_workload_request(
    workload: &str,
    max_steps: usize,
    attempts: usize,
    actor: ActorId,
) -> Result<(), IpcError> {
    if workload.is_empty() || workload.len() > MAX_WORKLOAD_NAME_BYTES {
        return Err(IpcError::Protocol("invalid workload name"));
    }
    if max_steps == 0 || max_steps as u64 > MAX_SERVER_STEPS {
        return Err(IpcError::CounterBounds {
            name: "max_steps",
            raw: max_steps as u64,
        });
    }
    if attempts == 0 || attempts > MAX_IPC_ATTEMPTS {
        return Err(IpcError::CounterBounds {
            name: "attempts",
            raw: attempts as u64,
        });
    }
    if actor.0 > MAX_IPC_ACTOR {
        return Err(IpcError::CounterBounds {
            name: "actor",
            raw: u64::from(actor.0),
        });
    }
    Ok(())
}

/// Parse one successful `{roots, findings, steps}` reply.
fn parse_run_response(value: &serde_json::Value) -> Result<RunOutcome, IpcError> {
    let mut roots: Vec<EntryHash> = Vec::new();
    if let Some(array) = value.get("roots").and_then(|v| v.as_array()) {
        for item in array {
            if let Some(hex) = item.as_str() {
                roots.push(hex_decode32(hex)?);
            }
        }
    } else if let Some(hex) = value
        .get("journal_root")
        .or_else(|| value.get("journal_root_hex"))
        .and_then(|value| value.as_str())
    {
        roots.push(hex_decode32(hex)?);
    } else if let Some(hex) = value.get("root").and_then(|value| value.as_str()) {
        roots.push(hex_decode32(hex)?);
    }
    if roots.is_empty() {
        return Err(IpcError::Protocol("missing roots/journal_root in response"));
    }
    let findings_raw = value
        .get("findings")
        .and_then(|value| value.as_u64())
        .ok_or(IpcError::Protocol("missing integer findings in response"))?;
    let steps_raw = value
        .get("steps")
        .and_then(|value| value.as_u64())
        .ok_or(IpcError::Protocol("missing integer steps in response"))?;
    let findings = counter_from_server(findings_raw, MAX_SERVER_FINDINGS, "findings")?;
    let steps = counter_from_server(steps_raw, MAX_SERVER_STEPS, "steps")?;
    Ok(RunOutcome {
        roots,
        findings,
        steps,
    })
}

/// Convert one server-reported counter into `usize` under an explicit cap.
fn counter_from_server(raw: u64, cap: u64, name: &'static str) -> Result<usize, IpcError> {
    if raw > cap {
        return Err(IpcError::CounterBounds { name, raw });
    }
    usize::try_from(raw).map_err(|_| IpcError::CounterBounds { name, raw })
}

fn connect_with_retry(path: &Path) -> Result<std::os::unix::net::UnixStream, IpcError> {
    let mut last_error = String::new();
    for _ in 0..20 {
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(stream) => {
                // Ensure a read timeout for the subsequent read_line.
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                return Ok(stream);
            }
            Err(error) => {
                last_error = error.to_string();
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    Err(IpcError::Connect {
        path: path.display().to_string(),
        reason: last_error,
    })
}

fn hex_encode(hash: &EntryHash) -> String {
    ledger_format::hash_to_hex(hash)
}

fn hex_decode32(text: &str) -> Result<EntryHash, ledger_format::HexError> {
    let trimmed = text.trim();
    // Allow 0x prefix.
    let hex = if let Some(stripped) = trimmed.strip_prefix("0x") {
        stripped
    } else if let Some(stripped) = trimmed.strip_prefix("0X") {
        stripped
    } else {
        trimmed
    };
    ledger_format::hash_from_hex(hex)
}

#[cfg(test)]
mod tests {
    use super::{IpcError, counter_from_server, hex_decode32, hex_encode, parse_run_response};
    use ledger_format::EntryHash;

    const ROOT_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn hex_roundtrip() {
        let bytes = EntryHash([0xabu8; 32]);
        let encoded = hex_encode(&bytes);
        assert_eq!(encoded.len(), 64);
        let decoded = hex_decode32(&encoded).expect("decode must succeed");
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn hex_decode_rejects_short() {
        let error = hex_decode32("abcd").unwrap_err();
        assert!(
            matches!(error, ledger_format::HexError::InvalidLength(4)),
            "{error}"
        );
    }

    #[test]
    fn private_dir_is_exclusive_restricted_and_owned() {
        let dir = std::env::temp_dir().join(format!("ldgr-rt-private-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        super::create_private_dir_checked(&dir).expect("first create must succeed");
        let mode = {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::metadata(&dir)
                .expect("dir must exist")
                .permissions()
                .mode()
        };
        assert_eq!(mode & 0o777, 0o700, "private dir must be 0700");

        // A second exclusive create must refuse the existing directory
        // instead of adopting a potentially planted one; the collision kind
        // is what drives bounded retries upstream.
        let error =
            super::create_private_dir_checked(&dir).expect_err("pre-existing dir must be refused");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists, "{error}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn socket_dir_preparation_retries_name_collisions() {
        use core::cell::Cell;

        let root = std::env::temp_dir();
        let blocker = root.join(format!("ldgr-rt-retry-blocker-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&blocker);
        std::fs::create_dir(&blocker).expect("planted blocker directory");

        let calls = Cell::new(0u64);
        let result = super::prepare_socket_dir_with(|attempt| {
            calls.set(calls.get() + 1);
            if attempt == 0 {
                blocker.clone()
            } else {
                root.join(format!(
                    "ldgr-rt-retry-fresh-{}-{attempt}",
                    std::process::id()
                ))
            }
        })
        .expect("retry must find a fresh candidate after one collision");
        assert_eq!(calls.get(), 2, "a collision must consume exactly one retry");
        assert_eq!(result.0.parent(), Some(root.as_path()));

        let _ = std::fs::remove_dir_all(&blocker);
        let _ = std::fs::remove_dir_all(result.0);
    }

    #[test]
    fn socket_dir_preparation_surfaces_exhaustion() {
        use core::cell::Cell;

        let root = std::env::temp_dir();
        let blocked: Vec<std::path::PathBuf> = (0..super::SOCKET_DIR_ATTEMPTS)
            .map(|attempt| root.join(format!("ldgr-rt-exhaust-{}-{attempt}", std::process::id())))
            .collect();
        for dir in &blocked {
            let _ = std::fs::remove_dir_all(dir);
            std::fs::create_dir(dir).expect("planted collision directory");
        }

        let calls = Cell::new(0u64);
        let error = super::prepare_socket_dir_with(|attempt| {
            calls.set(calls.get() + 1);
            blocked[attempt as usize].clone()
        })
        .expect_err("every candidate collides");
        assert_eq!(calls.get(), super::SOCKET_DIR_ATTEMPTS);
        assert!(matches!(error, IpcError::SocketSetup { .. }), "{error}");

        for dir in &blocked {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn prepared_socket_sits_inside_private_dir() {
        let (dir, socket) = super::prepare_socket_dir().expect("prepared dir");
        assert!(dir.is_dir());
        assert_eq!(socket.parent(), Some(dir.as_path()));
        assert_eq!(
            socket.file_name().and_then(|n| n.to_str()),
            Some("engine.sock")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_run_response_accepts_well_formed_payload() {
        let payload = serde_json::json!({ "roots": [ROOT_HEX], "findings": 1, "steps": 7 });
        let outcome = parse_run_response(&payload).expect("well-formed reply");
        assert_eq!(outcome.roots.len(), 1);
        assert_eq!(outcome.findings, 1);
        assert_eq!(outcome.steps, 7);
    }

    #[test]
    fn parse_run_response_rejects_missing_or_absurd_counters() {
        let base = serde_json::json!({ "roots": [ROOT_HEX] });

        let missing_findings = {
            let mut value = base.clone();
            value["steps"] = serde_json::json!(1);
            value
        };
        assert!(matches!(
            parse_run_response(&missing_findings),
            Err(IpcError::Protocol(_))
        ));

        let missing_steps = {
            let mut value = base.clone();
            value["findings"] = serde_json::json!(0);
            value
        };
        assert!(matches!(
            parse_run_response(&missing_steps),
            Err(IpcError::Protocol(_))
        ));

        let oversized_steps = serde_json::json!({
            "roots": [ROOT_HEX],
            "findings": 0,
            "steps": u64::MAX
        });
        assert!(matches!(
            parse_run_response(&oversized_steps),
            Err(IpcError::CounterBounds { name: "steps", .. })
        ));

        let no_roots = serde_json::json!({ "findings": 0, "steps": 1 });
        assert!(matches!(
            parse_run_response(&no_roots),
            Err(IpcError::Protocol(_))
        ));
    }

    #[test]
    fn counters_convert_under_caps_only() {
        assert_eq!(counter_from_server(5, 10, "steps").expect("in-cap"), 5);
        let error = counter_from_server(11, 10, "steps").expect_err("over cap");
        assert!(
            matches!(
                error,
                IpcError::CounterBounds {
                    name: "steps",
                    raw: 11
                }
            ),
            "{error}"
        );
    }

    #[test]
    fn engine_path_requires_explicit_or_env() {
        // Explicit paths pass through untouched without touching the env.
        let explicit = std::path::PathBuf::from("/tmp/ledger-test-engine");
        assert_eq!(
            super::EngineProcess::resolve_engine_path(Some(explicit.clone()))
                .expect("explicit path"),
            explicit
        );
        // An empty LEDGER_ENGINE_BIN is not a configuration: without an
        // explicit path the resolver must fail closed typed. When the ambient
        // env provides a real binary the Ok branch is exercised elsewhere
        // (ipc_roundtrip); here only assert the error type is typed when it
        // fires, without mutating process env (unsafe in edition 2024).
        if std::env::var("LEDGER_ENGINE_BIN")
            .map(|v| v.trim().is_empty())
            .unwrap_or(true)
        {
            // Only assert when no ambient config exists; otherwise the env
            // supplies a binary and Ok is correct.
            let error = super::EngineProcess::resolve_engine_path(None)
                .expect_err("missing config must fail closed");
            assert!(matches!(error, IpcError::EngineNotConfigured), "{error}");
        }
    }

    #[test]
    fn workload_requests_are_bounded() {
        assert!(
            super::validate_workload_request("kv", 256, 1, ledger_format::ActorId(0)).is_ok(),
            "well-formed request passes"
        );
        assert!(matches!(
            super::validate_workload_request("", 256, 1, ledger_format::ActorId(0)),
            Err(IpcError::Protocol(_))
        ));
        assert!(matches!(
            super::validate_workload_request(&"k".repeat(129), 256, 1, ledger_format::ActorId(0)),
            Err(IpcError::Protocol(_))
        ));
        assert!(matches!(
            super::validate_workload_request("kv", 0, 1, ledger_format::ActorId(0)),
            Err(IpcError::CounterBounds {
                name: "max_steps",
                ..
            })
        ));
        assert!(matches!(
            super::validate_workload_request("kv", 256, 0, ledger_format::ActorId(0)),
            Err(IpcError::CounterBounds {
                name: "attempts",
                ..
            })
        ));
        assert!(matches!(
            super::validate_workload_request(
                "kv",
                256,
                1,
                ledger_format::ActorId(super::MAX_IPC_ACTOR + 1)
            ),
            Err(IpcError::CounterBounds { name: "actor", .. })
        ));
    }
}
