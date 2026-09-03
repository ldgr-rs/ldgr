// ledger-lint:allow (host application; rt-server binds Unix socket and uses std::fs, unlike simulation code)
//! Hidden `ledger rt-server` for the `ldgr-rt` IPC transport.
//! Unix socket, line-delimited JSON (`run` op only, strict bounds).
//! Roots are byte-identical to `ledger sim`; caller programs never cross.

use std::fmt;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use ledger_explorer::{HistoryOracle, KeyValueSpec, Oracle, Workload};
use ledger_format::EntryHash;
use ledger_sim::{RunConfig, RuntimeError, Simulation};

use crate::DefaultMiniKv;

/// Errors from one rt-server workload run (formatted into the wire reply).
#[derive(Debug)]
enum RunError {
    /// The simulation run failed.
    Sim(RuntimeError),
    /// The requested workload has no server implementation.
    UnknownWorkload(String),
    /// The request violated the wire protocol (op, fields, or bounds).
    Protocol(String),
    /// The connection failed at the byte level.
    Io(std::io::Error),
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sim(error) => write!(f, "{error}"),
            Self::UnknownWorkload(name) => write!(f, "unknown workload {name:?}"),
            Self::Protocol(reason) => write!(f, "protocol violation: {reason}"),
            Self::Io(error) => write!(f, "connection I/O error: {error}"),
        }
    }
}

impl std::error::Error for RunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sim(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::UnknownWorkload(_) | Self::Protocol(_) => None,
        }
    }
}

/// Run the rt-server on `socket` until the process is killed.
///
/// The listener is blocking. Each client connection is handled synchronously;
/// one line request, one line response, then the next line on the same
/// connection until EOF.
///
/// The socket file is chmod 0700 after bind (owner-only), so a peer outside
/// the owning uid cannot connect even when it reaches the parent directory.
/// The peer uid is checked via `peer_cred` against the socket owner; a
/// mismatched peer is dropped before any request bytes are read.
pub fn run(socket: &Path) -> Result<ExitCode, Box<dyn std::error::Error>> {
    // A stale socket file is cleaned up before bind. A missing file is the
    // normal first-bind case; every other removal failure propagates so a
    // cleanup problem cannot hide behind the bind.
    if let Err(error) = std::fs::remove_file(socket)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(error.into());
    }
    if let Some(parent) = socket.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let listener = bind_private(socket)?;
    eprintln!("ledger rt-server listening on {}", socket.display());
    let owner_uid = socket_owner_uid(socket);
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if !peer_uid_allowed(&stream, owner_uid) {
                    eprintln!("rt-server rejected peer with mismatching uid");
                    continue;
                }
                if let Err(error) = handle_client(&mut stream, UDS_READ_TIMEOUT) {
                    eprintln!("rt-server client error: {error}");
                }
            }
            Err(error) => {
                eprintln!("rt-server accept error: {error}");
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Owner uid of the socket file at `path`, when the platform exposes it.
fn socket_owner_uid(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|metadata| metadata.uid())
}

/// Check the peer credential against the socket owner.
fn peer_uid_allowed(stream: &std::os::unix::net::UnixStream, owner_uid: Option<u32>) -> bool {
    let Some(owner) = owner_uid else {
        return false;
    };
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        // SAFETY: ucred is a plain-data struct; zeroed is a valid initial value for getsockopt to fill.
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: getsockopt writes a ucred to cred when fd is a valid Unix socket and len is
        // correctly sized; the return value is checked and cred is only read on success.
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if ret != 0 {
            return false;
        }
        cred.uid == owner
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = stream;
        // On non-Linux Unix, SO_PEERCRED is not available; owner-only socket
        // permissions remain the enforced boundary.
        true
    }
}

/// Read timeout per client connection, mirroring the worker's UDS cap.
///
/// A stalled peer must not block the synchronous accept loop forever; the
/// connection is dropped when no line arrives within this interval.
const UDS_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Bind the server socket and enforce owner-only permissions.
///
/// The mode is applied after bind so a hostile peer outside the owner's uid
/// cannot connect even when it reaches the parent directory.
///
/// # Errors
/// Returns the bind error, or the permission error when the mode cannot be
/// applied (the listener drops and the bind is rolled back).
fn bind_private(socket: &Path) -> Result<UnixListener, std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = socket.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    let listener = UnixListener::bind(socket)?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o700))?;
    Ok(listener)
}

/// Hard cap for one client request line, matching the worker-side UDS cap.
///
/// A longer line cannot be delimited reliably, so the connection is dropped
/// after the cap fires; the unread tail never parses as a new request.
const MAX_UDS_LINE_SIZE: usize = 1 << 20;

/// Read one newline-delimited line under [`MAX_UDS_LINE_SIZE`].
///
/// Mirrors the worker UDS reader: at most `MAX_UDS_LINE_SIZE + 1` bytes are
/// buffered, a longer line is an error, and EOF without a trailing newline
/// still returns the partial line. An empty line returns `None`.
///
/// # Errors
/// Returns [`RunError::Protocol`] when the line exceeds the cap and
/// [`RunError::Io`] when the underlying reader fails.
fn read_bounded_line<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>, RunError> {
    let mut limited = reader.take((MAX_UDS_LINE_SIZE + 1) as u64);
    let mut buf = Vec::with_capacity(MAX_UDS_LINE_SIZE.min(4096));
    let n = limited.read_until(b'\n', &mut buf).map_err(RunError::Io)?;
    if n == 0 {
        return Ok(None);
    }
    if buf.ends_with(b"\n") {
        buf.pop();
    }
    if buf.len() > MAX_UDS_LINE_SIZE {
        return Err(RunError::Protocol(format!(
            "request exceeds {MAX_UDS_LINE_SIZE} bytes"
        )));
    }
    if buf.is_empty() {
        return Ok(None);
    }
    Ok(Some(buf))
}

fn handle_client(
    stream: &mut std::os::unix::net::UnixStream,
    read_timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    // A stalled peer must not block the synchronous accept loop: every line
    // read is bounded, and a timeout drops the connection (fail closed). The
    // timeout is a socket option, shared by the cloned descriptor the
    // buffered reader uses.
    stream.set_read_timeout(Some(read_timeout))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    while let Some(line) = read_bounded_line(&mut reader)? {
        let text = match std::str::from_utf8(&line) {
            Ok(text) => text,
            Err(_) => {
                // Non-UTF-8 cannot be JSON: reply with a typed error and
                // continue with the next line.
                let mut out = serde_json::to_string(&serde_json::json!({
                    "error": "request line is not valid UTF-8"
                }))?;
                out.push('\n');
                stream.write_all(out.as_bytes())?;
                stream.flush()?;
                continue;
            }
        };
        let trimmed = text.trim();
        if trimmed.is_empty() {
            continue;
        }
        let response = handle_request(trimmed);
        let mut out = serde_json::to_string(&response)?;
        out.push('\n');
        stream.write_all(out.as_bytes())?;
        stream.flush()?;
    }
    Ok(())
}

/// Upper bound for a client-supplied step budget, matching the cap the
/// ldgr-rt client applies to server-reported counts (`MAX_SERVER_STEPS`).
const MAX_INBOUND_STEPS: u64 = 1 << 40;
/// Upper bound for client-supplied attempt counts; one journal per attempt.
const MAX_INBOUND_ATTEMPTS: u64 = 1 << 16;
/// Step budget used when the request omits one.
const DEFAULT_MAX_STEPS: u64 = 256;

/// One validated `run` request.
#[derive(Debug)]
struct RunRequest<'a> {
    workload: &'a str,
    seed: EntryHash,
    max_steps: usize,
    attempts: usize,
}

/// Convert one inbound counter under an explicit cap with a lossless
/// platform-width conversion; nothing is clamped or truncated.
fn bounded_inbound(raw: u64, cap: u64, name: &str) -> Result<usize, RunError> {
    if raw > cap {
        return Err(RunError::Protocol(format!(
            "{name}={raw} exceeds cap {cap}"
        )));
    }
    usize::try_from(raw).map_err(|_| RunError::Protocol(format!("{name}={raw} out of range")))
}

/// Read an optional non-negative integer field. A present field must parse;
/// wrong types are protocol errors, not silent defaults.
fn optional_counter(value: &serde_json::Value, key: &str) -> Result<Option<u64>, RunError> {
    match value.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(raw) => raw
            .as_u64()
            .map(Some)
            .ok_or_else(|| RunError::Protocol(format!("{key} must be a non-negative integer"))),
    }
}

fn parse_run_request(value: &serde_json::Value) -> Result<RunRequest<'_>, RunError> {
    let op = value
        .get("op")
        .and_then(|value| value.as_str())
        .ok_or_else(|| RunError::Protocol("missing op field".to_string()))?;
    if op != "run" {
        return Err(RunError::Protocol(format!(
            "unsupported op {op:?}; expected \"run\""
        )));
    }
    // The workload is explicit by contract: no silent default can run a
    // different program than the client named.
    let workload = value
        .get("workload")
        .and_then(|value| value.as_str())
        .ok_or_else(|| RunError::Protocol("missing workload field".to_string()))?;
    let max_steps_raw = optional_counter(value, "max_steps")?
        .or(optional_counter(value, "steps")?)
        .unwrap_or(DEFAULT_MAX_STEPS);
    let attempts_raw = optional_counter(value, "attempts")?.unwrap_or(1);
    let max_steps = bounded_inbound(max_steps_raw, MAX_INBOUND_STEPS, "max_steps")?;
    let attempts = bounded_inbound(attempts_raw, MAX_INBOUND_ATTEMPTS, "attempts")?;
    let seed = if let Some(hex) = value.get("seed_hex").and_then(|value| value.as_str()) {
        hex_decode32(hex).map_err(|error| RunError::Protocol(error.to_string()))?
    } else if let Some(hex) = value.get("seed").and_then(|value| value.as_str()) {
        hex_decode32(hex).map_err(|error| RunError::Protocol(error.to_string()))?
    } else if let Some(raw) = value.get("seed_u64") {
        // A present seed_u64 must be a u64 integer; an overflow or a string
        // is a protocol error, never a silent fallback to the zero seed.
        let number = raw.as_u64().ok_or_else(|| {
            RunError::Protocol("seed_u64 must be an integer in 0..=u64::MAX".to_string())
        })?;
        crate::seed_from_u64(number)
    } else {
        EntryHash([0u8; 32])
    };
    Ok(RunRequest {
        workload,
        seed,
        max_steps,
        attempts,
    })
}

fn handle_request(text: &str) -> serde_json::Value {
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(error) => {
            return serde_json::json!({"error": format!("invalid json: {error}")});
        }
    };
    let request = match parse_run_request(&value) {
        Ok(request) => request,
        Err(error) => return serde_json::json!({"error": error.to_string()}),
    };
    match run_workload_named(
        request.workload,
        request.seed,
        request.max_steps,
        request.attempts,
    ) {
        Ok((roots, findings, steps)) => {
            let hex_roots: Vec<String> = roots.iter().map(hex_encode).collect();
            // Back-compat single-root fields appear only when a root exists so
            // an absent root stays distinguishable from an empty-string root;
            // the `roots` array is the canonical field.
            let first_root = hex_roots.first().cloned();
            let mut response = serde_json::json!({
                "roots": hex_roots,
                "findings": findings,
                "steps": steps
            });
            if let Some(first_root) = first_root {
                response["journal_root"] = serde_json::json!(first_root);
                response["journal_root_hex"] = serde_json::json!(first_root);
            }
            response
        }
        Err(error) => serde_json::json!({"error": error.to_string()}),
    }
}

fn run_workload_named(
    workload: &str,
    seed: EntryHash,
    max_steps: usize,
    attempts: usize,
) -> Result<(Vec<EntryHash>, usize, usize), RunError> {
    // Named dispatch is the only remote execution surface; caller programs
    // stay in the SUT process and are refused by ldgr-rt under `sim`.
    // No aliases: unknown names fail loudly so removed workloads stay gone.
    match workload {
        "kv" => run_kv(seed, max_steps, attempts).map_err(RunError::Sim),
        other => Err(RunError::UnknownWorkload(other.to_string())),
    }
}

fn run_kv(
    seed: EntryHash,
    max_steps: usize,
    attempts: usize,
) -> Result<(Vec<EntryHash>, usize, usize), RuntimeError> {
    let workload = DefaultMiniKv;
    let oracle = HistoryOracle::new(&workload, KeyValueSpec::default());
    let attempts = attempts.max(1);
    let mut roots = Vec::with_capacity(attempts);
    let mut findings = 0usize;
    let mut max_steps_seen = 0usize;
    for attempt in 0..attempts {
        let mut attempt_seed = seed;
        if attempts > 1 {
            attempt_seed.0[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());
        }
        let config = RunConfig::builder()
            .seed(attempt_seed)
            .max_steps(max_steps)
            .build();
        let run = Simulation::new(config, workload.programs()).run()?;
        roots.push(run.journal.root_hash());
        max_steps_seen = max_steps_seen.max(run.steps);
        if oracle.check(&run).violated {
            findings += 1;
        }
    }
    Ok((roots, findings, max_steps_seen))
}

fn hex_encode(hash: &EntryHash) -> String {
    ledger_format::hash_to_hex(hash)
}

fn hex_decode32(text: &str) -> Result<EntryHash, ledger_format::HexError> {
    let trimmed = text.trim();
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
    use super::{EntryHash, RunError, hex_decode32, hex_encode};

    #[test]
    fn hex_roundtrip() {
        let bytes = EntryHash([0x5au8; 32]);
        let encoded = hex_encode(&bytes);
        assert_eq!(encoded.len(), 64);
        let decoded = hex_decode32(&encoded).expect("decode");
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn hex_decode32_tolerates_prefix_and_padding() {
        let bytes = EntryHash([0x11u8; 32]);
        let encoded = hex_encode(&bytes);
        assert_eq!(hex_decode32(&format!("0x{encoded}")).unwrap(), bytes);
        assert_eq!(hex_decode32(&format!("  {encoded} \n")).unwrap(), bytes);
        assert!(hex_decode32("nothex").is_err());
    }

    #[test]
    fn run_kv_is_deterministic() {
        let seed = EntryHash([7u8; 32]);
        let (a_roots, _, _) = super::run_kv(seed, 256, 1).expect("run");
        let (b_roots, _, _) = super::run_kv(seed, 256, 1).expect("run");
        assert_eq!(a_roots, b_roots);
    }

    /// Legacy workload aliases were removed with no compatibility surface;
    /// every removed name must keep failing loudly as UnknownWorkload.
    #[test]
    fn removed_legacy_workload_names_stay_unknown() {
        for name in [
            "sut-default",
            "sut_default",
            "mini-kv",
            "mini_kv",
            "default",
        ] {
            let error = super::run_workload_named(name, EntryHash([7u8; 32]), 256, 1).unwrap_err();
            assert!(
                matches!(error, RunError::UnknownWorkload(ref got) if got == name),
                "{name} must stay an unknown workload, got {error}"
            );
        }
    }

    /// The request parser sits on a trust boundary: only the exact `run` op
    /// is accepted, the workload is required, and counters are bounded with
    /// lossless conversions.
    #[test]
    fn run_request_parsing_is_strict_at_the_boundary() {
        use super::{MAX_INBOUND_ATTEMPTS, MAX_INBOUND_STEPS, parse_run_request};
        let valid = serde_json::json!({
            "op": "run",
            "workload": "kv",
            "seed_hex": "11".repeat(32),
            "max_steps": 64,
            "attempts": 2,
        });
        let request = parse_run_request(&valid).expect("valid request");
        assert_eq!(request.workload, "kv");
        assert_eq!(request.max_steps, 64);
        assert_eq!(request.attempts, 2);

        // Rejected op spellings stay rejected; nothing normalizes them.
        for op in ["run-workload", "run_workload", "Run", ""] {
            let mut value = valid.clone();
            value["op"] = serde_json::json!(op);
            let error = parse_run_request(&value).unwrap_err();
            assert!(
                matches!(error, RunError::Protocol(_)),
                "op {op:?} must be a protocol violation"
            );
        }

        // The workload is explicit by contract: no silent default.
        let mut missing_workload = valid.clone();
        missing_workload
            .as_object_mut()
            .expect("object")
            .remove("workload");
        let error = parse_run_request(&missing_workload).unwrap_err();
        assert!(
            matches!(error, RunError::Protocol(ref reason) if reason.contains("workload")),
            "{error}"
        );

        let wrong_type = serde_json::json!({
            "op": "run", "workload": "kv", "max_steps": "many",
        });
        assert!(matches!(
            parse_run_request(&wrong_type),
            Err(RunError::Protocol(_))
        ));

        let oversized_steps = serde_json::json!({
            "op": "run", "workload": "kv", "max_steps": MAX_INBOUND_STEPS + 1,
        });
        let RunError::Protocol(reason) = parse_run_request(&oversized_steps).unwrap_err() else {
            panic!("oversized max_steps must be a protocol violation");
        };
        assert!(reason.contains("max_steps"), "{reason}");

        let oversized_attempts = serde_json::json!({
            "op": "run", "workload": "kv", "attempts": MAX_INBOUND_ATTEMPTS + 1,
        });
        let RunError::Protocol(reason) = parse_run_request(&oversized_attempts).unwrap_err() else {
            panic!("oversized attempts must be a protocol violation");
        };
        assert!(reason.contains("attempts"), "{reason}");

        // Defaults apply only to genuinely absent fields.
        let minimal = serde_json::json!({ "op": "run", "workload": "kv" });
        let request = parse_run_request(&minimal).expect("minimal request");
        assert_eq!(request.max_steps, 256);
        assert_eq!(request.attempts, 1);
        assert_eq!(request.seed, EntryHash([0u8; 32]));
    }

    /// A present but invalid seed must be a protocol error: an overflowing
    /// number, a negative number, or a string must never silently fall back
    /// to the zero seed.
    #[test]
    fn invalid_present_seed_is_a_protocol_error() {
        use super::{MAX_INBOUND_STEPS, parse_run_request};
        let base = serde_json::json!({
            "op": "run",
            "workload": "kv",
            "max_steps": MAX_INBOUND_STEPS,
        });
        let bad_values = [
            serde_json::json!("18446744073709551616"),
            serde_json::json!(-1),
            serde_json::json!("0x10"),
            serde_json::json!(1.8e19),
            serde_json::json!(1.5),
        ];
        for bad in bad_values {
            let mut value = base.clone();
            value["seed_u64"] = bad.clone();
            let error = parse_run_request(&value).unwrap_err();
            assert!(
                matches!(error, RunError::Protocol(ref reason) if reason.contains("seed_u64")),
                "{bad}: {error}"
            );
        }
        // Malformed hex in either seed alias is a protocol error.
        for key in ["seed_hex", "seed"] {
            let mut value = base.clone();
            value[key] = serde_json::json!("zz");
            assert!(matches!(
                parse_run_request(&value),
                Err(RunError::Protocol(_))
            ));
        }
        // A valid seed_u64 is honored, not defaulted.
        let mut value = base.clone();
        value["seed_u64"] = serde_json::json!(42);
        let request = parse_run_request(&value).expect("valid seed_u64");
        assert_ne!(request.seed, EntryHash([0u8; 32]));
    }

    #[test]
    fn bounded_line_reader_enforces_the_cap() {
        use super::{MAX_UDS_LINE_SIZE, read_bounded_line};
        use std::io::BufReader;
        let exact = vec![b'x'; MAX_UDS_LINE_SIZE];
        let mut exact_reader = BufReader::new(exact.as_slice());
        let line = read_bounded_line(&mut exact_reader)
            .expect("exact-size line parses")
            .expect("a line is present");
        assert_eq!(line.len(), MAX_UDS_LINE_SIZE);

        let over = vec![b'x'; MAX_UDS_LINE_SIZE + 1];
        let mut over_reader = BufReader::new(over.as_slice());
        let error = read_bounded_line(&mut over_reader).expect_err("oversized line");
        assert!(
            matches!(error, RunError::Protocol(ref reason) if reason.contains("exceeds")),
            "{error}"
        );

        let mut multi = BufReader::new(&b"first\nsecond\n"[..]);
        assert_eq!(
            read_bounded_line(&mut multi).expect("first").expect("line"),
            b"first"
        );
        assert_eq!(
            read_bounded_line(&mut multi)
                .expect("second")
                .expect("line"),
            b"second"
        );
        assert!(read_bounded_line(&mut multi).expect("eof").is_none());

        // EOF without a trailing newline returns the partial line.
        let mut partial = BufReader::new(&b"tail"[..]);
        assert_eq!(
            read_bounded_line(&mut partial)
                .expect("partial")
                .expect("line"),
            b"tail"
        );
        // A blank line reads as no request.
        let mut blank = BufReader::new(&b"\n"[..]);
        assert!(read_bounded_line(&mut blank).expect("blank").is_none());
    }

    /// The connection layer replies to well-formed lines, rejects non-UTF-8
    /// lines with an error reply, and drops the connection on an oversized
    /// line without a reply (the worker UDS pattern).
    #[test]
    fn connection_handles_replies_utf8_errors_and_oversized_drops() {
        use std::io::{BufRead, BufReader, Read, Write};
        let (mut client, mut server) = std::os::unix::net::UnixStream::pair().expect("pair");
        let handle = std::thread::spawn(move || {
            match super::handle_client(&mut server, super::UDS_READ_TIMEOUT) {
                Ok(()) => Ok(()),
                // The handler error type is not Send; stringify on the worker.
                Err(error) => Err(error.to_string()),
            }
        });

        // Malformed JSON gets a typed error reply and the connection stays up.
        client.write_all(b"not json at all\n").expect("write");
        let mut reader = BufReader::new(client.try_clone().expect("clone"));
        let mut line = String::new();
        reader.read_line(&mut line).expect("read error reply");
        assert!(
            line.contains("\"error\""),
            "expected an error reply: {line}"
        );

        // Non-UTF-8 cannot be JSON; the error reply names the cause.
        client.write_all(b"\xff\xfe\x01\n").expect("write bytes");
        line.clear();
        reader.read_line(&mut line).expect("read utf8 reply");
        assert!(
            line.contains("UTF-8"),
            "expected a UTF-8 error reply: {line}"
        );

        // An oversized line produces no reply; the connection is dropped.
        client
            .write_all(&vec![b'x'; super::MAX_UDS_LINE_SIZE + 1])
            .expect("write oversized");
        let mut tail = Vec::new();
        let read = client.read_to_end(&mut tail).expect("read to end");
        assert_eq!(read, 0, "no reply may arrive for an oversized line");
        drop(client);
        let result = handle.join().expect("handler thread panicked");
        let error = result.expect_err("oversized line must fail the connection");
        assert!(error.contains("exceeds"), "{error}");
    }

    /// The socket file must be owner-only after bind; a hostile peer outside
    /// the owning uid must not be able to connect even when it reaches the
    /// parent directory.
    #[test]
    fn bind_private_enforces_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "ldgr-rt-server-{}-{}.sock",
            std::process::id(),
            0x5a
        ));
        let listener = super::bind_private(&path).expect("bind");
        let mode = std::fs::metadata(&path)
            .expect("socket metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "socket mode must be owner-only");
        drop(listener);
        std::fs::remove_file(&path).expect("cleanup");
    }

    /// A stalled peer must not block the synchronous accept loop: the read
    /// timeout drops the connection without a reply (fail closed).
    #[test]
    fn stalled_connection_is_dropped_after_read_timeout() {
        use std::io::Read;
        let (mut client, mut server) = std::os::unix::net::UnixStream::pair().expect("pair");
        let handle = std::thread::spawn(move || {
            match super::handle_client(&mut server, std::time::Duration::from_millis(50)) {
                Ok(()) => Ok(()),
                Err(error) => Err(error.to_string()),
            }
        });
        // Send nothing; the server must time out and drop the connection.
        let mut buf = Vec::new();
        let start = std::time::Instant::now();
        client.read_to_end(&mut buf).expect("read to EOF");
        let elapsed = start.elapsed();
        assert!(
            buf.is_empty(),
            "a stalled peer must receive no reply, got {} bytes",
            buf.len()
        );
        assert!(
            elapsed >= std::time::Duration::from_millis(50),
            "the drop must wait for the read timeout, not earlier: {elapsed:?}"
        );
        drop(client);
        let result = handle.join().expect("handler thread panicked");
        let error = result.expect_err("stalled connection must fail with the timeout");
        assert!(error.contains("I/O error"), "{error}");
    }
}
