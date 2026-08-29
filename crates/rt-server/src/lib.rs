// ledger-lint:allow (host daemon; rt-server binds Unix domain socket and uses std::fs for socket path setup)
//! AGPL composition root: the deterministic engine effect server.
//!
//! The server binds a private Unix socket, authenticates the peer by its
//! socket credentials, and serves one effect session per connection. A
//! session runs the `ldgr_rt::proto` framed protocol: the client sends a
//! `Hello` carrying the session identity, then one
//! `EffectRequest` per deterministic effect, then
//! `Finish`; the server replies with
//! `Welcome`, one `EffectResponse`
//! per request, and a final `Goodbye` carrying the
//! journal root and entry count.
//!
//! Every effect is served by the deterministic `SimBackend` and journaled.
//! Computation between effects (the SUT's business logic) is outside the
//! deterministic boundary: the engine only ever sees the effects themselves,
//! so the journal is a pure function of the effect stream and the seed.

#![deny(unsafe_code)]

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use ldgr_rt::proto::{
    Effect, EffectRequest, EffectResponse, EffectResult, Goodbye, Hello, Message as Wire, Reject,
    RejectReason, Welcome, decode_frame, decode_message, encode_frame, encode_message,
};
use ledger_format::{ActorId, Hash, MessageId};
use ledger_sim::{Effects, Message, SeedTree, SimBackend};
use rand_core::Rng;
use thiserror::Error;

/// Domain separator for the session identity derivation.
pub const SESSION_IDENTITY_DOMAIN: &[u8] = b"ldgr.d1.session\0";

/// Derive the session identity bound by the handshake.
///
/// The full `ExecutionIdentity` assembly (B2) is the production source; the
/// handshake already carries and verifies a 32-byte identity field, and this
/// derivation is the deterministic placeholder available to both the AGPL
/// server and the Apache-2.0 client without engine linkage.
pub fn session_identity(seed: Hash) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SESSION_IDENTITY_DOMAIN);
    hasher.update(&seed);
    *hasher.finalize().as_bytes()
}

/// Errors from the engine server.
#[derive(Debug, Error)]
pub enum ServerError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(#[from] ldgr_rt::proto::DecodeError),
    #[error("session rejected: {0:?}")]
    Rejected(RejectReason),
    #[error("socket setup failed at {path}: {reason}")]
    SocketSetup { path: String, reason: String },
}

/// One effect session against a single-actor deterministic backend.
pub struct Session {
    backend: SimBackend,
    actor: u32,
    expected_identity: Hash,
    send_sequence: u64,
}

impl Session {
    /// Create a session for `actor` bound to `seed` and `expected_identity`.
    pub fn new(seed: Hash, actor: u32, expected_identity: Hash) -> Self {
        Self {
            backend: SimBackend::new(SeedTree::new(seed)),
            actor,
            expected_identity,
            send_sequence: 0,
        }
    }

    /// Serve one session over generic read/write streams.
    ///
    /// Transport-agnostic so the protocol is testable with an in-process
    /// byte pair instead of a real socket.
    pub fn serve(
        &mut self,
        mut reader: impl Read,
        mut writer: impl Write,
    ) -> Result<Goodbye, ServerError> {
        // Handshake: sequence 0 must be the client Hello.
        let (hello_seq, hello) = read_message(&mut reader)?;
        if hello_seq != 0 {
            return self.reject(
                &mut writer,
                RejectReason::Protocol,
                "first frame is not hello",
            );
        }
        let Wire::Hello(Hello { identity }) = hello else {
            return self.reject(&mut writer, RejectReason::Protocol, "expected hello");
        };
        if identity != self.expected_identity {
            return self.reject(
                &mut writer,
                RejectReason::Identity,
                "session identity mismatch",
            );
        }
        write_message(
            &mut writer,
            hello_seq,
            &Wire::Welcome(Welcome { actor: self.actor }),
        )?;

        // Effect loop: sequences must be exactly 1, 2, ... per session.
        let mut next_seq = 1u64;
        loop {
            let (seq, frame) = read_message(&mut reader)?;
            if seq != next_seq {
                return self.reject(
                    &mut writer,
                    RejectReason::Protocol,
                    "sequence gap or repeat",
                );
            }
            next_seq = next_seq.checked_add(1).ok_or_else(|| {
                let _ = std::io::Error::new(std::io::ErrorKind::InvalidData, "sequence overflow");
                ServerError::Rejected(RejectReason::Protocol)
            })?;
            match frame {
                Wire::EffectRequest(EffectRequest { effect }) => {
                    let result = self.apply(effect)?;
                    write_message(
                        &mut writer,
                        seq,
                        &Wire::EffectResponse(EffectResponse { result }),
                    )?;
                }
                Wire::Finish => {
                    let journal = self.backend.journal_snapshot();
                    let goodbye = Goodbye {
                        root: journal.root_hash(),
                        entries: journal.len() as u64,
                    };
                    write_message(&mut writer, seq, &Wire::Goodbye(goodbye.clone()))?;
                    return Ok(goodbye);
                }
                other => {
                    return self.reject(
                        &mut writer,
                        RejectReason::Protocol,
                        &format!("unexpected message in effect loop: {other:?}"),
                    );
                }
            }
        }
    }

    fn apply(&mut self, effect: Effect) -> Result<EffectResult, ServerError> {
        match effect {
            Effect::Clock => Ok(EffectResult::Clock {
                ticks: self.backend.clock().now(),
            }),
            Effect::Sleep { ticks } => {
                futures::executor::block_on(self.backend.sleep(Duration::from_micros(ticks)));
                Ok(EffectResult::Ok)
            }
            Effect::Random { stream, count } => {
                let mut words = Vec::with_capacity(count as usize * 8);
                let rng = self.backend.rng(stream);
                for _ in 0..count {
                    words.extend_from_slice(&rng.next_u64().to_le_bytes());
                }
                Ok(EffectResult::Random { words })
            }
            Effect::Send { to, payload } => {
                let message = Message {
                    from: self.actor as usize,
                    to: to as usize,
                    content: payload,
                    send_id: [0u8; 32],
                    message_id: MessageId::new(self.actor as ActorId, self.send_sequence),
                    deliver_at: 0,
                };
                self.send_sequence = self.send_sequence.saturating_add(1);
                self.backend.net().send(message);
                Ok(EffectResult::Ok)
            }
            Effect::Recv => {
                let message = self
                    .backend
                    .net()
                    .recv(self.actor as usize, self.backend.clock().now());
                Ok(EffectResult::Recv {
                    payload: message.map(|m| m.content),
                })
            }
            Effect::FsWrite {
                path,
                offset,
                bytes,
            } => {
                self.backend
                    .fs_write_bytes(&path, offset, bytes)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                Ok(EffectResult::Ok)
            }
            Effect::FsRead { path, offset, len } => {
                let observed = self
                    .backend
                    .fs_read_bytes(&path, offset, len)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                let observed_bytes = match observed {
                    ledger_format::ObservedRead::Missing => Vec::new(),
                    ledger_format::ObservedRead::Present { content } => content,
                };
                Ok(EffectResult::FsRead {
                    observed: observed_bytes,
                })
            }
            Effect::FsSync { path } => {
                self.backend
                    .fs_sync_path(&path)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                Ok(EffectResult::Ok)
            }
        }
    }

    fn reject(
        &mut self,
        writer: &mut impl Write,
        reason: RejectReason,
        detail: &str,
    ) -> Result<Goodbye, ServerError> {
        let reply = Wire::Reject(Reject {
            reason,
            detail: detail.to_string(),
        });
        write_message(writer, 0, &reply)?;
        Err(ServerError::Rejected(reason))
    }
}

/// Read one frame from a stream and decode its message body.
fn read_message(reader: &mut impl Read) -> Result<(u64, Wire), ServerError> {
    let mut header = [0u8; ldgr_rt::proto::codec::FRAME_HEADER_LEN];
    reader.read_exact(&mut header)?;
    let (_, body_len) = ldgr_rt::proto::parse_header(&header)?;
    let mut full = Vec::with_capacity(ldgr_rt::proto::codec::FRAME_HEADER_LEN + body_len);
    full.extend_from_slice(&header);
    if body_len > 0 {
        full.resize(ldgr_rt::proto::codec::FRAME_HEADER_LEN + body_len, 0);
        reader.read_exact(&mut full[ldgr_rt::proto::codec::FRAME_HEADER_LEN..])?;
    }
    let (seq, body) = decode_frame(&full)?;
    let message = decode_message(body)?;
    Ok((seq, message))
}

/// Encode and write one frame.
fn write_message(writer: &mut impl Write, seq: u64, message: &Wire) -> Result<(), ServerError> {
    let body = encode_message(message);
    let frame = encode_frame(seq, &body)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    writer.write_all(&frame)?;
    writer.flush()?;
    Ok(())
}

/// Run the engine server until interrupted.
///
/// Binds `socket` (cleaning up any stale file), verifies connecting peers,
/// and serves one session per connection. On Linux the peer uid is checked;
/// non-matching peers are rejected before the handshake.
pub fn run(socket: &Path, seed: Hash) -> Result<std::process::ExitCode, ServerError> {
    if let Err(error) = std::fs::remove_file(socket)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(ServerError::SocketSetup {
            path: socket.display().to_string(),
            reason: error.to_string(),
        });
    }
    if let Some(parent) = socket.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(socket)?;
    let expected_identity = session_identity(seed);
    for stream in listener.incoming() {
        let mut stream = stream?;
        if !peer_is_current_user(&stream) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            continue;
        }
        let mut session = Session::new(seed, 0, expected_identity);
        let mut reader = stream.try_clone()?;
        let _ = session.serve(&mut reader, &mut stream);
    }
    Ok(std::process::ExitCode::SUCCESS)
}

/// Verify the peer socket credentials match the current user. On Linux the
/// `SO_PEERCRED` socket option is checked; on other Unix platforms where
/// `SO_PEERCRED` is unavailable the private mode-0700 socket directory is the
/// boundary.
#[allow(unsafe_code)]
fn peer_is_current_user(stream: &UnixStream) -> bool {
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
        // SAFETY: geteuid is a libc accessor with no failure mode.
        let current_uid = unsafe { libc::geteuid() };
        cred.uid == current_uid
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = stream;
        true
    }
}

/// Serve one session over a byte-pair in memory (tests and the acceptance
/// harness use this to exercise the full protocol without a socket).
pub fn serve_session(
    seed: Hash,
    actor: u32,
    identity: Hash,
    input: &[u8],
) -> Result<Goodbye, ServerError> {
    let mut session = Session::new(seed, actor, identity);
    let mut reader = std::io::Cursor::new(input.to_vec());
    let mut writer = Vec::new();
    let goodbye = session.serve(&mut reader, &mut writer)?;
    Ok(goodbye)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldgr_rt::proto::{Effect, EffectRequest, Hello, Message, encode_frame, encode_message};

    fn frames(_seed: Hash, identity: Hash) -> Vec<u8> {
        let hello = encode_frame(0, &encode_message(&Message::Hello(Hello { identity }))).unwrap();
        let clock = encode_frame(
            1,
            &encode_message(&Message::EffectRequest(EffectRequest {
                effect: Effect::Clock,
            })),
        )
        .unwrap();
        let write = encode_frame(
            2,
            &encode_message(&Message::EffectRequest(EffectRequest {
                effect: Effect::FsWrite {
                    path: "/kv/k".into(),
                    offset: 0,
                    bytes: 42u64.to_le_bytes().to_vec(),
                },
            })),
        )
        .unwrap();
        let read = encode_frame(
            3,
            &encode_message(&Message::EffectRequest(EffectRequest {
                effect: Effect::FsRead {
                    path: "/kv/k".into(),
                    offset: 0,
                    len: 8,
                },
            })),
        )
        .unwrap();
        let finish = encode_frame(4, &encode_message(&Message::Finish)).unwrap();
        [hello, clock, write, read, finish].concat()
    }

    #[test]
    fn full_session_serves_effects_and_journals_a_root() {
        let seed = [7u8; 32];
        let identity = session_identity(seed);
        let input = frames(seed, identity);
        let goodbye = serve_session(seed, 0, identity, &input).expect("session serves");
        assert_ne!(
            goodbye.root, [0u8; 32],
            "a served session must produce a root"
        );
        assert!(
            goodbye.entries >= 1,
            "at least one effect must journal (got {} entries)",
            goodbye.entries
        );
    }

    #[test]
    fn identity_mismatch_fails_closed() {
        let seed = [7u8; 32];
        let identity = session_identity(seed);
        let wrong = [9u8; 32];
        let input = frames(seed, wrong);
        let err = serve_session(seed, 0, identity, &input).unwrap_err();
        assert!(matches!(
            err,
            ServerError::Rejected(ldgr_rt::proto::RejectReason::Identity)
        ));
    }

    #[test]
    fn sequence_gap_fails_closed() {
        let seed = [7u8; 32];
        let identity = session_identity(seed);
        // Hello (seq 0), then Clock at seq 5 (gap) must be rejected.
        let hello = encode_frame(0, &encode_message(&Message::Hello(Hello { identity }))).unwrap();
        let clock = encode_frame(
            5,
            &encode_message(&Message::EffectRequest(EffectRequest {
                effect: Effect::Clock,
            })),
        )
        .unwrap();
        let input = [hello, clock].concat();
        let err = serve_session(seed, 0, identity, &input).unwrap_err();
        assert!(matches!(
            err,
            ServerError::Rejected(ldgr_rt::proto::RejectReason::Protocol)
        ));
    }

    #[test]
    fn byte_faithful_fs_operations_roundtrip() {
        let seed = [12u8; 32];
        let identity = session_identity(seed);
        let payload = vec![0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0x42];
        let hello = encode_frame(0, &encode_message(&Message::Hello(Hello { identity }))).unwrap();
        let write = encode_frame(
            1,
            &encode_message(&Message::EffectRequest(EffectRequest {
                effect: Effect::FsWrite {
                    path: "/data/file.bin".into(),
                    offset: 16,
                    bytes: payload.clone(),
                },
            })),
        )
        .unwrap();
        let read = encode_frame(
            2,
            &encode_message(&Message::EffectRequest(EffectRequest {
                effect: Effect::FsRead {
                    path: "/data/file.bin".into(),
                    offset: 16,
                    len: payload.len() as u64,
                },
            })),
        )
        .unwrap();
        let sync = encode_frame(
            3,
            &encode_message(&Message::EffectRequest(EffectRequest {
                effect: Effect::FsSync {
                    path: "/data/file.bin".into(),
                },
            })),
        )
        .unwrap();
        let finish = encode_frame(4, &encode_message(&Message::Finish)).unwrap();
        let input = [hello, write, read, sync, finish].concat();

        let goodbye = serve_session(seed, 0, identity, &input).expect("session serves");
        assert!(goodbye.entries >= 3, "fs operations must be journaled");
    }
}

/// The canary's business logic modeled as a deterministic [`Workload`].
///
/// The effect stream the external canary sends over the shim (clock, rng,
/// filesystem write/read/sync, sleep, send, receive) is mirrored here as the
/// scheduler [`Instruction`] set that represents it. The random effect has no
/// scheduler instruction (RNG is drawn by the task future, outside the
/// instruction stream), so the model omits it; the planted
/// [`Instruction::Assert`] failure is what the campaign oracle detects, the
/// strict replay reproduces, and the minimizer shrinks.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanaryWorkload;

impl ledger_explorer::Workload for CanaryWorkload {
    fn programs(&self) -> Vec<Vec<ledger_sim::Instruction>> {
        use ledger_sim::Instruction;
        vec![vec![
            Instruction::ReadClock,
            Instruction::FsWrite {
                path: "/kv/k".into(),
                value: 42,
            },
            Instruction::FsRead {
                path: "/kv/k".into(),
            },
            Instruction::FsFsync,
            Instruction::Sleep(10),
            Instruction::Send {
                to: 0,
                payload: 0x6f6c6c6568,
            },
            Instruction::Receive,
            // Planted assertion: the canary's read-back equality check, made
            // to fail here so the campaign has a finding to reproduce and
            // minimize.
            Instruction::Assert(false),
            Instruction::Done,
        ]]
    }

    fn history(
        &self,
        _run: &ledger_sim::RunResult,
    ) -> Vec<ledger_explorer::oracle::HistoryOperation> {
        Vec::new()
    }
}
