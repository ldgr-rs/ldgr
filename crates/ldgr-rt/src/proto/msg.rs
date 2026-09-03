//! Message bodies carried inside frames.
//!
//! The client (`ldgr-rt` shim) sends [`Hello`] first (frame sequence 0),
//! then one [`EffectRequest`] per effect (sequence 1, 2, ...), then a
//! [`Goodbye`] carrying the run result. The server replies [`Welcome`] or
//! [`Reject`] to the hello, then one [`EffectResponse`] per request with the
//! same sequence number.
//!
//! All lengths are checked before any allocation. Paths are UTF-8 and capped
//! at [`crate::MAX_PATH_BYTES`]; payloads at [`crate::MAX_PAYLOAD_BYTES`].

use super::codec::DecodeError;
use super::{MAX_ACTOR, MAX_PATH_BYTES, MAX_PAYLOAD_BYTES, MAX_RANDOM_COUNT};
use ledger_format::{ActorId, EntryHash};

/// A complete application message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Client opens a session, binding the protocol version and the run
    /// identity digest.
    Hello(Hello),
    /// Server accepts the session and assigns the actor id.
    Welcome(Welcome),
    /// Server refuses the session; the connection is closed after this.
    Reject(Reject),
    /// Client requests one deterministic effect.
    EffectRequest(EffectRequest),
    /// Server returns the effect result (same sequence as the request).
    EffectResponse(EffectResponse),
    /// Client signals the end of the effect stream.
    Finish,
    /// Server reports the finalized journal root and entry count.
    Goodbye(Goodbye),
}

/// Client hello: the run identity binds the effect stream to one
/// `ExecutionIdentity`, verified by the server before any effect is served.
///
/// The actor id travels in the handshake so the server routes every effect
/// for this connection as that actor; it must not default to zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    /// Complete `ExecutionIdentity` digest (BLAKE3, 32 bytes).
    pub identity: EntryHash,
    /// Logical actor this connection sends and receives as.
    pub actor: ActorId,
}

/// Server acceptance of a hello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Welcome {
    /// Stable actor id assigned to this connection for the run.
    pub actor: ActorId,
}

/// Server refusal of a hello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reject {
    pub reason: RejectReason,
    /// Bounded human-readable detail; at most [`crate::MAX_PATH_BYTES`] bytes.
    pub detail: String,
}

/// Why a session was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RejectReason {
    /// The identity digest was not the one the server expects.
    Identity = 1,
    /// The server cannot take another actor (outstanding-request bound).
    Overload = 2,
    /// A sequence or protocol rule was violated.
    Protocol = 3,
}

/// One deterministic effect request from the SUT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectRequest {
    pub effect: Effect,
}

/// One deterministic effect result from the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectResponse {
    pub result: EffectResult,
}

/// Final session message carrying the journal root (server to client).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Goodbye {
    /// Journal root hash (BLAKE3, 32 bytes).
    pub root: EntryHash,
    /// Number of entries the run journaled.
    pub entries: u64,
}

/// The set of effects a SUT may request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Read the virtual clock.
    Clock,
    /// Sleep for `ticks` virtual microseconds.
    Sleep { ticks: u64 },
    /// Draw `count` 64-bit words from a labeled RNG stream.
    Random { stream: u32, count: u32 },
    /// Send `payload` bytes to actor `to`.
    Send { to: ActorId, payload: Vec<u8> },
    /// Receive one message, if any is deliverable now.
    Recv,
    /// Write `bytes` at `offset` in the file at `path`.
    FsWrite {
        path: String,
        offset: u64,
        bytes: Vec<u8>,
    },
    /// Read up to `len` bytes at `offset` from `path`; returns the observed bytes.
    FsRead { path: String, offset: u64, len: u64 },
    /// Persist barrier on `path`.
    FsSync { path: String },
}

/// The engine's deterministic result for one effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectResult {
    /// Clock read result.
    Clock { ticks: u64 },
    /// Generic acknowledgement (sleep, send, write, sync).
    Ok,
    /// Random words (little-endian 64-bit words, `count * 8` bytes).
    Random { words: Vec<u8> },
    /// A received message, or none deliverable.
    Recv { payload: Option<Vec<u8>> },
    /// Observed bytes for a read.
    FsRead { observed: Vec<u8> },
}

/// Error mapping helper used by servers when an effect is structurally valid
/// but rejected by the engine (for example a path outside the allowed set).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectError(pub RejectReason);

impl core::fmt::Display for EffectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            RejectReason::Identity => f.write_str("identity rejected"),
            RejectReason::Overload => f.write_str("server overloaded"),
            RejectReason::Protocol => f.write_str("protocol violation"),
        }
    }
}

// Message tags.
const T_HELLO: u8 = 1;
const T_WELCOME: u8 = 2;
const T_REJECT: u8 = 3;
const T_EFFECT_REQUEST: u8 = 4;
const T_EFFECT_RESPONSE: u8 = 5;
const T_FINISH: u8 = 6;
const T_GOODBYE: u8 = 7;

// Effect tags.
const E_CLOCK: u8 = 1;
const E_SLEEP: u8 = 2;
const E_RANDOM: u8 = 3;
const E_SEND: u8 = 4;
const E_RECV: u8 = 5;
const E_FS_WRITE: u8 = 6;
const E_FS_READ: u8 = 7;
const E_FS_SYNC: u8 = 8;

// Result tags.
const R_CLOCK: u8 = 1;
const R_OK: u8 = 2;
const R_RANDOM: u8 = 3;
const R_RECV: u8 = 4;
const R_FS_READ: u8 = 5;

/// Encode a message body.
pub fn encode_message(message: &Message) -> Vec<u8> {
    let mut out = Vec::new();
    match message {
        Message::Hello(hello) => {
            out.push(T_HELLO);
            out.extend_from_slice(&hello.identity.0);
            out.extend_from_slice(&hello.actor.0.to_le_bytes());
        }
        Message::Welcome(welcome) => {
            out.push(T_WELCOME);
            out.extend_from_slice(&welcome.actor.0.to_le_bytes());
        }
        Message::Reject(reject) => {
            out.push(T_REJECT);
            out.push(reject.reason as u8);
            out.extend_from_slice(&(reject.detail.len() as u32).to_le_bytes());
            out.extend_from_slice(reject.detail.as_bytes());
        }
        Message::EffectRequest(request) => {
            out.push(T_EFFECT_REQUEST);
            encode_effect(&request.effect, &mut out);
        }
        Message::EffectResponse(response) => {
            out.push(T_EFFECT_RESPONSE);
            encode_result(&response.result, &mut out);
        }
        Message::Finish => out.push(T_FINISH),
        Message::Goodbye(goodbye) => {
            out.push(T_GOODBYE);
            out.extend_from_slice(&goodbye.root.0);
            out.extend_from_slice(&goodbye.entries.to_le_bytes());
        }
    }
    out
}

fn encode_effect(effect: &Effect, out: &mut Vec<u8>) {
    match effect {
        Effect::Clock => out.push(E_CLOCK),
        Effect::Sleep { ticks } => {
            out.push(E_SLEEP);
            out.extend_from_slice(&ticks.to_le_bytes());
        }
        Effect::Random { stream, count } => {
            out.push(E_RANDOM);
            out.extend_from_slice(&stream.to_le_bytes());
            out.extend_from_slice(&count.to_le_bytes());
        }
        Effect::Send { to, payload } => {
            out.push(E_SEND);
            out.extend_from_slice(&to.0.to_le_bytes());
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(payload);
        }
        Effect::Recv => out.push(E_RECV),
        Effect::FsWrite {
            path,
            offset,
            bytes,
        } => {
            out.push(E_FS_WRITE);
            encode_path(path, out);
            out.extend_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(bytes);
        }
        Effect::FsRead { path, offset, len } => {
            out.push(E_FS_READ);
            encode_path(path, out);
            out.extend_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(&len.to_le_bytes());
        }
        Effect::FsSync { path } => {
            out.push(E_FS_SYNC);
            encode_path(path, out);
        }
    }
}

fn encode_result(result: &EffectResult, out: &mut Vec<u8>) {
    match result {
        EffectResult::Clock { ticks } => {
            out.push(R_CLOCK);
            out.extend_from_slice(&ticks.to_le_bytes());
        }
        EffectResult::Ok => out.push(R_OK),
        EffectResult::Random { words } => {
            out.push(R_RANDOM);
            out.extend_from_slice(&(words.len() as u32).to_le_bytes());
            out.extend_from_slice(words);
        }
        EffectResult::Recv { payload } => {
            out.push(R_RECV);
            match payload {
                Some(bytes) => {
                    out.push(1);
                    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                    out.extend_from_slice(bytes);
                }
                None => out.push(0),
            }
        }
        EffectResult::FsRead { observed } => {
            out.push(R_FS_READ);
            out.extend_from_slice(&(observed.len() as u32).to_le_bytes());
            out.extend_from_slice(observed);
        }
    }
}

fn encode_path(path: &str, out: &mut Vec<u8>) {
    out.extend_from_slice(&(path.len() as u32).to_le_bytes());
    out.extend_from_slice(path.as_bytes());
}

/// Decode a message body.
pub fn decode_message(body: &[u8]) -> Result<Message, DecodeError> {
    let mut r = Reader::new(body);
    let tag = r.u8()?;
    match tag {
        T_HELLO => {
            let identity = r.hash32()?;
            let actor_raw = r.u32()?;
            if actor_raw > MAX_ACTOR {
                return Err(DecodeError::BadActor(actor_raw));
            }
            let actor = ActorId(actor_raw);
            r.finish()?;
            Ok(Message::Hello(Hello { identity, actor }))
        }
        T_WELCOME => {
            let actor = ActorId(r.u32()?);
            r.finish()?;
            Ok(Message::Welcome(Welcome { actor }))
        }
        T_REJECT => {
            let reason = RejectReason::from_byte(r.u8()?)?;
            let detail = r.bounded_string()?;
            r.finish()?;
            Ok(Message::Reject(Reject { reason, detail }))
        }
        T_EFFECT_REQUEST => {
            let effect = decode_effect(&mut r)?;
            r.finish()?;
            Ok(Message::EffectRequest(EffectRequest { effect }))
        }
        T_EFFECT_RESPONSE => {
            let result = decode_result(&mut r)?;
            r.finish()?;
            Ok(Message::EffectResponse(EffectResponse { result }))
        }
        T_FINISH => {
            r.finish()?;
            Ok(Message::Finish)
        }
        T_GOODBYE => {
            let root = r.hash32()?;
            let entries = r.u64()?;
            r.finish()?;
            Ok(Message::Goodbye(Goodbye { root, entries }))
        }
        other => Err(DecodeError::BadTag(other)),
    }
}

fn decode_effect(r: &mut Reader<'_>) -> Result<Effect, DecodeError> {
    let tag = r.u8()?;
    match tag {
        E_CLOCK => Ok(Effect::Clock),
        E_SLEEP => {
            let ticks = r.u64()?;
            Ok(Effect::Sleep { ticks })
        }
        E_RANDOM => {
            let stream = r.u32()?;
            let count = r.u32()?;
            if count > MAX_RANDOM_COUNT {
                return Err(DecodeError::BadCount(count));
            }
            Ok(Effect::Random { stream, count })
        }
        E_SEND => {
            let to_raw = r.u32()?;
            if to_raw > MAX_ACTOR {
                return Err(DecodeError::BadActor(to_raw));
            }
            let to = ActorId(to_raw);
            let payload = r.bounded_bytes()?;
            Ok(Effect::Send { to, payload })
        }
        E_RECV => Ok(Effect::Recv),
        E_FS_WRITE => {
            let path = r.bounded_string()?;
            let offset = r.u64()?;
            let bytes = r.bounded_bytes()?;
            Ok(Effect::FsWrite {
                path,
                offset,
                bytes,
            })
        }
        E_FS_READ => {
            let path = r.bounded_string()?;
            let offset = r.u64()?;
            let len = r.u64()?;
            Ok(Effect::FsRead { path, offset, len })
        }
        E_FS_SYNC => {
            let path = r.bounded_string()?;
            Ok(Effect::FsSync { path })
        }
        other => Err(DecodeError::BadTag(other)),
    }
}

fn decode_result(r: &mut Reader<'_>) -> Result<EffectResult, DecodeError> {
    let tag = r.u8()?;
    match tag {
        R_CLOCK => {
            let ticks = r.u64()?;
            Ok(EffectResult::Clock { ticks })
        }
        R_OK => Ok(EffectResult::Ok),
        R_RANDOM => {
            let words = r.bounded_bytes()?;
            Ok(EffectResult::Random { words })
        }
        R_RECV => {
            let present = r.u8()?;
            let payload = match present {
                0 => None,
                1 => Some(r.bounded_bytes()?),
                _ => return Err(DecodeError::BadTag(present)),
            };
            Ok(EffectResult::Recv { payload })
        }
        R_FS_READ => {
            let observed = r.bounded_bytes()?;
            Ok(EffectResult::FsRead { observed })
        }
        other => Err(DecodeError::BadTag(other)),
    }
}

impl RejectReason {
    fn from_byte(byte: u8) -> Result<Self, DecodeError> {
        match byte {
            1 => Ok(Self::Identity),
            2 => Ok(Self::Overload),
            3 => Ok(Self::Protocol),
            other => Err(DecodeError::BadTag(other)),
        }
    }
}

/// Bounds-checked cursor over a message body.
struct Reader<'a> {
    body: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn new(body: &'a [u8]) -> Self {
        Self { body, cursor: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .cursor
            .checked_add(n)
            .ok_or(DecodeError::UnexpectedEof)?;
        if end > self.body.len() {
            return Err(DecodeError::UnexpectedEof);
        }
        let slice = &self.body[self.cursor..end];
        self.cursor = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        let bytes = self.take(8)?;
        let mut out = [0u8; 8];
        out.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(out))
    }

    fn hash32(&mut self) -> Result<EntryHash, DecodeError> {
        let bytes = self.take(32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        Ok(EntryHash(out))
    }

    fn bounded_bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let len = self.u32()? as usize;
        if len > MAX_PAYLOAD_BYTES {
            return Err(DecodeError::PayloadTooLong);
        }
        Ok(self.take(len)?.to_vec())
    }

    fn bounded_string(&mut self) -> Result<String, DecodeError> {
        let len = self.u32()? as usize;
        if len > MAX_PATH_BYTES {
            return Err(DecodeError::PathTooLong);
        }
        let bytes = self.take(len)?;
        let text = core::str::from_utf8(bytes).map_err(|_| DecodeError::InvalidUtf8)?;
        Ok(String::from(text))
    }

    fn finish(&self) -> Result<(), DecodeError> {
        if self.cursor == self.body.len() {
            Ok(())
        } else {
            Err(DecodeError::UnexpectedEof)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{decode_frame, encode_frame};
    use super::*;

    fn roundtrip(msg: &Message) {
        let body = encode_message(msg);
        let frame = encode_frame(7, &body).expect("frame fits");
        let (seq, got_body) = decode_frame(&frame).expect("frame decodes");
        assert_eq!(seq, 7);
        let decoded = decode_message(got_body).expect("message decodes");
        assert_eq!(decoded, *msg);
    }

    #[test]
    fn all_message_kinds_roundtrip() {
        roundtrip(&Message::Hello(Hello {
            identity: EntryHash([0xAA; 32]),
            actor: ActorId(3),
        }));
        roundtrip(&Message::Welcome(Welcome { actor: ActorId(42) }));
        roundtrip(&Message::Reject(Reject {
            reason: RejectReason::Identity,
            detail: "identity mismatch".into(),
        }));
        roundtrip(&Message::EffectRequest(EffectRequest {
            effect: Effect::Clock,
        }));
        roundtrip(&Message::EffectRequest(EffectRequest {
            effect: Effect::Sleep { ticks: 1_000_000 },
        }));
        roundtrip(&Message::EffectRequest(EffectRequest {
            effect: Effect::Random {
                stream: 3,
                count: 16,
            },
        }));
        roundtrip(&Message::EffectRequest(EffectRequest {
            effect: Effect::Send {
                to: ActorId(1),
                payload: vec![0xDE; 64],
            },
        }));
        roundtrip(&Message::EffectRequest(EffectRequest {
            effect: Effect::FsWrite {
                path: "/kv/k".into(),
                offset: 0,
                bytes: vec![0x11, 0x22],
            },
        }));
        roundtrip(&Message::EffectRequest(EffectRequest {
            effect: Effect::FsRead {
                path: "/kv/k".into(),
                offset: 0,
                len: 4096,
            },
        }));
        roundtrip(&Message::EffectResponse(EffectResponse {
            result: EffectResult::Clock { ticks: 99 },
        }));
        roundtrip(&Message::EffectResponse(EffectResponse {
            result: EffectResult::Recv {
                payload: Some(vec![0xAB; 4]),
            },
        }));
        roundtrip(&Message::EffectResponse(EffectResponse {
            result: EffectResult::FsRead {
                observed: vec![0x33; 8],
            },
        }));
        roundtrip(&Message::Goodbye(Goodbye {
            root: EntryHash([0xBB; 32]),
            entries: 12,
        }));
        roundtrip(&Message::Finish);
    }

    #[test]
    fn oversized_path_fails_closed() {
        let msg = Message::EffectRequest(EffectRequest {
            effect: Effect::FsWrite {
                path: "x".repeat(MAX_PATH_BYTES + 1),
                offset: 0,
                bytes: vec![1],
            },
        });
        let body = encode_message(&msg);
        // Encode is unguarded for path (the cap is a decode-side trust bound
        // for the server); the decoder must reject it.
        assert_eq!(
            decode_message(&body),
            Err(DecodeError::PathTooLong),
            "a path over the cap must fail closed"
        );
    }

    #[test]
    fn bad_tags_fail_closed() {
        assert_eq!(decode_message(&[0xFF]), Err(DecodeError::BadTag(0xFF)));
        // A truncated send (no length bytes).
        let mut body = vec![T_EFFECT_REQUEST, E_SEND];
        body.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            decode_message(&body),
            Err(DecodeError::UnexpectedEof),
            "a truncated payload must fail closed"
        );
    }

    #[test]
    fn hello_actor_is_bounded() {
        let msg = Message::Hello(Hello {
            identity: EntryHash([0xAA; 32]),
            actor: ActorId(crate::proto::MAX_ACTOR + 1),
        });
        let body = encode_message(&msg);
        assert_eq!(
            decode_message(&body),
            Err(DecodeError::BadActor(crate::proto::MAX_ACTOR + 1)),
            "an actor over the cap must fail closed"
        );
        // A truncated hello (identity without actor) fails closed.
        let mut short = vec![T_HELLO];
        short.extend_from_slice(&[0xAA; 32]);
        assert_eq!(
            decode_message(&short),
            Err(DecodeError::UnexpectedEof),
            "old hellos without actor must not decode"
        );
    }
}
