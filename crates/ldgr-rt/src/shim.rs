//! Framed effect-protocol client for the SUT side of the D1 boundary.
//!
//! This is the explicit shim an external SUT (for example the canary binary)
//! links against. It connects to the AGPL `rt-server`, performs the identity
//! handshake, then exchanges one deterministic effect request at a time.
//!
//! Computation between effects (the SUT's business logic) is outside the
//! deterministic boundary; only the effects cross this shim, so the engine
//! journals a pure function of the effect stream and the seed.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::proto::{
    Effect, EffectRequest, EffectResponse, EffectResult, Goodbye, Hello, Message, Reject,
    RejectReason, Welcome, decode_frame, decode_message, encode_frame, encode_message,
    parse_header,
};
use thiserror::Error;

/// Errors from the SUT-side shim.
#[derive(Debug, Error)]
pub enum ShimError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(#[from] crate::proto::DecodeError),
    /// The server rejected the session.
    #[error("session rejected: {reason:?}: {detail}")]
    Rejected {
        reason: RejectReason,
        detail: String,
    },
    /// The server replied with the wrong message kind for the exchange.
    #[error("unexpected server reply")]
    UnexpectedReply,
    /// The server's effect response sequence does not match the request.
    #[error("sequence mismatch in effect response")]
    SequenceMismatch,
}

/// An open effect session to the engine.
pub struct EngineSession {
    stream: UnixStream,
    next_seq: u64,
    actor: u32,
}

impl EngineSession {
    /// Connect to the engine at `socket` and complete the identity handshake.
    ///
    /// `identity` must equal the digest the server was launched with; any
    /// mismatch fails closed before the first effect.
    pub fn connect(socket: &Path, identity: [u8; 32]) -> Result<Self, ShimError> {
        let mut stream = UnixStream::connect(socket)?;
        write_message(&mut stream, 0, &Message::Hello(Hello { identity }))?;
        let (seq, reply) = read_message(&mut stream)?;
        if seq != 0 {
            return Err(ShimError::UnexpectedReply);
        }
        match reply {
            Message::Welcome(Welcome { actor }) => Ok(Self {
                stream,
                next_seq: 1,
                actor,
            }),
            Message::Reject(Reject { reason, detail }) => {
                Err(ShimError::Rejected { reason, detail })
            }
            _ => Err(ShimError::UnexpectedReply),
        }
    }

    /// The stable actor id assigned by the server.
    pub fn actor(&self) -> u32 {
        self.actor
    }

    /// Send one effect request and wait for its deterministic result.
    pub fn effect(&mut self, effect: Effect) -> Result<EffectResult, ShimError> {
        let seq = self.next_seq;
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or(ShimError::SequenceMismatch)?;
        write_message(
            &mut self.stream,
            seq,
            &Message::EffectRequest(EffectRequest { effect }),
        )?;
        let (reply_seq, reply) = read_message(&mut self.stream)?;
        if reply_seq != seq {
            return Err(ShimError::SequenceMismatch);
        }
        match reply {
            Message::EffectResponse(EffectResponse { result }) => Ok(result),
            _ => Err(ShimError::UnexpectedReply),
        }
    }

    /// End the effect stream and receive the finalized journal root.
    pub fn finish(mut self) -> Result<Goodbye, ShimError> {
        let seq = self.next_seq;
        write_message(&mut self.stream, seq, &Message::Finish)?;
        let (reply_seq, reply) = read_message(&mut self.stream)?;
        if reply_seq != seq {
            return Err(ShimError::SequenceMismatch);
        }
        match reply {
            Message::Goodbye(goodbye) => Ok(goodbye),
            _ => Err(ShimError::UnexpectedReply),
        }
    }
}

/// Read one frame and decode its message body.
fn read_message(stream: &mut UnixStream) -> Result<(u64, Message), ShimError> {
    let mut header = [0u8; crate::proto::codec::FRAME_HEADER_LEN];
    stream.read_exact(&mut header)?;
    let (_, body_len) = parse_header(&header)?;
    let mut full = Vec::with_capacity(crate::proto::codec::FRAME_HEADER_LEN + body_len);
    full.extend_from_slice(&header);
    if body_len > 0 {
        full.resize(crate::proto::codec::FRAME_HEADER_LEN + body_len, 0);
        stream.read_exact(&mut full[crate::proto::codec::FRAME_HEADER_LEN..])?;
    }
    let (seq, body) = decode_frame(&full)?;
    let message = decode_message(body)?;
    Ok((seq, message))
}

/// Encode and write one frame.
fn write_message(stream: &mut UnixStream, seq: u64, message: &Message) -> Result<(), ShimError> {
    let body = encode_message(message);
    let frame = encode_frame(seq, &body)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}
