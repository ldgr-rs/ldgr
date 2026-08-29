//! Frame layout and stream codec.
//!
//! A frame is:
//!
//! ```text
//! magic[4] | version u16 LE | reserved u16 LE | body_len u32 LE | seq u64 LE | body
//! ```
//!
//! `reserved` must be zero; a decoder rejects any other value. `body_len` is
//! capped at [`crate::MAX_FRAME_BYTES`] before the body is touched. The
//! sequence number is validated by the caller (see [`msg::Message`] users):
//! the codec only carries it so every layer sees the same authoritative value.

use super::{MAGIC, MAX_FRAME_BYTES, PROTOCOL_VERSION};

/// Number of header bytes before the body.
pub const FRAME_HEADER_LEN: usize = 4 + 2 + 2 + 4 + 8;

/// Errors from framing or message decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Not enough bytes for a complete frame header.
    TruncatedHeader,
    /// The frame body extends past the provided buffer.
    TruncatedBody,
    /// The leading magic bytes do not match [`crate::MAGIC`].
    BadMagic,
    /// The frame carries a protocol version other than [`crate::PROTOCOL_VERSION`].
    UnsupportedVersion(u16),
    /// The reserved field is nonzero.
    ReservedNonZero,
    /// The declared body length exceeds [`crate::MAX_FRAME_BYTES`].
    BodyTooLarge(u32),
    /// The message body ended before a declared field was complete.
    UnexpectedEof,
    /// A message or effect tag is outside its documented set.
    BadTag(u8),
    /// A path field exceeds [`crate::MAX_PATH_BYTES`].
    PathTooLong,
    /// A payload field exceeds [`crate::MAX_PAYLOAD_BYTES`].
    PayloadTooLong,
    /// A path field is not valid UTF-8.
    InvalidUtf8,
    /// A count field exceeds its documented cap.
    BadCount(u32),
    /// An actor field exceeds [`crate::MAX_ACTOR`].
    BadActor(u32),
    /// A fixed-size hash field has the wrong length.
    BadHash,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TruncatedHeader => f.write_str("truncated frame header"),
            Self::TruncatedBody => f.write_str("truncated frame body"),
            Self::BadMagic => f.write_str("frame magic mismatch"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported protocol version {v}"),
            Self::ReservedNonZero => f.write_str("reserved frame field is nonzero"),
            Self::BodyTooLarge(n) => write!(f, "frame body too large: {n} bytes"),
            Self::UnexpectedEof => f.write_str("unexpected end of message"),
            Self::BadTag(t) => write!(f, "unknown message or effect tag {t}"),
            Self::PathTooLong => f.write_str("path exceeds the protocol cap"),
            Self::PayloadTooLong => f.write_str("payload exceeds the protocol cap"),
            Self::InvalidUtf8 => f.write_str("path is not valid UTF-8"),
            Self::BadCount(n) => write!(f, "count {n} exceeds the protocol cap"),
            Self::BadActor(a) => write!(f, "actor {a} exceeds the protocol cap"),
            Self::BadHash => f.write_str("hash field has the wrong length"),
        }
    }
}

impl core::error::Error for DecodeError {}

/// Errors from encoding a frame (only possible on an oversized body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// The body exceeds [`crate::MAX_FRAME_BYTES`].
    BodyTooLarge(usize),
}

impl core::fmt::Display for CodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BodyTooLarge(n) => write!(f, "frame body too large: {n} bytes"),
        }
    }
}

impl core::error::Error for CodecError {}

/// Encode one frame with the current [`crate::PROTOCOL_VERSION`].
pub fn encode_frame(seq: u64, body: &[u8]) -> Result<Vec<u8>, CodecError> {
    if body.len() > MAX_FRAME_BYTES {
        return Err(CodecError::BodyTooLarge(body.len()));
    }
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + body.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// Parse a frame header without requiring the body to be present.
///
/// Returns the sequence number and declared body length. Used by streaming
/// readers that must read the body in a second step.
pub fn parse_header(input: &[u8]) -> Result<(u64, usize), DecodeError> {
    if input.len() < FRAME_HEADER_LEN {
        return Err(DecodeError::TruncatedHeader);
    }
    if input[0..4] != MAGIC {
        return Err(DecodeError::BadMagic);
    }
    let version = u16::from_le_bytes([input[4], input[5]]);
    if version != PROTOCOL_VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }
    let reserved = u16::from_le_bytes([input[6], input[7]]);
    if reserved != 0 {
        return Err(DecodeError::ReservedNonZero);
    }
    let body_len = u32::from_le_bytes([input[8], input[9], input[10], input[11]]) as usize;
    if body_len > MAX_FRAME_BYTES {
        return Err(DecodeError::BodyTooLarge(body_len as u32));
    }
    let seq = u64::from_le_bytes([
        input[12], input[13], input[14], input[15], input[16], input[17], input[18], input[19],
    ]);
    Ok((seq, body_len))
}

/// Decode one frame from a complete buffer.
///
/// Returns `Err(TruncatedHeader)` if `input` cannot hold a header and
/// `Err(TruncatedBody)` if the declared body extends past `input`.
pub fn decode_frame(input: &[u8]) -> Result<(u64, &[u8]), DecodeError> {
    if input.len() < FRAME_HEADER_LEN {
        return Err(DecodeError::TruncatedHeader);
    }
    if input[0..4] != MAGIC {
        return Err(DecodeError::BadMagic);
    }
    let version = u16::from_le_bytes([input[4], input[5]]);
    if version != PROTOCOL_VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }
    let reserved = u16::from_le_bytes([input[6], input[7]]);
    if reserved != 0 {
        return Err(DecodeError::ReservedNonZero);
    }
    let body_len = u32::from_le_bytes([input[8], input[9], input[10], input[11]]) as usize;
    if body_len > MAX_FRAME_BYTES {
        return Err(DecodeError::BodyTooLarge(body_len as u32));
    }
    let seq = u64::from_le_bytes([
        input[12], input[13], input[14], input[15], input[16], input[17], input[18], input[19],
    ]);
    let end = FRAME_HEADER_LEN
        .checked_add(body_len)
        .ok_or(DecodeError::TruncatedBody)?;
    if end > input.len() {
        return Err(DecodeError::TruncatedBody);
    }
    Ok((seq, &input[FRAME_HEADER_LEN..end]))
}
