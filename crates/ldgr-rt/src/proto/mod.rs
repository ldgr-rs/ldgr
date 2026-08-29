//! Versioned, framed, sequence-checked wire protocol between the Apache-2.0
//! `ldgr-rt` facade and the AGPL engine server (`rt-server`).
//!
//! The transport is a byte stream (Unix socket in production, an in-process
//! loopback pair in tests). Frames are length-prefixed and carry a per-stream
//! sequence number. Every decode enforces size caps before allocation and
//! fails closed on any violation: wrong magic, wrong version, a frame larger
//! than [`MAX_FRAME_BYTES`], a path over [`MAX_PATH_BYTES`], a payload over
//! [`MAX_PAYLOAD_BYTES`], or a non-monotonic sequence number.
//!
//! Authentication is two-layered and lives outside this crate: the transport
//! checks Unix peer credentials, and the application handshake
//! ([`Hello`]/[`Welcome`]) binds the protocol version to the complete
//! `ExecutionIdentity` digest before any effect request is served.

pub mod codec;
pub mod msg;

pub use codec::{CodecError, DecodeError, decode_frame, encode_frame, parse_header};
pub use msg::{
    Effect, EffectError, EffectRequest, EffectResponse, EffectResult, Goodbye, Hello, Message,
    Reject, RejectReason, Welcome, decode_message, encode_message,
};

/// Protocol version carried in every frame header and the handshake.
///
/// Bump this (and the engine server's accepted set) on any breaking change to
/// the frame layout or message encoding.
pub const PROTOCOL_VERSION: u16 = 1;

/// Frame magic: the four leading bytes of every frame.
pub const MAGIC: [u8; 4] = *b"LDRP";

/// Maximum bytes in one frame body. Enforced before the body is read.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Maximum bytes in one path string (after the E2 canonical path contract).
pub const MAX_PATH_BYTES: usize = 4096;

/// Maximum bytes in one message or filesystem payload.
pub const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Maximum random words a single `Random` effect may request.
pub const MAX_RANDOM_COUNT: u32 = 4096;

/// Maximum actors addressed by one effect.
pub const MAX_ACTOR: u32 = 1 << 20;

/// Number of bytes in one `ExecutionIdentity` digest (a BLAKE3 `Hash`).
pub const IDENTITY_BYTES: usize = 32;

/// Number of bytes in a journal root (a BLAKE3 `Hash`).
pub const ROOT_BYTES: usize = 32;
