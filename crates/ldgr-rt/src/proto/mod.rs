//! Versioned, framed, sequence-checked wire protocol (`ldgr-rt` to `rt-server`).
//! Byte stream; frames carry a per-stream sequence number. Every decode
//! enforces size caps before allocation and fails closed. Auth lives outside
//! this crate: Unix peer credentials plus the [`Hello`]/[`Welcome`]
//! identity handshake.

pub mod codec;
pub mod msg;

pub use codec::{CodecError, DecodeError, decode_frame, encode_frame, parse_header};
pub use msg::{
    Effect, EffectError, EffectRequest, EffectResponse, EffectResult, FRAMED_HASH_LEN,
    FRAMED_HASH_PREFIX, Goodbye, Hello, Message, Reject, RejectReason, Welcome, decode_message,
    encode_message,
};

/// Protocol version carried in every frame header and the handshake.
///
/// Version 2 frames `EntryHash` values on the wire as 34-byte framed hashes
pub const PROTOCOL_VERSION: u16 = 2;

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

/// Number of bytes in one `ExecutionIdentity` digest on the wire (34 framed).
pub const IDENTITY_BYTES: usize = 34;

/// Number of bytes in a journal root on the wire (34 framed).
pub const ROOT_BYTES: usize = 34;
