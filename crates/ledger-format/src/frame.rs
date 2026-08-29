//! Outer frame prefix for every independently readable durable container.
//!
//! Version 2 layout:
//!
//! ```text
//! offset  size  field
//! 0       4     magic bytes, selected from the table below
//! 4       4     format_version, u32 little-endian, value 2
//! 8       4     header_len, u32 little-endian
//! 12      4     flags, u32 little-endian, value 0
//! ```
//!
//! The prefix is followed by exactly `header_len` bytes of canonical CBOR.
//! A decoder validates the outer version before decoding entries or
//! allocating payload content. Any value other than [`FORMAT_VERSION`]
//! returns [`FrameError::UnsupportedVersion`]. Unknown flag bits, incorrect
//! magic, a non-canonical header, an oversized header, or trailing data
//! outside the container grammar fails.

use alloc::vec::Vec;

use crate::limits::{FORMAT_VERSION, MAX_HEADER_BYTES};

/// Size of the raw frame prefix in bytes.
pub const FRAME_PREFIX_LEN: usize = 16;

/// WAL or journal stream magic.
pub const MAGIC_WAL: &[u8; 4] = b"LDGW";
/// Segment-store manifest magic.
pub const MAGIC_STORE_MANIFEST: &[u8; 4] = b"LDGM";
/// Sealed segment magic.
pub const MAGIC_SEGMENT: &[u8; 4] = b"LDGS";
/// Snapshot magic.
pub const MAGIC_SNAPSHOT: &[u8; 4] = b"LDGP";
/// Snapshot index magic.
pub const MAGIC_SNAPSHOT_INDEX: &[u8; 4] = b"LDGI";
/// Archive magic.
pub const MAGIC_ARCHIVE: &[u8; 4] = b"LDGA";
/// Archive index magic.
pub const MAGIC_ARCHIVE_INDEX: &[u8; 4] = b"LDGX";
/// Interchange envelope magic.
pub const MAGIC_ENVELOPE: &[u8; 4] = b"LDGE";
/// Solver-state artifact magic.
pub const MAGIC_SOLVER_STATE: &[u8; 4] = b"LDGV";

/// Outer frame validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// The container magic does not match the expected magic.
    WrongMagic,
    /// The outer format version is not [`FORMAT_VERSION`].
    UnsupportedVersion(u32),
    /// A reserved flag bit is set.
    ReservedFlags(u32),
    /// The declared header length exceeds [`MAX_HEADER_BYTES`].
    HeaderTooLarge(u32),
    /// The input ends before the declared header completes.
    TruncatedFrame,
}

/// A validated outer frame prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FramePrefix {
    /// The container magic that was validated.
    pub magic: [u8; 4],
    /// Outer format version; always [`FORMAT_VERSION`] after validation.
    pub format_version: u32,
    /// Length of the canonical CBOR header that follows the prefix.
    pub header_len: u32,
}

/// Encodes the 16-byte raw prefix for `magic` and `header_len`.
pub fn encode_prefix(out: &mut Vec<u8>, magic: &[u8; 4], header_len: u32) {
    out.extend_from_slice(magic);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&header_len.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
}

/// Validates the raw prefix at the start of `bytes` against `expected_magic`.
///
/// Returns the validated prefix and the offset where the canonical CBOR
/// header begins. The caller must still verify that the header itself is
/// exactly `header_len` canonical CBOR bytes and that no trailing data
/// violates the container grammar.
pub fn parse_prefix(bytes: &[u8], expected_magic: &[u8; 4]) -> Result<FramePrefix, FrameError> {
    if bytes.len() < FRAME_PREFIX_LEN {
        return Err(FrameError::TruncatedFrame);
    }
    let magic: [u8; 4] = bytes[0..4]
        .try_into()
        .map_err(|_| FrameError::TruncatedFrame)?;
    if &magic != expected_magic {
        return Err(FrameError::WrongMagic);
    }
    let format_version = u32::from_le_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| FrameError::TruncatedFrame)?,
    );
    if format_version != FORMAT_VERSION {
        return Err(FrameError::UnsupportedVersion(format_version));
    }
    let header_len = u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| FrameError::TruncatedFrame)?,
    );
    if header_len as usize > MAX_HEADER_BYTES {
        return Err(FrameError::HeaderTooLarge(header_len));
    }
    let flags = u32::from_le_bytes(
        bytes[12..16]
            .try_into()
            .map_err(|_| FrameError::TruncatedFrame)?,
    );
    if flags != 0 {
        return Err(FrameError::ReservedFlags(flags));
    }
    Ok(FramePrefix {
        magic,
        format_version,
        header_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_round_trips() {
        let mut bytes = Vec::new();
        encode_prefix(&mut bytes, MAGIC_SEGMENT, 24);
        assert_eq!(bytes.len(), FRAME_PREFIX_LEN);
        let parsed = parse_prefix(&bytes, MAGIC_SEGMENT).expect("prefix validates");
        assert_eq!(parsed.format_version, FORMAT_VERSION);
        assert_eq!(parsed.header_len, 24);
        assert_eq!(parsed.magic, *MAGIC_SEGMENT);
    }

    #[test]
    fn wrong_magic_is_rejected() {
        let mut bytes = Vec::new();
        encode_prefix(&mut bytes, MAGIC_SEGMENT, 24);
        assert_eq!(parse_prefix(&bytes, MAGIC_WAL), Err(FrameError::WrongMagic));
    }

    #[test]
    fn wrong_version_is_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC_SEGMENT);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&24u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            parse_prefix(&bytes, MAGIC_SEGMENT),
            Err(FrameError::UnsupportedVersion(1))
        );
    }

    #[test]
    fn reserved_flags_are_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC_SEGMENT);
        bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&24u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            parse_prefix(&bytes, MAGIC_SEGMENT),
            Err(FrameError::ReservedFlags(1))
        );
    }

    #[test]
    fn oversized_header_is_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC_SEGMENT);
        bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(MAX_HEADER_BYTES as u32 + 1).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            parse_prefix(&bytes, MAGIC_SEGMENT),
            Err(FrameError::HeaderTooLarge(_))
        ));
    }

    #[test]
    fn truncated_prefix_is_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC_SEGMENT);
        bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        assert_eq!(
            parse_prefix(&bytes, MAGIC_SEGMENT),
            Err(FrameError::TruncatedFrame)
        );
    }
}
