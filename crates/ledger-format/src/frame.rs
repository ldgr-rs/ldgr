//! Outer frame prefix for every independently readable durable container.
//!
//! Version 3 layout:
//!
//! ```text
//! offset  size  field
//! 0       4     magic bytes, selected from the table below
//! 4       4     format_version, u32 little-endian, value 3
//! 8       4     header_len, u32 little-endian
//! 12      4     flags, u32 little-endian, value 0
//! ```
//!
//! Followed by exactly `header_len` canonical CBOR bytes. Anything other
//! than [`FORMAT_VERSION`], unknown flag bits, wrong magic, a non-canonical
//! or oversized header, or trailing data outside the grammar fails.

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

/// Journal archive-file magic: registry entry for `archive.ldgr`.
///
/// Big-endian file magic; do not confuse with the little-endian
/// frame-prefix container [`MAGIC_ARCHIVE`].
pub const MAGIC_JOURNAL_ARCHIVE: &[u8; 4] = b"LDAR";

/// Journal archive-file format version.
pub const JOURNAL_ARCHIVE_VERSION: u32 = 1;

/// Snapshot-store file magic: registry entry for `snapshots.ldgr`.
///
/// File magic; do not confuse with the frame-prefix [`MAGIC_SNAPSHOT`].
pub const MAGIC_SNAPSHOT_STORE: &[u8; 4] = b"LDSN";

/// Snapshot-store file format version.
pub const SNAPSHOT_STORE_VERSION: u32 = 1;

/// Outer frame failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    WrongMagic,
    /// Outer version is not [`FORMAT_VERSION`].
    UnsupportedVersion(u32),
    ReservedFlags(u32),
    /// Declared header length exceeds [`MAX_HEADER_BYTES`].
    HeaderTooLarge(u32),
    TruncatedFrame,
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongMagic => f.write_str("container magic does not match expected magic"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported outer format version: {v}"),
            Self::ReservedFlags(flags) => write!(f, "reserved flag bit set: {flags:#x}"),
            Self::HeaderTooLarge(len) => write!(f, "declared header length {len} exceeds limit"),
            Self::TruncatedFrame => f.write_str("truncated frame input"),
        }
    }
}

impl core::error::Error for FrameError {}

/// A validated outer frame prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FramePrefix {
    pub magic: [u8; 4],
    /// Always [`FORMAT_VERSION`] after validation.
    pub format_version: u32,
    /// Canonical CBOR header length following the prefix.
    pub header_len: u32,
}

/// Encodes the 16-byte raw prefix for `magic` and `header_len`.
pub fn encode_prefix(out: &mut Vec<u8>, magic: &[u8; 4], header_len: u32) {
    out.extend_from_slice(magic);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&header_len.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
}

/// Validates the raw prefix against `expected_magic`.
///
/// Returns the prefix and the header offset. The caller must still verify
/// the header is exactly `header_len` canonical CBOR bytes.
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
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&24u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            parse_prefix(&bytes, MAGIC_SEGMENT),
            Err(FrameError::UnsupportedVersion(2))
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
