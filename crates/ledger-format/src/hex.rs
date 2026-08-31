//! Hex encoding for 32-byte content hashes.
//!
//! One canonical encoder/decoder so every crate prints and parses hashes
//! identically: 64 lowercase hex chars on the wire, case-insensitive on
//! decode.

use alloc::string::String;
use core::fmt;

use crate::Hash;

/// Errors from [`hash_from_hex`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    /// Input was not exactly 64 chars; carries the actual length.
    InvalidLength(usize),
    /// A non-hex character at the given char index.
    InvalidChar { index: usize, char: char },
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength(len) => write!(f, "hex hash must be 64 chars, got {len}"),
            Self::InvalidChar { index, char } => {
                write!(f, "invalid hex char {char:?} at index {index}")
            }
        }
    }
}

impl core::error::Error for HexError {}

/// Encode a hash as 64 lowercase hex chars.
pub fn hash_to_hex(hash: &Hash) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(hash.len() * 2);
    for byte in hash {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decode 64 hex chars (either case) into a hash.
///
/// # Errors
/// Returns [`HexError`] when the input is not exactly 64 hex characters.
pub fn hash_from_hex(s: &str) -> Result<Hash, HexError> {
    if s.len() != 64 {
        return Err(HexError::InvalidLength(s.len()));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_val(chunk[0]).ok_or(HexError::InvalidChar {
            index: i * 2,
            char: chunk[0] as char,
        })?;
        let low = hex_val(chunk[1]).ok_or(HexError::InvalidChar {
            index: i * 2 + 1,
            char: chunk[1] as char,
        })?;
        out[i] = (high << 4) | low;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let head = [0x00, 0x01, 0xfe, 0xff, 0xab, 0xcd, 0xef, 0x10];
        let mut h = [0u8; 32];
        h[..head.len()].copy_from_slice(&head);
        let hex = hash_to_hex(&h);
        assert_eq!(hex.len(), 64);
        assert_eq!(
            hex,
            "0001feffabcdef10000000000000000000000000000000000000000000000000"
        );
        assert_eq!(hash_from_hex(&hex).unwrap(), h);
    }

    #[test]
    fn decode_accepts_uppercase() {
        let upper = "00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
        let decoded = hash_from_hex(upper).unwrap();
        assert_eq!(decoded[0], 0);
        assert!(decoded[1..].iter().all(|&b| b == 0xff));
    }

    #[test]
    fn rejects_short() {
        assert_eq!(
            hash_from_hex(&"0".repeat(63)),
            Err(HexError::InvalidLength(63))
        );
    }

    #[test]
    fn rejects_long() {
        assert_eq!(
            hash_from_hex(&"0".repeat(65)),
            Err(HexError::InvalidLength(65))
        );
    }

    #[test]
    fn rejects_odd_length() {
        assert_eq!(
            hash_from_hex(&"0".repeat(31)),
            Err(HexError::InvalidLength(31))
        );
    }

    #[test]
    fn rejects_invalid_chars() {
        let mut s = "0".repeat(64);
        s.replace_range(5..6, "g");
        assert_eq!(
            hash_from_hex(&s),
            Err(HexError::InvalidChar {
                index: 5,
                char: 'g'
            })
        );
        let mut s = "0".repeat(64);
        s.replace_range(8..9, " ");
        assert_eq!(
            hash_from_hex(&s),
            Err(HexError::InvalidChar {
                index: 8,
                char: ' '
            })
        );
    }
}
