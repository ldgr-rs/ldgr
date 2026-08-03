//! Minimal canonical CBOR primitives used by the journal hash function.

use std::fmt;

/// Encoding error for the closed-world canonical encoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// A text value contained invalid UTF-8 after decoding.
    InvalidText,
    /// The value cannot be represented by the selected CBOR type.
    InvalidValue,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidText => f.write_str("invalid UTF-8 text"),
            Self::InvalidValue => f.write_str("invalid CBOR value"),
        }
    }
}

impl std::error::Error for EncodeError {}

/// Append a canonical CBOR unsigned integer.
pub fn unsigned(out: &mut Vec<u8>, value: u64) {
    major(out, 0, value);
}

/// Append a canonical CBOR signed integer.
pub fn signed(out: &mut Vec<u8>, value: i64) {
    if value >= 0 {
        unsigned(out, value as u64);
    } else {
        major(out, 1, value.unsigned_abs() - 1);
    }
}

/// Append a canonical CBOR byte string.
pub fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    major(out, 2, value.len() as u64);
    out.extend_from_slice(value);
}

/// Append a canonical CBOR UTF-8 text string.
pub fn text(out: &mut Vec<u8>, value: &str) {
    major(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

/// Append a canonical CBOR array header.
pub fn array(out: &mut Vec<u8>, length: usize) {
    major(out, 4, length as u64);
}

/// Append a canonical CBOR map header.
pub fn map(out: &mut Vec<u8>, length: usize) {
    major(out, 5, length as u64);
}

fn major(out: &mut Vec<u8>, kind: u8, value: u64) {
    let head = kind << 5;
    if value <= 23 {
        out.push(head | value as u8);
    } else if value <= u8::MAX as u64 {
        out.push(head | 24);
        out.push(value as u8);
    } else if value <= u16::MAX as u64 {
        out.push(head | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u32::MAX as u64 {
        out.push(head | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(head | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_shortest_integer_forms() {
        let mut bytes = Vec::new();
        unsigned(&mut bytes, 23);
        unsigned(&mut bytes, 24);
        assert_eq!(bytes, [0x17, 0x18, 0x18]);
    }

    #[test]
    fn encodes_definite_length_values() {
        let mut bytes = Vec::new();
        text(&mut bytes, "ok");
        assert_eq!(bytes, [0x62, b'o', b'k']);
    }
}
