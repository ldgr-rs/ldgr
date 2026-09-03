//! Canonical RFC 8949 Core Deterministic CBOR encoder, validating decoder, and
//! zero-trust tolerant reader.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;

const MAX_DEPTH: usize = 128;

/// Allowlist of CBOR semantic tags accepted by the canonical decoder.
///
/// Empty by policy: the journal self-emits no tags. Extend only when the
/// spec adds a tag with defined semantics.
pub const TAG_ALLOWLIST: &[u64] = &[];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborError {
    UnexpectedEof,
    IndefiniteLengthForbidden,
    /// Integer was not encoded in shortest possible form.
    NonCanonicalIntegerEncoding,
    /// Float is `-0.0`, `NaN`, or not the minimal width that round-trips.
    NonCanonicalFloat,
    /// Map keys are not sorted by canonical byte representation.
    UnsortedMapKeys,
    DuplicateMapKey,
    InvalidUtf8,
    /// CBOR semantic tag is not on the documented allowlist.
    UnknownTag(u64),
    /// Declared array, map, byte, or text length exceeds remaining input.
    LengthOverflow,
    /// One entry exceeds [`crate::limits::MAX_ENTRY_BYTES`].
    EntryTooLarge(usize),
    DepthLimitExceeded,
    UnsupportedType(u8),
    TrailingBytes,
    UnsupportedVersion(u32),
    /// Structure does not match the versioned layout.
    MalformedManifest(&'static str),
}

impl CborError {
    pub fn into_value(self) -> crate::value::ValueError {
        crate::value::ValueError::Cbor(self)
    }
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => f.write_str("unexpected end of CBOR buffer"),
            Self::IndefiniteLengthForbidden => {
                f.write_str("indefinite length items forbidden in canonical CBOR")
            }
            Self::NonCanonicalIntegerEncoding => {
                f.write_str("integer not in shortest canonical representation")
            }
            Self::NonCanonicalFloat => {
                f.write_str("float is -0.0, NaN, or not minimal width in canonical CBOR")
            }
            Self::UnsortedMapKeys => f.write_str("map keys not sorted canonically"),
            Self::DuplicateMapKey => f.write_str("duplicate map key detected"),
            Self::InvalidUtf8 => f.write_str("invalid UTF-8 sequence in text string"),
            Self::UnknownTag(t) => write!(f, "unknown or disallowed CBOR tag: {t}"),
            Self::LengthOverflow => f.write_str("declared length exceeds remaining input"),
            Self::EntryTooLarge(size) => {
                write!(f, "canonical entry exceeds the {size}-byte limit")
            }
            Self::DepthLimitExceeded => f.write_str("CBOR nesting depth exceeds the limit"),
            Self::UnsupportedType(t) => write!(f, "unsupported CBOR major type or value: {t:#x}"),
            Self::TrailingBytes => f.write_str("trailing unparsed bytes in CBOR buffer"),
            Self::UnsupportedVersion(v) => {
                write!(f, "unsupported manifest format version: {v}")
            }
            Self::MalformedManifest(msg) => write!(f, "malformed manifest: {msg}"),
        }
    }
}

impl core::error::Error for CborError {}

/// An in-memory CBOR data item.
///
/// `Float` equality compares IEEE bit patterns, a true equivalence relation
/// even for `NaN` and `-0.0`. Canonical paths never store either; the
/// tolerant reader may.
#[derive(Debug, Clone)]
pub enum CborValue {
    Unsigned(u64),
    Negative(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    /// Maintained in canonical key order.
    Map(Vec<(CborValue, CborValue)>),
    Tag(u64, Box<CborValue>),
    Bool(bool),
    Null,
    /// Never `NaN` or `-0.0` on the canonical path.
    Float(f64),
}

impl PartialEq for CborValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Unsigned(a), Self::Unsigned(b)) => a == b,
            (Self::Negative(a), Self::Negative(b)) => a == b,
            (Self::Bytes(a), Self::Bytes(b)) => a == b,
            (Self::Text(a), Self::Text(b)) => a == b,
            (Self::Array(a), Self::Array(b)) => a == b,
            (Self::Map(a), Self::Map(b)) => a == b,
            (Self::Tag(at, ai), Self::Tag(bt, bi)) => at == bt && ai == bi,
            (Self::Bool(a), Self::Bool(b)) => a == b,
            (Self::Null, Self::Null) => true,
            (Self::Float(a), Self::Float(b)) => a.to_bits() == b.to_bits(),
            _ => false,
        }
    }
}

impl Eq for CborValue {}

/// Zero-trust reader for a superset of canonical CBOR.
///
/// Accepts indefinite lengths, non-shortest widths, duplicate keys,
/// non-minimal floats, `-0.0`, `NaN`, and unknown tags. Never panics;
/// depth and length bounds turn hostile input into errors.
#[derive(Debug, Clone, Copy)]
pub struct TolerantReader {
    max_depth: usize,
}

impl TolerantReader {
    pub const fn new() -> Self {
        Self {
            max_depth: MAX_DEPTH,
        }
    }

    /// Constructs a reader with a custom depth limit.
    ///
    /// Keep the depth modest: it is the only guard against stack
    /// exhaustion from hostile nesting.
    pub const fn with_max_depth(max_depth: usize) -> Self {
        Self { max_depth }
    }
}

impl Default for TolerantReader {
    fn default() -> Self {
        Self::new()
    }
}

/// Compares canonical CBOR keys (RFC 8949 sec 4.2.3): shorter first,
/// then bytewise lexicographic.
#[inline]
pub fn compare_canonical_keys(a: &[u8], b: &[u8]) -> Ordering {
    if a.len() != b.len() {
        a.len().cmp(&b.len())
    } else {
        a.cmp(b)
    }
}

pub mod decode;
pub mod encode;
pub mod items;

pub use items::{Item, ItemReader};

pub use decode::parse_tolerant;
pub use encode::{
    array, boolean, bytes, encode_minimal_float, map, null, signed, tag, text, unsigned,
};
