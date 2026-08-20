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
/// Tags carry type semantics only, never structural meaning. The journal
/// self-emits no tags, so the allowlist is empty. Extend it only when the
/// specification adds a tag with defined semantics.
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
    /// Declared array, map, byte, or text length exceeds the remaining input.
    LengthOverflow,
    DepthLimitExceeded,
    UnsupportedType(u8),
    TrailingBytes,
    UnsupportedVersion(u32),
    /// Manifest structure does not match the version 1 layout.
    MalformedManifest(&'static str),
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

#[cfg(feature = "std")]
impl std::error::Error for CborError {}

/// An in-memory CBOR data item.
///
/// `Float` equality compares IEEE bit patterns. The canonical encoder and
/// decoder never store `NaN` or `-0.0`; the tolerant reader may store either.
/// Bit-pattern equality is a true equivalence relation for every value,
/// including `NaN` and `-0.0`.
#[derive(Debug, Clone)]
pub enum CborValue {
    /// Major type 0: Unsigned integer.
    Unsigned(u64),
    /// Major type 1: Negative integer (-1 - n).
    Negative(u64),
    /// Major type 2: Byte string.
    Bytes(Vec<u8>),
    /// Major type 3: UTF-8 text string.
    Text(String),
    /// Major type 4: Array of values.
    Array(Vec<CborValue>),
    /// Major type 5: Map of key-value pairs (maintained in canonical key order).
    Map(Vec<(CborValue, CborValue)>),
    /// Major type 6: Tagged value.
    Tag(u64, Box<CborValue>),
    /// Major type 7: Boolean.
    Bool(bool),
    /// Major type 7: Null.
    Null,
    /// Major type 7: IEEE 754 floating point. The canonical path never stores
    /// `NaN` or `-0.0`; the tolerant reader may store either from input.
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

/// Zero-trust CBOR reader for a superset of canonical RFC 8949 Core
/// Deterministic CBOR.
///
/// The canonical decoder [`CborValue::from_canonical_bytes`] rejects every
/// non-canonical form. This reader is a separate path for untrusted input. It
/// accepts indefinite-length arrays and maps, non-shortest integer widths,
/// duplicate map keys, non-minimal float widths, `-0.0`, `NaN`, and unknown
/// semantic tags. It never panics on any byte input. A nesting depth limit and
/// bounded declared lengths make hostile input return an error instead of
/// exhausting the stack or the heap.
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

    /// Constructs a tolerant reader with a custom nesting depth limit.
    ///
    /// Keep the depth modest. The depth bound is the only guard against stack
    /// exhaustion from hostile nesting. A huge limit lets deeply nested input
    /// recurse to the input length. Prefer a small value near [`MAX_DEPTH`].
    pub const fn with_max_depth(max_depth: usize) -> Self {
        Self { max_depth }
    }
}

impl Default for TolerantReader {
    fn default() -> Self {
        Self::new()
    }
}

/// Compares two serialized canonical CBOR keys according to RFC 8949,
/// section 4.2.3:
/// 1. Shorter byte length precedes longer byte length.
/// 2. Identical byte length uses bytewise lexicographical comparison.
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

pub use decode::parse_tolerant;
pub use encode::{
    array, boolean, bytes, encode_minimal_float, map, null, signed, tag, text, unsigned,
};
