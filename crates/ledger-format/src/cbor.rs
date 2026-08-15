//! Canonical RFC 8949 Core Deterministic CBOR encoder, validating decoder, and
//! zero-trust tolerant reader.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
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

impl CborValue {
    /// Returns the canonical serialized bytes of this value.
    ///
    /// This method cannot fail. A value from the tolerant reader may hold
    /// `-0.0`, `NaN`, or a disallowed tag; for those values the encoding
    /// silently writes nothing. Use [`Self::try_to_canonical_bytes`] for
    /// untrusted input so the failure is visible.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }

    pub fn try_to_canonical_bytes(&self) -> Result<Vec<u8>, CborError> {
        let mut out = Vec::new();
        self.try_encode(&mut out)?;
        Ok(out)
    }

    /// Encodes this value into the output byte buffer.
    ///
    /// On error nothing is written to the buffer. Values from the canonical
    /// path always encode. Values from the tolerant reader can fail when they
    /// hold `-0.0`, `NaN`, or a disallowed tag.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let start = out.len();
        if self.try_encode(out).is_err() {
            out.truncate(start);
        }
    }

    /// Encodes this value into the output byte buffer, reporting the error.
    ///
    /// On error the buffer may contain partial bytes; the caller must discard
    /// the tail.
    pub fn try_encode(&self, out: &mut Vec<u8>) -> Result<(), CborError> {
        match self {
            Self::Unsigned(val) => {
                unsigned(out, *val);
                Ok(())
            }
            Self::Negative(val) => {
                major(out, 1, *val);
                Ok(())
            }
            Self::Bytes(b) => {
                bytes(out, b);
                Ok(())
            }
            Self::Text(s) => {
                text(out, s);
                Ok(())
            }
            Self::Array(items) => {
                array(out, items.len());
                for item in items {
                    item.try_encode(out)?;
                }
                Ok(())
            }
            Self::Map(entries) => {
                let mut encoded_entries: Vec<(Vec<u8>, Vec<u8>)> =
                    Vec::with_capacity(entries.len());
                for (key, val) in entries {
                    let key_bytes = key.try_to_canonical_bytes()?;
                    let val_bytes = val.try_to_canonical_bytes()?;
                    encoded_entries.push((key_bytes, val_bytes));
                }
                // Reject duplicate canonical keys before sorting.
                for i in 0..encoded_entries.len() {
                    for j in (i + 1)..encoded_entries.len() {
                        if encoded_entries[i].0 == encoded_entries[j].0 {
                            return Err(CborError::DuplicateMapKey);
                        }
                    }
                }
                encoded_entries.sort_by(|a, b| compare_canonical_keys(&a.0, &b.0));

                map(out, encoded_entries.len());
                for (key_bytes, val_bytes) in encoded_entries {
                    out.extend_from_slice(&key_bytes);
                    out.extend_from_slice(&val_bytes);
                }
                Ok(())
            }
            Self::Tag(tag_num, inner) => {
                if !TAG_ALLOWLIST.contains(tag_num) {
                    return Err(CborError::UnknownTag(*tag_num));
                }
                tag(out, *tag_num);
                inner.try_encode(out)
            }
            Self::Bool(b) => {
                boolean(out, *b);
                Ok(())
            }
            Self::Null => {
                null(out);
                Ok(())
            }
            Self::Float(value) => {
                if value.is_nan() {
                    return Err(CborError::NonCanonicalFloat);
                }
                if value.is_sign_negative() && *value == 0.0 {
                    return Err(CborError::NonCanonicalFloat);
                }
                encode_minimal_float(out, *value);
                Ok(())
            }
        }
    }

    /// Parses one canonical CBOR value from bytes, enforcing all canonical constraints.
    pub fn from_canonical_bytes(input: &[u8]) -> Result<Self, CborError> {
        let mut cursor = 0;
        let val = decode_value(input, &mut cursor, 0)?;
        if cursor != input.len() {
            return Err(CborError::TrailingBytes);
        }
        Ok(val)
    }
}

#[inline]
pub fn unsigned(out: &mut Vec<u8>, value: u64) {
    major(out, 0, value);
}

#[inline]
pub fn signed(out: &mut Vec<u8>, value: i64) {
    if value >= 0 {
        unsigned(out, value as u64);
    } else {
        major(out, 1, value.unsigned_abs().saturating_sub(1));
    }
}

#[inline]
pub fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    major(out, 2, value.len() as u64);
    out.extend_from_slice(value);
}

#[inline]
pub fn text(out: &mut Vec<u8>, value: &str) {
    major(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

#[inline]
pub fn array(out: &mut Vec<u8>, length: usize) {
    major(out, 4, length as u64);
}

#[inline]
pub fn map(out: &mut Vec<u8>, length: usize) {
    major(out, 5, length as u64);
}

#[inline]
pub fn tag(out: &mut Vec<u8>, tag_num: u64) {
    major(out, 6, tag_num);
}

#[inline]
pub fn boolean(out: &mut Vec<u8>, val: bool) {
    if val {
        out.push(0xf5);
    } else {
        out.push(0xf4);
    }
}

#[inline]
pub fn null(out: &mut Vec<u8>) {
    out.push(0xf6);
}

/// Appends a canonical CBOR float using the minimal width that round-trips.
///
/// The caller must reject `-0.0` and `NaN` before calling.
///
/// Width selection: half precision when the value round-trips exactly, else
/// single precision when the value round-trips through `f32`, else double
/// precision. An integer-valued float is never coerced to an integer encoding;
/// the specification only notes this as a policy, not a rule.
pub fn encode_minimal_float(out: &mut Vec<u8>, value: f64) {
    if let Some(half_bits) = value_round_trips_as_f16(value) {
        out.push(0xf9);
        out.extend_from_slice(&half_bits.to_be_bytes());
    } else if value as f32 as f64 == value {
        out.push(0xfa);
        out.extend_from_slice(&(value as f32).to_bits().to_be_bytes());
    } else {
        out.push(0xfb);
        out.extend_from_slice(&value.to_bits().to_be_bytes());
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

#[inline]
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

/// Returns the half-precision bits for `value`, if it round-trips exactly
/// through half precision.
///
/// The value must round-trip through `f32` first; a value not representable in
/// single precision can never be representable in half precision. The final
/// check compares the half value against the original `f64`, not against the
/// intermediate `f32`.
fn value_round_trips_as_f16(value: f64) -> Option<u16> {
    let single = value as f32;
    if single as f64 != value {
        return None;
    }
    let half_bits = f32_bits_to_f16(single.to_bits());
    if f16_bits_to_f64(half_bits) == value {
        Some(half_bits)
    } else {
        None
    }
}

/// Converts IEEE 754 single-precision bits to half-precision bits using
/// round-to-nearest-even on the discarded mantissa bits.
fn f32_bits_to_f16(bits: u32) -> u16 {
    let sign = ((bits >> 16) & 0x8000) as u16;
    let exp = ((bits >> 23) & 0xff) as i32;
    let mant = bits & 0x7f_ffff;

    if exp == 0xff {
        // Infinity or NaN: preserve the class in half precision. Callers
        // reject NaN upstream, so this path only carries a NaN class bit.
        return sign | 0x7c00 | u16::from(mant != 0);
    }

    let exp16 = exp - 127 + 15;
    if exp16 >= 0x1f {
        // Magnitude overflows half precision: round to infinity.
        return sign | 0x7c00;
    }

    if exp16 > 0 {
        // Normal half value: shift the 23-bit mantissa down 13 bits.
        let mut m16 = (mant >> 13) as u16;
        let round_bit = (mant >> 12) & 1;
        let sticky = mant & 0x0fff;
        if round_bit == 1 && (sticky != 0 || m16 & 1 == 1) {
            m16 += 1;
            if m16 == 0x400 {
                // Mantissa overflow: carry into the exponent field.
                return sign | ((exp16 + 1) as u16) << 10;
            }
        }
        return sign | ((exp16 as u16) << 10) | m16;
    }

    // Subnormal or zero in half precision. exp16 <= 0.
    let shift = (14 - exp16) as u32;
    if shift >= 25 {
        // Magnitude rounds to zero; the round bit is never set at this shift.
        return sign;
    }
    let full = mant | 0x80_0000;
    let mut m16 = full >> shift;
    let round_bit = (full >> (shift - 1)) & 1;
    let sticky = full & ((1u32 << (shift - 1)) - 1);
    if round_bit == 1 && (sticky != 0 || m16 & 1 == 1) {
        m16 += 1;
    }
    sign | (m16 as u16)
}

/// Converts half-precision bits to an exact `f64`. Every half value is
/// exactly representable as a double, so the arithmetic below is exact.
fn f16_bits_to_f64(bits: u16) -> f64 {
    let sign = if bits & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exp = ((bits >> 10) & 0x1f) as i32;
    let mant = (bits & 0x03ff) as f64;
    let magnitude = if exp == 0 {
        mant * 1.0 / 16_777_216.0 // 2^-24; exact power of two
    } else if exp == 31 {
        if mant == 0.0 { f64::INFINITY } else { f64::NAN }
    } else {
        (1.0 + mant / 1024.0) * two_to_power(exp - 15)
    };
    sign * magnitude
}

/// Returns `2^k` exactly, for `-24 <= k <= 15`.
///
/// `f64::powi` is not available in `core`. Powers of two are exactly
/// representable, and division by a power of two is exact, so the result has
/// the same bits as `powi`.
fn two_to_power(k: i32) -> f64 {
    if k >= 0 {
        (1u32 << k) as f64
    } else {
        1.0 / ((1u32 << -k) as f64)
    }
}

fn decode_header(input: &[u8], cursor: &mut usize) -> Result<(u8, u64), CborError> {
    if *cursor >= input.len() {
        return Err(CborError::UnexpectedEof);
    }
    let initial = input[*cursor];
    *cursor += 1;
    let major = initial >> 5;
    let additional = initial & 0x1f;

    let value = match additional {
        0..=23 => additional as u64,
        24 => {
            if *cursor >= input.len() {
                return Err(CborError::UnexpectedEof);
            }
            let v = input[*cursor] as u64;
            *cursor += 1;
            if v < 24 {
                return Err(CborError::NonCanonicalIntegerEncoding);
            }
            v
        }
        25 => {
            if *cursor + 2 > input.len() {
                return Err(CborError::UnexpectedEof);
            }
            let bytes = [input[*cursor], input[*cursor + 1]];
            *cursor += 2;
            let v = u16::from_be_bytes(bytes) as u64;
            if v <= u8::MAX as u64 {
                return Err(CborError::NonCanonicalIntegerEncoding);
            }
            v
        }
        26 => {
            if *cursor + 4 > input.len() {
                return Err(CborError::UnexpectedEof);
            }
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&input[*cursor..*cursor + 4]);
            *cursor += 4;
            let v = u32::from_be_bytes(bytes) as u64;
            if v <= u16::MAX as u64 {
                return Err(CborError::NonCanonicalIntegerEncoding);
            }
            v
        }
        27 => {
            if *cursor + 8 > input.len() {
                return Err(CborError::UnexpectedEof);
            }
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&input[*cursor..*cursor + 8]);
            *cursor += 8;
            let v = u64::from_be_bytes(bytes);
            if v <= u32::MAX as u64 {
                return Err(CborError::NonCanonicalIntegerEncoding);
            }
            v
        }
        31 => return Err(CborError::IndefiniteLengthForbidden),
        _ => return Err(CborError::UnsupportedType(initial)),
    };

    Ok((major, value))
}

/// Decodes one canonical CBOR value from `input`, advancing `cursor`.
///
/// `depth` tracks the current nesting level. The decoder rejects input deeper
/// than [`MAX_DEPTH`] so hostile data can never exhaust the stack.
fn decode_value(input: &[u8], cursor: &mut usize, depth: usize) -> Result<CborValue, CborError> {
    if depth > MAX_DEPTH {
        return Err(CborError::DepthLimitExceeded);
    }
    if *cursor >= input.len() {
        return Err(CborError::UnexpectedEof);
    }
    let initial = input[*cursor];
    let major = initial >> 5;
    let additional = initial & 0x1f;

    if major == 7 {
        *cursor += 1;
        return match additional {
            20 => Ok(CborValue::Bool(false)),
            21 => Ok(CborValue::Bool(true)),
            22 => Ok(CborValue::Null),
            25 => decode_f16(input, cursor),
            26 => decode_f32(input, cursor),
            27 => decode_f64(input, cursor),
            24 => {
                if *cursor >= input.len() {
                    return Err(CborError::UnexpectedEof);
                }
                let v = input[*cursor];
                *cursor += 1;
                if v < 24 {
                    // A simple value below 24 must use the one-byte form.
                    Err(CborError::NonCanonicalIntegerEncoding)
                } else {
                    Err(CborError::UnsupportedType(initial))
                }
            }
            31 => Err(CborError::IndefiniteLengthForbidden),
            _ => Err(CborError::UnsupportedType(initial)),
        };
    }

    let (major, value) = decode_header(input, cursor)?;
    let remaining = input.len() - *cursor;
    match major {
        0 => Ok(CborValue::Unsigned(value)),
        1 => Ok(CborValue::Negative(value)),
        2 => {
            if value > remaining as u64 {
                return Err(CborError::LengthOverflow);
            }
            let len = value as usize;
            let b = input[*cursor..*cursor + len].to_vec();
            *cursor += len;
            Ok(CborValue::Bytes(b))
        }
        3 => {
            if value > remaining as u64 {
                return Err(CborError::LengthOverflow);
            }
            let len = value as usize;
            let s = core::str::from_utf8(&input[*cursor..*cursor + len])
                .map_err(|_| CborError::InvalidUtf8)?
                .to_string();
            *cursor += len;
            Ok(CborValue::Text(s))
        }
        4 => {
            if value > remaining as u64 {
                return Err(CborError::LengthOverflow);
            }
            let count = value as usize;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                items.push(decode_value(input, cursor, depth + 1)?);
            }
            Ok(CborValue::Array(items))
        }
        5 => {
            if value > remaining as u64 {
                return Err(CborError::LengthOverflow);
            }
            let count = value as usize;
            let mut entries = Vec::with_capacity(count);
            let mut previous_raw_key: Option<Vec<u8>> = None;

            for _ in 0..count {
                let key_start = *cursor;
                let key = decode_value(input, cursor, depth + 1)?;
                let key_end = *cursor;
                let raw_key = input[key_start..key_end].to_vec();

                if let Some(prev) = &previous_raw_key {
                    match compare_canonical_keys(prev, &raw_key) {
                        Ordering::Greater => return Err(CborError::UnsortedMapKeys),
                        Ordering::Equal => return Err(CborError::DuplicateMapKey),
                        Ordering::Less => {}
                    }
                }
                previous_raw_key = Some(raw_key);

                let val = decode_value(input, cursor, depth + 1)?;
                entries.push((key, val));
            }
            Ok(CborValue::Map(entries))
        }
        6 => {
            if !TAG_ALLOWLIST.contains(&value) {
                return Err(CborError::UnknownTag(value));
            }
            let inner = decode_value(input, cursor, depth + 1)?;
            Ok(CborValue::Tag(value, Box::new(inner)))
        }
        _ => Err(CborError::UnsupportedType(initial)),
    }
}

/// Decodes a half-precision float (major type 7, additional value 25).
fn decode_f16(input: &[u8], cursor: &mut usize) -> Result<CborValue, CborError> {
    if *cursor + 2 > input.len() {
        return Err(CborError::UnexpectedEof);
    }
    let bits = u16::from_be_bytes([input[*cursor], input[*cursor + 1]]);
    *cursor += 2;
    let value = f16_bits_to_f64(bits);
    if value.is_nan() {
        return Err(CborError::NonCanonicalFloat);
    }
    if value.is_sign_negative() && value == 0.0 {
        return Err(CborError::NonCanonicalFloat);
    }
    // Half precision has no narrower float width, so a half is always minimal.
    Ok(CborValue::Float(value))
}

/// Decodes a single-precision float (major type 7, additional value 26).
fn decode_f32(input: &[u8], cursor: &mut usize) -> Result<CborValue, CborError> {
    if *cursor + 4 > input.len() {
        return Err(CborError::UnexpectedEof);
    }
    let mut bits = [0u8; 4];
    bits.copy_from_slice(&input[*cursor..*cursor + 4]);
    *cursor += 4;
    let value = f32::from_bits(u32::from_be_bytes(bits));
    if value.is_nan() {
        return Err(CborError::NonCanonicalFloat);
    }
    if value.is_sign_negative() && value == 0.0 {
        return Err(CborError::NonCanonicalFloat);
    }
    // A single that is exactly representable in half is non-canonical.
    let half_bits = f32_bits_to_f16(value.to_bits());
    if f16_bits_to_f64(half_bits) == value as f64 {
        return Err(CborError::NonCanonicalFloat);
    }
    Ok(CborValue::Float(value as f64))
}

/// Decodes a double-precision float (major type 7, additional value 27).
fn decode_f64(input: &[u8], cursor: &mut usize) -> Result<CborValue, CborError> {
    if *cursor + 8 > input.len() {
        return Err(CborError::UnexpectedEof);
    }
    let mut bits = [0u8; 8];
    bits.copy_from_slice(&input[*cursor..*cursor + 8]);
    *cursor += 8;
    let value = f64::from_bits(u64::from_be_bytes(bits));
    if value.is_nan() {
        return Err(CborError::NonCanonicalFloat);
    }
    if value.is_sign_negative() && value == 0.0 {
        return Err(CborError::NonCanonicalFloat);
    }
    // A double that is exactly representable as a single is non-canonical.
    if value as f32 as f64 == value {
        return Err(CborError::NonCanonicalFloat);
    }
    Ok(CborValue::Float(value))
}

/// Parses one CBOR value from `bytes` with a default [`TolerantReader`].
///
/// The tolerant reader accepts supersets of the canonical form and never
/// panics on any byte input. See [`TolerantReader::parse`] for the contract.
pub fn parse_tolerant(bytes: &[u8]) -> Result<CborValue, CborError> {
    TolerantReader::new().parse(bytes)
}

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

    /// Parses one CBOR value from `bytes`.
    ///
    /// Returns [`CborError::TrailingBytes`] when extra bytes follow the
    /// complete value. The reader never panics; malformed, hostile, and
    /// truncated input returns an error.
    pub fn parse(&self, bytes: &[u8]) -> Result<CborValue, CborError> {
        let mut cursor = 0;
        let Some(value) = self.decode_item(bytes, &mut cursor, 0, false)? else {
            return Err(CborError::UnsupportedType(0xff));
        };
        if cursor != bytes.len() {
            return Err(CborError::TrailingBytes);
        }
        Ok(value)
    }

    /// Decodes one CBOR item, advancing `cursor`.
    ///
    /// `break_allowed` is true only directly inside an indefinite-length
    /// container. A break stop code at such a position is consumed and yields
    /// `Ok(None)`. Every other item yields `Ok(Some(...))`. `depth` tracks the
    /// nesting level; input deeper than `max_depth` is rejected so hostile
    /// data can never exhaust the stack.
    fn decode_item(
        &self,
        input: &[u8],
        cursor: &mut usize,
        depth: usize,
        break_allowed: bool,
    ) -> Result<Option<CborValue>, CborError> {
        if depth > self.max_depth {
            return Err(CborError::DepthLimitExceeded);
        }
        if *cursor >= input.len() {
            return Err(CborError::UnexpectedEof);
        }
        let initial = input[*cursor];
        let major = initial >> 5;
        let additional = initial & 0x1f;

        if major == 7 && additional == 31 {
            // Break stop code: terminates an enclosing indefinite container.
            if break_allowed {
                *cursor += 1;
                return Ok(None);
            }
            return Err(CborError::UnsupportedType(initial));
        }

        if major == 7 {
            *cursor += 1;
            return match additional {
                20 => Ok(Some(CborValue::Bool(false))),
                21 => Ok(Some(CborValue::Bool(true))),
                22 => Ok(Some(CborValue::Null)),
                25 => decode_f16_tolerant(input, cursor).map(Some),
                26 => decode_f32_tolerant(input, cursor).map(Some),
                27 => decode_f64_tolerant(input, cursor).map(Some),
                // Simple values 0..23, one-byte simple values, and reserved
                // additional values have no representation in CborValue.
                _ => Err(CborError::UnsupportedType(initial)),
            };
        }

        let (major, additional, value) = read_tolerant_header(input, cursor)?;
        match major {
            0 => {
                if additional == 31 {
                    return Err(CborError::UnsupportedType(initial));
                }
                Ok(Some(CborValue::Unsigned(value)))
            }
            1 => {
                if additional == 31 {
                    return Err(CborError::UnsupportedType(initial));
                }
                Ok(Some(CborValue::Negative(value)))
            }
            2 => {
                if additional == 31 {
                    self.decode_indefinite_bytes(input, cursor, depth).map(Some)
                } else {
                    let span = take_bytes_span(input, cursor, value)?;
                    Ok(Some(CborValue::Bytes(span.to_vec())))
                }
            }
            3 => {
                if additional == 31 {
                    self.decode_indefinite_text(input, cursor, depth).map(Some)
                } else {
                    let span = take_bytes_span(input, cursor, value)?;
                    let s = core::str::from_utf8(span).map_err(|_| CborError::InvalidUtf8)?;
                    Ok(Some(CborValue::Text(s.to_string())))
                }
            }
            4 => {
                if additional == 31 {
                    self.decode_indefinite_array(input, cursor, depth).map(Some)
                } else {
                    let count = bounded_item_count(input, cursor, value, 1)?;
                    let mut items = Vec::with_capacity(count);
                    for _ in 0..count {
                        let Some(item) = self.decode_item(input, cursor, depth + 1, false)? else {
                            return Err(CborError::UnsupportedType(0xff));
                        };
                        items.push(item);
                    }
                    Ok(Some(CborValue::Array(items)))
                }
            }
            5 => {
                if additional == 31 {
                    self.decode_indefinite_map(input, cursor, depth).map(Some)
                } else {
                    let count = bounded_item_count(input, cursor, value, 2)?;
                    let mut entries = Vec::with_capacity(count);
                    for _ in 0..count {
                        let Some(key) = self.decode_item(input, cursor, depth + 1, false)? else {
                            return Err(CborError::UnsupportedType(0xff));
                        };
                        let Some(val) = self.decode_item(input, cursor, depth + 1, false)? else {
                            return Err(CborError::UnsupportedType(0xff));
                        };
                        entries.push((key, val));
                    }
                    Ok(Some(CborValue::Map(entries)))
                }
            }
            6 => {
                if additional == 31 {
                    return Err(CborError::UnsupportedType(initial));
                }
                let Some(inner) = self.decode_item(input, cursor, depth + 1, false)? else {
                    return Err(CborError::UnsupportedType(0xff));
                };
                Ok(Some(CborValue::Tag(value, Box::new(inner))))
            }
            _ => Err(CborError::UnsupportedType(initial)),
        }
    }

    fn decode_indefinite_bytes(
        &self,
        input: &[u8],
        cursor: &mut usize,
        depth: usize,
    ) -> Result<CborValue, CborError> {
        let mut out = Vec::new();
        loop {
            match self.decode_item(input, cursor, depth + 1, true)? {
                Some(CborValue::Bytes(chunk)) => out.extend_from_slice(&chunk),
                Some(_) => return Err(CborError::UnsupportedType(0x5f)),
                None => break,
            }
        }
        Ok(CborValue::Bytes(out))
    }

    fn decode_indefinite_text(
        &self,
        input: &[u8],
        cursor: &mut usize,
        depth: usize,
    ) -> Result<CborValue, CborError> {
        let mut out = String::new();
        loop {
            match self.decode_item(input, cursor, depth + 1, true)? {
                Some(CborValue::Text(chunk)) => out.push_str(&chunk),
                Some(_) => return Err(CborError::UnsupportedType(0x7f)),
                None => break,
            }
        }
        Ok(CborValue::Text(out))
    }

    fn decode_indefinite_array(
        &self,
        input: &[u8],
        cursor: &mut usize,
        depth: usize,
    ) -> Result<CborValue, CborError> {
        let mut items = Vec::new();
        while let Some(item) = self.decode_item(input, cursor, depth + 1, true)? {
            items.push(item);
        }
        Ok(CborValue::Array(items))
    }

    /// Duplicate keys are kept, matching the tolerant policy of the reader.
    fn decode_indefinite_map(
        &self,
        input: &[u8],
        cursor: &mut usize,
        depth: usize,
    ) -> Result<CborValue, CborError> {
        let mut entries = Vec::new();
        while let Some(key) = self.decode_item(input, cursor, depth + 1, true)? {
            let Some(value) = self.decode_item(input, cursor, depth + 1, false)? else {
                return Err(CborError::UnsupportedType(0xff));
            };
            entries.push((key, value));
        }
        Ok(CborValue::Map(entries))
    }
}

impl Default for TolerantReader {
    fn default() -> Self {
        Self::new()
    }
}

/// Reads a CBOR header without canonical width checks.
///
/// Non-shortest integer widths are accepted. `additional == 31` is reported to
/// the caller as an indefinite-length marker.
fn read_tolerant_header(input: &[u8], cursor: &mut usize) -> Result<(u8, u8, u64), CborError> {
    if *cursor >= input.len() {
        return Err(CborError::UnexpectedEof);
    }
    let initial = input[*cursor];
    *cursor += 1;
    let major = initial >> 5;
    let additional = initial & 0x1f;
    let value = match additional {
        0..=23 => additional as u64,
        24 => u64::from(take_one(input, cursor)?),
        25 => u64::from(u16::from_be_bytes(take_bytes::<2>(input, cursor)?)),
        26 => u64::from(u32::from_be_bytes(take_bytes::<4>(input, cursor)?)),
        27 => u64::from_be_bytes(take_bytes::<8>(input, cursor)?),
        28..=30 => return Err(CborError::UnsupportedType(initial)),
        31 => 0,
        // The 5-bit mask bounds additional to 0..=31, so this arm is
        // unreachable; it keeps the match exhaustive.
        _ => return Err(CborError::UnsupportedType(initial)),
    };
    Ok((major, additional, value))
}

fn take_one(input: &[u8], cursor: &mut usize) -> Result<u8, CborError> {
    if *cursor >= input.len() {
        return Err(CborError::UnexpectedEof);
    }
    let byte = input[*cursor];
    *cursor += 1;
    Ok(byte)
}

fn take_bytes<const N: usize>(input: &[u8], cursor: &mut usize) -> Result<[u8; N], CborError> {
    let end = cursor.checked_add(N).ok_or(CborError::UnexpectedEof)?;
    if end > input.len() {
        return Err(CborError::UnexpectedEof);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&input[*cursor..end]);
    *cursor = end;
    Ok(out)
}

/// Returns a slice of `declared` bytes starting at `cursor`.
///
/// The declared length is bounded against the remaining input, so a hostile
/// declared length yields an error instead of an out-of-bounds read.
fn take_bytes_span<'a>(
    input: &'a [u8],
    cursor: &mut usize,
    declared: u64,
) -> Result<&'a [u8], CborError> {
    let remaining = input.len().saturating_sub(*cursor);
    if declared > remaining as u64 {
        return Err(CborError::LengthOverflow);
    }
    let len = declared as usize;
    let end = cursor.checked_add(len).ok_or(CborError::LengthOverflow)?;
    let span = &input[*cursor..end];
    *cursor = end;
    Ok(span)
}

/// Bounds a declared item count against the remaining input.
///
/// `min_bytes_per_item` is the minimum bytes one item occupies (1 for array
/// items, 2 for map entries). The returned count never exceeds the available
/// bytes, so a hostile count cannot force a huge allocation.
fn bounded_item_count(
    input: &[u8],
    cursor: &mut usize,
    declared: u64,
    min_bytes_per_item: usize,
) -> Result<usize, CborError> {
    let remaining = input.len().saturating_sub(*cursor);
    let max_count = remaining / min_bytes_per_item;
    if declared > max_count as u64 {
        return Err(CborError::LengthOverflow);
    }
    Ok(declared as usize)
}

/// Decodes a half-precision float without canonical checks.
///
/// `-0.0` and `NaN` are accepted. Half precision is never wider than needed,
/// so no minimal-width check applies.
fn decode_f16_tolerant(input: &[u8], cursor: &mut usize) -> Result<CborValue, CborError> {
    let bits = u16::from_be_bytes(take_bytes::<2>(input, cursor)?);
    Ok(CborValue::Float(f16_bits_to_f64(bits)))
}

/// Decodes a single-precision float without canonical checks.
///
/// `-0.0`, `NaN`, and non-minimal widths are accepted.
fn decode_f32_tolerant(input: &[u8], cursor: &mut usize) -> Result<CborValue, CborError> {
    let bits = u32::from_be_bytes(take_bytes::<4>(input, cursor)?);
    Ok(CborValue::Float(f32::from_bits(bits) as f64))
}

/// Decodes a double-precision float without canonical checks.
///
/// `-0.0`, `NaN`, and non-minimal widths are accepted.
fn decode_f64_tolerant(input: &[u8], cursor: &mut usize) -> Result<CborValue, CborError> {
    let bits = u64::from_be_bytes(take_bytes::<8>(input, cursor)?);
    Ok(CborValue::Float(f64::from_bits(bits)))
}
