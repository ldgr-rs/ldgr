use alloc::vec::Vec;

use super::{CborError, CborValue, TAG_ALLOWLIST, compare_canonical_keys};

impl CborValue {
    /// Returns the canonical serialized bytes of this value.
    ///
    /// Returns a [`CborError`] when encountering disallowed values (such as `-0.0`, `NaN`, or
    /// disallowed tags).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, CborError> {
        let mut out = Vec::new();
        self.try_encode(&mut out)?;
        Ok(out)
    }

    /// Explicit alias for [`Self::to_canonical_bytes`].
    pub fn try_to_canonical_bytes(&self) -> Result<Vec<u8>, CborError> {
        self.to_canonical_bytes()
    }

    /// Encodes this value into the output byte buffer.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), CborError> {
        self.try_encode(out)
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

#[inline]
fn major(out: &mut Vec<u8>, kind: u8, value: u64) {
    // Every narrowing cast below is guarded by the preceding bounds check,
    // so the value always fits the encoded width.
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
pub(crate) fn f32_bits_to_f16(bits: u32) -> u16 {
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
pub(crate) fn f16_bits_to_f64(bits: u16) -> f64 {
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
