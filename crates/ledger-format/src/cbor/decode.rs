use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::Ordering;

use super::encode::{f16_bits_to_f64, f32_bits_to_f16};
use super::{CborError, CborValue, TAG_ALLOWLIST, TolerantReader, compare_canonical_keys};

impl CborValue {
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

pub(crate) fn decode_header(input: &[u8], cursor: &mut usize) -> Result<(u8, u64), CborError> {
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
/// than [`super::MAX_DEPTH`] so hostile data can never exhaust the stack.
fn decode_value(input: &[u8], cursor: &mut usize, depth: usize) -> Result<CborValue, CborError> {
    if depth > super::MAX_DEPTH {
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

impl TolerantReader {
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
