//! Borrowed canonical CBOR item reader for bounded entry decoding.
//!
//! Borrows byte and text strings so declared lengths check against remaining
//! input before any content allocation.

use alloc::string::ToString;
use alloc::vec::Vec;
use core::cmp::Ordering;

use super::decode::decode_header;
use super::{CborError, compare_canonical_keys};

/// One borrowed canonical CBOR item.
#[derive(Debug, Clone, PartialEq)]
pub enum Item<'a> {
    Unsigned(u64),
    Negative(u64),
    /// Borrowed from the input.
    Bytes(&'a [u8]),
    /// Borrowed from the input.
    Text(&'a str),
    /// Array header with the declared element count.
    Array(usize),
    /// Map header with the declared entry count.
    Map(usize),
    Bool(bool),
    Null,
    Float(f64),
}

/// Cursor-based canonical item reader.
#[derive(Debug, Clone)]
pub struct ItemReader<'a> {
    input: &'a [u8],
    cursor: usize,
    depth: usize,
}

impl<'a> ItemReader<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            cursor: 0,
            depth: 0,
        }
    }

    pub fn position(&self) -> usize {
        self.cursor
    }

    pub fn remaining(&self) -> usize {
        self.input.len() - self.cursor
    }

    pub fn at_end(&self) -> bool {
        self.cursor == self.input.len()
    }

    /// Reads the next item, borrowing byte and text strings.
    pub fn read_item(&mut self) -> Result<Item<'a>, CborError> {
        self.depth += 1;
        if self.depth > super::MAX_DEPTH {
            return Err(CborError::DepthLimitExceeded);
        }
        let item = self.read_item_inner()?;
        self.depth -= 1;
        Ok(item)
    }

    fn read_item_inner(&mut self) -> Result<Item<'a>, CborError> {
        if self.cursor >= self.input.len() {
            return Err(CborError::UnexpectedEof);
        }
        let initial = self.input[self.cursor];
        let major = initial >> 5;

        if major == 7 {
            self.cursor += 1;
            let additional = initial & 0x1f;
            return match additional {
                20 => Ok(Item::Bool(false)),
                21 => Ok(Item::Bool(true)),
                22 => Ok(Item::Null),
                25 => self.read_f16().map(Item::Float),
                26 => self.read_f32().map(Item::Float),
                27 => self.read_f64().map(Item::Float),
                24 => {
                    if self.cursor >= self.input.len() {
                        return Err(CborError::UnexpectedEof);
                    }
                    let v = self.input[self.cursor];
                    self.cursor += 1;
                    if v < 24 {
                        return Err(CborError::NonCanonicalIntegerEncoding);
                    }
                    Ok(Item::Unsigned(v as u64))
                }
                31 => Err(CborError::IndefiniteLengthForbidden),
                _ => Err(CborError::UnsupportedType(initial)),
            };
        }

        let (major, value) = decode_header(self.input, &mut self.cursor)?;
        match major {
            0 => Ok(Item::Unsigned(value)),
            1 => Ok(Item::Negative(value)),
            2 => {
                let len = self.checked_len(value)?;
                let bytes = &self.input[self.cursor..self.cursor + len];
                self.cursor += len;
                Ok(Item::Bytes(bytes))
            }
            3 => {
                let len = self.checked_len(value)?;
                let text = core::str::from_utf8(&self.input[self.cursor..self.cursor + len])
                    .map_err(|_| CborError::InvalidUtf8)?;
                self.cursor += len;
                Ok(Item::Text(text))
            }
            4 => {
                self.checked_len(value)?;
                Ok(Item::Array(value as usize))
            }
            5 => {
                self.checked_len(value)?;
                Ok(Item::Map(value as usize))
            }
            _ => Err(CborError::UnsupportedType(initial)),
        }
    }

    fn checked_len(&self, declared: u64) -> Result<usize, CborError> {
        if declared > self.remaining() as u64 {
            return Err(CborError::LengthOverflow);
        }
        // declared <= remaining <= usize::MAX, so the cast is lossless.
        Ok(declared as usize)
    }

    pub fn read_unsigned(&mut self) -> Result<u64, CborError> {
        match self.read_item()? {
            Item::Unsigned(v) => Ok(v),
            _ => Err(CborError::UnsupportedType(0)),
        }
    }

    pub fn read_bytes(&mut self) -> Result<&'a [u8], CborError> {
        match self.read_item()? {
            Item::Bytes(b) => Ok(b),
            _ => Err(CborError::UnsupportedType(0)),
        }
    }

    pub fn read_text(&mut self) -> Result<&'a str, CborError> {
        match self.read_item()? {
            Item::Text(t) => Ok(t),
            _ => Err(CborError::UnsupportedType(0)),
        }
    }

    pub fn read_bool(&mut self) -> Result<bool, CborError> {
        match self.read_item()? {
            Item::Bool(b) => Ok(b),
            _ => Err(CborError::UnsupportedType(0)),
        }
    }

    pub fn read_array(&mut self) -> Result<usize, CborError> {
        match self.read_item()? {
            Item::Array(n) => Ok(n),
            _ => Err(CborError::UnsupportedType(0)),
        }
    }

    pub fn read_null(&mut self) -> Result<(), CborError> {
        match self.read_item()? {
            Item::Null => Ok(()),
            _ => Err(CborError::UnsupportedType(0)),
        }
    }

    /// Reads one canonical value with canonical-value bounds enforced.
    pub fn read_canonical_value(
        &mut self,
    ) -> Result<crate::value::CanonicalValue, crate::value::ValueError> {
        let mut budget = crate::value::Budget::new();
        self.read_value(&mut budget)
    }

    fn read_value(
        &mut self,
        budget: &mut crate::value::Budget,
    ) -> Result<crate::value::CanonicalValue, crate::value::ValueError> {
        budget.visit()?;
        let item = self.read_item().map_err(CborError::into_value)?;
        match item {
            Item::Unsigned(v) => Ok(crate::value::CanonicalValue::Unsigned(v)),
            Item::Negative(v) => Ok(crate::value::CanonicalValue::Negative(v)),
            Item::Bytes(b) => {
                budget.string(b.len())?;
                Ok(crate::value::CanonicalValue::Bytes(b.to_vec()))
            }
            Item::Text(t) => {
                budget.string(t.len())?;
                Ok(crate::value::CanonicalValue::Text(t.to_string()))
            }
            Item::Array(n) => {
                budget.collection(n)?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.read_value(budget)?);
                }
                Ok(crate::value::CanonicalValue::Array(items))
            }
            Item::Map(n) => {
                budget.collection(n)?;
                let mut entries = Vec::with_capacity(n);
                let mut previous_key: Option<Vec<u8>> = None;
                for _ in 0..n {
                    let key_start = self.position();
                    let key = self.read_value(budget)?;
                    let key_end = self.position();
                    let raw_key = self.input[key_start..key_end].to_vec();
                    if let Some(prev) = &previous_key {
                        match compare_canonical_keys(prev, &raw_key) {
                            Ordering::Greater => {
                                return Err(crate::value::ValueError::Cbor(
                                    CborError::UnsortedMapKeys,
                                ));
                            }
                            Ordering::Equal => {
                                return Err(crate::value::ValueError::Cbor(
                                    CborError::DuplicateMapKey,
                                ));
                            }
                            Ordering::Less => {}
                        }
                    }
                    previous_key = Some(raw_key);
                    let value = self.read_value(budget)?;
                    entries.push((key, value));
                }
                Ok(crate::value::CanonicalValue::Map(entries))
            }
            Item::Bool(b) => Ok(crate::value::CanonicalValue::Bool(b)),
            Item::Null => Ok(crate::value::CanonicalValue::Null),
            Item::Float(f) => {
                if f.is_nan() || (f.is_sign_negative() && f == 0.0) {
                    return Err(crate::value::ValueError::BoundsExceeded(
                        "floats must not be NaN or negative zero",
                    ));
                }
                Ok(crate::value::CanonicalValue::Float(f))
            }
        }
    }

    fn read_f16(&mut self) -> Result<f64, CborError> {
        if self.cursor + 2 > self.input.len() {
            return Err(CborError::UnexpectedEof);
        }
        let bits = u16::from_be_bytes([self.input[self.cursor], self.input[self.cursor + 1]]);
        self.cursor += 2;
        let value = super::encode::f16_bits_to_f64(bits);
        if value.is_nan() {
            return Err(CborError::NonCanonicalFloat);
        }
        if value.is_sign_negative() && value == 0.0 {
            return Err(CborError::NonCanonicalFloat);
        }
        Ok(value)
    }

    fn read_f32(&mut self) -> Result<f64, CborError> {
        if self.cursor + 4 > self.input.len() {
            return Err(CborError::UnexpectedEof);
        }
        let mut bits = [0u8; 4];
        bits.copy_from_slice(&self.input[self.cursor..self.cursor + 4]);
        self.cursor += 4;
        let value = f32::from_bits(u32::from_be_bytes(bits));
        if value.is_nan() {
            return Err(CborError::NonCanonicalFloat);
        }
        if value.is_sign_negative() && value == 0.0 {
            return Err(CborError::NonCanonicalFloat);
        }
        if super::encode::f16_bits_to_f64(super::encode::f32_bits_to_f16(value.to_bits()))
            == value as f64
        {
            return Err(CborError::NonCanonicalFloat);
        }
        Ok(value as f64)
    }

    fn read_f64(&mut self) -> Result<f64, CborError> {
        if self.cursor + 8 > self.input.len() {
            return Err(CborError::UnexpectedEof);
        }
        let mut bits = [0u8; 8];
        bits.copy_from_slice(&self.input[self.cursor..self.cursor + 8]);
        self.cursor += 8;
        let value = f64::from_bits(u64::from_be_bytes(bits));
        if value.is_nan() {
            return Err(CborError::NonCanonicalFloat);
        }
        if value.is_sign_negative() && value == 0.0 {
            return Err(CborError::NonCanonicalFloat);
        }
        if value as f32 as f64 == value {
            return Err(CborError::NonCanonicalFloat);
        }
        Ok(value)
    }
}

/// Converts one borrowed item into an owned [`crate::cbor::CborValue`].
pub fn item_to_owned(item: Item<'_>) -> Result<crate::cbor::CborValue, CborError> {
    Ok(match item {
        Item::Unsigned(v) => crate::cbor::CborValue::Unsigned(v),
        Item::Negative(v) => crate::cbor::CborValue::Negative(v),
        Item::Bytes(b) => crate::cbor::CborValue::Bytes(b.to_vec()),
        Item::Text(t) => crate::cbor::CborValue::Text(t.to_string()),
        Item::Array(_) | Item::Map(_) => {
            return Err(CborError::UnsupportedType(0));
        }
        Item::Bool(b) => crate::cbor::CborValue::Bool(b),
        Item::Null => crate::cbor::CborValue::Null,
        Item::Float(f) => crate::cbor::CborValue::Float(f),
    })
}
