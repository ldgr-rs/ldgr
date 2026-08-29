//! Bounded canonical CBOR value used by Outcome, Assert, InputStep, and
//! StepEnd payloads.
//!
//! `CanonicalValue` is canonical RFC 8949 Core Deterministic CBOR with
//! nesting at most [`MAX_CANONICAL_VALUE_DEPTH`], at most
//! [`MAX_CANONICAL_VALUE_ITEMS`] collection items in total, text or byte
//! strings at most [`MAX_CANONICAL_VALUE_STRING_BYTES`], sorted unique map
//! keys, and no floating-point NaN or negative zero. Each domain that uses
//! a payload carrying a `CanonicalValue` defines and binds its schema digest
//! in `ExecutionIdentity`.

use alloc::string::String;
use alloc::vec::Vec;

use crate::cbor::{self, CborError, CborValue, compare_canonical_keys};
use crate::limits::{
    MAX_CANONICAL_VALUE_DEPTH, MAX_CANONICAL_VALUE_ITEMS, MAX_CANONICAL_VALUE_STRING_BYTES,
};

/// Bounded canonical CBOR value.
#[derive(Debug, Clone, PartialEq)]
pub enum CanonicalValue {
    /// Unsigned integer.
    Unsigned(u64),
    /// Negative integer (-1 - n).
    Negative(u64),
    /// Byte string.
    Bytes(Vec<u8>),
    /// UTF-8 text string.
    Text(String),
    /// Array of values.
    Array(Vec<CanonicalValue>),
    /// Map of canonical-key-sorted entries.
    Map(Vec<(CanonicalValue, CanonicalValue)>),
    /// Boolean.
    Bool(bool),
    /// Null.
    Null,
    /// IEEE 754 float, never NaN or -0.0.
    Float(f64),
}

impl Eq for CanonicalValue {}

/// Canonical-value validation failures beyond the CBOR codec errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueError {
    /// The value exceeds a canonical-value bound.
    BoundsExceeded(&'static str),
    /// The underlying CBOR is not canonical.
    Cbor(CborError),
}

impl From<CborError> for ValueError {
    fn from(err: CborError) -> Self {
        Self::Cbor(err)
    }
}

impl CanonicalValue {
    /// Encodes the value as canonical CBOR into `out`.
    ///
    /// Fails when a bound is exceeded; on error the buffer may contain
    /// partial bytes and the caller must discard the tail.
    pub fn try_encode(&self, out: &mut Vec<u8>) -> Result<(), ValueError> {
        let mut budget = Budget::default();
        self.encode_into(out, &mut budget)
    }

    fn encode_into(&self, out: &mut Vec<u8>, budget: &mut Budget) -> Result<(), ValueError> {
        budget.visit()?;
        match self {
            Self::Unsigned(v) => {
                cbor::unsigned(out, *v);
                Ok(())
            }
            Self::Negative(v) => {
                major(out, 1, *v);
                Ok(())
            }
            Self::Bytes(b) => {
                budget.string(b.len())?;
                cbor::bytes(out, b);
                Ok(())
            }
            Self::Text(s) => {
                budget.string(s.len())?;
                cbor::text(out, s);
                Ok(())
            }
            Self::Array(items) => {
                budget.collection(items.len())?;
                cbor::array(out, items.len());
                for item in items {
                    item.encode_into(out, budget)?;
                }
                Ok(())
            }
            Self::Map(entries) => {
                budget.collection(entries.len())?;
                // Canonical key ordering requires the encoded key bytes; the
                // values are encoded after the sorted keys so item accounting
                // stays on the shared budget.
                let mut encoded_keys: Vec<(Vec<u8>, &CanonicalValue)> =
                    Vec::with_capacity(entries.len());
                for (key, value) in entries {
                    let mut key_bytes = Vec::new();
                    key.encode_into(&mut key_bytes, budget)?;
                    encoded_keys.push((key_bytes, value));
                }
                for i in 0..encoded_keys.len() {
                    for j in (i + 1)..encoded_keys.len() {
                        if encoded_keys[i].0 == encoded_keys[j].0 {
                            return Err(ValueError::BoundsExceeded("duplicate map key"));
                        }
                    }
                }
                encoded_keys.sort_by(|a, b| compare_canonical_keys(&a.0, &b.0));
                cbor::map(out, encoded_keys.len());
                for (key_bytes, value) in encoded_keys {
                    out.extend_from_slice(&key_bytes);
                    value.encode_into(out, budget)?;
                }
                Ok(())
            }
            Self::Bool(b) => {
                cbor::boolean(out, *b);
                Ok(())
            }
            Self::Null => {
                cbor::null(out);
                Ok(())
            }
            Self::Float(value) => {
                if value.is_nan() || (value.is_sign_negative() && *value == 0.0) {
                    return Err(ValueError::BoundsExceeded(
                        "floats must not be NaN or negative zero",
                    ));
                }
                cbor::encode_minimal_float(out, *value);
                Ok(())
            }
        }
    }

    /// Returns the canonical serialized bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ValueError> {
        let mut out = Vec::new();
        self.try_encode(&mut out)?;
        Ok(out)
    }

    /// Decodes a canonical value from canonical CBOR bytes.
    ///
    /// Rejects non-canonical encodings, values exceeding the bounds, and
    /// trailing bytes.
    pub fn from_canonical_bytes(input: &[u8]) -> Result<Self, ValueError> {
        let value = CborValue::from_canonical_bytes(input)?;
        let mut budget = Budget::default();
        let parsed = Self::from_cbor(&value, &mut budget)?;
        // from_canonical_bytes already rejected trailing bytes.
        Ok(parsed)
    }

    fn from_cbor(value: &CborValue, budget: &mut Budget) -> Result<Self, ValueError> {
        budget.visit()?;
        match value {
            CborValue::Unsigned(v) => Ok(Self::Unsigned(*v)),
            CborValue::Negative(v) => Ok(Self::Negative(*v)),
            CborValue::Bytes(b) => {
                budget.string(b.len())?;
                Ok(Self::Bytes(b.clone()))
            }
            CborValue::Text(s) => {
                budget.string(s.len())?;
                Ok(Self::Text(s.clone()))
            }
            CborValue::Array(items) => {
                budget.collection(items.len())?;
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(Self::from_cbor(item, budget)?);
                }
                Ok(Self::Array(out))
            }
            CborValue::Map(entries) => {
                budget.collection(entries.len())?;
                let mut out = Vec::with_capacity(entries.len());
                for (key, val) in entries {
                    out.push((Self::from_cbor(key, budget)?, Self::from_cbor(val, budget)?));
                }
                Ok(Self::Map(out))
            }
            CborValue::Bool(b) => Ok(Self::Bool(*b)),
            CborValue::Null => Ok(Self::Null),
            CborValue::Float(f) => {
                if f.is_nan() || (f.is_sign_negative() && *f == 0.0) {
                    return Err(ValueError::BoundsExceeded(
                        "floats must not be NaN or negative zero",
                    ));
                }
                Ok(Self::Float(*f))
            }
            CborValue::Tag(..) => Err(ValueError::BoundsExceeded(
                "canonical values must not carry semantic tags",
            )),
        }
    }
}

/// Tracks canonical-value bounds during encode and decode.
#[derive(Debug, Default)]
pub(crate) struct Budget {
    depth: usize,
    items: usize,
}

impl Budget {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn visit(&mut self) -> Result<(), ValueError> {
        self.depth += 1;
        if self.depth > MAX_CANONICAL_VALUE_DEPTH {
            return Err(ValueError::BoundsExceeded("nesting depth"));
        }
        self.items += 1;
        if self.items > MAX_CANONICAL_VALUE_ITEMS {
            return Err(ValueError::BoundsExceeded("collection item count"));
        }
        Ok(())
    }

    pub(crate) fn collection(&mut self, len: usize) -> Result<(), ValueError> {
        self.items += len;
        if self.items > MAX_CANONICAL_VALUE_ITEMS {
            return Err(ValueError::BoundsExceeded("collection item count"));
        }
        Ok(())
    }

    pub(crate) fn string(&mut self, len: usize) -> Result<(), ValueError> {
        if len > MAX_CANONICAL_VALUE_STRING_BYTES {
            return Err(ValueError::BoundsExceeded("string size"));
        }
        Ok(())
    }
}

/// Appends a major-type item with the canonical minimal-width argument.
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
