//! Bounded canonical CBOR value for Outcome, Assert, InputStep, and StepEnd.
//!
//! Canonical RFC 8949 Core Deterministic CBOR: bounded depth, item count,
//! and string size, sorted unique map keys, no NaN or negative zero.

use alloc::string::String;
use alloc::vec::Vec;

use crate::cbor::{self, CborError, CborValue, compare_canonical_keys};
use crate::limits::{
    MAX_CANONICAL_VALUE_DEPTH, MAX_CANONICAL_VALUE_ITEMS, MAX_CANONICAL_VALUE_STRING_BYTES,
};

/// Bounded canonical CBOR value.
#[derive(Debug, Clone, PartialEq)]
pub enum CanonicalValue {
    Unsigned(u64),
    Negative(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CanonicalValue>),
    /// Map entries in canonical-key order.
    Map(Vec<(CanonicalValue, CanonicalValue)>),
    Bool(bool),
    Null,
    /// Never NaN or -0.0.
    Float(f64),
}

impl Eq for CanonicalValue {}

/// Canonical-value validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueError {
    BoundsExceeded(&'static str),
    Cbor(CborError),
}

impl From<CborError> for ValueError {
    fn from(err: CborError) -> Self {
        Self::Cbor(err)
    }
}

impl core::fmt::Display for ValueError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BoundsExceeded(msg) => write!(f, "canonical value bounds exceeded: {msg}"),
            Self::Cbor(err) => write!(f, "canonical CBOR error: {err}"),
        }
    }
}

impl core::error::Error for ValueError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::BoundsExceeded(_) => None,
            Self::Cbor(err) => Some(err),
        }
    }
}

impl CanonicalValue {
    /// Encodes the value as canonical CBOR into `out`.
    ///
    /// On error the buffer may hold partial bytes; discard the tail.
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
                // Sort by encoded key bytes; values encode after sorting
                // so item accounting stays on the shared budget.
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
    /// Rejects non-canonical encodings, out-of-bounds values, trailing bytes.
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
