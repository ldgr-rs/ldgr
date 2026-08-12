#![deny(unsafe_code)]
#![allow(missing_docs)]

//! Forbidden ambient API scanner for deterministic simulation boundaries.

pub mod scanner;
pub use scanner::{
    ALLOW_MARKER, FORBIDDEN_PATTERNS, LintViolation, ScanResult, scan_rs_files, scan_source,
};
