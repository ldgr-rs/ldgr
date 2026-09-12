#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::redundant_clone,
        clippy::needless_collect
    )
)]
#![deny(unsafe_code)]
#![allow(missing_docs)]

//! Forbidden ambient API scanner for deterministic simulation boundaries.

pub mod scanner;
pub use scanner::{
    ALLOW_MARKER, FORBIDDEN_PATTERNS, LintViolation, ScanResult, scan_rs_files, scan_source,
    scan_warnings,
};
