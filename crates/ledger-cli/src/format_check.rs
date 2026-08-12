//! `ledger format --check` canonical-encoding verification.
// ledger-lint:allow (host application; format check reads files on disk,
//   unlike simulation code)

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

use ledger_format::TolerantReader;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatCheckOutcome {
    Canonical,
    /// Input parses but is not canonically encoded, or does not parse.
    NonCanonical {
        reason: String,
    },
}

/// Checks one buffer of bytes for canonical RFC 8949 Core Deterministic CBOR.
///
/// The tolerant reader never panics. The parsed value is re-encoded
/// canonically and compared byte-for-byte against the input.
pub fn check_bytes(bytes: &[u8]) -> FormatCheckOutcome {
    let value = match TolerantReader::new().parse(bytes) {
        Ok(value) => value,
        Err(error) => {
            return FormatCheckOutcome::NonCanonical {
                reason: format!("input is not valid CBOR: {error}"),
            };
        }
    };
    let canonical = match value.try_to_canonical_bytes() {
        Ok(bytes) => bytes,
        Err(error) => {
            return FormatCheckOutcome::NonCanonical {
                reason: format!("cannot canonically re-encode input: {error}"),
            };
        }
    };
    if canonical == bytes {
        FormatCheckOutcome::Canonical
    } else {
        let offset = first_differing_offset(bytes, &canonical);
        FormatCheckOutcome::NonCanonical {
            reason: format!(
                "input differs from canonical encoding at byte {offset} (input {} bytes, canonical {} bytes)",
                bytes.len(),
                canonical.len()
            ),
        }
    }
}

fn first_differing_offset(left: &[u8], right: &[u8]) -> usize {
    let common = left.len().min(right.len());
    (0..common)
        .find(|&index| left[index] != right[index])
        .unwrap_or(common)
}

pub fn check_file(path: &Path) -> Result<FormatCheckOutcome, FormatCheckError> {
    let bytes = fs::read(path).map_err(|error| FormatCheckError {
        path: path.to_path_buf(),
        source: error,
    })?;
    Ok(check_bytes(&bytes))
}

/// A read failure for `format --check`.
#[derive(Debug)]
pub struct FormatCheckError {
    path: std::path::PathBuf,
    source: io::Error,
}

impl fmt::Display for FormatCheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "cannot read {}: {}",
            self.path.display(),
            self.source
        )
    }
}

impl std::error::Error for FormatCheckError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
