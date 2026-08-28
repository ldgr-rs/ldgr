// ledger-lint:allow (host application; coverage export reads files on disk)
//! `ledger coverage` export command.
//!
//! Input is NDJSON of `{root_hex, run_index, finding}` lines produced by
//! campaigns. Each line is a JSON object with those three fields. The header
//! may include comment lines starting with `#` which are ignored.
//! The command builds a [`CoverageReport`] via [`CoverageBuilder`] and
//! exports to lcov, SARIF, or JaCoCo.

use std::path::Path;

use ledger_explorer::{CovError, CoverageBuilder};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct NdjsonRecord {
    root_hex: String,
    run_index: usize,
    finding: bool,
}

/// Errors from `ledger coverage`.
#[derive(Debug)]
pub enum CoverageCmdError {
    /// The NDJSON input could not be read.
    Io(std::io::Error),
    /// A record line did not parse.
    Parse {
        line: usize,
        source: serde_json::Error,
    },
    /// A `root_hex` field was not a 64-char hex hash.
    Hex {
        line: usize,
        source: ledger_format::HexError,
    },
    /// The requested export format is not supported.
    UnknownFormat(String),
    /// The exporter rejected the report.
    Export(CovError),
}

impl std::fmt::Display for CoverageCmdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "io: {error}"),
            Self::Parse { line, source } => write!(f, "parse line {line}: {source}"),
            Self::Hex { line, source } => write!(f, "line {line} root_hex: {source}"),
            Self::UnknownFormat(format) => {
                write!(
                    f,
                    "unknown format '{format}': expected lcov, sarif, or jacoco"
                )
            }
            Self::Export(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for CoverageCmdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Parse { source, .. } => Some(source),
            Self::Hex { source, .. } => Some(source),
            Self::Export(error) => Some(error),
            Self::UnknownFormat(_) => None,
        }
    }
}

/// Run the coverage export for `input` NDJSON and return the rendered output.
///
/// `format` is one of `lcov`, `sarif`, or `jacoco` (case insensitive).
///
/// # Errors
/// Returns [`CoverageCmdError`] when the input cannot be read, parsed, or
/// exported.
pub fn run(input: &Path, format: &str) -> Result<String, CoverageCmdError> {
    let raw = std::fs::read_to_string(input).map_err(CoverageCmdError::Io)?;
    let mut builder = CoverageBuilder::new();
    let mut max_index: Option<usize> = None;
    for (line_number, line) in raw
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line))
    {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parsed: NdjsonRecord =
            serde_json::from_str(trimmed).map_err(|source| CoverageCmdError::Parse {
                line: line_number,
                source,
            })?;
        // Validate hex and normalise to lowercase.
        let bytes = ledger_format::hash_from_hex(&parsed.root_hex).map_err(|source| {
            CoverageCmdError::Hex {
                line: line_number,
                source,
            }
        })?;
        let normalized = ledger_format::hash_to_hex(&bytes);
        builder
            .record_hex(normalized, parsed.run_index, parsed.finding)
            .map_err(CoverageCmdError::Export)?;
        max_index =
            Some(max_index.map_or(parsed.run_index, |current| current.max(parsed.run_index)));
    }
    let total_runs = max_index.map_or(0, |index| index + 1).max(builder.len());
    let report = builder.finish(total_runs);
    let format_lower = format.to_ascii_lowercase();
    match format_lower.as_str() {
        "lcov" => Ok(ledger_explorer::to_lcov(&report)),
        "sarif" => ledger_explorer::to_sarif(&report).map_err(CoverageCmdError::Export),
        "jacoco" => ledger_explorer::to_jacoco(&report).map_err(CoverageCmdError::Export),
        other => Err(CoverageCmdError::UnknownFormat(other.to_string())),
    }
}
