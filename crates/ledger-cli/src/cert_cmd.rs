// ledger-lint:allow (host application; certificate verification reads files on disk)
//! `ledger cert verify` command.

use std::io::Read;
use std::path::Path;

use ledger_explorer::certs::{CERT_MAX_BYTES, CertError, check_cert_bytes};
use ledger_explorer::search::PersistentJournal;
use ledger_explorer::services::ServiceError;
use ledger_explorer::services::{
    parse_statement, validate_cut_against_journal, validate_statement,
};

/// Errors from `ledger cert verify`.
#[derive(Debug, thiserror::Error)]
pub enum CertVerifyError {
    /// The certificate file could not be read.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The JSON did not parse into a certificate.
    #[error(transparent)]
    Decode(CertError),
    /// The persistent journal could not be opened.
    #[error("journal open: {0}")]
    JournalOpen(#[from] ledger_journal::JournalError),
    /// Statement validation or journal binding failed.
    #[error(transparent)]
    Verification(CertError),
    /// JSON serialization failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Maps a statement service failure onto the command error, keeping the
/// decode-versus-validation distinction the CLI surfaces.
fn to_verify_error(error: ServiceError) -> CertVerifyError {
    match error {
        ServiceError::Cert(err) => match &err {
            CertError::Verification(_) => CertVerifyError::Verification(err),
            _ => CertVerifyError::Decode(err),
        },
        ServiceError::Journal(err) => CertVerifyError::JournalOpen(err),
        other => CertVerifyError::Decode(CertError::Schema(format!(
            "unexpected service failure: {other}"
        ))),
    }
}

/// Verifies a campaign certificate JSON file.
///
/// Reads `path` through a bounded reader, validates the statement, and
/// optionally binds it to a journal.
///
/// # Errors
/// Returns [`CertVerifyError`] when the file cannot be read, parsed, validated,
/// or bound to the supplied journal.
pub fn run_verify(
    path: &Path,
    journal: Option<&Path>,
    json: bool,
) -> Result<String, CertVerifyError> {
    let file = std::fs::File::open(path).map_err(CertVerifyError::Io)?;
    let mut raw = String::new();
    let mut limited = file.take((CERT_MAX_BYTES + 1) as u64);
    limited
        .read_to_string(&mut raw)
        .map_err(CertVerifyError::Io)?;
    check_cert_bytes(raw.len()).map_err(CertVerifyError::Decode)?;
    let cert = parse_statement(&raw).map_err(to_verify_error)?;
    let mode_label = if let Some(journal_dir) = journal {
        let persistent =
            PersistentJournal::open(journal_dir).map_err(CertVerifyError::JournalOpen)?;
        validate_cut_against_journal(&cert, persistent.journal()).map_err(to_verify_error)?;
        "journal-bound"
    } else {
        validate_statement(&cert).map_err(to_verify_error)?;
        "statement-validated"
    };

    if json {
        let value = serde_json::json!({
            "valid": true,
            "mode": mode_label,
            "subject": {
                "name": cert.subject.name,
                "digest": ledger_format::hash_to_hex(&cert.subject.digest)
            },
            "predicate_type": cert.predicate_type,
            "runs_executed": cert.runs_executed,
            "findings_count": cert.findings_count,
            "solver_data": cert.solver_data.as_ref().map(|entry| serde_json::json!({
                "cut": entry.cut.iter().map(ledger_format::hash_to_hex).collect::<Vec<_>>(),
                "recorded_lower_bound": entry.recorded_lower_bound,
                "method": entry.method,
                "horizon": entry.horizon
            })).unwrap_or(serde_json::Value::Null),
            "statistical": cert.statistical.as_ref().map(|entry| serde_json::json!({
                "upper_p": entry.upper_p,
                "confidence": entry.confidence,
                "method": entry.method
            })).unwrap_or(serde_json::Value::Null)
        });
        serde_json::to_string(&value).map_err(CertVerifyError::Json)
    } else {
        let mut out = String::new();
        out.push_str("certificate valid\n");
        out.push_str(&format!("mode: {mode_label}\n"));
        out.push_str(&format!(
            "subject digest: {}\n",
            ledger_format::hash_to_hex(&cert.subject.digest)
        ));
        out.push_str(&format!("subject name: {}\n", cert.subject.name));
        out.push_str(&format!("predicate type: {}\n", cert.predicate_type));
        out.push_str(&format!("runs: {}\n", cert.runs_executed));
        out.push_str(&format!("findings: {}\n", cert.findings_count));
        match &cert.solver_data {
            Some(entry) => {
                out.push_str(&format!(
                    "solver data: cut={} recorded_lower_bound={} method={} horizon={:?}\n",
                    entry.cut.len(),
                    entry.recorded_lower_bound,
                    entry.method,
                    entry.horizon
                ));
            }
            None => out.push_str("solver data: none\n"),
        }
        match &cert.statistical {
            Some(entry) => {
                out.push_str(&format!(
                    "statistical: upper_p={} confidence={} method={}\n",
                    entry.upper_p, entry.confidence, entry.method
                ));
            }
            None => out.push_str("statistical: none\n"),
        }
        // Trim trailing newline for consistent output.
        if out.ends_with('\n') {
            out.pop();
        }
        Ok(out)
    }
}
