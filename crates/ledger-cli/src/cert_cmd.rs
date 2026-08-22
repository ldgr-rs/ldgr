// ledger-lint:allow (host application; certificate verification reads files on disk)
//! `ledger cert verify` command.

use std::path::Path;

use ledger_explorer::{CampaignCertificate, CertError};

/// Errors from `ledger cert verify`.
#[derive(Debug)]
pub enum CertVerifyError {
    /// The certificate file could not be read.
    Io(std::io::Error),
    /// The JSON did not parse into a certificate; carries the `schema:`
    /// distinction from [`CertError`].
    Decode(CertError),
    /// The signature or statement failed verification.
    Verification(CertError),
    /// JSON serialization failed.
    Json(serde_json::Error),
}

impl std::fmt::Display for CertVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "io: {error}"),
            Self::Decode(error) | Self::Verification(error) => write!(f, "{error}"),
            Self::Json(error) => write!(f, "json: {error}"),
        }
    }
}

impl std::error::Error for CertVerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Decode(error) | Self::Verification(error) => Some(error),
            Self::Json(error) => Some(error),
        }
    }
}

/// Verifies a campaign certificate JSON file.
///
/// Reads `path`, parses it with `CampaignCertificate::from_json`, then
/// calls `verify`. On success returns human text when `json` is false or a
/// JSON object when `json` is true. On failure returns a
/// [`CertVerifyError`] that preserves the `schema:` vs `verification:`
/// distinction from `CertError`.
///
/// # Errors
/// Returns [`CertVerifyError`] when the file cannot be read, parsed, or
/// verified.
pub fn run_verify(path: &Path, json: bool) -> Result<String, CertVerifyError> {
    let raw = std::fs::read_to_string(path).map_err(CertVerifyError::Io)?;
    let cert = CampaignCertificate::from_json(&raw).map_err(CertVerifyError::Decode)?;
    cert.verify().map_err(CertVerifyError::Verification)?;

    if json {
        let value = serde_json::json!({
            "valid": true,
            "subject": {
                "name": cert.subject.name,
                "digest": ledger_format::hash_to_hex(&cert.subject.digest)
            },
            "predicate_type": cert.predicate_type,
            "runs_executed": cert.runs_executed,
            "findings_count": cert.findings_count,
            "minimality": cert.minimality.as_ref().map(|entry| serde_json::json!({
                "cut": entry.cut.iter().map(ledger_format::hash_to_hex).collect::<Vec<_>>(),
                "lower_bound": entry.lower_bound,
                "method": entry.method
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
        out.push_str(&format!(
            "subject digest: {}\n",
            ledger_format::hash_to_hex(&cert.subject.digest)
        ));
        out.push_str(&format!("subject name: {}\n", cert.subject.name));
        out.push_str(&format!("predicate type: {}\n", cert.predicate_type));
        out.push_str(&format!("runs: {}\n", cert.runs_executed));
        out.push_str(&format!("findings: {}\n", cert.findings_count));
        match &cert.minimality {
            Some(entry) => {
                out.push_str(&format!(
                    "minimality: cut={} lower_bound={} method={}\n",
                    entry.cut.len(),
                    entry.lower_bound,
                    entry.method
                ));
            }
            None => out.push_str("minimality: none\n"),
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
