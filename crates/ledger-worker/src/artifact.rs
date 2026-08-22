//! Artifact publication client for the control plane.
//!
//! After a task finishes, the worker publishes a certificate artifact
//! (`certificate.json`) through an [`ArtifactSink`]. Publication is
//! best-effort: a sink error is logged and never fails the task. [`NoopSink`]
//! is the default and only logs; [`HttpSink`] is
//! compiled behind the `control-plane` feature and talks GetUploadURL /
//! ConfirmUpload against the R2-backed control plane. The feature pulls the
//! optional `reqwest` dependency and needs network access at build time, so
//! offline builds stay on the default (noop) path.

use std::fmt;

use ledger_format::Hash;
use thiserror::Error;

/// Publication stage of an [`ArtifactError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Presigned upload-url request.
    UrlFetch,
    /// Raw artifact byte transfer.
    Upload,
    /// Upload confirmation call.
    Confirm,
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UrlFetch => write!(f, "upload-url fetch"),
            Self::Upload => write!(f, "artifact upload"),
            Self::Confirm => write!(f, "upload confirmation"),
        }
    }
}

/// Errors from artifact publication.
#[derive(Debug, Error)]
pub enum ArtifactError {
    /// The control-plane HTTP exchange failed (transport or status).
    #[cfg(feature = "control-plane")]
    #[error("{phase} failed: {source}")]
    Http {
        phase: Phase,
        #[source]
        source: reqwest::Error,
    },
    /// The response was decodable but violated the wire contract.
    #[error("{0} response invalid: {1}")]
    Contract(Phase, &'static str),
}

/// Destination for task artifacts (certificates, journals).
///
/// The three operations mirror the `ledger.control.v1` wire contract:
/// GetUploadURL, byte transfer, ConfirmUpload.
pub trait ArtifactSink: Send + Sync {
    /// Request a presigned upload URL for `task_id`/`name`.
    ///
    /// # Errors
    /// Returns [`ArtifactError`] when the control plane rejects the request.
    fn get_upload_url(&self, task_id: &str, name: &str) -> Result<String, ArtifactError>;

    /// Tell the control plane the artifact bytes are stored under
    /// `checksum_hex`.
    ///
    /// # Errors
    /// Returns [`ArtifactError`] when confirmation is rejected.
    fn confirm(&self, task_id: &str, name: &str, checksum_hex: &str) -> Result<(), ArtifactError>;

    /// Transfer `bytes` and confirm them. Returns the stored URL.
    ///
    /// # Errors
    /// Returns [`ArtifactError`] when any stage fails.
    fn upload(
        &self,
        task_id: &str,
        name: &str,
        bytes: &[u8],
        checksum_hex: &str,
    ) -> Result<String, ArtifactError>;
}

/// Default no-op destination: logs and reports a synthetic URL.
///
/// Keeps standalone runs fully local; nothing leaves the process.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopSink;

impl ArtifactSink for NoopSink {
    fn get_upload_url(&self, task_id: &str, name: &str) -> Result<String, ArtifactError> {
        let url = format!("noop://{task_id}/{name}");
        eprintln!("ledger-worker: artifact sink noop, would upload {name} for {task_id}");
        Ok(url)
    }

    fn confirm(&self, _task_id: &str, name: &str, checksum_hex: &str) -> Result<(), ArtifactError> {
        eprintln!("ledger-worker: artifact sink noop, would confirm {name} ({checksum_hex})");
        Ok(())
    }

    fn upload(
        &self,
        task_id: &str,
        name: &str,
        _bytes: &[u8],
        checksum_hex: &str,
    ) -> Result<String, ArtifactError> {
        let url = self.get_upload_url(task_id, name)?;
        self.confirm(task_id, name, checksum_hex)?;
        Ok(url)
    }
}

/// Real HTTP destination behind the `control-plane` feature.
///
/// Expects a control plane exposing:
/// - `GET {base}/tasks/{task_id}/artifacts/{name}/upload-url` returning
///   `{"url": "...", "method": "PUT"}`,
/// - the returned presigned URL accepting the raw bytes,
/// - `POST {base}/tasks/{task_id}/artifacts/{name}/confirm` accepting a
///   `ConfirmUpload`-shaped JSON body.
#[cfg(feature = "control-plane")]
pub struct HttpSink {
    base_url: String,
    token: Option<String>,
    client: reqwest::blocking::Client,
}

#[cfg(feature = "control-plane")]
impl HttpSink {
    /// Build a sink for `base_url`, optionally sending `Authorization:
    /// Bearer <token>`.
    ///
    /// # Panics
    /// Panics when the TLS backend cannot initialize (reqwest builder
    /// contract); this is a startup-time failure, not per-task.
    pub fn new(base_url: impl Into<String>, token: Option<String>) -> Self {
        Self {
            base_url: base_url.into(),
            token,
            client: reqwest::blocking::Client::new(),
        }
    }

    fn get(&self, path: &str) -> Result<reqwest::blocking::Response, ArtifactError> {
        let url = format!("{}{path}", self.base_url);
        let mut req = self.client.get(&url);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        req.send()
            .and_then(|res| res.error_for_status())
            .map_err(|source| ArtifactError::Http {
                phase: Phase::UrlFetch,
                source,
            })
    }
}

#[cfg(feature = "control-plane")]
impl ArtifactSink for HttpSink {
    fn get_upload_url(&self, task_id: &str, name: &str) -> Result<String, ArtifactError> {
        let path = format!("/tasks/{task_id}/artifacts/{name}/upload-url");
        // Body decode failures surface as reqwest::Error too.
        let body: serde_json::Value =
            self.get(&path)?
                .json::<serde_json::Value>()
                .map_err(|source| ArtifactError::Http {
                    phase: Phase::UrlFetch,
                    source,
                })?;
        body.get("url")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or(ArtifactError::Contract(
                Phase::UrlFetch,
                "response missing url",
            ))
    }

    fn confirm(&self, task_id: &str, name: &str, checksum_hex: &str) -> Result<(), ArtifactError> {
        let wire = serde_json::json!({
            "task_id": task_id,
            "artifact_name": name,
            "checksum_hex": checksum_hex,
        });
        let url = format!("{}/tasks/{task_id}/artifacts/{name}/confirm", self.base_url);
        let mut req = self.client.post(&url).json(&wire);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        req.send()
            .and_then(|res| res.error_for_status())
            .map(|_| ())
            .map_err(|source| ArtifactError::Http {
                phase: Phase::Confirm,
                source,
            })
    }

    fn upload(
        &self,
        task_id: &str,
        name: &str,
        bytes: &[u8],
        checksum_hex: &str,
    ) -> Result<String, ArtifactError> {
        let url = self.get_upload_url(task_id, name)?;
        self.client
            .put(&url)
            .body(bytes.to_vec())
            .send()
            .and_then(|res| res.error_for_status())
            .map_err(|source| ArtifactError::Http {
                phase: Phase::Upload,
                source,
            })?;
        self.confirm(task_id, name, checksum_hex)?;
        Ok(url)
    }
}

/// BLAKE3 digest of `bytes` as 64-char lowercase hex.
pub fn checksum_hex(bytes: &[u8]) -> String {
    let hash = blake3::hash(bytes);
    ledger_format::hash_to_hex(hash.as_bytes())
}

/// Builder id used by the worker daemon and drain paths.
pub const WORKER_BUILDER_ID: &str = "ledger-worker";

/// Render the minimal task certificate as JSON bytes.
///
/// Full [`ledger_explorer::certs::CampaignCertificate`] statements need the
/// complete campaign report; the minimal certificate attests the journal
/// root as subject and carries the campaign findings count in the predicate.
///
/// When `builder_id` is set the statement gains
/// `predicate.runDetails.builder.id`; when `profile_fingerprint_hex8` is set
/// it gains `predicate.extensions.runtimeProfile`, binding the certificate
/// to the runtime profile that produced the run. Both fields are omitted
/// otherwise.
///
/// # Errors
/// Returns the serialization error when JSON rendering fails.
pub fn certificate_json(
    task_id: &str,
    journal_root: &Hash,
    steps: usize,
    campaign_findings: usize,
    builder_id: Option<&str>,
    profile_fingerprint_hex8: Option<&str>,
) -> Result<Vec<u8>, serde_json::Error> {
    let root_hex = ledger_format::hash_to_hex(journal_root);
    let mut stmt = serde_json::json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "journal-root", "digest": {"blake3": root_hex}}],
        "predicateType": ledger_explorer::attest_uri::predicate_type_task_v1(),
        "predicate": {
            "task": {"id": task_id, "steps": steps},
            "campaign": {"findings": campaign_findings},
        },
    });
    if let Some(builder) = builder_id {
        stmt["predicate"]["runDetails"]["builder"]["id"] =
            serde_json::Value::String(builder.to_string());
    }
    if let Some(profile) = profile_fingerprint_hex8 {
        stmt["predicate"]["extensions"]["runtimeProfile"] =
            serde_json::Value::String(profile.to_string());
    }
    serde_json::to_vec(&stmt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_is_deterministic_blake3_hex() {
        let first = checksum_hex(b"abc");
        let second = checksum_hex(b"abc");
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(
            first
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        let expected = blake3::hash(b"abc")
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(first, expected);
        assert_ne!(checksum_hex(b"abd"), first);
    }

    #[test]
    fn noop_sink_returns_task_scoped_url() {
        let sink = NoopSink;
        let url = sink.get_upload_url("task-7", "certificate.json").unwrap();
        assert!(url.contains("task-7"));
        assert!(url.contains("certificate.json"));
        assert!(sink.confirm("task-7", "certificate.json", "ab").is_ok());
        let bytes = b"payload";
        let uploaded = sink
            .upload("task-7", "certificate.json", bytes, &checksum_hex(bytes))
            .unwrap();
        assert!(uploaded.contains("task-7"));
    }

    #[test]
    fn certificate_json_attests_journal_root() {
        let root: Hash = [9u8; 32];
        let bytes = certificate_json("task-1", &root, 12, 0, None, None).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["_type"], "https://in-toto.io/Statement/v1");
        let digest = value["subject"][0]["digest"]["blake3"].as_str().unwrap();
        assert_eq!(digest.len(), 64);
        assert_eq!(value["predicate"]["task"]["steps"], 12);
        assert_eq!(value["predicate"]["campaign"]["findings"], 0);
        // Deterministic render: same inputs, same bytes.
        assert_eq!(
            certificate_json("task-1", &root, 12, 0, None, None).unwrap(),
            bytes
        );
        // Non-zero findings travel into the predicate.
        let flagged = certificate_json("task-1", &root, 12, 3, None, None).unwrap();
        let flagged_value: serde_json::Value = serde_json::from_slice(&flagged).unwrap();
        assert_eq!(flagged_value["predicate"]["campaign"]["findings"], 3);
    }

    #[test]
    fn certificate_json_binds_builder_and_profile_when_present() {
        let root: Hash = [1u8; 32];
        let bytes = certificate_json(
            "task-2",
            &root,
            7,
            0,
            Some(WORKER_BUILDER_ID),
            Some("deadbeef"),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            value["predicate"]["runDetails"]["builder"]["id"],
            WORKER_BUILDER_ID
        );
        assert_eq!(
            value["predicate"]["extensions"]["runtimeProfile"],
            "deadbeef"
        );
        // Deterministic render with the optional fields set.
        assert_eq!(
            certificate_json(
                "task-2",
                &root,
                7,
                0,
                Some(WORKER_BUILDER_ID),
                Some("deadbeef"),
            )
            .unwrap(),
            bytes
        );
    }

    #[test]
    fn certificate_json_omits_builder_and_profile_when_absent() {
        let root: Hash = [2u8; 32];
        let bytes = certificate_json("task-3", &root, 5, 0, None, None).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let predicate = value["predicate"].as_object().unwrap();
        assert!(!predicate.contains_key("runDetails"));
        assert!(!predicate.contains_key("extensions"));
        // Profile alone binds only the extension; no builder id appears.
        let profile_only = certificate_json("task-3", &root, 5, 0, None, Some("cafe1234")).unwrap();
        let profile_value: serde_json::Value = serde_json::from_slice(&profile_only).unwrap();
        assert_eq!(
            profile_value["predicate"]["extensions"]["runtimeProfile"],
            "cafe1234"
        );
        assert!(profile_value["predicate"].get("runDetails").is_none());
    }
}
