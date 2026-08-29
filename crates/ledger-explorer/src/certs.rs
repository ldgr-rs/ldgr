// ledger-lint:allow:std::fs:: (host-side certificate emission; writes via std::fs, unlike simulation code)
use std::path::Path;

use crate::attest_uri::{build_type_campaign_v1, predicate_type_campaign_v1};
use crate::search::CampaignReport;
use crate::solver::{event_fault_cost, is_faultable};
use ledger_format::{EntryKind, Hash, Payload};
use ledger_journal::Journal;
use serde::{Deserialize, Serialize};
use thiserror::Error;

fn is_lineage_only_journal(journal: &Journal) -> bool {
    journal.entries().any(|entry| {
        entry.data.kind == EntryKind::Epoch
            && matches!(&entry.data.payload, Payload::Text(text) if text == "lineage-only")
    })
}

/// Reject lineage-only journals unless the caller explicitly allows them.
fn check_lineage_not_certifiable(journal: &Journal) -> Result<(), CertError> {
    if is_lineage_only_journal(journal) {
        return Err(CertError::Verification(
            "lineage-only journal cannot be certified".into(),
        ));
    }
    Ok(())
}

/// Maximum per-event fault cost of the solver's cost model.
///
/// The single cost table is [`crate::solver::event_fault_cost`]; per-kind
/// costs run 2..=5 and this constant is its maximum. Shared by `verify()` -
/// which has no journal, so it bounds a cut's summed event cost with this
/// maximum - and by gate tests that need the same cut-cost upper bound or a
/// tampered bound just above it.
pub const MAX_EVENT_COST: u64 = 5;

/// Maximum raw JSON statement size in bytes (1 MiB).
pub const CERT_MAX_BYTES: usize = 1024 * 1024;

/// Cap for `resolvedDependencies` entries in a parsed statement.
const MAX_RESOLVED_DEPENDENCIES: usize = 4096;

/// Cap for `cut` members in a parsed statement.
const MAX_CUT_MEMBERS: usize = 65536;

/// Cap for any certificate string, in bytes.
const MAX_STRING_BYTES: usize = 4096;

/// Maximum recorded solver horizon accepted by Wave 1.
const MAX_RECORDED_HORIZON: usize = 64;

/// Policy for lineage-only journals.
///
/// Strict rejects lineage-only journals, AllowLineage accepts them for
/// debugging or lineage export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineagePolicy {
    /// Reject lineage-only journals.
    Strict,
    /// Allow lineage-only journals.
    AllowLineage,
}

/// Check that `len` fits within the certificate byte limit.
///
/// Single source for the 1 MiB limit used by parsing, emission, and CLI
/// bounded readers.
pub fn check_cert_bytes(len: usize) -> Result<(), CertError> {
    if len > CERT_MAX_BYTES {
        return Err(CertError::Serialization(format!(
            "certificate file too large: {len} bytes exceeds {CERT_MAX_BYTES} byte limit"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    pub name: String,
    pub digest: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedDependency {
    pub name: String,
    pub digest: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedSolverData {
    pub cut: Vec<Hash>,
    /// Exact cut cost recomputed from the journal fault model at emission.
    pub cost: u64,
    pub method: String,
    /// Solver horizon recorded at emission time. `None` records an unbounded
    /// solver configuration. Inclusion-minimal validation refuses an
    /// unbounded configuration because it cannot bound the walk.
    pub horizon: Option<usize>,
    /// Support-provider version pinned at emission. Tampering with this value
    /// after the fact is rejected by support-aware validation.
    pub support_provider_version: Option<u64>,
    /// Violation witnesses the cut was derived against.
    pub witnesses: Vec<Hash>,
    /// Strict replay with the recorded cut applied reproduced the violation.
    pub reproduced: bool,
    /// The no-fault baseline rerun passed.
    pub baseline_passed: bool,
}

/// Journal-anchored validation result recorded in a statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JournalValidation {
    /// The statement bound to a journal: root matched and every cut member
    /// existed in that journal and was faultable.
    Bound,
}

/// Inclusion-minimal fault-cut validation result recorded when checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InclusionMinimal {
    /// No cut member is redundant: dropping any member loses hazard coverage.
    Minimal,
    /// At least one cut member is redundant.
    NotMinimal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatisticalBound {
    pub upper_p: f64,
    pub confidence: f64,
    pub method: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CampaignCertificate {
    pub subject: Subject,
    pub predicate_type: String,
    pub build_type: String,
    pub external_parameters_digest: Hash,
    pub resolved_dependencies: Vec<ResolvedDependency>,
    pub builder_id: String,
    pub runs_executed: usize,
    pub findings_count: usize,
    pub solver_data: Option<RecordedSolverData>,
    pub statistical: Option<StatisticalBound>,
    /// Result of journal-anchored validation when it has been run.
    pub journal_validation: Option<JournalValidation>,
    /// Result of bounded inclusion-minimal fault-cut validation when checked.
    pub inclusion_minimal: Option<InclusionMinimal>,
    /// Execution-identity digest of the run that produced this statement.
    ///
    /// `None` on certificates emitted without identity binding; the
    /// identity-aware journal verification ([`Self::verify_with_journal_and_identity`])
    /// treats a present-but-unmatched digest as a failure before any root
    /// comparison.
    pub execution_identity: Option<Hash>,
}

#[derive(Debug, Error)]
pub enum CertError {
    /// The certificate could not be serialized to JSON.
    #[error("serialization: {0}")]
    Serialization(String),
    /// The JSON document violated the certificate schema.
    #[error("schema: {0}")]
    Schema(String),
    /// Verification of the certificate against its attestation failed.
    #[error("verification: {0}")]
    Verification(String),
    /// The certificate file could not be created or written on disk.
    #[error("certificate io {operation} on {path}: {source}")]
    Io {
        /// The std operation that failed.
        operation: &'static str,
        /// Path passed to the failed operation.
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Shared lowercase-hex renderer for 32-byte hashes, used by certificate and
/// coverage emission.
pub(crate) fn hash_to_hex(hash: &Hash) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_to_hash(s: &str) -> Result<Hash, String> {
    if s.len() != 64 {
        return Err(format!("hash hex must be 64 chars, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

fn check_string_bytes(s: &str, field: &str) -> Result<(), CertError> {
    if s.len() > MAX_STRING_BYTES {
        return Err(CertError::Schema(format!(
            "{field} exceeds {MAX_STRING_BYTES} bytes"
        )));
    }
    Ok(())
}

fn check_emitted_json_size(bytes: usize) -> Result<(), CertError> {
    if bytes > CERT_MAX_BYTES {
        return Err(CertError::Serialization(format!(
            "certificate JSON is {bytes} bytes and exceeds {CERT_MAX_BYTES} bytes"
        )));
    }
    Ok(())
}

fn get_str<'a>(v: &'a serde_json::Value, k: &str) -> Result<&'a str, CertError> {
    let s = v
        .get(k)
        .and_then(|x| x.as_str())
        .ok_or_else(|| CertError::Schema(k.into()))?;
    check_string_bytes(s, k)?;
    Ok(s)
}

fn get_obj<'a>(v: &'a serde_json::Value, k: &str) -> Result<&'a serde_json::Value, CertError> {
    v.get(k).ok_or_else(|| CertError::Schema(k.into()))
}

fn get_arr<'a>(v: &'a serde_json::Value, k: &str) -> Result<&'a Vec<serde_json::Value>, CertError> {
    v.get(k)
        .and_then(|x| x.as_array())
        .ok_or_else(|| CertError::Schema(k.into()))
}

fn check_object_fields(
    value: &serde_json::Value,
    context: &str,
    required: &[&str],
    optional: &[&str],
) -> Result<(), CertError> {
    let object = value
        .as_object()
        .ok_or_else(|| CertError::Schema(format!("{context} must be an object")))?;
    for field in required {
        if !object.contains_key(*field) {
            return Err(CertError::Schema(format!(
                "{context} missing required field {field}"
            )));
        }
    }
    for field in object.keys() {
        if !required.contains(&field.as_str()) && !optional.contains(&field.as_str()) {
            return Err(CertError::Schema(format!(
                "{context} contains unknown field {field}"
            )));
        }
    }
    Ok(())
}

/// Reject duplicate cut members after count bounds have been checked.
fn check_cut_duplicates(cut: &[Hash]) -> Result<(), CertError> {
    let mut seen = std::collections::HashSet::with_capacity(cut.len());
    for id in cut {
        if !seen.insert(id) {
            return Err(CertError::Verification(format!(
                "duplicate cut member {:02x?}",
                &id[..4]
            )));
        }
    }
    Ok(())
}

/// Convert a raw u64 from JSON to usize with checked overflow.
/// On 64-bit `usize::try_from(u64::MAX)` succeeds, but a forged
/// `u64::MAX` must still be rejected as schema error so it never widens
/// traversal. Treat `u64::MAX` as overflow explicitly.
fn u64_to_usize_checked(raw: u64, field: &str) -> Result<usize, CertError> {
    if raw == u64::MAX {
        return Err(CertError::Schema(format!("{field} overflow")));
    }
    usize::try_from(raw).map_err(|_| CertError::Schema(format!("{field} overflow")))
}

impl CampaignCertificate {
    /// Create a certificate from a campaign report, rejecting lineage-only
    /// journals. Use [`Self::from_campaign_with`] to select a policy.
    ///
    /// # Errors
    /// Returns [`CertError`] when any finding journal is lineage-only, so a
    /// caller can never emit a certificate that attests more than the
    /// underlying evidence supports.
    pub fn from_campaign(
        report: &CampaignReport,
        builder_id: &str,
        deps: Vec<ResolvedDependency>,
        run_config_digest: Hash,
        execution_identity: Option<Hash>,
    ) -> Result<Self, CertError> {
        Self::from_campaign_with(
            report,
            builder_id,
            deps,
            run_config_digest,
            execution_identity,
            LineagePolicy::Strict,
        )
    }

    /// Create a certificate with an explicit lineage policy.
    pub fn from_campaign_with(
        report: &CampaignReport,
        builder_id: &str,
        deps: Vec<ResolvedDependency>,
        run_config_digest: Hash,
        execution_identity: Option<Hash>,
        policy: LineagePolicy,
    ) -> Result<Self, CertError> {
        if policy == LineagePolicy::Strict {
            for finding in &report.findings {
                check_lineage_not_certifiable(&finding.run.journal)?;
            }
        }
        Self::from_campaign_inner(
            report,
            builder_id,
            deps,
            run_config_digest,
            execution_identity,
        )
    }

    fn from_campaign_inner(
        report: &CampaignReport,
        builder_id: &str,
        deps: Vec<ResolvedDependency>,
        run_config_digest: Hash,
        execution_identity: Option<Hash>,
    ) -> Result<Self, CertError> {
        let subject = if let Some(f) = report.findings.first() {
            Subject {
                name: "journal-root".to_string(),
                digest: f.run.journal.root_hash(),
            }
        } else {
            Subject {
                name: "journal-root".to_string(),
                digest: [0u8; 32],
            }
        };
        let mut s = deps;
        s.sort_by(|a, b| a.name.cmp(&b.name));
        let statistical = if report.findings.is_empty() {
            Self::rule_of_three(report.runs_executed)
        } else {
            None
        };
        let certificate = Self {
            subject,
            predicate_type: predicate_type_campaign_v1(),
            build_type: build_type_campaign_v1(),
            external_parameters_digest: run_config_digest,
            resolved_dependencies: s,
            builder_id: builder_id.to_string(),
            runs_executed: report.runs_executed,
            findings_count: report.findings.len(),
            solver_data: None,
            statistical,
            journal_validation: None,
            inclusion_minimal: None,
            execution_identity,
        };
        certificate.verify()?;
        Ok(certificate)
    }

    pub fn rule_of_three(runs: usize) -> Option<StatisticalBound> {
        if runs == 0 {
            None
        } else {
            Some(StatisticalBound {
                upper_p: (3.0 / runs as f64).min(1.0),
                confidence: 0.95,
                method: "rule-of-three-v1".to_string(),
            })
        }
    }

    pub fn to_json(&self) -> Result<String, CertError> {
        let cut_count = self.solver_data.as_ref().map_or(0, |data| data.cut.len());
        let hash_count = 2usize
            .checked_add(self.resolved_dependencies.len())
            .and_then(|count| count.checked_add(cut_count))
            .ok_or_else(|| CertError::Serialization("certificate size overflow".into()))?;
        let mut structural_bytes = hash_count
            .checked_mul(64)
            .ok_or_else(|| CertError::Serialization("certificate size overflow".into()))?;
        for value in [
            self.subject.name.as_str(),
            self.predicate_type.as_str(),
            self.build_type.as_str(),
            self.builder_id.as_str(),
        ] {
            structural_bytes = structural_bytes
                .checked_add(value.len())
                .ok_or_else(|| CertError::Serialization("certificate size overflow".into()))?;
        }
        for dependency in &self.resolved_dependencies {
            structural_bytes = structural_bytes
                .checked_add(dependency.name.len())
                .ok_or_else(|| CertError::Serialization("certificate size overflow".into()))?;
        }
        if let Some(data) = &self.solver_data {
            structural_bytes = structural_bytes
                .checked_add(data.method.len())
                .ok_or_else(|| CertError::Serialization("certificate size overflow".into()))?;
        }
        if let Some(statistical) = &self.statistical {
            structural_bytes = structural_bytes
                .checked_add(statistical.method.len())
                .ok_or_else(|| CertError::Serialization("certificate size overflow".into()))?;
        }
        check_emitted_json_size(structural_bytes)?;

        let mut d = self.resolved_dependencies.clone();
        d.sort_by(|a, b| a.name.cmp(&b.name));
        let deps_json: Vec<serde_json::Value> = d
            .iter()
            .map(|x| serde_json::json!({"name":x.name,"digest":{"blake3":hash_to_hex(&x.digest)}}))
            .collect();
        let mut p = serde_json::json!({"buildDefinition":{"buildType":self.build_type,"externalParameters":{"runConfigDigest":hash_to_hex(&self.external_parameters_digest)},"resolvedDependencies":deps_json},"runDetails":{"builder":{"id":self.builder_id},"metadata":{"runsExecuted":self.runs_executed,"findingsCount":self.findings_count}}});
        if let Some(identity) = &self.execution_identity {
            p["buildDefinition"]["externalParameters"]["executionIdentity"] =
                serde_json::json!(hash_to_hex(identity));
        }
        if let Some(data) = &self.solver_data {
            let mut solver_json = serde_json::json!({"cut":data.cut.iter().map(hash_to_hex).collect::<Vec<_>>(),"cost":data.cost,"method":data.method,"reproduced":data.reproduced,"baselinePassed":data.baseline_passed});
            if let Some(horizon) = data.horizon {
                solver_json["horizon"] = serde_json::json!(horizon);
            }
            if let Some(version) = data.support_provider_version {
                solver_json["supportProviderVersion"] = serde_json::json!(version);
            }
            if !data.witnesses.is_empty() {
                solver_json["witnesses"] =
                    serde_json::json!(data.witnesses.iter().map(hash_to_hex).collect::<Vec<_>>());
            }
            p["solverData"] = solver_json;
        }
        if let Some(validation) = &self.journal_validation {
            let label = match validation {
                JournalValidation::Bound => "bound",
            };
            p["journalValidation"] = serde_json::json!(label);
        }
        if let Some(minimal) = &self.inclusion_minimal {
            let label = match minimal {
                InclusionMinimal::Minimal => true,
                InclusionMinimal::NotMinimal => false,
            };
            p["inclusionMinimal"] = serde_json::json!(label);
        }
        if let Some(s) = &self.statistical {
            p["statistical"] =
                serde_json::json!({"upperP":s.upper_p,"confidence":s.confidence,"method":s.method});
        }
        let stmt = serde_json::json!({"_type":"https://in-toto.io/Statement/v1","subject":[{"name":self.subject.name,"digest":{"blake3":hash_to_hex(&self.subject.digest)}}],"predicateType":self.predicate_type,"predicate":p});
        let json =
            serde_json::to_string(&stmt).map_err(|e| CertError::Serialization(e.to_string()))?;
        check_emitted_json_size(json.len())?;
        Ok(json)
    }

    pub fn from_json(s: &str) -> Result<Self, CertError> {
        if s.len() > CERT_MAX_BYTES {
            return Err(CertError::Schema(format!(
                "certificate JSON exceeds {CERT_MAX_BYTES} bytes"
            )));
        }
        let v: serde_json::Value =
            serde_json::from_str(s).map_err(|e| CertError::Schema(e.to_string()))?;
        check_object_fields(
            &v,
            "statement",
            &["_type", "subject", "predicateType", "predicate"],
            &[],
        )?;
        let type_str = get_str(&v, "_type")?;
        if type_str != "https://in-toto.io/Statement/v1" {
            return Err(CertError::Schema(
                "_type must be https://in-toto.io/Statement/v1".into(),
            ));
        }
        let subject_arr = get_arr(&v, "subject")?;
        if subject_arr.len() != 1 {
            return Err(CertError::Schema(
                "subject must contain exactly one entry".into(),
            ));
        }
        let subj = &subject_arr[0];
        check_object_fields(subj, "subject entry", &["name", "digest"], &[])?;
        let subject_digest = get_obj(subj, "digest")?;
        check_object_fields(subject_digest, "subject digest", &["blake3"], &[])?;
        let subject = Subject {
            name: get_str(subj, "name")?.to_string(),
            digest: hex_to_hash(get_str(subject_digest, "blake3")?).map_err(CertError::Schema)?,
        };
        let pt = get_str(&v, "predicateType")?.to_string();
        let pred = get_obj(&v, "predicate")?;
        check_object_fields(
            pred,
            "predicate",
            &["buildDefinition", "runDetails"],
            &[
                "solverData",
                "statistical",
                "journalValidation",
                "inclusionMinimal",
            ],
        )?;
        let bd = get_obj(pred, "buildDefinition")?;
        check_object_fields(
            bd,
            "buildDefinition",
            &["buildType", "externalParameters", "resolvedDependencies"],
            &[],
        )?;
        let bt = get_str(bd, "buildType")?.to_string();
        let external_parameters = get_obj(bd, "externalParameters")?;
        check_object_fields(
            external_parameters,
            "externalParameters",
            &["runConfigDigest"],
            &["executionIdentity"],
        )?;
        let run_digest = hex_to_hash(get_str(external_parameters, "runConfigDigest")?)
            .map_err(CertError::Schema)?;
        let execution_identity = match external_parameters.get("executionIdentity") {
            Some(value) => {
                let text = value
                    .as_str()
                    .ok_or_else(|| CertError::Schema("executionIdentity".into()))?;
                check_string_bytes(text, "executionIdentity")?;
                Some(hex_to_hash(text).map_err(CertError::Schema)?)
            }
            None => None,
        };
        let deps_arr = get_arr(bd, "resolvedDependencies")?;
        if deps_arr.len() > MAX_RESOLVED_DEPENDENCIES {
            return Err(CertError::Schema(format!(
                "resolvedDependencies exceeds {MAX_RESOLVED_DEPENDENCIES}"
            )));
        }
        let mut deps = Vec::new();
        for item in deps_arr {
            check_object_fields(item, "resolved dependency", &["name", "digest"], &[])?;
            let digest = get_obj(item, "digest")?;
            check_object_fields(digest, "resolved dependency digest", &["blake3"], &[])?;
            deps.push(ResolvedDependency {
                name: get_str(item, "name")?.to_string(),
                digest: hex_to_hash(get_str(digest, "blake3")?).map_err(CertError::Schema)?,
            });
        }
        deps.sort_by(|a, b| a.name.cmp(&b.name));
        let rd = get_obj(pred, "runDetails")?;
        check_object_fields(rd, "runDetails", &["builder", "metadata"], &[])?;
        let builder = get_obj(rd, "builder")?;
        check_object_fields(builder, "builder", &["id"], &[])?;
        let builder_id = get_str(builder, "id")?.to_string();
        let meta = get_obj(rd, "metadata")?;
        check_object_fields(meta, "metadata", &["runsExecuted", "findingsCount"], &[])?;
        let runs_executed_raw = meta
            .get("runsExecuted")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| CertError::Schema("runsExecuted".into()))?;
        let runs_executed = u64_to_usize_checked(runs_executed_raw, "runsExecuted")?;
        let findings_count_raw = meta
            .get("findingsCount")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| CertError::Schema("findingsCount".into()))?;
        let findings_count = u64_to_usize_checked(findings_count_raw, "findingsCount")?;
        let solver_data = if let Some(data) = pred.get("solverData") {
            check_object_fields(
                data,
                "solverData",
                &["cut", "cost", "method", "reproduced", "baselinePassed"],
                &["horizon", "supportProviderVersion", "witnesses"],
            )?;
            let cut_arr = get_arr(data, "cut")?;
            if cut_arr.is_empty() {
                return Err(CertError::Schema(
                    "solverData requires a non-empty cut".into(),
                ));
            }
            if cut_arr.len() > MAX_CUT_MEMBERS {
                return Err(CertError::Schema(format!("cut exceeds {MAX_CUT_MEMBERS}")));
            }
            let mut cut = Vec::with_capacity(cut_arr.len());
            for value in cut_arr {
                let text = value
                    .as_str()
                    .ok_or_else(|| CertError::Schema("cut member".into()))?;
                check_string_bytes(text, "cut member")?;
                cut.push(hex_to_hash(text).map_err(CertError::Schema)?);
            }
            let cost = data
                .get("cost")
                .and_then(|value| value.as_u64())
                .ok_or_else(|| CertError::Schema("cost".into()))?;
            let method = get_str(data, "method")?.to_string();
            let reproduced = data
                .get("reproduced")
                .and_then(|value| value.as_bool())
                .ok_or_else(|| CertError::Schema("reproduced".into()))?;
            let baseline_passed = data
                .get("baselinePassed")
                .and_then(|value| value.as_bool())
                .ok_or_else(|| CertError::Schema("baselinePassed".into()))?;
            let witnesses = if let Some(arr) = data.get("witnesses").and_then(|x| x.as_array()) {
                if arr.len() > MAX_RESOLVED_DEPENDENCIES {
                    return Err(CertError::Schema(format!(
                        "witnesses exceeds {MAX_RESOLVED_DEPENDENCIES}"
                    )));
                }
                let mut out = Vec::with_capacity(arr.len());
                for value in arr {
                    let text = value
                        .as_str()
                        .ok_or_else(|| CertError::Schema("witness".into()))?;
                    check_string_bytes(text, "witness")?;
                    out.push(hex_to_hash(text).map_err(CertError::Schema)?);
                }
                out
            } else {
                Vec::new()
            };
            let support_provider_version = if let Some(value) = data.get("supportProviderVersion") {
                let raw = value
                    .as_u64()
                    .ok_or_else(|| CertError::Schema("supportProviderVersion".into()))?;
                let converted = u64_to_usize_checked(raw, "supportProviderVersion")?;
                Some(
                    u64::try_from(converted)
                        .map_err(|_| CertError::Schema("supportProviderVersion overflow".into()))?,
                )
            } else {
                None
            };
            let horizon = if let Some(value) = data.get("horizon") {
                let raw = value
                    .as_u64()
                    .ok_or_else(|| CertError::Schema("horizon".into()))?;
                let converted = u64_to_usize_checked(raw, "horizon")?;
                if !(1..=MAX_RECORDED_HORIZON).contains(&converted) {
                    return Err(CertError::Schema(format!(
                        "horizon {converted} out of range 1..={MAX_RECORDED_HORIZON}"
                    )));
                }
                Some(converted)
            } else {
                None
            };
            Some(RecordedSolverData {
                cut,
                cost,
                method,
                horizon,
                support_provider_version,
                witnesses,
                reproduced,
                baseline_passed,
            })
        } else {
            None
        };
        let statistical = if let Some(s) = pred.get("statistical") {
            check_object_fields(s, "statistical", &["upperP", "confidence", "method"], &[])?;
            Some(StatisticalBound {
                upper_p: s
                    .get("upperP")
                    .and_then(|x| x.as_f64())
                    .ok_or_else(|| CertError::Schema("upperP".into()))?,
                confidence: s
                    .get("confidence")
                    .and_then(|x| x.as_f64())
                    .ok_or_else(|| CertError::Schema("confidence".into()))?,
                method: get_str(s, "method")?.to_string(),
            })
        } else {
            None
        };
        let journal_validation = match pred.get("journalValidation").and_then(|x| x.as_str()) {
            Some("bound") => Some(JournalValidation::Bound),
            Some(other) => {
                return Err(CertError::Schema(format!(
                    "journalValidation must be `bound`, got {other:?}"
                )));
            }
            None => None,
        };
        let inclusion_minimal = match pred.get("inclusionMinimal") {
            Some(value) => match value.as_bool() {
                Some(true) => Some(InclusionMinimal::Minimal),
                Some(false) => Some(InclusionMinimal::NotMinimal),
                None => {
                    return Err(CertError::Schema(
                        "inclusionMinimal must be a boolean".into(),
                    ));
                }
            },
            None => None,
        };
        Ok(Self {
            subject,
            predicate_type: pt,
            build_type: bt,
            external_parameters_digest: run_digest,
            resolved_dependencies: deps,
            builder_id,
            runs_executed,
            findings_count,
            solver_data,
            statistical,
            journal_validation,
            inclusion_minimal,
            execution_identity,
        })
    }

    /// Validate bounded statement fields without a journal.
    pub fn verify(&self) -> Result<(), CertError> {
        let expected_predicate = predicate_type_campaign_v1();
        if self.predicate_type != expected_predicate {
            return Err(CertError::Verification(format!(
                "predicateType must be {expected_predicate}"
            )));
        }
        let expected_build = build_type_campaign_v1();
        if self.build_type != expected_build {
            return Err(CertError::Verification(format!(
                "buildType must be {expected_build}"
            )));
        }
        for (value, field) in [
            (self.subject.name.as_str(), "subject.name"),
            (self.predicate_type.as_str(), "predicateType"),
            (self.build_type.as_str(), "buildType"),
            (self.builder_id.as_str(), "builder.id"),
        ] {
            check_string_bytes(value, field)?;
            if value.trim().is_empty() {
                return Err(CertError::Verification(format!("{field} must be present")));
            }
        }
        if self.resolved_dependencies.len() > MAX_RESOLVED_DEPENDENCIES {
            return Err(CertError::Verification(format!(
                "resolvedDependencies exceeds {MAX_RESOLVED_DEPENDENCIES}"
            )));
        }
        for dependency in &self.resolved_dependencies {
            check_string_bytes(&dependency.name, "resolvedDependencies.name")?;
            if dependency.name.trim().is_empty() {
                return Err(CertError::Verification(
                    "resolvedDependencies.name must be present".into(),
                ));
            }
        }
        if self.findings_count > self.runs_executed {
            return Err(CertError::Verification(
                "findingsCount must not exceed runsExecuted".into(),
            ));
        }
        if self.findings_count > 0 && self.subject.digest == [0u8; 32] {
            return Err(CertError::Verification(
                "subject digest must be non-zero when findings exist".into(),
            ));
        }
        if self.findings_count == 0 && self.subject.digest != [0u8; 32] {
            return Err(CertError::Verification(
                "subject digest must be zero when no findings exist".into(),
            ));
        }
        if let Some(data) = &self.solver_data {
            if data.cut.is_empty() {
                return Err(CertError::Verification(
                    "solverData requires a non-empty cut".into(),
                ));
            }
            if data.cut.len() > MAX_CUT_MEMBERS {
                return Err(CertError::Verification(format!(
                    "cut exceeds {MAX_CUT_MEMBERS}"
                )));
            }
            check_string_bytes(&data.method, "solverData.method")?;
            if data.method.trim().is_empty() {
                return Err(CertError::Verification(
                    "solverData.method must be present".into(),
                ));
            }
            if let Some(horizon) = data.horizon
                && !(1..=MAX_RECORDED_HORIZON).contains(&horizon)
            {
                return Err(CertError::Verification(format!(
                    "horizon {horizon} out of range 1..={MAX_RECORDED_HORIZON}"
                )));
            }
            check_cut_duplicates(&data.cut)?;
            let cut_count = u64::try_from(data.cut.len())
                .map_err(|_| CertError::Verification("cut count overflow".into()))?;
            let maximum_cost = cut_count.checked_mul(MAX_EVENT_COST).ok_or_else(|| {
                CertError::Verification("maximum recorded cut cost overflow".into())
            })?;
            if data.cost > maximum_cost {
                return Err(CertError::Verification(format!(
                    "recorded cut cost {} exceeds maximum cut cost {maximum_cost}",
                    data.cost
                )));
            }
        }
        if self.inclusion_minimal.is_some() && self.solver_data.is_none() {
            return Err(CertError::Verification(
                "inclusionMinimal requires a recorded cut".into(),
            ));
        }
        if self.journal_validation.is_some() && self.findings_count == 0 {
            // A bound result records journal-anchored validation, which only
            // runs on findings-bearing statements; a campaign statement that
            // never bound to a journal must not claim the result.
            return Err(CertError::Verification(
                "journalValidation requires findings to validate against a journal".into(),
            ));
        }
        if let Some(statistical) = &self.statistical {
            check_string_bytes(&statistical.method, "statistical.method")?;
            if statistical.method.trim().is_empty() {
                return Err(CertError::Verification(
                    "statistical.method must be present".into(),
                ));
            }
            if !statistical.upper_p.is_finite() || !(0.0..=1.0).contains(&statistical.upper_p) {
                return Err(CertError::Verification(
                    "statistical.upperP must be finite and in 0..=1".into(),
                ));
            }
            if !statistical.confidence.is_finite() || !(0.0..=1.0).contains(&statistical.confidence)
            {
                return Err(CertError::Verification(
                    "statistical.confidence must be finite and in 0..=1".into(),
                ));
            }
        }
        Ok(())
    }

    /// Validate the statement and bind it to one concrete journal.
    ///
    /// Wave 1 checks the subject root, cut membership, faultability, and the
    /// recorded solver cost fields. It does not inspect causal parent paths.
    /// Use [`Self::verify_with_journal_with`] to select a lineage policy.
    pub fn verify_with_journal_with(
        &self,
        journal: &Journal,
        policy: LineagePolicy,
    ) -> Result<(), CertError> {
        if policy == LineagePolicy::Strict {
            check_lineage_not_certifiable(journal)?;
        }
        if let Some(data) = &self.solver_data
            && data.cut.len() > journal.len()
        {
            return Err(CertError::Verification(format!(
                "cut has {} members but journal has {} entries",
                data.cut.len(),
                journal.len()
            )));
        }
        if self.subject.digest == [0u8; 32] {
            return Err(CertError::Verification(
                "journal mode requires concrete subject digest; zero digest never binds".into(),
            ));
        }
        if let Some(data) = &self.solver_data {
            for witness in &data.witnesses {
                if journal.get(witness).is_none() {
                    return Err(CertError::Verification(format!(
                        "forged witness: references unknown journal entry {:02x?}",
                        &witness[..4]
                    )));
                }
            }
        }
        let subject_root = journal.root_hash();
        if subject_root != self.subject.digest {
            return Err(CertError::Verification(format!(
                "subject digest mismatch: certificate attests {:02x?}, journal root is {:02x?}",
                &self.subject.digest[..4],
                &subject_root[..4]
            )));
        }
        if let Some(data) = &self.solver_data {
            for id in &data.cut {
                let Some(entry) = journal.get(id) else {
                    return Err(CertError::Verification(format!(
                        "forged cut: references unknown journal entry {:02x?}",
                        &id[..4]
                    )));
                };
                if !is_faultable(entry.data.kind) {
                    return Err(CertError::Verification(format!(
                        "forged cut: entry {:02x?} has kind {:?}, which the fault model cannot inject",
                        &id[..4],
                        entry.data.kind
                    )));
                }
            }
        }
        self.verify()?;
        let Some(data) = &self.solver_data else {
            return Ok(());
        };
        let exact_cost = data.cut.iter().try_fold(0u64, |total, id| {
            total
                .checked_add(event_fault_cost(journal, id))
                .ok_or_else(|| CertError::Verification("recomputed cut cost overflow".into()))
        })?;
        if data.cost != exact_cost {
            return Err(CertError::Verification(format!(
                "recorded cut cost {} disagrees with recomputed cut cost {exact_cost}",
                data.cost
            )));
        }
        Ok(())
    }

    /// Validate and bind the certificate to a journal.
    ///
    /// Lineage-only journals are rejected. Use
    /// [`Self::verify_with_journal_with`] with [`LineagePolicy::AllowLineage`]
    /// to override.
    pub fn verify_with_journal(&self, journal: &Journal) -> Result<(), CertError> {
        self.verify_with_journal_with(journal, LineagePolicy::Strict)
    }

    /// Validate and bind the certificate to a journal, gated on execution
    /// identity.
    ///
    /// The identity gate runs before any root comparison: a certificate that
    /// carries an identity digest must match the expected digest of the run
    /// that produced the journal, and a digest present on only one side is
    /// treated as incomplete and rejected. When both sides carry no identity
    /// the legacy comparison path is used.
    pub fn verify_with_journal_and_identity(
        &self,
        journal: &Journal,
        expected_identity: Option<Hash>,
    ) -> Result<(), CertError> {
        match (self.execution_identity, expected_identity) {
            (Some(certificate), Some(expected)) if certificate == expected => {}
            (Some(_), Some(_)) => {
                return Err(CertError::Verification(
                    "execution identity mismatch: certificate and run disagree".into(),
                ));
            }
            (Some(_), None) => {
                return Err(CertError::Verification(
                    "execution identity incomplete: run carries no identity".into(),
                ));
            }
            (None, Some(_)) => {
                return Err(CertError::Verification(
                    "execution identity incomplete: certificate carries no identity".into(),
                ));
            }
            (None, None) => {}
        }
        self.verify_with_journal(journal)
    }

    /// Bound the statement to a journal and verify the recorded cut is
    /// inclusion-minimal: every member is essential, so no proper subset of
    /// the cut still covers every witness derivation path.
    ///
    /// Requires a non-empty reproduced cut and a passing no-fault baseline;
    /// a baseline violation may still produce a campaign statement, but it is
    /// not fault-causation evidence and this operation refuses it.
    pub fn verify_inclusion_minimal_with(
        &self,
        journal: &Journal,
        policy: LineagePolicy,
    ) -> Result<(), CertError> {
        self.verify_inclusion_minimal_with_support(journal, policy, None)
    }

    /// Inclusion-minimal validation bound to an expected support-provider
    /// version.
    ///
    /// When the statement records a support-provider version and an expected
    /// version is supplied, the two must agree; a disagreement fails before
    /// any traversal, so an altered support binding can never certify a cut.
    pub fn verify_inclusion_minimal_with_support(
        &self,
        journal: &Journal,
        policy: LineagePolicy,
        expected_support_version: Option<u64>,
    ) -> Result<(), CertError> {
        self.verify_with_journal_with(journal, policy)?;
        let Some(data) = &self.solver_data else {
            return Err(CertError::Verification(
                "inclusion-minimal validation requires a recorded cut".into(),
            ));
        };
        if let (Some(recorded), Some(expected)) =
            (data.support_provider_version, expected_support_version)
            && recorded != expected
        {
            return Err(CertError::Verification(format!(
                "support-provider version mismatch: statement records {recorded}, \
                 expected {expected}"
            )));
        }
        if !data.reproduced || !data.baseline_passed {
            return Err(CertError::Verification(
                "fault-cut extension requires a reproduced cut and a passing \
                 no-fault baseline; a baseline violation is a campaign \
                 statement, not fault-causation evidence"
                    .into(),
            ));
        }
        let Some(horizon) = data.horizon else {
            return Err(CertError::Verification(
                "inclusion-minimal validation requires a recorded solver \
                 horizon to bound the traversal"
                    .into(),
            ));
        };
        if data.witnesses.is_empty() {
            return Err(CertError::Verification(
                "inclusion-minimal validation requires recorded witnesses".into(),
            ));
        }
        let paths = collect_fault_paths_iterative(journal, &data.witnesses, horizon)?;
        let cut: std::collections::BTreeSet<Hash> = data.cut.iter().copied().collect();
        for path in &paths {
            if path.iter().all(|id| !cut.contains(id)) {
                return Err(CertError::Verification(
                    "recorded cut misses a witness derivation path".into(),
                ));
            }
        }
        for member in &data.cut {
            let essential = paths.iter().any(|path| {
                path.contains(member) && path.iter().filter(|id| cut.contains(*id)).count() == 1
            });
            if !essential {
                return Err(CertError::Verification(format!(
                    "cut member {:02x?} is redundant: the recorded cut is not \
                     inclusion-minimal",
                    &member[..4]
                )));
            }
        }
        Ok(())
    }

    /// Journal-bound inclusion-minimal validation under the strict lineage
    /// policy. See [`Self::verify_inclusion_minimal_with`].
    pub fn verify_inclusion_minimal(&self, journal: &Journal) -> Result<(), CertError> {
        self.verify_inclusion_minimal_with(journal, LineagePolicy::Strict)
    }
}

/// Maximum derivation paths a bounded inclusion-minimal check will walk
/// before failing closed: a cut whose witness closure is wider than this
/// cannot be certified with the recorded horizon.
const MAX_INCLUSION_PATHS: usize = 65536;

/// Iteratively collect faultable derivation paths from `witnesses`, bounded
/// by `horizon`.
///
/// The explicit stack keeps journal-derived graph depth off the call stack,
/// and the per-walk visited set bounds re-expansion of shared ancestors, so
/// a deep or wide graph cannot overflow or explode the walk. Returns an
/// error when the path budget is exceeded, which fails the check closed.
fn collect_fault_paths_iterative(
    journal: &Journal,
    witnesses: &[Hash],
    horizon: usize,
) -> Result<Vec<Vec<Hash>>, CertError> {
    let mut paths = Vec::new();
    for witness in witnesses {
        let mut visited: std::collections::HashSet<(Hash, usize)> =
            std::collections::HashSet::new();
        let mut stack = vec![(*witness, 0usize, Vec::new())];
        while let Some((current, depth, mut path)) = stack.pop() {
            if depth > horizon {
                if !path.is_empty() {
                    paths.push(path);
                    if paths.len() > MAX_INCLUSION_PATHS {
                        return Err(CertError::Verification(format!(
                            "inclusion-minimal check exceeds {MAX_INCLUSION_PATHS} paths"
                        )));
                    }
                }
                continue;
            }
            if !visited.insert((current, depth)) {
                continue;
            }
            let Some(entry) = journal.get(&current) else {
                continue;
            };
            if is_faultable(entry.data.kind) {
                path.push(current);
            }
            if entry.data.parents.is_empty() {
                if !path.is_empty() {
                    paths.push(path);
                    if paths.len() > MAX_INCLUSION_PATHS {
                        return Err(CertError::Verification(format!(
                            "inclusion-minimal check exceeds {MAX_INCLUSION_PATHS} paths"
                        )));
                    }
                }
            } else {
                for parent in &entry.data.parents {
                    stack.push((*parent, depth + 1, path.clone()));
                }
            }
        }
    }
    Ok(paths)
}

impl CampaignReport {
    /// Write an in-toto Statement certificate for this report to `path`.
    ///
    /// The JSON is produced by [`CampaignCertificate::to_json`] and written
    /// with `std::fs` (host-side, not simulation code). The digest covers the
    /// base `RunConfig` canonical bytes and the builder is recorded as
    /// `builder_id`.
    ///
    /// # Errors
    /// Returns [`CertError::Io`] when the parent directory cannot be created
    /// or the file cannot be written, and the certificate serialize error
    /// from [`CampaignCertificate::to_json`] otherwise.
    pub fn write_certificate(
        &self,
        path: &Path,
        run_config_digest: Hash,
        builder_id: &str,
        execution_identity: Option<Hash>,
    ) -> Result<(), CertError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|source| CertError::Io {
                operation: "create_dir_all",
                path: parent.display().to_string(),
                source,
            })?;
        }
        let cert = CampaignCertificate::from_campaign(
            self,
            builder_id,
            Vec::new(),
            run_config_digest,
            execution_identity,
        )?;
        let json = cert.to_json()?;
        check_cert_bytes(json.len())?;
        std::fs::write(path, json).map_err(|source| CertError::Io {
            operation: "write",
            path: path.display().to_string(),
            source,
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle::Verdict;
    use crate::search::{CampaignReport, Finding};
    use ledger_format::{EntryKind, Payload};
    use ledger_journal::Journal;
    use ledger_sim::RunResult;
    use std::error::Error as _;

    fn with_finding() -> CampaignReport {
        let mut j = Journal::new();
        j.append(
            ledger_format::EntryKind::Outcome,
            1,
            [],
            ledger_format::Payload::Number(1),
        )
        .unwrap();
        let run = RunResult {
            outcome: ledger_sim::RunOutcome::Completed,
            journal_error: None,
            journal: j,
            decisions: Vec::new(),
            trace: Vec::new(),
            registers: Vec::new(),
            steps: 0,
            monitor_issues: Vec::new(),
            applied_faults: Vec::new(),
            origins: Vec::new(),
            protection: ledger_sim::BeltStatus::NotArmed,
        };
        CampaignReport {
            runs_executed: 10,
            distinct_roots: 1,
            findings: vec![Finding {
                seed: [7u8; 32],
                run,
                verdict: Verdict::fail(vec![[7u8; 32]], "test"),
            }],
            variants: Vec::new(),
            monitors: Vec::new(),
            memo_hits: 0,
        }
    }

    fn empty(runs: usize) -> CampaignReport {
        CampaignReport {
            runs_executed: runs,
            distinct_roots: runs,
            findings: Vec::new(),
            variants: Vec::new(),
            monitors: Vec::new(),
            memo_hits: 0,
        }
    }

    #[test]
    fn roundtrip_json() {
        let r = with_finding();
        let deps = vec![
            ResolvedDependency {
                name: "z-dep".into(),
                digest: [2u8; 32],
            },
            ResolvedDependency {
                name: "a-dep".into(),
                digest: [1u8; 32],
            },
        ];
        let c = CampaignCertificate::from_campaign(&r, "builder-1", deps, [9u8; 32], None).unwrap();
        let j = c.to_json().unwrap();
        let b = CampaignCertificate::from_json(&j).unwrap();
        assert_eq!(c.subject, b.subject);
        assert_eq!(c.resolved_dependencies, b.resolved_dependencies);
        assert!(b.verify().is_ok());
    }

    #[test]
    fn emitted_json_limit_preserves_round_trip_boundary() {
        let base =
            CampaignCertificate::from_campaign(&empty(10), "builder", Vec::new(), [9u8; 32], None)
                .expect("base certificate must be valid");
        let with_dependency_name_size = |name_bytes: usize| {
            let mut certificate = base.clone();
            certificate.resolved_dependencies = (0..MAX_RESOLVED_DEPENDENCIES)
                .map(|_| ResolvedDependency {
                    name: "x".repeat(name_bytes),
                    digest: [7u8; 32],
                })
                .collect();
            certificate
        };

        let mut accepted = 1usize;
        let mut rejected = MAX_STRING_BYTES;
        while accepted + 1 < rejected {
            let candidate = accepted + (rejected - accepted) / 2;
            if with_dependency_name_size(candidate).to_json().is_ok() {
                accepted = candidate;
            } else {
                rejected = candidate;
            }
        }

        let json = with_dependency_name_size(accepted)
            .to_json()
            .expect("largest accepted certificate must serialize");
        assert!(json.len() <= CERT_MAX_BYTES);
        let decoded = CampaignCertificate::from_json(&json)
            .expect("every emitted certificate must parse under the same byte limit");
        assert_eq!(
            decoded.resolved_dependencies.len(),
            MAX_RESOLVED_DEPENDENCIES
        );

        let error = with_dependency_name_size(rejected)
            .to_json()
            .expect_err("the next larger certificate must be rejected");
        assert!(
            matches!(error, CertError::Serialization(_)),
            "oversize emission must be a serialization error: {error:?}"
        );
    }

    #[test]
    fn rule_of_three_math() {
        let b = CampaignCertificate::rule_of_three(1000).unwrap();
        assert!((b.upper_p - 0.003).abs() < 1e-12);
        assert_eq!(b.confidence, 0.95);
        assert!(CampaignCertificate::rule_of_three(0).is_none());
    }

    fn unique_cert_dir(tag: &str) -> std::path::PathBuf {
        // Process ids keep temp dirs unique per test; distinct tags keep
        // them unique across tests sharing one process.
        let dir = std::env::temp_dir().join(format!("ldgr-cert-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// A failing filesystem write must surface as the typed `Io` variant with
    /// the io source in the error chain, never a bare message.
    #[test]
    fn write_certificate_reports_typed_io_errors() {
        let dir = unique_cert_dir("io");
        // Writing onto an existing directory fails deterministically on
        // unix with IsADirectory: the write arm keeps the io source.
        let err = empty(1)
            .write_certificate(&dir, [0u8; 32], "builder", None)
            .unwrap_err();
        match &err {
            CertError::Io {
                operation,
                path,
                source,
            } => {
                assert_eq!(*operation, "write");
                assert!(
                    path.contains("ldgr-cert-io"),
                    "path must name the failed target: {path}"
                );
                assert_eq!(source.kind(), std::io::ErrorKind::IsADirectory);
            }
            other => panic!("expected Io, got {other:?}"),
        }
        assert!(
            err.source().is_some(),
            "io source must stay in the error chain"
        );
        assert!(
            err.to_string().contains("certificate io"),
            "display must identify the failing surface: {err}"
        );

        // The create_dir_all arm stays typed as well: a regular file used
        // as a parent makes the mkdir path fail with a real io error. The
        // exact kind differs across platforms (NotADirectory or
        // AlreadyExists), so only the arm, the path, and the chain are
        // asserted.
        let blocker = dir.join("blocker");
        std::fs::write(&blocker, b"x").expect("write blocker file");
        let cert_path = blocker.join("cert.json");
        let err = empty(1)
            .write_certificate(&cert_path, [0u8; 32], "builder", None)
            .unwrap_err();
        match &err {
            CertError::Io {
                operation,
                path,
                source,
            } => {
                assert_eq!(*operation, "create_dir_all");
                assert!(
                    path.contains("blocker"),
                    "path must name the failed parent: {path}"
                );
                assert!(
                    matches!(
                        source.kind(),
                        std::io::ErrorKind::NotADirectory | std::io::ErrorKind::AlreadyExists
                    ),
                    "a real io failure is required, got {:?}",
                    source.kind()
                );
            }
            other => panic!("expected Io, got {other:?}"),
        }
        assert!(
            err.source().is_some(),
            "io source must stay in the error chain"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_certificate_rejects_oversized_input_before_writing() {
        let dir = unique_cert_dir("oversized-write");
        let cert_path = dir.join("cert.json");
        let builder = "x".repeat(CERT_MAX_BYTES + 1);
        let error = empty(1)
            .write_certificate(&cert_path, [9u8; 32], &builder, None)
            .expect_err("oversized certificate input must fail");
        assert!(
            matches!(error, CertError::Schema(_) | CertError::Serialization(_)),
            "oversized write must return a bounded certificate error: {error:?}"
        );
        assert!(!cert_path.exists(), "oversized JSON must not be written");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The happy path still writes a parseable, verifiable certificate after
    /// the error typing change.
    #[test]
    fn write_certificate_round_trips_to_disk() {
        let dir = unique_cert_dir("rt");
        let cert_path = dir.join("cert.json");
        with_finding()
            .write_certificate(&cert_path, [9u8; 32], "builder", None)
            .expect("write certificate");
        let bytes = std::fs::read(&cert_path).expect("read certificate");
        let text = String::from_utf8(bytes).expect("certificate must be utf8");
        let parsed = CampaignCertificate::from_json(&text).expect("parse certificate");
        assert!(parsed.verify().is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_rejects_wrong_predicate_type() {
        let mut c =
            CampaignCertificate::from_campaign(&empty(10), "b", Vec::new(), [1u8; 32], None)
                .unwrap();
        c.predicate_type = format!(
            "{}/attestations/wrong/v1",
            crate::attest_uri::attestation_base()
        );
        assert!(matches!(c.verify(), Err(CertError::Verification(_))));
        let j = c.to_json().unwrap();
        assert!(
            CampaignCertificate::from_json(&j)
                .unwrap()
                .verify()
                .is_err()
        );
    }

    #[test]
    fn verify_rejects_zero_subject_with_findings() {
        let mut c =
            CampaignCertificate::from_campaign(&with_finding(), "b", Vec::new(), [1u8; 32], None)
                .expect("valid campaign must create a certificate");
        c.subject.digest = [0u8; 32];
        assert!(matches!(c.verify(), Err(CertError::Verification(_))));
    }

    #[test]
    fn identity_gate_rejects_disagreeing_statement_and_run() {
        // Statement and run disagree: the gate fails before any root
        // comparison.
        let certificate = CampaignCertificate::from_campaign(
            &with_finding(),
            "b",
            Vec::new(),
            [1u8; 32],
            Some([0xaa; 32]),
        )
        .expect("certificate with identity must build");
        let journal = &with_finding().findings[0].run.journal;
        let error = certificate
            .verify_with_journal_and_identity(journal, Some([0xbb; 32]))
            .expect_err("disagreeing identity must fail");
        assert!(matches!(error, CertError::Verification(_)));
    }

    #[test]
    fn identity_gate_rejects_incomplete_sides() {
        let certificate = CampaignCertificate::from_campaign(
            &with_finding(),
            "b",
            Vec::new(),
            [1u8; 32],
            Some([0xaa; 32]),
        )
        .expect("certificate with identity must build");
        let journal = &with_finding().findings[0].run.journal;
        // Certificate carries identity, run carries none: incomplete.
        let error = certificate
            .verify_with_journal_and_identity(journal, None)
            .expect_err("run without identity must fail");
        assert!(matches!(error, CertError::Verification(_)));

        // Run carries identity, certificate carries none: incomplete.
        let legacy =
            CampaignCertificate::from_campaign(&with_finding(), "b", Vec::new(), [1u8; 32], None)
                .expect("legacy certificate must build");
        let error = legacy
            .verify_with_journal_and_identity(journal, Some([0xaa; 32]))
            .expect_err("certificate without identity must fail");
        assert!(matches!(error, CertError::Verification(_)));
    }

    #[test]
    fn identity_gate_passes_when_both_sides_match_or_are_absent() {
        let certificate = CampaignCertificate::from_campaign(
            &with_finding(),
            "b",
            Vec::new(),
            [1u8; 32],
            Some([0xaa; 32]),
        )
        .expect("certificate with identity must build");
        let journal = &with_finding().findings[0].run.journal;
        // Matching identity proceeds to the normal journal binding (subject
        // digest equals the journal root from with_finding).
        assert!(
            certificate
                .verify_with_journal_and_identity(journal, Some([0xaa; 32]))
                .is_ok()
        );
        // Both sides absent: the legacy comparison path is unchanged.
        let legacy =
            CampaignCertificate::from_campaign(&with_finding(), "b", Vec::new(), [1u8; 32], None)
                .expect("legacy certificate must build");
        assert!(
            legacy
                .verify_with_journal_and_identity(journal, None)
                .is_ok()
        );
    }

    #[test]
    fn identity_json_round_trips() {
        let certificate = CampaignCertificate::from_campaign(
            &with_finding(),
            "b",
            Vec::new(),
            [1u8; 32],
            Some([0xaa; 32]),
        )
        .expect("certificate with identity must build");
        let json = certificate.to_json().expect("certificate serializes");
        assert!(json.contains("executionIdentity"));
        let decoded = CampaignCertificate::from_json(&json).expect("certificate parses");
        assert_eq!(decoded.execution_identity, Some([0xaa; 32]));
        // Legacy JSON without the field parses to None. The identity field
        // lives under externalParameters; removing the serialized value must
        // leave a valid legacy statement.
        let value: serde_json::Value = serde_json::from_str(&json).expect("json parses");
        let mut params = value["predicate"]["buildDefinition"]["externalParameters"]
            .as_object()
            .expect("externalParameters is an object")
            .clone();
        params.remove("executionIdentity");
        let legacy_json = serde_json::to_string(&serde_json::json!({
            "_type": value["_type"],
            "subject": value["subject"],
            "predicateType": value["predicateType"],
            "predicate": {
                "buildDefinition": {
                    "buildType": value["predicate"]["buildDefinition"]["buildType"],
                    "externalParameters": params,
                    "resolvedDependencies": value["predicate"]["buildDefinition"]
                        ["resolvedDependencies"],
                },
                "runDetails": value["predicate"]["runDetails"],
            },
        }))
        .expect("legacy json builds");
        let legacy = CampaignCertificate::from_json(&legacy_json).expect("legacy statement parses");
        assert_eq!(legacy.execution_identity, None);
    }

    #[test]
    fn verify_rejects_absent_or_malformed_subject() {
        let mut c =
            CampaignCertificate::from_campaign(&with_finding(), "b", Vec::new(), [1u8; 32], None)
                .expect("valid campaign must create a certificate");
        c.subject.name = "  ".into();
        assert!(matches!(c.verify(), Err(CertError::Verification(_))));
        let mut c =
            CampaignCertificate::from_campaign(&empty(10), "b", Vec::new(), [1u8; 32], None)
                .unwrap();
        c.subject.digest = [7u8; 32];
        assert!(
            matches!(c.verify(), Err(CertError::Verification(_))),
            "zero findings must not carry a subject digest"
        );
    }

    #[test]
    fn statement_validation_rejects_empty_solver_data_cut() {
        let mut certificate = CampaignCertificate::from_campaign(
            &with_finding(),
            "builder",
            Vec::new(),
            [1u8; 32],
            None,
        )
        .expect("valid campaign must create a certificate");
        certificate.solver_data = Some(RecordedSolverData {
            cut: Vec::new(),
            cost: 0,
            method: "solver-v1".into(),
            horizon: Some(64),
            support_provider_version: None,
            witnesses: Vec::new(),
            reproduced: false,
            baseline_passed: false,
        });
        let error = certificate.verify().expect_err("empty cut must fail");
        assert!(error.to_string().contains("non-empty cut"), "{error}");

        certificate.solver_data = None;
        assert!(
            certificate.verify().is_ok(),
            "a baseline statement may omit solver data"
        );
    }

    #[test]
    fn from_json_rejects_raw_oversize_before_parsing() {
        let raw = " ".repeat(CERT_MAX_BYTES + 1);
        let error = CampaignCertificate::from_json(&raw).expect_err("oversize must fail");
        assert!(error.to_string().contains("exceeds"), "{error}");
    }

    #[test]
    fn from_json_rejects_wrong_type_and_multiple_subjects() {
        let certificate =
            CampaignCertificate::from_campaign(&empty(10), "builder", Vec::new(), [1u8; 32], None)
                .expect("valid campaign must create a certificate");
        let mut value: serde_json::Value =
            serde_json::from_str(&certificate.to_json().expect("certificate must serialize"))
                .expect("certificate JSON must parse");

        value["_type"] = serde_json::json!("https://in-toto.io/Statement/v0");
        let wrong_type = serde_json::to_string(&value).expect("JSON must serialize");
        let error = CampaignCertificate::from_json(&wrong_type).expect_err("wrong type must fail");
        assert!(error.to_string().contains("_type"), "{error}");

        value["_type"] = serde_json::json!("https://in-toto.io/Statement/v1");
        let subject = value["subject"][0].clone();
        value["subject"] = serde_json::json!([subject.clone(), subject]);
        let multiple = serde_json::to_string(&value).expect("JSON must serialize");
        let error =
            CampaignCertificate::from_json(&multiple).expect_err("multiple subjects must fail");
        assert!(error.to_string().contains("exactly one"), "{error}");
    }

    #[test]
    fn from_json_rejects_empty_cut_duplicate_cut_and_invalid_horizon() {
        let certificate = CampaignCertificate::from_campaign(
            &with_finding(),
            "builder",
            Vec::new(),
            [1u8; 32],
            None,
        )
        .expect("valid campaign must create a certificate");
        let mut value: serde_json::Value =
            serde_json::from_str(&certificate.to_json().expect("certificate must serialize"))
                .expect("certificate JSON must parse");
        value["predicate"]["solverData"] = serde_json::json!({
            "cut": [],
            "cost": 0,
            "method": "solver-v1",
            "reproduced": true,
            "baselinePassed": true,
            "horizon": 64
        });
        let empty_cut = serde_json::to_string(&value).expect("JSON must serialize");
        assert!(CampaignCertificate::from_json(&empty_cut).is_err());

        let member = "01".repeat(32);
        value["predicate"]["solverData"] = serde_json::json!({
            "cut": [member.clone(), member],
            "cost": 1,
            "method": "solver-v1",
            "reproduced": true,
            "baselinePassed": true,
            "horizon": 64
        });
        let duplicate = serde_json::to_string(&value).expect("JSON must serialize");
        let decoded = CampaignCertificate::from_json(&duplicate).expect("schema must decode");
        let error = decoded.verify().expect_err("duplicate cut must fail");
        assert!(error.to_string().contains("duplicate"), "{error}");

        value["predicate"]["solverData"]["cut"] = serde_json::json!(["01".repeat(32)]);
        value["predicate"]["solverData"]["horizon"] = serde_json::json!(65);
        let invalid_horizon = serde_json::to_string(&value).expect("JSON must serialize");
        let error = CampaignCertificate::from_json(&invalid_horizon)
            .expect_err("invalid horizon must fail");
        assert!(error.to_string().contains("horizon"), "{error}");
    }

    fn journal_certificate(journal: &Journal, cut: Vec<Hash>) -> CampaignCertificate {
        let report = CampaignReport {
            runs_executed: 1,
            distinct_roots: 1,
            findings: vec![Finding {
                seed: [7u8; 32],
                run: RunResult {
                    outcome: ledger_sim::RunOutcome::Completed,
                    journal_error: None,
                    journal: journal.clone(),
                    decisions: Vec::new(),
                    trace: Vec::new(),
                    registers: Vec::new(),
                    steps: 0,
                    monitor_issues: Vec::new(),
                    applied_faults: Vec::new(),
                    origins: Vec::new(),
                    protection: ledger_sim::BeltStatus::NotArmed,
                },
                verdict: Verdict::fail(Vec::new(), "test"),
            }],
            variants: Vec::new(),
            monitors: Vec::new(),
            memo_hits: 0,
        };
        let mut certificate =
            CampaignCertificate::from_campaign(&report, "builder", Vec::new(), [1u8; 32], None)
                .expect("valid campaign must create a certificate");
        let exact_cost = cut.iter().fold(0u64, |total, id| {
            total.saturating_add(event_fault_cost(journal, id))
        });
        certificate.solver_data = Some(RecordedSolverData {
            cost: exact_cost,
            cut,
            method: "solver-v1".into(),
            horizon: Some(64),
            support_provider_version: None,
            witnesses: Vec::new(),
            reproduced: true,
            baseline_passed: true,
        });
        certificate
    }

    #[test]
    fn journal_binding_rejects_zero_root_and_wrong_journal() {
        let mut journal = Journal::new();
        let member = journal
            .append(EntryKind::Send, 1, [], Payload::Pair { left: 2, right: 7 })
            .expect("journal append must succeed");
        let mut certificate = journal_certificate(&journal, vec![member]);
        certificate.subject.digest = [0u8; 32];
        certificate.findings_count = 0;
        let error = certificate
            .verify_with_journal(&journal)
            .expect_err("zero root must not bind");
        assert!(error.to_string().contains("zero digest"), "{error}");

        let certificate = journal_certificate(&journal, vec![member]);
        let mut other = Journal::new();
        other
            .append(EntryKind::Send, 1, [], Payload::Pair { left: 2, right: 8 })
            .expect("journal append must succeed");
        let error = certificate
            .verify_with_journal(&other)
            .expect_err("wrong journal must not bind");
        assert!(error.to_string().contains("digest mismatch"), "{error}");
    }

    #[test]
    fn journal_binding_rejects_cut_larger_than_journal_before_duplicate_check() {
        let mut journal = Journal::new();
        let member = journal
            .append(EntryKind::Send, 1, [], Payload::Pair { left: 2, right: 7 })
            .expect("journal append must succeed");
        let certificate = journal_certificate(&journal, vec![member, member]);
        let error = certificate
            .verify_with_journal(&journal)
            .expect_err("oversized cut must fail");
        assert!(
            error.to_string().contains("journal has 1 entries"),
            "{error}"
        );
    }

    #[test]
    fn journal_binding_rejects_unknown_cut_member() {
        let mut journal = Journal::new();
        let member = journal
            .append(EntryKind::Send, 1, [], Payload::Pair { left: 2, right: 7 })
            .expect("journal append must succeed");
        journal
            .append(EntryKind::Outcome, 2, [member], Payload::Number(0))
            .expect("journal append must succeed");
        let certificate = journal_certificate(&journal, vec![[0xEE; 32]]);
        let error = certificate
            .verify_with_journal(&journal)
            .expect_err("unknown cut member must fail");
        assert!(
            error.to_string().contains("unknown journal entry"),
            "{error}"
        );
    }

    #[test]
    fn journal_binding_checks_members_without_parent_path_inference() {
        let mut journal = Journal::new();
        let recorded = journal
            .append(EntryKind::Send, 1, [], Payload::Pair { left: 2, right: 7 })
            .expect("journal append must succeed");
        let unrelated = journal
            .append(EntryKind::Send, 2, [], Payload::Pair { left: 3, right: 8 })
            .expect("journal append must succeed");
        journal
            .append(EntryKind::Outcome, 3, [recorded], Payload::Number(0))
            .expect("journal append must succeed");

        let certificate = journal_certificate(&journal, vec![unrelated]);
        assert!(
            certificate.verify_with_journal(&journal).is_ok(),
            "Wave 1 must only bind recorded data to journal entries"
        );
    }

    fn deep_chain_journal(depth: usize) -> (Journal, Hash, Hash) {
        let mut journal = Journal::new();
        let mut parent = None;
        let mut head = [0u8; 32];
        let mut witness = [0u8; 32];
        for i in 0..depth {
            let id = journal
                .append(
                    EntryKind::Send,
                    1,
                    parent.map_or(Vec::new(), |p: Hash| vec![p]),
                    Payload::Pair {
                        left: (i as u64).wrapping_add(1),
                        right: (i as u64).wrapping_add(2),
                    },
                )
                .expect("append must succeed");
            if i == 0 {
                head = id;
            }
            parent = Some(id);
            witness = id;
        }
        (journal, head, witness)
    }

    #[test]
    fn inclusion_minimal_accepts_chain_cut_without_stack_overflow() {
        // A 20k-deep single-parent chain behind a shallow statement horizon:
        // the recorded horizon bounds the walk, and the iterative traversal
        // never puts journal depth on the call stack.
        let (journal, head, witness) = deep_chain_journal(20_000);
        // The cut must sit inside the recorded horizon (64) of the witness;
        // the head of a 20k chain is far beyond it.
        let mut cut = Vec::new();
        let mut current = Some(witness);
        for _ in 0..16 {
            current = current
                .and_then(|id| journal.get(&id))
                .and_then(|e| e.data.parents.first().copied());
        }
        let within_horizon = current.expect("chain must extend 16 levels");
        cut.push(within_horizon);
        let mut certificate = journal_certificate(&journal, cut);
        certificate
            .solver_data
            .as_mut()
            .expect("solver data present")
            .witnesses = vec![witness];
        certificate
            .verify_inclusion_minimal(&journal)
            .expect("the within-horizon chain cut must be inclusion-minimal");
        assert_ne!(
            head, within_horizon,
            "the deep head stays outside the horizon"
        );
    }

    #[test]
    fn iterative_traversal_handles_deep_chain_without_recursion() {
        // The traversal itself must survive graph depth far beyond any
        // reasonable call-stack budget: 100k levels with no recursion.
        let (journal, _, witness) = deep_chain_journal(100_000);
        let paths = collect_fault_paths_iterative(&journal, &[witness], 100_000)
            .expect("deep walk must complete within the path budget");
        assert_eq!(paths.len(), 1, "a chain has exactly one witness path");
        assert_eq!(
            paths[0].len(),
            100_000,
            "every faultable chain level lands on the path"
        );
    }

    #[test]
    fn inclusion_minimal_rejects_redundant_cut_member() {
        let (journal, head, witness) = deep_chain_journal(32);
        // Cut with both the head and the witness: the witness is redundant
        // because every path through the witness also passes the head.
        let mut certificate = journal_certificate(&journal, vec![head, witness]);
        certificate
            .solver_data
            .as_mut()
            .expect("solver data present")
            .witnesses = vec![witness];
        let error = certificate
            .verify_inclusion_minimal(&journal)
            .expect_err("redundant member must fail");
        assert!(
            error.to_string().contains("redundant"),
            "error must name the redundancy: {error}"
        );
    }

    #[test]
    fn inclusion_minimal_requires_reproduction_and_baseline() {
        let (journal, head, witness) = deep_chain_journal(8);
        let mut certificate = journal_certificate(&journal, vec![head]);
        certificate
            .solver_data
            .as_mut()
            .expect("solver data present")
            .witnesses = vec![witness];
        let data = certificate
            .solver_data
            .as_mut()
            .expect("solver data present");
        data.reproduced = false;
        let error = certificate
            .verify_inclusion_minimal(&journal)
            .expect_err("an unreproduced cut is campaign data, not fault evidence");
        assert!(
            error.to_string().contains("reproduced"),
            "error must name the missing reproduction: {error}"
        );

        let mut certificate = journal_certificate(&journal, vec![head]);
        certificate
            .solver_data
            .as_mut()
            .expect("solver data present")
            .witnesses = vec![witness];
        certificate
            .solver_data
            .as_mut()
            .expect("solver data present")
            .baseline_passed = false;
        let error = certificate
            .verify_inclusion_minimal(&journal)
            .expect_err("a violating baseline is a campaign statement, not causation");
        assert!(
            error.to_string().contains("baseline"),
            "error must name the baseline: {error}"
        );
    }

    #[test]
    fn altered_support_version_fails_statement_validation() {
        // A real chain journal so cut membership and exact-cost checks pass
        // before the support-version gate is exercised.
        let (journal, head, witness) = deep_chain_journal(8);
        let mut certificate = journal_certificate(&journal, vec![head]);
        certificate
            .solver_data
            .as_mut()
            .expect("solver data present")
            .witnesses = vec![witness];
        certificate
            .solver_data
            .as_mut()
            .expect("solver data present")
            .support_provider_version = Some(1);
        // The statement records which support-provider version derived its
        // cut; tampering with that binding is a schema-level integrity break.
        let json = certificate.to_json().expect("certificate serializes");
        let mut value: serde_json::Value =
            serde_json::from_str(&json).expect("certificate JSON must parse");
        value["predicate"]["solverData"]["supportProviderVersion"] = serde_json::json!(2);
        let tampered = serde_json::to_string(&value).expect("JSON must serialize");
        let decoded = CampaignCertificate::from_json(&tampered).expect("schema must decode");
        assert_eq!(
            decoded
                .solver_data
                .as_ref()
                .expect("solver data present")
                .support_provider_version,
            Some(2),
            "the altered version must parse"
        );
        // Support binding is checked by the support-aware journal operation:
        // a statement claiming one version while carrying another fails closed
        // before any traversal.
        let mut consistent = decoded.clone();
        consistent
            .solver_data
            .as_mut()
            .expect("solver data present")
            .support_provider_version = Some(1);
        assert!(
            consistent
                .verify_inclusion_minimal_with_support(&journal, LineagePolicy::Strict, Some(1))
                .is_ok(),
            "a statement matching the expected provider version must pass"
        );
        let error = decoded
            .verify_inclusion_minimal_with_support(&journal, LineagePolicy::Strict, Some(1))
            .expect_err("altered support version must fail support-bound validation");
        assert!(
            error
                .to_string()
                .contains("support-provider version mismatch"),
            "error must name the support binding: {error}"
        );
    }

    #[test]
    fn statement_round_trips_journal_validation_and_minimality_results() {
        let report = with_finding();
        let mut certificate =
            CampaignCertificate::from_campaign(&report, "b", Vec::new(), [1u8; 32], None)
                .expect("valid campaign must create a certificate");
        certificate.journal_validation = Some(JournalValidation::Bound);
        certificate.inclusion_minimal = Some(InclusionMinimal::Minimal);
        let json = certificate.to_json().expect("certificate serializes");
        assert!(json.contains("journalValidation"), "{json}");
        assert!(json.contains("inclusionMinimal"), "{json}");
        let decoded = CampaignCertificate::from_json(&json).expect("certificate parses");
        assert_eq!(decoded.journal_validation, Some(JournalValidation::Bound));
        assert_eq!(decoded.inclusion_minimal, Some(InclusionMinimal::Minimal));
        // Unknown values fail closed.
        let mut value: serde_json::Value =
            serde_json::from_str(&json).expect("certificate JSON must parse");
        value["predicate"]["journalValidation"] = serde_json::json!("unbound");
        let bad = serde_json::to_string(&value).expect("JSON must serialize");
        assert!(
            CampaignCertificate::from_json(&bad).is_err(),
            "unknown journalValidation label must fail"
        );
    }

    #[test]
    fn certificate_surfaces_contain_no_future_claim_wording() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let files = [
            manifest.join("src/certs.rs"),
            manifest.join("../ledger-cli/src/cert_cmd.rs"),
            manifest.join("../../README.md"),
        ];
        // Stage 2 statements are unsigned. Public text must not claim
        // trust guarantees the format does not provide, and the unverified
        // solver bound wording is gone with the field. Every phrase is
        // concatenated so this test never matches its own source.
        let forbidden = [
            ["authent", "ic"].concat(),
            ["non-", "repudiation"].concat(),
            ["complete", "ness"].concat(),
            ["global", " optimum"].concat(),
            ["tamper", "-proof"].concat(),
            ["proven", " lower bound"].concat(),
            ["optimal", "ity"].concat(),
        ];
        for file in files {
            let text = std::fs::read_to_string(&file).expect("claim surface must be readable");
            let lower = text.to_lowercase();
            for phrase in &forbidden {
                assert!(
                    !lower.contains(phrase),
                    "{} contains forbidden claim wording `{phrase}`",
                    file.display()
                );
            }
        }
    }
}
