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
pub struct MinimalityExtension {
    pub cut: Vec<Hash>,
    pub lower_bound: u64,
    pub method: String,
    /// The solver horizon under which the cut was derived, recorded at emit
    /// time. Verification re-derives the hazard at this horizon, so a
    /// certificate with a bounded horizon is never judged against deeper
    /// paths. `None` means the legacy emit path: the derivation horizon is
    /// the verification default (64). Every current emitter records
    /// `Some(64)` from the production solver default.
    pub horizon: Option<usize>,
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
    pub minimality: Option<MinimalityExtension>,
    pub statistical: Option<StatisticalBound>,
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
fn get_str<'a>(v: &'a serde_json::Value, k: &str) -> Result<&'a str, CertError> {
    v.get(k)
        .and_then(|x| x.as_str())
        .ok_or_else(|| CertError::Schema(k.into()))
}
fn get_obj<'a>(v: &'a serde_json::Value, k: &str) -> Result<&'a serde_json::Value, CertError> {
    v.get(k).ok_or_else(|| CertError::Schema(k.into()))
}
fn get_arr<'a>(v: &'a serde_json::Value, k: &str) -> Result<&'a Vec<serde_json::Value>, CertError> {
    v.get(k)
        .and_then(|x| x.as_array())
        .ok_or_else(|| CertError::Schema(k.into()))
}
impl CampaignCertificate {
    /// Create a certificate from a campaign report, rejecting lineage-only
    /// journals. Use [`Self::from_campaign_allow_lineage`] to override.
    pub fn from_campaign(
        report: &CampaignReport,
        builder_id: &str,
        deps: Vec<ResolvedDependency>,
        run_config_digest: Hash,
    ) -> Self {
        match Self::from_campaign_allow_lineage(report, builder_id, deps, run_config_digest, false)
        {
            Ok(cert) => cert,
            Err(error) => panic!("{error}"),
        }
    }

    /// Like [`Self::from_campaign`] but with an explicit lineage override.
    pub fn from_campaign_allow_lineage(
        report: &CampaignReport,
        builder_id: &str,
        deps: Vec<ResolvedDependency>,
        run_config_digest: Hash,
        allow_lineage: bool,
    ) -> Result<Self, CertError> {
        if !allow_lineage {
            for finding in &report.findings {
                check_lineage_not_certifiable(&finding.run.journal)?;
            }
        }
        Self::from_campaign_inner(report, builder_id, deps, run_config_digest)
    }

    fn from_campaign_inner(
        report: &CampaignReport,
        builder_id: &str,
        deps: Vec<ResolvedDependency>,
        run_config_digest: Hash,
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
        Ok(Self {
            subject,
            predicate_type: predicate_type_campaign_v1(),
            build_type: build_type_campaign_v1(),
            external_parameters_digest: run_config_digest,
            resolved_dependencies: s,
            builder_id: builder_id.to_string(),
            runs_executed: report.runs_executed,
            findings_count: report.findings.len(),
            minimality: None,
            statistical,
        })
    }
    pub fn rule_of_three(runs: usize) -> Option<StatisticalBound> {
        if runs == 0 {
            None
        } else {
            Some(StatisticalBound {
                upper_p: 3.0 / runs as f64,
                confidence: 0.95,
                method: "rule-of-three-v1".to_string(),
            })
        }
    }
    pub fn to_json(&self) -> Result<String, CertError> {
        let mut d = self.resolved_dependencies.clone();
        d.sort_by(|a, b| a.name.cmp(&b.name));
        let deps_json: Vec<serde_json::Value> = d
            .iter()
            .map(|x| serde_json::json!({"name":x.name,"digest":{"blake3":hash_to_hex(&x.digest)}}))
            .collect();
        let mut p = serde_json::json!({"buildDefinition":{"buildType":self.build_type,"externalParameters":{"runConfigDigest":hash_to_hex(&self.external_parameters_digest)},"resolvedDependencies":deps_json},"runDetails":{"builder":{"id":self.builder_id},"metadata":{"runsExecuted":self.runs_executed,"findingsCount":self.findings_count}}});
        if let Some(m) = &self.minimality {
            let mut minimality_json = serde_json::json!({"cut":m.cut.iter().map(hash_to_hex).collect::<Vec<_>>(),"lowerBound":m.lower_bound,"method":m.method});
            if let Some(horizon) = m.horizon {
                minimality_json["horizon"] = serde_json::json!(horizon);
            }
            p["minimality"] = minimality_json;
        }
        if let Some(s) = &self.statistical {
            p["statistical"] =
                serde_json::json!({"upperP":s.upper_p,"confidence":s.confidence,"method":s.method});
        }
        let stmt = serde_json::json!({"_type":"https://in-toto.io/Statement/v1","subject":[{"name":self.subject.name,"digest":{"blake3":hash_to_hex(&self.subject.digest)}}],"predicateType":self.predicate_type,"predicate":p});
        serde_json::to_string(&stmt).map_err(|e| CertError::Serialization(e.to_string()))
    }
    pub fn from_json(s: &str) -> Result<Self, CertError> {
        let v: serde_json::Value =
            serde_json::from_str(s).map_err(|e| CertError::Schema(e.to_string()))?;
        let subj = get_arr(&v, "subject")?
            .first()
            .ok_or_else(|| CertError::Schema("subject".into()))?;
        let subject = Subject {
            name: get_str(subj, "name")?.to_string(),
            digest: hex_to_hash(get_str(
                subj.get("digest")
                    .ok_or_else(|| CertError::Schema("digest".into()))?,
                "blake3",
            )?)
            .map_err(CertError::Schema)?,
        };
        let pt = get_str(&v, "predicateType")?.to_string();
        let pred = get_obj(&v, "predicate")?;
        let bd = get_obj(pred, "buildDefinition")?;
        let bt = get_str(bd, "buildType")?.to_string();
        let run_digest = hex_to_hash(get_str(
            get_obj(bd, "externalParameters")?,
            "runConfigDigest",
        )?)
        .map_err(CertError::Schema)?;
        let mut deps = Vec::new();
        for item in get_arr(bd, "resolvedDependencies")? {
            deps.push(ResolvedDependency {
                name: get_str(item, "name")?.to_string(),
                digest: hex_to_hash(get_str(get_obj(item, "digest")?, "blake3")?)
                    .map_err(CertError::Schema)?,
            });
        }
        deps.sort_by(|a, b| a.name.cmp(&b.name));
        let rd = get_obj(pred, "runDetails")?;
        let builder_id = get_str(get_obj(rd, "builder")?, "id")?.to_string();
        let meta = get_obj(rd, "metadata")?;
        let runs_executed =
            meta.get("runsExecuted")
                .and_then(|x| x.as_u64())
                .ok_or_else(|| CertError::Schema("runsExecuted".into()))? as usize;
        let findings_count =
            meta.get("findingsCount")
                .and_then(|x| x.as_u64())
                .ok_or_else(|| CertError::Schema("findingsCount".into()))? as usize;
        let minimality = if let Some(m) = pred.get("minimality") {
            let mut cut = Vec::new();
            for hx in get_arr(m, "cut")? {
                cut.push(
                    hex_to_hash(hx.as_str().ok_or_else(|| CertError::Schema("cut".into()))?)
                        .map_err(CertError::Schema)?,
                );
            }
            Some(MinimalityExtension {
                cut,
                lower_bound: m
                    .get("lowerBound")
                    .and_then(|x| x.as_u64())
                    .ok_or_else(|| CertError::Schema("lowerBound".into()))?,
                method: get_str(m, "method")?.to_string(),
                // Optional on input for back-compat with certificates emitted
                // before the horizon was recorded: absent maps to the
                // verification default (64).
                horizon: m
                    .get("horizon")
                    .and_then(|x| x.as_u64())
                    .map(|h| h as usize),
            })
        } else {
            None
        };
        let statistical = if let Some(s) = pred.get("statistical") {
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
        Ok(Self {
            subject,
            predicate_type: pt,
            build_type: bt,
            external_parameters_digest: run_digest,
            resolved_dependencies: deps,
            builder_id,
            runs_executed,
            findings_count,
            minimality,
            statistical,
        })
    }
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
        if self.subject.name.trim().is_empty() {
            return Err(CertError::Verification(
                "subject name must be present".into(),
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
        if let Some(m) = &self.minimality {
            // lower_bound is in COST units while cut.len() counts events;
            // compare against the cut's summed event cost. Without a
            // journal the per-event kind is unknown, so bound each event by
            // the cost-model maximum: a legitimate single-Send cut (cost 2,
            // lower_bound 2, one event) must pass.
            let cut_cost = m.cut.len() as u64 * MAX_EVENT_COST;
            if m.lower_bound > cut_cost {
                return Err(CertError::Verification(format!(
                    "minimality lower_bound {} exceeds the cut's maximum summed event cost {} ({} events x {MAX_EVENT_COST})",
                    m.lower_bound,
                    cut_cost,
                    m.cut.len()
                )));
            }
        }
        Ok(())
    }

    /// Verify the certificate against the actual journal the certificate
    /// attests, recomputing every obligation instead of trusting persisted
    /// numbers.
    ///
    /// `journal` MUST be the subject journal: its root hash must equal the
    /// certificate's subject digest. A certificate attested against journal
    /// A never verifies against a structurally identical journal B, because
    /// the digest binding fails first with a typed error naming both roots.
    ///
    /// The journal-anchored checks then rebuild the cut's exact per-event
    /// cost from the journal's entry kinds, check the lower-bound proof
    /// obligations (positive bound for a non-empty cut, bound at most the
    /// recomputed cut cost), check that every cut member is a faultable
    /// journal entry, and check the cut against the hazard it must break:
    /// every derivation path from every observable entry (numeric-payload
    /// Outcome/Assert) to a faultable root must be hit, and no proper
    /// subset of the cut may hit them all. The paths are re-derived at the
    /// certificate's RECORDED solver horizon ([`MinimalityExtension
    /// ::horizon`]); a certificate without the field falls back to the
    /// verification default (64), the horizon of every legacy emitter. A
    /// forged certificate (wrong cost, wrong cut, tampered lower bound,
    /// junk members, non-minimal cut) fails with a typed error naming the
    /// defect.
    ///
    /// The path check is deliberately computed from the journal alone: a
    /// certificate over a journal with multiple observable entries must
    /// break every derivation from every observable, which is strictly
    /// stronger than the witness-only obligation the solver computed. For
    /// single-observable journals (the standard corpus shape) the two
    /// obligations coincide.
    /// Like [`Self::verify_with_journal`] but with an explicit lineage override.
    pub fn verify_with_journal_allow_lineage(
        &self,
        journal: &Journal,
        allow_lineage: bool,
    ) -> Result<(), CertError> {
        if !allow_lineage {
            check_lineage_not_certifiable(journal)?;
        }
        self.verify()?;
        // Bind the certificate to its subject journal. A zero digest marks a
        // no-finding certificate (verify() enforces the pairing), which
        // attests nothing, so the root binding is skipped there.
        let subject_root = journal.root_hash();
        if self.subject.digest != [0u8; 32] && subject_root != self.subject.digest {
            return Err(CertError::Verification(format!(
                "subject digest mismatch: certificate attests {:02x?}, journal root is {:02x?}",
                &self.subject.digest[..4],
                &subject_root[..4]
            )));
        }
        let Some(minimality) = &self.minimality else {
            return Ok(());
        };
        if minimality.cut.is_empty() {
            return Ok(());
        }
        for id in &minimality.cut {
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
        // Recompute the exact cut cost from the journal; never trust a
        // persisted total.
        let exact_cost: u64 = minimality
            .cut
            .iter()
            .map(|id| event_fault_cost(journal, id))
            .sum();
        if minimality.lower_bound > exact_cost {
            return Err(CertError::Verification(format!(
                "tampered lower bound: {} exceeds the recomputed cut cost {}",
                minimality.lower_bound, exact_cost
            )));
        }
        if minimality.lower_bound == 0 {
            return Err(CertError::Verification(
                "lower-bound proof obligation: a non-empty cut costs at least 1 under the fault model, got lower_bound 0".into(),
            ));
        }
        // Rebuild the hazard from the journal's observable entries at the
        // certificate's RECORDED solver horizon and check the cut against
        // it. The obligation covers numeric-payload
        // Outcome and Assert entries: they are the witness class the
        // campaign oracles produce. The framework's terminal text-payload
        // outcome markers (the interpreter's `Done` instruction) are not
        // semantic observables and carry their own noise chains, so they
        // are excluded; a certificate over a journal with several semantic
        // observables must break every derivation from every one of them.
        let observables: Vec<Hash> = crate::oracle::witnesses_from_journal(journal)
            .into_iter()
            .filter(|id| {
                !journal.get(id).is_some_and(|entry| {
                    entry.data.kind == EntryKind::Outcome
                        && matches!(&entry.data.payload, Payload::Text(_))
                })
            })
            .collect();
        let horizon = minimality.horizon.unwrap_or(CERT_PATH_HORIZON);
        let paths = derivation_paths(journal, &observables, horizon);
        for (origin, path) in &paths {
            if !path.iter().any(|event| minimality.cut.contains(event)) {
                return Err(CertError::Verification(format!(
                    "forged cut: derivation path from observable entry {:02x?} is not broken by the cut",
                    &origin[..4]
                )));
            }
        }
        if !paths.is_empty() {
            for removed in &minimality.cut {
                let subset: Vec<Hash> = minimality
                    .cut
                    .iter()
                    .copied()
                    .filter(|id| id != removed)
                    .collect();
                let subset_hits_all = paths
                    .iter()
                    .all(|(_, path)| path.iter().any(|event| subset.contains(event)));
                if subset_hits_all {
                    return Err(CertError::Verification(format!(
                        "non-minimal cut: removing {:02x?} still breaks every derivation path",
                        &removed[..4]
                    )));
                }
            }
        }
        Ok(())
    }

    /// Verify the certificate against the journal, rejecting lineage-only
    /// journals. Use [`Self::verify_with_journal_allow_lineage`] to override.
    pub fn verify_with_journal(&self, journal: &Journal) -> Result<(), CertError> {
        self.verify_with_journal_allow_lineage(journal, false)
    }
}

/// Depth bound for the derivation-path recomputation, mirroring the solver's
/// default horizon (`HittingSetSolver::new`).
const CERT_PATH_HORIZON: usize = 64;

/// Every maximal faultable ancestor sequence of each observable entry,
/// paired with the observable's id.
///
/// Mirrors the hazard encoding's path collection: a sequence ends at a
/// parentless entry or at the depth bound. Non-faultable entries pass
/// through without joining the sequence.
fn derivation_paths(
    journal: &Journal,
    observables: &[Hash],
    limit: usize,
) -> Vec<(Hash, Vec<Hash>)> {
    let mut out = Vec::new();
    for origin in observables {
        let mut path = Vec::new();
        collect_derivation_paths(journal, *origin, 0, limit, *origin, &mut path, &mut out);
    }
    out
}

fn collect_derivation_paths(
    journal: &Journal,
    current: Hash,
    depth: usize,
    limit: usize,
    origin: Hash,
    path: &mut Vec<Hash>,
    out: &mut Vec<(Hash, Vec<Hash>)>,
) {
    if depth > limit {
        if !path.is_empty() {
            out.push((origin, path.clone()));
        }
        return;
    }
    let Some(entry) = journal.get(&current) else {
        return;
    };
    let faultable = is_faultable(entry.data.kind);
    if faultable {
        path.push(current);
    }
    if entry.data.parents.is_empty() {
        if !path.is_empty() {
            out.push((origin, path.clone()));
        }
    } else {
        for parent in &entry.data.parents {
            collect_derivation_paths(journal, *parent, depth + 1, limit, origin, path, out);
        }
    }
    if faultable {
        path.pop();
    }
}

/// Thin wrapper over [`CampaignCertificate::from_campaign`] with no extra
/// resolved dependencies.
///
/// This is the campaign-certificate helper for nightly and integration
/// callers that only need to attest the base [`RunConfig`] digest and the
/// builder identity.
pub fn certificate_for_report(
    report: &CampaignReport,
    run_config_digest: Hash,
    builder_id: &str,
) -> CampaignCertificate {
    CampaignCertificate::from_campaign(report, builder_id, Vec::new(), run_config_digest)
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
        let cert = certificate_for_report(self, run_config_digest, builder_id);
        let json = cert.to_json()?;
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
            journal_error: None,
            journal: j,
            decisions: Vec::new(),
            trace: Vec::new(),
            registers: Vec::new(),
            steps: 0,
            monitor_issues: Vec::new(),
            applied_faults: Vec::new(),
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
        let c = CampaignCertificate::from_campaign(&r, "builder-1", deps, [9u8; 32]);
        let j = c.to_json().unwrap();
        let b = CampaignCertificate::from_json(&j).unwrap();
        assert_eq!(c.subject, b.subject);
        assert_eq!(c.resolved_dependencies, b.resolved_dependencies);
        assert!(b.verify().is_ok());
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
            .write_certificate(&dir, [0u8; 32], "builder")
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
            .write_certificate(&cert_path, [0u8; 32], "builder")
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

    /// The happy path still writes a parseable, verifiable certificate after
    /// the error typing change.
    #[test]
    fn write_certificate_round_trips_to_disk() {
        let dir = unique_cert_dir("rt");
        let cert_path = dir.join("cert.json");
        with_finding()
            .write_certificate(&cert_path, [9u8; 32], "builder")
            .expect("write certificate");
        let bytes = std::fs::read(&cert_path).expect("read certificate");
        let text = String::from_utf8(bytes).expect("certificate must be utf8");
        let parsed = CampaignCertificate::from_json(&text).expect("parse certificate");
        assert!(parsed.verify().is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn verify_rejects_wrong_predicate_type() {
        let mut c = CampaignCertificate::from_campaign(&empty(10), "b", Vec::new(), [1u8; 32]);
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
        let mut c = CampaignCertificate::from_campaign(&with_finding(), "b", Vec::new(), [1u8; 32]);
        c.subject.digest = [0u8; 32];
        assert!(matches!(c.verify(), Err(CertError::Verification(_))));
    }
    #[test]
    fn verify_rejects_absent_or_malformed_subject() {
        let mut c = CampaignCertificate::from_campaign(&with_finding(), "b", Vec::new(), [1u8; 32]);
        c.subject.name = "  ".into();
        assert!(matches!(c.verify(), Err(CertError::Verification(_))));
        let mut c = CampaignCertificate::from_campaign(&empty(10), "b", Vec::new(), [1u8; 32]);
        c.subject.digest = [7u8; 32];
        assert!(
            matches!(c.verify(), Err(CertError::Verification(_))),
            "zero findings must not carry a subject digest"
        );
    }
    #[test]
    fn verify_accepts_single_send_cut_with_cost_lower_bound() {
        // A legitimate single-Send cut: lower_bound 2 is in COST units while
        // the cut holds one event; the old cardinality comparison rejected
        // exactly this certificate.
        let mut c = CampaignCertificate::from_campaign(&with_finding(), "b", Vec::new(), [1u8; 32]);
        c.minimality = Some(MinimalityExtension {
            cut: vec![[9u8; 32]],
            lower_bound: 2,
            method: "mcs-lower-bound-v1".into(),
            horizon: None,
        });
        assert!(c.verify().is_ok(), "{:?}", c.verify());
        let json = c.to_json().unwrap();
        assert!(
            CampaignCertificate::from_json(&json)
                .unwrap()
                .verify()
                .is_ok()
        );
    }
    #[test]
    fn verify_rejects_lower_bound_above_cut_event_cost() {
        let mut c = CampaignCertificate::from_campaign(&with_finding(), "b", Vec::new(), [1u8; 32]);
        c.minimality = Some(MinimalityExtension {
            cut: vec![[9u8; 32]],
            lower_bound: MAX_EVENT_COST + 1,
            method: "mcs-lower-bound-v1".into(),
            horizon: None,
        });
        assert!(matches!(c.verify(), Err(CertError::Verification(_))));
        // An empty cut admits no positive lower bound.
        let mut c2 = CampaignCertificate::from_campaign(&empty(4), "b", Vec::new(), [1u8; 32]);
        c2.minimality = Some(MinimalityExtension {
            cut: Vec::new(),
            lower_bound: 1,
            method: "mcs-lower-bound-v1".into(),
            horizon: None,
        });
        assert!(matches!(c2.verify(), Err(CertError::Verification(_))));
    }
    #[test]
    fn deterministic_serialization_order() {
        let r = empty(5);
        let a = CampaignCertificate::from_campaign(
            &r,
            "b",
            vec![
                ResolvedDependency {
                    name: "b".into(),
                    digest: [2u8; 32],
                },
                ResolvedDependency {
                    name: "a".into(),
                    digest: [1u8; 32],
                },
            ],
            [3u8; 32],
        );
        let b = CampaignCertificate::from_campaign(
            &r,
            "b",
            vec![
                ResolvedDependency {
                    name: "a".into(),
                    digest: [1u8; 32],
                },
                ResolvedDependency {
                    name: "b".into(),
                    digest: [2u8; 32],
                },
            ],
            [3u8; 32],
        );
        assert_eq!(a.to_json().unwrap(), b.to_json().unwrap());
    }

    // -----------------------------------------------------------------------
    // Journal-anchored verification: recomputed costs, cut validity, and
    // forged-certificate rejection.
    // -----------------------------------------------------------------------

    /// Two disjoint derivation paths to the observable: s1 via recv_a and s2
    /// via recv_b, plus an unrelated third send.
    fn two_path_journal() -> (Journal, Hash, Hash, Hash) {
        let mut journal = Journal::new();
        let s1 = journal
            .append(EntryKind::Send, 1, [], Payload::Pair { left: 2, right: 7 })
            .unwrap();
        let s2 = journal
            .append(EntryKind::Send, 2, [], Payload::Pair { left: 3, right: 9 })
            .unwrap();
        let junk = journal
            .append(EntryKind::Send, 3, [], Payload::Pair { left: 4, right: 1 })
            .unwrap();
        let recv_a = journal
            .append(EntryKind::Recv, 5, [s1], Payload::Number(0))
            .unwrap();
        let recv_b = journal
            .append(EntryKind::Recv, 5, [s2], Payload::Number(0))
            .unwrap();
        let _witness = journal
            .append(EntryKind::Outcome, 5, [recv_a, recv_b], Payload::Number(0))
            .unwrap();
        (journal, s1, s2, junk)
    }

    fn cert_with_minimality(
        journal: &Journal,
        cut: Vec<Hash>,
        lower_bound: u64,
    ) -> CampaignCertificate {
        let run = RunResult {
            journal_error: None,
            journal: journal.clone(),
            decisions: Vec::new(),
            trace: Vec::new(),
            registers: Vec::new(),
            steps: 0,
            monitor_issues: Vec::new(),
            applied_faults: Vec::new(),
        };
        let report = CampaignReport {
            runs_executed: 1,
            distinct_roots: 1,
            findings: vec![Finding {
                seed: [7u8; 32],
                run,
                verdict: Verdict::fail(vec![[7u8; 32]], "test"),
            }],
            variants: Vec::new(),
            monitors: Vec::new(),
            memo_hits: 0,
        };
        let mut certificate =
            CampaignCertificate::from_campaign(&report, "b", Vec::new(), [1u8; 32]);
        certificate.minimality = Some(MinimalityExtension {
            cut,
            lower_bound,
            method: "mcs-lower-bound-v1".into(),
            horizon: None,
        });
        certificate
    }

    #[test]
    fn verify_with_journal_accepts_a_real_cut_with_recomputed_cost() {
        let (journal, s1, s2, _junk) = two_path_journal();
        // The honest cut hits both paths; its exact recomputed cost is 4.
        let certificate = cert_with_minimality(&journal, vec![s1, s2], 4);
        assert!(
            certificate.verify_with_journal(&journal).is_ok(),
            "{:?}",
            certificate.verify_with_journal(&journal)
        );
    }

    #[test]
    fn verify_with_journal_rejects_a_tampered_lower_bound() {
        let (journal, s1, s2, _junk) = two_path_journal();
        let certificate = cert_with_minimality(&journal, vec![s1, s2], 5);
        let error = certificate.verify_with_journal(&journal).unwrap_err();
        assert!(
            format!("{error}").contains("tampered lower bound"),
            "{error}"
        );
    }

    #[test]
    fn verify_with_journal_rejects_a_zero_lower_bound_proof() {
        let (journal, s1, s2, _junk) = two_path_journal();
        let certificate = cert_with_minimality(&journal, vec![s1, s2], 0);
        let error = certificate.verify_with_journal(&journal).unwrap_err();
        assert!(
            format!("{error}").contains("lower-bound proof obligation"),
            "{error}"
        );
    }

    #[test]
    fn verify_with_journal_rejects_a_wrong_cut() {
        let (journal, s1, _s2, _junk) = two_path_journal();
        // Hitting only the first path: the second path stays unbroken.
        let certificate = cert_with_minimality(&journal, vec![s1], 2);
        let error = certificate.verify_with_journal(&journal).unwrap_err();
        assert!(format!("{error}").contains("derivation path"), "{error}");
    }

    #[test]
    fn verify_with_journal_rejects_an_unknown_cut_entry() {
        let (journal, _s1, _s2, junk) = two_path_journal();
        let bogus = [0xEE; 32];
        let certificate = cert_with_minimality(
            &journal,
            vec![junk, bogus],
            2 + event_fault_cost(&journal, &junk),
        );
        let error = certificate.verify_with_journal(&journal).unwrap_err();
        assert!(
            format!("{error}").contains("unknown journal entry"),
            "{error}"
        );
    }

    #[test]
    fn verify_with_journal_rejects_a_non_faultable_cut_entry() {
        let (journal, s1, s2, _junk) = two_path_journal();
        let mut with_marker = journal.clone();
        let marker = with_marker
            .append(EntryKind::Assert, 5, [], Payload::Number(1))
            .unwrap();
        let certificate = cert_with_minimality(&with_marker, vec![s1, s2, marker], 4 + 5);
        let error = certificate.verify_with_journal(&with_marker).unwrap_err();
        assert!(format!("{error}").contains("cannot inject"), "{error}");
    }

    #[test]
    fn verify_with_journal_rejects_a_non_minimal_cut() {
        let (journal, s1, s2, junk) = two_path_journal();
        // The junk send is in the journal and faultable, but the honest pair
        // already breaks every path: the cut is not minimal.
        let certificate = cert_with_minimality(
            &journal,
            vec![s1, s2, junk],
            4 + event_fault_cost(&journal, &junk),
        );
        let error = certificate.verify_with_journal(&journal).unwrap_err();
        assert!(format!("{error}").contains("non-minimal cut"), "{error}");
    }

    #[test]
    fn verify_with_journal_skips_path_checks_without_observables() {
        // A journal with no Outcome/Assert entries has no derivation paths;
        // the cut obligations reduce to existence and cost.
        let mut journal = Journal::new();
        let s1 = journal
            .append(EntryKind::Send, 1, [], Payload::Pair { left: 2, right: 7 })
            .unwrap();
        let s2 = journal
            .append(EntryKind::Send, 2, [], Payload::Pair { left: 3, right: 9 })
            .unwrap();
        let certificate = cert_with_minimality(&journal, vec![s1, s2], 4);
        assert!(certificate.verify_with_journal(&journal).is_ok());
    }

    #[test]
    fn verify_with_journal_rejects_a_different_subject_journal() {
        // The certificate is attested against journal A. Journal B has the
        // same structure (two sends, two receives, one outcome) with
        // different values, so every structural obligation could be
        // satisfied; the subject-digest binding must reject it first with a
        // typed error naming the mismatch.
        let (journal_a, s1, s2, _junk) = two_path_journal();
        let certificate = cert_with_minimality(&journal_a, vec![s1, s2], 4);
        assert!(
            certificate.verify_with_journal(&journal_a).is_ok(),
            "the certificate must verify against its own subject journal"
        );

        let mut journal_b = Journal::new();
        let b1 = journal_b
            .append(EntryKind::Send, 1, [], Payload::Pair { left: 2, right: 77 })
            .unwrap();
        let b2 = journal_b
            .append(EntryKind::Send, 2, [], Payload::Pair { left: 3, right: 99 })
            .unwrap();
        let b_recv_a = journal_b
            .append(EntryKind::Recv, 5, [b1], Payload::Number(0))
            .unwrap();
        let b_recv_b = journal_b
            .append(EntryKind::Recv, 5, [b2], Payload::Number(0))
            .unwrap();
        let _b_witness = journal_b
            .append(
                EntryKind::Outcome,
                5,
                [b_recv_a, b_recv_b],
                Payload::Number(0),
            )
            .unwrap();
        assert_ne!(
            journal_a.root_hash(),
            journal_b.root_hash(),
            "the two subject journals must differ"
        );
        let error = certificate.verify_with_journal(&journal_b).unwrap_err();
        assert!(
            format!("{error}").contains("subject digest mismatch"),
            "the rejection must name the digest mismatch: {error}"
        );
    }

    #[test]
    fn verify_with_journal_binds_even_without_a_minimality_extension() {
        // Even without a minimality extension the journal binding holds: the
        // certificate attests a specific journal root, not any journal.
        let (journal, _s1, _s2, _junk) = two_path_journal();
        let report = CampaignReport {
            runs_executed: 1,
            distinct_roots: 1,
            findings: vec![Finding {
                seed: [7u8; 32],
                run: RunResult {
                    journal_error: None,
                    journal: journal.clone(),
                    decisions: Vec::new(),
                    trace: Vec::new(),
                    registers: Vec::new(),
                    steps: 0,
                    monitor_issues: Vec::new(),
                    applied_faults: Vec::new(),
                },
                verdict: Verdict::fail(vec![[7u8; 32]], "test"),
            }],
            variants: Vec::new(),
            monitors: Vec::new(),
            memo_hits: 0,
        };
        let certificate = CampaignCertificate::from_campaign(&report, "b", Vec::new(), [1u8; 32]);
        assert!(certificate.minimality.is_none());
        assert!(certificate.verify_with_journal(&journal).is_ok());
        let mut other = journal.clone();
        other
            .append(EntryKind::Send, 1, [], Payload::Pair { left: 2, right: 7 })
            .unwrap();
        let error = certificate.verify_with_journal(&other).unwrap_err();
        assert!(
            format!("{error}").contains("subject digest mismatch"),
            "the binding must hold without a minimality extension: {error}"
        );
    }

    /// A six-deep faultable chain so the horizon cuts the derivation into
    /// distinguishable hazards: `outcome <- recv <- s5 <- s4 <- s3 <- s2 <- s1`.
    /// Every send uses a distinct actor so the explicit parent is the only
    /// parent edge (no accidental same-actor head chaining).
    fn deep_chain_journal() -> (Journal, Vec<Hash>) {
        let mut journal = Journal::new();
        let mut ids = Vec::new();
        for index in 1..=5u64 {
            let id = journal
                .append(
                    EntryKind::Send,
                    index as u32,
                    ids.last().copied().into_iter().collect::<Vec<_>>(),
                    Payload::Pair {
                        left: 2,
                        right: index,
                    },
                )
                .unwrap();
            ids.push(id);
        }
        let recv = journal
            .append(EntryKind::Recv, 6, [ids[4]], Payload::Number(0))
            .unwrap();
        journal
            .append(EntryKind::Outcome, 6, [recv], Payload::Number(0))
            .unwrap();
        (journal, ids)
    }

    #[test]
    fn verify_with_journal_honors_the_recorded_solver_horizon() {
        // The cut targets a DEEP event (s4) of the chain. Whether it breaks
        // the hazard depends on the horizon the solver solved under:
        // recorded horizon 64 (or legacy None) sees the deep path and
        // accepts; recorded horizon 2 must REJECT, because the hazard it
        // certifies only reaches s5. The verifier must re-derive at the
        // recorded horizon, not at a hard-coded one.
        let (journal, ids) = deep_chain_journal();
        let deep_cut = vec![ids[3]];
        let deep_cost = event_fault_cost(&journal, &ids[3]);

        let deep_64 = cert_with_minimality(&journal, deep_cut.clone(), deep_cost);
        assert_eq!(deep_64.minimality.as_ref().unwrap().horizon, None);
        assert!(
            deep_64.verify_with_journal(&journal).is_ok(),
            "legacy certs without a recorded horizon verify at the default 64"
        );

        let mut recorded_64 = cert_with_minimality(&journal, deep_cut.clone(), deep_cost);
        recorded_64.minimality.as_mut().unwrap().horizon = Some(64);
        assert!(
            recorded_64.verify_with_journal(&journal).is_ok(),
            "a cut covering the deep path must verify at its recorded horizon 64"
        );

        let mut recorded_2 = cert_with_minimality(&journal, deep_cut, deep_cost);
        recorded_2.minimality.as_mut().unwrap().horizon = Some(2);
        let error = recorded_2.verify_with_journal(&journal).unwrap_err();
        assert!(
            format!("{error}").contains("derivation path"),
            "a cut covering only the deep hazard must FAIL when the certificate claims horizon 2: {error}"
        );

        // Cross-check the horizon-2 hazard: a cut on the shallow events
        // (s5 or the recv) verifies fine under the recorded horizon 2.
        let shallow_cut = vec![ids[4]];
        let mut recorded_2_shallow = cert_with_minimality(&journal, shallow_cut, 2);
        recorded_2_shallow.minimality.as_mut().unwrap().horizon = Some(2);
        assert!(
            recorded_2_shallow.verify_with_journal(&journal).is_ok(),
            "a cut covering the shallow hazard must verify at its recorded horizon 2"
        );
    }

    #[test]
    fn minimality_horizon_survives_serialization_roundtrip() {
        let (journal, ids) = deep_chain_journal();
        let mut certificate = cert_with_minimality(&journal, vec![ids[0]], 2);
        certificate.minimality.as_mut().unwrap().horizon = Some(3);
        let json = certificate.to_json().unwrap();
        let decoded = CampaignCertificate::from_json(&json).unwrap();
        assert_eq!(
            decoded.minimality.as_ref().unwrap().horizon,
            Some(3),
            "the recorded horizon must survive the JSON roundtrip"
        );
        // And a legacy certificate without the field decodes to None.
        let mut legacy = cert_with_minimality(&journal, vec![ids[0]], 2);
        legacy.minimality.as_mut().unwrap().horizon = None;
        let json = legacy.to_json().unwrap();
        let decoded = CampaignCertificate::from_json(&json).unwrap();
        assert_eq!(decoded.minimality.as_ref().unwrap().horizon, None);
    }

    #[test]
    fn lineage_only_journal_cannot_certify() {
        let mut journal = Journal::new();
        journal
            .append(
                EntryKind::Epoch,
                0,
                [],
                Payload::Text("lineage-only".to_string()),
            )
            .unwrap();
        journal
            .append(EntryKind::Send, 1, [], Payload::Pair { left: 2, right: 7 })
            .unwrap();
        let run = RunResult {
            journal_error: None,
            journal: journal.clone(),
            decisions: Vec::new(),
            trace: Vec::new(),
            registers: Vec::new(),
            steps: 0,
            monitor_issues: Vec::new(),
            applied_faults: Vec::new(),
        };
        let report = CampaignReport {
            runs_executed: 1,
            distinct_roots: 1,
            findings: vec![Finding {
                seed: [7u8; 32],
                run,
                verdict: Verdict::fail(vec![[7u8; 32]], "test"),
            }],
            variants: Vec::new(),
            monitors: Vec::new(),
            memo_hits: 0,
        };
        // from_campaign rejects lineage-only unless overridden.
        assert!(
            CampaignCertificate::from_campaign_allow_lineage(
                &report,
                "b",
                Vec::new(),
                [1u8; 32],
                false
            )
            .is_err(),
            "lineage-only must be rejected"
        );
        let cert = CampaignCertificate::from_campaign_allow_lineage(
            &report,
            "b",
            Vec::new(),
            [1u8; 32],
            true,
        )
        .expect("allow_lineage must succeed");
        // verify_with_journal also rejects unless overridden.
        let error = cert.verify_with_journal(&journal).unwrap_err();
        assert!(
            format!("{error}").contains("lineage-only"),
            "verify must mention lineage-only: {error}"
        );
        assert!(
            cert.verify_with_journal_allow_lineage(&journal, true)
                .is_ok(),
            "allow_lineage must pass"
        );
    }
}
