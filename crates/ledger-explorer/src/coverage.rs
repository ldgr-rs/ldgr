#![deny(unsafe_code)]

//! Exploration coverage export for campaign data.
//!
//! "Coverage" here means scenario-space exploration coverage:
//! `distinct journal roots / runs executed`, derived from campaign journals
//! and exported in CI-renderable formats (lcov, SARIF, JaCoCo).
//!
//! Input for the CLI is NDJSON of `{root_hex, run_index, finding}` lines
//! produced by campaigns. Use [`CoverageBuilder`] for incremental collection
//! at call sites where `RunResult` values exist.

use std::collections::HashSet;

use ledger_format::EntryHash;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::search::CampaignReport;

/// One distinct journal root observed during a campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootRecord {
    /// Lowercase 64-char hex of the journal root hash.
    pub root_hex: String,
    /// Zero-based run index that produced this root.
    pub run_index: usize,
    /// Whether the run produced an oracle finding.
    pub finding: bool,
}

/// Exploration coverage aggregated from a campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageReport {
    /// Total runs executed (attempts).
    pub total_runs: usize,
    /// Number of distinct journal root hashes.
    pub distinct_roots: usize,
    /// Number of runs that produced a finding.
    pub findings: usize,
    /// Per-root records sorted by `run_index` after building.
    pub roots: Vec<RootRecord>,
}

/// Error from coverage export serialization.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CovError {
    #[error("serialization: {0}")]
    Serialization(String),
}

/// Incremental builder for [`CoverageReport`].
///
/// Records are accumulated out of order and sorted on `finish`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CoverageBuilder {
    records: Vec<RootRecord>,
}

impl CoverageBuilder {
    /// Create an empty builder.
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Record a root hash for one run.
    pub fn record(&mut self, root: EntryHash, run_index: usize, finding: bool) {
        let hex = ledger_format::hash_to_hex(&root);
        self.records.push(RootRecord {
            root_hex: hex,
            run_index,
            finding,
        });
    }

    /// Record a pre-encoded hex string for one run.
    ///
    /// The hex must be 64 lowercase hex digits, otherwise an error is returned.
    pub fn record_hex(
        &mut self,
        root_hex: String,
        run_index: usize,
        finding: bool,
    ) -> Result<(), CovError> {
        if root_hex.len() != 64 || !root_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(CovError::Serialization(format!(
                "root_hex must be 64 hex chars, got {}",
                root_hex.len()
            )));
        }
        self.records.push(RootRecord {
            root_hex: root_hex.to_ascii_lowercase(),
            run_index,
            finding,
        });
        Ok(())
    }

    /// Number of records accumulated so far.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// True when no records have been added.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Finish the build into a sorted [`CoverageReport`].
    ///
    /// `total_runs` is the total attempts of the campaign. When zero and
    /// records exist, `max(run_index)+1` is used. Records are sorted by
    /// `run_index` for deterministic output. `distinct_roots` counts unique
    /// `root_hex` values, `findings` counts records where `finding` is true.
    pub fn finish(mut self, total_runs: usize) -> CoverageReport {
        self.records.sort_by_key(|record| record.run_index);
        let distinct = {
            let mut set: HashSet<&str> = HashSet::new();
            for record in &self.records {
                set.insert(record.root_hex.as_str());
            }
            set.len()
        };
        let findings = self.records.iter().filter(|record| record.finding).count();
        let total = if total_runs == 0 && !self.records.is_empty() {
            self.records
                .iter()
                .map(|record| record.run_index + 1)
                .max()
                .unwrap_or(0)
                .max(self.records.len())
        } else {
            total_runs
        };
        let distinct_roots = distinct;
        CoverageReport {
            total_runs: total,
            distinct_roots,
            findings,
            roots: self.records,
        }
    }
}

impl CoverageReport {
    /// Derive a report from a [`CampaignReport`] aggregate.
    ///
    /// Only finding roots are available from [`CampaignReport`]; non-finding
    /// distinct roots cannot be reconstructed from aggregates alone. This
    /// constructor emits one record per finding (with the true journal root
    /// hex) and preserves `distinct_roots` and `runs_executed` as counts for
    /// export totals. For per-run tracking with complete root hexes, use
    /// [`CoverageBuilder`] at call sites where each `RunResult` is available.
    pub fn from_campaign(report: &CampaignReport) -> Self {
        let mut builder = CoverageBuilder::new();
        for (index, finding) in report.findings.iter().enumerate() {
            let root = finding.run.journal.root_hash();
            builder.record(root, index, true);
        }
        let mut out = builder.finish(report.runs_executed);
        // Preserve the campaign-level distinct count even when builder sees
        // fewer unique hexes (findings only).
        out.distinct_roots = report.distinct_roots;
        out.findings = report.findings.len();
        // When there were no findings but distinct roots existed, roots stays
        // empty and exporters use the aggregate counts for LF/LH.
        out
    }
}

fn sorted_roots(report: &CoverageReport) -> Vec<RootRecord> {
    let mut sorted = report.roots.clone();
    sorted.sort_by_key(|record| record.run_index);
    sorted
}

/// Export coverage as lcov tracefile format.
///
/// - `SF:ledger-campaign` is the source file marker.
/// - Each distinct root is one `DA` line: `DA:<run_index+1>,<1 if finding else 0>`.
/// - `LF` is `distinct_roots`, `LH` is `findings`.
/// - Deterministic: records sorted by `run_index` before emission.
pub fn to_lcov(report: &CoverageReport) -> String {
    let sorted = sorted_roots(report);
    let mut out = String::new();
    out.push_str("TN:\n");
    out.push_str("SF:ledger-campaign\n");
    for record in &sorted {
        let count = if record.finding { 1 } else { 0 };
        out.push_str(&format!("DA:{},{count}\n", record.run_index + 1));
    }
    out.push_str(&format!("LF:{}\n", report.distinct_roots));
    out.push_str(&format!("LH:{}\n", report.findings));
    out.push_str("end_of_record\n");
    out
}

/// Export coverage as SARIF 2.1.0 JSON.
///
/// Each root record becomes one result: level `error` for findings, `note`
/// for covered non-finding roots, with the root hex in the message text.
/// Deterministic: results sorted by `run_index`.
pub fn to_sarif(report: &CoverageReport) -> Result<String, CovError> {
    let sorted = sorted_roots(report);
    let results: Vec<serde_json::Value> = sorted
        .iter()
        .map(|record| {
            let level = if record.finding { "error" } else { "note" };
            let kind = if record.finding { "finding" } else { "covered" };
            serde_json::json!({
                "ruleId": format!("ldgr/coverage/{kind}"),
                "level": level,
                "message": {"text": format!("root {} run {} {}", record.root_hex, record.run_index, kind)},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "ledger-campaign"},
                        "region": {"startLine": record.run_index + 1}
                    }
                }]
            })
        })
        .collect();
    let sarif = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ldgr",
                    "informationUri": crate::attest_uri::tool_information_uri(),
                    "rules": []
                }
            },
            "results": results
        }]
    });
    serde_json::to_string(&sarif).map_err(|error| CovError::Serialization(error.to_string()))
}

/// Export coverage as minimal JaCoCo XML.
///
/// Produces `<report><counter type="LINE" missed=.. covered=.. />`.
/// `missed = distinct_roots - findings`, `covered = findings`.
/// Deterministic: single counter element.
pub fn to_jacoco(report: &CoverageReport) -> Result<String, CovError> {
    let missed = report.distinct_roots.saturating_sub(report.findings);
    let covered = report.findings;
    // Build XML by hand for determinism and no extra dependencies.
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<report name=\"ledger-campaign\">\n\
  <counter type=\"LINE\" missed=\"{missed}\" covered=\"{covered}\"/>\n\
  <counter type=\"INSTRUCTION\" missed=\"{missed}\" covered=\"{covered}\"/>\n\
</report>\n"
    );
    Ok(xml)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_format::ActorId;
    use ledger_journal::Journal;
    use ledger_sim::RunResult;

    fn hash_of(byte: u8) -> EntryHash {
        EntryHash([byte; 32])
    }

    #[test]
    fn builder_accumulates_and_sorts() {
        let mut builder = CoverageBuilder::new();
        builder.record(hash_of(2), 2, false);
        builder.record(hash_of(1), 1, true);
        builder.record(hash_of(0), 0, false);
        assert_eq!(builder.len(), 3);
        let report = builder.finish(3);
        assert_eq!(report.total_runs, 3);
        assert_eq!(report.distinct_roots, 3);
        assert_eq!(report.findings, 1);
        assert_eq!(report.roots[0].run_index, 0);
        assert_eq!(report.roots[1].run_index, 1);
        assert_eq!(report.roots[2].run_index, 2);
        assert!(report.roots[1].finding);
        assert!(!report.roots[0].finding);
    }

    #[test]
    fn builder_dedup_distinct() {
        let mut builder = CoverageBuilder::new();
        builder.record(hash_of(1), 0, true);
        builder.record(hash_of(1), 1, true);
        let report = builder.finish(2);
        assert_eq!(report.distinct_roots, 1);
        assert_eq!(report.findings, 2);
        assert_eq!(report.total_runs, 2);
    }

    #[test]
    fn builder_record_and_hex_validation() {
        let mut builder = CoverageBuilder::new();
        builder.record(hash_of(7), 0, true);
        assert!(builder.record_hex("00".repeat(32), 1, false).is_ok());
        assert!(builder.record_hex("invalid".to_string(), 2, false).is_err());
        assert!(builder.record_hex("00".repeat(63), 3, false).is_err());
        let report = builder.finish(2);
        assert_eq!(report.findings, 1);
        assert_eq!(
            report.roots[0].root_hex,
            ledger_format::hash_to_hex(&hash_of(7))
        );
    }

    #[test]
    fn lcov_contains_da_and_end() {
        let mut builder = CoverageBuilder::new();
        builder.record(hash_of(1), 0, true);
        builder.record(hash_of(2), 1, false);
        let report = builder.finish(2);
        let lcov = to_lcov(&report);
        assert!(lcov.contains("SF:ledger-campaign"), "missing SF: {lcov}");
        assert!(lcov.contains("DA:1,1"), "missing DA 1: {lcov}");
        assert!(lcov.contains("DA:2,0"), "missing DA 2: {lcov}");
        assert!(lcov.contains("LF:2"), "missing LF: {lcov}");
        assert!(lcov.contains("LH:1"), "missing LH: {lcov}");
        assert!(
            lcov.contains("end_of_record"),
            "missing end_of_record: {lcov}"
        );
        assert!(lcov.starts_with("TN:\n"), "should start with TN: {lcov}");
    }

    #[test]
    fn sarif_parses_with_version() {
        let mut builder = CoverageBuilder::new();
        builder.record(hash_of(9), 0, true);
        builder.record(hash_of(10), 1, false);
        let report = builder.finish(2);
        let json = to_sarif(&report).expect("sarif must serialize");
        let value: serde_json::Value = serde_json::from_str(&json).expect("must be JSON");
        assert_eq!(value["version"], "2.1.0");
        let results = value["runs"][0]["results"]
            .as_array()
            .expect("results array");
        assert_eq!(results.len(), 2);
        let levels: Vec<&str> = results
            .iter()
            .map(|value| value["level"].as_str().unwrap())
            .collect();
        assert!(levels.contains(&"error"));
        assert!(levels.contains(&"note"));
        let messages: Vec<&str> = results
            .iter()
            .map(|value| value["message"]["text"].as_str().unwrap())
            .collect();
        assert!(
            messages
                .iter()
                .any(|message| message.contains(&ledger_format::hash_to_hex(&hash_of(9))))
        );
    }

    #[test]
    fn jacoco_has_counter() {
        let mut builder = CoverageBuilder::new();
        builder.record(hash_of(3), 0, true);
        builder.record(hash_of(4), 1, false);
        builder.record(hash_of(5), 2, false);
        let report = builder.finish(3);
        let xml = to_jacoco(&report).expect("jacoco must serialize");
        assert!(xml.contains("<counter"), "missing counter: {xml}");
        assert!(xml.contains("type=\"LINE\""), "missing LINE counter: {xml}");
        assert!(xml.contains("missed=\"2\""), "missed should be 2: {xml}");
        assert!(xml.contains("covered=\"1\""), "covered should be 1: {xml}");
        assert!(
            xml.contains("<report name=\"ledger-campaign\">"),
            "missing report: {xml}"
        );
    }

    #[test]
    fn determinism_byte_identical() {
        let build = || {
            let mut builder = CoverageBuilder::new();
            builder.record(hash_of(5), 1, false);
            builder.record(hash_of(6), 0, true);
            let report = builder.finish(2);
            (
                to_lcov(&report),
                to_sarif(&report).unwrap(),
                to_jacoco(&report).unwrap(),
            )
        };
        let first = build();
        let second = build();
        assert_eq!(first.0, second.0);
        assert_eq!(first.1, second.1);
        assert_eq!(first.2, second.2);
    }

    #[test]
    fn determinism_sorted_regardless_of_insertion_order() {
        let mut first = CoverageBuilder::new();
        first.record(hash_of(2), 2, true);
        first.record(hash_of(0), 0, false);
        first.record(hash_of(1), 1, true);
        let first_report = first.finish(3);
        let mut second = CoverageBuilder::new();
        second.record(hash_of(0), 0, false);
        second.record(hash_of(1), 1, true);
        second.record(hash_of(2), 2, true);
        let second_report = second.finish(3);
        assert_eq!(to_lcov(&first_report), to_lcov(&second_report));
        assert_eq!(
            to_sarif(&first_report).unwrap(),
            to_sarif(&second_report).unwrap()
        );
    }

    #[test]
    fn empty_report_exports() {
        let builder = CoverageBuilder::new();
        let report = builder.finish(0);
        let lcov = to_lcov(&report);
        assert!(lcov.contains("LF:0"));
        assert!(lcov.contains("LH:0"));
        let sarif_json = to_sarif(&report).unwrap();
        let value: serde_json::Value = serde_json::from_str(&sarif_json).unwrap();
        assert_eq!(value["version"], "2.1.0");
        let results = value["runs"][0]["results"].as_array().unwrap();
        assert!(results.is_empty());
        let jacoco = to_jacoco(&report).unwrap();
        assert!(jacoco.contains("missed=\"0\""));
        assert!(jacoco.contains("covered=\"0\""));
    }

    #[test]
    fn from_campaign_preserves_counts() {
        use crate::oracle::Verdict;
        use crate::search::{CampaignReport, Finding};
        use ledger_format::{CanonicalValue, EntryKind, EntryPayload};
        let mut journal = Journal::new();
        journal
            .append(
                EntryKind::Outcome,
                ActorId(0),
                [],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: EntryHash([0x00; 32]),
                    value: CanonicalValue::Unsigned(1),
                }),
            )
            .unwrap();
        let run = RunResult {
            outcome: ledger_sim::RunOutcome::Completed,
            journal_error: None,
            journal,
            decisions: Vec::new(),
            trace: Vec::new(),
            registers: Vec::new(),
            steps: 0,
            monitor_issues: Vec::new(),
            applied_faults: Vec::new(),
            origins: Vec::new(),
            protection: ledger_sim::BeltStatus::NotArmed,
        };
        let root_hex = ledger_format::hash_to_hex(&run.journal.root_hash());
        let report = CampaignReport {
            runs_executed: 5,
            distinct_roots: 3,
            findings: vec![Finding {
                seed: EntryHash([1u8; 32]),
                run,
                verdict: Verdict::fail(vec![EntryHash([1u8; 32])], "test"),
            }],
            variants: vec!["a".into(), "b".into(), "c".into(), "d".into(), "e".into()],
            monitors: Vec::new(),
            memo_hits: 0,
        };
        let coverage = CoverageReport::from_campaign(&report);
        assert_eq!(coverage.total_runs, 5);
        assert_eq!(coverage.distinct_roots, 3);
        assert_eq!(coverage.findings, 1);
        assert_eq!(coverage.roots.len(), 1);
        assert_eq!(coverage.roots[0].root_hex, root_hex);
        assert!(coverage.roots[0].finding);
    }
}
