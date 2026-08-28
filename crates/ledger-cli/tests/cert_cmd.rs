use std::error::Error as _;
use std::path::PathBuf;

use ledger_explorer::search::CampaignReport;
use ledger_explorer::{
    CampaignCertificate, RecordedSolverData, ResolvedDependency, StatisticalBound,
    predicate_type_campaign_v1,
};

fn temp_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ldgr-cert-{name}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir.join(format!("{name}.json"))
}

fn make_report(runs: usize) -> CampaignReport {
    CampaignReport {
        runs_executed: runs,
        distinct_roots: runs,
        findings: Vec::new(),
        variants: Vec::new(),
        monitors: Vec::new(),
        memo_hits: 0,
    }
}

fn write_cert(path: &PathBuf, json: &str) {
    std::fs::write(path, json).unwrap();
}

#[test]
fn cert_verify_human_valid() {
    let report = make_report(10);
    let cert = CampaignCertificate::from_campaign(&report, "builder-test", Vec::new(), [1u8; 32])
        .expect("valid report must create a certificate");
    let json = cert.to_json().unwrap();
    let path = temp_path("valid-human");
    write_cert(&path, &json);

    let out = ledger_cli::cert_cmd::run_verify(&path, None, false).unwrap();
    assert!(
        out.contains("certificate valid"),
        "output missing valid marker: {out}"
    );
    assert!(
        out.contains("mode: statement-validated"),
        "output has wrong mode label: {out}"
    );
    assert!(
        out.contains("subject digest"),
        "missing subject digest: {out}"
    );
    assert!(
        out.contains(&predicate_type_campaign_v1()),
        "missing predicate type: {out}"
    );
    assert!(out.contains("runs:"), "missing runs: {out}");
    assert!(out.contains("findings:"), "missing findings: {out}");
    assert!(out.contains("solver data:"), "missing solver data: {out}");
    assert!(out.contains("statistical:"), "missing statistical: {out}");
    // digest hex should appear
    let digest_hex: String = cert
        .subject
        .digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(out.contains(&digest_hex), "missing digest hex: {out}");
}

#[test]
fn cert_verify_json_valid() {
    let report = make_report(20);
    let deps = vec![ResolvedDependency {
        name: "dep-a".into(),
        digest: [2u8; 32],
    }];
    let mut cert = CampaignCertificate::from_campaign(&report, "builder-json", deps, [9u8; 32])
        .expect("valid report must create a certificate");
    cert.solver_data = Some(RecordedSolverData {
        cut: vec![[3u8; 32], [4u8; 32]],
        recorded_lower_bound: 1,
        method: "test-method".into(),
        horizon: Some(64),
    });
    cert.statistical = Some(StatisticalBound {
        upper_p: 0.01,
        confidence: 0.95,
        method: "rule-of-three-v1".into(),
    });
    let json = cert.to_json().unwrap();
    let path = temp_path("valid-json");
    write_cert(&path, &json);

    let out = ledger_cli::cert_cmd::run_verify(&path, None, true).unwrap();
    assert!(out.contains("\"valid\":true"), "json missing valid: {out}");
    assert!(
        out.contains(&predicate_type_campaign_v1()),
        "json missing predicate: {out}"
    );
    assert!(
        out.contains("\"runs_executed\""),
        "json missing runs: {out}"
    );
    assert!(
        out.contains("\"findings_count\""),
        "json missing findings: {out}"
    );
    assert!(
        out.contains("\"solver_data\""),
        "json missing solver data: {out}"
    );
    assert!(
        out.contains("\"statistical\""),
        "json missing statistical: {out}"
    );
    // json should be parseable
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["valid"], true);
    assert_eq!(parsed["mode"], "statement-validated");
    assert_eq!(parsed["runs_executed"], 20);
}

#[test]
fn cert_verify_tampered_predicate_fails() {
    let report = make_report(10);
    let cert = CampaignCertificate::from_campaign(&report, "builder-test", Vec::new(), [1u8; 32])
        .expect("valid report must create a certificate");
    let mut json = cert.to_json().unwrap();
    // tamper predicateType
    let tampered = format!(
        "{}/attestations/wrong/v1",
        ledger_explorer::attestation_base()
    );
    json = json.replace(&predicate_type_campaign_v1(), &tampered);
    let path = temp_path("tampered-predicate");
    write_cert(&path, &json);

    let err = ledger_cli::cert_cmd::run_verify(&path, None, false).unwrap_err();
    let lower = err.to_string().to_lowercase();
    assert!(
        lower.contains("predicate") || lower.contains("verification") || lower.contains("schema"),
        "error should mention predicate/schema/verification, got: {err}"
    );
}

#[test]
fn cert_verify_preserves_journal_open_error_source() {
    let report = make_report(10);
    let cert = CampaignCertificate::from_campaign(&report, "builder-test", Vec::new(), [1u8; 32])
        .expect("valid report must create a certificate");
    let cert_path = temp_path("journal-source-cert");
    write_cert(
        &cert_path,
        &cert.to_json().expect("certificate must serialize"),
    );
    let journal_path = temp_path("journal-source-invalid");
    write_cert(&journal_path, "not a journal directory");

    let error = ledger_cli::cert_cmd::run_verify(&cert_path, Some(&journal_path), false)
        .expect_err("invalid journal path must fail");
    assert!(
        matches!(error, ledger_cli::cert_cmd::CertVerifyError::JournalOpen(_)),
        "journal open must keep its dedicated error variant: {error:?}"
    );
    let source = error.source().expect("journal error must be a source");
    assert!(
        source
            .downcast_ref::<ledger_journal::JournalError>()
            .is_some(),
        "source must retain ledger_journal::JournalError, got {source:?}"
    );
}

#[test]
fn cert_verify_invalid_json_schema_error() {
    let path = temp_path("invalid-json");
    write_cert(&path, r#"{"not": "a certificate"}"#);
    let err = ledger_cli::cert_cmd::run_verify(&path, None, false).unwrap_err();
    let lower = err.to_string().to_lowercase();
    assert!(
        lower.contains("schema"),
        "invalid json should be schema error, got: {err}"
    );
}
