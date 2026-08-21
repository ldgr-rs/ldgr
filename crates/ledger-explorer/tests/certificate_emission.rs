use ledger_explorer::CampaignCertificate;
use ledger_explorer::MaxSatSolver;
use ledger_explorer::certs::MAX_EVENT_COST;
use ledger_explorer::oracle::{HistoryOracle, KeyValueSpec};
use ledger_explorer::search::run_campaign;
use ledger_explorer::workloads::MiniKvWorkload;
use ledger_sim::{Policy, RunConfig};

fn temp_cert_path(name: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("ldgr-cert-emission-{name}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir.join("campaign-certificate.json")
}

#[test]
fn certificate_write_and_verify_roundtrip() {
    let config = RunConfig::builder()
        .seed([0; 32])
        .policy(Policy::Random)
        .max_steps(256)
        .build();
    let workload = MiniKvWorkload;
    let oracle = HistoryOracle::new(&workload, KeyValueSpec::default());
    let report = run_campaign(&workload, &oracle, config.clone(), 10).unwrap();
    let digest = *blake3::hash(&config.seed()).as_bytes();
    let builder = "test-builder-certificate-emission";
    let path = temp_cert_path("roundtrip");
    report
        .write_certificate(&path, digest, builder)
        .expect("write_certificate must succeed");
    let json = std::fs::read_to_string(&path).expect("certificate file must be readable");
    assert!(
        json.contains("\"_type\":\"https://in-toto.io/Statement/v1\""),
        "JSON must contain in-toto Statement _type, got: {json}"
    );
    let cert = CampaignCertificate::from_json(&json).expect("from_json must parse");
    assert!(
        cert.verify().is_ok(),
        "verify must succeed: {:?}",
        cert.verify()
    );
    // Re-encode and verify deterministic builder and digest.
    assert_eq!(cert.builder_id, builder);
    assert_eq!(cert.external_parameters_digest, digest);
    assert_eq!(cert.runs_executed, report.runs_executed);
    assert_eq!(cert.findings_count, report.findings.len());
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn certificate_for_report_helper_is_equivalent() {
    let config = RunConfig::builder()
        .seed([3; 32])
        .policy(Policy::Random)
        .max_steps(64)
        .build();
    let report = run_campaign(
        &MiniKvWorkload,
        &HistoryOracle::new(&MiniKvWorkload, KeyValueSpec::default()),
        config.clone(),
        5,
    )
    .unwrap();
    let digest = [7u8; 32];
    let builder = "helper-builder";
    let cert_a = ledger_explorer::certificate_for_report(&report, digest, builder);
    let cert_b =
        ledger_explorer::CampaignCertificate::from_campaign(&report, builder, Vec::new(), digest);
    assert_eq!(cert_a.builder_id, cert_b.builder_id);
    assert_eq!(
        cert_a.external_parameters_digest,
        cert_b.external_parameters_digest
    );
    assert_eq!(cert_a.runs_executed, cert_b.runs_executed);
    assert_eq!(cert_a.to_json().unwrap(), cert_b.to_json().unwrap());
}

/// End-to-end minimality certificate: a real violating sim, a real weighted
/// MaxSAT cut with its lower-bound proof, and `verify()` accepting the
/// result. A tampered lower_bound above the cut's summed event cost must be
/// rejected.
#[test]
fn minimality_certificate_from_real_cut_verifies() {
    let config = RunConfig::builder()
        .seed([0; 32])
        .policy(Policy::Random)
        .max_steps(256)
        .build();
    let workload = MiniKvWorkload;
    let oracle = HistoryOracle::new(&workload, KeyValueSpec::default());
    let report = run_campaign(&workload, &oracle, config, 256)
        .unwrap_or_else(|error| panic!("campaign must run: {error}"));
    let finding = report
        .findings
        .first()
        .expect("the campaign must find the stale-read violation");

    let mut solver = MaxSatSolver::default();
    let (hypotheses, extension) = solver
        .solve_with_certificate(&finding.run.journal, &finding.verdict)
        .expect("weighted MaxSAT solve must succeed");
    assert!(!extension.cut.is_empty(), "the real cut must be non-empty");
    assert!(
        extension.lower_bound <= hypotheses[0].total_cost,
        "the lower bound must not exceed the solved cut cost"
    );

    let mut certificate = CampaignCertificate::from_campaign(
        &report,
        "test-builder-minimality",
        Vec::new(),
        [2u8; 32],
    );
    certificate.minimality = Some(extension.clone());
    assert!(
        certificate.verify().is_ok(),
        "verify must accept the real cut: {:?}",
        certificate.verify()
    );
    // Journal-anchored verification recomputes the exact event costs and the
    // derivation paths from the finding journal; the real solver cut must
    // satisfy every obligation.
    assert!(
        certificate
            .verify_with_journal(&finding.run.journal)
            .is_ok(),
        "verify_with_journal must accept the real cut: {:?}",
        certificate.verify_with_journal(&finding.run.journal)
    );
    // The acceptance must survive a JSON roundtrip.
    let json = certificate.to_json().unwrap();
    let decoded = CampaignCertificate::from_json(&json).unwrap();
    assert!(decoded.verify().is_ok());
    assert!(
        decoded.verify_with_journal(&finding.run.journal).is_ok(),
        "roundtripped certificates must keep satisfying journal-anchored verification"
    );
    assert_eq!(
        decoded.minimality.as_ref().unwrap().horizon,
        certificate.minimality.as_ref().unwrap().horizon,
        "the recorded solver horizon must survive the roundtrip"
    );

    // Negative: a lower_bound above the cut's summed event cost (at most
    // MAX_EVENT_COST per event under the solver cost model) must fail
    // verification.
    let tampered_bound = certificate
        .minimality
        .as_ref()
        .map(|m| m.cut.len() as u64 * MAX_EVENT_COST + 1)
        .unwrap();
    let mut tampered = certificate.clone();
    tampered.minimality = Some(ledger_explorer::MinimalityExtension {
        cut: certificate.minimality.as_ref().unwrap().cut.clone(),
        lower_bound: tampered_bound,
        method: extension.method.clone(),
        horizon: extension.horizon,
    });
    assert!(
        tampered.verify().is_err(),
        "verify must reject lower_bound {tampered_bound} above the cut's summed event cost"
    );
}
