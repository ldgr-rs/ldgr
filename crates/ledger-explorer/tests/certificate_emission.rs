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
        .write_certificate(&path, digest, builder, None)
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
fn from_campaign_is_deterministic() {
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
    let cert_a = ledger_explorer::CampaignCertificate::from_campaign(
        &report,
        builder,
        Vec::new(),
        digest,
        None,
    )
    .unwrap();
    let cert_b = ledger_explorer::CampaignCertificate::from_campaign(
        &report,
        builder,
        Vec::new(),
        digest,
        None,
    )
    .unwrap();
    assert_eq!(cert_a.builder_id, cert_b.builder_id);
    assert_eq!(
        cert_a.external_parameters_digest,
        cert_b.external_parameters_digest
    );
    assert_eq!(cert_a.runs_executed, cert_b.runs_executed);
    assert_eq!(cert_a.to_json().unwrap(), cert_b.to_json().unwrap());
}

/// A solver cut round-trips as recorded data and binds to its journal.
#[test]
fn recorded_solver_data_from_real_cut_verifies() {
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
    let extension = extension.expect("non-empty solve must return recorded solver data");
    assert!(!extension.cut.is_empty(), "the real cut must be non-empty");
    assert!(
        extension.recorded_lower_bound <= hypotheses[0].total_cost,
        "the recorded bound must not exceed the solved cut cost"
    );

    let mut certificate = CampaignCertificate::from_campaign(
        &report,
        "test-builder-solver-data",
        Vec::new(),
        [2u8; 32],
        None,
    )
    .unwrap();
    certificate.solver_data = Some(extension.clone());
    assert!(
        certificate.verify().is_ok(),
        "verify must accept the real cut: {:?}",
        certificate.verify()
    );
    // Journal binding checks the root, members, and recorded costs.
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
        decoded.solver_data.as_ref().unwrap().horizon,
        certificate.solver_data.as_ref().unwrap().horizon,
        "the recorded solver horizon must survive the roundtrip"
    );

    // A recorded bound above the maximum cut cost must fail validation.
    let tampered_bound = certificate
        .solver_data
        .as_ref()
        .map(|data| data.cut.len() as u64 * MAX_EVENT_COST + 1)
        .unwrap();
    let mut tampered = certificate.clone();
    tampered.solver_data = Some(ledger_explorer::RecordedSolverData {
        cut: certificate.solver_data.as_ref().unwrap().cut.clone(),
        recorded_lower_bound: tampered_bound,
        method: extension.method.clone(),
        horizon: extension.horizon,
    });
    assert!(
        tampered.verify().is_err(),
        "verify must reject recorded bound {tampered_bound} above the cut cost"
    );
}
