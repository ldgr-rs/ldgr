//! Solver-scaling acceptance gate: end-to-end hazard certification on a
//! relevant closure that grows from 10^3 to 10^6 journal entries.
//!
//! The fixture is a shared-gate fan-in: one gate `Send` and `paths` witness
//! `Recv`s that each observe only the gate send. Every derivation path runs
//! through the gate send, so the minimal weighted cut is the gate send alone
//! while the clause count - the real solver-problem size - grows linearly
//! with `paths`. At the top size the journal holds 10^6 entries and the
//! hazard holds 10^6 clauses.
//!
//! The measured pipeline is `services::certify_hazard`: witness closure
//! extraction and hazard encoding, solver routing and solve (Auto resolves
//! to the builtin BnB engine), statement emission, and journal-anchored
//! validation - the exact stages the Stage-2 criterion names. The release
//! budget asserts the whole pipeline under 60 seconds at 10^6 entries, and
//! the pipeline duration must grow monotonically with the closure.
//!
//! Statement scope: the scaling statement records a bounded witness sample
//! (`CERT_MAX_BYTES` bounds statements); the solve itself always runs over
//! every witness. The statement carries no fault-causation claim - pair
//! `certify_hazard` with `services::qualify_cut` for that.

use ledger_explorer::services::certify_hazard;
use ledger_format::{EntryKind, EntryPayload, MessageId, RecvFrame, SendFrame};
use ledger_journal::Journal;
use ledger_sim::RunResult;

/// Witness counts: journal entries are `paths + 1`, so the top size holds
/// 10^6 entries and 10^6 hazard clauses.
const PATHS: [usize; 4] = [500, 5_000, 50_000, 1_000_000];

/// The recorded witness cap: statements are byte-bounded, the analysis is
/// not.
const RECORDED_WITNESS_CAP: usize = 1024;

/// Build the fan-in hazard fixture: (journal, verdict, gate-send id).
fn build_fan_in(paths: usize) -> (Journal, ledger_explorer::Verdict, ledger_format::Hash) {
    let mut journal = Journal::new();
    let gate = journal
        .append(
            EntryKind::Send,
            0,
            [],
            EntryPayload::Send(SendFrame {
                message_id: MessageId::new(0, 0),
                from: 0,
                to: 1,
                original_content: vec![0],
            }),
        )
        .expect("gate send must append");
    let mut witnesses = Vec::with_capacity(paths);
    for index in 0..paths {
        let actor = 2_000_000_u32 + index as u32;
        let witness = journal
            .append(
                EntryKind::Recv,
                actor,
                [gate],
                EntryPayload::Recv(RecvFrame {
                    message_id: MessageId::new(actor, index as u64),
                    from: 0,
                    to: actor,
                    observed_content: vec![0],
                }),
            )
            .expect("witness must append");
        witnesses.push(witness);
    }
    let verdict = ledger_explorer::Verdict {
        violated: true,
        witnesses,
        reason: "fan-in hazard fixture".to_string(),
    };
    (journal, verdict, gate)
}

#[test]
fn hazard_certification_scales_to_one_million_entries() {
    let mut durations: Vec<(usize, std::time::Duration)> = Vec::new();

    for &paths in &PATHS {
        let entries = paths + 1;
        let (journal, verdict, gate) = build_fan_in(paths);
        assert_eq!(
            journal.len(),
            entries,
            "the fixture must hold the declared entry count"
        );

        let start = std::time::Instant::now();
        let (hypotheses, certificate) =
            certify_hazard(journal, &verdict, [7u8; 32], RECORDED_WITNESS_CAP).unwrap_or_else(
                |error| panic!("paths={paths}: end-to-end certification failed: {error}"),
            );
        let duration = start.elapsed();

        // The shared witness literal is the unique minimal cut.
        assert!(!hypotheses.is_empty(), "paths={paths}: must solve");
        let mut cut = hypotheses[0].events.clone();
        cut.sort();
        assert_eq!(
            cut,
            vec![gate],
            "paths={paths}: the minimal cut must be the shared witness literal"
        );

        // Journal-anchored validation ran inside the pipeline; the statement
        // must also round-trip through the bounded parser.
        let json = certificate
            .to_json()
            .unwrap_or_else(|error| panic!("paths={paths}: statement emission failed: {error}"));
        let parsed = ledger_explorer::certs::CampaignCertificate::from_json(&json)
            .unwrap_or_else(|error| panic!("paths={paths}: statement parse failed: {error}"));
        parsed
            .verify()
            .unwrap_or_else(|error| panic!("paths={paths}: statement validation failed: {error}"));

        durations.push((entries, duration));
        println!(
            "entries {entries}, hazard clauses {paths}, end-to-end {duration:?}, cut cost {}",
            hypotheses[0].total_cost
        );
    }

    // Monotonicity: the pipeline must actually grow with the closure.
    for window in durations.windows(2) {
        assert!(
            window[0].1 <= window[1].1,
            "end-to-end duration must grow with the closure: {:?}",
            window
        );
    }

    // Release budget: 60 seconds end-to-end at the 10^6-entry closure.
    #[cfg(not(debug_assertions))]
    {
        let (entries, duration) = durations.last().expect("top size measured");
        assert_eq!(*entries, 1_000_001, "the top size must be the 10^6 closure");
        assert!(
            *duration <= std::time::Duration::from_secs(60),
            "end-to-end certification at {entries} entries took {duration:?}, over the 60s budget"
        );
    }
}

/// The pipeline is deterministic: the same fixture certifies to the same
/// cut and statement bytes.
#[test]
fn hazard_certification_is_deterministic() {
    let (journal, verdict, gate) = build_fan_in(500);
    let (first, cert_a) =
        certify_hazard(journal, &verdict, [7u8; 32], RECORDED_WITNESS_CAP).expect("first run");
    let (journal, verdict, _) = build_fan_in(500);
    let (second, cert_b) =
        certify_hazard(journal, &verdict, [7u8; 32], RECORDED_WITNESS_CAP).expect("second run");
    assert_eq!(first[0].events, second[0].events, "cut must be stable");
    assert_eq!(
        first[0].total_cost, second[0].total_cost,
        "cost must be stable"
    );
    let json_a = cert_a.to_json().expect("emit a");
    let json_b = cert_b.to_json().expect("emit b");
    assert_eq!(json_a, json_b, "statement bytes must be identical");

    // The recorded witness sample is bounded by the cap.
    let data = cert_b.solver_data.expect("solver data recorded");
    assert!(
        data.witnesses.len() <= RECORDED_WITNESS_CAP,
        "the recorded witness list must respect the cap"
    );
    assert_eq!(
        data.cut,
        vec![gate],
        "the recorded cut must be the gate send"
    );

    // The empty verdict certifies nothing (fail closed, not panic).
    let empty = ledger_explorer::Verdict {
        violated: false,
        witnesses: Vec::new(),
        reason: "negative control".to_string(),
    };
    let (journal, _, _) = build_fan_in(500);
    let no_finding = certify_hazard(journal, &empty, [7u8; 32], RECORDED_WITNESS_CAP);
    assert!(
        no_finding.is_err(),
        "an empty hazard must not produce a statement"
    );
}

/// Keep the sim type in scope for fixture consumers documenting that the
/// hazard journal is journal-native (no simulation run backs it).
#[allow(dead_code)]
fn _journal_native(_run: Option<RunResult>) {}
