//! MCS certificates on bug-corpus-v1: each planted bug reproduces,
//! yields a MaxSAT MCS cut with a valid lower-bound certificate, and
//! the cut maps to an executable fault schedule that replays.
//!
//! Every scenario comes from the shared registry
//! (`ledger_explorer::reference::corpus_scenarios`); this gate holds no
//! private name-to-builder mapping.

use ledger_explorer::MaxSatSolver;
use ledger_explorer::certs::MAX_EVENT_COST;
use ledger_explorer::ldfi::hypothesis_to_schedule;
use ledger_explorer::reference::ReferenceReplayError;
use ledger_explorer::reference::corpus_scenario;
use ledger_format::RunManifest;
use std::fs;
use std::path::Path;

#[test]
fn mcs_certificates_on_bug_corpus_v1() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpora/bug-corpus-v1");
    let mut checked = 0usize;
    let mut table: Vec<(String, usize, u64)> = Vec::new();
    let mut non_reproducing: Vec<String> = Vec::new();

    for entry in fs::read_dir(&corpus).expect("corpus dir must exist") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("ldgr") {
            continue;
        }
        let bytes = fs::read(&path).unwrap();
        let manifest = RunManifest::from_canonical_bytes(&bytes)
            .unwrap_or_else(|error| panic!("{}: manifest must decode: {error}", path.display()));
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        let scenario =
            corpus_scenario(&name).unwrap_or_else(|| panic!("unexpected manifest: {name}"));

        // Reproduce the failing run exactly like corpus_v1_gate's pinned check.
        let run = scenario
            .run(manifest.root_seed, Vec::new())
            .unwrap_or_else(|error| panic!("{name}: pinned rerun failed: {error}"));
        let verdict = scenario.check(&run);
        assert!(
            verdict.violated,
            "{name}: planted bug must fire under oracle"
        );
        assert_eq!(
            run.journal.root_hash(),
            manifest.journal_root,
            "{name}: pinned root must match fresh run"
        );

        // Solve with MCS certificate.
        let mut solver = MaxSatSolver::default();
        let (hyps, cert) = solver
            .solve_with_certificate(&run.journal, &verdict)
            .unwrap_or_else(|e| panic!("{name}: solve_with_certificate must succeed: {e:?}"));
        let cert = cert
            .unwrap_or_else(|| panic!("{name}: non-empty solve must return recorded solver data"));
        assert!(
            !hyps.is_empty(),
            "{name}: solver must return at least one hypothesis"
        );
        assert!(!cert.cut.is_empty(), "{name}: MCS cut must be non-empty");
        assert_eq!(
            cert.method, "mcs-lower-bound-v1",
            "{name}: method must be mcs-lower-bound-v1"
        );
        // Upper bound on the cut's summed event cost: each cut event is a
        // faultable kind, bounded by the shared cost-model maximum.
        let upper = (cert.cut.len() as u64).saturating_mul(MAX_EVENT_COST);
        assert!(
            cert.cost <= upper,
            "{name}: recorded cut cost {} must be <= cut.len()*{MAX_EVENT_COST} ({upper})",
            cert.cost
        );
        assert_eq!(
            cert.cost, hyps[0].total_cost,
            "{name}: recorded cut cost must equal the hypothesis cost"
        );

        // Map cut to executable fault schedule and verify replay reproduces
        // the violation: full schedule first, then single injections when the
        // full schedule over-blocks progress.
        let hyp = ledger_explorer::ldfi::FaultHypothesis {
            events: cert.cut.clone(),
            total_cost: cert.cost,
            explanation: "mcs cut".to_string(),
        };
        let schedule = hypothesis_to_schedule(&hyp, &run.journal);
        assert!(
            !schedule.is_empty(),
            "{name}: hypothesis_to_schedule must yield non-empty schedule"
        );

        let holds = |sched: &[ledger_sim::SimFault]| -> bool {
            match scenario.replay_faults(manifest.root_seed, &run, sched.to_vec()) {
                Ok(replay) => scenario.check(&replay).violated,
                Err(ReferenceReplayError::Engine {
                    source: ledger_sim::RuntimeError::StrictReplay(_),
                    ..
                }) => {
                    // Strict violation is Wave 1 evidence that the schedule
                    // diverged; treat as not reproducing and try next single.
                    false
                }
                Err(error) => panic!("{name}: fault replay must run: {error}"),
            }
        };

        let mut violated = holds(&schedule);
        println!(
            "{name} full schedule violated={} cut_len={} cost={} schedule_len={}",
            violated,
            cert.cut.len(),
            cert.cost,
            schedule.len()
        );
        if !violated {
            for injection in &schedule {
                if holds(std::slice::from_ref(injection)) {
                    println!("{name} single {injection:?} violates");
                    violated = true;
                    break;
                }
            }
        }
        // No fault-space fallback: a cut whose schedule cannot reproduce is
        // reported, not accepted. The certificate for such a scenario is
        // counted as evidence of the cut's shape only; the scenario cannot
        // claim cut-caused reproduction. Non-reproducing scenarios are
        // listed in the summary table and must stay a fixed, documented set.
        if !violated {
            non_reproducing.push(name.clone());
            println!(
                "{name}: the recorded cut's schedule does not reproduce the violation \
                 (report-only, not counted as cut-caused reproduction)"
            );
        }

        table.push((name.clone(), cert.cut.len(), cert.cost));
        checked += 1;
    }

    assert_eq!(
        checked,
        ledger_explorer::reference::corpus_scenarios().len(),
        "every registry scenario must be exercised"
    );

    // The known non-reproducing set is fixed: mini-kv-stale-read's recorded
    // cut relied on Delay on non-link sends being dropped (no-op). With the
    // corrected Delay semantics the cut no longer reproduces; the scenario
    // stays a v1 reproduction fixture, but it cannot claim cut-caused
    // reproduction. Growing this list requires a review decision.
    non_reproducing.sort();
    assert_eq!(
        non_reproducing,
        vec!["mini-kv-stale-read".to_string()],
        "the report-only non-reproducing set must stay fixed"
    );

    // Deterministic per-bug table for reporting (sorted by name for stability).
    table.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, cut_len, lb) in &table {
        println!("{name}: cut_len={cut_len} lower_bound={lb}");
    }
}
