//! Cross-engine solver differential: the pure-Rust branch-and-bound engine
//! (builtin, `crate::maxsat::solve_maxsat_bnb`) vs the CaDiCaL
//! ascending-threshold search (behind the `solver-cadical` feature) over
//! common randomized BOUNDED encodings.
//!
//! The encodings come from a deterministic randomized journal builder (fixed
//! seed, bounded actor count, bounded horizon and max-faults cardinality), so
//! both engines see byte-identical hazard inputs. Per case the gate asserts:
//!
//! - COST EQUALITY: both engines report the same optimal cut cost.
//! - CUT VALIDITY: the cut hits every hard clause of the encoding.
//! - MINIMALITY: dropping any cut event leaves some hard clause unhit.
//! - COST CONSISTENCY: the recomputed per-event cost of the cut equals the
//!   reported total (no engine trusts a persisted number).
//! - CERTIFICATE PARITY: both lower-bound proofs carry the same method and
//!   the same unsat-core cost, and that bound never exceeds the cut cost.
//!   Equal-cost equivalence is the cross-engine contract: the argmin cut SET
//!   may legitimately differ between engines, so set identity is never
//!   asserted.
//!
//! The CaDiCaL leg is feature-gated: the default build has no cadical
//! dependency, and the gate documents that availability instead of skipping
//! silently. The non-gated leg runs the same randomized corpus through the
//! builtin engine alone and asserts its own determinism, validity, and
//! minimality.

use ledger_explorer::FaultSolver;
use ledger_explorer::maxsat::{HazardEncoding, encode_hazard};
use ledger_explorer::oracle::Verdict;
use ledger_explorer::solver::{MaxSatSolver, SolverConfig, SolverEngine, event_fault_cost};
use ledger_format::{EntryKind, Hash, Payload};
use ledger_journal::Journal;
use rand_chacha::ChaCha8Rng;
use rand_core::{Rng, SeedableRng};

/// Number of randomized bounded encodings per corpus run.
const CASES: usize = 12;
/// Max parents sampled per event; keeps the DAG bounded and acyclic.
const MAX_SAMPLED_PARENTS: usize = 3;
/// Recent window for parent sampling.
const PARENT_WINDOW: usize = 8;

/// Deterministic bounded encoding case: one randomized journal plus its
/// witness verdict and the shared solver config.
struct EncodingCase {
    journal: Journal,
    verdict: Verdict,
    /// Engine-neutral config: horizon, cardinality, and version pinning.
    config: SolverConfig,
}

/// Build one randomized bounded journal from the seeded stream.
fn build_case(rng: &mut ChaCha8Rng) -> EncodingCase {
    let count = 12 + (rng.next_u32() as usize % 9);
    let mut journal = Journal::new();
    let mut ids: Vec<Hash> = Vec::new();
    for _ in 0..count {
        let kind = match rng.next_u32() % 4 {
            0 => EntryKind::Send,
            1 => EntryKind::Recv,
            2 => EntryKind::TimerSet,
            _ => EntryKind::FsWrite,
        };
        let actor = (rng.next_u32() % 3) + 1;
        let mut parents = Vec::new();
        let parent_count = (rng.next_u32() as usize % (MAX_SAMPLED_PARENTS + 1)).min(ids.len());
        for _ in 0..parent_count {
            let offset = (rng.next_u32() as usize % PARENT_WINDOW).min(ids.len().saturating_sub(1));
            let parent = ids[ids.len() - 1 - offset];
            if !parents.contains(&parent) {
                parents.push(parent);
            }
        }
        let payload = match kind {
            EntryKind::Send => Payload::Pair {
                left: (rng.next_u32() % 3 + 1) as u64,
                right: (rng.next_u32() % 1000) as u64,
            },
            _ => Payload::Number((rng.next_u32() % 1000) as u64),
        };
        let id = journal
            .append(kind, actor, parents, payload)
            .expect("randomized append must succeed");
        ids.push(id);
    }
    // Witness: an outcome observing several recent events.
    let witness_parents = ids
        .iter()
        .rev()
        .take(1 + (rng.next_u32() as usize % 3))
        .copied()
        .collect::<Vec<_>>();
    let witness = journal
        .append(
            EntryKind::Outcome,
            4,
            witness_parents,
            Payload::Number(rng.next_u32() as u64 % 1000),
        )
        .expect("witness append must succeed");
    let verdict = Verdict::fail(vec![witness], "cross-engine randomized case");
    let config = SolverConfig::default()
        .with_horizon(8)
        .with_oracle_version(7);
    EncodingCase {
        journal,
        verdict,
        config,
    }
}

/// The randomized corpus: `CASES` journals plus the shared encoding.
fn corpus() -> Vec<(EncodingCase, HazardEncoding)> {
    let mut rng = ChaCha8Rng::seed_from_u64(0x5EED_5EED_00C0_FFEE);
    (0..CASES)
        .map(|_| {
            let case = build_case(&mut rng);
            let encoding = encode_hazard(&case.journal, &case.verdict, &case.config)
                .expect("encode must succeed");
            (case, encoding)
        })
        .collect()
}

/// The cut must hit every hard clause, and dropping any member must leave
/// some hard clause unhit.
fn assert_cut_valid_and_minimal(encoding: &HazardEncoding, cut: &[Hash]) {
    assert!(
        encoding
            .hard
            .iter()
            .all(|clause| clause.iter().any(|event| cut.contains(event))),
        "the cut must satisfy every hard clause"
    );
    for removed in cut {
        let reduced: Vec<Hash> = cut
            .iter()
            .copied()
            .filter(|event| event != removed)
            .collect();
        assert!(
            !encoding
                .hard
                .iter()
                .all(|clause| clause.iter().any(|event| reduced.contains(event))),
            "dropping an event must leave some hard clause unhit: the cut is not minimal"
        );
    }
}

/// The recomputed per-event cost of the cut must equal the reported total.
fn assert_cost_consistent(journal: &Journal, cut: &[Hash], total_cost: u64) {
    let recomputed: u64 = cut
        .iter()
        .map(|event| event_fault_cost(journal, event))
        .sum();
    assert_eq!(
        recomputed, total_cost,
        "the recomputed cut cost must equal the reported total"
    );
}

#[test]
fn builtin_bnb_is_deterministic_valid_and_minimal_on_randomized_encodings() {
    for (index, (case, encoding)) in corpus().iter().enumerate() {
        let mut first =
            MaxSatSolver::with_config(case.config.clone().with_engine(SolverEngine::Builtin));
        let mut second =
            MaxSatSolver::with_config(case.config.clone().with_engine(SolverEngine::Builtin));
        assert_eq!(first.name(), "maxsat");
        let (first_hyp, extension_a) = first
            .solve_with_certificate(&case.journal, &case.verdict)
            .expect("builtin solve must succeed");
        let (second_hyp, extension_b) = second
            .solve_with_certificate(&case.journal, &case.verdict)
            .expect("builtin solve must succeed");
        let extension_a =
            extension_a.expect("non-empty builtin solve must return recorded solver data");
        let extension_b =
            extension_b.expect("non-empty builtin solve must return recorded solver data");
        let first_cost = first_hyp[0].total_cost;
        let second_cost = second_hyp[0].total_cost;
        assert_eq!(
            extension_a.cut, extension_b.cut,
            "case {index}: the builtin engine must be deterministic"
        );
        assert_eq!(
            first_cost, second_cost,
            "case {index}: the builtin cost must be deterministic"
        );
        assert_eq!(
            extension_a.recorded_lower_bound, extension_b.recorded_lower_bound,
            "case {index}: the recorded solver bound must be deterministic"
        );
        assert_cut_valid_and_minimal(encoding, &extension_a.cut);
        assert_cost_consistent(&case.journal, &extension_a.cut, first_cost);
        assert!(
            extension_a.recorded_lower_bound <= first_cost,
            "case {index}: the recorded solver bound must not exceed the cut cost"
        );
    }
}

/// Cross-engine leg, compiled only with the `solver-cadical` feature: the
/// builtin branch-and-bound and the CaDiCaL threshold search solve the SAME
/// randomized bounded encodings, and every contract below holds.
#[cfg(feature = "solver-cadical")]
#[test]
fn bnb_and_cadical_agree_on_randomized_bounded_encodings() {
    for (index, (case, encoding)) in corpus().iter().enumerate() {
        let mut builtin =
            MaxSatSolver::with_config(case.config.clone().with_engine(SolverEngine::Builtin));
        let mut cadical =
            MaxSatSolver::with_config(case.config.clone().with_engine(SolverEngine::Cadical));
        assert_eq!(builtin.name(), "maxsat");
        assert_eq!(
            cadical.name(),
            "maxsat-cadical",
            "the feature must route the forced Cadical request to CaDiCaL"
        );

        let (builtin_hyp, builtin_ext) = builtin
            .solve_with_certificate(&case.journal, &case.verdict)
            .expect("builtin solve must succeed");
        let (cadical_hyp, cadical_ext) = cadical
            .solve_with_certificate(&case.journal, &case.verdict)
            .expect("cadical solve must succeed");
        let builtin_ext =
            builtin_ext.expect("non-empty builtin solve must return recorded solver data");
        let cadical_ext =
            cadical_ext.expect("non-empty cadical solve must return recorded solver data");
        let builtin_cost = builtin_hyp[0].total_cost;
        let cadical_cost = cadical_hyp[0].total_cost;

        // COST EQUALITY: the optimal cut cost is engine-independent.
        assert_eq!(
            builtin_cost, cadical_cost,
            "case {index}: engines must agree on the optimal cut cost"
        );
        // VALIDITY and MINIMALITY hold for BOTH cuts.
        assert_cut_valid_and_minimal(encoding, &builtin_ext.cut);
        assert_cut_valid_and_minimal(encoding, &cadical_ext.cut);
        // COST CONSISTENCY for both cuts.
        assert_cost_consistent(&case.journal, &builtin_ext.cut, builtin_cost);
        assert_cost_consistent(&case.journal, &cadical_ext.cut, cadical_cost);
        // CERTIFICATE PARITY: same method, same lower bound, bound <= cost.
        assert_eq!(
            builtin_ext.method, cadical_ext.method,
            "case {index}: the lower-bound method must match across engines"
        );
        assert_eq!(
            builtin_ext.recorded_lower_bound, cadical_ext.recorded_lower_bound,
            "case {index}: the recorded solver bounds must agree across engines"
        );
        assert!(
            builtin_ext.recorded_lower_bound <= builtin_cost,
            "case {index}: the bound must never exceed the cut cost"
        );
        println!(
            "case {index}: hard={} builtin_cost={builtin_cost} cadical_cost={cadical_cost} recorded_bound={} builtin_cut={} cadical_cut={}",
            encoding.hard.len(),
            builtin_ext.recorded_lower_bound,
            builtin_ext.cut.len(),
            cadical_ext.cut.len(),
        );
    }
}

/// Documented gate: without `solver-cadical` the cross-engine leg does not
/// compile; this test pins what the no-feature build DOES provide: forcing
/// the Cadical engine must fall back to the pure-Rust branch-and-bound and
/// report the active backend truthfully, never a CaDiCaL run.
#[cfg(not(feature = "solver-cadical"))]
#[test]
fn cadical_request_falls_back_to_builtin_truthfully_without_the_feature() {
    // The default build deliberately ships without the C++ CaDiCaL
    // dependency. The forced request still compiles and runs, and the solver
    // must keep reporting the backend that actually solved. The solver
    // config equals the corpus encoding config (bounded horizon 8), the
    // same pattern the cross-engine leg uses, so cut obligations are
    // asserted against the exact encoding that was solved.
    let (case, encoding) = corpus().into_iter().next().expect("corpus is non-empty");
    let mut solver =
        MaxSatSolver::with_config(case.config.clone().with_engine(SolverEngine::Cadical));
    assert_eq!(
        solver.resolved_engine(),
        SolverEngine::Builtin,
        "without the feature the forced Cadical request must resolve to the builtin backend"
    );
    assert_eq!(
        solver.name(),
        "maxsat",
        "name() must report the active backend, not the requested one"
    );
    let (hypotheses, extension) = solver
        .solve_with_certificate(&case.journal, &case.verdict)
        .expect("the branch-and-bound fallback must solve without the feature");
    let extension = extension.expect("non-empty solve must return recorded solver data");
    let cost = hypotheses[0].total_cost;
    assert_cut_valid_and_minimal(&encoding, &extension.cut);
    assert_cost_consistent(&case.journal, &extension.cut, cost);
    assert!(
        extension.recorded_lower_bound <= cost,
        "the recorded solver bound must not exceed the cut cost"
    );
    assert_eq!(
        extension.horizon,
        Some(8),
        "the fallback must record the horizon it solved under"
    );
    // Enabling `solver-cadical` compiles the cross-engine leg
    // (`bnb_and_cadical_agree_on_randomized_bounded_encodings`) and requires
    // a working C++ toolchain. The feature is exercised in CI and in the
    // developer gates with `cargo test -p ledger-explorer --all-features`.
}
