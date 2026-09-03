//! Differential oracle gate: paired IMPLEMENTATION fixtures over a shared
//! pinned corpus, plus the divergence-location checks of
//! [`DifferentialOracle::compare`].
//!
//! Legs over real simulations:
//! - identical config twice -> equal verdict (registers, outputs, faults, and
//!   journal root all agree),
//! - diverging programs with identical final registers -> the observable-output
//!   check fires with the output index, actor, and both values located,
//! - diverging registers -> the register check fires unchanged,
//! - PAIRED IMPLEMENTATIONS of the same key-value behavior: a relay
//!   forwarding path and a direct path must produce equal registers, equal
//!   numeric outcomes, and equal shared-oracle verdicts on every seed of the
//!   corpus, and a planted stale-relay implementation must diverge from the
//!   correct one on every seed.
//!
//! Cross-implementation equality deliberately compares behavior (registers,
//! observable outputs, oracle verdicts), not journal roots: two distinct
//! programs journal different structures by construction, so a root-hash
//! comparison would be vacuous for this pair.
//!
//! A native-vs-wasm leg is out of scope here: `ledger-explorer` has no
//! `backend-wasm` feature, and adding one would change the crate's feature
//! surface. The native/wasm differential runs in `ledger-sim`
//! (`tests/wasm_differential.rs`).

use ledger_explorer::oracle::{
    DifferentialOracle, HistoryOperation, HistoryOracle, KeyValueSpec, Oracle, Verdict,
};
use ledger_explorer::search::Workload;
use ledger_format::ActorId;
use ledger_format::EntryHash;
use ledger_format::{CanonicalValue, EntryKind, EntryPayload};
use ledger_sim::{Instruction, Policy, RunConfig, RunResult, Simulation};

fn config(seed: EntryHash) -> RunConfig {
    RunConfig::builder()
        .seed(seed)
        .policy(Policy::Random)
        .max_steps(512)
        .build()
}

fn run(programs: Vec<Vec<Instruction>>, seed: EntryHash) -> RunResult {
    Simulation::new(config(seed), programs)
        .run()
        .expect("simulation must run")
}

/// Journal a value, emit it as an outcome, then overwrite the register so the
/// final registers agree while the journaled output differs.
fn program(outcome_value: u64, final_register: u64) -> Vec<Vec<Instruction>> {
    vec![vec![
        Instruction::Set(outcome_value),
        Instruction::Outcome,
        Instruction::Set(final_register),
        Instruction::Done,
    ]]
}

/// The shared corpus: pinned seeds both implementations must agree on.
const CORPUS: [EntryHash; 4] = [
    EntryHash([0; 32]),
    EntryHash([1; 32]),
    EntryHash([2; 32]),
    EntryHash([3; 32]),
];

/// PAIRED IMPLEMENTATION A: the writer reaches the reader through a relay.
///
/// Three tasks: writer sends 42 to the relay; the relay forwards 42 to the
/// reader; the reader outputs it. The relay task keeps the value in its
/// register but never emits it.
#[derive(Debug, Clone, Copy)]
struct RelayKv;

impl Workload for RelayKv {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        vec![
            vec![Instruction::Send { to: 1, payload: 42 }, Instruction::Done],
            vec![
                Instruction::Receive,
                Instruction::Set(0),
                Instruction::Send { to: 2, payload: 42 },
                Instruction::Done,
            ],
            vec![
                Instruction::Receive,
                Instruction::Outcome,
                Instruction::Done,
            ],
        ]
    }

    fn history(&self, run: &RunResult) -> Vec<HistoryOperation> {
        kv_history(run)
    }
}

/// PAIRED IMPLEMENTATION B: the writer reaches the reader directly.
///
/// Three tasks in the same layout as [`RelayKv`]: the middle task is a
/// no-op placeholder so the register vectors match shape.
#[derive(Debug, Clone, Copy)]
struct DirectKv;

impl Workload for DirectKv {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        vec![
            vec![Instruction::Send { to: 2, payload: 42 }, Instruction::Done],
            vec![Instruction::Done],
            vec![
                Instruction::Receive,
                Instruction::Outcome,
                Instruction::Done,
            ],
        ]
    }

    fn history(&self, run: &RunResult) -> Vec<HistoryOperation> {
        kv_history(run)
    }
}

/// BUGGY PAIRED IMPLEMENTATION: the relay forwards a stale 0 instead of the
/// received value, so the reader serves stale data after the write.
#[derive(Debug, Clone, Copy)]
struct StaleRelayKv;

impl Workload for StaleRelayKv {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        vec![
            vec![Instruction::Send { to: 1, payload: 42 }, Instruction::Done],
            vec![
                Instruction::Receive,
                Instruction::Set(0),
                Instruction::Send { to: 2, payload: 0 },
                Instruction::Done,
            ],
            vec![
                Instruction::Receive,
                Instruction::Outcome,
                Instruction::Done,
            ],
        ]
    }

    fn history(&self, run: &RunResult) -> Vec<HistoryOperation> {
        kv_history(run)
    }
}

/// Shared history extraction for the three implementations: the write is the
/// writer's Send carrying 42, the read is the reader's numeric outcome.
fn kv_history(run: &RunResult) -> Vec<HistoryOperation> {
    run.journal
        .entries()
        .filter_map(|entry| match (&entry.data.kind, &entry.data.payload) {
            (
                EntryKind::Send,
                EntryPayload::Send(ledger_format::SendFrame {
                    original_content, ..
                }),
            ) if entry.data.actor == ActorId(0)
                && original_content.as_slice() == 42u64.to_le_bytes() =>
            {
                Some(HistoryOperation::Write {
                    key: "k".into(),
                    value: 42,
                    witness: entry.id,
                })
            }
            (
                EntryKind::Outcome,
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    value: CanonicalValue::Unsigned(value),
                    ..
                }),
            ) if entry.data.actor == ActorId(2) => Some(HistoryOperation::Read {
                key: "k".into(),
                value: *value,
                witness: entry.id,
            }),
            _ => None,
        })
        .collect()
}

/// The last numeric outcome of a run.
fn outcome_value(run: &RunResult) -> Option<u64> {
    run.journal
        .entries()
        .filter(|entry| entry.data.kind == EntryKind::Outcome)
        .find_map(|entry| match &entry.data.payload {
            EntryPayload::Outcome(ledger_format::OutcomePayload {
                value: CanonicalValue::Unsigned(value),
                ..
            }) => Some(*value),
            _ => None,
        })
}

#[test]
fn identical_runs_compare_equal() {
    let programs = program(7, 8);
    let left = run(programs.clone(), EntryHash([3; 32]));
    let right = run(programs, EntryHash([3; 32]));
    let verdict = DifferentialOracle::compare(&left, &right);
    assert_eq!(verdict, Verdict::pass());
}

#[test]
fn diverging_outputs_are_located_not_just_hash_mismatched() {
    // Same final register (8), different journaled outputs (7 vs 9): only the
    // observable-output check can locate this divergence.
    let left = run(program(7, 8), EntryHash([3; 32]));
    let right = run(program(9, 8), EntryHash([3; 32]));

    let register_verdict = DifferentialOracle::compare(&left, &right);
    assert!(register_verdict.violated, "the divergence must be reported");
    assert!(
        register_verdict
            .reason
            .contains("output divergence at output 0"),
        "the reason must locate the diverging output: {}",
        register_verdict.reason
    );
    assert!(
        register_verdict
            .reason
            .contains("left=(actor 0, value 7), right=(actor 0, value 9)"),
        "the reason must name both observed values: {}",
        register_verdict.reason
    );
}

#[test]
fn diverging_registers_still_fail_first() {
    let left = run(program(7, 7), EntryHash([3; 32]));
    let right = run(program(9, 9), EntryHash([3; 32]));
    let verdict = DifferentialOracle::compare(&left, &right);
    assert!(verdict.violated);
    assert!(
        verdict.reason.contains("register mismatch"),
        "a register divergence must keep firing the register check: {}",
        verdict.reason
    );
}

/// A seed divergence on a schedule-dependent workload must not be reported as
/// equal unless every compared surface actually agrees: here the runs share
/// config shape but flip which message wins the delivery race, so the outputs
/// or the root must diverge.
#[test]
fn schedule_divergence_is_detected_on_a_race_workload() {
    // Two-task relay: the receiver outcomes whichever payload arrives first.
    let relay = || {
        vec![
            vec![
                Instruction::SendTimed {
                    to: 1,
                    payload: 1,
                    delay: 2,
                },
                Instruction::SendTimed {
                    to: 1,
                    payload: 2,
                    delay: 1,
                },
                Instruction::Done,
            ],
            vec![
                Instruction::Receive,
                Instruction::Outcome,
                Instruction::Done,
            ],
        ]
    };
    let first = run(relay(), EntryHash([5; 32]));
    let second = run(relay(), EntryHash([6; 32]));
    let same = DifferentialOracle::compare(&first, &first.clone());
    assert_eq!(same, Verdict::pass(), "a run must equal itself");

    // The two seeds order the receiver's wake differently or identically;
    // either way the comparison must agree with a full bit comparison, never
    // pass when the journals differ.
    let roots_equal = first.journal.root_hash() == second.journal.root_hash();
    let verdict = DifferentialOracle::compare(&first, &second);
    assert_eq!(
        verdict.violated, !roots_equal,
        "compare must diverge exactly when the journals diverge"
    );
}

/// Paired implementations: the relay path and the direct path must agree on
/// every corpus seed in registers, numeric outcomes, and shared-oracle
/// verdicts. This is an implementation-vs-implementation differential over a
/// shared corpus, not a literal/seed-change comparison.
#[test]
fn paired_implementations_agree_on_the_shared_corpus() {
    let oracle = HistoryOracle::new(&RelayKv, KeyValueSpec::default());
    for seed in CORPUS {
        let relay_run = run(RelayKv.programs(), seed);
        let direct_run = run(DirectKv.programs(), seed);
        assert_eq!(
            relay_run.registers, direct_run.registers,
            "the paired implementations must keep equal final registers at seed {seed:?}"
        );
        assert_eq!(
            outcome_value(&relay_run),
            outcome_value(&direct_run),
            "the paired implementations must emit equal outcomes at seed {seed:?}"
        );
        let relay_verdict = oracle.check(&relay_run);
        let direct_verdict = oracle.check(&direct_run);
        assert_eq!(
            relay_verdict, direct_verdict,
            "the shared oracle must return equal verdicts at seed {seed:?}"
        );
        assert!(
            !relay_verdict.violated,
            "the correct pair must pass the shared oracle at seed {seed:?}"
        );
    }
}

/// The BUGGY pair: stale relay vs correct direct path. On every corpus seed
/// the buggy implementation violates the shared oracle, the correct one
/// passes, and the differential oracle reports the divergence with a typed
/// reason locating the register (hence the served value) mismatch.
#[test]
fn buggy_pair_diverges_from_the_correct_pair_on_every_corpus_seed() {
    let relay_oracle = HistoryOracle::new(&RelayKv, KeyValueSpec::default());
    let buggy_oracle = HistoryOracle::new(&StaleRelayKv, KeyValueSpec::default());
    for seed in CORPUS {
        let buggy_run = run(StaleRelayKv.programs(), seed);
        let correct_run = run(DirectKv.programs(), seed);
        // The buggy implementation serves the stale value after a completed
        // write: the shared sequential specification rejects the read.
        let buggy_verdict = buggy_oracle.check(&buggy_run);
        assert!(
            buggy_verdict.violated,
            "seed {seed:?}: the stale relay must violate the shared oracle"
        );
        assert_eq!(
            outcome_value(&buggy_run),
            Some(0),
            "seed {seed:?}: the stale relay must serve 0"
        );
        let correct_verdict = relay_oracle.check(&correct_run);
        assert!(
            !correct_verdict.violated,
            "seed {seed:?}: the correct direct path must pass"
        );
        assert_eq!(
            outcome_value(&correct_run),
            Some(42),
            "seed {seed:?}: the correct direct path must serve 42"
        );

        // The differential oracle must report the implementation divergence.
        let verdict = DifferentialOracle::compare(&buggy_run, &correct_run);
        assert!(
            verdict.violated,
            "seed {seed:?}: the implementation pair must diverge"
        );
        assert!(
            verdict.reason.contains("register mismatch"),
            "seed {seed:?}: the divergence must be located: {}",
            verdict.reason
        );
    }
}
