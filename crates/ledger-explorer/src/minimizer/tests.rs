use super::*;
use crate::oracle::{AssertionOracle, HistoryOperation, Oracle, PropertyOracle};
use crate::search::{Finding, Workload};
use ledger_sim::{Instruction, Policy, RunConfig, RunResult, Simulation};
use std::error::Error as _;

/// Workload that journals input values and then an outcome.
struct InputJournalWorkload;

impl Workload for InputJournalWorkload {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        vec![vec![
            Instruction::Set(0),
            Instruction::Outcome,
            Instruction::Done,
        ]]
    }

    fn history(&self, _run: &RunResult) -> Vec<HistoryOperation> {
        Vec::new()
    }

    fn with_inputs(&self, inputs: &[u64]) -> Box<dyn Workload> {
        let generator = gen_id("input-journal");
        let mut program = Vec::with_capacity(inputs.len() + 2);
        for (index, value) in inputs.iter().enumerate() {
            program.push(Instruction::Input {
                generator,
                replay: index as u64,
                value: *value,
            });
        }
        program.push(Instruction::Outcome);
        program.push(Instruction::Done);
        Box::new(crate::pbt::InputsWorkload::new(vec![program]))
    }
}

fn input_value_present(run: &RunResult, target: u64) -> bool {
    run.journal.entries().any(|entry| {
        matches!(entry.data.kind, EntryKind::InputStep { .. })
            && matches!(&entry.data.payload, Payload::Number(value) if *value == target)
    })
}

fn no_input_equals_42() -> PropertyOracle<impl Fn(&Journal) -> bool> {
    PropertyOracle {
        property: |journal: &Journal| {
            !journal.entries().any(|entry| {
                matches!(entry.data.kind, EntryKind::InputStep { .. })
                    && matches!(&entry.data.payload, Payload::Number(42))
            })
        },
        name: "no input value equals 42".into(),
    }
}

fn input_journal_finding() -> Finding {
    let base = RunConfig::builder()
        .seed([10; 32])
        .policy(Policy::Random)
        .max_steps(512)
        .build();
    let workload = InputJournalWorkload;
    let oracle = no_input_equals_42();
    let with_inputs = workload.with_inputs(&[1, 42, 3]);
    let run = Simulation::new(base.clone(), with_inputs.programs())
        .run()
        .expect("finding run must execute");
    let verdict = oracle.check(&run);
    assert!(verdict.violated, "the finding must journal a 42 input");
    Finding {
        seed: base.seed(),
        run,
        verdict,
    }
}

#[test]
fn minimize_input_derives_from_failing_journal_entries() {
    let workload = InputJournalWorkload;
    let oracle = no_input_equals_42();
    let finding = input_journal_finding();

    let journal_inputs = journal_inputs(&finding.run.journal, "input-journal");
    assert!(
        journal_inputs.contains(&42),
        "the finding journal must carry the triggering input"
    );

    let reduction = minimize_input(&workload, &oracle, &finding, "input-journal");
    assert!(reduction.violation_preserved);
    assert!(
        reduction.inputs.contains(&42),
        "the reduction must keep the trigger value"
    );
    assert!(
        reduction.inputs.len() < journal_inputs.len(),
        "ddmin must drop journal-derived inputs"
    );
    assert!(
        reduction
            .inputs
            .iter()
            .all(|value| journal_inputs.contains(value)),
        "reported inputs must be journal-derived, not fresh re-samples"
    );

    let workload = workload.with_inputs(&reduction.inputs);
    let run = Simulation::new(RunConfig::default(), workload.programs())
        .run()
        .expect("minimized run must execute");
    assert!(oracle.check(&run).violated);
    assert!(
        input_value_present(&run, 42),
        "the minimized run must journal the triggering input"
    );
}

#[test]
fn minimize_input_reports_unpreserved_when_no_journal_inputs() {
    let workload = InputJournalWorkload;
    let oracle = no_input_equals_42();
    let finding = input_journal_finding();

    let reduction = minimize_input(&workload, &oracle, &finding, "other-generator");
    assert!(
        !reduction.violation_preserved,
        "a generator with no journal inputs cannot preserve a violation"
    );
    assert!(
        reduction.inputs.is_empty(),
        "the un-reduced journal input must be reported"
    );
}

fn chain_journal(values: &[u64]) -> Journal {
    let mut journal = Journal::new();
    for value in values {
        journal
            .append(EntryKind::Outcome, 1, [], Payload::Number(*value))
            .expect("append must succeed");
    }
    journal
}

fn run_for_test(journal: Journal) -> RunResult {
    RunResult {
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
    }
}

#[test]
fn memoized_replay_hits_on_identical_batch() {
    let source = chain_journal(&(0..10).collect::<Vec<_>>());
    let ids = source
        .entries()
        .map(|entry| entry.id)
        .collect::<Vec<Hash>>();
    let empty = Journal::new().root_hash();

    let mut memo = MemoizedReplay::new();
    let first = memo.replay(empty, &ids, &source).unwrap();
    let second = memo.replay(empty, &ids, &source).unwrap();

    assert_eq!(
        first.root_hash(),
        source.root_hash(),
        "full batch replays the source root"
    );
    assert_eq!(
        second.root_hash(),
        first.root_hash(),
        "identical key returns the cached root"
    );
    assert_eq!(memo.stats(), (1, 1));
}

#[test]
fn memoized_replay_misses_on_distinct_batches() {
    let source = chain_journal(&(0..8).collect::<Vec<_>>());
    let ids = source
        .entries()
        .map(|entry| entry.id)
        .collect::<Vec<Hash>>();
    let empty = Journal::new().root_hash();

    let mut memo = MemoizedReplay::new();
    let full = memo.replay(empty, &ids, &source).unwrap();
    let prefix = memo.replay(empty, &ids[..5], &source).unwrap();

    assert_ne!(
        full.root_hash(),
        prefix.root_hash(),
        "different batches yield different roots"
    );
    assert_eq!(memo.stats(), (0, 2));
}

#[test]
fn memoized_replay_returns_correct_journal_for_multi_batch_sequence() {
    let source = chain_journal(&(0..8).collect::<Vec<_>>());
    let ids = source
        .entries()
        .map(|entry| entry.id)
        .collect::<Vec<Hash>>();
    let empty = Journal::new().root_hash();

    let mut memo = MemoizedReplay::new();
    let first = memo.replay(empty, &ids[..3], &source).unwrap();
    assert_eq!(first.entries().count(), 3);
    let second = memo.replay(first.root_hash(), &ids[3..6], &source).unwrap();
    assert_eq!(second.entries().count(), 6);
    let third = memo.replay(second.root_hash(), &ids[6..], &source).unwrap();
    assert_eq!(third.entries().count(), 8);
    assert_eq!(
        third.root_hash(),
        source.root_hash(),
        "chained batches must rebuild the whole source journal"
    );

    let expected = source.subgraph(&ids).unwrap();
    assert_eq!(
        third.entries().map(|entry| entry.id).collect::<Vec<_>>(),
        expected.entries().map(|entry| entry.id).collect::<Vec<_>>(),
        "the replayed journal must be the correct prefix-plus-batch journal"
    );
    assert_eq!(memo.stats(), (0, 3));
}

#[test]
fn memoized_replay_rejects_tampered_prefix_root() {
    let source = chain_journal(&(0..4).collect::<Vec<_>>());
    let ids = source
        .entries()
        .map(|entry| entry.id)
        .collect::<Vec<Hash>>();
    let empty = Journal::new().root_hash();

    let mut memo = MemoizedReplay::new();
    let first = memo.replay(empty, &ids[..2], &source).unwrap();
    assert_eq!(first.entries().count(), 2);

    // A batch that actually continues the recorded prefix is valid.
    let second = memo.replay(first.root_hash(), &ids[2..], &source).unwrap();
    assert_eq!(second.entries().count(), 4);

    // Passing the initial empty state as the prefix of a later batch is a
    // stale key: the journal state before ids[2..] is `first`, not empty.
    let stale = memo.replay(empty, &ids[2..], &source);
    let MemoError::PrefixMismatch { caller, state } = stale.unwrap_err() else {
        panic!("stale prefix must be the typed mismatch");
    };
    assert_eq!(caller, empty, "the caller root must be preserved");
    assert_eq!(
        state,
        first.root_hash(),
        "the rebuilt journal state must be preserved"
    );

    let bogus = memo.replay([0xAB; 32], &ids[..2], &source);
    let MemoError::PrefixMismatch { caller, .. } = bogus.unwrap_err() else {
        panic!("bogus initial state must be the typed mismatch");
    };
    assert_eq!(caller, [0xAB; 32]);
    assert_eq!(memo.stats(), (0, 2), "no tampered key may hit the cache");
}

/// A batch whose first entry is missing from the source is a typed
/// contract error, never a silently rebuilt journal.
#[test]
fn memoized_replay_rejects_unknown_batch_entry() {
    let source = chain_journal(&(0..4).collect::<Vec<_>>());
    let mut memo = MemoizedReplay::new();
    let err = memo
        .replay(Journal::new().root_hash(), &[[0x42; 32]], &source)
        .unwrap_err();
    assert!(matches!(err, MemoError::UnknownBatchEntry), "got {err:?}");
}

/// A batch that is not a contiguous source run is a typed contract error
/// and the journal is never rebuilt from it.
#[test]
fn memoized_replay_rejects_non_contiguous_batch() {
    let source = chain_journal(&(0..4).collect::<Vec<_>>());
    let ids = source
        .entries()
        .map(|entry| entry.id)
        .collect::<Vec<Hash>>();
    let mut memo = MemoizedReplay::new();
    let err = memo
        .replay(Journal::new().root_hash(), &[ids[0], ids[2]], &source)
        .unwrap_err();
    assert!(matches!(err, MemoError::NonContiguousBatch), "got {err:?}");
}

/// The pipeline error keeps the journal error as its source: a subgraph
/// failure must surface as the typed `Subgraph` variant with the source in
/// the chain, never folded into a message-only string.
#[test]
fn minimize_error_keeps_journal_source() {
    let err = MinimizeError::from(JournalError::MissingParent([0x7E; 32]));
    let MinimizeError::Subgraph(source) = &err else {
        panic!("expected Subgraph, got {err:?}");
    };
    assert!(matches!(source, JournalError::MissingParent(_)));
    assert!(
        err.source().is_some(),
        "the journal source must stay in the error chain"
    );
    assert!(
        err.to_string().contains("subgraph"),
        "display must identify the surface: {err}"
    );
}

/// Same for the memo error: a memo-internal subgraph failure keeps its
/// journal source, and the pipeline converts it without losing the type.
#[test]
fn memo_error_keeps_journal_source() {
    let err = MemoError::from(JournalError::MissingParent([0x7E; 32]));
    assert!(matches!(err, MemoError::Subgraph(_)), "got {err:?}");
    let wrapped = MinimizeError::from(err);
    assert!(matches!(wrapped, MinimizeError::Memo(_)), "got {wrapped:?}");
}

#[test]
fn memoized_replay_fast_forwards_repeated_batches() {
    let source = chain_journal(&(0..128).collect::<Vec<_>>());
    let ids = source
        .entries()
        .map(|entry| entry.id)
        .collect::<Vec<Hash>>();
    let empty = Journal::new().root_hash();

    let mut memo = MemoizedReplay::new();
    let first = memo.replay(empty, &ids, &source).unwrap();
    let second = memo.replay(empty, &ids, &source).unwrap();
    assert_eq!(first.root_hash(), second.root_hash());
    assert_eq!(
        memo.stats(),
        (1, 1),
        "the repeat must be served from the cache, not rebuilt"
    );
}

#[test]
fn candidate_journal_fast_forwards_source_prefix_runs() {
    let mut source = Journal::new();
    source
        .append(EntryKind::Outcome, 1, [], Payload::Number(0))
        .expect("append must succeed");
    for value in 1..20u64 {
        source
            .append(EntryKind::Outcome, 2, [], Payload::Number(value))
            .expect("append must succeed");
    }
    let ids = source
        .entries()
        .map(|entry| entry.id)
        .collect::<Vec<Hash>>();

    let mut memo = MemoizedReplay::new();
    let early = candidate_journal(&mut memo, &source, &ids[..13]).unwrap();
    assert_eq!(early.entries().count(), 13);
    assert_eq!(
        early.root_hash(),
        source.subgraph(&ids[..13]).unwrap().root_hash()
    );
    let later = candidate_journal(&mut memo, &source, &ids[..17]).unwrap();
    assert_eq!(later.entries().count(), 17);
    assert_eq!(
        later.root_hash(),
        source.subgraph(&ids[..17]).unwrap().root_hash()
    );
    assert!(
        memo.stats().0 >= 1,
        "the shared prefix batches must hit across leading-run candidates"
    );

    let interior = candidate_journal(&mut memo, &source, &[ids[1], ids[2]]).unwrap();
    assert_eq!(interior.entries().count(), 2);
}

#[test]
fn minimize_slice_forward_closure_preserves_violation() {
    let mut journal = Journal::new();
    let boundary = journal
        .append(EntryKind::Send, 1, [], Payload::Number(1))
        .expect("append must succeed");
    let witness = journal
        .append(EntryKind::Assert, 1, [], Payload::Number(0))
        .expect("append must succeed");
    let consumer = journal
        .append(EntryKind::Recv, 2, [boundary], Payload::Number(1))
        .expect("append must succeed");

    let backward = causal_slice(&journal, witness).expect("backward slice must succeed");
    assert!(
        !backward.contains(&consumer),
        "the backward-only slice must drop the boundary consumer"
    );
    let forward = causal_slice_forward(&journal, witness).expect("forward slice must succeed");
    assert!(
        forward.contains(&consumer),
        "the forward-closed slice must keep the boundary consumer"
    );

    let sliced = journal
        .subgraph(&forward)
        .expect("slice subgraph must succeed");
    let verdict = AssertionOracle.check(&run_for_test(sliced));
    assert!(
        verdict.violated,
        "replaying the forward-closed slice must preserve the violation"
    );
}

#[test]
fn minimize_full_reduces_inputs_when_generator_is_set() {
    let base = RunConfig::builder()
        .seed([10; 32])
        .policy(Policy::Random)
        .max_steps(512)
        .build();
    let workload = InputJournalWorkload;
    let oracle = no_input_equals_42();

    let with_inputs = workload.with_inputs(&[1, 42, 3]);
    let run = Simulation::new(base.clone(), with_inputs.programs())
        .run()
        .expect("finding run must execute");
    let verdict = oracle.check(&run);
    assert!(verdict.violated);
    let finding = Finding {
        seed: base.seed(),
        run,
        verdict,
    };

    let repro = minimize_full(&workload, &oracle, &finding, "input-journal")
        .expect("pipeline must complete");
    assert!(repro.violations_preserved);
    assert!(
        repro.inputs_preserved,
        "the input stage must preserve the violation"
    );
    assert!(
        repro.inputs.contains(&42),
        "inputs must keep the trigger value"
    );
    assert!(!repro.journal.is_empty());
    assert!(
        input_value_present(&run_for_test(repro.journal.clone()), 42),
        "the minimal journal must keep the triggering input entry"
    );
}

#[test]
fn minimize_full_does_not_hard_error_when_input_stage_cannot_preserve() {
    let workload = InputJournalWorkload;
    let oracle = no_input_equals_42();
    let finding = input_journal_finding();

    let repro = minimize_full(&workload, &oracle, &finding, "other-generator")
        .expect("an unpreserved input stage must not hard-error the pipeline");
    assert!(
        !repro.inputs_preserved,
        "the input stage must report non-preservation, not error"
    );
    assert!(
        repro.inputs.is_empty(),
        "the un-reduced journal input must be reported"
    );
}

/// Oracle violated when any journaled input reaches the high band.
///
/// A `Power{0.5}` energy distribution biases samples toward the top of
/// the domain, so a quad campaign over this oracle finds a violation on
/// its first attempt.
fn no_high_band_inputs() -> PropertyOracle<impl Fn(&Journal) -> bool> {
    PropertyOracle {
        property: |journal: &Journal| {
            !journal.entries().any(|entry| {
                matches!(entry.data.kind, EntryKind::InputStep { .. })
                    && matches!(&entry.data.payload, Payload::Number(value) if *value >= 80)
            })
        },
        name: "no input value in the high band".into(),
    }
}

#[test]
fn quad_power_campaign_finding_minimizes_inputs_under_recorded_schedule() {
    use crate::pbt::EnergyDistribution;
    use crate::search::{QuadMutation, run_campaign_quad};

    const HIGH_BAND_FLOOR: u64 = 80;

    let base = RunConfig::builder()
        .seed([12; 32])
        .policy(Policy::Random)
        .max_steps(512)
        .build();
    let mutation = QuadMutation {
        input_generator: Some("input-journal".into()),
        input_energy: Some(EnergyDistribution::Power { exponent: 0.5 }),
        ..Default::default()
    };
    let workload = InputJournalWorkload;
    let oracle = no_high_band_inputs();

    let finding = run_campaign_quad(&workload, &oracle, base, &mutation, 16)
        .expect("quad campaign must run")
        .findings
        .into_iter()
        .next()
        .expect("power-biased samples must reach the high band");

    // The minimizer's input stage replays every candidate under the
    // finding's recorded decisions, independent of the sampling
    // distribution that produced the inputs.
    let repro = minimize_full(&workload, &oracle, &finding, "input-journal").expect("pipeline");
    assert!(repro.violations_preserved);
    assert!(
        repro.inputs_preserved,
        "the reduced sample must keep the violation"
    );
    assert!(
        repro.inputs.len() <= 8,
        "ddmin must drop at least half of the 16 sampled inputs, kept {}",
        repro.inputs.len()
    );
    assert!(
        repro.inputs.iter().any(|value| *value >= HIGH_BAND_FLOOR),
        "the minimal input set must retain one high-band trigger"
    );
}
