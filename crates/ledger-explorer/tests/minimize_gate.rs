//! Minimization gate: at least 90% of entries removed off a failing
//! 10^6-entry run, violation preserved, judged by a VALUE-DEPENDENT causal
//! oracle instead of a marker-assertion oracle.
//!
//! The oracle is [`ExactlyOnceValueOracle`]: an exactly-once journal
//! invariant over observed values. A run violates when an input value is
//! applied twice (a duplicate apply) or when the final outcome does not
//! match the last applied value (a torn final apply). The verdict is
//! decided by the VALUES of the causal event set, never by the presence of
//! one marker entry.
//!
//! The failing workload journals one million distinct noise inputs on actor
//! 0, then applies the same value twice (`Set(42)`, `Set(42)`) and records
//! the outcome. Measured on this fixture, the run journals 2,000,009
//! entries in TWO classes:
//!
//! - The actor-0 instruction chain: ~1,000,005 entries (the one million
//!   distinct noise inputs, the duplicated pair, the numeric outcome, and
//!   the terminal marker). Every entry parents the actor's previous head,
//!   so the whole noise stream is causally ancestral to the witness.
//! - The scheduler's per-step `RngDraw` stream: ~1,000,004 entries on their
//!   own actor, journaled for the random-policy step draws. They are NOT
//!   ancestral to the witness, so the causal slice alone drops exactly this
//!   class (50.0% reduction measured); ddmin then removes the ancestral
//!   half down to the duplicated pair (100.0% reduction measured).
//!
//! The duplicate pair is the unique minimal failing set: removing either
//! member flips the verdict to pass, and adding back a removed event keeps
//! it failing. The assertion-oracle shortcut (one marker entry alone
//! decides the verdict) is impossible here: a journal without the
//! duplicated value always passes.
//!
//! The gate asserts:
//!
//! 1. The violation is preserved after every stage (slice and final).
//! 2. The causal slice ALONE reduces less than 80%: the ancestral chain
//!    keeps every instruction entry in the witness's causal past, so the
//!    slice cannot explain the result by dropping the noise.
//! 3. The final (post-ddmin) result reduces at least 90%.
//! 4. The ddmin event stage genuinely contributed: the final entry count is
//!    below the slice entry count by at least 10^5 entries.
//! 5. Verdict sensitivity: removing each retained dependency flips the
//!    verdict to pass; adding back SAMPLED removed events keeps it failing;
//!    the noise-only journal passes.
//!
//! The numbers come from the production APIs (`causal_slice_forward`,
//! `ddmin`, `Journal::subgraph`) at full 10^6 scale, the same stages
//! `minimize_full` composes; the schedule-delta stage is not run because
//! each of its candidates replays the whole 10^6-step simulation.
//!
//! Release-oriented: run with
//! `cargo test -p ledger-explorer --test minimize_gate --release`.

use ledger_explorer::minimizer::{causal_slice_forward, ddmin};
use ledger_explorer::oracle::{ExactlyOnceValueOracle, Oracle};
use ledger_format::{CanonicalValue, EntryHash, EntryKind, EntryPayload};
use ledger_sim::{Instruction, Policy, RunConfig, RunResult, Simulation};

/// Total noise inputs journaled on actor 0.
const NOISE: u64 = 1_000_000;
/// The duplicated apply value: the unique two-entry minimal failing set.
const DUP_VALUE: u64 = 42;

/// A noise input value: distinct across the whole stream and never the
/// duplicated apply value, so the noise alone can never trigger the
/// exactly-once oracle.
fn noise_value(index: u64) -> u64 {
    if index < DUP_VALUE { index } else { index + 1 }
}

/// Build the failing workload: one million distinct noise inputs, the
/// duplicated apply pair, and the outcome recording the applied value.
fn failing_programs() -> Vec<Vec<Instruction>> {
    let mut program = Vec::with_capacity(NOISE as usize + 3);
    for index in 0..NOISE {
        program.push(Instruction::Set(noise_value(index)));
    }
    program.push(Instruction::Set(DUP_VALUE));
    program.push(Instruction::Set(DUP_VALUE));
    program.push(Instruction::Outcome);
    program.push(Instruction::Done);
    vec![program]
}

/// Rebuild a minimal `RunResult` around a journal for oracle checking, the
/// same shape the minimizer pipeline uses internally.
fn run_for_check(journal: ledger_journal::Journal) -> RunResult {
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
        protection: ledger_sim::BeltStatus::NotArmed,
    }
}

/// Oracle check over one candidate entry set: rebuild the subgraph journal
/// and ask the exactly-once value oracle. Subgraph rebuilds that fail count
/// as non-failing candidates, mirroring `minimize_full`'s ddmin closure.
fn candidate_violates(source: &ledger_journal::Journal, candidate: &[EntryHash]) -> bool {
    source
        .subgraph(candidate)
        .map(|journal| {
            ExactlyOnceValueOracle
                .check(&run_for_check(journal))
                .violated
        })
        .unwrap_or(false)
}

/// The entry ids of the duplicated apply pair in a journal.
fn duplicate_pair_ids(journal: &ledger_journal::Journal) -> Vec<EntryHash> {
    journal
        .entries()
        .filter(|entry| {
            matches!(entry.data.kind, EntryKind::InputStep)
                && matches!(&entry.data.payload, EntryPayload::InputStep(ledger_format::InputStepPayload {
            generator: _,
            replay: _,
            value: CanonicalValue::Unsigned(value),
        }) if *value == DUP_VALUE)
        })
        .map(|entry| entry.id)
        .collect()
}

/// The id of the last numeric Outcome entry in journal order.
fn numeric_outcome_id(journal: &ledger_journal::Journal) -> Option<EntryHash> {
    journal
        .entries()
        .filter(|entry| {
            entry.data.kind == EntryKind::Outcome
                && matches!(
                    &entry.data.payload,
                    EntryPayload::Outcome(ledger_format::OutcomePayload {
                        value: CanonicalValue::Unsigned(_),
                        ..
                    })
                )
        })
        .map(|entry| entry.id)
        .last()
}

#[test]
fn minimize_removes_90_percent_of_an_entangled_million_entry_failure() {
    let programs = failing_programs();
    let config = RunConfig::builder()
        .seed(EntryHash([1; 32]))
        .policy(Policy::Random)
        .max_steps(2_000_000)
        .build();

    let run = Simulation::new(config, programs)
        .run()
        .expect("the failing run must execute");
    let total_entries = run.journal.len();
    assert!(
        total_entries >= 1_000_000,
        "gate requires a 10^6-entry run, got {total_entries}"
    );

    let verdict = ExactlyOnceValueOracle.check(&run);
    assert!(
        verdict.violated,
        "the duplicated apply must violate the exactly-once oracle"
    );
    // Anchor the causal slice at the numeric outcome (the terminal `Done`
    // journals a separate text-payload Outcome entry).
    let witness = numeric_outcome_id(&run.journal).expect("the run must journal a numeric outcome");

    // The minimal failing set is the duplicated apply pair; locate it in the
    // full journal before minimization.
    let pair = duplicate_pair_ids(&run.journal);
    assert_eq!(
        pair.len(),
        2,
        "the fixture must journal the duplicated apply exactly twice"
    );

    // Stage 1: causal slice from the witness, forward-closed over boundary
    // inputs exactly as minimize_full slices.
    let slice = causal_slice_forward(&run.journal, witness).expect("slice must succeed");
    assert!(
        !slice.is_empty(),
        "the causal slice of the witness must not be empty"
    );
    let slice_len = slice.len();
    let slice_reduction = (total_entries - slice_len) as f64 / total_entries as f64 * 100.0;

    // (2) Entanglement: the chain makes every entry a causal ancestor of the
    // witness, so the causal slice alone keeps almost the whole run.
    assert!(
        slice_reduction < 80.0,
        "causal slice alone reduced {slice_reduction:.1}% (>80%): the noise is not entangled \
         (slice kept {slice_len} of {total_entries})"
    );
    assert!(
        pair.iter().all(|id| slice.contains(id)),
        "the causal slice must keep the duplicated apply pair"
    );
    // And the slice must still preserve the violation.
    let slice_journal = run
        .journal
        .subgraph(&slice)
        .expect("slice subgraph must build");
    assert!(
        ExactlyOnceValueOracle
            .check(&run_for_check(slice_journal.clone()))
            .violated,
        "the causal slice must still violate the exactly-once oracle"
    );

    // Stage 2: ddmin over the slice entry set, the same event stage
    // minimize_full runs, at the full 10^6-entry scale.
    let minimal_ids = ddmin(&slice, |candidate| {
        candidate_violates(&slice_journal, candidate)
    });
    let final_len = minimal_ids.len();

    // The unique minimal failing set is the duplicated apply pair: neither
    // member is individually sufficient, so a one-element journal passes.
    assert_eq!(
        final_len, 2,
        "the minimal failing set must be the duplicated apply pair, got {} entries",
        final_len
    );
    assert!(
        minimal_ids.iter().all(|id| pair.contains(id)),
        "the minimized journal must retain exactly the duplicated apply entries"
    );

    let minimal_journal = run
        .journal
        .subgraph(&minimal_ids)
        .expect("minimal subgraph must build");

    // (1) Violation preserved after minimization.
    assert!(
        ExactlyOnceValueOracle
            .check(&run_for_check(minimal_journal.clone()))
            .violated,
        "the minimized journal must still violate the exactly-once oracle"
    );

    // (3) Final reduction >= 90%.
    let final_reduction = (total_entries - final_len) as f64 / total_entries as f64 * 100.0;
    assert!(
        final_reduction >= 90.0,
        "gate requires >= 90% final reduction, got {final_reduction:.1}% ({total_entries} -> {final_len})"
    );

    // (4) The ddmin stage contributed beyond the causal slice by a wide
    // margin: at least 10^5 additional entries removed.
    let ddmin_removed = slice_len.saturating_sub(final_len);
    assert!(
        final_len < slice_len && ddmin_removed >= 100_000,
        "the ddmin stage must contribute: slice kept {slice_len}, final kept {final_len} \
         (removed {ddmin_removed}, need >= 100000)"
    );

    // (5) Verdict sensitivity to the causal event set.
    // (5a) Removing any retained dependency flips the verdict to pass.
    for retained in &minimal_ids {
        let reduced_ids = minimal_ids
            .iter()
            .copied()
            .filter(|id| id != retained)
            .collect::<Vec<EntryHash>>();
        assert!(
            !candidate_violates(&run.journal, &reduced_ids),
            "removing the retained dependency {:02x?} must flip the verdict to pass",
            &retained.0[..4]
        );
    }
    // (5b) Adding back SAMPLED removed events keeps the verdict failing:
    // the witness and the first four removed entries are asserted here, a
    // five-entry sample of the removed set.
    let mut removed_sample: Vec<EntryHash> = vec![witness];
    removed_sample.extend(
        run.journal
            .entries()
            .take(4)
            .map(|entry| entry.id)
            .filter(|id| !minimal_ids.contains(id)),
    );
    assert!(
        removed_sample.iter().all(|id| !minimal_ids.contains(id)),
        "the removed-event sample must not overlap the minimal set"
    );
    for removed in &removed_sample {
        let mut extended = minimal_ids.clone();
        extended.push(*removed);
        assert!(
            candidate_violates(&run.journal, &extended),
            "adding back the sampled removed event {:02x?} must keep the verdict failing",
            &removed.0[..4]
        );
    }
    // (5c) The noise alone never violates: strip the pair and the outcome.
    let noise_ids = run
        .journal
        .entries()
        .map(|entry| entry.id)
        .filter(|id| !pair.contains(id) && *id != witness)
        .collect::<Vec<EntryHash>>();
    assert!(
        !candidate_violates(&run.journal, &noise_ids),
        "the noise-only journal must pass the exactly-once oracle"
    );

    println!(
        "minimize gate: entries={total_entries}, causal-slice={slice_len} ({slice_reduction:.1}% \
         reduced), final={final_len} ({final_reduction:.1}% reduced), ddmin-contribution={ddmin_removed}"
    );
}
