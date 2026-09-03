use super::MemoizedReplay;
use super::candidate_journal;
use super::ddmin::{causal_slice_forward_all, ddmin, minimize_schedule};
use super::input::minimize_input;
use crate::oracle::Oracle;
use crate::search::{Finding, Workload, replay_prefix};
use ledger_format::EntryHash;
use ledger_journal::Journal;
use ledger_sim::RunResult;

use super::MinimizeError;

/// Output of the composed minimization pipeline.
#[derive(Debug, Clone)]
pub struct MinimizedRepro {
    /// One-minimal repro journal.
    pub journal: Journal,
    /// Schedule-delta-minimized scheduler decisions.
    pub decisions: Vec<usize>,
    /// Input-delta-minimized input values.
    ///
    /// Empty when the pipeline ran without an input generator.
    pub inputs: Vec<u64>,
    pub slice_kept: usize,
    pub slice_total: usize,
    pub violations_preserved: bool,
    /// True when the input stage's reduction still violates the oracle.
    ///
    /// False when the input stage found nothing to preserve; the pipeline
    /// still returns a repro, it just does not claim input minimality.
    pub inputs_preserved: bool,
}

/// Rebuild a minimal [`RunResult`] around a journal for oracle checking.
///
/// Only the journal carries meaning for journal-based oracles; the other
/// fields are neutral.
fn run_for_check(journal: Journal) -> RunResult {
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

/// Four-stage pipeline: slice, ddmin, schedule-delta, input-delta. Slice
/// keeps only when it still violates.
pub fn minimize_full<W, O>(
    workload: &W,
    oracle: &O,
    finding: &Finding,
    generator: &str,
) -> Result<MinimizedRepro, MinimizeError>
where
    W: Workload,
    O: Oracle,
{
    let slice_total = finding.run.journal.len();
    let all_ids = finding
        .run
        .journal
        .entries()
        .map(|entry| entry.id)
        .collect::<Vec<EntryHash>>();

    // Causal slice from all witnesses, closed forward over boundary
    // inputs so the slice is self-contained for replay.
    let (slice, slice_journal) = if !finding.verdict.witnesses.is_empty() {
        match causal_slice_forward_all(&finding.run.journal, &finding.verdict.witnesses) {
            Ok(ids) if !ids.is_empty() => {
                let journal = finding.run.journal.subgraph(&ids)?;
                if oracle.check(&run_for_check(journal.clone())).violated {
                    (ids, journal)
                } else {
                    (all_ids.clone(), finding.run.journal.clone())
                }
            }
            _ => (all_ids.clone(), finding.run.journal.clone()),
        }
    } else {
        (all_ids.clone(), finding.run.journal.clone())
    };
    let slice_kept = slice.len();

    // ddmin over the slice entry set to a one-minimal journal. Candidate
    // journals replay through the memoized replay so source-prefix runs are
    // rebuilt once across candidates instead of once per candidate.
    let mut memo = MemoizedReplay::new();
    let minimal_ids = ddmin(&slice, |candidate| {
        candidate_journal(&mut memo, &slice_journal, candidate)
            .map(|journal| oracle.check(&run_for_check(journal)).violated)
            // Deliberate discard: a candidate that cannot be rebuilt does not
            // preserve the violation, so ddmin treats it as non-minimizing.
            // The final claim is re-derived through a typed `?` below.
            .unwrap_or(false)
    });

    // Schedule-delta debugging over the recorded decisions.
    let schedule = minimize_schedule(&finding.run.decisions, |decisions| {
        replay_prefix(workload, finding.seed, decisions.to_vec())
            .map(|run| oracle.check(&run).violated)
            // Deliberate discard: same ddmin probe semantics as above; an
            // unbuildable candidate counts as non-violating, not as an error.
            .unwrap_or(false)
    });

    // Input-delta debugging over the failing journal's InputStep entries.
    let (inputs, inputs_preserved) = if generator.is_empty() {
        (Vec::new(), true)
    } else {
        let reduction = minimize_input(workload, oracle, finding, generator);
        (reduction.inputs, reduction.violation_preserved)
    };

    let journal = finding.run.journal.subgraph(&minimal_ids)?;
    let violations_preserved = oracle.check(&run_for_check(journal.clone())).violated;

    Ok(MinimizedRepro {
        journal,
        decisions: schedule.minimized_decisions,
        inputs,
        slice_kept,
        slice_total,
        violations_preserved,
        inputs_preserved,
    })
}
