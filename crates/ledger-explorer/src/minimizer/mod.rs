//! Multi-stage minimization pipeline: causal slice, event ddmin, schedule-delta
//! debugging, input-delta debugging, and memoized replay.

mod ddmin;
mod input;
mod memo;
mod pipeline;
#[cfg(test)]
mod tests;

pub use ddmin::{MinimizationReport, causal_slice, causal_slice_forward, ddmin, minimize_schedule};
pub use input::{InputReduction, minimize_input, minimize_input_with_faults};
pub use memo::{MemoError, MemoizedReplay};
pub use pipeline::{MinimizedRepro, minimize_full};

use crate::pbt::gen_id;
use ledger_format::{EntryHash, EntryKind, EntryPayload};
use ledger_journal::{Journal, JournalError};
use thiserror::Error;

/// Typed failure of the minimization pipeline.
#[derive(Debug, Error)]
pub enum MinimizeError {
    /// A journal subgraph could not be built for a candidate.
    #[error("journal subgraph build failed: {0}")]
    Subgraph(#[from] JournalError),
    /// A memoized replay contract error.
    #[error("memoized replay: {0}")]
    Memo(#[from] MemoError),
}

/// Extract the generated input sequence from a journal.
///
/// The sequence is the `InputStepPayload` values of the `InputStep` entries
/// for `generator`, in journal order. This is the exact input that produced
/// the journal, never a fresh re-sample.
fn journal_inputs(journal: &Journal, generator: &str) -> Vec<u64> {
    let generator_id = gen_id(generator);
    journal
        .entries()
        .filter_map(|entry| match &entry.data.payload {
            EntryPayload::InputStep(step)
                if entry.data.kind == EntryKind::InputStep && step.generator == generator_id =>
            {
                match step.value {
                    ledger_format::CanonicalValue::Unsigned(value) => Some(value),
                    _ => None,
                }
            }
            _ => None,
        })
        .collect()
}

/// Batch size for memoized prefix replay of ddmin candidates.
const CANDIDATE_REPLAY_BATCH: usize = 8;

/// Return the length of `candidate` when it is a leading run of `source`'s
/// append order; `None` otherwise.
fn source_prefix_len(source: &Journal, candidate: &[EntryHash]) -> Option<usize> {
    if candidate.is_empty() {
        return Some(0);
    }
    let ids = source.entries().map(|entry| entry.id).collect::<Vec<_>>();
    if candidate.len() <= ids.len() && ids[..candidate.len()] == *candidate {
        Some(candidate.len())
    } else {
        None
    }
}

/// Replay one ddmin candidate journal, fast-forwarding source-prefix runs.
///
/// A candidate equal to a leading run of the source journal is a contiguous
/// batch sequence: replaying it through [`MemoizedReplay`] in fixed-size
/// batches rebuilds the shared prefix once and reuses the cached journal on
/// later candidates. Interior-removal candidates are not contiguous source
/// runs; they are rebuilt directly.
fn candidate_journal(
    memo: &mut MemoizedReplay,
    source: &Journal,
    candidate: &[EntryHash],
) -> Result<Journal, MinimizeError> {
    if let Some(prefix_len) = source_prefix_len(source, candidate)
        && prefix_len > 0
    {
        let source_root = source.root_hash();
        let order = source.entries().map(|entry| entry.id).collect::<Vec<_>>();
        let mut prefix_root = Journal::new().root_hash();
        let mut journal = Journal::new();
        let mut offset = 0;
        while offset < prefix_len {
            let end = (offset + CANDIDATE_REPLAY_BATCH).min(prefix_len);
            journal =
                memo.replay_with_root(source_root, prefix_root, &order[offset..end], source)?;
            prefix_root = journal.root_hash();
            offset = end;
        }
        return Ok(journal);
    }
    source.subgraph(candidate).map_err(MinimizeError::Subgraph)
}
