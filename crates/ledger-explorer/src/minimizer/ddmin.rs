use ledger_format::Hash;
use ledger_journal::Journal;
use ledger_journal::JournalError;

#[derive(Debug, Clone, PartialEq)]
pub struct MinimizationReport {
    pub original_count: usize,
    pub minimized_count: usize,
    /// Percentage reduction achieved (0.0 .. 100.0).
    pub reduction_percent: f64,
    pub minimized_decisions: Vec<usize>,
}

pub fn causal_slice(journal: &Journal, witness: Hash) -> Result<Vec<Hash>, JournalError> {
    journal.causal_slice(&[witness])
}

/// Causal slice closed forward over its boundary inputs.
///
/// The minimizer's slice path uses the forward-closed slice so the repro
/// journal is self-contained for replay: the entries that consume the sliced
/// boundary events are kept alongside their causes.
pub fn causal_slice_forward(journal: &Journal, witness: Hash) -> Result<Vec<Hash>, JournalError> {
    journal.causal_slice_forward(&[witness])
}

/// Return a one-minimal failing subset using the ddmin delta-debugging algorithm.
pub fn ddmin<T: Clone, F: FnMut(&[T]) -> bool>(input: &[T], mut fails: F) -> Vec<T> {
    if input.len() < 2 || !fails(input) {
        return input.to_vec();
    }
    let mut current = input.to_vec();
    let mut partitions = 2usize;
    let mut candidate = Vec::new();
    while current.len() >= 2 {
        let chunk = current.len().div_ceil(partitions);
        let mut reduced = false;
        let mut index = 0;
        while index < partitions {
            let start = index * chunk;
            if start >= current.len() {
                break;
            }
            let end = (start + chunk).min(current.len());
            candidate.clear();
            candidate.reserve((current.len() - (end - start)).saturating_sub(candidate.capacity()));
            candidate.extend_from_slice(&current[..start]);
            candidate.extend_from_slice(&current[end..]);
            if fails(&candidate) {
                current = std::mem::take(&mut candidate);
                partitions = partitions.saturating_sub(1).max(2);
                reduced = true;
                break;
            }
            index += 1;
        }
        if !reduced {
            if partitions == current.len() {
                break;
            }
            partitions = (partitions * 2).min(current.len());
        }
    }
    current
}

/// Minimize a scheduler decision sequence while preserving the failure predicate.
pub fn minimize_schedule<F: Fn(&[usize]) -> bool>(
    decisions: &[usize],
    oracle_check: F,
) -> MinimizationReport {
    let original_count = decisions.len();
    let minimized_decisions = ddmin(decisions, oracle_check);
    let minimized_count = minimized_decisions.len();
    let reduction_percent = if original_count > 0 {
        ((original_count.saturating_sub(minimized_count)) as f64 / original_count as f64) * 100.0
    } else {
        0.0
    };

    MinimizationReport {
        original_count,
        minimized_count,
        reduction_percent,
        minimized_decisions,
    }
}
