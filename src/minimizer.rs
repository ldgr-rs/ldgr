//! Causal slicing and delta debugging.

use crate::journal::{Hash, Journal, JournalError};

/// Compute the backward causal slice for a witness.
pub fn causal_slice(journal: &Journal, witness: Hash) -> Result<Vec<Hash>, JournalError> {
    journal.causal_closure(witness)
}

/// Return a one-minimal failing subset using Zeller's delta-debugging loop.
pub fn ddmin<T: Clone, F: Fn(&[T]) -> bool>(input: &[T], fails: F) -> Vec<T> {
    if input.len() < 2 || !fails(input) {
        return input.to_vec();
    }
    let mut current = input.to_vec();
    let mut partitions = 2usize;
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
            let mut candidate = Vec::with_capacity(current.len() - (end - start));
            candidate.extend_from_slice(&current[..start]);
            candidate.extend_from_slice(&current[end..]);
            if fails(&candidate) {
                current = candidate;
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

#[cfg(test)]
mod tests {
    use super::ddmin;

    #[test]
    fn removes_irrelevant_items() {
        let input = [1, 2, 3, 4];
        let result = ddmin(&input, |items| items.contains(&2) && items.contains(&4));
        assert_eq!(result, [2, 4]);
    }
}
