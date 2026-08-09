//! history oracles over immutable journal runs.

use std::collections::BTreeMap;

use crate::journal::{Entry, Hash, Journal};
use crate::runtime::RunResult;

/// A predicate result with the entries that explain it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// Whether the predicate failed.
    pub violated: bool,
    /// Entries that witness the result.
    pub witnesses: Vec<Hash>,
    /// Human-readable explanation.
    pub reason: String,
}

/// A journal oracle.
pub trait Oracle {
    /// Evaluate the oracle against a completed run.
    fn check(&self, run: &RunResult) -> Verdict;
}

/// An abstract operation extracted from a workload history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryOperation {
    /// A write that establishes a value.
    Write {
        key: String,
        value: u64,
        witness: Hash,
    },
    /// A read that observed a value.
    Read {
        key: String,
        value: u64,
        witness: Hash,
    },
}

/// A sequential specification for history checking.
pub trait SequentialSpec: Clone {
    /// Apply one operation and return an error if its result is invalid.
    fn apply(&mut self, operation: &HistoryOperation) -> Result<(), String>;
}

/// A simple sequential key-value specification.
#[derive(Debug, Clone, Default)]
pub struct KeyValueSpec {
    values: BTreeMap<String, u64>,
}

impl SequentialSpec for KeyValueSpec {
    fn apply(&mut self, operation: &HistoryOperation) -> Result<(), String> {
        match operation {
            HistoryOperation::Write { key, value, .. } => {
                self.values.insert(key.clone(), *value);
                Ok(())
            }
            HistoryOperation::Read { key, value, .. } => {
                let expected = self.values.get(key).copied().unwrap_or(0);
                if expected == *value {
                    Ok(())
                } else {
                    Err(format!(
                        "read of {key} returned {value}, expected {expected}"
                    ))
                }
            }
        }
    }
}

/// A generic history oracle coupled to a workload's history adapter.
pub struct HistoryOracle<'a, W, S> {
    workload: &'a W,
    specification: S,
}

impl<'a, W, S> HistoryOracle<'a, W, S> {
    /// Create a history oracle for a workload and sequential specification.
    pub const fn new(workload: &'a W, specification: S) -> Self {
        Self {
            workload,
            specification,
        }
    }
}

impl<W, S> Oracle for HistoryOracle<'_, W, S>
where
    W: crate::explorer::Workload,
    S: SequentialSpec,
{
    fn check(&self, run: &RunResult) -> Verdict {
        let mut specification = self.specification.clone();
        for operation in self.workload.history(run) {
            let witness = match &operation {
                HistoryOperation::Write { witness, .. }
                | HistoryOperation::Read { witness, .. } => *witness,
            };
            if let Err(reason) = specification.apply(&operation) {
                return Verdict {
                    violated: true,
                    witnesses: vec![witness],
                    reason,
                };
            }
        }
        Verdict {
            violated: false,
            witnesses: Vec::new(),
            reason: "history satisfies its sequential specification".into(),
        }
    }
}

/// Compare two journal streams and return their first differing pair.
pub fn first_divergence<'a>(
    left: &'a Journal,
    right: &'a Journal,
) -> Option<(Option<&'a Entry>, Option<&'a Entry>)> {
    let mut left_iter = left.entries();
    let mut right_iter = right.entries();
    loop {
        let l = left_iter.next();
        let r = right_iter.next();
        if l.map(|entry| entry.id) != r.map(|entry| entry.id) {
            return Some((l, r));
        }
        l?;
    }
}
