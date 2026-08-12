//! Multi-stage minimization pipeline: causal slice, event ddmin, schedule-delta
//! debugging, input-delta debugging, and memoized replay.

use crate::oracle::Oracle;
use crate::pbt::gen_id;
use crate::search::{Finding, Workload, replay};
use ledger_format::{EntryKind, Hash, Payload};
use ledger_journal::{Journal, JournalError};
use ledger_sim::{Policy, RunConfig, RunResult, Simulation};
use std::collections::HashMap;

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

pub fn causal_slice_multi(
    journal: &Journal,
    witnesses: &[Hash],
) -> Result<Vec<Hash>, JournalError> {
    journal.causal_slice(witnesses)
}

/// Return a one-minimal failing subset using the ddmin delta-debugging algorithm.
pub fn ddmin<T: Clone, F: FnMut(&[T]) -> bool>(input: &[T], mut fails: F) -> Vec<T> {
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

/// Extract the generated input sequence from a journal.
///
/// The sequence is the `Payload::Number` values of the `InputStep` entries
/// for `generator`, in journal order. This is the exact input that produced
/// the journal, never a fresh re-sample.
fn journal_inputs(journal: &Journal, generator: &str) -> Vec<u64> {
    let generator_id = gen_id(generator);
    journal
        .entries()
        .filter_map(|entry| {
            let entry_generator = match entry.data.kind {
                EntryKind::InputStep { generator, .. } => generator,
                _ => return None,
            };
            if entry_generator != generator_id {
                return None;
            }
            match &entry.data.payload {
                Payload::Number(value) => Some(*value),
                _ => None,
            }
        })
        .collect()
}

/// Outcome of the input-delta debugging stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputReduction {
    /// One-minimal input values in journal order.
    pub inputs: Vec<u64>,
    /// True when the reduced inputs still violate the oracle.
    pub violation_preserved: bool,
}

/// Input-delta debugging over the generated input that produced a finding.
///
/// The input is read from the failing journal's `InputStep` entries, so ddmin
/// runs over the exact sequence that violated the oracle. Every candidate
/// replays under the finding's recorded schedule, keeping the input reduction
/// on the finding's own schedule axis. When no reduction preserves the
/// violation, the un-reduced journal input is returned with
/// `violation_preserved` false; the stage never errors on that.
pub fn minimize_input<W, O>(
    workload_template: &W,
    oracle: &O,
    finding: &Finding,
    generator: &str,
) -> InputReduction
where
    W: Workload,
    O: Oracle,
{
    let full = journal_inputs(&finding.run.journal, generator);
    let fails = |candidate: &[u64]| -> bool {
        let workload = workload_template.with_inputs(candidate);
        let config = RunConfig {
            seed: finding.seed,
            policy: Policy::Replay,
            max_steps: finding.run.decisions.len().saturating_add(256),
            ..RunConfig::default()
        };
        Simulation::with_replay(config, workload.programs(), finding.run.decisions.clone())
            .run()
            .map(|run| oracle.check(&run).violated)
            .unwrap_or(false)
    };
    let preserved = fails(&full);
    let inputs = if preserved { ddmin(&full, fails) } else { full };
    InputReduction {
        inputs,
        violation_preserved: preserved,
    }
}

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
        journal,
        decisions: Vec::new(),
        trace: Vec::new(),
        registers: Vec::new(),
        steps: 0,
        monitor_issues: Vec::new(),
        applied_faults: Vec::new(),
    }
}

/// Compose the four-stage minimization pipeline.
///
/// The pipeline runs in order: backward causal slice from the first oracle
/// witness, ddmin over the slice entry set, schedule-delta debugging over
/// the recorded decisions, and input-delta debugging when `generator` is
/// non-empty. The slice is kept only if it still violates the oracle;
/// otherwise the full journal is used.
pub fn minimize_full<W, O>(
    workload: &W,
    oracle: &O,
    finding: &Finding,
    generator: &str,
) -> Result<MinimizedRepro, String>
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
        .collect::<Vec<Hash>>();

    // Causal slice from the first witness, closed forward over boundary
    // inputs so the slice is self-contained for replay.
    let witness = finding.verdict.witnesses.first().copied();
    let (slice, slice_journal) = match witness {
        Some(target) => match causal_slice_forward(&finding.run.journal, target) {
            Ok(ids) if !ids.is_empty() => {
                let journal = finding
                    .run
                    .journal
                    .subgraph(&ids)
                    .map_err(|error| format!("slice subgraph failed: {error}"))?;
                if oracle.check(&run_for_check(journal.clone())).violated {
                    (ids, journal)
                } else {
                    (all_ids.clone(), finding.run.journal.clone())
                }
            }
            _ => (all_ids.clone(), finding.run.journal.clone()),
        },
        None => (all_ids.clone(), finding.run.journal.clone()),
    };
    let slice_kept = slice.len();

    // ddmin over the slice entry set to a one-minimal journal. Candidate
    // journals replay through the memoized replay so source-prefix runs are
    // rebuilt once across candidates instead of once per candidate.
    let mut memo = MemoizedReplay::new();
    let minimal_ids = ddmin(&slice, |candidate| {
        candidate_journal(&mut memo, &slice_journal, candidate)
            .map(|journal| oracle.check(&run_for_check(journal)).violated)
            .unwrap_or(false)
    });

    // Schedule-delta debugging over the recorded decisions.
    let schedule = minimize_schedule(&finding.run.decisions, |decisions| {
        replay(workload, finding.seed, decisions.to_vec())
            .map(|run| oracle.check(&run).violated)
            .unwrap_or(false)
    });

    // Input-delta debugging over the failing journal's InputStep entries.
    let (inputs, inputs_preserved) = if generator.is_empty() {
        (Vec::new(), true)
    } else {
        let reduction = minimize_input(workload, oracle, finding, generator);
        (reduction.inputs, reduction.violation_preserved)
    };

    let journal = finding
        .run
        .journal
        .subgraph(&minimal_ids)
        .map_err(|error| format!("minimal subgraph failed: {error}"))?;
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

fn hash_batch(next_batch: &[Hash]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    for id in next_batch {
        hasher.update(id);
    }
    *hasher.finalize().as_bytes()
}

/// Batch size for memoized prefix replay of ddmin candidates.
const CANDIDATE_REPLAY_BATCH: usize = 8;

/// Memoized replay keyed by `(prefix_root_hash, next_entry_batch_hash)`.
///
/// `prefix_root_hash` is the root of the journal state before the batch: the
/// subgraph of the source entries strictly preceding the batch in append
/// order. Every call verifies the caller's prefix root against that state, so
/// a stale or tampered key is an error, never a wrong answer. The batch must
/// be a contiguous run of the source's append order. Identical keys return
/// the cached journal without rebuilding it.
#[derive(Debug, Default)]
pub struct MemoizedReplay {
    /// `(prefix_root, batch_hash)` to the replayed journal.
    cache: HashMap<(Hash, Hash), Journal>,
    /// Verified prefix roots by `(source_root, prefix_len)`, so repeat calls
    /// with the same prefix verify in O(1) instead of rebuilding it.
    prefix_roots: HashMap<(Hash, usize), Hash>,
    /// Source append order by source root, so batch location is O(1) per call.
    orders: HashMap<Hash, std::sync::Arc<Vec<Hash>>>,
    /// Batch content hashes by `(source_root, batch_start, batch_len)`, so a
    /// repeated batch is not re-hashed on every call.
    batch_hashes: HashMap<(Hash, usize, usize), Hash>,
    hits: usize,
    misses: usize,
}

impl MemoizedReplay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replay one batch of entries and return the journal after the batch.
    ///
    /// `prefix_root_hash` must be the root of the journal state before the
    /// batch; use [`Journal::root_hash`] of an empty journal for the initial
    /// state. `source` provides the entry contents for each batch id. A
    /// mismatched prefix root or a non-contiguous batch is an error, never a
    /// wrong answer.
    pub fn replay(
        &mut self,
        prefix_root_hash: Hash,
        next_batch: &[Hash],
        source: &Journal,
    ) -> Result<Journal, String> {
        let source_root = source.root_hash();
        self.replay_with_root(source_root, prefix_root_hash, next_batch, source)
    }

    /// Replay one batch against a caller-verified source root.
    ///
    /// `source_root` must be [`Journal::root_hash`] of `source`; the caller
    /// computes it once and reuses it, so repeat calls never re-hash the
    /// source. A batch that cannot be located in the source's append order is
    /// an error, so an inconsistent root can never produce a wrong answer.
    pub fn replay_with_root(
        &mut self,
        source_root: Hash,
        prefix_root_hash: Hash,
        next_batch: &[Hash],
        source: &Journal,
    ) -> Result<Journal, String> {
        let order = self
            .orders
            .entry(source_root)
            .or_insert_with(|| {
                std::sync::Arc::new(source.entries().map(|entry| entry.id).collect::<Vec<_>>())
            })
            .clone();

        let first = if next_batch.is_empty() {
            if source_root != prefix_root_hash {
                return Err(format!(
                    "memoized replay prefix mismatch: caller supplied {:02x?}, the empty-batch state is the whole journal ({:02x?})",
                    &prefix_root_hash[..8],
                    &source_root[..8],
                ));
            }
            return Ok(source.clone());
        } else {
            let Some(start) = order.iter().position(|id| *id == next_batch[0]) else {
                return Err("memoized replay batch entry is not in the source journal".into());
            };
            let len = next_batch.len();
            let contiguous = start + len <= order.len() && order[start..start + len] == *next_batch;
            if !contiguous {
                return Err(
                    "memoized replay batch must be a contiguous run of the source journal".into(),
                );
            }
            start
        };

        let prefix_root = match self.prefix_roots.get(&(source_root, first)) {
            Some(&root) => root,
            None => {
                let root = source
                    .subgraph(&order[..first])
                    .map_err(|error| format!("memoized replay prefix rebuild failed: {error}"))?
                    .root_hash();
                self.prefix_roots.insert((source_root, first), root);
                root
            }
        };
        if prefix_root != prefix_root_hash {
            return Err(format!(
                "memoized replay prefix mismatch: caller supplied {:02x?}, journal state before the batch is {:02x?}",
                &prefix_root_hash[..8],
                &prefix_root[..8],
            ));
        }

        let len = next_batch.len();
        let batch_hash = *self
            .batch_hashes
            .entry((source_root, first, len))
            .or_insert_with(|| hash_batch(next_batch));
        let key = (prefix_root, batch_hash);
        if let Some(journal) = self.cache.get(&key) {
            self.hits += 1;
            return Ok(journal.clone());
        }
        self.misses += 1;
        let journal = source
            .subgraph(&order[..first + len])
            .map_err(|error| format!("memoized replay rebuild failed: {error}"))?;
        self.cache.insert(key, journal.clone());
        Ok(journal)
    }

    pub fn stats(&self) -> (usize, usize) {
        (self.hits, self.misses)
    }
}

/// Return the length of `candidate` when it is a leading run of `source`'s
/// append order; `None` otherwise.
fn source_prefix_len(source: &Journal, candidate: &[Hash]) -> Option<usize> {
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
    candidate: &[Hash],
) -> Result<Journal, String> {
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
    source
        .subgraph(candidate)
        .map_err(|error| format!("candidate subgraph failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle::{AssertionOracle, HistoryOperation, Oracle, PropertyOracle};
    use ledger_format::{EntryKind, Payload};
    use ledger_journal::Journal;
    use ledger_sim::{Instruction, Policy, RunResult};

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
        let base = RunConfig {
            seed: [10; 32],
            policy: Policy::Random,
            max_steps: 512,
            ..RunConfig::default()
        };
        let workload = InputJournalWorkload;
        let oracle = no_input_equals_42();
        let with_inputs = workload.with_inputs(&[1, 42, 3]);
        let run = Simulation::new(base.clone(), with_inputs.programs())
            .run()
            .expect("finding run must execute");
        let verdict = oracle.check(&run);
        assert!(verdict.violated, "the finding must journal a 42 input");
        Finding {
            seed: base.seed,
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
            journal,
            decisions: Vec::new(),
            trace: Vec::new(),
            registers: Vec::new(),
            steps: 0,
            monitor_issues: Vec::new(),
            applied_faults: Vec::new(),
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
        assert!(
            stale.is_err(),
            "a stale prefix root must be an error, not a wrong answer"
        );

        let bogus = memo.replay([0xAB; 32], &ids[..2], &source);
        assert!(
            bogus.is_err(),
            "a bogus initial state must be rejected, not served from the cache"
        );
        assert_eq!(memo.stats(), (0, 2), "no tampered key may hit the cache");
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
        let base = RunConfig {
            seed: [10; 32],
            policy: Policy::Random,
            max_steps: 512,
            ..RunConfig::default()
        };
        let workload = InputJournalWorkload;
        let oracle = no_input_equals_42();

        let with_inputs = workload.with_inputs(&[1, 42, 3]);
        let run = Simulation::new(base.clone(), with_inputs.programs())
            .run()
            .expect("finding run must execute");
        let verdict = oracle.check(&run);
        assert!(verdict.violated);
        let finding = Finding {
            seed: base.seed,
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
}
