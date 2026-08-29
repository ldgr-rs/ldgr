//! Composable history, assertion, invariant, and differential oracles over journal runs.

use ledger_format::{EntryKind, EntryPayload, Hash};
use ledger_journal::Journal;
use ledger_sim::RunResult;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};

/// A predicate evaluation verdict with causal witness hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub violated: bool,
    /// Journal entry hashes witnessing the violation.
    pub witnesses: Vec<Hash>,
    pub reason: String,
}

impl Verdict {
    pub fn pass() -> Self {
        Self {
            violated: false,
            witnesses: Vec::new(),
            reason: "specification satisfied".into(),
        }
    }

    pub fn fail(witnesses: Vec<Hash>, reason: impl Into<String>) -> Self {
        Self {
            violated: true,
            witnesses,
            reason: reason.into(),
        }
    }
}

/// An oracle that evaluates properties over completed simulation runs.
pub trait Oracle {
    fn check(&self, run: &RunResult) -> Verdict;
}

/// Exactly-once journal oracle over observed values.
///
/// The oracle checks two value-dependent invariants against the journaled
/// input stream:
///
/// 1. Every input value is applied at most once. A repeated value is a
///    duplicate apply of the same command and violates exactly-once
///    semantics. CONTRACT: the oracle's domain is exactly-once streams; a
///    workload whose protocol legitimately re-applies a value must not use
///    this oracle.
/// 2. When inputs exist and an outcome exists, the outcome payload must
///    equal the last applied input value. A different value is a torn final
///    apply: the visible result does not match the last command.
///
/// STREAM SCOPE: both conditions read the JOURNAL-GLOBAL last input and the
/// journal-global last numeric outcome, whichever actor journaled them. The
/// oracle therefore models a single input stream feeding a single outcome
/// stream. A journal that interleaves several independent actor streams
/// must scope per actor or rely on the duplicate-apply condition alone;
/// comparing streams across actors would compare unrelated values.
///
/// The verdict is value-dependent on the causal event set: the journal's
/// entry values decide the outcome, not the mere presence of a marker entry.
/// The duplicate-apply condition is monotone in the entry set: adding entries
/// never removes a duplicate, so extending a minimal failing journal keeps it
/// failing. A duplicate-apply violation carries the outcome and assertion
/// entries as witnesses, matching [`PropertyOracle`]; a torn-apply violation
/// carries only the numeric outcome entry it compares. The reason strings
/// name the duplicated value and its entry positions.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExactlyOnceValueOracle;

impl Oracle for ExactlyOnceValueOracle {
    fn check(&self, run: &RunResult) -> Verdict {
        let mut input_values: HashMap<u64, Vec<usize>> = HashMap::new();
        let mut last_input: Option<(u64, usize)> = None;
        // The last numeric Outcome in journal order: the terminal `Done`
        // journals an Outcome with a text payload that must not shadow it.
        let mut last_numeric_outcome: Option<Hash> = None;
        for (index, entry) in run.journal.entries().enumerate() {
            if let EntryPayload::InputStep(step) = &entry.data.payload {
                if let ledger_format::CanonicalValue::Unsigned(value) = step.value {
                    input_values.entry(value).or_default().push(index);
                    last_input = Some((value, index));
                }
            } else if entry.data.kind == EntryKind::Outcome
                && matches!(
                    &entry.data.payload,
                    EntryPayload::Outcome(ledger_format::OutcomePayload {
                        value: ledger_format::CanonicalValue::Unsigned(_),
                        ..
                    })
                )
            {
                last_numeric_outcome = Some(entry.id);
            }
        }
        // The duplicate must be reported deterministically: pick the smallest
        // duplicated value, never a hash-map iteration artifact.
        let mut duplicates: Vec<(&u64, &Vec<usize>)> = input_values
            .iter()
            .filter(|(_, positions)| positions.len() > 1)
            .collect();
        duplicates.sort_by_key(|(value, _)| **value);
        if let Some((value, positions)) = duplicates.first() {
            return Verdict::fail(
                witnesses_from_journal(&run.journal),
                format!(
                    "exactly-once violation: input value {} applied {} times (entry positions {:?})",
                    value,
                    positions.len(),
                    positions
                ),
            );
        }
        if let (Some((last_value, _)), Some(id)) = (last_input, last_numeric_outcome)
            && let Some(entry) = run.journal.get(&id)
            && let EntryPayload::Outcome(ledger_format::OutcomePayload {
                value: ledger_format::CanonicalValue::Unsigned(outcome_value),
                ..
            }) = &entry.data.payload
            && *outcome_value != last_value
        {
            return Verdict::fail(
                vec![id],
                format!(
                    "exactly-once violation: torn final apply: outcome {} does not match last applied input {}",
                    outcome_value, last_value
                ),
            );
        }
        Verdict::pass()
    }
}

/// Composite oracle over boxed sub-oracles.
///
/// A run violates when any sub-oracle violates. Witness hashes merge in
/// sub-oracle order; reasons of violating sub-oracles join with "; ".
struct CompositeOracle {
    oracles: Vec<Box<dyn Oracle>>,
}

impl Oracle for CompositeOracle {
    fn check(&self, run: &RunResult) -> Verdict {
        let mut violated = false;
        let mut witnesses = Vec::new();
        let mut reasons = Vec::new();
        for oracle in &self.oracles {
            let verdict = oracle.check(run);
            violated |= verdict.violated;
            witnesses.extend(verdict.witnesses);
            if verdict.violated {
                reasons.push(verdict.reason);
            }
        }
        if violated {
            Verdict {
                violated,
                witnesses,
                reason: reasons.join("; "),
            }
        } else {
            Verdict::pass()
        }
    }
}

/// Combine boxed oracles into one that violates when any input violates.
///
/// The composite evaluates every sub-oracle on each check, merging witnesses
/// and violation reasons, so callers can pass one composed oracle to any
/// existing campaign function.
pub fn compose_oracles(oracles: Vec<Box<dyn Oracle>>) -> Box<dyn Oracle> {
    Box::new(CompositeOracle { oracles })
}

impl Oracle for Box<dyn Oracle> {
    fn check(&self, run: &RunResult) -> Verdict {
        self.as_ref().check(run)
    }
}

/// An abstract operation extracted from a workload execution history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryOperation {
    Write {
        key: String,
        value: u64,
        witness: Hash,
    },
    Read {
        key: String,
        value: u64,
        witness: Hash,
    },
    Push {
        value: u64,
        witness: Hash,
    },
    Pop {
        value: u64,
        witness: Hash,
    },
}

impl HistoryOperation {
    /// Journal entry witnessing this operation.
    pub fn witness(&self) -> Hash {
        match self {
            HistoryOperation::Write { witness, .. }
            | HistoryOperation::Read { witness, .. }
            | HistoryOperation::Push { witness, .. }
            | HistoryOperation::Pop { witness, .. } => *witness,
        }
    }
}

/// One operation with the journal entries of its invoke and response events.
///
/// The real-time order between operations derives from the vector clocks of
/// these entries: operation A precedes operation B when A's response entry
/// happens before B's invoke entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinOperation {
    /// Journal entry id of the operation's invocation.
    pub invoke: Hash,
    /// Journal entry id of the operation's response.
    pub response: Hash,
    /// The operation replayed against the sequential specification.
    pub operation: HistoryOperation,
}

/// A sequential specification for history checking.
pub trait SequentialSpec: Clone {
    fn apply(&mut self, operation: &HistoryOperation) -> Result<(), String>;
}

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
            _ => Ok(()),
        }
    }
}

/// A generic history oracle checking operations against a sequential specification.
pub struct HistoryOracle<'a, W, S> {
    workload: &'a W,
    specification: S,
}

impl<'a, W, S> HistoryOracle<'a, W, S> {
    pub const fn new(workload: &'a W, specification: S) -> Self {
        Self {
            workload,
            specification,
        }
    }
}

impl<W, S> Oracle for HistoryOracle<'_, W, S>
where
    W: crate::search::Workload,
    S: SequentialSpec,
{
    fn check(&self, run: &RunResult) -> Verdict {
        let mut specification = self.specification.clone();
        for operation in self.workload.history(run) {
            let witness = operation.witness();
            if let Err(reason) = specification.apply(&operation) {
                return Verdict::fail(vec![witness], reason);
            }
        }
        Verdict::pass()
    }
}

/// Default bound on operations the linearizability checker explores.
///
/// The search is exponential in the operation count. Reference workloads stay
/// far below the bound; larger histories are reported as not checked rather
/// than explored blindly.
const DEFAULT_LIN_BOUND: usize = 12;

/// Linearizability oracle over journal-extracted histories.
///
/// Operations carry invoke and response journal witnesses. The checker builds
/// the real-time partial order from the witnesses' vector clocks: operation A
/// precedes B when A's response happens before B's invoke. It then searches
/// for a serial order that extends the partial order and satisfies the
/// sequential specification. A non-linearizable history is rejected with the
/// failing operation and its already-serialized predecessors reported.
pub struct LinearizabilityOracle<'a, W, S> {
    workload: &'a W,
    specification: S,
    bound: usize,
}

impl<'a, W, S> LinearizabilityOracle<'a, W, S> {
    pub const fn new(workload: &'a W, specification: S) -> Self {
        Self {
            workload,
            specification,
            bound: DEFAULT_LIN_BOUND,
        }
    }
}

/// The operation a failed serialization search could not place.
struct LinFailure {
    /// Operations already serialized, in order.
    prefix: Vec<usize>,
    /// The operation that could not be placed after the prefix.
    index: usize,
    /// Why the sequential specification rejected it.
    reason: String,
}

/// Search for a serial order extending the real-time partial order.
///
/// Every recursion tries each ready operation in index order, so the search
/// is deterministic. On a dead end the first unplaceable operation and the
/// serialized prefix are recorded.
fn find_serialization<S: SequentialSpec>(
    operations: &[LinOperation],
    predecessors: &[Vec<usize>],
    state: S,
    pending: &mut [bool],
    serialized: &mut Vec<usize>,
    failure: &mut Option<LinFailure>,
) -> bool {
    if !pending.iter().any(|open| *open) {
        return true;
    }
    for index in 0..operations.len() {
        if !pending[index] {
            continue;
        }
        if !predecessors[index].iter().all(|earlier| !pending[*earlier]) {
            continue;
        }
        let mut next = state.clone();
        if next.apply(&operations[index].operation).is_ok() {
            pending[index] = false;
            serialized.push(index);
            if find_serialization(operations, predecessors, next, pending, serialized, failure) {
                return true;
            }
            serialized.pop();
            pending[index] = true;
        }
    }
    if failure.is_none() {
        for index in 0..operations.len() {
            if !pending[index] {
                continue;
            }
            if !predecessors[index].iter().all(|earlier| !pending[*earlier]) {
                continue;
            }
            let mut next = state.clone();
            if let Err(reason) = next.apply(&operations[index].operation) {
                *failure = Some(LinFailure {
                    prefix: serialized.clone(),
                    index,
                    reason,
                });
                break;
            }
        }
    }
    false
}

impl<'a, W, S> LinearizabilityOracle<'a, W, S>
where
    S: SequentialSpec,
{
    /// Check explicit operations against a journal's real-time order.
    pub fn check_operations(&self, journal: &Journal, operations: &[LinOperation]) -> Verdict {
        let count = operations.len();
        if count > self.bound {
            return Verdict {
                violated: false,
                witnesses: Vec::new(),
                reason: format!(
                    "linearizability check bounded at {} operations; history has {count}",
                    self.bound
                ),
            };
        }
        let mut clocks = Vec::with_capacity(count);
        for operation in operations {
            let Some(invoke) = journal.get(&operation.invoke) else {
                return Verdict::fail(
                    vec![operation.invoke],
                    "linearizability: missing invoke entry",
                );
            };
            let Some(response) = journal.get(&operation.response) else {
                return Verdict::fail(
                    vec![operation.response],
                    "linearizability: missing response entry",
                );
            };
            clocks.push((invoke.vector_clock.clone(), response.vector_clock.clone()));
        }
        let mut predecessors = vec![Vec::new(); count];
        for later in 0..count {
            for earlier in 0..count {
                if earlier != later && clocks[earlier].1.happens_before(&clocks[later].0) {
                    predecessors[later].push(earlier);
                }
            }
        }
        let mut pending = vec![true; count];
        let mut serialized = Vec::with_capacity(count);
        let mut failure: Option<LinFailure> = None;
        let found = find_serialization(
            operations,
            &predecessors,
            self.specification.clone(),
            &mut pending,
            &mut serialized,
            &mut failure,
        );
        if found {
            return Verdict::pass();
        }
        let failure = failure.unwrap_or(LinFailure {
            prefix: Vec::new(),
            index: 0,
            reason: "no serial order exists".into(),
        });
        let chain = failure
            .prefix
            .iter()
            .map(|index| format!("{}:{:02x?}", index, &operations[*index].invoke[..4]))
            .collect::<Vec<_>>()
            .join(" -> ");
        let operation = &operations[failure.index];
        Verdict::fail(
            vec![operation.invoke, operation.response],
            format!(
                "non-linearizable: no serial order extends the real-time order; operation {} ({:?}) rejected after [{}]: {}",
                failure.index, operation.operation, chain, failure.reason
            ),
        )
    }
}

impl<W, S> Oracle for LinearizabilityOracle<'_, W, S>
where
    W: crate::search::Workload,
    S: SequentialSpec,
{
    fn check(&self, run: &RunResult) -> Verdict {
        let operations = self.workload.lin_history(run);
        self.check_operations(&run.journal, &operations)
    }
}

/// An assertion oracle that checks all `Assert` entries in the journal.
#[derive(Debug, Default, Clone, Copy)]
pub struct AssertionOracle;

impl Oracle for AssertionOracle {
    fn check(&self, run: &RunResult) -> Verdict {
        for entry in run.journal.entries() {
            if entry.data.kind == EntryKind::Assert {
                match &entry.data.payload {
                    EntryPayload::Assert(ledger_format::AssertPayload {
                        passed: false, ..
                    }) => {
                        return Verdict::fail(
                            vec![entry.id],
                            format!("assertion failed at actor {}", entry.data.actor),
                        );
                    }
                    EntryPayload::Assert(ledger_format::AssertPayload {
                        detail: ledger_format::CanonicalValue::Text(msg),
                        ..
                    }) if msg.starts_with("fail") => {
                        return Verdict::fail(vec![entry.id], format!("assertion failed: {msg}"));
                    }
                    _ => {}
                }
            }
        }
        Verdict::pass()
    }
}

/// One observable output of a run: the actor plus payload of an `Outcome`
/// entry, in journal order.
fn observable_outputs(run: &RunResult) -> Vec<(u32, u64)> {
    run.journal
        .entries()
        .filter(|entry| entry.data.kind == EntryKind::Outcome)
        .filter_map(|entry| match &entry.data.payload {
            EntryPayload::Outcome(ledger_format::OutcomePayload {
                value: ledger_format::CanonicalValue::Unsigned(value),
                ..
            }) => Some((entry.data.actor, *value)),
            _ => None,
        })
        .collect()
}

/// Locate the first index where two observable-output sequences disagree.
///
/// `None` when the sequences are equal. The reason names the actor and both
/// payloads (or the length mismatch) so a divergence report points at the
/// diverging step instead of only at the journal root.
fn output_divergence_reason(left: &[(u32, u64)], right: &[(u32, u64)]) -> Option<String> {
    let common = left.len().min(right.len());
    for index in 0..common {
        if left[index] != right[index] {
            return Some(format!(
                "differential output divergence at output {index}: left=(actor {}, value {}), right=(actor {}, value {})",
                left[index].0, left[index].1, right[index].0, right[index].1
            ));
        }
    }
    if left.len() != right.len() {
        return Some(format!(
            "differential output divergence: left produced {} outputs, right produced {}",
            left.len(),
            right.len()
        ));
    }
    None
}

/// Differential equivalence oracle that compares two runs for equivalent behavior.
///
/// Compared surfaces, in order: final registers, observable outputs (the
/// `Outcome` entries of the journals, in order), applied fault ids, and the
/// journal root hash. Register and root equality are unchanged; the output
/// and fault checks run before the root check so a behavioral divergence is
/// reported with its location, not only as a hash mismatch. Scheduler
/// decision sequences are deliberately not compared: two equivalent runs may
/// follow different legal schedules, and every semantic surface above already
/// pins the behavior those decisions produced.
#[derive(Debug, Default, Clone, Copy)]
pub struct DifferentialOracle;

impl DifferentialOracle {
    pub fn compare(left: &RunResult, right: &RunResult) -> Verdict {
        if left.registers != right.registers {
            return Verdict::fail(
                Vec::new(),
                format!(
                    "differential register mismatch: left={:?}, right={:?}",
                    left.registers, right.registers
                ),
            );
        }
        let left_outputs = observable_outputs(left);
        let right_outputs = observable_outputs(right);
        if let Some(reason) = output_divergence_reason(&left_outputs, &right_outputs) {
            return Verdict::fail(Vec::new(), reason);
        }
        if left.applied_faults != right.applied_faults {
            return Verdict::fail(
                Vec::new(),
                format!(
                    "differential applied-fault mismatch: left={:?}, right={:?}",
                    left.applied_faults, right.applied_faults
                ),
            );
        }
        if left.journal.root_hash() != right.journal.root_hash() {
            return Verdict::fail(
                Vec::new(),
                "differential journal hash divergence between runs",
            );
        }
        Verdict::pass()
    }
}

/// Collect the entry ids of `Outcome` and `Assert` entries.
///
/// These structural entries carry the semantic outcome of a run, so they are
/// the natural witnesses for a property violation.
pub fn witnesses_from_journal(journal: &Journal) -> Vec<Hash> {
    journal
        .entries()
        .filter_map(|entry| match entry.data.kind {
            EntryKind::Outcome | EntryKind::Assert => Some(entry.id),
            _ => None,
        })
        .collect()
}

/// Property predicate over the journal, used as an oracle.
///
/// The predicate runs over the completed run's journal. A `false` result is a
/// violation whose witnesses are the outcome and assertion entries.
pub struct PropertyOracle<P: Fn(&Journal) -> bool> {
    pub property: P,
    /// Human-readable property name for the failure reason.
    pub name: String,
}

impl<P: Fn(&Journal) -> bool> Oracle for PropertyOracle<P> {
    fn check(&self, run: &RunResult) -> Verdict {
        if (self.property)(&run.journal) {
            Verdict::pass()
        } else {
            Verdict::fail(
                witnesses_from_journal(&run.journal),
                format!("property violated: {}", self.name),
            )
        }
    }
}

/// Derive a monotonic predicate version from a property name and a counter.
///
/// The counter distinguishes versions of the same named property; bump it when
/// the predicate's semantics change. A version change invalidates every cached
/// verdict for the property.
pub fn predicate_version(name: &str, counter: u64) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(name.as_bytes());
    hasher.update(&counter.to_le_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&hasher.finalize().as_bytes()[..8]);
    u64::from_le_bytes(out)
}

/// Cache layer over a journal predicate, keyed by `(predicate_version, root_hash)`.
///
/// The offline checking path evaluates a predicate once per distinct journal
/// root and reuses the verdict on repeat roots. The version pins the property
/// semantics: bump it when the predicate changes so a stale verdict never
/// surfaces.
pub struct CachedPropertyOracle<P>
where
    P: Fn(&Journal) -> bool,
{
    oracle: PropertyOracle<P>,
    version: u64,
    cache: RefCell<HashMap<(u64, Hash), Verdict>>,
    evaluations: Cell<usize>,
}

impl<P> CachedPropertyOracle<P>
where
    P: Fn(&Journal) -> bool,
{
    pub fn new(property: P, name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            version: predicate_version(&name, 0),
            oracle: PropertyOracle { property, name },
            cache: RefCell::new(HashMap::new()),
            evaluations: Cell::new(0),
        }
    }

    /// Construct the cache with an explicit version.
    pub fn with_version(property: P, name: impl Into<String>, version: u64) -> Self {
        Self {
            version,
            oracle: PropertyOracle {
                property,
                name: name.into(),
            },
            cache: RefCell::new(HashMap::new()),
            evaluations: Cell::new(0),
        }
    }

    /// Number of times the underlying predicate actually evaluated.
    pub fn evaluations(&self) -> usize {
        self.evaluations.get()
    }

    /// Number of distinct `(version, root)` verdicts cached.
    pub fn cache_len(&self) -> usize {
        self.cache.borrow().len()
    }

    /// Evaluate `run`, serving repeat roots from the cache.
    pub fn check_cached(&self, run: &RunResult) -> Verdict {
        let root = run.journal.root_hash();
        let key = (self.version, root);
        if let Some(verdict) = self.cache.borrow().get(&key) {
            return verdict.clone();
        }
        let verdict = self.oracle.check(run);
        self.evaluations.set(self.evaluations.get() + 1);
        self.cache.borrow_mut().insert(key, verdict.clone());
        verdict
    }
}

impl<P> Oracle for CachedPropertyOracle<P>
where
    P: Fn(&Journal) -> bool,
{
    fn check(&self, run: &RunResult) -> Verdict {
        self.check_cached(run)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::search;
    use crate::workloads::MiniKvWorkload;
    use ledger_sim::{Instruction, RunConfig, Simulation};

    fn single_actor_programs(sets: usize) -> Vec<Vec<Instruction>> {
        let mut program = (0..sets)
            .map(|value| Instruction::Set(value as u64))
            .collect::<Vec<_>>();
        program.push(Instruction::Outcome);
        program.push(Instruction::Done);
        vec![program]
    }

    fn run_programs(programs: Vec<Vec<Instruction>>) -> RunResult {
        let config = RunConfig::builder()
            .seed([3; 32])
            .policy(ledger_sim::Policy::Random)
            .max_steps(512)
            .build();
        Simulation::new(config, programs).run().unwrap()
    }

    #[test]
    fn property_violated_when_journal_exceeds_bound() {
        let run = run_programs(single_actor_programs(10));
        let oracle = PropertyOracle {
            property: |journal| journal.len() < 5,
            name: "few entries".into(),
        };
        let verdict = oracle.check(&run);
        assert!(verdict.violated);
        assert!(!verdict.witnesses.is_empty());
        assert!(verdict.reason.contains("few entries"));
    }

    #[test]
    fn property_passes_within_bound() {
        let run = run_programs(vec![vec![Instruction::Done]]);
        let oracle = PropertyOracle {
            property: |journal| journal.len() < 5,
            name: "few entries".into(),
        };
        let verdict = oracle.check(&run);
        assert!(!verdict.violated);
    }

    #[test]
    fn cached_property_oracle_evaluates_once_per_root() {
        let run = run_programs(single_actor_programs(2));
        let calls = Cell::new(0usize);
        let oracle = CachedPropertyOracle::new(
            |journal: &Journal| {
                calls.set(calls.get() + 1);
                !journal.entries().any(|entry| {
                    matches!(
                        &entry.data.payload,
                        EntryPayload::Outcome(ledger_format::OutcomePayload {
                            value: ledger_format::CanonicalValue::Unsigned(1),
                            ..
                        })
                    )
                })
            },
            "no set of value 1",
        );

        let first = oracle.check(&run);
        let second = oracle.check(&run);
        assert_eq!(
            first, second,
            "the same root must return the cached verdict"
        );
        assert!(first.violated);
        assert_eq!(calls.get(), 1, "the closure must run once for one root");
        assert_eq!(oracle.evaluations(), 1);

        let other = run_programs(single_actor_programs(1));
        let verdict = oracle.check(&other);
        assert!(
            !verdict.violated,
            "a different root must recompute against the smaller journal"
        );
        assert_eq!(calls.get(), 2, "a different root must recompute");
        assert_eq!(oracle.evaluations(), 2);
        assert_eq!(oracle.cache_len(), 2);
    }

    fn linearizable_point_journal() -> (Journal, Vec<LinOperation>) {
        let mut journal = Journal::new();
        let write = journal
            .append(
                EntryKind::Send,
                1,
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(1, 1),
                    from: 1,
                    to: 2,
                    original_content: 1u64.to_le_bytes().to_vec(),
                }),
            )
            .expect("append must succeed");
        let read = journal
            .append(
                EntryKind::Outcome,
                2,
                [write],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: [0x00; 32],
                    value: ledger_format::CanonicalValue::Unsigned(1),
                }),
            )
            .expect("append must succeed");
        let operations = vec![
            LinOperation {
                invoke: write,
                response: write,
                operation: HistoryOperation::Write {
                    key: "k".into(),
                    value: 1,
                    witness: write,
                },
            },
            LinOperation {
                invoke: read,
                response: read,
                operation: HistoryOperation::Read {
                    key: "k".into(),
                    value: 1,
                    witness: read,
                },
            },
        ];
        (journal, operations)
    }

    #[test]
    fn linearizability_accepts_a_serializable_history() {
        let (journal, operations) = linearizable_point_journal();
        let oracle = LinearizabilityOracle::new(&MiniKvWorkload, KeyValueSpec::default());
        let verdict = oracle.check_operations(&journal, &operations);
        assert!(!verdict.violated, "{}", verdict.reason);
    }

    #[test]
    fn linearizability_rejects_a_real_time_stale_read() {
        let mut journal = Journal::new();
        let write = journal
            .append(
                EntryKind::Send,
                1,
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(1, 1),
                    from: 1,
                    to: 2,
                    original_content: 1u64.to_le_bytes().to_vec(),
                }),
            )
            .expect("append must succeed");
        let read = journal
            .append(
                EntryKind::Outcome,
                2,
                [write],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: [0x00; 32],
                    value: ledger_format::CanonicalValue::Unsigned(0),
                }),
            )
            .expect("append must succeed");
        let operations = vec![
            LinOperation {
                invoke: write,
                response: write,
                operation: HistoryOperation::Write {
                    key: "k".into(),
                    value: 1,
                    witness: write,
                },
            },
            LinOperation {
                invoke: read,
                response: read,
                operation: HistoryOperation::Read {
                    key: "k".into(),
                    value: 0,
                    witness: read,
                },
            },
        ];
        let oracle = LinearizabilityOracle::new(&MiniKvWorkload, KeyValueSpec::default());
        let verdict = oracle.check_operations(&journal, &operations);
        assert!(
            verdict.violated,
            "a read that started after the write completed must see the new value"
        );
        assert!(
            verdict.witnesses.contains(&read),
            "the offending read must witness the violation"
        );
        assert!(
            verdict.reason.contains("non-linearizable"),
            "the offending cycle must be reported: {}",
            verdict.reason
        );
    }

    #[test]
    fn linearizability_accepts_concurrent_overlapping_operations() {
        let mut journal = Journal::new();
        let w_invoke = journal
            .append(
                EntryKind::Send,
                1,
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(1, 1),
                    from: 1,
                    to: 2,
                    original_content: 1u64.to_le_bytes().to_vec(),
                }),
            )
            .expect("append must succeed");
        let w_response = journal
            .append(
                EntryKind::Recv,
                1,
                [w_invoke],
                EntryPayload::Recv(ledger_format::RecvFrame {
                    message_id: ledger_format::MessageId::new(1, 0),
                    from: 1,
                    to: 1,
                    observed_content: 0u64.to_le_bytes().to_vec(),
                }),
            )
            .expect("append must succeed");
        let r_invoke = journal
            .append(
                EntryKind::Outcome,
                2,
                [],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: [0x00; 32],
                    value: ledger_format::CanonicalValue::Unsigned(0),
                }),
            )
            .expect("append must succeed");
        let r_response = journal
            .append(
                EntryKind::Outcome,
                2,
                [r_invoke],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: [0x00; 32],
                    value: ledger_format::CanonicalValue::Unsigned(0),
                }),
            )
            .expect("append must succeed");
        let operations = vec![
            LinOperation {
                invoke: w_invoke,
                response: w_response,
                operation: HistoryOperation::Write {
                    key: "k".into(),
                    value: 1,
                    witness: w_invoke,
                },
            },
            LinOperation {
                invoke: r_invoke,
                response: r_response,
                operation: HistoryOperation::Read {
                    key: "k".into(),
                    value: 0,
                    witness: r_invoke,
                },
            },
        ];
        let oracle = LinearizabilityOracle::new(&MiniKvWorkload, KeyValueSpec::default());
        let verdict = oracle.check_operations(&journal, &operations);
        assert!(
            !verdict.violated,
            "a stale read overlapping the write is linearizable: {}",
            verdict.reason
        );
    }

    #[test]
    fn linearizability_oracle_finds_mini_kv_stale_read() {
        let config = RunConfig::builder()
            .seed([0; 32])
            .policy(ledger_sim::Policy::Random)
            .max_steps(256)
            .build();
        let oracle = LinearizabilityOracle::new(&MiniKvWorkload, KeyValueSpec::default());
        let finding = search(&MiniKvWorkload, &oracle, config, 256)
            .expect("search must run")
            .expect("the mini-kv stale read must violate linearizability");
        assert!(finding.verdict.violated);
    }

    fn value_journal(values: &[u64], outcome: Option<u64>) -> RunResult {
        let mut journal = Journal::new();
        for value in values {
            journal
                .append(
                    EntryKind::InputStep,
                    1,
                    [],
                    EntryPayload::InputStep(ledger_format::InputStepPayload {
                        generator: 0,
                        replay: 0,
                        value: ledger_format::CanonicalValue::Unsigned(*value),
                    }),
                )
                .expect("append must succeed");
        }
        if let Some(outcome) = outcome {
            journal
                .append(
                    EntryKind::Outcome,
                    1,
                    [],
                    EntryPayload::Outcome(ledger_format::OutcomePayload {
                        schema: [0x00; 32],
                        value: ledger_format::CanonicalValue::Unsigned(outcome),
                    }),
                )
                .expect("append must succeed");
        }
        run_for_value_oracle(journal)
    }

    fn run_for_value_oracle(journal: Journal) -> RunResult {
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

    #[test]
    fn exactly_once_oracle_rejects_a_duplicate_apply() {
        let run = value_journal(&[1, 2, 2], Some(2));
        let verdict = ExactlyOnceValueOracle.check(&run);
        assert!(verdict.violated);
        assert!(
            verdict.reason.contains("applied 2 times"),
            "the reason must name the duplicate: {}",
            verdict.reason
        );
        // Extending the journal never cures the duplicate: the condition is
        // monotone in the entry set.
        let extended = value_journal(&[0, 1, 2, 2, 3, 4], Some(2));
        assert!(ExactlyOnceValueOracle.check(&extended).violated);
    }

    #[test]
    fn exactly_once_oracle_rejects_a_torn_final_apply() {
        let run = value_journal(&[1, 2, 3], Some(9));
        let verdict = ExactlyOnceValueOracle.check(&run);
        assert!(verdict.violated, "{}", verdict.reason);
        assert!(
            verdict.reason.contains("torn final apply"),
            "the reason must name the torn apply: {}",
            verdict.reason
        );
        assert!(
            !verdict.witnesses.is_empty(),
            "the outcome entry must witness the torn apply"
        );
    }

    #[test]
    fn exactly_once_oracle_passes_a_clean_log() {
        let run = value_journal(&[1, 2, 3], Some(3));
        assert_eq!(ExactlyOnceValueOracle.check(&run), Verdict::pass());
        // No inputs, no outcome: vacuously holds.
        assert_eq!(
            ExactlyOnceValueOracle.check(&value_journal(&[], None)),
            Verdict::pass()
        );
        // No outcome with inputs: the forward check is vacuous.
        assert_eq!(
            ExactlyOnceValueOracle.check(&value_journal(&[1, 2], None)),
            Verdict::pass()
        );
    }

    #[test]
    fn exactly_once_oracle_sensitivity_to_the_causal_event_set() {
        // Removing any single entry from a minimal duplicate pair flips the
        // verdict to pass; adding any removed entry back keeps it failing.
        let journal = value_journal(&[1, 2, 2], Some(2)).journal;
        let ids = journal.entries().map(|entry| entry.id).collect::<Vec<_>>();
        let minimal = journal
            .subgraph(&[ids[1], ids[2]])
            .expect("subgraph must build");
        assert!(
            ExactlyOnceValueOracle
                .check(&run_for_value_oracle(minimal.clone()))
                .violated,
            "the duplicated pair alone must violate"
        );
        for removed in 0..2 {
            let subset = minimal
                .subgraph(&[ids[1 + (1 - removed)]])
                .expect("subset must build");
            assert!(
                !ExactlyOnceValueOracle
                    .check(&run_for_value_oracle(subset))
                    .violated,
                "removing one retained duplicate must flip the verdict"
            );
        }
        for added in [0usize, 3] {
            let extended = journal
                .subgraph(&[ids[1], ids[2], ids[added]])
                .expect("extension must build");
            assert!(
                ExactlyOnceValueOracle
                    .check(&run_for_value_oracle(extended))
                    .violated,
                "adding back a removed entry must keep the verdict failing"
            );
        }
    }
}
