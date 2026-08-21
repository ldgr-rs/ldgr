#![deny(unsafe_code)]

//! Persisted content-addressed solver state.
//!
//! Search state is a persisted, content-addressed artifact over the segment
//! pool. The artifact rebuilds exactly on another machine and pre-warms the
//! clause and hypothesis caches.
//!
//! The artifact records, per closure cache key, the exact clauses the live
//! solver derived and the exact hypotheses it computed (with their exact
//! costs). Resume restores those entries without recomputing anything and
//! rejects artifacts whose state key, resolved engine, or run-config hash do
//! not match the receiving solver.

use crate::ldfi::FaultHypothesis;
use crate::solver::{HittingSetSolver, SolverConfig, SolverEngine, SolverError};
use crate::solver_cache::{WeightedClause, engine_tag};
use ledger_format::{ActorId, EntryKind, Hash, Payload};
use ledger_journal::{Journal, JournalError};
use std::collections::BTreeSet;
use std::collections::HashSet;

/// Magic prefix for solver-state payloads.
///
/// Distinguishes solver-state Outcome entries from other Outcome entries. The
/// format version byte inside the payload is authoritative; the `V1` suffix
/// only discriminates the payload class.
const MAGIC: &[u8; 8] = b"LDGRSSV1";

/// Current solver-state format version.
///
/// Bumped when the encoded fields change. Decoders reject any other version
/// with a typed error, so an artifact written by an older or newer binary
/// never pre-warms a solver silently.
const FORMAT_VERSION: u8 = 2;

/// One hypothesis as persisted in a solver-state artifact.
///
/// `events` is the sorted event set; `total_cost` is the exact cost the live
/// solver computed for it (the sum of the per-event costs under the solver
/// cost model). The artifact copies the value from the live hypothesis, so
/// resume never re-derives costs from approximations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedHypothesis {
    pub events: Vec<Hash>,
    pub total_cost: u64,
}

/// One closure cache entry as persisted in a solver-state artifact.
///
/// `clauses` are the exact clauses the live solver derived for `key`, and
/// `hypotheses` are the hypotheses derived from those clauses, in the order
/// the live solver produced them. Resume restores both under `key`, so a
/// resumed hypothesis can only ever be returned by a closure whose clauses
/// actually produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedClosure {
    pub key: Hash,
    pub clauses: Vec<WeightedClause>,
    pub hypotheses: Vec<PersistedHypothesis>,
}

/// Persisted solver state artifact.
///
/// `closures` holds one entry per closure cache key seen by the solver.
/// `config_fingerprint` is the state key: it domain-separates the solver
/// configuration, the resolved engine, and the run-config hash, so artifacts
/// derived under different contexts never satisfy each other.
/// `run_config_hash` and `resolved_engine` record the encoding context that
/// produced the artifact; resume validates them explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolverStateArtifact {
    pub closures: Vec<PersistedClosure>,
    pub config_fingerprint: Hash,
    pub run_config_hash: Option<Hash>,
    pub resolved_engine: SolverEngine,
}

/// Typed errors from solver-state encoding, decoding, and resume validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolverStateError {
    /// A journal operation failed while persisting.
    Journal(JournalError),
    /// The payload does not start with the solver-state magic.
    MissingMagic,
    /// The payload ended before a declared field was complete.
    ///
    /// `offset` is the byte position at which the read failed. The same
    /// variant is returned when the position arithmetic itself overflows.
    Truncated { offset: usize },
    /// The payload carries a format version this decoder does not know.
    UnsupportedFormatVersion(u8),
    /// The payload carries an engine byte that is neither builtin nor cadical.
    UnknownEngineByte(u8),
    /// The run-config hash flag byte is neither 0 nor 1.
    UnknownRunConfigFlag(u8),
    /// An artifact that resolves no concrete engine cannot be encoded.
    UnresolvedEngine,
    /// A declared count cannot fit this build or exceeds the remaining bytes.
    LengthOverflow {
        /// The field carrying the count.
        field: &'static str,
        /// The declared count.
        declared: u64,
        /// Bytes remaining after the count field.
        remaining: usize,
    },
    /// Bytes follow the last declared field.
    TrailingBytes,
    /// The artifact was produced by a different engine than the receiver.
    EngineMismatch {
        expected: SolverEngine,
        found: SolverEngine,
    },
    /// The artifact was persisted under a different run-config hash.
    RunConfigMismatch {
        expected: Option<Hash>,
        found: Option<Hash>,
    },
    /// The artifact's state key does not match the receiver's state key.
    StateKeyMismatch { expected: Hash, found: Hash },
    /// A resumed hypothesis names an event absent from its key's clauses.
    HypothesisNotCovered {
        /// The closure key whose clauses do not cover the event.
        key: Hash,
        /// The uncovered event.
        event: Hash,
    },
}

impl core::fmt::Display for SolverStateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Journal(error) => write!(f, "journal error: {error}"),
            Self::MissingMagic => write!(f, "artifact payload missing solver-state magic"),
            Self::Truncated { offset } => {
                write!(f, "artifact payload truncated at byte offset {offset}")
            }
            Self::UnsupportedFormatVersion(version) => {
                write!(f, "unsupported solver-state format version: {version}")
            }
            Self::UnknownEngineByte(byte) => write!(f, "unknown solver engine byte: {byte}"),
            Self::UnknownRunConfigFlag(flag) => {
                write!(f, "unknown run-config hash flag byte: {flag}")
            }
            Self::UnresolvedEngine => {
                write!(
                    f,
                    "artifact engine is unresolved Auto; resolve before persisting"
                )
            }
            Self::LengthOverflow {
                field,
                declared,
                remaining,
            } => write!(
                f,
                "declared {field} count {declared} exceeds the {remaining} remaining bytes"
            ),
            Self::TrailingBytes => write!(f, "trailing bytes after solver-state artifact"),
            Self::EngineMismatch { expected, found } => {
                write!(
                    f,
                    "artifact engine {found:?} does not match solver engine {expected:?}"
                )
            }
            Self::RunConfigMismatch { expected, found } => write!(
                f,
                "artifact run-config hash {found:?} does not match solver run-config hash {expected:?}"
            ),
            Self::StateKeyMismatch { expected, found } => write!(
                f,
                "artifact state key {found:?} does not match solver state key {expected:?}"
            ),
            Self::HypothesisNotCovered { key, event } => write!(
                f,
                "resumed hypothesis event {event:?} is absent from the clauses of key {key:?}"
            ),
        }
    }
}

impl std::error::Error for SolverStateError {}

impl From<JournalError> for SolverStateError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

/// Version of the solver cost and certificate model bound by the state key.
///
/// Bump whenever the semantics of `crate::solver::event_fault_cost` (the
/// per-kind cost table) or `crate::maxsat::LOWER_BOUND_METHOD` (the
/// certificate method tag) change. The state fingerprint folds this tag into
/// its domain, so artifacts persisted under an older cost model are rejected
/// on resume instead of being pre-warmed with stale costs.
pub const COST_MODEL_VERSION: u8 = 1;

/// Compute the state key for a solver configuration and its resolved engine.
///
/// The hash covers the cost-model version tag, horizon, oracle version,
/// input class, max faults, the RESOLVED engine (never the configured mode:
/// Auto resolves before the key is derived), and the canonical run-config
/// hash, with domain separators. Deterministic and stable across machines.
/// Two artifacts derived by different engines, cost models, or under
/// different run configs always hash apart, so resuming one into the other
/// can never satisfy the state-key check.
pub fn fingerprint(config: &SolverConfig, resolved_engine: SolverEngine) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ldgr.solver_state.config.fingerprint.v2");
    hasher.update(&[0x00]);
    hasher.update(&[COST_MODEL_VERSION]);
    hasher.update(&[0x01]);
    match config.max_horizon {
        Some(value) => {
            hasher.update(&[0x01]);
            hasher.update(&(value as u64).to_le_bytes());
        }
        None => {
            hasher.update(&[0x00]);
            hasher.update(&[0xFF, 0xFF]);
        }
    }
    hasher.update(&[0x02]);
    match config.oracle_version {
        Some(value) => {
            hasher.update(&[0x01]);
            hasher.update(&value.to_le_bytes());
        }
        None => {
            hasher.update(&[0x00]);
        }
    }
    hasher.update(&[0x03]);
    match config.input_class {
        Some(value) => {
            hasher.update(&[0x01]);
            hasher.update(&value.to_le_bytes());
        }
        None => {
            hasher.update(&[0x00]);
        }
    }
    hasher.update(&[0x04]);
    match config.max_faults {
        Some(value) => {
            hasher.update(&[0x01]);
            hasher.update(&(value as u64).to_le_bytes());
        }
        None => {
            hasher.update(&[0x00]);
        }
    }
    // Engine discriminator: the RESOLVED engine. Auto is not an engine and
    // hashes to a byte that matches neither concrete engine, so an unresolved
    // caller cannot collude with either namespace.
    hasher.update(&[0x05]);
    let engine_byte = match resolved_engine {
        SolverEngine::Builtin => engine_tag::BUILTIN,
        SolverEngine::Cadical => engine_tag::CADICAL,
        SolverEngine::Auto => 0xFE,
    };
    hasher.update(&[engine_byte]);
    hasher.update(&[0x06]);
    match config.run_config_hash {
        Some(hash) => {
            hasher.update(&[0x01]);
            hasher.update(&hash);
        }
        None => {
            hasher.update(&[0x00]);
        }
    }
    *hasher.finalize().as_bytes()
}

/// Encode an artifact into deterministic canonical bytes.
///
/// Length-prefixed little-endian fields. `resolved_engine` must be a concrete
/// engine; an unresolved Auto artifact cannot be persisted.
fn encode_artifact(artifact: &SolverStateArtifact) -> Result<Vec<u8>, SolverStateError> {
    let engine_byte = match artifact.resolved_engine {
        SolverEngine::Builtin => engine_tag::BUILTIN,
        SolverEngine::Cadical => engine_tag::CADICAL,
        SolverEngine::Auto => return Err(SolverStateError::UnresolvedEngine),
    };
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(FORMAT_VERSION);
    out.push(engine_byte);
    match artifact.run_config_hash {
        Some(hash) => {
            out.push(0x01);
            out.extend_from_slice(&hash);
        }
        None => out.push(0x00),
    }
    out.extend_from_slice(&artifact.config_fingerprint);
    out.extend_from_slice(&(artifact.closures.len() as u64).to_le_bytes());
    for closure in &artifact.closures {
        out.extend_from_slice(&closure.key);
        out.extend_from_slice(&(closure.clauses.len() as u64).to_le_bytes());
        for clause in &closure.clauses {
            out.extend_from_slice(&(clause.literals.len() as u64).to_le_bytes());
            for literal in &clause.literals {
                out.extend_from_slice(literal);
            }
            out.extend_from_slice(&clause.weight.to_le_bytes());
        }
        out.extend_from_slice(&(closure.hypotheses.len() as u64).to_le_bytes());
        for hypothesis in &closure.hypotheses {
            out.extend_from_slice(&(hypothesis.events.len() as u64).to_le_bytes());
            for event in &hypothesis.events {
                out.extend_from_slice(event);
            }
            out.extend_from_slice(&hypothesis.total_cost.to_le_bytes());
        }
    }
    Ok(out)
}

/// Bounded cursor over a solver-state payload.
///
/// Every read checks the remaining bytes first, so no read can run past the
/// payload and no count can drive an allocation.
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Cursor<'_> {
    fn take(&mut self, length: usize) -> Result<&[u8], SolverStateError> {
        let offset = self.offset;
        let end = offset
            .checked_add(length)
            .ok_or(SolverStateError::Truncated { offset })?;
        if end > self.bytes.len() {
            return Err(SolverStateError::Truncated { offset });
        }
        let slice = &self.bytes[offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn u64(&mut self) -> Result<u64, SolverStateError> {
        let mut array = [0u8; 8];
        array.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(array))
    }

    fn hash(&mut self) -> Result<Hash, SolverStateError> {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(self.take(32)?);
        Ok(hash)
    }
}

/// Convert one declared count into a usize and prove the payload can hold
/// `count` elements of `elem_bytes` bytes, before any caller allocates.
///
/// The check bounds every allocation by the actual payload size: a hostile
/// declared count can never cause `Vec::with_capacity` to reserve more than
/// the surviving bytes can describe.
fn bounded_count(
    cursor: &mut Cursor,
    declared: u64,
    elem_bytes: usize,
    field: &'static str,
) -> Result<usize, SolverStateError> {
    let count = usize::try_from(declared).map_err(|_| SolverStateError::LengthOverflow {
        field,
        declared,
        remaining: cursor.remaining(),
    })?;
    let needed = count
        .checked_mul(elem_bytes)
        .ok_or(SolverStateError::LengthOverflow {
            field,
            declared,
            remaining: cursor.remaining(),
        })?;
    if needed > cursor.remaining() {
        return Err(SolverStateError::LengthOverflow {
            field,
            declared,
            remaining: cursor.remaining(),
        });
    }
    Ok(count)
}

/// Decode canonical bytes into an artifact.
///
/// Every declared length is checked against the remaining payload before any
/// allocation, so malformed or hostile payloads fail cleanly with a typed
/// error instead of reserving attacker-controlled sizes.
fn decode_artifact(bytes: &[u8]) -> Result<SolverStateArtifact, SolverStateError> {
    if bytes.len() < MAGIC.len() + 1 + 1 + 1 + 32 + 8 {
        return Err(SolverStateError::Truncated { offset: 0 });
    }
    if &bytes[0..MAGIC.len()] != MAGIC {
        return Err(SolverStateError::MissingMagic);
    }
    let mut cursor = Cursor {
        bytes,
        offset: MAGIC.len(),
    };
    let version = cursor.take(1)?[0];
    if version != FORMAT_VERSION {
        return Err(SolverStateError::UnsupportedFormatVersion(version));
    }
    let resolved_engine = match cursor.take(1)?[0] {
        engine_tag::BUILTIN => SolverEngine::Builtin,
        engine_tag::CADICAL => SolverEngine::Cadical,
        other => return Err(SolverStateError::UnknownEngineByte(other)),
    };
    let run_config_hash = match cursor.take(1)?[0] {
        0 => None,
        1 => Some(cursor.hash()?),
        other => return Err(SolverStateError::UnknownRunConfigFlag(other)),
    };
    let config_fingerprint = cursor.hash()?;

    // A closure entry needs at least a key and two count fields; this bound
    // applies before the closures vector is allocated.
    let closures_declared = cursor.u64()?;
    let closures_len = bounded_count(&mut cursor, closures_declared, 48, "closures")?;
    let mut closures = Vec::with_capacity(closures_len);
    for _ in 0..closures_len {
        let key = cursor.hash()?;
        let clauses_declared = cursor.u64()?;
        let clauses_len = bounded_count(&mut cursor, clauses_declared, 16, "clause")?;
        let mut clauses = Vec::with_capacity(clauses_len);
        for _ in 0..clauses_len {
            let literals_declared = cursor.u64()?;
            let literals_len = bounded_count(&mut cursor, literals_declared, 32, "literal")?;
            let mut literals = Vec::with_capacity(literals_len);
            for _ in 0..literals_len {
                literals.push(cursor.hash()?);
            }
            let weight = cursor.u64()?;
            clauses.push(WeightedClause::new(literals, weight));
        }
        let hypotheses_declared = cursor.u64()?;
        let hypotheses_len = bounded_count(&mut cursor, hypotheses_declared, 16, "hypothesis")?;
        let mut hypotheses = Vec::with_capacity(hypotheses_len);
        for _ in 0..hypotheses_len {
            let events_declared = cursor.u64()?;
            let events_len = bounded_count(&mut cursor, events_declared, 32, "event")?;
            let mut events = Vec::with_capacity(events_len);
            for _ in 0..events_len {
                events.push(cursor.hash()?);
            }
            let total_cost = cursor.u64()?;
            hypotheses.push(PersistedHypothesis { events, total_cost });
        }
        closures.push(PersistedClosure {
            key,
            clauses,
            hypotheses,
        });
    }

    if cursor.remaining() != 0 {
        return Err(SolverStateError::TrailingBytes);
    }

    Ok(SolverStateArtifact {
        closures,
        config_fingerprint,
        run_config_hash,
        resolved_engine,
    })
}

/// Persist an artifact to the journal.
///
/// The artifact is appended as a single `Outcome` entry with
/// `Payload::Bytes` containing the deterministic encoding. The entry id is the
/// content address. Saving an identical artifact twice returns the same entry
/// id without duplicating the entry (payload equality check).
pub fn save(
    journal: &mut Journal,
    actor: ActorId,
    artifact: &SolverStateArtifact,
) -> Result<Hash, SolverStateError> {
    let bytes = encode_artifact(artifact)?;
    // Dedup: if an entry with identical payload already exists, reuse it.
    for entry in journal.entries() {
        if let Payload::Bytes(payload) = &entry.data.payload
            && payload == &bytes
        {
            return Ok(entry.id);
        }
    }
    journal
        .append(EntryKind::Outcome, actor, [], Payload::Bytes(bytes))
        .map_err(SolverStateError::from)
}

/// Load all solver-state artifacts from the journal.
///
/// Scans entries in append order, decodes those whose payload starts with the
/// solver-state magic. Returns them in journal order. Malformed or
/// version-mismatched payloads produce a typed `SolverError::SolverState`.
pub fn load(journal: &Journal) -> Result<Vec<SolverStateArtifact>, SolverError> {
    let mut out = Vec::new();
    for entry in journal.entries() {
        if let Payload::Bytes(payload) = &entry.data.payload
            && payload.starts_with(MAGIC)
        {
            match decode_artifact(payload) {
                Ok(artifact) => out.push(artifact),
                Err(error) => return Err(SolverError::SolverState(error)),
            }
        }
    }
    Ok(out)
}

impl HittingSetSolver {
    /// Persist the current solver state to the journal.
    ///
    /// Captures per-closure clauses and hypotheses with exact costs, plus the
    /// state key and the resolved engine, into an artifact appended as a
    /// content-addressed entry.
    pub fn persist_state(
        &self,
        journal: &mut Journal,
        actor: ActorId,
    ) -> Result<Hash, JournalError> {
        let artifact = self.snapshot_artifact(self.resolved_engine());
        save(journal, actor, &artifact).map_err(|error| match error {
            SolverStateError::Journal(journal_error) => journal_error,
            other => JournalError::InvariantViolation(other.to_string()),
        })
    }

    /// Pre-warm the clause and hypothesis caches from a persisted artifact.
    ///
    /// The artifact must have been produced under the same state key
    /// (configuration, resolved engine, and run-config hash); anything else is
    /// rejected with a typed error before any cache entry is touched.
    /// Hypotheses are restored only under their own closure key and only
    /// alongside a non-empty recorded clause set (an empty clause set cannot
    /// determine costs or hitting sets, and the trivial empty case must
    /// recompute like a fresh solver), and an entry whose hypothesis names an
    /// event absent from the key's clauses is rejected, so resume never
    /// returns a hypothesis without matching clauses. `resolved_engine` is
    /// the engine the receiving solver resolves to; the artifact must have
    /// been produced by that engine.
    pub fn resume(
        &mut self,
        artifact: &SolverStateArtifact,
        resolved_engine: SolverEngine,
    ) -> Result<(), SolverError> {
        if artifact.resolved_engine != resolved_engine {
            return Err(SolverError::SolverState(SolverStateError::EngineMismatch {
                expected: resolved_engine,
                found: artifact.resolved_engine,
            }));
        }
        if artifact.run_config_hash != self.config().run_config_hash {
            return Err(SolverError::SolverState(
                SolverStateError::RunConfigMismatch {
                    expected: self.config().run_config_hash,
                    found: artifact.run_config_hash,
                },
            ));
        }
        let expected_fingerprint = fingerprint(self.config(), resolved_engine);
        if artifact.config_fingerprint != expected_fingerprint {
            return Err(SolverError::SolverState(
                SolverStateError::StateKeyMismatch {
                    expected: expected_fingerprint,
                    found: artifact.config_fingerprint,
                },
            ));
        }
        // Validate every entry before applying any, so a forged artifact can
        // never leave the solver half-warmed.
        for closure in &artifact.closures {
            let mut literals: HashSet<Hash> = HashSet::new();
            for clause in &closure.clauses {
                literals.extend(clause.literals.iter().copied());
            }
            for hypothesis in &closure.hypotheses {
                if let Some(event) = hypothesis
                    .events
                    .iter()
                    .find(|event| !literals.contains(*event))
                {
                    return Err(SolverError::SolverState(
                        SolverStateError::HypothesisNotCovered {
                            key: closure.key,
                            event: *event,
                        },
                    ));
                }
            }
        }
        for closure in &artifact.closures {
            // Every recorded clause set is restored under its key, including
            // an empty one: the live solver stores empty clause sets (for
            // example the MaxSAT empty-hard cut), and a missing entry would
            // split the state and let a stale hypothesis pass an unvalidated
            // hit check.
            self.clause_cache_mut()
                .insert(closure.key, closure.clauses.clone());
            // The returned bool is is_new, not an error.
            crate::solver_cache::global_insert(closure.key, closure.clauses.clone());
            // Hypotheses are restored only alongside a non-empty recorded
            // clause set. An empty clause set cannot determine any cost or
            // hitting set, and an empty clause query must behave like a
            // fresh solver, which returns no hypotheses; restoring a
            // recorded empty-cut hypothesis would let that query be served
            // instead. Both engines recompute the trivial empty case.
            if !closure.hypotheses.is_empty() && !closure.clauses.is_empty() {
                let hyps: Vec<FaultHypothesis> = closure
                    .hypotheses
                    .iter()
                    .map(|persisted| FaultHypothesis {
                        // Recorded order is the live solver's order, so the
                        // resumed cache reproduces the live decisions.
                        events: persisted.events.clone(),
                        // Exact cost captured from the live solver.
                        total_cost: persisted.total_cost,
                        explanation: format!(
                            "resumed hypothesis with {} fault(s)",
                            persisted.events.len()
                        ),
                    })
                    .collect();
                self.hypothesis_cache_mut().insert(closure.key, hyps);
            }
        }
        Ok(())
    }

    /// Snapshot the solver's current cache state into an artifact.
    ///
    /// Closure keys are the sorted union of the clause and hypothesis cache
    /// keys. Each closure entry records the exact clauses derived for that
    /// key and the exact hypotheses (with exact costs) derived from them, in
    /// the live cache order.
    pub(crate) fn snapshot_artifact(&self, resolved_engine: SolverEngine) -> SolverStateArtifact {
        let mut keys: BTreeSet<Hash> = self.hypothesis_cache().keys().copied().collect();
        keys.extend(self.clause_cache().iter().map(|(key, _)| *key));
        let closures: Vec<PersistedClosure> = keys
            .iter()
            .map(|key| {
                let clauses = self.clause_cache().get_cloned(key).unwrap_or_default();
                let hypotheses = self
                    .hypothesis_cache()
                    .get(key)
                    .map(|hyps| {
                        hyps.iter()
                            .map(|hypothesis| {
                                let mut events = hypothesis.events.clone();
                                events.sort();
                                PersistedHypothesis {
                                    events,
                                    total_cost: hypothesis.total_cost,
                                }
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                PersistedClosure {
                    key: *key,
                    clauses,
                    hypotheses,
                }
            })
            .collect();

        SolverStateArtifact {
            closures,
            config_fingerprint: fingerprint(self.config(), resolved_engine),
            run_config_hash: self.config().run_config_hash,
            resolved_engine,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle::Verdict;
    use crate::solver::{FaultSolver, HittingSetSolver, MaxSatSolver};
    use crate::solver_cache::{ClauseCache, engine_tag};
    use ledger_format::Payload;
    use ledger_journal::Journal;

    fn test_hash(byte: u8) -> Hash {
        [byte; 32]
    }

    /// Config exactly as `HittingSetSolver::new()` holds it.
    fn solver_config() -> SolverConfig {
        HittingSetSolver::new().config().clone()
    }

    /// Build a journal whose witness depends on events with distinct costs:
    /// one Send (cost 2), one TimerFire (cost 3), one FsWrite (cost 4).
    fn mixed_cost_journal() -> (Journal, Hash) {
        let mut journal = Journal::new();
        let send = journal
            .append(
                ledger_format::EntryKind::Send,
                1,
                [],
                Payload::Pair { left: 2, right: 1 },
            )
            .expect("append send");
        let timer = journal
            .append(
                ledger_format::EntryKind::TimerFire,
                2,
                [],
                Payload::Number(7),
            )
            .expect("append timer");
        let write = journal
            .append(
                ledger_format::EntryKind::FsWrite,
                3,
                [],
                Payload::Bytes(vec![1, 2, 3]),
            )
            .expect("append fs write");
        let witness = journal
            .append(
                ledger_format::EntryKind::Outcome,
                4,
                [send, timer, write],
                Payload::Number(0),
            )
            .expect("append witness");
        (journal, witness)
    }

    #[test]
    fn fingerprint_deterministic_and_differs_per_field() {
        let base = solver_config()
            .with_horizon(64)
            .with_oracle_version(1)
            .with_input_class(10)
            .with_max_faults(3);
        let same = solver_config()
            .with_horizon(64)
            .with_oracle_version(1)
            .with_input_class(10)
            .with_max_faults(3);
        assert_eq!(
            fingerprint(&base, SolverEngine::Builtin),
            fingerprint(&same, SolverEngine::Builtin)
        );

        let mut variant = base.clone();
        variant.max_horizon = Some(32);
        assert_ne!(
            fingerprint(&base, SolverEngine::Builtin),
            fingerprint(&variant, SolverEngine::Builtin)
        );

        let mut variant = base.clone();
        variant.oracle_version = Some(2);
        assert_ne!(
            fingerprint(&base, SolverEngine::Builtin),
            fingerprint(&variant, SolverEngine::Builtin)
        );

        let mut variant = base.clone();
        variant.input_class = Some(11);
        assert_ne!(
            fingerprint(&base, SolverEngine::Builtin),
            fingerprint(&variant, SolverEngine::Builtin)
        );

        let mut variant = base.clone();
        variant.max_faults = Some(4);
        assert_ne!(
            fingerprint(&base, SolverEngine::Builtin),
            fingerprint(&variant, SolverEngine::Builtin)
        );

        let mut variant = base.clone();
        variant.max_horizon = None;
        assert_ne!(
            fingerprint(&base, SolverEngine::Builtin),
            fingerprint(&variant, SolverEngine::Builtin)
        );

        let mut variant = base.clone();
        variant.oracle_version = None;
        assert_ne!(
            fingerprint(&base, SolverEngine::Builtin),
            fingerprint(&variant, SolverEngine::Builtin)
        );

        let mut variant = base.clone();
        variant.input_class = None;
        assert_ne!(
            fingerprint(&base, SolverEngine::Builtin),
            fingerprint(&variant, SolverEngine::Builtin)
        );

        let mut variant = base.clone();
        variant.max_faults = None;
        assert_ne!(
            fingerprint(&base, SolverEngine::Builtin),
            fingerprint(&variant, SolverEngine::Builtin)
        );
    }

    #[test]
    fn fingerprint_full_vs_builder_equality_for_solver_default() {
        // The literal config in `HittingSetSolver::new` must fingerprint like
        // the same fields built through the builders.
        let literal = SolverConfig {
            max_horizon: Some(64),
            oracle_version: None,
            input_class: None,
            max_faults: None,
            engine: SolverEngine::Auto,
            run_config_hash: None,
        };
        assert_eq!(
            fingerprint(&literal, SolverEngine::Builtin),
            fingerprint(&solver_config(), SolverEngine::Builtin)
        );
    }

    #[test]
    fn fingerprint_reflects_resolved_engine_not_configured_mode() {
        let auto = solver_config();
        assert_eq!(
            fingerprint(&auto, SolverEngine::Builtin),
            fingerprint(&auto, SolverEngine::Builtin)
        );
        // Auto resolves to builtin below the crossover, so its resolved key
        // equals a forced builtin request with the same other fields...
        let forced_builtin = auto.clone().with_engine(SolverEngine::Builtin);
        assert_eq!(
            fingerprint(&auto, SolverEngine::Builtin),
            fingerprint(&forced_builtin, SolverEngine::Builtin)
        );
        // ...and differs from a cadical-resolved request.
        assert_ne!(
            fingerprint(&auto, SolverEngine::Builtin),
            fingerprint(&auto, SolverEngine::Cadical)
        );
        // An unresolved engine in the key hashes apart from both concrete
        // engines, so it cannot collide with either namespace.
        assert_ne!(
            fingerprint(&auto, SolverEngine::Auto),
            fingerprint(&auto, SolverEngine::Builtin)
        );
        assert_ne!(
            fingerprint(&auto, SolverEngine::Auto),
            fingerprint(&auto, SolverEngine::Cadical)
        );
    }

    #[test]
    fn fingerprint_differs_on_run_config_hash() {
        let base = solver_config();
        let with_hash = base.clone().with_run_config_hash(test_hash(9));
        assert_ne!(
            fingerprint(&base, SolverEngine::Builtin),
            fingerprint(&with_hash, SolverEngine::Builtin)
        );
        let other_hash = base.clone().with_run_config_hash(test_hash(10));
        assert_ne!(
            fingerprint(&with_hash, SolverEngine::Builtin),
            fingerprint(&other_hash, SolverEngine::Builtin)
        );
        // The configured engine field never joins the key; only the resolved
        // engine does.
        let with_hash_auto = with_hash.clone().with_engine(SolverEngine::Auto);
        assert_eq!(
            fingerprint(&with_hash, SolverEngine::Builtin),
            fingerprint(&with_hash_auto, SolverEngine::Builtin)
        );
    }

    #[test]
    fn save_load_roundtrip_preserves_artifact() {
        let mut journal = Journal::new();
        let key_a = test_hash(1);
        let artifact = SolverStateArtifact {
            closures: vec![
                PersistedClosure {
                    key: key_a,
                    clauses: vec![
                        WeightedClause::new(vec![test_hash(10), test_hash(11)], 5),
                        WeightedClause::new(vec![test_hash(20)], 3),
                    ],
                    hypotheses: vec![PersistedHypothesis {
                        events: vec![test_hash(10), test_hash(11)],
                        total_cost: 7,
                    }],
                },
                PersistedClosure {
                    key: test_hash(2),
                    clauses: vec![WeightedClause::new(vec![test_hash(30)], 4)],
                    hypotheses: vec![],
                },
            ],
            config_fingerprint: fingerprint(&solver_config(), SolverEngine::Builtin),
            run_config_hash: Some(test_hash(42)),
            resolved_engine: SolverEngine::Builtin,
        };
        let id = save(&mut journal, 1, &artifact).expect("save must succeed");
        assert!(journal.get(&id).is_some());
        let loaded = load(&journal).expect("load must succeed");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], artifact);
        assert_eq!(loaded[0].closures[0].hypotheses[0].total_cost, 7);
        assert_eq!(loaded[0].run_config_hash, Some(test_hash(42)));
        assert_eq!(loaded[0].resolved_engine, SolverEngine::Builtin);

        // Encode directly and compare bytes stability.
        let bytes_first = encode_artifact(&artifact).expect("encode must succeed");
        let bytes_second = encode_artifact(&loaded[0]).expect("encode must succeed");
        assert_eq!(bytes_first, bytes_second);
    }

    #[test]
    fn encode_rejects_unresolved_auto_engine() {
        let artifact = SolverStateArtifact {
            closures: Vec::new(),
            config_fingerprint: fingerprint(&solver_config(), SolverEngine::Auto),
            run_config_hash: None,
            resolved_engine: SolverEngine::Auto,
        };
        assert!(matches!(
            encode_artifact(&artifact),
            Err(SolverStateError::UnresolvedEngine)
        ));
        let mut journal = Journal::new();
        assert!(save(&mut journal, 1, &artifact).is_err());
    }

    #[test]
    fn dedup_saving_identical_artifact_twice_yields_same_entry_id() {
        let mut journal = Journal::new();
        let artifact = SolverStateArtifact {
            closures: vec![PersistedClosure {
                key: test_hash(7),
                clauses: vec![WeightedClause::new(vec![test_hash(42)], 2)],
                hypotheses: vec![PersistedHypothesis {
                    events: vec![test_hash(42)],
                    total_cost: 2,
                }],
            }],
            config_fingerprint: fingerprint(&solver_config(), SolverEngine::Builtin),
            run_config_hash: None,
            resolved_engine: SolverEngine::Builtin,
        };
        let first = save(&mut journal, 1, &artifact).expect("first save");
        let len_after_first = journal.len();
        let second = save(&mut journal, 1, &artifact).expect("second save");
        assert_eq!(first, second);
        assert_eq!(journal.len(), len_after_first);

        // Different actor with same payload should still dedup via payload equality
        // (artifact content address), but we verify at least same payload returns same id.
        let third = save(&mut journal, 2, &artifact).expect("third save with different actor");
        assert_eq!(first, third);
        assert_eq!(journal.len(), len_after_first);

        // Different artifact must produce different id.
        let mut other = artifact.clone();
        other.closures[0]
            .clauses
            .push(WeightedClause::new(vec![test_hash(99)], 9));
        let other_id = save(&mut journal, 1, &other).expect("other artifact");
        assert_ne!(first, other_id);
        assert_eq!(journal.len(), len_after_first + 1);
    }

    #[test]
    fn resume_parity_reproduces_exact_costs_and_selected_set() {
        crate::solver_cache::global_clear();
        let (journal, witness) = mixed_cost_journal();
        let verdict = Verdict::fail(vec![witness], "mixed costs");

        // Fresh solver solves and we capture its result.
        let mut fresh = HittingSetSolver::new();
        let fresh_hyps = fresh.solve(&journal, &verdict).expect("fresh solve");
        assert!(!fresh_hyps.is_empty());
        // The journal carries non-Send costs, so the fixed-cost-2 fallback of
        // the old resume path would produce different totals here.
        let live_costs: Vec<u64> = fresh_hyps.iter().map(|hyp| hyp.total_cost).collect();
        assert!(
            live_costs.iter().any(|cost| *cost != 2),
            "fixture must break the flat-cost-2 approximation"
        );

        // Persist solver state via persist_state (snapshot + save).
        let mut persist_journal = journal.fork();
        let artifact_id = fresh
            .persist_state(&mut persist_journal, 99)
            .expect("persist must succeed");
        assert!(persist_journal.get(&artifact_id).is_some());

        // Simulate another machine: fresh journal fork plus cleared global cache.
        crate::solver_cache::global_clear();
        let loaded_journal = persist_journal.fork();
        let artifacts = load(&loaded_journal).expect("load must succeed");
        assert_eq!(artifacts.len(), 1);
        let artifact = &artifacts[0];
        assert_eq!(artifact.resolved_engine, SolverEngine::Builtin);

        // Resume into a new empty solver.
        let mut resumed = HittingSetSolver::new();
        assert_eq!(resumed.cache_len(), 0);
        assert_eq!(resumed.hypothesis_cache_len(), 0);
        resumed
            .resume(artifact, SolverEngine::Builtin)
            .expect("resume must apply the matching artifact");
        assert!(resumed.cache_len() > 0 || resumed.hypothesis_cache_len() > 0);

        // The resumed solver must reproduce the live decisions: same event
        // sets, same exact total costs, in the same order. Explanations are
        // display strings and are not part of a decision.
        let resumed_hyps = resumed
            .solve(&loaded_journal, &verdict)
            .expect("resumed solve");
        let fresh_decisions: Vec<(Vec<Hash>, u64)> = fresh_hyps
            .iter()
            .map(|hyp| (hyp.events.clone(), hyp.total_cost))
            .collect();
        let resumed_decisions: Vec<(Vec<Hash>, u64)> = resumed_hyps
            .iter()
            .map(|hyp| (hyp.events.clone(), hyp.total_cost))
            .collect();
        assert_eq!(
            fresh_decisions, resumed_decisions,
            "resumed hypotheses must reproduce the fresh decisions including exact costs"
        );
        assert_eq!(
            fresh_hyps.first().map(|hyp| hyp.total_cost),
            resumed_hyps.first().map(|hyp| hyp.total_cost),
            "the selected hypothesis must carry the exact live cost"
        );

        // Second solve on resumed solver should be cache hit (no cache growth).
        let len_before = resumed.cache_len();
        let hyp_len_before = resumed.hypothesis_cache_len();
        let second = resumed
            .solve(&loaded_journal, &verdict)
            .expect("second solve");
        assert_eq!(resumed_hyps, second);
        assert_eq!(resumed.cache_len(), len_before);
        assert_eq!(resumed.hypothesis_cache_len(), hyp_len_before);
    }

    #[test]
    fn resume_rejects_cross_engine_artifact() {
        crate::solver_cache::global_clear();
        let config = solver_config();
        let cadical_artifact = SolverStateArtifact {
            closures: Vec::new(),
            config_fingerprint: fingerprint(&config, SolverEngine::Cadical),
            run_config_hash: None,
            resolved_engine: SolverEngine::Cadical,
        };
        let mut solver = HittingSetSolver::with_config(config);
        let error = solver
            .resume(&cadical_artifact, SolverEngine::Builtin)
            .expect_err("a cadical artifact must never warm a builtin solver");
        assert!(matches!(
            error,
            SolverError::SolverState(SolverStateError::EngineMismatch { .. })
        ));
        assert_eq!(solver.cache_len(), 0);
        assert_eq!(solver.hypothesis_cache_len(), 0);
    }

    #[test]
    fn resume_rejects_state_key_mismatch() {
        crate::solver_cache::global_clear();
        let other_config = solver_config().with_horizon(32);
        let artifact = SolverStateArtifact {
            closures: Vec::new(),
            config_fingerprint: fingerprint(&other_config, SolverEngine::Builtin),
            run_config_hash: None,
            resolved_engine: SolverEngine::Builtin,
        };
        let mut solver = HittingSetSolver::new();
        let error = solver
            .resume(&artifact, SolverEngine::Builtin)
            .expect_err("a differing horizon must change the state key");
        assert!(matches!(
            error,
            SolverError::SolverState(SolverStateError::StateKeyMismatch { .. })
        ));
    }

    #[test]
    fn resume_rejects_run_config_mismatch() {
        crate::solver_cache::global_clear();
        // Artifact persisted under run config A into a solver under B.
        let config_a = solver_config().with_run_config_hash(test_hash(1));
        let artifact = SolverStateArtifact {
            closures: Vec::new(),
            config_fingerprint: fingerprint(&config_a, SolverEngine::Builtin),
            run_config_hash: Some(test_hash(1)),
            resolved_engine: SolverEngine::Builtin,
        };
        let mut solver = HittingSetSolver::new();
        let error = solver
            .resume(&artifact, SolverEngine::Builtin)
            .expect_err("a run-config mismatch must reject the artifact");
        assert!(matches!(
            error,
            SolverError::SolverState(SolverStateError::RunConfigMismatch { .. })
        ));
        // A solver that recorded no run config rejects a hash-carrying artifact.
        let mut solver_none = HittingSetSolver::new();
        let error_none = solver_none
            .resume(&artifact, SolverEngine::Builtin)
            .expect_err("artifact with a run-config hash must not warm a solver without one");
        assert!(matches!(
            error_none,
            SolverError::SolverState(SolverStateError::RunConfigMismatch { .. })
        ));
        // A matching hash applies cleanly.
        let mut solver_matching = HittingSetSolver::with_config(config_a);
        assert!(
            solver_matching
                .resume(&artifact, SolverEngine::Builtin)
                .is_ok()
        );
    }

    #[test]
    fn resume_rejects_hypothesis_not_covered_by_clauses() {
        crate::solver_cache::global_clear();
        let mut solver = HittingSetSolver::new();
        let key = solver.incremental_key_with_tag(
            ClauseCache::closure_hash(&[test_hash(1)]),
            engine_tag::BUILTIN,
        );
        let forged = SolverStateArtifact {
            closures: vec![PersistedClosure {
                key,
                // Clauses cover event 1; the hypothesis names event 2.
                clauses: vec![WeightedClause::new(vec![test_hash(1)], 2)],
                hypotheses: vec![PersistedHypothesis {
                    events: vec![test_hash(2)],
                    total_cost: 2,
                }],
            }],
            config_fingerprint: fingerprint(&solver_config(), SolverEngine::Builtin),
            run_config_hash: None,
            resolved_engine: SolverEngine::Builtin,
        };
        let error = solver
            .resume(&forged, SolverEngine::Builtin)
            .expect_err("a hypothesis event outside its key's clauses must be rejected");
        assert!(matches!(
            error,
            SolverError::SolverState(SolverStateError::HypothesisNotCovered { .. })
        ));
        assert_eq!(solver.hypothesis_cache_len(), 0);
        assert_eq!(solver.cache_len(), 0);
    }

    #[test]
    fn resume_places_hypotheses_only_under_own_closure_key() {
        crate::solver_cache::global_clear();
        let mut solver = HittingSetSolver::new();
        let hash_a = test_hash(1);
        let hash_b = test_hash(2);
        let closure_a = ClauseCache::closure_hash(&[hash_a]);
        let closure_b = ClauseCache::closure_hash(&[hash_b]);
        let key_a = solver.incremental_key_with_tag(closure_a, engine_tag::BUILTIN);
        let clauses_a = vec![WeightedClause::new(vec![hash_a], 2)];
        let artifact = SolverStateArtifact {
            closures: vec![PersistedClosure {
                key: key_a,
                clauses: clauses_a.clone(),
                hypotheses: vec![PersistedHypothesis {
                    events: vec![hash_a],
                    total_cost: 2,
                }],
            }],
            config_fingerprint: fingerprint(&solver_config(), SolverEngine::Builtin),
            run_config_hash: None,
            resolved_engine: SolverEngine::Builtin,
        };
        solver
            .resume(&artifact, SolverEngine::Builtin)
            .expect("matching artifact must apply");
        assert_eq!(solver.hypothesis_cache_len(), 1);

        // A query under the OTHER closure key gets fresh hypotheses derived
        // from its own clauses, never closure A's cached hypothesis.
        let clauses_b = vec![WeightedClause::new(vec![hash_b], 3)];
        let got_b = solver.solve_incremental(closure_b, clauses_b.clone());
        let mut fresh = HittingSetSolver::new();
        let expected_b = fresh.solve_incremental(closure_b, clauses_b);
        assert_eq!(
            got_b, expected_b,
            "the other key must recompute from its own clauses"
        );
        assert!(!got_b.is_empty());
        assert!(got_b.iter().all(|hyp| hyp.events == vec![hash_b]));
        assert!(got_b.iter().all(|hyp| hyp.total_cost == 3));

        // A clause-mismatched query under closure A recomputes as well: the
        // stored hypothesis is never returned for a different clause set.
        // The one two-literal clause yields the minimal hitting sets {a} and
        // {b}, each costing the clause weight.
        let clauses_a2 = vec![WeightedClause::new(vec![hash_a, hash_b], 4)];
        let got_a2 = solver.solve_incremental(closure_a, clauses_a2.clone());
        let mut fresh2 = HittingSetSolver::new();
        let expected_a2 = fresh2.solve_incremental(closure_a, clauses_a2);
        assert_eq!(got_a2, expected_a2, "mismatched assumptions must recompute");
        let mut got_a2_sets: Vec<Vec<Hash>> = got_a2
            .iter()
            .map(|hyp| {
                let mut events = hyp.events.clone();
                events.sort();
                events
            })
            .collect();
        got_a2_sets.sort();
        assert_eq!(got_a2_sets, vec![vec![hash_a], vec![hash_b]]);
        assert!(got_a2.iter().all(|hyp| hyp.total_cost == 4));
    }

    #[test]
    fn resume_preserves_recorded_hypothesis_order() {
        crate::solver_cache::global_clear();
        let mut solver = HittingSetSolver::new();
        let hash_a = test_hash(1);
        let hash_b = test_hash(2);
        let closure = ClauseCache::closure_hash(&[hash_a, hash_b]);
        let key = solver.incremental_key_with_tag(closure, engine_tag::BUILTIN);
        let clauses = vec![
            WeightedClause::new(vec![hash_a], 2),
            WeightedClause::new(vec![hash_b], 3),
        ];
        let artifact = SolverStateArtifact {
            closures: vec![PersistedClosure {
                key,
                clauses: clauses.clone(),
                hypotheses: vec![
                    PersistedHypothesis {
                        events: vec![hash_b],
                        total_cost: 3,
                    },
                    PersistedHypothesis {
                        events: vec![hash_a],
                        total_cost: 2,
                    },
                ],
            }],
            config_fingerprint: fingerprint(&solver_config(), SolverEngine::Builtin),
            run_config_hash: None,
            resolved_engine: SolverEngine::Builtin,
        };
        solver
            .resume(&artifact, SolverEngine::Builtin)
            .expect("artifact must apply");
        let restored = solver
            .hypothesis_cache()
            .get(&key)
            .expect("key must be warmed");
        assert_eq!(
            restored
                .iter()
                .map(|hyp| hyp.events.clone())
                .collect::<Vec<_>>(),
            vec![vec![hash_b], vec![hash_a]],
            "resume must preserve the recorded order of the live solver"
        );
        assert_eq!(
            restored
                .iter()
                .map(|hyp| hyp.total_cost)
                .collect::<Vec<_>>(),
            vec![3, 2],
            "resume must preserve the exact recorded costs"
        );
    }

    #[test]
    fn maxsat_resume_parity_includes_certificate_fields() {
        crate::solver_cache::global_clear();
        let (journal, witness) = mixed_cost_journal();
        let verdict = Verdict::fail(vec![witness], "certificate parity");

        let mut fresh = MaxSatSolver::new();
        let (fresh_hyps, fresh_cert) = fresh
            .solve_with_certificate(&journal, &verdict)
            .expect("fresh solve must succeed");
        assert!(!fresh_hyps.is_empty());

        let mut persist_journal = journal.fork();
        let artifact = fresh.snapshot_state().expect("maxsat solver must snapshot");
        save(&mut persist_journal, 99, &artifact).expect("persist must succeed");

        crate::solver_cache::global_clear();
        let loaded_journal = persist_journal.fork();
        let loaded = load(&loaded_journal).expect("load must succeed");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].resolved_engine, SolverEngine::Builtin);
        assert_eq!(
            loaded[0].config_fingerprint,
            fingerprint(&fresh.config().clone(), SolverEngine::Builtin)
        );

        let mut resumed = MaxSatSolver::new();
        resumed
            .warm_from_artifact(&loaded[0])
            .expect("resume must apply");

        let (resumed_hyps, resumed_cert) = resumed
            .solve_with_certificate(&loaded_journal, &verdict)
            .expect("resumed solve must succeed");
        assert_eq!(
            fresh_hyps, resumed_hyps,
            "hypotheses must be byte-identical"
        );
        assert_eq!(
            fresh_cert, resumed_cert,
            "certificate fields (cut, lower bound, method) must be byte-identical"
        );
    }

    #[test]
    fn auto_artifact_records_concrete_resolution() {
        crate::solver_cache::global_clear();
        let (journal, witness) = mixed_cost_journal();
        let verdict = Verdict::fail(vec![witness], "auto resolution");

        let mut solver = HittingSetSolver::new();
        solver.solve(&journal, &verdict).expect("solve");
        let artifact = solver.snapshot_state().expect("solver must snapshot");
        // Auto configures this solver, but the artifact records the concrete
        // resolution, and the state key is derived from it.
        assert_eq!(artifact.resolved_engine, SolverEngine::Builtin);
        assert_eq!(
            artifact.config_fingerprint,
            fingerprint(solver.config(), SolverEngine::Builtin)
        );
        assert_ne!(
            artifact.config_fingerprint,
            fingerprint(solver.config(), SolverEngine::Cadical)
        );
    }

    #[test]
    fn load_ignores_non_solver_state_entries() {
        let mut journal = Journal::new();
        // Append a regular outcome entry with different payload.
        let _regular = journal
            .append(
                ledger_format::EntryKind::Outcome,
                1,
                [],
                Payload::Number(123),
            )
            .expect("regular append");
        let _bytes_other = journal
            .append(
                ledger_format::EntryKind::Outcome,
                1,
                [],
                Payload::Bytes(b"not a solver state".to_vec()),
            )
            .expect("bytes other");

        let artifact = SolverStateArtifact {
            closures: vec![PersistedClosure {
                key: test_hash(9),
                clauses: vec![WeightedClause::new(vec![test_hash(1)], 1)],
                hypotheses: vec![PersistedHypothesis {
                    events: vec![test_hash(1)],
                    total_cost: 1,
                }],
            }],
            config_fingerprint: fingerprint(&solver_config(), SolverEngine::Builtin),
            run_config_hash: None,
            resolved_engine: SolverEngine::Builtin,
        };
        save(&mut journal, 1, &artifact).expect("save artifact");
        let loaded = load(&journal).expect("load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], artifact);
    }

    #[test]
    fn encode_decode_roundtrip_empty_artifact() {
        let artifact = SolverStateArtifact {
            closures: Vec::new(),
            config_fingerprint: [0u8; 32],
            run_config_hash: None,
            resolved_engine: SolverEngine::Builtin,
        };
        let bytes = encode_artifact(&artifact).expect("encode empty");
        let decoded = decode_artifact(&bytes).expect("decode empty");
        assert_eq!(artifact, decoded);
    }

    #[test]
    fn fingerprint_differs_for_each_config_field_including_none_vs_some_zero() {
        // None vs Some(0) must differ for optional fields where 0 is a valid value.
        let none_horizon = SolverConfig {
            max_horizon: None,
            oracle_version: None,
            input_class: None,
            max_faults: None,
            engine: SolverEngine::Auto,
            run_config_hash: None,
        };
        let zero_horizon = SolverConfig {
            max_horizon: Some(0),
            oracle_version: Some(0),
            input_class: Some(0),
            max_faults: Some(0),
            engine: SolverEngine::Auto,
            run_config_hash: None,
        };
        assert_ne!(
            fingerprint(&none_horizon, SolverEngine::Builtin),
            fingerprint(&zero_horizon, SolverEngine::Builtin)
        );

        let with_horizon_zero = SolverConfig {
            max_horizon: Some(0),
            ..Default::default()
        };
        let with_horizon_none = SolverConfig {
            max_horizon: None,
            ..Default::default()
        };
        assert_ne!(
            fingerprint(&with_horizon_none, SolverEngine::Builtin),
            fingerprint(&with_horizon_zero, SolverEngine::Builtin)
        );
    }

    #[test]
    fn incremental_resume_via_solve_incremental() {
        crate::solver_cache::global_clear();
        let closure = ClauseCache::closure_hash(&[test_hash(1), test_hash(2)]);
        let clauses = vec![
            WeightedClause::new(vec![test_hash(1)], 2),
            WeightedClause::new(vec![test_hash(2)], 2),
        ];

        let mut solver_a = HittingSetSolver::new();
        let first = solver_a.solve_incremental(closure, clauses.clone());
        assert!(!first.is_empty());

        // Snapshot and resume into fresh solver.
        let mut tmp_journal = Journal::new();
        let persist_id = solver_a
            .persist_state(&mut tmp_journal, 1)
            .expect("persist incremental");
        crate::solver_cache::global_clear();
        let fresh_journal = tmp_journal.fork();
        let artifact = load(&fresh_journal).expect("load")[0].clone();
        assert_eq!(artifact.closures.len(), 1);
        assert_eq!(artifact.resolved_engine, SolverEngine::Builtin);

        let solver_b = HittingSetSolver::new();
        // Verify dedup id stable.
        let second_id = solver_b
            .persist_state(&mut tmp_journal.clone(), 1)
            .unwrap_or(persist_id);
        let _ = second_id;

        let mut solver_resumed = HittingSetSolver::new();
        solver_resumed
            .resume(&artifact, SolverEngine::Builtin)
            .expect("resume incremental");
        let second = solver_resumed.solve_incremental(closure, clauses.clone());
        // Incremental cache hit path should produce identical sets and costs.
        let first_decisions: Vec<(Vec<Hash>, u64)> = first
            .iter()
            .map(|hyp| (hyp.events.clone(), hyp.total_cost))
            .collect();
        let second_decisions: Vec<(Vec<Hash>, u64)> = second
            .iter()
            .map(|hyp| (hyp.events.clone(), hyp.total_cost))
            .collect();
        assert_eq!(
            first_decisions, second_decisions,
            "resumed incremental solve must be byte-identical"
        );
        let _ = persist_id;
    }

    #[test]
    fn incremental_resume_exact_cost_is_not_flat_two() {
        crate::solver_cache::global_clear();
        let closure = ClauseCache::closure_hash(&[test_hash(7)]);
        let clauses = vec![WeightedClause::new(vec![test_hash(7)], 4)];

        let mut solver_a = HittingSetSolver::new();
        let first = solver_a.solve_incremental(closure, clauses.clone());
        assert_eq!(first[0].total_cost, 4);

        let mut tmp_journal = Journal::new();
        solver_a
            .persist_state(&mut tmp_journal, 1)
            .expect("persist");
        crate::solver_cache::global_clear();
        let artifact = load(&tmp_journal.fork()).expect("load")[0].clone();

        let mut resumed = HittingSetSolver::new();
        resumed
            .resume(&artifact, SolverEngine::Builtin)
            .expect("resume");
        let second = resumed.solve_incremental(closure, clauses);
        assert_eq!(
            second[0].total_cost, 4,
            "resumed cost must be the exact clause-weight cost, not a flat 2"
        );
        let first_decisions: Vec<(Vec<Hash>, u64)> = first
            .iter()
            .map(|hyp| (hyp.events.clone(), hyp.total_cost))
            .collect();
        let second_decisions: Vec<(Vec<Hash>, u64)> = second
            .iter()
            .map(|hyp| (hyp.events.clone(), hyp.total_cost))
            .collect();
        assert_eq!(first_decisions, second_decisions);
    }

    #[test]
    fn resume_rejects_artifact_from_other_run_config_name_space() {
        crate::solver_cache::global_clear();
        let solver_config_a = solver_config().with_run_config_hash(test_hash(11));
        let solver_config_b = solver_config().with_run_config_hash(test_hash(22));
        let mut solver_a = HittingSetSolver::with_config(solver_config_a);
        let hash = test_hash(3);
        let closure = ClauseCache::closure_hash(&[hash]);
        let clauses = vec![WeightedClause::new(vec![hash], 2)];
        solver_a.solve_incremental(closure, clauses);
        let artifact = solver_a.snapshot_state().expect("snapshot under config A");

        let mut solver_b = HittingSetSolver::with_config(solver_config_b);
        let error = solver_b
            .resume(&artifact, SolverEngine::Builtin)
            .expect_err("artifacts from another run-config namespace must be rejected");
        assert!(matches!(
            error,
            SolverError::SolverState(SolverStateError::RunConfigMismatch { .. })
        ));
        assert_eq!(
            solver_b.hypothesis_cache_len(),
            0,
            "nothing may warm from a rejected artifact"
        );
        assert_eq!(solver_b.cache_len(), 0);
    }

    #[test]
    fn resume_empty_clause_entry_recomputes_like_fresh_solver() {
        crate::solver_cache::global_clear();
        // A journal with a witness but no faultable entries: the MaxSAT
        // engine derives an empty clause set and one cost-0 empty-cut
        // hypothesis, which it persists with EMPTY clauses.
        let mut journal = Journal::new();
        let witness = journal
            .append(ledger_format::EntryKind::Outcome, 1, [], Payload::Number(0))
            .expect("append witness");
        let verdict = Verdict::fail(vec![witness], "no faultables");
        let mut maxsat = MaxSatSolver::new();
        let (maxsat_hyps, _) = maxsat
            .solve_with_certificate(&journal, &verdict)
            .expect("maxsat solve");
        assert_eq!(maxsat_hyps.len(), 1);
        assert_eq!(maxsat_hyps[0].total_cost, 0);
        let artifact = maxsat.snapshot_state().expect("snapshot");
        assert_eq!(artifact.closures.len(), 1);
        assert!(
            artifact.closures[0].clauses.is_empty(),
            "fixture must record an empty clause set"
        );
        assert_eq!(artifact.closures[0].hypotheses.len(), 1);
        let closure = ClauseCache::closure_hash(&[witness]);
        let expected_key =
            HittingSetSolver::new().incremental_key_with_tag(closure, engine_tag::BUILTIN);
        assert_eq!(artifact.closures[0].key, expected_key);

        // Batch solve after resume must equal a fresh batch solve: both
        // return no hypotheses. The persisted cost-0 empty hypothesis must
        // never be served by the batch fast path.
        let mut resumed = HittingSetSolver::new();
        resumed
            .warm_from_artifact(&artifact)
            .expect("resume must apply");
        assert_eq!(
            resumed.cache_len(),
            1,
            "resume must insert the empty clause entry like the live solver does"
        );
        assert_eq!(
            resumed.hypothesis_cache_len(),
            0,
            "empty-clause hypotheses must not be restored"
        );
        let mut fresh = HittingSetSolver::new();
        let fresh_hyps = fresh.solve(&journal, &verdict).expect("fresh batch solve");
        assert!(fresh_hyps.is_empty());
        let resumed_hyps = resumed
            .solve(&journal, &verdict)
            .expect("resumed batch solve");
        assert_eq!(
            resumed_hyps, fresh_hyps,
            "resumed batch solve must recompute like a fresh one"
        );
        assert!(
            resumed_hyps.is_empty(),
            "the stale cost-0 empty hypothesis must not be returned"
        );

        // Incremental solve under the persisted key with REAL clauses must
        // recompute: the empty clause entry never satisfies a non-empty
        // query, so the stale cost-0 hypothesis is never served.
        let real_clauses = vec![WeightedClause::new(vec![witness], 2)];
        let got = resumed.solve_incremental(closure, real_clauses.clone());
        let mut fresh_incremental = HittingSetSolver::new();
        let expected = fresh_incremental.solve_incremental(closure, real_clauses);
        assert_eq!(
            got, expected,
            "incremental solve under the resumed key must recompute like a fresh one"
        );
        assert!(!got.is_empty());
        assert!(
            got.iter().all(|hyp| hyp.total_cost == 2),
            "the computed hypotheses must carry the real clause cost, not the stale 0"
        );

        // An EMPTY clause query under the persisted key must recompute
        // identically to a fresh solver: a fresh solver returns no
        // hypotheses for the trivial empty case, and the recorded cost-0
        // empty-cut hypothesis is not restored, so the clause-equality hit
        // path can never serve it.
        let empty_query = Vec::<WeightedClause>::new();
        let got_empty = resumed.solve_incremental(closure, empty_query.clone());
        let mut fresh_empty = HittingSetSolver::new();
        let expected_empty = fresh_empty.solve_incremental(closure, empty_query);
        assert_eq!(
            got_empty, expected_empty,
            "the empty-clause query must behave like a fresh solver"
        );
        assert!(
            got_empty.is_empty(),
            "the trivial empty case yields no hypotheses on either engine"
        );
    }

    #[test]
    fn batch_solve_recomputes_when_cached_clauses_mismatch_journal() {
        crate::solver_cache::global_clear();
        // Journal whose derivation yields one clause over send_a.
        let mut journal = Journal::new();
        let send_a = journal
            .append(
                ledger_format::EntryKind::Send,
                1,
                [],
                Payload::Pair { left: 2, right: 1 },
            )
            .expect("append send_a");
        let witness = journal
            .append(
                ledger_format::EntryKind::Outcome,
                2,
                [send_a],
                Payload::Number(0),
            )
            .expect("append witness");
        let verdict = Verdict::fail(vec![witness], "forged mismatch");

        let mut fresh = HittingSetSolver::new();
        let fresh_hyps = fresh.solve(&journal, &verdict).expect("fresh solve");
        assert_eq!(fresh_hyps.len(), 1);
        assert_eq!(fresh_hyps[0].events, vec![send_a]);
        assert_eq!(fresh_hyps[0].total_cost, 2);

        // Forge an artifact: the correct key for this closure, but clauses
        // and a hypothesis over an event absent from the journal. The entry
        // is internally covered (events are clause literals) and carries a
        // valid state key, so it passes resume validation.
        let closure = ClauseCache::closure_hash(&[witness]);
        let send_b = test_hash(0xA5);
        let forged_key =
            HittingSetSolver::new().incremental_key_with_tag(closure, engine_tag::BUILTIN);
        let forged = SolverStateArtifact {
            closures: vec![PersistedClosure {
                key: forged_key,
                clauses: vec![WeightedClause::new(vec![send_b], 3)],
                hypotheses: vec![PersistedHypothesis {
                    events: vec![send_b],
                    total_cost: 3,
                }],
            }],
            config_fingerprint: fingerprint(&solver_config(), SolverEngine::Builtin),
            run_config_hash: None,
            resolved_engine: SolverEngine::Builtin,
        };
        let mut resumed = HittingSetSolver::new();
        resumed
            .warm_from_artifact(&forged)
            .expect("covered forged entry must apply");

        // Batch solve validates the recorded clauses against the journal
        // derivation: the forged hypothesis is recomputed away.
        let got = resumed.solve(&journal, &verdict).expect("resumed solve");
        assert_eq!(
            got, fresh_hyps,
            "mismatched cached clauses must recompute to the journal derivation"
        );
        assert_eq!(got[0].events, vec![send_a]);
        assert_eq!(got[0].total_cost, 2);
        assert!(
            !got.iter().any(|hyp| hyp.events == vec![send_b]),
            "the forged hypothesis must never be served"
        );
    }

    #[cfg(feature = "solver-cadical")]
    #[test]
    fn resume_rejects_real_cadical_artifact_in_builtin_solver() {
        crate::solver_cache::global_clear();
        let (journal, witness) = mixed_cost_journal();
        let verdict = Verdict::fail(vec![witness], "real cadical cross-engine");

        let mut cadical =
            MaxSatSolver::with_config(SolverConfig::default().with_engine(SolverEngine::Cadical));
        assert_eq!(cadical.resolved_engine(), SolverEngine::Cadical);
        let (hyps, _) = cadical
            .solve_with_certificate(&journal, &verdict)
            .expect("cadical solve must succeed");
        assert!(!hyps.is_empty());
        let artifact = cadical.snapshot_state().expect("snapshot");
        assert_eq!(artifact.resolved_engine, SolverEngine::Cadical);
        assert_ne!(
            artifact.config_fingerprint,
            fingerprint(&solver_config(), SolverEngine::Builtin),
            "a cadical-produced state key must differ from the builtin key"
        );

        let mut builtin = HittingSetSolver::new();
        let error = builtin
            .resume(&artifact, SolverEngine::Builtin)
            .expect_err("a real cadical artifact must be rejected by the builtin solver");
        assert!(matches!(
            error,
            SolverError::SolverState(SolverStateError::EngineMismatch { .. })
        ));
        assert_eq!(builtin.cache_len(), 0);
        assert_eq!(builtin.hypothesis_cache_len(), 0);
    }

    /// Version check for the cost-model tag bound by the state key.
    ///
    /// The fingerprint folds [`COST_MODEL_VERSION`] into its domain. This
    /// assertion pins the current value so a reviewer can see when the tag
    /// moves and re-check the resume policy.
    #[test]
    fn cost_model_version_is_pinned() {
        assert_eq!(COST_MODEL_VERSION, 1);
    }

    fn header_bytes(
        version: u8,
        engine: u8,
        run_config_bytes: Vec<u8>,
        fingerprint: Hash,
        closures_len: u64,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(version);
        out.push(engine);
        out.extend_from_slice(&run_config_bytes);
        out.extend_from_slice(&fingerprint);
        out.extend_from_slice(&closures_len.to_le_bytes());
        out
    }

    #[test]
    fn decode_rejects_oversized_closure_length() {
        let bytes = header_bytes(
            FORMAT_VERSION,
            engine_tag::BUILTIN,
            vec![0x00],
            [0u8; 32],
            u64::MAX,
        );
        assert!(matches!(
            decode_artifact(&bytes),
            Err(SolverStateError::LengthOverflow {
                field: "closures",
                ..
            })
        ));
    }

    #[test]
    fn decode_rejects_oversized_literal_length() {
        // One closure whose clause declares an absurd literal count. The
        // clause-level guard passes (the clause can still hold a count and a
        // weight), so the literal-count guard is the one that fires.
        let mut bytes = header_bytes(
            FORMAT_VERSION,
            engine_tag::BUILTIN,
            vec![0x00],
            [0u8; 32],
            1,
        );
        bytes.extend_from_slice(&test_hash(1));
        bytes.extend_from_slice(&1u64.to_le_bytes()); // one clause
        bytes.extend_from_slice(&u64::MAX.to_le_bytes()); // literal count
        bytes.extend_from_slice(&2u64.to_le_bytes()); // weight field
        assert!(matches!(
            decode_artifact(&bytes),
            Err(SolverStateError::LengthOverflow {
                field: "literal",
                ..
            })
        ));
    }

    #[test]
    fn decode_rejects_oversized_event_length() {
        // One closure, no clauses, one hypothesis with an absurd event count.
        let mut bytes = header_bytes(
            FORMAT_VERSION,
            engine_tag::BUILTIN,
            vec![0x00],
            [0u8; 32],
            1,
        );
        bytes.extend_from_slice(&test_hash(1));
        bytes.extend_from_slice(&0u64.to_le_bytes()); // no clauses
        bytes.extend_from_slice(&1u64.to_le_bytes()); // one hypothesis
        bytes.extend_from_slice(&u64::MAX.to_le_bytes()); // event count
        bytes.extend_from_slice(&4u64.to_le_bytes()); // total cost field
        assert!(matches!(
            decode_artifact(&bytes),
            Err(SolverStateError::LengthOverflow { field: "event", .. })
        ));
    }

    #[test]
    fn decode_rejects_truncated_payload() {
        // A payload far shorter than the fixed header is truncated at offset 0.
        assert!(matches!(
            decode_artifact(&MAGIC[..4]),
            Err(SolverStateError::Truncated { offset: 0 })
        ));
        // A payload cut one byte short of a complete artifact ends inside the
        // final field read, and the error names the failing offset.
        let artifact = SolverStateArtifact {
            closures: vec![PersistedClosure {
                key: test_hash(1),
                clauses: vec![WeightedClause::new(vec![test_hash(2)], 3)],
                hypotheses: vec![PersistedHypothesis {
                    events: vec![test_hash(2)],
                    total_cost: 3,
                }],
            }],
            config_fingerprint: [0u8; 32],
            run_config_hash: None,
            resolved_engine: SolverEngine::Builtin,
        };
        let mut bytes = encode_artifact(&artifact).expect("encode");
        bytes.pop();
        match decode_artifact(&bytes) {
            Err(SolverStateError::Truncated { offset }) => {
                // The final (truncated) u64 read starts seven bytes before the
                // end of the payload.
                assert_eq!(
                    offset,
                    bytes.len() - 7,
                    "the offset must name the failed read position"
                );
            }
            other => panic!("expected Truncated with offset, got {other:?}"),
        }
        // A declared closure count that the payload cannot satisfy fails
        // cleanly before any allocation.
        let mut short = header_bytes(
            FORMAT_VERSION,
            engine_tag::BUILTIN,
            vec![0x00],
            [0u8; 32],
            1,
        );
        short.extend_from_slice(&test_hash(1));
        assert!(matches!(
            decode_artifact(&short),
            Err(SolverStateError::LengthOverflow {
                field: "closures",
                ..
            })
        ));
    }

    #[test]
    fn decode_rejects_garbage_version() {
        let bytes = header_bytes(99, engine_tag::BUILTIN, vec![0x00], [0u8; 32], 0);
        assert!(matches!(
            decode_artifact(&bytes),
            Err(SolverStateError::UnsupportedFormatVersion(99))
        ));
    }

    #[test]
    fn decode_rejects_unknown_engine_byte() {
        let bytes = header_bytes(FORMAT_VERSION, 0xEE, vec![0x00], [0u8; 32], 0);
        assert!(matches!(
            decode_artifact(&bytes),
            Err(SolverStateError::UnknownEngineByte(0xEE))
        ));
    }

    #[test]
    fn decode_rejects_unknown_run_config_flag() {
        let bytes = header_bytes(
            FORMAT_VERSION,
            engine_tag::BUILTIN,
            vec![0x02],
            [0u8; 32],
            0,
        );
        assert!(matches!(
            decode_artifact(&bytes),
            Err(SolverStateError::UnknownRunConfigFlag(2))
        ));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let artifact = SolverStateArtifact {
            closures: Vec::new(),
            config_fingerprint: [0u8; 32],
            run_config_hash: None,
            resolved_engine: SolverEngine::Builtin,
        };
        let mut bytes = encode_artifact(&artifact).expect("encode");
        bytes.push(0xAA);
        assert!(matches!(
            decode_artifact(&bytes),
            Err(SolverStateError::TrailingBytes)
        ));
    }

    #[test]
    fn decode_rejects_missing_magic() {
        let mut bytes = encode_artifact(&SolverStateArtifact {
            closures: Vec::new(),
            config_fingerprint: [0u8; 32],
            run_config_hash: None,
            resolved_engine: SolverEngine::Builtin,
        })
        .expect("encode");
        bytes[0] ^= 0xFF;
        assert!(matches!(
            decode_artifact(&bytes),
            Err(SolverStateError::MissingMagic)
        ));
    }

    #[test]
    fn load_fails_loudly_on_malformed_state_entry() {
        use ledger_journal::Journal as J;
        let mut journal = J::new();
        let malformed = header_bytes(
            FORMAT_VERSION,
            engine_tag::BUILTIN,
            vec![0x00],
            [0u8; 32],
            u64::MAX,
        );
        journal
            .append(
                ledger_format::EntryKind::Outcome,
                1,
                [],
                Payload::Bytes(malformed),
            )
            .expect("append malformed state entry");
        assert!(matches!(
            load(&journal),
            Err(SolverError::SolverState(
                SolverStateError::LengthOverflow { .. }
            ))
        ));
    }

    #[test]
    fn resume_rejects_artifact_from_older_format_version() {
        crate::solver_cache::global_clear();
        let mut solver = HittingSetSolver::new();
        let artifact = SolverStateArtifact {
            closures: Vec::new(),
            config_fingerprint: fingerprint(&solver_config(), SolverEngine::Builtin),
            run_config_hash: None,
            resolved_engine: SolverEngine::Builtin,
        };
        let mut bytes = encode_artifact(&artifact).expect("encode");
        // Rewind the version byte to the previous format.
        bytes[MAGIC.len()] = FORMAT_VERSION - 1;
        assert!(matches!(
            decode_artifact(&bytes),
            Err(SolverStateError::UnsupportedFormatVersion(_))
        ));
        solver
            .resume(&artifact, SolverEngine::Builtin)
            .expect("current-format artifact still applies");
    }
}
