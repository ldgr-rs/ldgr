//! Typed support semantics for fault-cut evidence.
//!
//! Journal parent edges represent causal order only. They never imply that a
//! parent is sufficient or necessary support for an outcome. Support is
//! declared explicitly by a [`SupportProvider`]; no code path in this module
//! infers support from parent count, path shape, or vector-clock order.
//!
//! The [`SupportExpr`] tree is the single source of support semantics. An
//! expression with any [`SupportExpr::Opaque`] child cannot back strong
//! fault-cut or optimality claims ([`SupportExpr::is_strong`] reports that).

use std::collections::BTreeSet;

use ledger_format::{ActorId, EntryKind, Hash};
use ledger_journal::Journal;
use thiserror::Error;

/// Typed failure while constructing a support expression.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SupportError {
    /// An `AllOf` expression must name at least one jointly required entry.
    #[error("AllOf requires at least one jointly required entry")]
    EmptyAllOf,
    /// An `AnyOf` expression must list at least one alternative branch.
    #[error("AnyOf requires at least one alternative branch")]
    EmptyAnyOf,
}

/// Result of evaluating a support expression against a journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportOutcome {
    /// Every `AllOf` child exists and at least one `AnyOf` branch holds.
    Satisfied,
    /// The expression evaluates to false against the journal.
    NotSatisfied,
    /// `Opaque` semantics or a horizon cut leave the truth unknown.
    Unknown,
}

impl SupportOutcome {
    /// Whether the outcome is a definite positive.
    pub fn is_satisfied(self) -> bool {
        matches!(self, Self::Satisfied)
    }
}

/// Explicit support expression over journal entry ids.
///
/// `AllOf` means every child is jointly required. `AnyOf` means one listed
/// branch is sufficient. `Opaque` prevents strong fault-cut and optimality
/// claims: any `Opaque` child forces [`SupportExpr::is_strong`] to `false`.
///
/// The variants are public for pattern matching, but construction goes
/// through [`SupportExpr::all_of`] and [`SupportExpr::any_of`] (or the
/// `TryFrom` impls) so an empty `AllOf` or `AnyOf` cannot be built.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SupportExpr {
    /// Every listed entry is jointly required.
    AllOf(BTreeSet<Hash>),
    /// One listed branch is sufficient.
    AnyOf(Vec<SupportExpr>),
    /// Semantics are unknown; strong claims degrade to heuristic.
    Opaque,
}

impl SupportExpr {
    /// Construct `AllOf`, rejecting an empty requirement set.
    pub fn all_of(ids: BTreeSet<Hash>) -> Result<Self, SupportError> {
        if ids.is_empty() {
            return Err(SupportError::EmptyAllOf);
        }
        Ok(Self::AllOf(ids))
    }

    /// Construct `AnyOf`, rejecting an empty branch list.
    pub fn any_of(branches: Vec<SupportExpr>) -> Result<Self, SupportError> {
        if branches.is_empty() {
            return Err(SupportError::EmptyAnyOf);
        }
        Ok(Self::AnyOf(branches))
    }

    /// Whether this expression supports strong fault-cut and optimality
    /// claims. Any `Opaque` child degrades the whole expression to heuristic.
    pub fn is_strong(&self) -> bool {
        match self {
            Self::AllOf(_) => true,
            Self::AnyOf(branches) => branches.iter().all(SupportExpr::is_strong),
            Self::Opaque => false,
        }
    }

    /// Evaluate this expression against `journal`.
    pub fn evaluate(&self, journal: &Journal) -> SupportOutcome {
        self.evaluate_with_horizon(journal, None)
    }

    /// Evaluate with an optional derivation-depth horizon.
    ///
    /// Nested `AnyOf` branches beyond the horizon evaluate to
    /// [`SupportOutcome::Unknown`], so a bounded walk cannot over-claim.
    pub fn evaluate_with_horizon(
        &self,
        journal: &Journal,
        horizon: Option<usize>,
    ) -> SupportOutcome {
        self.eval_depth(journal, horizon, 0)
    }

    fn eval_depth(
        &self,
        journal: &Journal,
        horizon: Option<usize>,
        depth: usize,
    ) -> SupportOutcome {
        if let Some(limit) = horizon
            && depth > limit
        {
            return SupportOutcome::Unknown;
        }
        match self {
            Self::Opaque => SupportOutcome::Unknown,
            Self::AllOf(ids) => {
                if ids.iter().all(|id| journal.get(id).is_some()) {
                    SupportOutcome::Satisfied
                } else {
                    SupportOutcome::NotSatisfied
                }
            }
            Self::AnyOf(branches) => {
                let mut saw_unknown = false;
                for branch in branches {
                    match branch.eval_depth(journal, horizon, depth + 1) {
                        SupportOutcome::Satisfied => return SupportOutcome::Satisfied,
                        SupportOutcome::Unknown => saw_unknown = true,
                        SupportOutcome::NotSatisfied => {}
                    }
                }
                if saw_unknown {
                    SupportOutcome::Unknown
                } else {
                    SupportOutcome::NotSatisfied
                }
            }
        }
    }

    /// Canonical encoding: a variant tag byte followed by sorted child bytes.
    ///
    /// `BTreeSet` iteration and the recursive visit order are deterministic,
    /// so equal expressions always encode to equal bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::AllOf(ids) => {
                out.push(0x00);
                for id in ids {
                    out.extend_from_slice(id);
                }
            }
            Self::AnyOf(branches) => {
                out.push(0x01);
                for branch in branches {
                    branch.encode_into(out);
                }
            }
            Self::Opaque => out.push(0x02),
        }
    }

    /// BLAKE3 digest over the canonical encoding.
    pub fn digest(&self) -> Hash {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }
}

impl TryFrom<BTreeSet<Hash>> for SupportExpr {
    type Error = SupportError;

    fn try_from(ids: BTreeSet<Hash>) -> Result<Self, Self::Error> {
        Self::all_of(ids)
    }
}

impl TryFrom<Vec<SupportExpr>> for SupportExpr {
    type Error = SupportError;

    fn try_from(branches: Vec<SupportExpr>) -> Result<Self, Self::Error> {
        Self::any_of(branches)
    }
}

/// Versioned support provider.
///
/// Derives support from workload, effect, oracle, or adapter semantics.
/// [`SupportProvider::version`] and [`SupportProvider::digest`] identify the
/// provider; both feed solver cache keys so a provider change never reuses
/// derived clauses or hypotheses.
pub trait SupportProvider {
    /// Provider version. Bump when the derived semantics change.
    fn version(&self) -> u64;

    /// Digest over `version` and the declared expression.
    fn digest(&self) -> Hash;

    /// The support expression this provider derives for `journal`.
    fn support(&self, journal: &Journal) -> SupportExpr;
}

/// Provider that serves one explicitly declared expression.
///
/// The fixture registry uses this type to attach a versioned, digest-pinned
/// support model to every certifiable corpus scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticSupportProvider {
    version: u64,
    expression: SupportExpr,
    digest: Hash,
}

impl StaticSupportProvider {
    /// Construct a provider whose digest pins `version` and `expression`.
    pub fn new(version: u64, expression: SupportExpr) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&version.to_le_bytes());
        hasher.update(&expression.digest());
        let digest = *hasher.finalize().as_bytes();
        Self {
            version,
            expression,
            digest,
        }
    }

    /// The declared expression this provider serves.
    pub fn expression(&self) -> &SupportExpr {
        &self.expression
    }

    /// The provider version.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The provider digest over `version` and the declared expression.
    pub fn digest(&self) -> Hash {
        self.digest
    }
}

impl SupportProvider for StaticSupportProvider {
    fn version(&self) -> u64 {
        self.version
    }

    fn digest(&self) -> Hash {
        self.digest
    }

    fn support(&self, _journal: &Journal) -> SupportExpr {
        self.expression.clone()
    }
}

/// Collect every entry id of `kind` written by `actor`.
///
/// The result is a `BTreeSet`, so ids arrive canonically sorted for
/// [`SupportExpr::all_of`].
pub fn entry_ids_by(journal: &Journal, kind: EntryKind, actor: ActorId) -> BTreeSet<Hash> {
    journal
        .entries()
        .filter(|entry| entry.data.kind == kind && entry.data.actor == actor)
        .map(|entry| entry.id)
        .collect()
}

/// Build `AllOf` over `ids`, degrading to `Opaque` when the set is empty.
///
/// A run without the named semantic role cannot support a strong claim, so
/// the model reports unknown instead of an empty requirement set.
pub fn all_of_ids(ids: impl IntoIterator<Item = Hash>) -> SupportExpr {
    match SupportExpr::all_of(ids.into_iter().collect()) {
        Ok(expr) => expr,
        Err(_) => SupportExpr::Opaque,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_format::EntryPayload;

    fn journal_with_ids(count: usize) -> (Journal, Vec<Hash>) {
        let mut journal = Journal::new();
        let mut recorded = Vec::new();
        for i in 0..count {
            let hash = journal
                .append(
                    EntryKind::Send,
                    (i % 3) as ActorId,
                    [],
                    EntryPayload::Send(ledger_format::SendFrame {
                        message_id: ledger_format::MessageId::new((i % 3) as ActorId, 0),
                        from: (i % 3) as ActorId,
                        to: 1,
                        original_content: (i as u64).to_le_bytes().to_vec(),
                    }),
                )
                .expect("append must succeed");
            recorded.push(hash);
        }
        (journal, recorded)
    }

    fn absent_id() -> Hash {
        [0xEE; 32]
    }

    fn all(ids: Vec<Hash>) -> SupportExpr {
        SupportExpr::all_of(ids.into_iter().collect()).expect("non-empty")
    }

    fn any(branches: Vec<SupportExpr>) -> SupportExpr {
        SupportExpr::any_of(branches).expect("non-empty")
    }

    #[test]
    fn construction_rejects_empty_all_of() {
        assert_eq!(
            SupportExpr::all_of(BTreeSet::new()),
            Err(SupportError::EmptyAllOf)
        );
        assert_eq!(
            BTreeSet::<Hash>::new().try_into(),
            Err::<SupportExpr, _>(SupportError::EmptyAllOf)
        );
    }

    #[test]
    fn construction_rejects_empty_any_of() {
        assert_eq!(
            SupportExpr::any_of(Vec::new()),
            Err(SupportError::EmptyAnyOf)
        );
        assert_eq!(
            Vec::<SupportExpr>::new().try_into(),
            Err::<SupportExpr, _>(SupportError::EmptyAnyOf)
        );
    }

    #[test]
    fn nested_truth_table_satisfied_cases() {
        let (journal, recorded) = journal_with_ids(4);
        let (a, b, c, d) = (recorded[0], recorded[1], recorded[2], recorded[3]);

        // AllOf over present ids: satisfied.
        assert_eq!(
            all(vec![a, b]).evaluate(&journal),
            SupportOutcome::Satisfied
        );
        // Nested AnyOf{AllOf{a,b}, AllOf{c,d}} with both branches present.
        let nested = any(vec![all(vec![a, b]), all(vec![c, d])]);
        assert_eq!(nested.evaluate(&journal), SupportOutcome::Satisfied);
    }

    #[test]
    fn all_of_requires_every_child() {
        let (journal, recorded) = journal_with_ids(2);
        let (present, missing) = (recorded[0], absent_id());
        assert_eq!(
            all(vec![present, missing]).evaluate(&journal),
            SupportOutcome::NotSatisfied
        );
    }

    #[test]
    fn any_of_one_branch_suffices() {
        let (journal, recorded) = journal_with_ids(1);
        let (present, absent) = (recorded[0], absent_id());
        let expr = any(vec![all(vec![absent]), all(vec![present])]);
        assert_eq!(expr.evaluate(&journal), SupportOutcome::Satisfied);
    }

    #[test]
    fn chain_deeper_than_horizon_is_unknown() {
        let (journal, recorded) = journal_with_ids(3);
        let (a, b, c) = (recorded[0], recorded[1], recorded[2]);
        let chain = any(vec![any(vec![any(vec![all(vec![a, b, c])])])]);
        assert_eq!(chain.evaluate(&journal), SupportOutcome::Satisfied);
        assert_eq!(
            chain.evaluate_with_horizon(&journal, Some(1)),
            SupportOutcome::Unknown,
            "a bounded walk cannot verify past its depth"
        );
    }

    #[test]
    fn diamond_holds_when_either_witness_present() {
        let (journal, recorded) = journal_with_ids(3);
        let (a, b, c) = (recorded[0], recorded[1], recorded[2]);
        let diamond = any(vec![all(vec![a, b]), all(vec![a, c])]);
        assert_eq!(diamond.evaluate(&journal), SupportOutcome::Satisfied);
    }

    #[test]
    fn redundant_support_member_is_still_required() {
        let (journal, recorded) = journal_with_ids(1);
        let (present, duplicate) = (recorded[0], absent_id());
        // A redundant member cannot be elided: it is still jointly required.
        assert_eq!(
            all(vec![present, duplicate]).evaluate(&journal),
            SupportOutcome::NotSatisfied
        );
    }

    #[test]
    fn disjoint_witness_only_one_present() {
        let (journal, recorded) = journal_with_ids(3);
        let (a, b, c) = (recorded[0], recorded[1], recorded[2]);
        let missing = absent_id();
        let disjoint = any(vec![all(vec![a, missing]), all(vec![b, c])]);
        assert_eq!(disjoint.evaluate(&journal), SupportOutcome::Satisfied);
    }

    #[test]
    fn opaque_degrades_strong_claims() {
        let (journal, recorded) = journal_with_ids(2);
        let (a, b) = (recorded[0], recorded[1]);
        let strong = all(vec![a, b]);
        assert!(strong.is_strong());
        let with_opaque = any(vec![all(vec![a]), SupportExpr::Opaque]);
        assert!(!with_opaque.is_strong());
        assert_eq!(
            with_opaque.evaluate(&journal),
            SupportOutcome::Satisfied,
            "the satisfied branch still satisfies, but the claim is weak"
        );
        assert_eq!(
            SupportExpr::Opaque.evaluate(&journal),
            SupportOutcome::Unknown
        );
    }

    #[test]
    fn encoding_and_digest_are_equivalent() {
        let (_journal, recorded) = journal_with_ids(2);
        let (a, b) = (recorded[0], recorded[1]);
        let left = all(vec![a, b]);
        let right = all(vec![a, b]);
        assert_eq!(left.canonical_bytes(), right.canonical_bytes());
        assert_eq!(left.digest(), right.digest());
        // AllOf is a set: member order never changes the expression.
        assert_eq!(all(vec![a, b]).digest(), all(vec![b, a]).digest());
        // Same provider state yields the same provider digest.
        let provider_a = StaticSupportProvider::new(1, left.clone());
        let provider_b = StaticSupportProvider::new(1, right.clone());
        assert_eq!(provider_a.digest(), provider_b.digest());
        assert_eq!(provider_a.version(), 1);
    }

    #[test]
    fn provider_digest_changes_with_version() {
        let (_journal, recorded) = journal_with_ids(1);
        let expr = all(vec![recorded[0]]);
        let v1 = StaticSupportProvider::new(1, expr.clone());
        let v2 = StaticSupportProvider::new(2, expr);
        assert_ne!(v1.digest(), v2.digest());
    }

    #[test]
    fn opaque_has_distinct_canonical_bytes() {
        assert_eq!(SupportExpr::Opaque.canonical_bytes(), vec![0x02]);
        let (_journal, recorded) = journal_with_ids(1);
        assert_eq!(all(vec![recorded[0]]).canonical_bytes()[0], 0x00);
    }

    #[test]
    fn entry_ids_by_filters_kind_and_actor() {
        let mut journal = Journal::new();
        let send = journal
            .append(
                EntryKind::Send,
                0,
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(0, 0),
                    from: 0,
                    to: 1,
                    original_content: 1u64.to_le_bytes().to_vec(),
                }),
            )
            .expect("send");
        journal
            .append(
                EntryKind::Recv,
                1,
                [],
                EntryPayload::Recv(ledger_format::RecvFrame {
                    message_id: ledger_format::MessageId::new(1, 0),
                    from: 1,
                    to: 1,
                    observed_content: 2u64.to_le_bytes().to_vec(),
                }),
            )
            .expect("recv");
        let ids = entry_ids_by(&journal, EntryKind::Send, 0);
        assert_eq!(ids.len(), 1);
        assert!(ids.contains(&send));
        assert!(entry_ids_by(&journal, EntryKind::Send, 1).is_empty());
    }
}
