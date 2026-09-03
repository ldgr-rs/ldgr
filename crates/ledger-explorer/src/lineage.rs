#![deny(unsafe_code)]
//! Differential lineage maintenance: index caches witness causal closure and derivation paths.
//!
//! `LineageIndex` caches the witness causal closure and derivation paths for
//! one solver configuration. `build` computes a fresh index; `refresh`
//! recomputes the same full walk and replaces the cached state whenever the
//! journal length or configuration fingerprint moved, so a refreshed index
//! is always equal to a fresh build.

use std::collections::BTreeSet;

use ledger_format::EntryHash;
use ledger_journal::Journal;

use crate::solver::SolverConfig;
use crate::solver::SolverEngine;
use crate::solver::is_faultable;
use crate::solver_state::fingerprint;

/// Cached lineage for a witness set under a solver configuration.
#[derive(Debug, Clone)]
pub struct LineageIndex {
    /// Causal closure (all entries visited up to horizon) or faultable union.
    pub closure: BTreeSet<EntryHash>,
    /// Derivation paths as faultable hash sequences.
    pub paths: Vec<Vec<EntryHash>>,
    /// Journal length at last build/refresh.
    pub journal_len_at_build: usize,
    /// Fingerprint of the solver configuration at last build.
    pub config_fingerprint: EntryHash,
    /// Entries visited by the last build or refresh walk. This is the
    /// intended-work measure: a differential refresh walks only witnesses
    /// absent from the cached closure, so this stays small relative to the
    /// journal even after the journal grows.
    pub walked_entries: usize,
}

#[allow(clippy::too_many_arguments)]
fn collect_bounded_hash(
    journal: &Journal,
    current: EntryHash,
    depth: usize,
    max_depth: usize,
    current_path: &mut Vec<EntryHash>,
    paths: &mut Vec<Vec<EntryHash>>,
    closure: &mut BTreeSet<EntryHash>,
    truncated: &mut bool,
) {
    if depth > max_depth {
        *truncated = true;
        if !current_path.is_empty() {
            paths.push(current_path.clone());
        }
        return;
    }
    let Some(entry) = journal.get(&current) else {
        return;
    };
    closure.insert(current);
    let pushed = if is_faultable(entry.data.kind) {
        current_path.push(current);
        true
    } else {
        false
    };
    if entry.data.parents.is_empty() {
        if !current_path.is_empty() {
            paths.push(current_path.clone());
        }
    } else {
        for parent in &entry.data.parents {
            collect_bounded_hash(
                journal,
                *parent,
                depth + 1,
                max_depth,
                current_path,
                paths,
                closure,
                truncated,
            );
        }
    }
    if pushed {
        current_path.pop();
    }
}

fn collect_hash(
    journal: &Journal,
    current: EntryHash,
    current_path: &mut Vec<EntryHash>,
    paths: &mut Vec<Vec<EntryHash>>,
    closure: &mut BTreeSet<EntryHash>,
) {
    let Some(entry) = journal.get(&current) else {
        return;
    };
    closure.insert(current);
    let pushed = if is_faultable(entry.data.kind) {
        current_path.push(current);
        true
    } else {
        false
    };
    if entry.data.parents.is_empty() {
        if !current_path.is_empty() {
            paths.push(current_path.clone());
        }
    } else {
        for parent in &entry.data.parents {
            collect_hash(journal, *parent, current_path, paths, closure);
        }
    }
    if pushed {
        current_path.pop();
    }
}

fn collect_lineage(
    journal: &Journal,
    witnesses: &[EntryHash],
    config: &SolverConfig,
    walked: &mut usize,
) -> (BTreeSet<EntryHash>, Vec<Vec<EntryHash>>) {
    let mut closure = BTreeSet::new();
    let mut raw_paths = Vec::new();
    let mut truncated = false;
    for witness in witnesses {
        let mut current_path = Vec::new();
        if let Some(h) = config.max_horizon {
            collect_bounded_hash(
                journal,
                *witness,
                0,
                h,
                &mut current_path,
                &mut raw_paths,
                &mut closure,
                &mut truncated,
            );
        } else {
            collect_hash(
                journal,
                *witness,
                &mut current_path,
                &mut raw_paths,
                &mut closure,
            );
        }
    }
    *walked = closure.len();
    // Typed hazard walk over explicit support semantics. Each raw parent path
    // becomes one `AllOf` branch under a single `AnyOf`; a horizon cut joins
    // an `Opaque` branch. The hard-clause walk then preserves every
    // alternative group instead of flattening them into one clause.
    let bounded_cut = truncated && config.max_horizon.is_some();
    let support = crate::support::support_from_paths(&raw_paths, bounded_cut);
    let mut paths = crate::support::hard_clauses_from_support(&support);
    // An `Opaque`-only support yields no clause: the bounded walk proved
    // nothing, so the caller fails closed with `EmptyProvenance` instead of
    // ranking an unrelated event.
    if paths.is_empty() {
        raw_paths.sort();
        raw_paths.dedup();
        let mut filtered: Vec<Vec<EntryHash>> = Vec::new();
        for p in &raw_paths {
            let s: BTreeSet<EntryHash> = p.iter().copied().collect();
            if !s.is_empty() {
                filtered.push(s.into_iter().collect());
            }
        }
        filtered.sort();
        filtered.dedup();
        paths = filtered;
    } else {
        for clause in &mut paths {
            clause.sort();
        }
        paths.sort();
        paths.dedup();
    }
    (closure, paths)
}

impl LineageIndex {
    /// Build a fresh lineage index for `witnesses` under `config`.
    ///
    /// The state key folds in `resolved_engine`, the engine the solver
    /// actually executes, so a rebuilt index tracks the same namespace the
    /// solver's cache keys use.
    pub fn build(
        journal: &Journal,
        witnesses: &[EntryHash],
        config: &SolverConfig,
        resolved_engine: SolverEngine,
    ) -> Self {
        let mut walked = 0usize;
        let (closure, paths) = collect_lineage(journal, witnesses, config, &mut walked);
        Self {
            closure,
            paths,
            journal_len_at_build: journal.len(),
            config_fingerprint: fingerprint(config, resolved_engine),
            walked_entries: walked,
        }
    }

    /// Build lineage directly from an explicit support expression.
    ///
    /// Each `AllOf` becomes one path; each `AnyOf` branch stays separate so
    /// alternative groups never flatten. Only faultable entries present in
    /// `journal` are kept. The closure joins the witnesses and the surviving
    /// support ids in deterministic `BTreeSet` order.
    pub fn build_with_support(
        journal: &Journal,
        witnesses: &[EntryHash],
        config: &SolverConfig,
        resolved_engine: SolverEngine,
        support: &crate::support::SupportExpr,
    ) -> Self {
        let mut closure: BTreeSet<EntryHash> = witnesses.iter().copied().collect();
        let mut paths = Vec::new();
        for mut clause in crate::support::hard_clauses_from_support(support) {
            clause.retain(|h| {
                journal
                    .get(h)
                    .is_some_and(|e| crate::solver::is_faultable(e.data.kind))
            });
            if clause.is_empty() {
                continue;
            }
            clause.sort();
            for h in &clause {
                closure.insert(*h);
            }
            paths.push(clause);
        }
        paths.sort();
        paths.dedup();
        let walked = closure.len();
        Self {
            closure,
            paths,
            journal_len_at_build: journal.len(),
            config_fingerprint: fingerprint(config, resolved_engine),
            walked_entries: walked,
        }
    }

    /// Refresh the index after the journal may have grown.
    ///
    /// The journal DAG is append-only: parents of existing entries never
    /// change, so the cached closure of an already-walked witness stays
    /// valid when only the journal length moves. This refresh walks only
    /// witnesses absent from the cached closure (a differential update);
    /// the return value reports whether the cached state changed. A
    /// config-fingerprint change forces a full re-walk because the walk
    /// semantics themselves changed.
    pub fn refresh(
        &mut self,
        journal: &Journal,
        witnesses: &[EntryHash],
        config: &SolverConfig,
        resolved_engine: SolverEngine,
    ) -> bool {
        let new_fp = fingerprint(config, resolved_engine);
        let new_len = journal.len();
        if new_fp != self.config_fingerprint {
            // Walk semantics changed; rebuild from scratch.
            let mut walked = 0usize;
            let (closure, paths) = collect_lineage(journal, witnesses, config, &mut walked);
            self.closure = closure;
            self.paths = paths;
            self.journal_len_at_build = new_len;
            self.config_fingerprint = new_fp;
            self.walked_entries = walked;
            return true;
        }
        // Append-only: only witnesses not yet in the cached closure can
        // contribute new lineage.
        let new_witnesses: Vec<EntryHash> = witnesses
            .iter()
            .filter(|w| !self.closure.contains(*w))
            .copied()
            .collect();
        if new_witnesses.is_empty() {
            // Nothing new to walk. The journal may still have grown; the
            // cached closure remains valid and the growth is recorded so
            // the next same-length refresh reports no change.
            self.journal_len_at_build = new_len;
            self.walked_entries = 0;
            return false;
        }
        let mut walked = 0usize;
        let (new_closure, new_paths) =
            collect_lineage(journal, &new_witnesses, config, &mut walked);
        self.closure.extend(new_closure);
        self.paths.extend(new_paths);
        self.paths.sort();
        self.paths.dedup();
        self.journal_len_at_build = new_len;
        self.config_fingerprint = new_fp;
        self.walked_entries = walked;
        true
    }

    /// Borrow derivation paths.
    pub fn paths(&self) -> &[Vec<EntryHash>] {
        &self.paths
    }

    /// Borrow closure.
    pub fn closure(&self) -> &BTreeSet<EntryHash> {
        &self.closure
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_format::{ActorId, CanonicalValue, EntryKind, EntryPayload};
    use ledger_journal::Journal;

    fn test_config_bounded() -> SolverConfig {
        SolverConfig::default().with_horizon(64)
    }

    fn test_resolved() -> SolverEngine {
        SolverEngine::Builtin
    }

    #[test]
    fn build_then_refresh_no_growth_returns_false() {
        let mut journal = Journal::new();
        let send = journal
            .append(
                EntryKind::Send,
                ActorId(1),
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(ActorId(1), 0),
                    from: ActorId(1),
                    to: ActorId(1),
                    original_content: 0u64.to_le_bytes().to_vec(),
                }),
            )
            .unwrap();
        let witness = journal
            .append(
                EntryKind::Outcome,
                ActorId(1),
                [send],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: EntryHash([0x00; 32]),
                    value: CanonicalValue::Unsigned(1),
                }),
            )
            .unwrap();
        let config = test_config_bounded();
        let mut idx = LineageIndex::build(&journal, &[witness], &config, test_resolved());
        let first_closure = idx.closure.clone();
        let first_paths = idx.paths.clone();
        let changed = idx.refresh(&journal, &[witness], &config, test_resolved());
        assert!(!changed, "no growth must return false");
        assert_eq!(idx.closure, first_closure);
        assert_eq!(idx.paths, first_paths);
        assert_eq!(idx.journal_len_at_build, journal.len());
    }

    #[test]
    fn append_then_refresh_returns_true_and_closure_contains_new_faultable() {
        let mut journal = Journal::new();
        let send_a = journal
            .append(
                EntryKind::Send,
                ActorId(1),
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(ActorId(1), 0),
                    from: ActorId(1),
                    to: ActorId(1),
                    original_content: 1u64.to_le_bytes().to_vec(),
                }),
            )
            .unwrap();
        let witness_a = journal
            .append(
                EntryKind::Outcome,
                ActorId(1),
                [send_a],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: EntryHash([0x00; 32]),
                    value: CanonicalValue::Unsigned(0),
                }),
            )
            .unwrap();
        let config = test_config_bounded();
        let mut idx = LineageIndex::build(&journal, &[witness_a], &config, test_resolved());
        assert!(idx.closure.contains(&send_a));
        // Append new faultable and new witness that depends on it and old.
        let send_b = journal
            .append(
                EntryKind::Send,
                ActorId(2),
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(ActorId(2), 0),
                    from: ActorId(2),
                    to: ActorId(2),
                    original_content: 2u64.to_le_bytes().to_vec(),
                }),
            )
            .unwrap();
        let witness_b = journal
            .append(
                EntryKind::Outcome,
                ActorId(2),
                [send_b, witness_a],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: EntryHash([0x00; 32]),
                    value: CanonicalValue::Unsigned(1),
                }),
            )
            .unwrap();
        // Refresh with witnesses including new witness
        let changed = idx.refresh(&journal, &[witness_a, witness_b], &config, test_resolved());
        assert!(changed, "growth must return true");
        assert!(
            idx.closure.contains(&send_b),
            "closure must contain new faultable reachable from witnesses"
        );
        // also witness_b should be in closure
        assert!(idx.closure.contains(&witness_b));
    }

    #[test]
    fn refreshed_paths_equal_fresh_build() {
        let mut journal = Journal::new();
        let send_a = journal
            .append(
                EntryKind::Send,
                ActorId(1),
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(ActorId(1), 0),
                    from: ActorId(1),
                    to: ActorId(1),
                    original_content: 1u64.to_le_bytes().to_vec(),
                }),
            )
            .unwrap();
        let recv_a = journal
            .append(
                EntryKind::Recv,
                ActorId(1),
                [send_a],
                EntryPayload::Recv(ledger_format::RecvFrame {
                    message_id: ledger_format::MessageId::new(ActorId(1), 0),
                    from: ActorId(1),
                    to: ActorId(1),
                    observed_content: 0u64.to_le_bytes().to_vec(),
                }),
            )
            .unwrap();
        let witness = journal
            .append(
                EntryKind::Outcome,
                ActorId(1),
                [recv_a],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: EntryHash([0x00; 32]),
                    value: CanonicalValue::Unsigned(0),
                }),
            )
            .unwrap();
        let config = test_config_bounded();
        let mut idx = LineageIndex::build(&journal, &[witness], &config, test_resolved());
        // Grow journal with irrelevant and relevant entries
        let send_b = journal
            .append(
                EntryKind::Send,
                ActorId(2),
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(ActorId(2), 0),
                    from: ActorId(2),
                    to: ActorId(2),
                    original_content: 2u64.to_le_bytes().to_vec(),
                }),
            )
            .unwrap();
        // New witness branching
        let witness2 = journal
            .append(
                EntryKind::Outcome,
                ActorId(2),
                [send_b, recv_a],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: EntryHash([0x00; 32]),
                    value: CanonicalValue::Unsigned(1),
                }),
            )
            .unwrap();
        let witnesses = vec![witness, witness2];
        let changed = idx.refresh(&journal, &witnesses, &config, test_resolved());
        assert!(changed);
        let fresh = LineageIndex::build(&journal, &witnesses, &config, test_resolved());
        assert_eq!(
            idx.paths, fresh.paths,
            "refreshed paths must equal fresh build paths"
        );
        assert_eq!(
            idx.closure, fresh.closure,
            "refreshed closure must equal fresh build closure"
        );
    }

    #[test]
    fn fingerprint_mismatch_forces_rebuild() {
        let mut journal = Journal::new();
        let send = journal
            .append(
                EntryKind::Send,
                ActorId(1),
                [],
                EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(ActorId(1), 0),
                    from: ActorId(1),
                    to: ActorId(1),
                    original_content: 0u64.to_le_bytes().to_vec(),
                }),
            )
            .unwrap();
        let witness = journal
            .append(
                EntryKind::Outcome,
                ActorId(1),
                [send],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: EntryHash([0x00; 32]),
                    value: CanonicalValue::Unsigned(1),
                }),
            )
            .unwrap();
        let config_a = SolverConfig::default().with_horizon(1);
        let config_b = SolverConfig::default().with_horizon(64);
        let mut idx = LineageIndex::build(&journal, &[witness], &config_a, test_resolved());
        let fp_a = idx.config_fingerprint;
        let changed = idx.refresh(&journal, &[witness], &config_b, test_resolved());
        assert!(changed, "fingerprint mismatch must return true");
        assert_ne!(idx.config_fingerprint, fp_a);
        assert_eq!(
            idx.config_fingerprint,
            fingerprint(&config_b, test_resolved())
        );
        let fresh = LineageIndex::build(&journal, &[witness], &config_b, test_resolved());
        assert_eq!(idx.paths, fresh.paths);
        assert_eq!(idx.closure, fresh.closure);
        let no_change = idx.refresh(&journal, &[witness], &config_b, test_resolved());
        assert!(!no_change);
    }
}
