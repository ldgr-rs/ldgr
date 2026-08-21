#![deny(unsafe_code)]
//! Differential lineage maintenance: index caches witness causal closure and derivation paths.
//!
//! `LineageIndex` caches the witness causal closure and derivation paths for
//! one solver configuration. `build` computes a fresh index; `refresh`
//! recomputes the same full walk and replaces the cached state whenever the
//! journal length or configuration fingerprint moved, so a refreshed index
//! is always equal to a fresh build.

use std::collections::BTreeSet;

use ledger_format::Hash;
use ledger_journal::Journal;

use crate::solver::SolverConfig;
use crate::solver::SolverEngine;
use crate::solver::is_faultable;
use crate::solver_state::fingerprint;

/// Cached lineage for a witness set under a solver configuration.
#[derive(Debug, Clone)]
pub struct LineageIndex {
    /// Causal closure (all entries visited up to horizon) or faultable union.
    pub closure: BTreeSet<Hash>,
    /// Derivation paths as faultable hash sequences.
    pub paths: Vec<Vec<Hash>>,
    /// Journal length at last build/refresh.
    pub journal_len_at_build: usize,
    /// Fingerprint of the solver configuration at last build.
    pub config_fingerprint: Hash,
}

fn collect_bounded_hash(
    journal: &Journal,
    current: Hash,
    depth: usize,
    max_depth: usize,
    current_path: &mut Vec<Hash>,
    paths: &mut Vec<Vec<Hash>>,
    closure: &mut BTreeSet<Hash>,
) {
    if depth > max_depth {
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
            );
        }
    }
    if pushed {
        current_path.pop();
    }
}

fn collect_hash(
    journal: &Journal,
    current: Hash,
    current_path: &mut Vec<Hash>,
    paths: &mut Vec<Vec<Hash>>,
    closure: &mut BTreeSet<Hash>,
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
    witnesses: &[Hash],
    config: &SolverConfig,
) -> (BTreeSet<Hash>, Vec<Vec<Hash>>) {
    let mut closure = BTreeSet::new();
    let mut paths = Vec::new();
    for witness in witnesses {
        let mut current_path = Vec::new();
        if let Some(h) = config.max_horizon {
            collect_bounded_hash(
                journal,
                *witness,
                0,
                h,
                &mut current_path,
                &mut paths,
                &mut closure,
            );
        } else {
            collect_hash(
                journal,
                *witness,
                &mut current_path,
                &mut paths,
                &mut closure,
            );
        }
    }
    paths.sort();
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
        witnesses: &[Hash],
        config: &SolverConfig,
        resolved_engine: SolverEngine,
    ) -> Self {
        let (closure, paths) = collect_lineage(journal, witnesses, config);
        Self {
            closure,
            paths,
            journal_len_at_build: journal.len(),
            config_fingerprint: fingerprint(config, resolved_engine),
        }
    }

    /// Refresh the index after the journal may have grown.
    ///
    /// Returns `false` when nothing changed (same journal length and config
    /// fingerprint), in which case the cached state stays untouched.
    /// Otherwise recomputes the full witness walk and replaces the cached
    /// closure and paths, so a refreshed index equals a fresh
    /// [`LineageIndex::build`].
    pub fn refresh(
        &mut self,
        journal: &Journal,
        witnesses: &[Hash],
        config: &SolverConfig,
        resolved_engine: SolverEngine,
    ) -> bool {
        let new_fp = fingerprint(config, resolved_engine);
        let new_len = journal.len();
        if new_len == self.journal_len_at_build && new_fp == self.config_fingerprint {
            return false;
        }
        let (closure, paths) = collect_lineage(journal, witnesses, config);
        self.closure = closure;
        self.paths = paths;
        self.journal_len_at_build = new_len;
        self.config_fingerprint = new_fp;
        true
    }

    /// Borrow derivation paths.
    pub fn paths(&self) -> &[Vec<Hash>] {
        &self.paths
    }

    /// Borrow closure.
    pub fn closure(&self) -> &BTreeSet<Hash> {
        &self.closure
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_format::Payload;
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
            .append(ledger_format::EntryKind::Send, 1, [], Payload::Number(0))
            .unwrap();
        let witness = journal
            .append(
                ledger_format::EntryKind::Outcome,
                1,
                [send],
                Payload::Number(1),
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
                ledger_format::EntryKind::Send,
                1,
                [],
                Payload::Pair { left: 1, right: 1 },
            )
            .unwrap();
        let witness_a = journal
            .append(
                ledger_format::EntryKind::Outcome,
                1,
                [send_a],
                Payload::Number(0),
            )
            .unwrap();
        let config = test_config_bounded();
        let mut idx = LineageIndex::build(&journal, &[witness_a], &config, test_resolved());
        assert!(idx.closure.contains(&send_a));
        // Append new faultable and new witness that depends on it and old.
        let send_b = journal
            .append(
                ledger_format::EntryKind::Send,
                2,
                [],
                Payload::Pair { left: 2, right: 2 },
            )
            .unwrap();
        let witness_b = journal
            .append(
                ledger_format::EntryKind::Outcome,
                2,
                [send_b, witness_a],
                Payload::Number(1),
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
                ledger_format::EntryKind::Send,
                1,
                [],
                Payload::Pair { left: 1, right: 1 },
            )
            .unwrap();
        let recv_a = journal
            .append(
                ledger_format::EntryKind::Recv,
                1,
                [send_a],
                Payload::Number(0),
            )
            .unwrap();
        let witness = journal
            .append(
                ledger_format::EntryKind::Outcome,
                1,
                [recv_a],
                Payload::Number(0),
            )
            .unwrap();
        let config = test_config_bounded();
        let mut idx = LineageIndex::build(&journal, &[witness], &config, test_resolved());
        // Grow journal with irrelevant and relevant entries
        let send_b = journal
            .append(
                ledger_format::EntryKind::Send,
                2,
                [],
                Payload::Pair { left: 2, right: 2 },
            )
            .unwrap();
        // New witness branching
        let witness2 = journal
            .append(
                ledger_format::EntryKind::Outcome,
                2,
                [send_b, recv_a],
                Payload::Number(1),
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
            .append(ledger_format::EntryKind::Send, 1, [], Payload::Number(0))
            .unwrap();
        let witness = journal
            .append(
                ledger_format::EntryKind::Outcome,
                1,
                [send],
                Payload::Number(1),
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
