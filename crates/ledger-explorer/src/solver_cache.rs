#![deny(unsafe_code)]

//! Content-addressed clause cache for the LDFI solver.
//!
//! The cache is keyed by a BLAKE3 digest over the causal closure hash,
//! the horizon bound, and the oracle predicate version. All operations
//! are deterministic and do not use time or ambient threads. A per-solver
//! instance cache is the primary store; a global [`OnceLock`] store is
//! provided for cross-solver memoization.

use crate::solver::SolverConfig;
use ledger_format::Hash;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Engine discriminator folded into content-addressed cache keys.
///
/// The builtin pure-Rust engines (hitting set, MaxSAT branch-and-bound) tag
/// with [`BUILTIN`]. The CaDiCaL-backed MaxSAT tags with [`CADICAL`], so a
/// clause or hypothesis entry derived by one engine never satisfies another.
/// Without the `solver-cadical` feature no caller produces [`CADICAL`] keys.
pub mod engine_tag {
    pub const BUILTIN: u8 = 0;
    pub const CADICAL: u8 = 1;
}

/// A weighted clause over fault events.
///
/// Each clause is a disjunction over fault events; the weight is the cost of
/// breaking that clause. The hitting-set formulation becomes a weighted MaxSAT
/// where soft clauses correspond to derivation paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightedClause {
    pub literals: Vec<Hash>,
    pub weight: u64,
}

impl WeightedClause {
    pub fn new(literals: Vec<Hash>, weight: u64) -> Self {
        Self { literals, weight }
    }

    pub fn is_empty(&self) -> bool {
        self.literals.is_empty()
    }
}

/// Deterministic content-addressed cache for derived clauses.
///
/// The key is `BLAKE3(closure_hash || max_horizon || oracle_version ||
/// input_class || max_faults || engine_tag || run_config_hash)`.
/// The value is the exact clause set that was derived for that closure
/// so repeat solves hit the cache without re-walking the journal.
#[derive(Debug, Clone, Default)]
pub struct ClauseCache {
    inner: HashMap<Hash, Vec<WeightedClause>>,
}

impl ClauseCache {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    pub fn get(&self, key: &Hash) -> Option<&Vec<WeightedClause>> {
        self.inner.get(key)
    }

    pub fn get_cloned(&self, key: &Hash) -> Option<Vec<WeightedClause>> {
        self.inner.get(key).cloned()
    }

    pub fn insert(&mut self, key: Hash, clauses: Vec<WeightedClause>) {
        self.inner.insert(key, clauses);
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn clear(&mut self) {
        self.inner.clear();
    }

    pub fn contains(&self, key: &Hash) -> bool {
        self.inner.contains_key(key)
    }

    /// Compute the closure hash over sorted fault hypothesis ids.
    ///
    /// Deterministic: sorts the input, hashes with BLAKE3.
    pub fn closure_hash(sorted_ids: &[Hash]) -> Hash {
        let mut ids = sorted_ids.to_vec();
        ids.sort();
        let mut hasher = blake3::Hasher::new();
        for id in &ids {
            hasher.update(id);
        }
        *hasher.finalize().as_bytes()
    }

    /// Hash a clause set deterministically.
    ///
    /// Sorts literals within each clause and sorts clauses by their
    /// literal bytes so the hash is stable under permutation.
    pub fn clauses_hash(clauses: &[WeightedClause]) -> Hash {
        let mut hasher = blake3::Hasher::new();
        let mut sorted = clauses.to_vec();
        for clause in &mut sorted {
            let mut lits = clause.literals.clone();
            lits.sort();
            clause.literals = lits;
        }
        sorted.sort_by(|a, b| a.literals.cmp(&b.literals).then(a.weight.cmp(&b.weight)));
        for clause in &sorted {
            hasher.update(&clause.weight.to_le_bytes());
            for lit in &clause.literals {
                hasher.update(lit);
            }
            hasher.update(&[0xff]);
        }
        *hasher.finalize().as_bytes()
    }

    /// Compute the content-addressed key for a solver invocation.
    ///
    /// `closure_hash` is `BLAKE3(sorted event ids in the causal closure)`.
    /// `engine_tag` separates entries per solver engine
    /// ([`engine_tag::BUILTIN`] / [`engine_tag::CADICAL`]); an entry derived
    /// by one engine must never satisfy another.
    /// `config` carries the remaining cache dimensions: horizon,
    /// oracle version, input class, max faults, run-config hash, and the
    /// support-provider version and digest. Entries derived under different
    /// values of any dimension must never satisfy each other, and each
    /// presence byte keeps `None` apart from `Some(0)`.
    pub fn compute_key(closure_hash: Hash, engine_tag: u8, config: &SolverConfig) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&closure_hash);
        hasher.update(&[0xfe]);
        if let Some(h) = config.max_horizon {
            hasher.update(&(h as u64).to_le_bytes());
        } else {
            hasher.update(&[0xff, 0xff]);
        }
        hasher.update(&[0xfd]);
        if let Some(version) = config.oracle_version {
            hasher.update(&[0x01]);
            hasher.update(&version.to_le_bytes());
        } else {
            hasher.update(&[0x00]);
        }
        hasher.update(&[0xfc]);
        if let Some(class) = config.input_class {
            hasher.update(&[0x01]);
            hasher.update(&class.to_le_bytes());
        } else {
            hasher.update(&[0x00]);
        }
        hasher.update(&[0xfb]);
        if let Some(faults) = config.max_faults {
            hasher.update(&[0x01]);
            hasher.update(&(faults as u64).to_le_bytes());
        } else {
            hasher.update(&[0x00]);
        }
        hasher.update(&[0xfa]);
        hasher.update(&[engine_tag]);
        hasher.update(&[0xf9]);
        if let Some(hash) = config.run_config_hash {
            hasher.update(&[0x01]);
            hasher.update(&hash);
        } else {
            hasher.update(&[0x00]);
        }
        hasher.update(&[0xf8]);
        if let Some(version) = config.support_version {
            hasher.update(&[0x01]);
            hasher.update(&version.to_le_bytes());
        } else {
            hasher.update(&[0x00]);
        }
        hasher.update(&[0xf7]);
        if let Some(digest) = config.support_digest {
            hasher.update(&[0x01]);
            hasher.update(&digest);
        } else {
            hasher.update(&[0x00]);
        }
        *hasher.finalize().as_bytes()
    }

    /// Iterate over cached entries.
    pub fn iter(&self) -> impl Iterator<Item = (&Hash, &Vec<WeightedClause>)> {
        self.inner.iter()
    }
}

/// Global content-addressed clause cache.
///
/// Backed by `OnceLock<Mutex<ClauseCache>>` so it is deterministic and
/// does not spawn threads. Callers that need cross-solver sharing lock
/// the mutex, clone the hit, and release.
pub fn global_cache() -> &'static Mutex<ClauseCache> {
    static GLOBAL: OnceLock<Mutex<ClauseCache>> = OnceLock::new();
    GLOBAL.get_or_init(|| Mutex::new(ClauseCache::new()))
}

/// Insert into the global cache and return whether it was a new key.
pub fn global_insert(key: Hash, clauses: Vec<WeightedClause>) -> bool {
    let mut cache = global_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let is_new = !cache.contains(&key);
    cache.insert(key, clauses);
    is_new
}

/// Get a cloned entry from the global cache.
pub fn global_get(key: &Hash) -> Option<Vec<WeightedClause>> {
    let cache = global_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.get_cloned(key)
}

/// Number of entries in the global cache.
pub fn global_len() -> usize {
    let cache = global_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.len()
}

/// Clear the global cache.
pub fn global_clear() {
    let mut cache = global_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_format::Hash;

    fn hash_of(byte: u8) -> Hash {
        [byte; 32]
    }

    #[test]
    fn closure_hash_deterministic_under_permutation() {
        let a = hash_of(1);
        let b = hash_of(2);
        let c = hash_of(3);
        let h1 = ClauseCache::closure_hash(&[c, a, b]);
        let h2 = ClauseCache::closure_hash(&[a, b, c]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_key_differs_on_horizon() {
        let closure = hash_of(7);
        let k1 = ClauseCache::compute_key(
            closure,
            engine_tag::BUILTIN,
            &SolverConfig::default().with_horizon(10),
        );
        let k2 = ClauseCache::compute_key(
            closure,
            engine_tag::BUILTIN,
            &SolverConfig::default().with_horizon(100),
        );
        let k3 = ClauseCache::compute_key(closure, engine_tag::BUILTIN, &SolverConfig::default());
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
    }

    #[test]
    fn compute_key_differs_on_oracle_version() {
        let closure = hash_of(9);
        let k1 = ClauseCache::compute_key(
            closure,
            engine_tag::BUILTIN,
            &SolverConfig::default().with_oracle_version(1),
        );
        let k2 = ClauseCache::compute_key(
            closure,
            engine_tag::BUILTIN,
            &SolverConfig::default().with_oracle_version(2),
        );
        assert_ne!(k1, k2);
    }

    #[test]
    fn compute_key_separates_oracle_none_from_some_zero() {
        // An absent oracle version and a pinned version 0 are different
        // configurations: the presence byte must keep them apart, mirroring
        // the state fingerprint's None-vs-Some(0) behavior.
        let closure = hash_of(9);
        let none = ClauseCache::compute_key(closure, engine_tag::BUILTIN, &SolverConfig::default());
        let zero = ClauseCache::compute_key(
            closure,
            engine_tag::BUILTIN,
            &SolverConfig::default().with_oracle_version(0),
        );
        assert_ne!(none, zero);
        let again = ClauseCache::compute_key(
            closure,
            engine_tag::BUILTIN,
            &SolverConfig::default().with_oracle_version(0),
        );
        assert_eq!(zero, again);
    }

    #[test]
    fn compute_key_differs_on_support_version() {
        // A provider version change must isolate the cache: same closure,
        // horizon, oracle, and run config, different support version.
        let closure = hash_of(11);
        let digest = hash_of(3);
        let v1 = ClauseCache::compute_key(
            closure,
            engine_tag::BUILTIN,
            &SolverConfig::default()
                .with_support_version(1)
                .with_support_digest(digest),
        );
        let v2 = ClauseCache::compute_key(
            closure,
            engine_tag::BUILTIN,
            &SolverConfig::default()
                .with_support_version(2)
                .with_support_digest(digest),
        );
        assert_ne!(v1, v2);
    }

    #[test]
    fn compute_key_differs_on_support_digest() {
        // A provider model change must isolate the cache even when the
        // version is unchanged: different digest, all else equal.
        let closure = hash_of(13);
        let a = ClauseCache::compute_key(
            closure,
            engine_tag::BUILTIN,
            &SolverConfig::default()
                .with_support_version(1)
                .with_support_digest(hash_of(1)),
        );
        let b = ClauseCache::compute_key(
            closure,
            engine_tag::BUILTIN,
            &SolverConfig::default()
                .with_support_version(1)
                .with_support_digest(hash_of(2)),
        );
        assert_ne!(a, b);
    }

    #[test]
    fn compute_key_differs_on_input_class() {
        let closure = hash_of(7);
        let k_none = ClauseCache::compute_key(
            closure,
            engine_tag::BUILTIN,
            &SolverConfig::default().with_horizon(64),
        );
        let k_a = ClauseCache::compute_key(
            closure,
            engine_tag::BUILTIN,
            &SolverConfig::default().with_horizon(64).with_input_class(1),
        );
        let k_b = ClauseCache::compute_key(
            closure,
            engine_tag::BUILTIN,
            &SolverConfig::default().with_horizon(64).with_input_class(2),
        );
        assert_ne!(k_none, k_a);
        assert_ne!(k_a, k_b);
    }

    #[test]
    fn compute_key_same_when_input_class_none() {
        let closure = hash_of(7);
        let k1 = ClauseCache::compute_key(
            closure,
            engine_tag::BUILTIN,
            &SolverConfig::default().with_horizon(64),
        );
        let k2 = ClauseCache::compute_key(
            closure,
            engine_tag::BUILTIN,
            &SolverConfig::default().with_horizon(64),
        );
        assert_eq!(k1, k2);
    }

    #[test]
    fn compute_key_differs_per_engine_tag() {
        // A clause set derived by the CaDiCaL engine must never satisfy the
        // builtin engine: the tag separates their cache namespaces.
        let closure = hash_of(7);
        let builtin = ClauseCache::compute_key(
            closure,
            engine_tag::BUILTIN,
            &SolverConfig::default().with_horizon(64),
        );
        let cadical = ClauseCache::compute_key(
            closure,
            engine_tag::CADICAL,
            &SolverConfig::default().with_horizon(64),
        );
        assert_ne!(builtin, cadical);
    }

    #[test]
    fn compute_key_differs_on_max_faults() {
        let closure = hash_of(7);
        let none = ClauseCache::compute_key(
            closure,
            engine_tag::BUILTIN,
            &SolverConfig::default().with_horizon(64),
        );
        let bounded = ClauseCache::compute_key(
            closure,
            engine_tag::BUILTIN,
            &SolverConfig::default().with_horizon(64).with_max_faults(2),
        );
        let bounded_more = ClauseCache::compute_key(
            closure,
            engine_tag::BUILTIN,
            &SolverConfig::default().with_horizon(64).with_max_faults(3),
        );
        assert_ne!(none, bounded);
        assert_ne!(bounded, bounded_more);
    }

    #[test]
    fn compute_key_differs_on_run_config_hash() {
        // Entries derived under different run configs must never satisfy each
        // other, and an entry without a run-config hash is its own namespace.
        let closure = hash_of(7);
        let none = ClauseCache::compute_key(
            closure,
            engine_tag::BUILTIN,
            &SolverConfig::default().with_horizon(64),
        );
        let run_a = ClauseCache::compute_key(
            closure,
            engine_tag::BUILTIN,
            &SolverConfig::default()
                .with_horizon(64)
                .with_run_config_hash(hash_of(1)),
        );
        let run_b = ClauseCache::compute_key(
            closure,
            engine_tag::BUILTIN,
            &SolverConfig::default()
                .with_horizon(64)
                .with_run_config_hash(hash_of(2)),
        );
        assert_ne!(none, run_a);
        assert_ne!(run_a, run_b);
    }

    #[test]
    fn cache_insert_and_get() {
        let mut cache = ClauseCache::new();
        let key = hash_of(42);
        let clause = WeightedClause::new(vec![hash_of(1)], 5);
        cache.insert(key, vec![clause.clone()]);
        assert_eq!(cache.get(&key), Some(&vec![clause]));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn global_cache_is_singleton() {
        let mut guard = global_cache()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.clear();
        let key = hash_of(11);
        let clause = WeightedClause::new(vec![hash_of(2)], 7);
        guard.insert(key, vec![clause.clone()]);
        assert_eq!(guard.get_cloned(&key), Some(vec![clause]));
        assert_eq!(guard.len(), 1);
        guard.clear();
        assert_eq!(guard.len(), 0);
    }

    #[test]
    fn clauses_hash_stable_under_permutation() {
        let a = WeightedClause::new(vec![hash_of(2), hash_of(1)], 5);
        let b = WeightedClause::new(vec![hash_of(1), hash_of(2)], 5);
        assert_eq!(
            ClauseCache::clauses_hash(&[a]),
            ClauseCache::clauses_hash(&[b])
        );
    }
}
