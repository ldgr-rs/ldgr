use ledger_format::EntryHash;
use ledger_journal::{Journal, JournalError};
use std::collections::HashMap;
use thiserror::Error;

/// Typed failure of a memoized replay. Every variant is a contract error:
/// the memo answers from its cache only when the prefix and batch invariants
/// hold, and fails loudly otherwise instead of returning a wrong journal.
#[derive(Debug, Error)]
pub enum MemoError {
    /// The caller's prefix root does not match the journal state before the
    /// batch; the supplied and rebuilt roots stay inspectable.
    #[error(
        "memoized replay prefix mismatch: caller supplied {:02x?}, journal state is {:02x?}",
        &caller.0[..8],
        &state.0[..8]
    )]
    PrefixMismatch {
        /// Prefix root supplied by the caller.
        caller: EntryHash,
        /// Prefix root rebuilt from the source journal.
        state: EntryHash,
    },
    /// The first batch entry is not present in the source journal.
    #[error("memoized replay batch entry is not in the source journal")]
    UnknownBatchEntry,
    /// The batch is not a contiguous run of the source append order.
    #[error("memoized replay batch must be a contiguous run of the source journal")]
    NonContiguousBatch,
    /// A prefix or batch subgraph could not be built from the source.
    #[error("memoized replay subgraph: {0}")]
    Subgraph(#[from] JournalError),
}

fn hash_batch(next_batch: &[EntryHash]) -> EntryHash {
    let mut hasher = blake3::Hasher::new();
    for id in next_batch {
        hasher.update(&id.0);
    }
    EntryHash(*hasher.finalize().as_bytes())
}

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
    cache: HashMap<(EntryHash, EntryHash), Journal>,
    /// Verified prefix roots by `(source_root, prefix_len)`, so repeat calls
    /// with the same prefix verify in O(1) instead of rebuilding it.
    prefix_roots: HashMap<(EntryHash, usize), EntryHash>,
    /// Source append order by source root, so batch location is O(1) per call.
    orders: HashMap<EntryHash, std::sync::Arc<Vec<EntryHash>>>,
    /// Batch content hashes by `(source_root, batch_start, batch_len)`, so a
    /// repeated batch is not re-hashed on every call.
    batch_hashes: HashMap<(EntryHash, usize, usize), EntryHash>,
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
        prefix_root_hash: EntryHash,
        next_batch: &[EntryHash],
        source: &Journal,
    ) -> Result<Journal, MemoError> {
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
        source_root: EntryHash,
        prefix_root_hash: EntryHash,
        next_batch: &[EntryHash],
        source: &Journal,
    ) -> Result<Journal, MemoError> {
        let order = self
            .orders
            .entry(source_root)
            .or_insert_with(|| {
                std::sync::Arc::new(source.entries().map(|entry| entry.id).collect::<Vec<_>>())
            })
            .clone();

        let first = if next_batch.is_empty() {
            if source_root != prefix_root_hash {
                return Err(MemoError::PrefixMismatch {
                    caller: prefix_root_hash,
                    state: source_root,
                });
            }
            return Ok(source.clone());
        } else {
            let Some(start) = order.iter().position(|id| *id == next_batch[0]) else {
                return Err(MemoError::UnknownBatchEntry);
            };
            let len = next_batch.len();
            let contiguous = start + len <= order.len() && order[start..start + len] == *next_batch;
            if !contiguous {
                return Err(MemoError::NonContiguousBatch);
            }
            start
        };

        let prefix_root = match self.prefix_roots.get(&(source_root, first)) {
            Some(&root) => root,
            None => {
                let root = source.subgraph(&order[..first])?.root_hash();
                self.prefix_roots.insert((source_root, first), root);
                root
            }
        };
        if prefix_root != prefix_root_hash {
            return Err(MemoError::PrefixMismatch {
                caller: prefix_root_hash,
                state: prefix_root,
            });
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
        let journal = source.subgraph(&order[..first + len])?;
        self.cache.insert(key, journal.clone());
        Ok(journal)
    }

    /// Cache hit/miss counters for the unit tests that assert memoization.
    #[cfg(test)]
    pub fn stats(&self) -> (usize, usize) {
        (self.hits, self.misses)
    }
}
