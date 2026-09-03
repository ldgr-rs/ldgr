//! Hierarchical deterministic seed tree using ChaCha20 and BLAKE3 KDF.

use ledger_format::EntryHash;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// A deterministic seed tree that derives independent RNG streams.
#[derive(Debug, Clone)]
pub struct SeedTree {
    root_seed: EntryHash,
}

impl SeedTree {
    pub const fn new(root_seed: EntryHash) -> Self {
        Self { root_seed }
    }

    /// Derive an independent stream key for a labeled subsystem.
    ///
    /// Implements `stream_key(label) = BLAKE3_kdf(root_seed, label)`.
    pub fn derive(&self, label: &str) -> EntryHash {
        EntryHash(blake3::derive_key(label, &self.root_seed.0))
    }

    pub fn rng(&self, label: &str) -> ChaCha20Rng {
        ChaCha20Rng::from_seed(self.derive(label).0)
    }

    /// Build the deterministic per-generator input stream for a PBT generator.
    ///
    /// The stream key is `gen/<generator>`, so every PBT generator gets its
    /// own independent, reproducible stream. Used by the explorer PBT bridge.
    pub fn gen_stream(&self, generator: &str) -> ChaCha20Rng {
        self.rng(&format!("gen/{generator}"))
    }

    /// Draw a deterministic unsigned integer from a labeled stream at an offset.
    ///
    /// This keyed-mode helper is for scheduler draws. The general stream
    /// construction is [`Self::derive`] feeding a ChaCha20 RNG ([`Self::rng`]).
    pub fn draw_u64(&self, label: &str, offset: u64) -> u64 {
        let mut hasher = blake3::Hasher::new_keyed(&self.root_seed.0);
        hasher.update(label.as_bytes());
        hasher.update(&offset.to_le_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest.as_bytes()[0..8]);
        u64::from_le_bytes(bytes)
    }
}
