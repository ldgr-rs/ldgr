//! Deterministic, independently-seeded random streams.

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

/// A deterministic random stream derived from one campaign seed.
#[derive(Debug, Clone)]
pub struct SeedTree {
    root: [u8; 32],
}

impl SeedTree {
    /// Create a seed tree from a root seed.
    pub const fn new(root: [u8; 32]) -> Self {
        Self { root }
    }

    /// Derive an independent ChaCha20 stream for a label.
    pub fn stream(&self, label: &str) -> ChaCha20Rng {
        let mut material = Vec::with_capacity(self.root.len() + label.len());
        material.extend_from_slice(&self.root);
        material.extend_from_slice(label.as_bytes());
        let key = blake3::derive_key("ldgr seed tree v1", &material);
        ChaCha20Rng::from_seed(key)
    }

    /// Draw a deterministic `u64` from a named stream.
    pub fn draw_u64(&self, label: &str, draw: u64) -> u64 {
        let mut stream = self.stream(label);
        for _ in 0..draw {
            let _ = stream.next_u64();
        }
        stream.next_u64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_independent_and_reproducible() {
        let tree = SeedTree::new([7; 32]);
        assert_eq!(tree.draw_u64("sched", 0), tree.draw_u64("sched", 0));
        assert_ne!(tree.draw_u64("sched", 0), tree.draw_u64("net", 0));
    }
}
