//! PBT-in-sim input axis: per-generator samplers and input-parameterized workloads.
//!
//! Each generator draws from its own `gen/<generator>` seed-tree stream.
//! The same name plus seed always reproduces the same input sequence, and
//! distinct generator names are mutually independent.

use crate::oracle::HistoryOperation;
use crate::search::Workload;
use ledger_format::{GenId, Hash};
use ledger_sim::{Instruction, RunResult, SeedTree};
use rand_chacha::ChaCha20Rng;
use rand_core::Rng;

/// Deterministic per-generator input sampler over a `gen/<name>` stream.
pub struct PbtBridge {
    name: String,
    rng: ChaCha20Rng,
}

/// Upper bound (exclusive) for input-axis samples.
///
/// A small bounded domain keeps specific target values (for example 42)
/// reachable by search and minimizer while staying deterministic.
pub const INPUT_SAMPLE_RANGE: u64 = 100;

impl PbtBridge {
    pub fn new(name: &str, seed: Hash) -> Self {
        let tree = SeedTree::new(seed);
        Self {
            name: name.to_string(),
            rng: tree.gen_stream(name),
        }
    }

    pub fn sample_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    /// Draw a deterministic `u64` uniformly in `lo .. hi`.
    ///
    /// Requires `hi > lo`; the modulo is biased but deterministic, which is
    /// the property the PBT input axis needs.
    pub fn sample_range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.sample_u64() % (hi - lo)
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Derive a stable generator id from a generator name.
///
/// The first 8 bytes of the BLAKE3 hash of the name become the `GenId`, so a
/// named generator maps to one id across every run.
pub fn gen_id(generator: &str) -> GenId {
    let digest = blake3::hash(generator.as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_le_bytes(bytes)
}

/// Workload holding programs with injected `Input` steps.
///
/// Built by [`Workload::with_inputs`] implementations; the concrete input
/// values are already baked into the programs.
pub struct InputsWorkload {
    programs: Vec<Vec<Instruction>>,
}

impl InputsWorkload {
    pub fn new(programs: Vec<Vec<Instruction>>) -> Self {
        Self { programs }
    }
}

impl Workload for InputsWorkload {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        self.programs.clone()
    }

    fn history(&self, _run: &RunResult) -> Vec<HistoryOperation> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_name_and_seed_reproduces_identical_sequence() {
        let mut left = PbtBridge::new("arith", [1; 32]);
        let mut right = PbtBridge::new("arith", [1; 32]);
        for _ in 0..16 {
            assert_eq!(left.sample_u64(), right.sample_u64());
        }
    }

    #[test]
    fn distinct_generator_names_draw_independent_sequences() {
        let mut left = PbtBridge::new("alpha", [1; 32]);
        let mut right = PbtBridge::new("beta", [1; 32]);
        let left_seq = (0..16).map(|_| left.sample_u64()).collect::<Vec<_>>();
        let right_seq = (0..16).map(|_| right.sample_u64()).collect::<Vec<_>>();
        assert_ne!(left_seq, right_seq, "independent streams must differ");
    }

    #[test]
    fn sample_range_stays_within_bounds() {
        let mut bridge = PbtBridge::new("range", [2; 32]);
        for _ in 0..256 {
            let value = bridge.sample_range(10, 20);
            assert!((10..20).contains(&value));
        }
    }

    #[test]
    fn gen_id_is_stable_per_name() {
        assert_eq!(gen_id("arith"), gen_id("arith"));
        assert_ne!(gen_id("arith"), gen_id("arithx"));
    }
}
