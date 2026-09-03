//! PBT input axis: per-generator samplers over `gen/<name>` streams. Same
//! name plus seed reproduces; names are independent.

use crate::oracle::HistoryOperation;
use crate::search::Workload;
use ledger_format::EntryHash;
use ledger_sim::{Instruction, RunResult, SeedTree};
use rand_chacha::ChaCha20Rng;
use rand_core::Rng;

/// Deterministic per-generator input sampler over a `gen/<name>` stream.
pub struct PbtBridge {
    rng: ChaCha20Rng,
}

/// Typed validation failure for energy-distribution sampling.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum PbtError {
    /// The sample range must be positive.
    #[error("sample range must be positive")]
    EmptyRange,
    /// The power exponent must be finite and positive.
    #[error("invalid exponent {exponent}: must be finite and > 0")]
    InvalidExponent { exponent: f64 },
}

/// Bounded sample domain keeping targets reachable and deterministic.
pub const INPUT_SAMPLE_RANGE: u64 = 100;

/// Input energy sampling distribution.
#[derive(Debug, Clone, PartialEq)]
pub enum EnergyDistribution {
    Uniform,
    Power { exponent: f64 },
}

impl PbtBridge {
    pub fn new(name: &str, seed: EntryHash) -> Self {
        let tree = SeedTree::new(seed);
        Self {
            rng: tree.gen_stream(name),
        }
    }

    pub fn sample_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    // Single modulo helper for uniform draws; biased but deterministic.
    fn uniform_mod(&mut self, modulus: u64) -> u64 {
        self.sample_u64() % modulus
    }

    /// Uniform `lo .. hi`. Modulo is biased but deterministic.
    pub fn sample_range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.uniform_mod(hi - lo)
    }

    /// Sample `0 .. range` under `dist`. Errors on empty range or bad exponent.
    pub fn sample_energy(
        &mut self,
        range: u64,
        dist: &EnergyDistribution,
    ) -> Result<u64, PbtError> {
        if range == 0 {
            return Err(PbtError::EmptyRange);
        }
        match dist {
            EnergyDistribution::Uniform => Ok(self.uniform_mod(range)),
            EnergyDistribution::Power { exponent } => {
                if !exponent.is_finite() || *exponent <= 0.0 {
                    return Err(PbtError::InvalidExponent {
                        exponent: *exponent,
                    });
                }
                let v = self.sample_u64();
                let u = v as f64 / u64::MAX as f64;
                let powered = u.powf(*exponent);
                let raw = (range as f64 * powered) as u64;
                let clamped = if raw >= range { range - 1 } else { raw };
                Ok(clamped)
            }
        }
    }
}

/// Derive a stable generator id from a generator name.
///
/// The first 8 bytes of the BLAKE3 hash of the name become the generator id, so a
/// named generator maps to one id across every run.
pub fn gen_id(generator: &str) -> u64 {
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
        let mut left = PbtBridge::new("arith", EntryHash([1; 32]));
        let mut right = PbtBridge::new("arith", EntryHash([1; 32]));
        for _ in 0..16 {
            assert_eq!(left.sample_u64(), right.sample_u64());
        }
    }

    #[test]
    fn distinct_generator_names_draw_independent_sequences() {
        let mut left = PbtBridge::new("alpha", EntryHash([1; 32]));
        let mut right = PbtBridge::new("beta", EntryHash([1; 32]));
        let left_seq = (0..16).map(|_| left.sample_u64()).collect::<Vec<_>>();
        let right_seq = (0..16).map(|_| right.sample_u64()).collect::<Vec<_>>();
        assert_ne!(left_seq, right_seq, "independent streams must differ");
    }

    #[test]
    fn sample_range_stays_within_bounds() {
        let mut bridge = PbtBridge::new("range", EntryHash([2; 32]));
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

    #[test]
    fn uniform_equals_sample_range_sequence() {
        let mut via_range = PbtBridge::new("uniform-eq", EntryHash([7; 32]));
        let mut via_energy = PbtBridge::new("uniform-eq", EntryHash([7; 32]));
        for _ in 0..256 {
            let a = via_range.sample_range(0, INPUT_SAMPLE_RANGE);
            let b = via_energy
                .sample_energy(INPUT_SAMPLE_RANGE, &EnergyDistribution::Uniform)
                .expect("uniform must succeed");
            assert_eq!(a, b);
        }
    }

    #[test]
    fn power_exponent_2_biases_low() {
        let mut bridge = PbtBridge::new("power-low", EntryHash([11; 32]));
        let dist = EnergyDistribution::Power { exponent: 2.0 };
        let n = 1000;
        let mut sum: u64 = 0;
        for _ in 0..n {
            let v = bridge
                .sample_energy(INPUT_SAMPLE_RANGE, &dist)
                .expect("power 2 must succeed");
            assert!(v < INPUT_SAMPLE_RANGE);
            sum += v;
        }
        let mean = sum as f64 / n as f64;
        assert!(
            mean < INPUT_SAMPLE_RANGE as f64 / 3.0,
            "mean {mean} must be < range/3 for exponent 2"
        );
    }

    #[test]
    fn power_exponent_half_biases_high() {
        let mut bridge = PbtBridge::new("power-high", EntryHash([13; 32]));
        let dist = EnergyDistribution::Power { exponent: 0.5 };
        let n = 1000;
        let mut sum: u64 = 0;
        for _ in 0..n {
            let v = bridge
                .sample_energy(INPUT_SAMPLE_RANGE, &dist)
                .expect("power 0.5 must succeed");
            assert!(v < INPUT_SAMPLE_RANGE);
            sum += v;
        }
        let mean = sum as f64 / n as f64;
        assert!(
            mean > 2.0 * INPUT_SAMPLE_RANGE as f64 / 3.0,
            "mean {mean} must be > 2*range/3 for exponent 0.5"
        );
    }

    #[test]
    fn invalid_exponent_returns_error() {
        let mut bridge = PbtBridge::new("invalid-exp", EntryHash([17; 32]));
        assert!(
            bridge
                .sample_energy(
                    INPUT_SAMPLE_RANGE,
                    &EnergyDistribution::Power { exponent: 0.0 }
                )
                .is_err()
        );
        assert!(
            bridge
                .sample_energy(
                    INPUT_SAMPLE_RANGE,
                    &EnergyDistribution::Power { exponent: -1.0 }
                )
                .is_err()
        );
        assert!(
            bridge
                .sample_energy(
                    INPUT_SAMPLE_RANGE,
                    &EnergyDistribution::Power { exponent: f64::NAN }
                )
                .is_err()
        );
        assert!(
            bridge
                .sample_energy(
                    INPUT_SAMPLE_RANGE,
                    &EnergyDistribution::Power {
                        exponent: f64::INFINITY
                    }
                )
                .is_err()
        );
        assert!(
            bridge
                .sample_energy(
                    INPUT_SAMPLE_RANGE,
                    &EnergyDistribution::Power {
                        exponent: f64::NEG_INFINITY
                    }
                )
                .is_err()
        );
    }

    #[test]
    fn sample_energy_is_deterministic() {
        let mut left = PbtBridge::new("energy-det", EntryHash([19; 32]));
        let mut right = PbtBridge::new("energy-det", EntryHash([19; 32]));
        let dist = EnergyDistribution::Power { exponent: 2.0 };
        for _ in 0..64 {
            let a = left.sample_energy(INPUT_SAMPLE_RANGE, &dist).unwrap();
            let b = right.sample_energy(INPUT_SAMPLE_RANGE, &dist).unwrap();
            assert_eq!(a, b);
        }
        // Uniform determinism already covered via uniform_equals test, but double-check.
        let mut left_u = PbtBridge::new("energy-det-u", EntryHash([23; 32]));
        let mut right_u = PbtBridge::new("energy-det-u", EntryHash([23; 32]));
        for _ in 0..64 {
            let a = left_u
                .sample_energy(INPUT_SAMPLE_RANGE, &EnergyDistribution::Uniform)
                .unwrap();
            let b = right_u
                .sample_energy(INPUT_SAMPLE_RANGE, &EnergyDistribution::Uniform)
                .unwrap();
            assert_eq!(a, b);
        }
    }
}
