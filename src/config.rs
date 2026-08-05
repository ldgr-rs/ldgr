//! Run configuration shared by simulation and Explorer code.

use crate::seedtree::SeedTree;

/// Scheduling policy for one deterministic run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Select a ready task from the seeded stream.
    Random,
    /// Use a bounded probabilistic concurrency schedule.
    Pct { priority_changes: usize },
    /// Follow a previously recorded task decision sequence.
    Replay,
}

/// Immutable configuration for one simulation.
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// Root seed for all independent streams.
    pub seed: [u8; 32],
    /// Scheduling policy.
    pub policy: Policy,
    /// Maximum number of executed instructions.
    pub max_steps: usize,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            seed: [0; 32],
            policy: Policy::Random,
            max_steps: 10_000,
        }
    }
}

impl RunConfig {
    /// Return the seed tree for this run.
    pub fn seed_tree(&self) -> SeedTree {
        SeedTree::new(self.seed)
    }
}
