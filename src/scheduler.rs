//! Deterministic scheduling policies.

use crate::config::Policy;
use crate::seedtree::SeedTree;

/// Scheduler state for one run.
#[derive(Debug, Clone)]
pub struct Scheduler {
    policy: Policy,
    seed_tree: SeedTree,
    decisions: Vec<usize>,
    replay: Vec<usize>,
    pct_priorities: Vec<u64>,
}

impl Scheduler {
    /// Create a scheduler from a policy and seed.
    pub fn new(policy: Policy, seed_tree: SeedTree, replay: Vec<usize>) -> Self {
        Self {
            policy,
            seed_tree,
            decisions: Vec::new(),
            replay,
            pct_priorities: Vec::new(),
        }
    }

    /// Select an index from the ready task list.
    pub fn choose(&mut self, ready_len: usize, step: usize) -> usize {
        assert!(ready_len > 0, "scheduler requires a ready task");
        let choice = match self.policy {
            Policy::Random => {
                let value = self.seed_tree.draw_u64("sched", step as u64);
                value as usize % ready_len
            }
            Policy::Replay => self.replay.get(step).copied().unwrap_or(0) % ready_len,
            Policy::Pct { priority_changes } => {
                if self.pct_priorities.len() < ready_len {
                    self.pct_priorities.resize(ready_len, 0);
                    let changes = priority_changes.max(1).min(ready_len);
                    for change in 0..changes {
                        let index = self.seed_tree.draw_u64("pct", (step + change) as u64) as usize;
                        self.pct_priorities[index % ready_len] = (changes - change) as u64 + 1;
                    }
                }
                self.pct_priorities
                    .iter()
                    .take(ready_len)
                    .enumerate()
                    .max_by_key(|(_, priority)| *priority)
                    .map_or(0, |(index, _)| index)
            }
        };
        self.decisions.push(choice);
        choice
    }

    /// Return the recorded scheduler choices.
    pub fn decisions(&self) -> &[usize] {
        &self.decisions
    }
}
