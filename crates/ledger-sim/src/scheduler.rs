//! Deterministic scheduling policies with journal-novelty bandit exploration.

use crate::config::Policy;
use crate::seedtree::SeedTree;
use ledger_format::{ActorId, EntryKind};
use std::collections::{HashMap, HashSet};

/// One scheduler decision and the ready set it saw (DPOR trace unit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepTrace {
    /// Scheduler step index.
    pub step: usize,
    /// Snapshot of the ready task ids at this step.
    pub ready: Vec<usize>,
    /// Position into `ready` chosen by the policy.
    pub chosen: usize,
    /// Journal length after this step; the DPOR driver rebuilds per-step
    /// clocks from these boundaries.
    pub journal_len: usize,
}

/// Novelty bookkeeping keyed by task id, never by ready position.
#[derive(Debug, Clone, Default)]
pub struct NoveltyModel {
    // ledger-lint:allow:HashMap ledger-lint:allow:HashSet (membership and keyed
    // lookup only; iteration never escapes the scheduler)
    seen_transitions: HashSet<(EntryKind, EntryKind)>,
    seen_actor_pairs: HashSet<(ActorId, ActorId)>,
    seen_vc_branches: HashSet<u64>,
    last_event: Option<(ActorId, EntryKind)>,
    task_pull_counts: HashMap<usize, usize>,
    task_rewards: HashMap<usize, f64>,
    total_pulls: usize,
}

impl NoveltyModel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an emission for `task_id` and return its novelty reward.
    pub fn record_emission(
        &mut self,
        actor: ActorId,
        kind: EntryKind,
        task_id: usize,
        vc_signature: Option<u64>,
    ) -> f64 {
        let mut reward = 0.0;
        if let Some((last_actor, last_kind)) = self.last_event {
            if self.seen_transitions.insert((last_kind, kind)) {
                reward += 1.0;
            }
            if self.seen_actor_pairs.insert((last_actor, actor)) {
                reward += 0.5;
            }
            // Fault-witness adjacency: reward entries adjacent to a fault.
            if matches!(last_kind, EntryKind::Fault) {
                reward += 1.0;
            }
        }
        if matches!(kind, EntryKind::Fault) {
            reward += 1.0;
        }
        if let Some(signature) = vc_signature
            && self.seen_vc_branches.insert(signature)
        {
            reward += 1.0;
        }
        self.last_event = Some((actor, kind));

        *self.task_pull_counts.entry(task_id).or_insert(0) += 1;
        let r = self.task_rewards.entry(task_id).or_insert(0.0);
        *r = (*r * 0.9) + (reward * 0.1);
        self.total_pulls += 1;

        reward
    }

    /// Compute UCB1 score for a candidate task id.
    pub fn ucb1_score(&self, task_id: usize, exploration: f64) -> f64 {
        let pulls = self.task_pull_counts.get(&task_id).copied().unwrap_or(0);
        if pulls == 0 {
            return f64::INFINITY;
        }
        let avg_reward = self.task_rewards.get(&task_id).copied().unwrap_or(0.0);
        let bonus = exploration * ((self.total_pulls as f64).ln() / (pulls as f64)).sqrt();
        avg_reward + bonus
    }
}

/// Offset regions separating bandit tie-break, mix, and PCT draws so
/// `pct_mix == 0.0` leaves the tie-break stream untouched.
const MIX_OFFSET_BIT: u64 = 1 << 63;
/// Dedicated offset region for PCT-style perturbations.
const PCT_OFFSET_BIT: u64 = 1 << 62;

/// Strict-replay rejection: out-of-range, exhausted, or trailing leftover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayViolation {
    /// Decision value is outside the ready set.
    OutOfRange {
        step: usize,
        value: usize,
        ready_len: usize,
    },
    /// Replay stream exhausted before the run finished.
    Exhausted { step: usize, replay_len: usize },
    /// Replay is longer than the run, leftover decisions remain.
    Trailing { trailing: usize, steps: usize },
}

impl std::fmt::Display for ReplayViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutOfRange {
                step,
                value,
                ready_len,
            } => write!(
                f,
                "out of range at step {step}: value {value} >= ready_len {ready_len}"
            ),
            Self::Exhausted { step, replay_len } => write!(
                f,
                "replay exhausted at step {step}: replay_len {replay_len}"
            ),
            Self::Trailing { trailing, steps } => write!(
                f,
                "trailing replay: {trailing} leftover after {steps} steps"
            ),
        }
    }
}

impl std::error::Error for ReplayViolation {}

/// Scheduler state for one run.
#[derive(Debug, Clone)]
pub struct Scheduler {
    policy: Policy,
    seed_tree: SeedTree,
    decisions: Vec<usize>,
    replay: Vec<usize>,
    /// Policy used when `replay` is exhausted under `Policy::Replay`.
    fallback: Policy,
    /// Whether strict replay is enabled.
    strict: bool,
    /// Pending strict violation, taken by the executor before journaling.
    violation: Option<ReplayViolation>,
    /// Priority per task id for the PCT policy.
    ///
    /// The vector is keyed by stable task id, never by ready-list position:
    /// the ready list is reordered by `swap_remove`, so a position is not a
    /// stable identity. `None` marks a task whose priority is not yet drawn.
    pct_priorities: Vec<Option<u64>>,
    /// Priority re-assignments performed by the PCT policy (the budget spent).
    pct_preemptions: usize,
    /// Task id chosen by the PCT policy at the previous step.
    pct_last_chosen: Option<usize>,
    /// Re-prioritization counter feeding the PCT draw offsets.
    pct_generation: u64,
    novelty: NoveltyModel,
    trace: Vec<StepTrace>,
    /// Whether the DPOR driver consumes the step trace.
    ///
    /// Only the DPOR base run reads the trace; other policies never consult
    /// it, so recording the per-step ready snapshot is skipped for them.
    trace_enabled: bool,
}

impl Scheduler {
    /// Create a scheduler from a policy and seed.
    ///
    /// The replay-exhaustion fallback defaults to [`Policy::Random`].
    pub fn new(policy: Policy, seed_tree: SeedTree, replay: Vec<usize>) -> Self {
        Self::with_fallback(policy, seed_tree, replay, Policy::Random)
    }

    /// Create a scheduler with an explicit replay-exhaustion fallback policy.
    pub fn with_fallback(
        policy: Policy,
        seed_tree: SeedTree,
        replay: Vec<usize>,
        fallback: Policy,
    ) -> Self {
        Self {
            policy,
            seed_tree,
            decisions: Vec::new(),
            replay,
            fallback,
            strict: false,
            violation: None,
            pct_priorities: Vec::new(),
            pct_preemptions: 0,
            pct_last_chosen: None,
            pct_generation: 0,
            novelty: NoveltyModel::new(),
            trace: Vec::new(),
            trace_enabled: matches!(policy, Policy::Dpor),
        }
    }

    /// Create a scheduler with an explicit fallback and strict replay enabled.
    pub fn with_fallback_strict(
        policy: Policy,
        seed_tree: SeedTree,
        replay: Vec<usize>,
        fallback: Policy,
    ) -> Self {
        Self {
            policy,
            seed_tree,
            decisions: Vec::new(),
            replay,
            fallback,
            strict: true,
            violation: None,
            pct_priorities: Vec::new(),
            pct_preemptions: 0,
            pct_last_chosen: None,
            pct_generation: 0,
            novelty: NoveltyModel::new(),
            trace: Vec::new(),
            trace_enabled: matches!(policy, Policy::Dpor),
        }
    }

    /// Take a pending strict violation, if any.
    pub fn take_violation(&mut self) -> Option<ReplayViolation> {
        self.violation.take()
    }

    /// Check for trailing replay leftover; `steps` is decisions consumed.
    pub(crate) fn check_trailing(&mut self, steps: usize) -> Option<ReplayViolation> {
        if self.strict && self.replay.len() > steps {
            let trailing = self.replay.len() - steps;
            let violation = ReplayViolation::Trailing { trailing, steps };
            self.violation = Some(violation.clone());
            Some(violation)
        } else {
            None
        }
    }

    /// Select a position into `ready`; bandit scores by task id so
    /// `swap_remove` reordering never misattributes rewards.
    pub fn choose(&mut self, ready: &[usize], step: usize) -> usize {
        assert!(!ready.is_empty(), "scheduler requires a ready task");
        // Strict path rejects out-of-range and exhausted decisions without
        // normalizing or drawing fallback RNG, keeping the lenient path
        // byte-identical when not strict.
        if self.strict && matches!(self.policy, Policy::Replay) {
            match self.replay.get(step).copied() {
                Some(value) => {
                    if value >= ready.len() {
                        self.violation = Some(ReplayViolation::OutOfRange {
                            step,
                            value,
                            ready_len: ready.len(),
                        });
                        return 0;
                    }
                    let choice = value;
                    if self.trace_enabled {
                        self.trace.push(StepTrace {
                            step,
                            ready: ready.to_vec(),
                            chosen: choice,
                            journal_len: 0,
                        });
                    }
                    self.decisions.push(choice);
                    return choice;
                }
                None => {
                    self.violation = Some(ReplayViolation::Exhausted {
                        step,
                        replay_len: self.replay.len(),
                    });
                    return 0;
                }
            }
        }
        let policy = self.policy;
        let choice = match policy {
            Policy::Replay => match self.replay.get(step).copied() {
                Some(value) => value % ready.len(),
                None => self.select_fallback(ready, step, self.fallback),
            },
            _ => self.select_fallback(ready, step, policy),
        };
        if self.trace_enabled {
            self.trace.push(StepTrace {
                step,
                ready: ready.to_vec(),
                chosen: choice,
                journal_len: 0,
            });
        }
        self.decisions.push(choice);
        choice
    }

    /// Record the journal length after the latest step for the DPOR driver.
    pub(crate) fn note_step_journal_len(&mut self, journal_len: usize) {
        if let Some(last) = self.trace.last_mut() {
            last.journal_len = journal_len;
        }
    }

    /// Policy selection; `Replay` degrades to `Random` to avoid recursion.
    fn select_fallback(&mut self, ready: &[usize], step: usize, policy: Policy) -> usize {
        match policy {
            Policy::Random | Policy::Dpor | Policy::Replay => {
                let value = self.seed_tree.draw_u64("sched", step as u64);
                value as usize % ready.len()
            }
            Policy::Pct { priority_changes } => self.select_pct(ready, priority_changes),
            Policy::Bandit {
                exploration_constant,
                pct_mix,
            } => {
                let mix = self
                    .seed_tree
                    .draw_u64("bandit", step as u64 | MIX_OFFSET_BIT);
                let mix = (mix % 100) as f64 / 100.0;
                if mix < pct_mix.get() {
                    self.select_bandit_pct(ready, step)
                } else {
                    self.select_bandit(ready, step, exploration_constant)
                }
            }
        }
    }

    /// PCT selection with a bounded preemption budget; at most `k`
    /// preemptions per run, then a fixed-priority order.
    fn select_pct(&mut self, ready: &[usize], priority_changes: usize) -> usize {
        // Grow the priority table and draw a priority for any task seen for
        // the first time in the current generation.
        for task in ready {
            while self.pct_priorities.len() <= *task {
                self.pct_priorities.push(None);
            }
            if self.pct_priorities[*task].is_none() {
                let priority = self.pct_priority_draw(self.pct_generation, *task);
                self.pct_priorities[*task] = Some(priority);
            }
        }
        let mut best_index = self.pct_best(ready);
        let budget_left = priority_changes.saturating_sub(self.pct_preemptions) > 0;
        let preempts = budget_left
            && ready.len() > 1
            && self
                .pct_last_chosen
                .is_some_and(|previous| ready.contains(&previous));
        if preempts {
            self.pct_generation += 1;
            for task in ready {
                let priority = self.pct_priority_draw(self.pct_generation, *task);
                self.pct_priorities[*task] = Some(priority);
            }
            self.pct_preemptions += 1;
            best_index = self.pct_best(ready);
        }
        self.pct_last_chosen = Some(ready[best_index]);
        best_index
    }

    /// Return the ready position of the highest-priority task, ties to the
    /// lowest position.
    fn pct_best(&self, ready: &[usize]) -> usize {
        let mut best_index = 0;
        let mut best_priority = self.pct_priorities[ready[0]].unwrap_or(0);
        for (index, task) in ready.iter().enumerate().skip(1) {
            let priority = self.pct_priorities[*task].unwrap_or(0);
            if priority > best_priority {
                best_index = index;
                best_priority = priority;
            }
        }
        best_index
    }

    /// Draw one PCT priority; the offset keeps (`generation`, `task`) draws
    /// independent of `sched` and `bandit`.
    fn pct_priority_draw(&self, generation: u64, task: usize) -> u64 {
        let mut offset = generation ^ 0x9E37_79B9_7F4A_7C15;
        offset = offset
            .wrapping_mul(0x100_0000_01B3)
            .wrapping_add(task as u64);
        self.seed_tree.draw_u64("pct", offset)
    }

    /// Pure UCB1 bandit selection with the tie-break at offset `step`.
    fn select_bandit(&mut self, ready: &[usize], step: usize, exploration: f64) -> usize {
        let mut best_indices = Vec::new();
        let mut best_score = f64::NEG_INFINITY;

        for (idx, task_id) in ready.iter().enumerate() {
            let score = self.novelty.ucb1_score(*task_id, exploration);
            if (score.is_infinite()
                && best_score.is_infinite()
                && score.is_sign_positive() == best_score.is_sign_positive())
                || (!score.is_infinite()
                    && !best_score.is_infinite()
                    && (score - best_score).abs() < 1e-9)
            {
                best_indices.push(idx);
            } else if score > best_score {
                best_score = score;
                best_indices.clear();
                best_indices.push(idx);
            }
        }

        if best_indices.len() == 1 {
            best_indices[0]
        } else {
            let tie_breaker = self.seed_tree.draw_u64("bandit", step as u64) as usize;
            best_indices[tie_breaker % best_indices.len()]
        }
    }

    /// PCT perturbation with draws from a dedicated `bandit` region.
    fn select_bandit_pct(&mut self, ready: &[usize], step: usize) -> usize {
        let mut priorities = vec![0u64; ready.len()];
        let changes = (ready.len() / 2).max(1);
        for change in 0..changes {
            let offset = PCT_OFFSET_BIT | ((step as u64) << 10) | change as u64;
            let index = self.seed_tree.draw_u64("bandit", offset) as usize;
            priorities[index % ready.len()] = (changes - change) as u64 + 1;
        }
        priorities
            .iter()
            .enumerate()
            .max_by_key(|(_, priority)| *priority)
            .map_or(0, |(index, _)| index)
    }

    /// Forward an emission to the novelty model.
    pub fn on_entry_emitted(
        &mut self,
        actor: ActorId,
        kind: EntryKind,
        task_id: usize,
        vc_signature: Option<u64>,
    ) {
        self.novelty
            .record_emission(actor, kind, task_id, vc_signature);
    }

    pub fn decisions(&self) -> &[usize] {
        &self.decisions
    }

    pub fn trace(&self) -> &[StepTrace] {
        &self.trace
    }

    /// Whether novelty scores are consulted; lets the executor skip the
    /// per-entry VC signature hash when inactive.
    pub(crate) fn novelty_active(&self) -> bool {
        match self.policy {
            Policy::Bandit { .. } => true,
            Policy::Replay => matches!(self.fallback, Policy::Bandit { .. }),
            _ => false,
        }
    }

    /// Whether the DPOR driver consumes this run's step trace.
    pub(crate) fn trace_active(&self) -> bool {
        self.trace_enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RunConfig;
    use crate::runtime::Instruction;
    use crate::runtime::Simulation;

    fn mini_kv_programs() -> Vec<Vec<Instruction>> {
        vec![
            vec![
                Instruction::Send { to: 1, payload: 42 },
                Instruction::Send {
                    to: 2,
                    payload: 100,
                },
                Instruction::Done,
            ],
            vec![
                Instruction::Receive,
                Instruction::Send { to: 2, payload: 42 },
                Instruction::Done,
            ],
            vec![
                Instruction::Receive,
                Instruction::Outcome,
                Instruction::Done,
            ],
        ]
    }

    #[test]
    fn novelty_rewards_are_keyed_by_task_id() {
        let mut model = NoveltyModel::new();
        model.record_emission(ActorId(3), EntryKind::Send, 3, None);
        model.record_emission(ActorId(3), EntryKind::Recv, 3, None);
        model.record_emission(ActorId(9), EntryKind::FsWrite, 9, None);
        // Task 3 observed a novel (Send, Recv) transition, task 9 a novel one too.
        assert!(model.ucb1_score(3, 1.0) > 0.0);
        assert!(model.ucb1_score(9, 1.0) > 0.0);
        assert!(
            model.ucb1_score(4, 1.0).is_infinite(),
            "untried task is infinitely exploratory"
        );
    }

    #[test]
    fn bandit_attributes_rewards_to_task_ids_not_positions() {
        let mut scheduler = Scheduler::new(
            Policy::Bandit {
                exploration_constant: 0.0,
                pct_mix: crate::config::Probability::ZERO,
            },
            SeedTree::new(ledger_format::EntryHash([0; 32])),
            Vec::new(),
        );
        // Task 4 earns a novel-transition reward; task 7 only repeats a seen one.
        scheduler.on_entry_emitted(ActorId(4), EntryKind::Send, 4, None);
        scheduler.on_entry_emitted(ActorId(4), EntryKind::Send, 4, None);
        scheduler.on_entry_emitted(ActorId(7), EntryKind::Send, 7, None);
        scheduler.on_entry_emitted(ActorId(7), EntryKind::Send, 7, None);

        // Task 4 sits at position 1, not position 4. Scoring must follow the
        // task id; a position-keyed scorer would pick untried position 0.
        let ready = vec![7, 4];
        assert_eq!(
            scheduler.choose(&ready, 0),
            1,
            "high-reward task 4 must win by task identity"
        );
    }

    #[test]
    fn bandit_same_seed_produces_same_decision_sequence() {
        let config = RunConfig::builder()
            .seed(ledger_format::EntryHash([11; 32]))
            .policy(Policy::Bandit {
                exploration_constant: 1.414,
                pct_mix: crate::config::Probability::new(0.1).unwrap(),
            })
            .max_steps(256)
            .build();
        let programs = mini_kv_programs();
        let first = Simulation::new(config.clone(), programs.clone())
            .run()
            .unwrap();
        let second = Simulation::new(config, programs).run().unwrap();
        assert_eq!(first.decisions, second.decisions);
        assert_eq!(first.journal.root_hash(), second.journal.root_hash());
    }

    #[test]
    fn bandit_rewards_vc_branch_novelty() {
        let mut model = NoveltyModel::new();
        // Seed the (Send, Send) transition and the (3, 3) actor pair first.
        model.record_emission(ActorId(3), EntryKind::Send, 3, Some(100));
        model.record_emission(ActorId(3), EntryKind::Send, 3, Some(100));
        // A fresh vector-clock signature on the same (actor, kind) earns exactly
        // the VC-branch reward: the transition and pair are already seen.
        let fresh_branch = model.record_emission(ActorId(3), EntryKind::Send, 3, Some(200));
        assert_eq!(fresh_branch, 1.0, "a new VC branch rewards +1.0");
        let repeated = model.record_emission(ActorId(3), EntryKind::Send, 3, Some(200));
        assert_eq!(repeated, 0.0, "a repeated VC branch earns nothing");
    }

    #[test]
    fn bandit_rewards_fault_adjacency() {
        let mut model = NoveltyModel::new();
        // Seed the (Send, Send) transition and (3, 3) actor pair.
        model.record_emission(ActorId(3), EntryKind::Send, 3, None);
        model.record_emission(ActorId(3), EntryKind::Send, 3, None);
        // A Fault-kind entry earns the transition reward plus the fault reward.
        let fault = model.record_emission(ActorId(3), EntryKind::Fault, 3, None);
        assert_eq!(fault, 2.0, "a fault entry earns transition + fault novelty");
        // The emission after a fault earns adjacency novelty on top of its own
        // new (Fault, Send) transition.
        let adjacent = model.record_emission(ActorId(3), EntryKind::Send, 3, None);
        assert_eq!(
            adjacent, 2.0,
            "an emission adjacent to a fault earns adjacency novelty"
        );
    }

    #[test]
    fn bandit_pct_mix_zero_is_unchanged() {
        let seed = SeedTree::new(ledger_format::EntryHash([13; 32]));
        let mut mixed = Scheduler::new(
            Policy::Bandit {
                exploration_constant: 1.414,
                pct_mix: crate::config::Probability::ZERO,
            },
            seed.clone(),
            Vec::new(),
        );
        // Control scheduler driven by the pure UCB1 path only.
        let mut control = Scheduler::new(Policy::Random, seed, Vec::new());
        let ready = vec![0, 1, 2, 3];
        for step in 0..16 {
            for task in &ready {
                mixed.on_entry_emitted(ActorId(*task as u32), EntryKind::Send, *task, None);
                control.on_entry_emitted(ActorId(*task as u32), EntryKind::Send, *task, None);
            }
            let expected = control.select_bandit(&ready, step, 1.414);
            assert_eq!(
                mixed.choose(&ready, step),
                expected,
                "pct_mix 0.0 must never perturb the pure UCB1 decision stream"
            );
        }
    }

    /// Pinned golden for the pure-Bandit decision stream.
    ///
    /// Freezes the UCB1 draw sequence for a fixed seed and ready shape so any
    /// accidental change to the bandit stream offsets or tie-breaks is caught.
    #[test]
    fn bandit_pure_stream_golden_is_stable() {
        let seed = SeedTree::new(ledger_format::EntryHash([7; 32]));
        let mut sched = Scheduler::new(
            Policy::Bandit {
                exploration_constant: 1.414,
                pct_mix: crate::config::Probability::ZERO,
            },
            seed,
            Vec::new(),
        );
        let ready = vec![0, 1, 2, 3];
        let mut decisions = Vec::new();
        for step in 0..20usize {
            for task in &ready {
                sched.on_entry_emitted(ActorId(*task as u32), EntryKind::Send, *task, None);
            }
            decisions.push(sched.choose(&ready, step));
        }
        assert_eq!(
            decisions,
            vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
            "the pure-Bandit decision stream must match the pinned golden"
        );
    }

    /// With a preemption budget of 1 the PCT policy re-assigns priorities at
    /// the first preemption, so its decision sequence diverges from the
    /// no-preemption run (budget 0), and the same seed replays identically.
    #[test]
    fn pct_reprioritizes_on_preemption_and_is_deterministic() {
        let ready = vec![0, 1, 2];
        let decisions = |budget: usize| -> Vec<usize> {
            let mut scheduler = Scheduler::new(
                Policy::Pct {
                    priority_changes: budget,
                },
                SeedTree::new(ledger_format::EntryHash([7; 32])),
                Vec::new(),
            );
            (0..16).map(|step| scheduler.choose(&ready, step)).collect()
        };
        let no_preemption = decisions(0);
        assert!(
            no_preemption.windows(2).all(|pair| pair[0] == pair[1]),
            "budget 0 must never re-prioritize: the max-priority task wins every step"
        );
        let one_preemption = decisions(1);
        assert_ne!(
            one_preemption, no_preemption,
            "budget 1 must re-prioritize on the first preemption"
        );
        assert_eq!(
            decisions(1),
            one_preemption,
            "the same seed must reproduce the same decision sequence"
        );
    }
}
