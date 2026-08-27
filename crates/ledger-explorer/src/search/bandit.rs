use super::input_axis::draw_inputs;
use super::{
    describe_variant, draw_fault_subset, draw_swarm, CampaignReport, Finding, QuadMutation,
    SearchError, Workload, SWARM_CRASH_CEILING,
};
use crate::memo::{hash_inputs, memo_key, CampaignMemo, MemoEntry};
use crate::oracle::Oracle;
use ledger_format::Hash;
use ledger_sim::{Policy, RunConfig, SeedTree, SimFault, Simulation, SwarmConfig};
use std::collections::{HashMap, HashSet};

/// UCB1 bandit over quadruple variants.
///
/// The variant hash is the arm and findings feed rewards. An untried
/// candidate scores infinity, so every arm is probed once before
/// exploitation. Ties break to the smaller hash, keeping picks
/// deterministic.
#[derive(Debug, Clone)]
pub struct QuadBandit {
    pulls: HashMap<u64, usize>,
    rewards: HashMap<u64, f64>,
    total: usize,
    candidates: Vec<u64>,
}

impl Default for QuadBandit {
    fn default() -> Self {
        Self::new()
    }
}

impl QuadBandit {
    pub fn new() -> Self {
        Self {
            pulls: HashMap::new(),
            rewards: HashMap::new(),
            total: 0,
            candidates: Vec::new(),
        }
    }

    /// Add a candidate arm. Registration never counts as a pull, so a
    /// registered-but-unpulled arm keeps the infinite untried score.
    pub fn register(&mut self, variant: u64) {
        if !self.candidates.contains(&variant) {
            self.candidates.push(variant);
        }
    }

    /// Register a candidate by its quadruple parts.
    ///
    /// The canonical arm hash is computed once at registration and reused on
    /// every pick, so a campaign never re-hashes the variant.
    pub fn register_variant(
        &mut self,
        policy: &Policy,
        swarm: &SwarmConfig,
        faults: &[SimFault],
    ) -> u64 {
        let arm = Self::variant_hash(policy, swarm, faults);
        self.register(arm);
        arm
    }

    /// Canonical content hash of one quadruple variant.
    ///
    /// The hash covers the policy tag and fields, the full swarm config, and
    /// every fault in canonical order (see
    /// [`crate::memo::canonical_variant_bytes`], the single byte-layout
    /// source shared with the campaign memo), so equal variants always hash
    /// equal.
    pub fn variant_hash(policy: &Policy, swarm: &SwarmConfig, faults: &[SimFault]) -> u64 {
        let digest = blake3::hash(&crate::memo::canonical_variant_bytes(policy, swarm, faults));
        let mut out = [0u8; 8];
        out.copy_from_slice(&digest.as_bytes()[..8]);
        u64::from_le_bytes(out)
    }

    /// UCB1 pick over the registered candidates.
    ///
    /// Untried candidates score infinity. Otherwise the score is the average
    /// reward plus the UCB1 exploration bonus. Ties break to the smaller arm.
    pub fn arm(&self, exploration: f64) -> u64 {
        let mut best: Option<(f64, u64)> = None;
        for &variant in &self.candidates {
            let pulls = self.pulls.get(&variant).copied().unwrap_or(0);
            let score = if pulls == 0 {
                f64::INFINITY
            } else {
                let average = self.rewards.get(&variant).copied().unwrap_or(0.0) / pulls as f64;
                average + exploration * ((self.total as f64).ln() / pulls as f64).sqrt()
            };
            let better = best.is_none_or(|(best_score, best_variant)| {
                score > best_score || (score == best_score && variant < best_variant)
            });
            if better {
                best = Some((score, variant));
            }
        }
        best.map_or(0, |(_, variant)| variant)
    }

    /// Record one pull of an arm and its reward (1.0 on a finding).
    pub fn reward(&mut self, variant: u64, reward: f64) {
        let pulls = self.pulls.entry(variant).or_insert(0);
        *pulls += 1;
        let total_reward = self.rewards.entry(variant).or_insert(0.0);
        *total_reward += reward;
        self.total += 1;
    }
}

#[derive(Debug, Clone)]
struct QuadVariant {
    policy: Policy,
    swarm: SwarmConfig,
    faults: Vec<SimFault>,
}

const BANDIT_SWARM_SAMPLES: usize = 4;
const BANDIT_FAULT_SAMPLES: usize = 4;

/// Enumerate the deterministic candidate quadruple variants for a campaign.
///
/// The enumeration crosses every policy with the drawn swarm samples and the
/// drawn fault subsets. The bandit derives each variant's canonical arm hash
/// once at registration.
fn enumerate_variants(
    base: &RunConfig,
    mutation: &QuadMutation,
) -> Result<Vec<QuadVariant>, SearchError> {
    let policies: Vec<Policy> = if mutation.policies.is_empty() {
        vec![base.policy()]
    } else {
        mutation.policies.clone()
    };
    let swarm_samples: Vec<SwarmConfig> = if mutation.use_swarm {
        (0..BANDIT_SWARM_SAMPLES)
            .map(|index| {
                draw_swarm(
                    base.seed(),
                    &format!("bandit-swarm/{index}"),
                    mutation.swarm_budget,
                    SWARM_CRASH_CEILING,
                )
                .map_err(SearchError::from)
            })
            .collect::<Result<Vec<_>, SearchError>>()?
    } else {
        vec![(*base.swarm()).clone()]
    };
    let fault_samples: Vec<Vec<SimFault>> = if mutation.fault_library.is_empty() {
        vec![Vec::new()]
    } else {
        (0..BANDIT_FAULT_SAMPLES)
            .map(|index| {
                let mut rng = SeedTree::new(base.seed()).rng(&format!("bandit-faults/{index}"));
                draw_fault_subset(
                    &mutation.fault_library,
                    mutation.max_faults_per_run,
                    &mut rng,
                )
            })
            .collect()
    };
    let mut variants = Vec::new();
    for policy in &policies {
        for swarm in &swarm_samples {
            for faults in &fault_samples {
                variants.push(QuadVariant {
                    policy: *policy,
                    swarm: swarm.clone(),
                    faults: faults.clone(),
                });
            }
        }
    }
    Ok(variants)
}

/// Run a UCB1 bandit campaign over the mutated quadruple variants.
///
/// The candidate variants are enumerated once from the seed stream; each
/// carries a canonical arm hash computed at registration. Every attempt pulls
/// the arm selected by UCB1, runs that quadruple variant (with a fresh PBT
/// input when the input axis is set), and rewards the arm with 1.0 when the
/// oracle fires. The per-attempt run seed still varies, so every arm runs
/// under fresh schedules.
pub fn run_bandit_campaign<W: Workload, O: Oracle>(
    workload: &W,
    oracle: &O,
    base: RunConfig,
    mutation: &QuadMutation,
    exploration: f64,
    attempts: usize,
) -> Result<CampaignReport, SearchError> {
    let candidates = enumerate_variants(&base, mutation)?;
    let mut bandit = QuadBandit::new();
    let mut variant_of: HashMap<u64, QuadVariant> = HashMap::new();
    for variant in candidates {
        let arm = bandit.register_variant(&variant.policy, &variant.swarm, &variant.faults);
        variant_of.insert(arm, variant);
    }

    let mut distinct_roots: HashSet<Hash> = HashSet::new();
    let mut findings: Vec<Finding> = Vec::new();
    let mut variants: Vec<String> = Vec::new();
    // LazyMOP / AgentReplay memo: per-campaign local dedup over
    // `BLAKE3(variant_hash || input_hash || replay)`. Duplicate bandit arms
    // hit the cache and skip re-execution, saving budget.
    let mut memo = CampaignMemo::new();

    for attempt in 0..attempts {
        let arm = bandit.arm(exploration);
        let variant = variant_of
            .get(&arm)
            .ok_or(SearchError::UnknownArm { arm })?;

        let (programs, input_label, input_hash) = match &mutation.input_generator {
            Some(generator) => {
                let label = format!("bandit-input/{attempt}");
                let attempt_seed = SeedTree::new(base.seed()).derive(&label);
                let inputs = draw_inputs(generator, attempt_seed, mutation.input_energy.as_ref())?;
                let hash = hash_inputs(&inputs);
                (
                    workload.with_inputs(&inputs).programs(),
                    Some(label),
                    Some(hash),
                )
            }
            None => (workload.programs(), None, None),
        };

        let key = memo_key(
            &variant.policy,
            &variant.swarm,
            &variant.faults,
            input_hash,
            None,
        );
        if let Some(entry) = memo.get(&key) {
            distinct_roots.insert(entry.journal_root);
            // Duplicate arm+input: reuse cached root without simulation.
            // Give a conservative 0 reward for the duplicate pull so UCB1
            // keeps exploring without budget cost. A cache that also stored
            // the violated flag could replay the exact reward.
            bandit.reward(arm, 0.0);
            let mut seed = base.seed();
            seed[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());
            let config = base
                .clone()
                .with_seed(seed)
                .with_policy(variant.policy)
                .with_swarm(variant.swarm.clone())
                .with_fault_schedule(variant.faults.clone());
            variants.push(describe_variant(&config, attempt, input_label.as_deref()));
            continue;
        }

        let mut seed = base.seed();
        seed[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());
        let config = base
            .clone()
            .with_seed(seed)
            .with_policy(variant.policy)
            .with_swarm(variant.swarm.clone())
            .with_fault_schedule(variant.faults.clone());

        let run = Simulation::new(config.clone(), programs).run()?;

        let root = run.journal.root_hash();
        let distinct = !distinct_roots.contains(&root);
        distinct_roots.insert(root);
        memo.insert(
            key,
            MemoEntry {
                run_config_hash: key,
                journal_root: root,
                distinct,
            },
        );
        let verdict = super::effective_verdict(&run, oracle.check(&run));
        let found = verdict.violated;
        if found {
            findings.push(Finding {
                seed: config.seed(),
                run,
                verdict,
            });
        }
        bandit.reward(arm, if found { 1.0 } else { 0.0 });
        variants.push(describe_variant(&config, attempt, input_label.as_deref()));
    }

    Ok(CampaignReport {
        runs_executed: attempts,
        distinct_roots: distinct_roots.len(),
        findings,
        variants,
        monitors: Vec::new(),
        memo_hits: 0,
    })
}
