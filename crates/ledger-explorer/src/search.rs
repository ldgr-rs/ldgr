//! Seeded campaign search, multi-policy exploration, and replay verification.

use crate::diagnosis::first_divergence;
use crate::ldfi::{hypothesis_to_schedule, solve_ldfi};
use crate::oracle::{Oracle, Verdict};
use crate::pbt::{INPUT_SAMPLE_RANGE, InputsWorkload, PbtBridge};
use ledger_format::Hash;
use ledger_sim::{
    FaultInjection, Instruction, Policy, RunConfig, RunResult, SeedTree, Simulation, SwarmConfig,
};
use rand_core::Rng;
use std::collections::{HashMap, HashSet};

fn fault_injection_target(injection: &FaultInjection) -> Option<Hash> {
    match injection {
        FaultInjection::Drop(id)
        | FaultInjection::Delay { send: id, .. }
        | FaultInjection::Crash(id)
        | FaultInjection::Corrupt { write: id, .. }
        | FaultInjection::CrashState { write: id, .. } => Some(*id),
        FaultInjection::Partition { .. } => None,
    }
}

/// A workload that can be executed by the deterministic simulator.
pub trait Workload {
    fn programs(&self) -> Vec<Vec<Instruction>>;

    fn history(&self, run: &RunResult) -> Vec<crate::oracle::HistoryOperation>;

    /// Rebuild this workload with a concrete input sequence (PBT input axis).
    ///
    /// The default treats the workload as unparameterized: inputs are ignored
    /// and the base programs are returned unchanged, so existing workloads
    /// compile without change.
    fn with_inputs(&self, _inputs: &[u64]) -> Box<dyn Workload> {
        Box::new(InputsWorkload::new(self.programs()))
    }

    /// Extract a linearizability history from a run.
    ///
    /// The default collapses each operation to its witness entry: the invoke
    /// and response events coincide. Workloads whose operations span several
    /// journal entries override this to supply real invoke/response intervals.
    fn lin_history(&self, run: &RunResult) -> Vec<crate::oracle::LinOperation> {
        self.history(run)
            .into_iter()
            .map(|operation| {
                let witness = operation.witness();
                crate::oracle::LinOperation {
                    invoke: witness,
                    response: witness,
                    operation,
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    /// Root seed that found the violation.
    pub seed: Hash,
    pub run: RunResult,
    pub verdict: Verdict,
}

#[derive(Debug, Clone)]
pub struct CampaignReport {
    pub runs_executed: usize,
    /// Number of distinct journal root hashes encountered.
    pub distinct_roots: usize,
    pub findings: Vec<Finding>,
    /// Per-run quadruple variant descriptions, one per attempt in order.
    ///
    /// Each entry names the policy, swarm knobs, and fault schedule used for
    /// that attempt, so callers can inspect which axes mutated.
    pub variants: Vec<String>,
}

/// Run a seed-varying exploration campaign, collecting findings and coverage.
pub fn run_campaign<W: Workload, O: Oracle>(
    workload: &W,
    oracle: &O,
    base: RunConfig,
    attempts: usize,
) -> Result<CampaignReport, String> {
    let mut distinct_roots: HashSet<Hash> = HashSet::new();
    let mut findings: Vec<Finding> = Vec::new();

    for attempt in 0..attempts {
        let mut config = base.clone();
        config.seed[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());
        let run = Simulation::new(config.clone(), workload.programs())
            .run()
            .map_err(|error| format!("simulation failed: {error:?}"))?;

        distinct_roots.insert(run.journal.root_hash());
        let verdict = oracle.check(&run);
        if verdict.violated {
            findings.push(Finding {
                seed: config.seed,
                run,
                verdict,
            });
        }
    }

    Ok(CampaignReport {
        runs_executed: attempts,
        distinct_roots: distinct_roots.len(),
        findings,
        variants: Vec::new(),
    })
}

/// Search deterministic seeds sequentially until the first oracle violation.
///
/// Returns the finding, if any, and the number of runs consumed. The total is
/// always exactly `budget`, so a campaign can compute its remaining budget.
fn find_first_violation<W: Workload, O: Oracle>(
    workload: &W,
    oracle: &O,
    base: &RunConfig,
    budget: usize,
) -> Result<(Option<Finding>, usize), String> {
    for attempt in 0..budget {
        let mut config = base.clone();
        config.seed[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());
        let run = Simulation::new(config.clone(), workload.programs())
            .run()
            .map_err(|error| format!("simulation failed: {error:?}"))?;
        let verdict = oracle.check(&run);
        if verdict.violated {
            return Ok((
                Some(Finding {
                    seed: config.seed,
                    run,
                    verdict,
                }),
                attempt + 1,
            ));
        }
    }
    Ok((None, budget))
}

pub fn search<W: Workload, O: Oracle>(
    workload: &W,
    oracle: &O,
    base: RunConfig,
    attempts: usize,
) -> Result<Option<Finding>, String> {
    find_first_violation(workload, oracle, &base, attempts).map(|(finding, _)| finding)
}

const INPUT_AXIS_SAMPLE: usize = 16;

/// Search the input axis: fix the schedule seed and vary the generated input.
///
/// Each attempt samples a fresh input sequence from the generator's
/// `gen/<name>` stream and rebuilds the workload with those values. The
/// schedule seed stays fixed, so a finding pins `(input, schedule)` jointly.
///
/// The workload must parameterize its inputs by overriding
/// [`Workload::with_inputs`]. Workloads that keep the default identity
/// implementation run identically on every attempt; the search then either
/// finds a violation on the first attempt or never.
pub fn search_input<W, O>(
    workload_template: &W,
    oracle: &O,
    base: RunConfig,
    generator: &str,
    attempts: usize,
) -> Result<Option<Finding>, String>
where
    W: Workload,
    O: Oracle,
{
    for attempt in 0..attempts {
        let attempt_seed = SeedTree::new(base.seed).derive(&format!("input-axis/{attempt}"));
        let mut bridge = PbtBridge::new(generator, attempt_seed);
        let mut inputs = Vec::with_capacity(INPUT_AXIS_SAMPLE);
        for _ in 0..INPUT_AXIS_SAMPLE {
            inputs.push(bridge.sample_range(0, INPUT_SAMPLE_RANGE));
        }
        let workload = workload_template.with_inputs(&inputs);
        let run = Simulation::new(base.clone(), workload.programs())
            .run()
            .map_err(|error| format!("simulation failed: {error:?}"))?;
        let verdict = oracle.check(&run);
        if verdict.violated {
            return Ok(Some(Finding {
                seed: attempt_seed,
                run,
                verdict,
            }));
        }
    }
    Ok(None)
}

/// Mutation options for one campaign attempt over the search quadruple
/// `(input, schedule_policy, fault_schedule, swarm_knobs)`.
#[derive(Debug, Clone, Default)]
pub struct QuadMutation {
    /// Policies to cycle among (empty = keep base policy).
    pub policies: Vec<Policy>,
    pub use_swarm: bool,
    /// `max_delay_ticks` bound for swarm draws.
    pub swarm_budget: u64,
    /// Pool of faults; empty = no fault axis.
    pub fault_library: Vec<FaultInjection>,
    pub max_faults_per_run: usize,
    /// PBT input generator for the input axis; `None` disables the axis.
    ///
    /// When set, every attempt draws a fresh input sequence from the
    /// generator's seed-tree `gen/<generator>` stream and rebuilds the
    /// workload with those values, mutating all four quadruple axes together.
    pub input_generator: Option<String>,
}

/// Shared fault-class budget for the swarm axis across every campaign type.
///
/// This is a budget, not a semantic guarantee: once this many distinct
/// post-crash state classes have been applied in one run, further sampled
/// crashes are skipped. Matches [`SwarmConfig::default`].
const SWARM_FAULT_CLASSES_PER_RUN: usize = 2;

/// Shared crash-probability ceiling for the swarm axis across every campaign
/// type, so quad and swarm-only campaigns draw comparable distributions.
const SWARM_CRASH_CEILING: f64 = 0.1;

/// Max-delay budget for the swarm-only campaign, so its swarm draws match the
/// quad campaign's default budget.
const SWARM_CAMPAIGN_MAX_DELAY_BUDGET: u64 = 8;

fn draw_swarm(seed: Hash, label: &str, budget: u64, crash_ceiling: f64) -> SwarmConfig {
    let mut rng = SeedTree::new(seed).rng(label);
    let scale = |value: u64| value as f64 / u64::MAX as f64;
    SwarmConfig {
        drop_probability: scale(rng.next_u64()),
        delay_probability: scale(rng.next_u64()),
        max_delay_ticks: rng.next_u64() % (budget + 1),
        crash_probability: scale(rng.next_u64()) * crash_ceiling,
        fault_classes_per_run: SWARM_FAULT_CLASSES_PER_RUN,
    }
}

fn draw_fault_subset(
    library: &[FaultInjection],
    max_per_run: usize,
    rng: &mut impl rand_core::Rng,
) -> Vec<FaultInjection> {
    let cap = max_per_run.min(library.len());
    let count = (rng.next_u64() as usize) % (cap + 1);
    let mut chosen = Vec::with_capacity(count);
    let mut used: HashSet<usize> = HashSet::new();
    while chosen.len() < count {
        let index = (rng.next_u64() as usize) % library.len();
        if used.insert(index) {
            chosen.push(library[index].clone());
        }
    }
    chosen
}

/// Draw a fresh PBT input sequence for one campaign attempt.
///
/// The attempt seed is derived per attempt, so each attempt samples an
/// independent, reproducible `gen/<generator>` input sequence.
fn draw_inputs(generator: &str, attempt_seed: Hash) -> Vec<u64> {
    let mut bridge = PbtBridge::new(generator, attempt_seed);
    let mut inputs = Vec::with_capacity(INPUT_AXIS_SAMPLE);
    for _ in 0..INPUT_AXIS_SAMPLE {
        inputs.push(bridge.sample_range(0, INPUT_SAMPLE_RANGE));
    }
    inputs
}

fn describe_variant(config: &RunConfig, attempt: usize, input_label: Option<&str>) -> String {
    let swarm = &config.swarm;
    let faults = config
        .fault_schedule
        .iter()
        .map(|fault| format!("{fault:?}"))
        .collect::<Vec<_>>()
        .join(",");
    let input = input_label
        .map(|label| format!(" input={label}"))
        .unwrap_or_default();
    format!(
        "attempt={attempt} policy={:?} swarm=drop={:.6} delay={:.6} max_delay={} crash={:.6} classes={} faults=[{faults}]{input}",
        config.policy,
        swarm.drop_probability,
        swarm.delay_probability,
        swarm.max_delay_ticks,
        swarm.crash_probability,
        swarm.fault_classes_per_run,
    )
}

/// Run a campaign that mutates all four axes of the search quadruple.
///
/// Per attempt the policy is drawn from `mutation.policies`, the swarm knobs
/// are drawn from the seeded stream when `use_swarm`, a fault subset is drawn
/// from `mutation.fault_library` when it is non-empty, and a fresh PBT input
/// is drawn from `mutation.input_generator` when it is set. The base seed
/// still varies across attempts for determinism.
pub fn run_campaign_quad<W: Workload, O: Oracle>(
    workload: &W,
    oracle: &O,
    base: RunConfig,
    mutation: &QuadMutation,
    attempts: usize,
) -> Result<CampaignReport, String> {
    let mut distinct_roots: HashSet<Hash> = HashSet::new();
    let mut findings: Vec<Finding> = Vec::new();
    let mut variants: Vec<String> = Vec::new();
    let base_seed = base.seed;

    for attempt in 0..attempts {
        let mut config = base.clone();
        config.seed[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());

        if mutation.policies.is_empty() {
            config.policy = base.policy;
        } else {
            let digest = SeedTree::new(base_seed).derive(&format!("quad-policy/{attempt}"));
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&digest[..8]);
            let draw = u64::from_le_bytes(bytes) as usize;
            config.policy = mutation.policies[draw % mutation.policies.len()];
        }

        if mutation.use_swarm {
            config.swarm = draw_swarm(
                base_seed,
                &format!("quad-swarm/{attempt}"),
                mutation.swarm_budget,
                SWARM_CRASH_CEILING,
            );
        }

        if !mutation.fault_library.is_empty() {
            let mut rng = SeedTree::new(base_seed).rng(&format!("quad-faults/{attempt}"));
            config.fault_schedule = draw_fault_subset(
                &mutation.fault_library,
                mutation.max_faults_per_run,
                &mut rng,
            );
        }

        let (programs, input_label) = match &mutation.input_generator {
            Some(generator) => {
                let label = format!("quad-input/{attempt}");
                let attempt_seed = SeedTree::new(base_seed).derive(&label);
                let inputs = draw_inputs(generator, attempt_seed);
                (workload.with_inputs(&inputs).programs(), Some(label))
            }
            None => (workload.programs(), None),
        };

        let run = Simulation::new(config.clone(), programs)
            .run()
            .map_err(|error| format!("simulation failed: {error:?}"))?;

        distinct_roots.insert(run.journal.root_hash());
        let verdict = oracle.check(&run);
        if verdict.violated {
            findings.push(Finding {
                seed: config.seed,
                run,
                verdict,
            });
        }
        variants.push(describe_variant(&config, attempt, input_label.as_deref()));
    }

    Ok(CampaignReport {
        runs_executed: attempts,
        distinct_roots: distinct_roots.len(),
        findings,
        variants,
    })
}

/// Run a campaign that mutates only the swarm axis of the quadruple.
///
/// Per attempt the swarm knobs are drawn from the seeded stream with the same
/// distribution as the quad campaign's swarm axis: drop and delay
/// probabilities in `0.0 .. 1.0`, `max_delay_ticks` in `0 ..= 8`, crash
/// probability in `0.0 .. 0.1`, and the shared fault-class budget. The seed
/// varies as in [`run_campaign`].
pub fn run_swarm_campaign<W: Workload, O: Oracle>(
    workload: &W,
    oracle: &O,
    base: RunConfig,
    attempts: usize,
) -> Result<CampaignReport, String> {
    let mut distinct_roots: HashSet<Hash> = HashSet::new();
    let mut findings: Vec<Finding> = Vec::new();
    let mut variants: Vec<String> = Vec::new();

    for attempt in 0..attempts {
        let mut config = base.clone();
        config.seed[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());
        config.swarm = draw_swarm(
            config.seed,
            &format!("swarm/{attempt}"),
            SWARM_CAMPAIGN_MAX_DELAY_BUDGET,
            SWARM_CRASH_CEILING,
        );

        let run = Simulation::new(config.clone(), workload.programs())
            .run()
            .map_err(|error| format!("simulation failed: {error:?}"))?;

        distinct_roots.insert(run.journal.root_hash());
        let verdict = oracle.check(&run);
        if verdict.violated {
            findings.push(Finding {
                seed: config.seed,
                run,
                verdict,
            });
        }
        variants.push(describe_variant(&config, attempt, None));
    }

    Ok(CampaignReport {
        runs_executed: attempts,
        distinct_roots: distinct_roots.len(),
        findings,
        variants,
    })
}

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
        faults: &[FaultInjection],
    ) -> u64 {
        let arm = Self::variant_hash(policy, swarm, faults);
        self.register(arm);
        arm
    }

    /// Canonical content hash of one quadruple variant.
    ///
    /// The hash covers the policy tag and fields, the full swarm config, and
    /// every fault in canonical order, so equal variants always hash equal.
    pub fn variant_hash(policy: &Policy, swarm: &SwarmConfig, faults: &[FaultInjection]) -> u64 {
        let mut bytes = Vec::new();
        match policy {
            Policy::Random => bytes.push(0),
            Policy::Pct { priority_changes } => {
                bytes.push(1);
                bytes.extend_from_slice(&priority_changes.to_le_bytes());
            }
            Policy::Bandit {
                exploration_constant,
                pct_mix,
            } => {
                bytes.push(2);
                bytes.extend_from_slice(&exploration_constant.to_bits().to_le_bytes());
                bytes.extend_from_slice(&pct_mix.to_bits().to_le_bytes());
            }
            Policy::Replay => bytes.push(3),
            Policy::Dpor => bytes.push(4),
        }
        bytes.extend_from_slice(&swarm.drop_probability.to_bits().to_le_bytes());
        bytes.extend_from_slice(&swarm.delay_probability.to_bits().to_le_bytes());
        bytes.extend_from_slice(&swarm.max_delay_ticks.to_le_bytes());
        bytes.extend_from_slice(&swarm.crash_probability.to_bits().to_le_bytes());
        bytes.extend_from_slice(&swarm.fault_classes_per_run.to_le_bytes());
        bytes.extend_from_slice(&(faults.len() as u64).to_le_bytes());
        for fault in faults {
            match fault {
                FaultInjection::Drop(id) => {
                    bytes.push(0);
                    bytes.extend_from_slice(id);
                }
                FaultInjection::Delay { send, ticks } => {
                    bytes.push(1);
                    bytes.extend_from_slice(send);
                    bytes.extend_from_slice(&ticks.to_le_bytes());
                }
                FaultInjection::Partition { src, dst } => {
                    bytes.push(2);
                    bytes.extend_from_slice(&src.to_le_bytes());
                    bytes.extend_from_slice(&dst.to_le_bytes());
                }
                FaultInjection::Crash(id) => {
                    bytes.push(3);
                    bytes.extend_from_slice(id);
                }
                FaultInjection::Corrupt { write, xor_mask } => {
                    bytes.push(4);
                    bytes.extend_from_slice(write);
                    bytes.extend_from_slice(&xor_mask.to_le_bytes());
                }
                FaultInjection::CrashState { write, state } => {
                    bytes.push(5);
                    bytes.extend_from_slice(write);
                    bytes.extend_from_slice(&state.to_le_bytes());
                }
            }
        }
        let digest = blake3::hash(&bytes);
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
    faults: Vec<FaultInjection>,
}

const BANDIT_SWARM_SAMPLES: usize = 4;
const BANDIT_FAULT_SAMPLES: usize = 4;

/// Enumerate the deterministic candidate quadruple variants for a campaign.
///
/// The enumeration crosses every policy with the drawn swarm samples and the
/// drawn fault subsets. The bandit derives each variant's canonical arm hash
/// once at registration.
fn enumerate_variants(base: &RunConfig, mutation: &QuadMutation) -> Vec<QuadVariant> {
    let policies: Vec<Policy> = if mutation.policies.is_empty() {
        vec![base.policy]
    } else {
        mutation.policies.clone()
    };
    let swarm_samples: Vec<SwarmConfig> = if mutation.use_swarm {
        (0..BANDIT_SWARM_SAMPLES)
            .map(|index| {
                draw_swarm(
                    base.seed,
                    &format!("bandit-swarm/{index}"),
                    mutation.swarm_budget,
                    SWARM_CRASH_CEILING,
                )
            })
            .collect()
    } else {
        vec![base.swarm.clone()]
    };
    let fault_samples: Vec<Vec<FaultInjection>> = if mutation.fault_library.is_empty() {
        vec![Vec::new()]
    } else {
        (0..BANDIT_FAULT_SAMPLES)
            .map(|index| {
                let mut rng = SeedTree::new(base.seed).rng(&format!("bandit-faults/{index}"));
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
    variants
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
) -> Result<CampaignReport, String> {
    let candidates = enumerate_variants(&base, mutation);
    let mut bandit = QuadBandit::new();
    let mut variant_of: HashMap<u64, QuadVariant> = HashMap::new();
    for variant in candidates {
        let arm = bandit.register_variant(&variant.policy, &variant.swarm, &variant.faults);
        variant_of.insert(arm, variant);
    }

    let mut distinct_roots: HashSet<Hash> = HashSet::new();
    let mut findings: Vec<Finding> = Vec::new();
    let mut variants: Vec<String> = Vec::new();

    for attempt in 0..attempts {
        let arm = bandit.arm(exploration);
        let variant = variant_of
            .get(&arm)
            .ok_or_else(|| format!("bandit selected unknown variant {arm:#x}"))?;
        let mut config = base.clone();
        config.seed[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());
        config.policy = variant.policy;
        config.swarm = variant.swarm.clone();
        config.fault_schedule = variant.faults.clone();

        let (programs, input_label) = match &mutation.input_generator {
            Some(generator) => {
                let label = format!("bandit-input/{attempt}");
                let attempt_seed = SeedTree::new(base.seed).derive(&label);
                let inputs = draw_inputs(generator, attempt_seed);
                (workload.with_inputs(&inputs).programs(), Some(label))
            }
            None => (workload.programs(), None),
        };

        let run = Simulation::new(config.clone(), programs)
            .run()
            .map_err(|error| format!("simulation failed: {error:?}"))?;

        distinct_roots.insert(run.journal.root_hash());
        let verdict = oracle.check(&run);
        let found = verdict.violated;
        if found {
            findings.push(Finding {
                seed: config.seed,
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
    })
}

/// Run the joint campaign: fault-adjacent schedule perturbation plus inputs
/// that reach the candidate witnesses.
///
/// The first phase searches for a violating run. Its LDFI hypothesis becomes
/// the fault schedule, and its recorded decisions are replayed per attempt
/// with one adjacent swap near the witness, while fresh inputs are sampled
/// through the input axis. The total run count is exactly `attempts`.
pub fn run_joint_campaign<W: Workload, O: Oracle>(
    workload: &W,
    oracle: &O,
    base: RunConfig,
    attempts: usize,
) -> Result<CampaignReport, String> {
    let mut distinct_roots: HashSet<Hash> = HashSet::new();
    let mut findings: Vec<Finding> = Vec::new();
    let mut variants: Vec<String> = Vec::new();

    let (base_finding, search_runs) = find_first_violation(workload, oracle, &base, attempts)?;
    if let Some(finding) = &base_finding {
        distinct_roots.insert(finding.run.journal.root_hash());
        if finding.verdict.violated {
            findings.push(finding.clone());
        }
    }
    for attempt in 0..search_runs {
        variants.push(format!("attempt={attempt} policy=joint-search"));
    }

    let mut schedule = Vec::new();
    let mut decisions = Vec::new();
    let mut witness_position = 0usize;
    if let Some(finding) = &base_finding {
        let hypotheses = solve_ldfi(&finding.run.journal, &finding.verdict);
        if let Some(hypothesis) = hypotheses.first() {
            schedule = hypothesis_to_schedule(hypothesis, &finding.run.journal);
        }
        decisions = finding.run.decisions.clone();
        witness_position = finding
            .verdict
            .witnesses
            .first()
            .and_then(|witness| {
                finding
                    .run
                    .journal
                    .entries()
                    .position(|entry| entry.id == *witness)
            })
            .unwrap_or(0);
    }

    let joint_runs = attempts.saturating_sub(search_runs);
    for offset in 0..joint_runs {
        let attempt = search_runs + offset;
        let attempt_seed = SeedTree::new(base.seed).derive(&format!("joint-input/{offset}"));
        let mut bridge = PbtBridge::new("joint", attempt_seed);
        let mut inputs = Vec::with_capacity(INPUT_AXIS_SAMPLE);
        for _ in 0..INPUT_AXIS_SAMPLE {
            inputs.push(bridge.sample_range(0, INPUT_SAMPLE_RANGE));
        }
        let joint_workload = workload.with_inputs(&inputs);

        let mut perturbed = decisions.clone();
        if perturbed.len() >= 2 {
            let pivot = witness_position.min(perturbed.len() - 2);
            perturbed.swap(pivot, pivot + 1);
        }

        let mut config = base.clone();
        config.seed = attempt_seed;
        config.policy = Policy::Replay;
        config.fault_schedule = schedule.clone();
        config.max_steps = perturbed.len().saturating_add(256);
        let run = Simulation::with_replay(config.clone(), joint_workload.programs(), perturbed)
            .run()
            .map_err(|error| format!("joint simulation failed: {error:?}"))?;

        distinct_roots.insert(run.journal.root_hash());
        let verdict = oracle.check(&run);
        if verdict.violated {
            findings.push(Finding {
                seed: attempt_seed,
                run,
                verdict,
            });
        }
        variants.push(format!("attempt={attempt} policy=joint-perturbed"));
    }

    Ok(CampaignReport {
        runs_executed: search_runs + joint_runs,
        distinct_roots: distinct_roots.len(),
        findings,
        variants,
    })
}

/// Replay one workload under a recorded scheduling decision sequence.
pub fn replay<W: Workload>(
    workload: &W,
    seed: Hash,
    decisions: Vec<usize>,
) -> Result<RunResult, String> {
    let mut config = RunConfig {
        seed,
        policy: Policy::Replay,
        ..RunConfig::default()
    };
    config.max_steps = decisions.len().saturating_add(256);
    Simulation::with_replay(config, workload.programs(), decisions)
        .run()
        .map_err(|error| format!("replay failed: {error}"))
}

/// Outcome of a fault-injected replay.
#[derive(Debug, Clone)]
pub struct FaultReplayReport {
    pub run: RunResult,
    /// Schedule injections that took effect: the first injection per applied
    /// event, in schedule order.
    pub applied: Vec<FaultInjection>,
    /// Injections whose target event never fired, whose class was superseded
    /// by an earlier injection on the same event, or which target a link
    /// rather than an event (voided faults are data).
    pub voided: Vec<FaultInjection>,
    /// No divergence before the first applied fault.
    pub prefix_ok: bool,
}

/// Replay one workload with a fault schedule injected at causal positions.
pub fn replay_with_faults<W: Workload>(
    workload: &W,
    base: &ledger_journal::Journal,
    seed: Hash,
    decisions: Vec<usize>,
    schedule: Vec<FaultInjection>,
) -> Result<FaultReplayReport, String> {
    let mut config = RunConfig {
        seed,
        policy: Policy::Replay,
        fault_schedule: schedule.clone(),
        ..RunConfig::default()
    };
    config.max_steps = decisions.len().saturating_add(256);
    let run = Simulation::with_replay(config, workload.programs(), decisions)
        .run()
        .map_err(|error| format!("fault replay failed: {error}"))?;
    let applied_set: std::collections::HashSet<&Hash> = run.applied_faults.iter().collect();
    let mut seen_applied = std::collections::HashSet::new();
    let mut applied = Vec::new();
    let mut voided = Vec::new();
    for injection in schedule {
        match fault_injection_target(&injection) {
            // A link partition targets no single event, so it cannot be
            // attributed to an applied event id; it is reported voided.
            None => voided.push(injection),
            Some(id) if applied_set.contains(&id) && seen_applied.insert(id) => {
                applied.push(injection);
            }
            Some(_) => voided.push(injection),
        }
    }
    let base_ids = base.entries().map(|entry| entry.id).collect::<Vec<_>>();
    let replay_ids = run
        .journal
        .entries()
        .map(|entry| entry.id)
        .collect::<Vec<_>>();
    let first_fault = run
        .applied_faults
        .iter()
        .filter_map(|id| base_ids.iter().position(|base| base == id))
        .min()
        .unwrap_or(base_ids.len());
    let prefix_ok = (0..first_fault).all(|index| base_ids.get(index) == replay_ids.get(index));
    Ok(FaultReplayReport {
        run,
        applied,
        voided,
        prefix_ok,
    })
}

pub fn diff(left: &RunResult, right: &RunResult) -> Option<(Hash, Hash)> {
    first_divergence(&left.journal, &right.journal).map(|(left, right)| {
        (
            left.map_or([0; 32], |entry| entry.id),
            right.map_or([0; 32], |entry| entry.id),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle::{HistoryOperation, PropertyOracle};
    use ledger_format::{EntryKind, Payload};
    use ledger_journal::Journal;

    /// Workload whose behavior depends on the first input value.
    ///
    /// The producer stores each input in a task-local register via `Input`
    /// steps; the final outcome registers the count of even inputs.
    struct InputSensitiveWorkload;

    impl Workload for InputSensitiveWorkload {
        fn programs(&self) -> Vec<Vec<Instruction>> {
            vec![vec![
                Instruction::Set(0),
                Instruction::Outcome,
                Instruction::Done,
            ]]
        }

        fn history(&self, _run: &RunResult) -> Vec<HistoryOperation> {
            Vec::new()
        }

        fn with_inputs(&self, inputs: &[u64]) -> Box<dyn Workload> {
            let generator = crate::pbt::gen_id("input-sensitive");
            let mut program = Vec::with_capacity(inputs.len() + 2);
            for (index, value) in inputs.iter().enumerate() {
                program.push(Instruction::Input {
                    generator,
                    replay: index as u64,
                    value: *value,
                });
            }
            program.push(Instruction::Outcome);
            program.push(Instruction::Done);
            Box::new(InputsWorkload::new(vec![program]))
        }
    }

    fn journal_contains_input_value(run: &RunResult, target: u64) -> bool {
        run.journal.entries().any(|entry| {
            matches!(entry.data.kind, EntryKind::InputStep { .. })
                && matches!(&entry.data.payload, Payload::Number(value) if *value == target)
        })
    }

    #[test]
    fn search_input_finds_violation_only_for_specific_input_sample() {
        let base = RunConfig {
            seed: [5; 32],
            policy: Policy::Random,
            max_steps: 512,
            ..RunConfig::default()
        };
        let workload = InputSensitiveWorkload;
        let oracle = PropertyOracle {
            property: |journal: &Journal| {
                !journal.entries().any(|entry| {
                    matches!(entry.data.kind, EntryKind::InputStep { .. })
                        && matches!(&entry.data.payload, Payload::Number(42))
                })
            },
            name: "no input value equals 42".into(),
        };

        let finding = search_input(&workload, &oracle, base.clone(), "input-sensitive", 64)
            .unwrap()
            .expect("a specific input sample must violate the oracle");
        assert!(finding.verdict.violated);
        assert!(
            journal_contains_input_value(&finding.run, 42),
            "the violating sample must journal the triggering input"
        );

        let again = search_input(&workload, &oracle, base.clone(), "input-sensitive", 64)
            .unwrap()
            .expect("deterministic search must find the same violation");
        assert_eq!(finding.seed, again.seed);
        assert_eq!(
            finding.run.journal.root_hash(),
            again.run.journal.root_hash()
        );
    }

    fn swarm_knob(variant: &str, knob: &str) -> f64 {
        variant
            .split(&format!("{knob}="))
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|value| value.parse().ok())
            .expect("variant must carry the knob")
    }

    #[test]
    fn swarm_axis_distribution_matches_across_campaign_types() {
        let base = RunConfig {
            seed: [3; 32],
            policy: Policy::Random,
            max_steps: 256,
            ..RunConfig::default()
        };
        let mutation = QuadMutation {
            policies: vec![Policy::Random],
            use_swarm: true,
            swarm_budget: SWARM_CAMPAIGN_MAX_DELAY_BUDGET,
            fault_library: Vec::new(),
            max_faults_per_run: 0,
            ..Default::default()
        };
        let oracle = PropertyOracle {
            property: |_journal: &Journal| true,
            name: "always passes".into(),
        };

        let quad = run_campaign_quad(&InputSensitiveWorkload, &oracle, base.clone(), &mutation, 8)
            .expect("quad campaign must run");
        let swarm = run_swarm_campaign(&InputSensitiveWorkload, &oracle, base, 8)
            .expect("swarm campaign must run");

        for variant in quad.variants.iter().chain(swarm.variants.iter()) {
            assert!(
                swarm_knob(variant, "crash") <= SWARM_CRASH_CEILING,
                "crash draws must respect the shared ceiling: {variant}"
            );
            assert_eq!(
                swarm_knob(variant, "classes") as usize,
                SWARM_FAULT_CLASSES_PER_RUN,
                "fault-class budget must match the shared constant: {variant}"
            );
            assert!(
                swarm_knob(variant, "max_delay") <= SWARM_CAMPAIGN_MAX_DELAY_BUDGET as f64,
                "max-delay draws must respect the shared budget: {variant}"
            );
        }
    }

    #[test]
    fn input_axis_draws_distinct_values_per_attempt_seed() {
        let base = RunConfig {
            seed: [9; 32],
            ..RunConfig::default()
        };
        let first = draw_inputs("quad-test", SeedTree::new(base.seed).derive("quad-input/0"));
        let second = draw_inputs("quad-test", SeedTree::new(base.seed).derive("quad-input/1"));
        assert_eq!(first.len(), INPUT_AXIS_SAMPLE);
        assert_eq!(second.len(), INPUT_AXIS_SAMPLE);
        assert_ne!(
            first, second,
            "each attempt must draw a fresh, independent input sequence"
        );
    }

    #[test]
    fn quad_campaign_mutates_input_axis_with_the_other_three() {
        let base = RunConfig {
            seed: [9; 32],
            policy: Policy::Random,
            max_steps: 256,
            ..RunConfig::default()
        };
        let mutation = QuadMutation {
            policies: vec![Policy::Random],
            use_swarm: true,
            swarm_budget: SWARM_CAMPAIGN_MAX_DELAY_BUDGET,
            fault_library: Vec::new(),
            max_faults_per_run: 0,
            input_generator: Some("quad-test".into()),
        };
        let oracle = PropertyOracle {
            property: |_journal: &Journal| true,
            name: "always passes".into(),
        };

        let report =
            run_campaign_quad(&InputSensitiveWorkload, &oracle, base.clone(), &mutation, 8)
                .expect("quad campaign must run");
        assert_eq!(report.runs_executed, 8);
        assert!(
            report
                .variants
                .iter()
                .any(|variant| variant.contains("input=quad-input/0"))
                && report
                    .variants
                    .iter()
                    .any(|variant| variant.contains("input=quad-input/7")),
            "each attempt must report its per-attempt input stream label"
        );

        let rerun = run_campaign_quad(&InputSensitiveWorkload, &oracle, base, &mutation, 8)
            .expect("quad campaign rerun must run");
        assert_eq!(report.variants, rerun.variants);
        assert_eq!(report.distinct_roots, rerun.distinct_roots);
        assert_eq!(report.findings.len(), rerun.findings.len());
    }

    #[test]
    fn bandit_campaign_mutates_input_axis() {
        let base = RunConfig {
            seed: [11; 32],
            policy: Policy::Random,
            max_steps: 256,
            ..RunConfig::default()
        };
        let mutation = QuadMutation {
            policies: vec![Policy::Random],
            use_swarm: false,
            swarm_budget: 0,
            fault_library: Vec::new(),
            max_faults_per_run: 0,
            input_generator: Some("quad-bandit-test".into()),
        };
        let oracle = PropertyOracle {
            property: |_journal: &Journal| true,
            name: "always passes".into(),
        };

        let report = run_bandit_campaign(
            &InputSensitiveWorkload,
            &oracle,
            base.clone(),
            &mutation,
            1.414,
            8,
        )
        .expect("bandit campaign must run");
        assert_eq!(report.runs_executed, 8);
        assert!(
            report
                .variants
                .iter()
                .any(|variant| variant.contains("input=bandit-input/0")),
            "the bandit must report the per-attempt input stream label"
        );

        let rerun =
            run_bandit_campaign(&InputSensitiveWorkload, &oracle, base, &mutation, 1.414, 8)
                .expect("bandit campaign rerun must run");
        assert_eq!(report.variants, rerun.variants);
        assert_eq!(report.distinct_roots, rerun.distinct_roots);
    }
}
