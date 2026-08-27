use super::input_axis::draw_inputs;
use super::{
    describe_variant, draw_fault_subset, draw_swarm, CampaignReport, Finding, SearchError,
    Workload, SWARM_CAMPAIGN_MAX_DELAY_BUDGET, SWARM_CRASH_CEILING,
};
use crate::memo::{hash_inputs, memo_key, CampaignMemo, MemoEntry};
use crate::oracle::Oracle;
use crate::pbt::EnergyDistribution;
use ledger_format::Hash;
use ledger_sim::{Policy, RunConfig, SeedTree, SimFault, Simulation};
use std::collections::HashSet;

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
    pub fault_library: Vec<SimFault>,
    pub max_faults_per_run: usize,
    /// PBT input generator for the input axis; `None` disables the axis.
    ///
    /// When set, every attempt draws a fresh input sequence from the
    /// generator's seed-tree `gen/<generator>` stream and rebuilds the
    /// workload with those values, mutating all four quadruple axes together.
    pub input_generator: Option<String>,
    /// Energy distribution for sampled inputs; `None` keeps the uniform
    /// modulo path for backward compatibility.
    pub input_energy: Option<EnergyDistribution>,
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
) -> Result<CampaignReport, SearchError> {
    let mut distinct_roots: HashSet<Hash> = HashSet::new();
    let mut findings: Vec<Finding> = Vec::new();
    let mut variants: Vec<String> = Vec::new();
    let base_seed = base.seed();
    // LazyMOP-style campaign memo: content-addressed dedup keyed by
    // `BLAKE3(variant_hash || input_hash || replay)`. A hit reuses the
    // cached journal root without re-executing the simulator, which saves
    // budget when the same quadruple variant is drawn repeatedly. The memo
    // is per-campaign (local HashMap) and orthogonal to the solver cache.
    let mut memo = CampaignMemo::new();

    for attempt in 0..attempts {
        let mut seed = base.seed();
        seed[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());
        let mut config = base.clone().with_seed(seed);

        if mutation.policies.is_empty() {
            config = config.with_policy(base.policy());
        } else {
            let digest = SeedTree::new(base_seed).derive(&format!("quad-policy/{attempt}"));
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&digest[..8]);
            let draw = u64::from_le_bytes(bytes) as usize;
            config = config.with_policy(mutation.policies[draw % mutation.policies.len()]);
        }

        if mutation.use_swarm {
            let swarm = draw_swarm(
                base_seed,
                &format!("quad-swarm/{attempt}"),
                mutation.swarm_budget,
                SWARM_CRASH_CEILING,
            )?;
            config = config.with_swarm(swarm);
        }

        if !mutation.fault_library.is_empty() {
            let mut rng = SeedTree::new(base_seed).rng(&format!("quad-faults/{attempt}"));
            let schedule = draw_fault_subset(
                &mutation.fault_library,
                mutation.max_faults_per_run,
                &mut rng,
            );
            config = config.with_fault_schedule(schedule);
        }

        let (programs, input_label, input_hash) = match &mutation.input_generator {
            Some(generator) => {
                let label = format!("quad-input/{attempt}");
                let attempt_seed = SeedTree::new(base_seed).derive(&label);
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
            &config.policy(),
            config.swarm(),
            config.fault_schedule(),
            input_hash,
            None,
        );
        if let Some(entry) = memo.get(&key) {
            distinct_roots.insert(entry.journal_root);
            variants.push(describe_variant(&config, attempt, input_label.as_deref()));
            continue;
        }

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
        let verdict = oracle.check(&run);
        if verdict.violated {
            findings.push(Finding {
                seed: config.seed(),
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
        monitors: Vec::new(),
        memo_hits: 0,
    })
}

/// Run a campaign that mutates only the swarm axis of the quadruple.
///
/// Per attempt the swarm knobs are drawn from the seeded stream with the same
/// distribution as the quad campaign's swarm axis: drop and delay
/// probabilities in `0.0 .. 1.0`, `max_delay_ticks` in `0 ..= 8`, crash
/// probability in `0.0 .. 0.1`, and the shared fault-class budget. The seed
/// varies as in [`crate::search::run_campaign`].
pub fn run_swarm_campaign<W: Workload, O: Oracle>(
    workload: &W,
    oracle: &O,
    base: RunConfig,
    attempts: usize,
) -> Result<CampaignReport, SearchError> {
    let mut distinct_roots: HashSet<Hash> = HashSet::new();
    let mut findings: Vec<Finding> = Vec::new();
    let mut variants: Vec<String> = Vec::new();
    let base_seed = base.seed();

    for attempt in 0..attempts {
        let mut seed = base.seed();
        seed[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());
        let swarm = draw_swarm(
            base_seed,
            &format!("swarm/{attempt}"),
            SWARM_CAMPAIGN_MAX_DELAY_BUDGET,
            SWARM_CRASH_CEILING,
        )?;
        let config = base.clone().with_seed(seed).with_swarm(swarm);

        let run = Simulation::new(config.clone(), workload.programs()).run()?;

        distinct_roots.insert(run.journal.root_hash());
        let verdict = oracle.check(&run);
        if verdict.violated {
            findings.push(Finding {
                seed: config.seed(),
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
        monitors: Vec::new(),
        memo_hits: 0,
    })
}
