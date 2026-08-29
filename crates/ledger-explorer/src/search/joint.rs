use super::input_axis::INPUT_AXIS_SAMPLE;
use super::{CampaignReport, Finding, SearchError, Workload, find_first_violation};
use crate::ldfi::hypothesis_to_schedule;
use crate::maxsat::encode_hazard;
use crate::memo::{CampaignMemo, MemoEntry, hash_inputs, memo_key};
use crate::oracle::Oracle;
use crate::pbt::{INPUT_SAMPLE_RANGE, PbtBridge, gen_id};
use crate::solver::{FaultSolver, HittingSetSolver, SolverConfig, select_solver};
use crate::solver_state::{load as load_solver_state, save as save_solver_state};
use ledger_format::{ActorId, Hash};
use ledger_journal::Journal;
use ledger_sim::{Policy, RunConfig, SeedTree, Simulation, canonical_hash};
use std::collections::HashSet;

/// Opt-in cross-round state for the stateful campaign variants.
///
/// Holds a crate-local in-memory journal of solver-state artifacts plus a
/// campaign memo. After each LDFI solve the campaign persists solver caches
/// into the journal; later rounds and later campaigns sharing one handle
/// resume them, pre-warming clause and hypothesis caches. The memo dedups
/// identical replay attempts by journal root.
pub struct CampaignPersist {
    pub(super) journal: Journal,
    memo: CampaignMemo,
}

impl Default for CampaignPersist {
    fn default() -> Self {
        Self::new()
    }
}

/// Actor id stamped on persisted solver-state entries.
const CAMPAIGN_PERSIST_ACTOR: ActorId = u32::MAX;

impl CampaignPersist {
    pub fn new() -> Self {
        Self {
            journal: Journal::new(),
            memo: CampaignMemo::new(),
        }
    }

    /// Resume every stored artifact into `solver`, pre-warming its caches.
    ///
    /// Works for any routed engine: engines without artifact support no-op
    /// via the trait defaults. An artifact whose state key, resolved engine,
    /// or run-config hash does not match the solver fails loudly instead of
    /// pre-warming with foreign state.
    pub(super) fn resume_into(&self, solver: &mut dyn FaultSolver) -> Result<(), SearchError> {
        let artifacts = load_solver_state(&self.journal)?;
        for artifact in &artifacts {
            solver.warm_from_artifact(artifact)?;
        }
        Ok(())
    }

    /// Persist `solver`'s cache state. Identical states dedup by content
    /// address, so repeated saves never grow the internal journal.
    pub(super) fn persist_from(&mut self, solver: &dyn FaultSolver) -> Result<(), SearchError> {
        let Some(artifact) = solver.snapshot_state() else {
            return Ok(());
        };
        save_solver_state(&mut self.journal, CAMPAIGN_PERSIST_ACTOR, &artifact)?;
        Ok(())
    }
}

/// Run the joint campaign without cross-campaign state.
///
/// See [`run_joint_campaign_with_state`] for the stateful variant.
pub fn run_joint_campaign<W: Workload, O: Oracle>(
    workload: &W,
    oracle: &O,
    base: RunConfig,
    attempts: usize,
) -> Result<CampaignReport, SearchError> {
    run_joint_campaign_with_state(workload, oracle, base, attempts, None)
}

/// Run the joint campaign: fault-adjacent schedule perturbation plus inputs
/// that reach the candidate witnesses.
///
/// The first phase searches for a violating run. Its LDFI hypothesis becomes
/// the fault schedule, and its recorded decisions are replayed per attempt
/// with one adjacent swap near the witness, while fresh inputs are sampled
/// through the input axis. The total run count is exactly `attempts`.
///
/// Each replay is keyed by `(Replay, swarm, schedule, input hash, decisions)`
/// in the campaign memo. A hit reuses the cached journal root instead of
/// re-executing and counts as a memo hit; with `state`, the memo and the
/// persisted solver state survive across calls, so an identical rerun hits
/// for every round instead of executing.
pub fn run_joint_campaign_with_state<W: Workload, O: Oracle>(
    workload: &W,
    oracle: &O,
    base: RunConfig,
    attempts: usize,
    mut state: Option<&mut CampaignPersist>,
) -> Result<CampaignReport, SearchError> {
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
        // Production solver uses bounded horizon 64 and per-input-class cache
        // for the joint generator. The canonical run-config hash joins the
        // solver keys so state persisted under one run config never pre-warms
        // a campaign under another.
        let run_config_hash = canonical_hash(&base)?;
        let base_cfg = HittingSetSolver::new().config().clone();
        let cfg = SolverConfig {
            input_class: Some(gen_id("joint")),
            run_config_hash: Some(run_config_hash),
            ..base_cfg
        };
        let encoded = encode_hazard(&finding.run.journal, &finding.verdict, &cfg)?;
        let mut solver = select_solver(&cfg, &encoded);
        if let Some(shared) = state.as_deref_mut() {
            shared.resume_into(solver.as_mut())?;
        }
        let hypotheses = solver.solve(&finding.run.journal, &finding.verdict)?;
        if let Some(shared) = state.as_deref_mut() {
            shared.persist_from(solver.as_ref())?;
        }
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
    let mut scratch_memo = CampaignMemo::new();
    let memo: &mut CampaignMemo = match state {
        Some(shared) => &mut shared.memo,
        None => &mut scratch_memo,
    };
    let mut memo_hits = 0usize;
    for offset in 0..joint_runs {
        let attempt = search_runs + offset;
        let attempt_seed = SeedTree::new(base.seed()).derive(&format!("joint-input/{offset}"));
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

        let config = base
            .clone()
            .with_seed(attempt_seed)
            .with_policy(Policy::Replay)
            .with_fault_schedule(schedule.clone())
            .with_max_steps(perturbed.len().saturating_add(256));

        let key = memo_key(
            &Policy::Replay,
            config.swarm(),
            &schedule,
            Some(hash_inputs(&inputs)),
            Some(&perturbed),
        );
        if let Some(entry) = memo.get(&key) {
            distinct_roots.insert(entry.journal_root);
            variants.push(format!("attempt={attempt} policy=joint-perturbed"));
            memo_hits += 1;
            continue;
        }

        let run =
            Simulation::with_replay(config.clone(), joint_workload.programs(), perturbed).run()?;

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
        monitors: Vec::new(),
        memo_hits,
    })
}
