//! Bounded single-trace single-base source-DPOR exploration driver.
//!
//! Runs one base execution, then re-runs each causally plausible alternative
//! at every trace step with a partial replay. A sleep-set test prunes flips
//! between causally ordered tasks using per-step vector clocks; equal clocks
//! count as concurrent. Bounded to one base trace with no recursive
//! re-analysis, so no completeness is claimed.

use std::collections::{HashMap, HashSet};

use crate::config::{Policy, RunConfig};
use crate::runtime::{Instruction, RuntimeError, Simulation};
use ledger_format::{ActorId, EntryHash};
use ledger_journal::VectorClock;

/// Configuration for one source-DPOR exploration campaign.
#[derive(Debug, Clone)]
pub struct DporConfig {
    /// Root seed shared by the base run and every re-run.
    pub seed: EntryHash,
    /// Instruction budget per run.
    pub max_steps: usize,
    /// Maximum number of runs, base run included.
    pub max_runs: usize,
}

/// One explored run: the root it reached and the decisions that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DporRun {
    pub root_hash: EntryHash,
    pub decisions: Vec<usize>,
    /// Length of the forced replay prefix, or 0 for the base run.
    ///
    /// For a flip run the decision at index `forced_prefix_len - 1` is the
    /// alternative choice under exploration.
    pub forced_prefix_len: usize,
}

/// Outcome of a source-DPOR campaign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DporReport {
    /// Every explored run, base run first.
    pub runs: Vec<DporRun>,
    pub distinct_roots: usize,
    /// Number of unique flips explored (sleep-set prunes excluded).
    pub explored_flips: usize,
    /// The unique `(step, alt_task)` keys that passed the sleep-set test.
    ///
    /// A key records which alternative task id was forced at which trace step.
    pub explored_flip_keys: Vec<(usize, usize)>,
}

/// Explore alternative schedules around one base run (bounded DPOR).
///
/// The base run leads the report; each flip forces one alternative decision
/// and continues with `Random`. Same seed yields an identical report.
pub fn run_dpor(
    programs: Vec<Vec<Instruction>>,
    cfg: &DporConfig,
) -> Result<DporReport, RuntimeError> {
    let base_config = RunConfig::builder()
        .seed(cfg.seed)
        .policy(Policy::Dpor)
        .max_steps(cfg.max_steps)
        .build();
    // Flip runs follow the forced prefix through the Replay policy; the
    // `Random` fallback continues the schedule after the prefix is exhausted.
    let replay_config = RunConfig::builder()
        .seed(cfg.seed)
        .policy(Policy::Replay)
        .max_steps(cfg.max_steps)
        .build();

    let base = Simulation::new(base_config.clone(), programs.clone()).run()?;
    let base_root = base.journal.root_hash();

    let mut report = DporReport {
        runs: vec![DporRun {
            root_hash: base_root,
            decisions: base.decisions.clone(),
            forced_prefix_len: 0,
        }],
        distinct_roots: 1,
        explored_flips: 0,
        explored_flip_keys: Vec::new(),
    };

    let journal_entries = base.journal.entries().collect::<Vec<_>>();
    // ledger-lint:allow:HashMap ledger-lint:allow:HashSet (explored-set
    // membership and per-actor clock lookups keyed by ActorId; no iteration
    // reaches decisions)
    let mut explored = HashSet::new();
    // `last_vc` holds each task's vector clock as of the current branch point:
    // entries journaled before the step under inspection, advanced per step
    // using the recorded journal boundary.
    let mut last_vc: HashMap<ActorId, VectorClock> = HashMap::new();
    let mut entry_idx = 0usize;

    'flips: for trace_entry in &base.trace {
        let step = trace_entry.step;
        let chosen_task = trace_entry.ready[trace_entry.chosen];
        for (alt_pos, alt) in trace_entry.ready.iter().enumerate() {
            if alt_pos == trace_entry.chosen {
                continue;
            }
            if sleep_set_pruned(&last_vc, chosen_task, *alt) {
                continue;
            }
            if !explored.insert((step, *alt)) {
                continue;
            }
            if report.runs.len() >= cfg.max_runs {
                break 'flips;
            }
            report.explored_flips += 1;
            report.explored_flip_keys.push((step, *alt));
            let mut replay = base.decisions[..step].to_vec();
            replay.push(alt_pos);
            let run = Simulation::with_replay_and_fallback(
                replay_config.clone(),
                programs.clone(),
                replay,
                Policy::Random,
            )
            .run()?;
            report.runs.push(DporRun {
                root_hash: run.journal.root_hash(),
                decisions: run.decisions,
                forced_prefix_len: step + 1,
            });
            if report.runs.len() >= cfg.max_runs {
                break 'flips;
            }
        }
        // Advance the per-task clocks past this step's journaled entries so the
        // next branch point sees only entries that precede it.
        while entry_idx < trace_entry.journal_len {
            let entry = journal_entries[entry_idx];
            last_vc.insert(entry.data.actor, entry.vector_clock.clone());
            entry_idx += 1;
        }
    }

    report.distinct_roots = report
        .runs
        .iter()
        .map(|run| run.root_hash)
        .collect::<HashSet<_>>()
        .len();
    Ok(report)
}

/// Sleep-set test: prunes the flip when the tasks are causally ordered as of
/// the branch point; missing or equal clocks count as concurrent.
fn sleep_set_pruned(
    task_last_vc: &HashMap<ActorId, VectorClock>,
    chosen_task: usize,
    alt: usize,
) -> bool {
    let chosen_vc = task_last_vc.get(&ActorId(chosen_task as u32));
    let alt_vc = task_last_vc.get(&ActorId(alt as u32));
    match (chosen_vc, alt_vc) {
        (Some(chosen), Some(alt)) => chosen.happens_before(alt) || alt.happens_before(chosen),
        _ => false,
    }
}
