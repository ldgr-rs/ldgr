//! Bounded single-trace single-base source-DPOR exploration driver.
//!
//! The driver runs one base execution under a `Dpor` policy (which behaves like
//! `Random`), records its scheduler trace, and re-runs each causally plausible
//! alternative choice at every trace step with a partial replay. A sleep-set
//! test prunes flips between causally ordered tasks using each task's vector
//! clock as of the branch point (the journal records the per-step boundary, so
//! the driver reconstructs per-step clocks rather than using end-of-run
//! clocks). Two tasks are pruned only when one strictly happens before the
//! other; equal clocks are treated as concurrent. The sleep-set is applied at
//! every trace step of the whole run, so each causal equivalence class is
//! represented by at most one flip per branch point and same-class reorderings
//! of already-ordered tasks are never explored.
//!
//! This is a bounded single-trace single-base variant: it explores schedule
//! flips around one base trace only and never re-analyzes flip runs as new
//! bases. It therefore makes no completeness claim; it does not guarantee one
//! execution per causal equivalence class, only bounded exploration of
//! alternative schedules around the single base run.

use std::collections::{HashMap, HashSet};

use crate::config::{Policy, RunConfig};
use crate::runtime::{Instruction, RuntimeError, Simulation};
use ledger_format::{ActorId, Hash};
use ledger_journal::VectorClock;

/// Configuration for one source-DPOR exploration campaign.
#[derive(Debug, Clone)]
pub struct DporConfig {
    /// Root seed shared by the base run and every re-run.
    pub seed: Hash,
    /// Instruction budget per run.
    pub max_steps: usize,
    /// Maximum number of runs, base run included.
    pub max_runs: usize,
}

/// One explored run: the root it reached and the decisions that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DporRun {
    pub root_hash: Hash,
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

/// Explore causally distinct schedules around one base run (bounded
/// single-trace single-base DPOR).
///
/// The base run is the first entry of the report. Each subsequent run forces a
/// decision different from the base run's at one trace step and lets the
/// `Random` fallback continue. This is bounded single-base DPOR: only flips
/// around the single base trace are explored, with no recursive re-analysis
/// of flip runs, so no completeness guarantee is claimed. The same seed
/// produces an identical report.
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

/// Sleep-set test: skip the flip when the two tasks are already causally
/// ordered by the events that precede the branch point.
///
/// `last_vc` maps each task to its vector clock as of the branch point. Two
/// tasks with strictly ordered clocks are pruned; a task with no journaled
/// entry yet, or two tasks with equal clocks, are treated as concurrent.
fn sleep_set_pruned(
    task_last_vc: &HashMap<ActorId, VectorClock>,
    chosen_task: usize,
    alt: usize,
) -> bool {
    let chosen_vc = task_last_vc.get(&(chosen_task as ActorId));
    let alt_vc = task_last_vc.get(&(alt as ActorId));
    match (chosen_vc, alt_vc) {
        (Some(chosen), Some(alt)) => chosen.happens_before(alt) || alt.happens_before(chosen),
        _ => false,
    }
}
