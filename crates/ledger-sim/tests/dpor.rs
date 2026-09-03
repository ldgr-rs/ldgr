//! Bounded source-DPOR driver tests.

use ledger_sim::{DporConfig, Instruction, Policy, RunConfig, Simulation, run_dpor};
use std::collections::{HashMap, HashSet};

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

/// Strictly ordered producer/dependent pair plus a causally independent task.
///
/// Task 0 (producer) sends one message and completes WITHOUT a terminal entry,
/// so its whole history is subsumed by task 1 (dependent), which consumes it.
/// Task 2 is independent and stays concurrent with both.
fn ordered_chain_programs() -> Vec<Vec<Instruction>> {
    vec![
        vec![Instruction::Send { to: 1, payload: 1 }],
        vec![
            Instruction::Receive,
            Instruction::Outcome,
            Instruction::Done,
        ],
        vec![
            Instruction::FsWrite {
                path: "k".into(),
                value: 7,
            },
            Instruction::Done,
        ],
    ]
}

#[test]
fn dpor_explores_causally_distinct_schedules() {
    let cfg = DporConfig {
        seed: ledger_format::EntryHash([3; 32]),
        max_steps: 256,
        max_runs: 8,
    };
    let report = run_dpor(mini_kv_programs(), &cfg).unwrap();

    assert!(
        report.runs.len() >= 2,
        "the driver must explore at least one flip, got {} runs",
        report.runs.len()
    );
    assert!(
        report.distinct_roots >= 2,
        "the flips must discover causally distinct schedules, got {} distinct roots",
        report.distinct_roots
    );

    // Replay determinism: every reported decision sequence reproduces its root.
    for run in &report.runs {
        let config = RunConfig::builder()
            .seed(cfg.seed)
            .policy(Policy::Replay)
            .max_steps(cfg.max_steps)
            .build();
        let replayed = Simulation::with_replay(config, mini_kv_programs(), run.decisions.clone())
            .run()
            .unwrap();
        assert_eq!(
            replayed.journal.root_hash(),
            run.root_hash,
            "replaying a run's decisions must reproduce its root"
        );
    }
}

#[test]
fn dpor_is_deterministic() {
    let cfg = DporConfig {
        seed: ledger_format::EntryHash([9; 32]),
        max_steps: 256,
        max_runs: 8,
    };
    let first = run_dpor(mini_kv_programs(), &cfg).unwrap();
    let second = run_dpor(mini_kv_programs(), &cfg).unwrap();
    assert_eq!(
        first, second,
        "same seed must produce an identical DPOR report"
    );
}

#[test]
fn dpor_sleep_set_prunes_ordered_tasks() {
    // Task 0 writes a value and stays alive; task 1 reads that value and stays
    // alive. Once the read observes the write, the two tasks are strictly
    // ordered (0 happens-before 1) while both remain co-ready, so the flips
    // between them are sleep-set pruned. Seed 24 schedules the write before
    // the read, forming that ordered window.
    let programs = vec![
        vec![
            Instruction::FsWrite {
                path: "k".into(),
                value: 1,
            },
            Instruction::Yield,
            Instruction::Yield,
            Instruction::Done,
        ],
        vec![
            Instruction::FsRead { path: "k".into() },
            Instruction::Yield,
            Instruction::Yield,
            Instruction::Done,
        ],
    ];
    let cfg = DporConfig {
        seed: ledger_format::EntryHash([24; 32]),
        max_steps: 512,
        max_runs: 64,
    };
    let report = run_dpor(programs.clone(), &cfg).unwrap();

    let base_config = RunConfig::builder()
        .seed(cfg.seed)
        .policy(Policy::Dpor)
        .max_steps(cfg.max_steps)
        .build();
    let base = Simulation::new(base_config, programs).run().unwrap();
    let eligible_pairs: usize = base
        .trace
        .iter()
        .map(|trace| trace.ready.len().saturating_sub(1))
        .sum();

    assert!(
        eligible_pairs > report.explored_flips,
        "the sleep-set test must prune at least one causally ordered flip \
         (eligible {eligible_pairs}, explored {})",
        report.explored_flips
    );
    assert!(
        report.runs.len() >= 2,
        "the pruned-pair workload must still explore at least one flip"
    );
}

/// The flip at an early branch point must be explored when the two tasks are
/// still concurrent there, even though they become causally ordered later.
///
/// The old final-clock sleep-set pruned this flip, missing the schedule where
/// the dependent blocks before the producer sends.
#[test]
fn dpor_explores_flip_before_tasks_become_ordered() {
    let programs = ordered_chain_programs();
    let cfg = DporConfig {
        seed: ledger_format::EntryHash([5; 32]),
        max_steps: 512,
        max_runs: 64,
    };
    let report = run_dpor(programs.clone(), &cfg).unwrap();

    let base_config = RunConfig::builder()
        .seed(cfg.seed)
        .policy(Policy::Dpor)
        .max_steps(cfg.max_steps)
        .build();
    let base = Simulation::new(base_config, programs).run().unwrap();
    let step0 = &base.trace[0];
    assert!(
        step0.ready.contains(&0) && step0.ready.contains(&1),
        "the producer and dependent must both be ready at step 0"
    );
    let alt = if step0.chosen == 0 { 1 } else { 0 };
    assert!(
        report.explored_flip_keys.contains(&(step0.step, alt)),
        "the step-0 flip between the producer and dependent must be explored \
         (they are concurrent before any message is sent)"
    );
}

#[test]
fn dpor_respects_max_runs() {
    let cfg = DporConfig {
        seed: ledger_format::EntryHash([11; 32]),
        max_steps: 256,
        max_runs: 2,
    };
    let report = run_dpor(mini_kv_programs(), &cfg).unwrap();
    assert!(
        report.runs.len() <= 2,
        "max_runs = 2 must cap the explored runs, got {}",
        report.runs.len()
    );
    assert!(
        !report.runs.is_empty(),
        "the base run must always be present"
    );
}

/// Each causally distinct alternative is explored exactly once.
#[test]
fn dpor_explores_each_causal_class_once() {
    let programs = ordered_chain_programs();
    let cfg = DporConfig {
        seed: ledger_format::EntryHash([5; 32]),
        max_steps: 512,
        max_runs: 64,
    };
    let report = run_dpor(programs.clone(), &cfg).unwrap();

    let base_config = RunConfig::builder()
        .seed(cfg.seed)
        .policy(Policy::Dpor)
        .max_steps(cfg.max_steps)
        .build();
    let base = Simulation::new(base_config, programs).run().unwrap();

    let concurrent = concurrent_alt_pairs(&base);
    let explored: HashSet<(usize, usize)> = report.explored_flip_keys.iter().copied().collect();
    assert_eq!(
        explored, concurrent,
        "each concurrent alternative must be explored exactly once and no \
         same-class (causally ordered) alternative may be explored"
    );
    assert_eq!(
        report.explored_flips,
        concurrent.len(),
        "the reported flip count must match the explored key set"
    );
}

/// Recompute the driver's sleep-set test from the base run's per-step journal
/// boundaries: return the `(step, alt)` pairs whose two tasks are concurrent
/// (not strictly happens-before ordered) as of each branch point.
fn concurrent_alt_pairs(base: &ledger_sim::RunResult) -> HashSet<(usize, usize)> {
    use ledger_format::ActorId;
    use ledger_journal::VectorClock;

    let entries = base.journal.entries().collect::<Vec<_>>();
    let mut last_vc: HashMap<ActorId, VectorClock> = HashMap::new();
    let mut entry_idx = 0usize;
    let mut pairs = HashSet::new();
    for trace in &base.trace {
        let chosen_task = trace.ready[trace.chosen];
        for (alt_pos, alt) in trace.ready.iter().enumerate() {
            if alt_pos == trace.chosen {
                continue;
            }
            let ordered = match (
                last_vc.get(&ActorId(chosen_task as u32)),
                last_vc.get(&ActorId(*alt as u32)),
            ) {
                (Some(chosen), Some(alt)) => {
                    chosen.happens_before(alt) || alt.happens_before(chosen)
                }
                _ => false,
            };
            if !ordered {
                pairs.insert((trace.step, *alt));
            }
        }
        while entry_idx < trace.journal_len {
            let entry = entries[entry_idx];
            last_vc.insert(entry.data.actor, entry.vector_clock.clone());
            entry_idx += 1;
        }
    }
    pairs
}

/// With `max_runs` exhausted the driver must not report flips it never ran:
/// the explored bookkeeping records only executed flips.
#[test]
fn dpor_does_not_report_unrun_flips() {
    let cfg = DporConfig {
        seed: ledger_format::EntryHash([13; 32]),
        max_steps: 256,
        max_runs: 1,
    };
    let report = run_dpor(mini_kv_programs(), &cfg).unwrap();
    assert_eq!(report.runs.len(), 1, "only the base run fits in the budget");
    assert_eq!(
        report.explored_flips, 0,
        "no flip was executed, so none may be reported as explored"
    );
    assert!(
        report.explored_flip_keys.is_empty(),
        "no flip was executed, so no flip key may be reported"
    );
}
