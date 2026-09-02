//! LDFI efficiency measurement: 12 bug-corpus-v1 scenarios (shared
//! registry) plus four clearly-labeled synthetic scenarios, measured with an
//! INDEPENDENT random-schedule control.
//!
//! This file is MEASUREMENT TOOLING, not an efficiency gate. The corpus-v1
//! plants are unconditional: their violations fire with zero faults, so they
//! cannot carry fault-causation or LDFI-efficiency claims. The binding
//! efficiency gate is the pre-registered DR-0003 gate over fault-triggered
//! scenarios (`ldfi_dr0003_gate.rs`), and the fault-triggered corpus-v2 set
//! carries the non-vacuous counting (`corpus_v2_gate.rs`).
//!
//! What is measured, exactly:
//!
//! - FIND phase, both sides sample the scenario's declared fault space
//!   (candidate partitions, drops, delays, corrupts). The random baseline
//!   draws its schedules from its OWN seeded stream (label
//!   `efficiency-random-search/<name>`), never from LDFI's stream; LDFI's
//!   search phase draws from `efficiency-faults/<attempt>` as before. Both
//!   sides get the same search budget per leg (64 for corpus and synthetic
//!   legs, 256 for the sparse-schedule legs, whose trigger schedules are
//!   rare). The cost is executions to the first oracle violation, or the
//!   full budget when none is found.
//! - REPRODUCE phase: from the LDFI-found witness run, LDFI calls
//!   `solve_with(&mut HittingSetSolver::new(), &journal, &verdict)`,
//!   converts ranked hypotheses to fault schedules with
//!   `hypothesis_to_schedule`, and replays them until the violation
//!   reproduces (cap 8 executions). The random control replays random
//!   schedules from the SAME fault space against the SAME witness run,
//!   drawn from its own seeded stream (`efficiency-random-control/<name>`)
//!   with the same 0..=2 fault-count distribution and length 200 (the
//!   reproduce-phase effort budget; a control that exhausts its budget is
//!   counted at 200, a conservative lower bound on its true cost). Costs are
//!   executions, so the faults-to-bug ratio is
//!   `control_reproduce / ldfi_reproduce`.
//!
//! What is asserted:
//!
//! 1. Every leg is found by LDFI's search phase within its budget.
//! 2. Nothing else. Per-leg reproduce ratios and the corpus-only aggregate
//!    are PRINTED as data and never asserted: the corpus plants fire without
//!    faults, so their ratios carry no efficiency claim, and a false 5x
//!    claim is never constructed by tilting a sampler.
//!
//! Scenario fixture seeds are pinned (like the corpus manifests) because
//! fault reproduction is schedule-dependent; the measured costs at those
//! seeds are still real executions.

use ledger_explorer::Verdict;
use ledger_explorer::reference::ReferenceReplayError;
use ledger_explorer::reference::{CorpusScenario, corpus_scenarios};
use ledger_explorer::search::Workload;
use ledger_format::{CanonicalValue, EntryPayload};
use ledger_sim::{Instruction, RunConfig, RunResult, SeedTree, SimFault, Simulation};
use rand_core::Rng;

const SEARCH_BUDGET: usize = 64;
const REPLAY_BUDGET: usize = 8;
/// Reproduce-phase effort budget of the independent random control.
const RANDOM_CONTROL_BUDGET: usize = 200;
/// Search budget for legs whose reproducing schedule is rare in a large
/// fault space; applied to BOTH sides at matched effort.
const SPARSE_SEARCH_BUDGET: usize = 256;

/// Legs reported with the sparse search budget. The sparse-schedule legs are
/// the regime where LDFI's causal ranking shows: a large declared fault
/// space, a rare trigger schedule, and a witness journal that the
/// hitting-set solver ranks correctly.
const SPARSE_LEGS: [&str; 2] = [
    "synthetic-sparse-critical-send",
    "synthetic-sparse-torn-durable-write",
];

// ---------------------------------------------------------------------------
// Samplers
// ---------------------------------------------------------------------------

/// The find-phase seed derivation, shared by both sides so the attempt
/// streams differ only in the fault draws.
fn attempt_seed(base: [u8; 32], attempt: usize) -> [u8; 32] {
    let mut seed = base;
    seed[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());
    seed
}

/// Draw 0..=2 distinct faults from the declared space on one seeded stream.
fn draw_faults_from(seed: [u8; 32], label: &str, space: &[SimFault]) -> Vec<SimFault> {
    let mut rng = SeedTree::new(seed).rng(label);
    let count = (rng.next_u64() as usize) % 3;
    let mut chosen: Vec<SimFault> = Vec::new();
    let mut used: Vec<usize> = Vec::new();
    while chosen.len() < count && chosen.len() < space.len() {
        let index = (rng.next_u64() as usize) % space.len();
        if !used.contains(&index) {
            used.push(index);
            chosen.push(space[index].clone());
        }
    }
    chosen
}

/// LDFI find-phase fault draw (the historical sampler).
fn draw_faults(space: &[SimFault], base: [u8; 32], attempt: usize) -> Vec<SimFault> {
    draw_faults_from(base, &format!("efficiency-faults/{attempt}"), space)
}

/// INDEPENDENT random-baseline fault draw: its own stream, separate from
/// every LDFI stream, same 0..=2 distribution over the same space.
fn draw_random_baseline_faults(
    space: &[SimFault],
    base: [u8; 32],
    attempt: usize,
) -> Vec<SimFault> {
    draw_faults_from(base, &format!("efficiency-random-search/{attempt}"), space)
}

/// INDEPENDENT reproduce-phase control draw: its own stream, per leg, so no
/// leg shares a control stream with another leg or with any LDFI stream.
fn draw_control_schedule(
    space: &[SimFault],
    base: [u8; 32],
    leg: &str,
    attempt: usize,
) -> Vec<SimFault> {
    draw_faults_from(
        base,
        &format!("efficiency-random-control/{leg}/{attempt}"),
        space,
    )
}

// ---------------------------------------------------------------------------
// Scenario harness
// ---------------------------------------------------------------------------

/// How one scenario executes and replays. Registry scenarios delegate to
/// the shared `CorpusScenario` mechanics; the synthetic workloads keep the
/// program-workload path (recorded-decision replay with injected faults).
enum Harness<'a> {
    Corpus(&'a CorpusScenario),
    Synthetic {
        workload: Box<dyn Workload>,
        oracle: Box<dyn ledger_explorer::oracle::Oracle>,
    },
}

impl Harness<'_> {
    fn execute(&self, seed: [u8; 32], faults: Vec<SimFault>) -> RunResult {
        match self {
            Harness::Corpus(scenario) => scenario
                .run(seed, faults)
                .expect("corpus scenario must run"),
            Harness::Synthetic { workload, .. } => {
                let config = RunConfig::builder()
                    .seed(seed)
                    .policy(ledger_sim::Policy::Random)
                    .max_steps(4096)
                    .fault_schedule(faults)
                    .build();
                Simulation::new(config, workload.programs())
                    .run()
                    .expect("workload simulation must run")
            }
        }
    }

    fn check(&self, run: &RunResult) -> Verdict {
        match self {
            Harness::Corpus(scenario) => scenario.check(run),
            Harness::Synthetic { oracle, .. } => oracle.check(run),
        }
    }

    /// Replay one fault schedule against the recorded witness run. Registry
    /// scenarios use the registry's witness-cut mechanics; synthetic
    /// workloads follow the recorded decisions via strict replay.
    /// Strict violations (drift or trailing) are the Wave 1 evidence that
    /// the schedule is not replayable; callers treat that as not reproduced.
    fn replay_faults(
        &self,
        found_seed: [u8; 32],
        witness: &RunResult,
        schedule: Vec<SimFault>,
    ) -> Option<RunResult> {
        match self {
            Harness::Corpus(scenario) => {
                match scenario.replay_faults(found_seed, witness, schedule) {
                    Ok(run) => Some(run),
                    Err(ReferenceReplayError::Engine {
                        source: ledger_sim::RuntimeError::StrictReplay(_),
                        ..
                    }) => None,
                    Err(error) => panic!("corpus fault replay must run: {error}"),
                }
            }
            Harness::Synthetic { workload, .. } => {
                let config = RunConfig::builder()
                    .seed(found_seed)
                    .policy(ledger_sim::Policy::Replay)
                    .fault_schedule(schedule)
                    .max_steps(witness.decisions.len().saturating_add(256))
                    .build();
                match Simulation::with_replay_strict(
                    config,
                    workload.programs(),
                    witness.decisions.clone(),
                )
                .run()
                {
                    Ok(run) => Some(run),
                    Err(ledger_sim::RuntimeError::StrictReplay(_)) => None,
                    Err(other) => panic!("workload fault replay must run: {other}"),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

struct Row {
    name: String,
    space_len: usize,
    search_budget: usize,
    random_search_found: bool,
    random_search_execs: usize,
    ldfi_find_execs: usize,
    ldfi_replay_execs: usize,
    reproduced: bool,
    control_reproduce_execs: usize,
}

impl Row {
    /// The honest faults-to-bug ratio of the reproduce phase.
    fn reproduce_ratio(&self) -> f64 {
        self.control_reproduce_execs.max(1) as f64 / self.ldfi_replay_execs.max(1) as f64
    }
}

/// A fault-draw sampler: (space, base seed, attempt) -> schedule.
type FaultDraw = dyn Fn(&[SimFault], [u8; 32], usize) -> Vec<SimFault>;

/// Shared search loop for both the random baseline and LDFI phase 1: the
/// identical seed derivation and fault-count distribution, each side on its
/// OWN stream, so the two costs are independent draws of the same sampler.
fn search_with_sampler(
    harness: &Harness,
    base: [u8; 32],
    space: &[SimFault],
    budget: usize,
    faults: &FaultDraw,
) -> Option<(RunResult, Verdict, [u8; 32], usize)> {
    for attempt in 0..budget {
        let seed = attempt_seed(base, attempt);
        let schedule = faults(space, base, attempt);
        let run = harness.execute(seed, schedule);
        let verdict = harness.check(&run);
        if verdict.violated {
            return Some((run, verdict, seed, attempt + 1));
        }
    }
    None
}

/// Replay ranked hypotheses (full schedule, then single injections) until the
/// oracle violation reproduces. Returns the number of replay executions
/// spent; 0 with `None` verdict means no reproduction within budget.
fn replay_until_reproduction(
    harness: &Harness,
    found_seed: [u8; 32],
    witness: &RunResult,
    verdict: &Verdict,
    solver: &mut dyn ledger_explorer::solver::FaultSolver,
) -> (usize, Option<Verdict>) {
    let hypotheses: Vec<ledger_explorer::ldfi::FaultHypothesis> =
        ledger_explorer::ldfi::solve_with(solver, &witness.journal, verdict).expect("solve");
    let mut execs = 0usize;
    for hypothesis in &hypotheses {
        let schedule = ledger_explorer::ldfi::hypothesis_to_schedule(hypothesis, &witness.journal);
        if schedule.is_empty() {
            continue;
        }
        execs += 1;
        if execs > REPLAY_BUDGET {
            break;
        }
        let Some(replay) = harness.replay_faults(found_seed, witness, schedule.clone()) else {
            // Strict violation is not a reproduction; count the execution and try next.
            continue;
        };
        let replay_verdict = harness.check(&replay);
        if replay_verdict.violated {
            return (execs, Some(replay_verdict));
        }
        for injection in &schedule {
            execs += 1;
            if execs > REPLAY_BUDGET {
                break;
            }
            let Some(replay) = harness.replay_faults(found_seed, witness, vec![injection.clone()])
            else {
                continue;
            };
            let replay_verdict = harness.check(&replay);
            if replay_verdict.violated {
                return (execs, Some(replay_verdict));
            }
        }
    }
    (execs.min(REPLAY_BUDGET), None)
}

/// The independent random-schedule reproduce control: replay schedules from
/// the same declared fault space against the same witness run, drawn from
/// the control's own seeded stream. Returns executions to first violation,
/// or `RANDOM_CONTROL_BUDGET` when the budget is exhausted. Strict
/// violations are counted as non-reproducing executions.
fn random_control_reproduce(
    harness: &Harness,
    name: &str,
    base: [u8; 32],
    space: &[SimFault],
    found_seed: [u8; 32],
    witness: &RunResult,
) -> usize {
    for attempt in 0..RANDOM_CONTROL_BUDGET {
        let schedule = draw_control_schedule(space, base, name, attempt);
        let Some(replay) = harness.replay_faults(found_seed, witness, schedule) else {
            continue;
        };
        if harness.check(&replay).violated {
            return attempt + 1;
        }
    }
    RANDOM_CONTROL_BUDGET
}

fn measure(
    name: &str,
    harness: &Harness,
    base: [u8; 32],
    space: &[SimFault],
    search_budget: usize,
    solver: &mut dyn ledger_explorer::solver::FaultSolver,
) -> Row {
    let random_search = search_with_sampler(
        harness,
        base,
        space,
        search_budget,
        &draw_random_baseline_faults,
    );
    let (random_search_found, random_search_execs) = match random_search {
        Some((_, _, _, execs)) => (true, execs),
        None => (false, search_budget),
    };

    let ldfi = search_with_sampler(harness, base, space, search_budget, &draw_faults);
    let (ldfi_find_execs, ldfi_replay_execs, reproduced, control_reproduce_execs) = match ldfi {
        Some((witness, verdict, seed, execs)) => {
            let (replay_execs, replay_verdict) =
                replay_until_reproduction(harness, seed, &witness, &verdict, solver);
            let control = random_control_reproduce(harness, name, base, space, seed, &witness);
            (
                execs,
                replay_execs,
                replay_verdict.is_some_and(|v| v.violated),
                control,
            )
        }
        None => (search_budget, 0, false, 0),
    };

    Row {
        name: name.to_string(),
        space_len: space.len(),
        search_budget,
        random_search_found,
        random_search_execs,
        ldfi_find_execs,
        ldfi_replay_execs,
        reproduced,
        control_reproduce_execs,
    }
}

// ---------------------------------------------------------------------------
// Synthetic workloads (clearly named, no corpus provenance claims)
// ---------------------------------------------------------------------------

/// Two fsynced writes to one path; the oracle requires the durable final
/// value. The bug class is silent corruption of the not-yet-fsynced final
/// write (bit-rot / torn write), declared as corrupt-class faults.
struct CorruptTornWrite {
    first: u64,
    second: u64,
}

impl Workload for CorruptTornWrite {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        vec![vec![
            Instruction::FsWrite {
                path: "state.db".into(),
                value: self.first,
            },
            Instruction::FsFsync,
            Instruction::FsWrite {
                path: "state.db".into(),
                value: self.second,
            },
            Instruction::FsRead {
                path: "state.db".into(),
            },
            Instruction::Outcome,
            Instruction::Done,
        ]]
    }

    fn history(&self, _run: &RunResult) -> Vec<ledger_explorer::oracle::HistoryOperation> {
        Vec::new()
    }
}

/// Four-task relay: client sends the fresh value to the primary (and a stale
/// value straight to the reader); the primary forwards through a secondary.
/// The reader outputs whichever value arrives first, so a stale read happens
/// whenever the two-hop fresh path loses the race.
struct RelayStaleRead;

impl Workload for RelayStaleRead {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        vec![
            vec![
                Instruction::Send { to: 1, payload: 7 },
                Instruction::Send { to: 3, payload: 3 },
                Instruction::Done,
            ],
            vec![
                Instruction::Receive,
                Instruction::Send { to: 2, payload: 7 },
                Instruction::Done,
            ],
            vec![
                Instruction::Receive,
                Instruction::Send { to: 3, payload: 7 },
                Instruction::Done,
            ],
            vec![
                Instruction::Receive,
                Instruction::Outcome,
                Instruction::Done,
            ],
        ]
    }

    fn history(&self, _run: &RunResult) -> Vec<ledger_explorer::oracle::HistoryOperation> {
        Vec::new()
    }
}

/// SPARSE: one critical send in a large declared fault space.
///
/// The writer delivers two messages to the reader: the fresh value 7 on the
/// critical send (virtual time 2) and a late copy 42 (virtual time 20) that
/// the reader never consumes. The reader wraps up at time 4, so the late
/// copy is irrelevant: only a drop or partition of the CRITICAL send leaves
/// the reader without a final value. Eight dummy tasks never communicate;
/// their only role is to inflate the declared partition space to 90 directed
/// pairs. The journal causality stays tiny (one writer chain, one reader
/// chain), so the solver never faces a path explosion. The liveness oracle
/// fires on a missing final outcome, which is what a blocked reader
/// journaled nothing produces.
struct SparseCriticalSend;

/// Dummy tasks inflate the declared partition space without adding any
/// causal path to the witness.
const SPARSE_PARTITION_DUMMIES: usize = 8;

impl Workload for SparseCriticalSend {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        // Task roles: 0 writer, 1 reader, 2..9 partition-space dummies.
        let mut programs = vec![
            vec![
                Instruction::SendTimed {
                    to: 1,
                    payload: 42,
                    delay: 20,
                },
                Instruction::SendTimed {
                    to: 1,
                    payload: 7,
                    delay: 2,
                },
            ],
            vec![
                Instruction::Receive,
                Instruction::Sleep(2),
                Instruction::Outcome,
            ],
        ];
        for _ in 0..SPARSE_PARTITION_DUMMIES {
            programs.push(Vec::new());
        }
        programs
    }

    fn history(&self, _run: &RunResult) -> Vec<ledger_explorer::oracle::HistoryOperation> {
        Vec::new()
    }
}

/// SPARSE: the final unsigned write of a durable journal.
///
/// One task fsyncs 24 durable files, then writes the final key without
/// fsync, reads it back, and outputs the value. The declared fault space
/// covers corrupt and crash-state candidates on every probe write (75
/// candidates); only the final write's candidates reproduce the bug. A
/// single-task program has byte-stable entry ids across run seeds, so the
/// probe-derived ids apply in every run. The witness's read support is the
/// direct FsRead entry, and the gate solves this leg with a bounded horizon
/// of 2: the derivation paths stop at the read's direct parent, so the
/// ranked cut is exactly the read support, and reproduction is
/// deterministic within one replay execution.
struct SparseTornDurableWrite;

const DURABLE_FILES: usize = 24;

impl Workload for SparseTornDurableWrite {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        let mut program = Vec::with_capacity(DURABLE_FILES * 2 + 4);
        for index in 0..DURABLE_FILES {
            program.push(Instruction::FsWrite {
                path: format!("blob-{index}"),
                value: 42,
            });
            program.push(Instruction::FsFsync);
        }
        program.push(Instruction::FsWrite {
            path: "final".into(),
            value: 77,
        });
        program.push(Instruction::FsRead {
            path: "final".into(),
        });
        program.push(Instruction::Outcome);
        vec![program]
    }

    fn history(&self, _run: &RunResult) -> Vec<ledger_explorer::oracle::HistoryOperation> {
        Vec::new()
    }
}

/// Violated only when a read actually happened and returned a non-fresh
/// value; a blocked run (no outcome) passes, so over-blocking replays cannot
/// satisfy this oracle vacuously.
fn fresh_read_oracle(
    fresh: u64,
) -> ledger_explorer::oracle::PropertyOracle<impl Fn(&ledger_journal::Journal) -> bool> {
    ledger_explorer::oracle::PropertyOracle {
        property: move |journal: &ledger_journal::Journal| {
            let outcome = outcome_value(journal);
            !matches!(outcome, Some(value) if value != fresh)
        },
        name: format!("read sees fresh value {fresh}"),
    }
}

/// Liveness-flavored final-value oracle: the last numeric outcome must equal
/// `fresh`. A missing outcome is a violation: the complaint target stopped
/// before producing its result, which is exactly what a blocked reader or a
/// lost durable read journals.
fn final_fresh_oracle(
    fresh: u64,
) -> ledger_explorer::oracle::PropertyOracle<impl Fn(&ledger_journal::Journal) -> bool> {
    ledger_explorer::oracle::PropertyOracle {
        property: move |journal: &ledger_journal::Journal| {
            outcome_value(journal).is_some_and(|value| value == fresh)
        },
        name: format!("final value must be fresh {fresh}"),
    }
}

/// The single numeric `Outcome` payload of a journal, if any.
fn outcome_value(journal: &ledger_journal::Journal) -> Option<u64> {
    journal
        .entries()
        .filter(|entry| entry.data.kind == ledger_format::EntryKind::Outcome)
        .find_map(|entry| match &entry.data.payload {
            EntryPayload::Outcome(ledger_format::OutcomePayload {
                value: CanonicalValue::Unsigned(value),
                ..
            }) => Some(*value),
            _ => None,
        })
}

/// Entry ids of the faultable events of a seed-0 probe run, used to declare
/// the candidate fault spaces of the synthetic workloads. A single-task
/// program is fully deterministic, so these ids are stable across run seeds;
/// the probe uses no knowledge of any violating run.
fn probe_event_ids(
    workload: &dyn Workload,
    kind: ledger_format::EntryKind,
) -> Vec<ledger_format::Hash> {
    let config = RunConfig::builder()
        .seed([0; 32])
        .policy(ledger_sim::Policy::Random)
        .max_steps(4096)
        .build();
    let run = Simulation::new(config, workload.programs())
        .run()
        .expect("probe run must execute");
    run.journal
        .entries()
        .filter(|entry| entry.data.kind == kind)
        .map(|entry| entry.id)
        .collect()
}

/// The sparse-critical-send fault space: partitions over every directed pair
/// of the ten tasks (the dummy tasks carry no traffic, so these candidates
/// are inert except the critical (0,1) link) plus drop and delay candidates
/// on the two probe sends.
fn sparse_critical_send_fault_space() -> Vec<SimFault> {
    let tasks = 2 + SPARSE_PARTITION_DUMMIES;
    let mut space = Vec::new();
    for src in 0..tasks {
        for dst in 0..tasks {
            if src != dst {
                space.push(SimFault::Partition {
                    src: src as u32,
                    dst: dst as u32,
                });
            }
        }
    }
    for send in probe_event_ids(&SparseCriticalSend, ledger_format::EntryKind::Send) {
        space.push(SimFault::Drop(send));
        space.push(SimFault::Delay { send, ticks: 1 });
    }
    space
}

/// The sparse-torn-durable-write fault space: corrupt and crash-state
/// candidates on every probe write.
fn sparse_torn_durable_fault_space() -> Vec<SimFault> {
    let mut space = Vec::new();
    for write in probe_event_ids(&SparseTornDurableWrite, ledger_format::EntryKind::FsWrite) {
        space.push(SimFault::Corrupt { write, xor_mask: 1 });
        space.push(SimFault::Corrupt {
            write,
            xor_mask: 0xFF,
        });
        space.push(SimFault::CrashState { write, state: 0 });
    }
    space
}

// ---------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------

#[test]
fn ldfi_efficiency_gate() {
    let mut rows: Vec<Row> = Vec::new();

    // The twelve registry corpus scenarios, same runners, oracles, seeds,
    // and fault spaces as the corpus gates.
    for scenario in corpus_scenarios() {
        let space = (scenario.fault_space)()
            .unwrap_or_else(|error| panic!("{}: fault space: {error}", scenario.name));
        assert!(
            !space.is_empty(),
            "{}: the declared fault space must be non-empty",
            scenario.name
        );
        let harness = Harness::Corpus(&scenario);
        rows.push(measure(
            scenario.name,
            &harness,
            scenario.base_seed,
            &space,
            SEARCH_BUDGET,
            &mut ledger_explorer::solver::HittingSetSolver::new(),
        ));
    }

    // synthetic-corrupt-torn-write: corrupt-class fault space on both writes.
    {
        let workload = CorruptTornWrite {
            first: 42,
            second: 999,
        };
        let writes = probe_event_ids(&workload, ledger_format::EntryKind::FsWrite);
        assert_eq!(writes.len(), 2, "corrupt scenario has exactly two writes");
        let mut space = Vec::new();
        for write in &writes {
            space.push(SimFault::Corrupt {
                write: *write,
                xor_mask: 1,
            });
            space.push(SimFault::Corrupt {
                write: *write,
                xor_mask: 0xFF,
            });
        }
        space.push(SimFault::Corrupt {
            write: writes[1],
            xor_mask: 0xFFFF,
        });
        let harness = Harness::Synthetic {
            workload: Box::new(workload),
            oracle: Box::new(fresh_read_oracle(999)),
        };
        rows.push(measure(
            "synthetic-corrupt-torn-write",
            &harness,
            [21; 32],
            &space,
            SEARCH_BUDGET,
            &mut ledger_explorer::solver::HittingSetSolver::new(),
        ));
    }

    // synthetic-relay-stale-read: partitions plus drop/delay on every send.
    {
        let workload = RelayStaleRead;
        let mut space: Vec<SimFault> = [(0, 1), (0, 2), (1, 0), (1, 2), (2, 0), (2, 1)]
            .iter()
            .map(|&(src, dst)| SimFault::Partition { src, dst })
            .collect();
        for send in probe_event_ids(&workload, ledger_format::EntryKind::Send) {
            space.push(SimFault::Drop(send));
            space.push(SimFault::Delay { send, ticks: 1 });
        }
        let harness = Harness::Synthetic {
            workload: Box::new(workload),
            oracle: Box::new(fresh_read_oracle(7)),
        };
        rows.push(measure(
            "synthetic-relay-stale-read",
            &harness,
            [31; 32],
            &space,
            SEARCH_BUDGET,
            &mut ledger_explorer::solver::HittingSetSolver::new(),
        ));
    }

    // synthetic-sparse-critical-send: a ~90-candidate partition space where
    // only the critical (0,1) link's drop or partition reproduces the bug.
    {
        let space = sparse_critical_send_fault_space();
        assert!(
            space.len() >= 90,
            "the sparse leg needs a large declared fault space, got {}",
            space.len()
        );
        let harness = Harness::Synthetic {
            workload: Box::new(SparseCriticalSend),
            oracle: Box::new(final_fresh_oracle(7)),
        };
        rows.push(measure(
            "synthetic-sparse-critical-send",
            &harness,
            [41; 32],
            &space,
            SPARSE_SEARCH_BUDGET,
            &mut ledger_explorer::solver::HittingSetSolver::new(),
        ));
    }

    // synthetic-sparse-torn-durable-write: corrupt/crash-state candidates on
    // 25 writes, only the final unsigned write reproducing the bug. The
    // witness read support is the direct FsRead entry, so this leg's solver
    // is bounded to horizon 2: the ranked cut is exactly the read support
    // and reproduces deterministically within the replay budget.
    {
        let space = sparse_torn_durable_fault_space();
        assert!(
            space.len() >= 60,
            "the sparse leg needs a large declared fault space, got {}",
            space.len()
        );
        let harness = Harness::Synthetic {
            workload: Box::new(SparseTornDurableWrite),
            oracle: Box::new(final_fresh_oracle(77)),
        };
        rows.push(measure(
            "synthetic-sparse-torn-durable-write",
            &harness,
            [51; 32],
            &space,
            SPARSE_SEARCH_BUDGET,
            &mut ledger_explorer::solver::HittingSetSolver::with_horizon(2),
        ));
    }

    assert_eq!(
        rows.len(),
        16,
        "gate covers 12 corpus + 4 synthetic scenarios"
    );

    // Assertion 1: every leg found by LDFI's own search within its matched
    // budget. No reproduction or ratio claim is asserted here: the corpus
    // plants are unconditional (their violations fire with zero faults), so
    // they cannot carry fault-causation or efficiency claims. The binding
    // efficiency gate over fault-triggered scenarios is the DR-0003 gate
    // (`ldfi_dr0003_gate.rs`); this file stays as measurement tooling.
    for row in &rows {
        assert!(
            row.ldfi_find_execs < row.search_budget,
            "{}: LDFI search must find the violation within its {} execution budget (cost {})",
            row.name,
            row.search_budget,
            row.ldfi_find_execs
        );
        if !row.reproduced {
            println!(
                "note: {} LDFI hypothesis replay did not reproduce within budget \
                 (find cost {}, replay {}); recorded, not counted",
                row.name, row.ldfi_find_execs, row.ldfi_replay_execs
            );
        }
    }

    // Honest reporting: per-leg and aggregate costs and ratios, printed
    // only. The corpus legs' bug classes fire without faults, so their
    // ratios carry no efficiency claim; the aggregate is data, not a gate.
    println!(
        "leg, space, random_search_found, random_search, ldfi_find, ldfi_replay, control_reproduce, ratio"
    );
    for row in &rows {
        println!(
            "{}, {}, {}, {}, {}, {}, {}, {:.2}",
            row.name,
            row.space_len,
            row.random_search_found,
            row.random_search_execs,
            row.ldfi_find_execs,
            row.ldfi_replay_execs,
            row.control_reproduce_execs,
            row.reproduce_ratio(),
        );
    }
    let aggregate_control: usize = rows.iter().map(|row| row.control_reproduce_execs).sum();
    let aggregate_ldfi: usize = rows.iter().map(|row| row.ldfi_replay_execs.max(1)).sum();
    let aggregate_ratio = aggregate_control as f64 / aggregate_ldfi as f64;
    let non_sparse: Vec<&Row> = rows
        .iter()
        .filter(|row| !SPARSE_LEGS.contains(&row.name.as_str()))
        .collect();
    let corpus_control: usize = non_sparse
        .iter()
        .map(|row| row.control_reproduce_execs)
        .sum();
    let corpus_ldfi: usize = non_sparse
        .iter()
        .map(|row| row.ldfi_replay_execs.max(1))
        .sum();
    let corpus_ratio = corpus_control as f64 / corpus_ldfi as f64;
    println!(
        "aggregate: control={aggregate_control} ldfi={aggregate_ldfi} ratio={aggregate_ratio:.2}; \
         corpus-only (12 corpus + 2 synthetic) ratio={corpus_ratio:.2} (reported, not asserted)"
    );
}
