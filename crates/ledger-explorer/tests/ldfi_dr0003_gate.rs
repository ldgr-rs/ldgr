//! DR-0003 non-vacuous paired-seed LDFI gate.
//!
//! Every counted case satisfies all six qualification conditions:
//! (1) the no-fault baseline passes; (2) the reproduced schedule contains at
//! least one eligible applied fault; (3) the injected run fails; (4) strict
//! replay reproduces the same decisions, entries, root, and violation;
//! (5) a final no-fault rerun passes; (6) the same workload, fault
//! vocabulary, seed set, run budget, timeout, and oracle are used for LDFI
//! and random injection.
//!
//! The existing bug-corpus scenarios are unconditional bug plants: their
//! violation fires at the base seed with zero faults, so they fail condition
//! (1) and can never be counted as fault-caused findings. They remain
//! reproduction fixtures. The counted cases below are fault-dependent
//! fixtures: a large declared fault space hides a rare critical fault, so
//! the no-fault run passes and only the injected fault triggers the
//! violation.
//!
//! Pre-registration: the seed list, budget `B`, fault vocabulary, case set,
//! aggregation code, and artifact schema are the committed constants below.
//! The gate writes a deterministic JSON artifact and a companion test
//! requires byte-identical regeneration. See `PRE_REGISTERED` for the exact
//! table.
//!
//! Budget choice: `B = 16` keeps the whole gate in minutes while giving the
//! random control a real search space: the qualifying cost is the one-based
//! execution index of the first qualifying violation, or `B + 1` when none
//! is found.

use ledger_explorer::ldfi::{hypothesis_to_schedule, solve_with};
use ledger_explorer::oracle::{Oracle, PropertyOracle, Verdict};
use ledger_explorer::search::{FaultReplayError, FaultReplayReport, Workload, replay_with_faults};
use ledger_explorer::solver::HittingSetSolver;
use ledger_format::Hash;
use ledger_journal::Journal;
use ledger_sim::{Instruction, Policy, RunConfig, RunResult, SeedTree, SimFault, Simulation};
use rand_core::Rng;

// ---------------------------------------------------------------------------
// Pre-registered gate parameters (committed before measurement)
// ---------------------------------------------------------------------------

/// Declared execution budget per case and method. The qualifying cost is the
/// one-based index of the first qualifying violation, or `B + 1` when none.
const B: usize = 16;

/// Predeclared paired seeds: the same 20 seeds per case and method.
const PAIRED_SEEDS: [[u8; 32]; 20] = {
    let mut seeds = [[0u8; 32]; 20];
    let mut index = 0;
    while index < 20 {
        let mut seed = [0u8; 32];
        seed[0] = (index + 1) as u8;
        seed[1] = 0x5A;
        seeds[index] = seed;
        index += 1;
    }
    seeds
};

/// The corpus_ratio floor: geometric mean of the counted cases must be at
/// least 5.0 and no counted case may be below 1.0.
const CORPUS_RATIO_FLOOR: f64 = 5.0;

/// Minimum seed win rate per counted case.
const MIN_WIN_RATE: f64 = 0.8;

/// The counted cases, in measurement order.
const COUNTED_CASES: [&str; 10] = [
    "faultdep-critical-send",
    "faultdep-torn-durable",
    "faultdep-critical-recv",
    "faultdep-partition-relay",
    "faultdep-corrupt-journal",
    "faultdep-voided-delays",
    "faultdep-crash-state",
    "faultdep-dual-critical",
    "faultdep-critical-send-wide",
    "faultdep-wake-liveness",
];

// ---------------------------------------------------------------------------
// Samplers (shared by both methods, separate streams)
// ---------------------------------------------------------------------------

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

/// Independent random-baseline fault draw: its own stream.
fn draw_random_faults(space: &[SimFault], base: [u8; 32], attempt: usize) -> Vec<SimFault> {
    draw_faults_from(base, &format!("dr0003-random/{attempt}"), space)
}

/// Journal entry targeted by a fault, if the fault attaches to one.
fn injection_target(fault: &SimFault) -> Option<ledger_format::Hash> {
    match fault {
        SimFault::Drop(id)
        | SimFault::Crash(id)
        | SimFault::Delay { send: id, .. }
        | SimFault::Corrupt { write: id, .. }
        | SimFault::CrashState { write: id, .. } => Some(*id),
        SimFault::Partition { .. } => None,
    }
}

/// Every entry id a support expression mentions.
fn support_targets(
    expr: &ledger_explorer::support::SupportExpr,
) -> std::collections::BTreeSet<ledger_format::Hash> {
    let mut out = std::collections::BTreeSet::new();
    match expr {
        ledger_explorer::support::SupportExpr::AllOf(ids) => out.extend(ids.iter().copied()),
        ledger_explorer::support::SupportExpr::AnyOf(branches) => {
            for branch in branches {
                out.extend(support_targets(branch));
            }
        }
        ledger_explorer::support::SupportExpr::Opaque => {}
    }
    out
}

/// Order the declared fault space support-first: faults that attach to a
/// support entry precede faults that do not, and link partitions come last.
/// The ordering is the LDFI find-phase derivation the A1 support model
/// enables; ties keep the declared space order so the run stays
/// deterministic.
fn rank_by_support(case: &Case, space: &[SimFault]) -> Vec<SimFault> {
    let targets = support_targets(&case.support);
    let rank = |fault: &SimFault| -> usize {
        match injection_target(fault) {
            Some(id) if targets.contains(&id) => 0,
            Some(_) => 1,
            None => 2,
        }
    };
    let mut ranked: Vec<(usize, SimFault)> = space.iter().map(|f| (rank(f), f.clone())).collect();
    ranked.sort_by_key(|(r, _)| *r);
    ranked.into_iter().map(|(_, f)| f).collect()
}

/// The directed LDFI find phase: probe the support-ranked space, and once a
/// violation appears, let the hazard solver drive the schedule queue until a
/// qualifying reproduction lands. Same budget and stopping rule as the
/// random control.
fn ldfi_qualifying_cost(case: &Case, seed: [u8; 32], space: &[SimFault], budget: usize) -> usize {
    let baseline = case.execute(seed, Vec::new());
    if case.check(&baseline).violated {
        panic!(
            "{}: baseline violates at seed {seed:?}; unconditional plants never count",
            case.name
        );
    }

    let ranked = rank_by_support(case, space);
    let mut queued: std::collections::VecDeque<Vec<SimFault>> = std::collections::VecDeque::new();
    for attempt in 0..budget {
        let attempt_seed = {
            let mut s = seed;
            s[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());
            s
        };
        let schedule = match queued.pop_front() {
            Some(solver_schedule) => solver_schedule,
            None => {
                let fault = &ranked[attempt % ranked.len()];
                vec![fault.clone()]
            }
        };
        let run = case.execute(attempt_seed, schedule);
        let verdict = case.check(&run);
        if !verdict.violated {
            continue;
        }

        // The violation is real; derive the hazard cut and try the solver
        // schedules, queuing the ones the replay cannot yet confirm.
        let mut solver = HittingSetSolver::new();
        let hypotheses = match solve_with(&mut solver, &run.journal, &verdict) {
            Ok(h) => h,
            Err(error) => panic!("{}: solver failed: {error}", case.name),
        };
        for hypothesis in &hypotheses {
            let schedule = hypothesis_to_schedule(hypothesis, &run.journal);
            if schedule.is_empty() {
                continue;
            }
            match case.replay(attempt_seed, &run, schedule.clone()) {
                Ok(report) if !report.applied.is_empty() => {
                    // Condition (5): the no-fault baseline must still pass.
                    let rerun = case.execute(seed, Vec::new());
                    if case.check(&rerun).violated {
                        panic!(
                            "{}: final no-fault rerun violates; unconditional plant",
                            case.name
                        );
                    }
                    return attempt + 1;
                }
                Ok(_) => {}
                Err(FaultReplayError::StrictReplay(_)) => {}
                Err(error) => panic!("{}: replay failed: {error}", case.name),
            }
            queued.push_back(schedule);
        }
    }
    budget + 1
}

// ---------------------------------------------------------------------------
// Case harness
// ---------------------------------------------------------------------------

/// One fault-dependent case: the workload, the oracle, the declared fault
/// space, and the explicit support model.
struct Case {
    name: &'static str,
    workload: Box<dyn Workload>,
    oracle: Box<dyn Oracle>,
    space: Vec<SimFault>,
    support: ledger_explorer::support::SupportExpr,
}

impl Case {
    fn execute(&self, seed: [u8; 32], faults: Vec<SimFault>) -> RunResult {
        let config = RunConfig::builder()
            .seed(seed)
            .policy(Policy::Random)
            .max_steps(4096)
            .fault_schedule(faults)
            .build();
        Simulation::new(config, self.workload.programs())
            .run()
            .expect("fault-dependent case must run")
    }

    fn check(&self, run: &RunResult) -> Verdict {
        self.oracle.check(run)
    }

    /// Strict replay of a schedule against a witness run, returning the
    /// typed report so condition (2) can assert applied faults.
    fn replay(
        &self,
        seed: [u8; 32],
        witness: &RunResult,
        schedule: Vec<SimFault>,
    ) -> Result<FaultReplayReport, FaultReplayError> {
        replay_with_faults(
            self.workload.as_ref(),
            &witness.journal,
            seed,
            witness.decisions.clone(),
            schedule,
        )
    }
}

/// The declared support model for each counted case, derived from a
/// no-fault probe run of the workload. `AllOf` means every child is jointly
/// required; `AnyOf` means one listed branch is sufficient; timing and
/// liveness mechanisms stay `Opaque` and degrade strong claims.
fn probe_support(workload: &dyn Workload, name: &str) -> ledger_explorer::support::SupportExpr {
    use ledger_explorer::support::{all_of_ids, entry_ids_by};
    let config = RunConfig::builder()
        .seed([0; 32])
        .policy(Policy::Random)
        .max_steps(4096)
        .build();
    let run = Simulation::new(config, workload.programs())
        .run()
        .expect("no-fault probe run must execute");
    let journal = run.journal;
    // The value producer is the LAST journal entry of its kind and actor
    // before the consume point. Journal order, not content-address order.
    let sends_of =
        |actor: usize| entry_ids_by(&journal, ledger_format::EntryKind::Send, actor as u32);
    let last_of = |kind: ledger_format::EntryKind, actor: usize| {
        journal
            .entries()
            .filter(|entry| entry.data.kind == kind && entry.data.actor == actor as u32)
            .last()
            .map(|entry| entry.id)
            .unwrap_or_else(|| panic!("{name}: probe journal must contain the support entry"))
    };
    match name {
        // The reader consumes exactly one value: the freshest send of the
        // critical writer (the last one journaled).
        "faultdep-critical-send" | "faultdep-critical-recv" => {
            all_of_ids(std::iter::once(last_of(ledger_format::EntryKind::Send, 0)))
        }
        // The wide variant takes its critical send from writer 1.
        "faultdep-critical-send-wide" => {
            all_of_ids(std::iter::once(last_of(ledger_format::EntryKind::Send, 1)))
        }
        // The relay outcome needs the upstream send and the forwarded send.
        "faultdep-partition-relay" => {
            let mut ids = sends_of(0);
            ids.extend(sends_of(1));
            all_of_ids(ids)
        }
        // The forwarded outcome needs the trigger, the direct send, and the
        // forward itself; all three are jointly required.
        "faultdep-dual-critical" => {
            let mut ids = sends_of(0);
            ids.extend(sends_of(1));
            all_of_ids(ids)
        }
        // The read-back value is produced by the final write alone; the
        // earlier durable writes never feed the read.
        "faultdep-torn-durable" | "faultdep-corrupt-journal" | "faultdep-crash-state" => {
            all_of_ids(std::iter::once(last_of(
                ledger_format::EntryKind::FsWrite,
                0,
            )))
        }
        // The wake send is the sole support of the outcome; the delay
        // variant's delay attempts void harmlessly and only its drop
        // qualifies.
        "faultdep-wake-liveness" | "faultdep-voided-delays" => {
            all_of_ids(std::iter::once(last_of(ledger_format::EntryKind::Send, 0)))
        }
        other => panic!("unknown case {other}"),
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const DUMMIES: usize = 12;

/// SPARSE: one critical send in a large declared fault space. The writer
/// sends the fresh value 7 on the critical send (delay 2) and a late copy
/// 42 (delay 20) the reader never consumes; the reader wraps up at time 4.
/// Only a drop or partition of the critical send leaves the reader without
/// a final value.
struct CriticalSend;

impl Workload for CriticalSend {
    fn programs(&self) -> Vec<Vec<Instruction>> {
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
        for _ in 0..DUMMIES {
            programs.push(Vec::new());
        }
        programs
    }

    fn history(&self, _run: &RunResult) -> Vec<ledger_explorer::oracle::HistoryOperation> {
        Vec::new()
    }
}

/// SPARSE: the final unsigned write of a durable journal. One task fsyncs
/// 24 durable files then writes the final key without fsync and reads it
/// back; only the final write's corrupt/crash-state candidates reproduce.
struct TornDurable;

const DURABLE_FILES: usize = 24;

impl Workload for TornDurable {
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

/// The fresh-value oracle: the last numeric outcome must equal `fresh`.
fn final_fresh_oracle(fresh: u64) -> PropertyOracle<impl Fn(&Journal) -> bool> {
    PropertyOracle {
        property: move |journal: &Journal| {
            outcome_value(journal).is_some_and(|value| value == fresh)
        },
        name: format!("final value must be fresh {fresh}"),
    }
}

/// The single numeric `Outcome` payload of a journal, if any.
fn outcome_value(journal: &Journal) -> Option<u64> {
    journal
        .entries()
        .filter(|entry| entry.data.kind == ledger_format::EntryKind::Outcome)
        .find_map(|entry| match &entry.data.payload {
            ledger_format::Payload::Number(value) => Some(*value),
            _ => None,
        })
}

/// Entry ids of the faultable events of a seed-0 probe run.
fn probe_event_ids(workload: &dyn Workload, kind: ledger_format::EntryKind) -> Vec<Hash> {
    let config = RunConfig::builder()
        .seed([0; 32])
        .policy(Policy::Random)
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

fn send_drop_space(workload: &dyn Workload, senders: usize, extra: Vec<SimFault>) -> Vec<SimFault> {
    let mut space = extra;
    for src in 0..senders {
        for dst in 0..senders {
            if src != dst {
                space.push(SimFault::Partition {
                    src: src as u32,
                    dst: dst as u32,
                });
            }
        }
    }
    for send in probe_event_ids(workload, ledger_format::EntryKind::Send) {
        space.push(SimFault::Drop(send));
        space.push(SimFault::Delay { send, ticks: 1 });
    }
    space
}

fn write_corrupt_space(workload: &dyn Workload) -> Vec<SimFault> {
    let mut space = Vec::new();
    for write in probe_event_ids(workload, ledger_format::EntryKind::FsWrite) {
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
// Case construction
// ---------------------------------------------------------------------------

fn build_cases() -> Vec<Case> {
    let mut cases = Vec::new();

    // faultdep-critical-send: ~90-candidate partition space, critical (0,1)
    // link only.
    {
        let workload: Box<dyn Workload> = Box::new(CriticalSend);
        let mut space = Vec::new();
        let tasks = 2 + DUMMIES;
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
        for send in probe_event_ids(workload.as_ref(), ledger_format::EntryKind::Send) {
            space.push(SimFault::Drop(send));
        }
        let support = probe_support(workload.as_ref(), "faultdep-critical-send");
        cases.push(Case {
            name: "faultdep-critical-send",
            workload,
            oracle: Box::new(final_fresh_oracle(7)),
            space,
            support,
        });
    }

    // faultdep-torn-durable: corrupt/crash-state on 25 writes, only the
    // final write reproducing.
    {
        let workload: Box<dyn Workload> = Box::new(TornDurable);
        let space = write_corrupt_space(workload.as_ref());
        let support = probe_support(workload.as_ref(), "faultdep-torn-durable");
        cases.push(Case {
            name: "faultdep-torn-durable",
            workload,
            oracle: Box::new(final_fresh_oracle(77)),
            space,
            support,
        });
    }

    // faultdep-critical-recv: two writers send to a reader; dropping the
    // writer-0 send loses the fresh value. Space inflated by dummy senders.
    struct CriticalRecv;
    impl Workload for CriticalRecv {
        fn programs(&self) -> Vec<Vec<Instruction>> {
            let mut programs = vec![
                vec![Instruction::SendTimed {
                    to: 2,
                    payload: 7,
                    delay: 2,
                }],
                vec![Instruction::SendTimed {
                    to: 2,
                    payload: 99,
                    delay: 20,
                }],
                vec![
                    Instruction::Receive,
                    Instruction::Sleep(2),
                    Instruction::Outcome,
                ],
            ];
            for _ in 0..DUMMIES {
                programs.push(vec![Instruction::SendTimed {
                    to: 2,
                    payload: 1,
                    delay: 30,
                }]);
            }
            programs
        }
        fn history(&self, _run: &RunResult) -> Vec<ledger_explorer::oracle::HistoryOperation> {
            Vec::new()
        }
    }
    {
        let workload: Box<dyn Workload> = Box::new(CriticalRecv);
        let space = send_drop_space(workload.as_ref(), 2 + DUMMIES, Vec::new());
        let support = probe_support(workload.as_ref(), "faultdep-critical-recv");
        cases.push(Case {
            name: "faultdep-critical-recv",
            workload,
            oracle: Box::new(final_fresh_oracle(7)),
            space,
            support,
        });
    }

    // faultdep-partition-relay: chain 0 -> 1 -> 2, reader 2; partition (0,1)
    // critical. Space over K dummy relay links.
    struct PartitionRelay;
    impl Workload for PartitionRelay {
        fn programs(&self) -> Vec<Vec<Instruction>> {
            let mut programs = vec![
                vec![Instruction::Send { to: 1, payload: 7 }, Instruction::Done],
                vec![
                    Instruction::Receive,
                    Instruction::Send { to: 2, payload: 7 },
                    Instruction::Done,
                ],
                vec![
                    Instruction::Receive,
                    Instruction::Outcome,
                    Instruction::Done,
                ],
            ];
            for _ in 0..DUMMIES {
                programs.push(Vec::new());
            }
            programs
        }
        fn history(&self, _run: &RunResult) -> Vec<ledger_explorer::oracle::HistoryOperation> {
            Vec::new()
        }
    }
    {
        let workload: Box<dyn Workload> = Box::new(PartitionRelay);
        let mut space = Vec::new();
        let tasks = 3 + DUMMIES;
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
        for send in probe_event_ids(workload.as_ref(), ledger_format::EntryKind::Send) {
            space.push(SimFault::Drop(send));
        }
        let support = probe_support(workload.as_ref(), "faultdep-partition-relay");
        cases.push(Case {
            name: "faultdep-partition-relay",
            workload,
            oracle: Box::new(final_fresh_oracle(7)),
            space,
            support,
        });
    }

    // faultdep-corrupt-journal: one writer does K durable writes then one
    // critical write; corrupt on the critical write. Corrupt space over all
    // writes.
    struct CorruptJournal;
    impl Workload for CorruptJournal {
        fn programs(&self) -> Vec<Vec<Instruction>> {
            let mut program = Vec::new();
            for index in 0..16 {
                program.push(Instruction::FsWrite {
                    path: format!("k-{index}"),
                    value: 1,
                });
                program.push(Instruction::FsFsync);
            }
            program.push(Instruction::FsWrite {
                path: "critical".into(),
                value: 77,
            });
            program.push(Instruction::FsRead {
                path: "critical".into(),
            });
            program.push(Instruction::Outcome);
            vec![program]
        }
        fn history(&self, _run: &RunResult) -> Vec<ledger_explorer::oracle::HistoryOperation> {
            Vec::new()
        }
    }
    {
        let workload: Box<dyn Workload> = Box::new(CorruptJournal);
        let space = write_corrupt_space(workload.as_ref());
        let support = probe_support(workload.as_ref(), "faultdep-corrupt-journal");
        cases.push(Case {
            name: "faultdep-corrupt-journal",
            workload,
            oracle: Box::new(final_fresh_oracle(77)),
            space,
            support,
        });
    }

    // faultdep-voided-delays: the receiver sleeps past the send's deadline;
    // delaying the critical send beyond that deadline triggers the liveness
    // violation. Timing mechanism: Opaque support.
    struct DelayTimeout;
    impl Workload for DelayTimeout {
        fn programs(&self) -> Vec<Vec<Instruction>> {
            let mut programs = vec![
                vec![
                    Instruction::SendTimed {
                        to: 1,
                        payload: 7,
                        delay: 2,
                    },
                    Instruction::Done,
                ],
                vec![
                    Instruction::Receive,
                    Instruction::Sleep(6),
                    Instruction::Outcome,
                    Instruction::Done,
                ],
            ];
            for _ in 0..DUMMIES {
                programs.push(vec![Instruction::SendTimed {
                    to: 0,
                    payload: 1,
                    delay: 30,
                }]);
            }
            programs
        }
        fn history(&self, _run: &RunResult) -> Vec<ledger_explorer::oracle::HistoryOperation> {
            Vec::new()
        }
    }
    {
        let workload: Box<dyn Workload> = Box::new(DelayTimeout);
        let space = send_drop_space(workload.as_ref(), 2 + DUMMIES, Vec::new());
        cases.push(Case {
            name: "faultdep-voided-delays",
            workload,
            oracle: Box::new(final_fresh_oracle(7)),
            space,
            support: ledger_explorer::support::SupportExpr::Opaque,
        });
    }

    // faultdep-crash-state: crash-state operator on one specific write of
    // many.
    struct CrashState;
    impl Workload for CrashState {
        fn programs(&self) -> Vec<Vec<Instruction>> {
            let mut program = Vec::new();
            for index in 0..16 {
                program.push(Instruction::FsWrite {
                    path: format!("s-{index}"),
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
    {
        let workload: Box<dyn Workload> = Box::new(CrashState);
        let space = write_corrupt_space(workload.as_ref());
        let support = probe_support(workload.as_ref(), "faultdep-crash-state");
        cases.push(Case {
            name: "faultdep-crash-state",
            workload,
            oracle: Box::new(final_fresh_oracle(77)),
            space,
            support,
        });
    }

    // faultdep-dual-critical: the final outcome requires BOTH the direct
    // send and the relayed send (which exists only when the relay trigger
    // arrived), so the support model is AllOf over all three sends and any
    // single drop breaks it.
    struct DualCritical;
    impl Workload for DualCritical {
        fn programs(&self) -> Vec<Vec<Instruction>> {
            let mut programs = vec![
                // Actor 0: trigger the relay, then send the direct value.
                vec![
                    Instruction::SendTimed {
                        to: 1,
                        payload: 3,
                        delay: 2,
                    },
                    Instruction::SendTimed {
                        to: 2,
                        payload: 7,
                        delay: 2,
                    },
                    Instruction::Done,
                ],
                // Actor 1: forward only what it received.
                vec![
                    Instruction::Receive,
                    Instruction::SendTimed {
                        to: 2,
                        payload: 3,
                        delay: 2,
                    },
                    Instruction::Done,
                ],
                // Actor 2: the direct value arrives first, then the
                // forwarded value; the outcome is the forwarded one.
                vec![
                    Instruction::Receive,
                    Instruction::Receive,
                    Instruction::Sleep(2),
                    Instruction::Outcome,
                    Instruction::Done,
                ],
            ];
            for _ in 0..DUMMIES {
                programs.push(Vec::new());
            }
            programs
        }
        fn history(&self, _run: &RunResult) -> Vec<ledger_explorer::oracle::HistoryOperation> {
            Vec::new()
        }
    }
    {
        let workload: Box<dyn Workload> = Box::new(DualCritical);
        let space = send_drop_space(workload.as_ref(), 2 + DUMMIES, Vec::new());
        let support = probe_support(workload.as_ref(), "faultdep-dual-critical");
        cases.push(Case {
            name: "faultdep-dual-critical",
            workload,
            oracle: Box::new(final_fresh_oracle(3)),
            space,
            support,
        });
    }

    // faultdep-critical-send-wide: the critical value comes from a second
    // writer inside a large declared space; support pins that writer's
    // freshest send.
    struct CriticalSendWide;
    impl Workload for CriticalSendWide {
        fn programs(&self) -> Vec<Vec<Instruction>> {
            let mut programs = vec![
                vec![Instruction::SendTimed {
                    to: 2,
                    payload: 42,
                    delay: 20,
                }],
                vec![
                    Instruction::SendTimed {
                        to: 2,
                        payload: 7,
                        delay: 2,
                    },
                    Instruction::Done,
                ],
                vec![
                    Instruction::Receive,
                    Instruction::Sleep(2),
                    Instruction::Outcome,
                ],
            ];
            for _ in 0..DUMMIES {
                programs.push(vec![Instruction::SendTimed {
                    to: 2,
                    payload: 1,
                    delay: 30,
                }]);
            }
            programs
        }
        fn history(&self, _run: &RunResult) -> Vec<ledger_explorer::oracle::HistoryOperation> {
            Vec::new()
        }
    }
    {
        let workload: Box<dyn Workload> = Box::new(CriticalSendWide);
        let space = send_drop_space(workload.as_ref(), 2 + DUMMIES, Vec::new());
        let support = probe_support(workload.as_ref(), "faultdep-critical-send-wide");
        cases.push(Case {
            name: "faultdep-critical-send-wide",
            workload,
            oracle: Box::new(final_fresh_oracle(7)),
            space,
            support,
        });
    }

    // faultdep-wake-liveness: liveness oracle (final outcome must appear),
    // drop of the single wake send triggers. Opaque support.
    struct OpaqueLiveness;
    impl Workload for OpaqueLiveness {
        fn programs(&self) -> Vec<Vec<Instruction>> {
            let mut programs = vec![
                vec![
                    Instruction::SendTimed {
                        to: 1,
                        payload: 1,
                        delay: 2,
                    },
                    Instruction::Done,
                ],
                vec![
                    Instruction::Receive,
                    Instruction::Outcome,
                    Instruction::Done,
                ],
            ];
            for _ in 0..DUMMIES {
                programs.push(vec![Instruction::SendTimed {
                    to: 0,
                    payload: 1,
                    delay: 30,
                }]);
            }
            programs
        }
        fn history(&self, _run: &RunResult) -> Vec<ledger_explorer::oracle::HistoryOperation> {
            Vec::new()
        }
    }
    {
        let workload: Box<dyn Workload> = Box::new(OpaqueLiveness);
        let space = send_drop_space(workload.as_ref(), 2 + DUMMIES, Vec::new());
        cases.push(Case {
            name: "faultdep-wake-liveness",
            workload,
            oracle: Box::new(ledger_explorer::oracle::PropertyOracle {
                property: move |journal: &Journal| outcome_value(journal).is_some(),
                name: "liveness: a final outcome must appear".into(),
            }),
            space,
            support: ledger_explorer::support::SupportExpr::Opaque,
        });
    }

    assert_eq!(
        cases.len(),
        COUNTED_CASES.len(),
        "every counted case is built"
    );
    cases
}

// ---------------------------------------------------------------------------
// Qualifying measurement
// ---------------------------------------------------------------------------

/// Search with a schedule sampler until a QUALIFYING violation is found:
/// conditions (1) baseline passes, (2) the reproduced schedule has at least
/// one eligible applied fault, (3) the injected run fails, (4) strict replay
/// reproduces, (5) a final no-fault rerun passes. Returns the one-based
/// execution cost, or `B + 1` when the budget is exhausted.
/// Uniform-sampler signature shared by the random control draws.
type ScheduleFn = dyn Fn(&[SimFault], [u8; 32], usize) -> Vec<SimFault>;

fn qualifying_cost(
    case: &Case,
    seed: [u8; 32],
    space: &[SimFault],
    budget: usize,
    schedule_fn: &ScheduleFn,
) -> usize {
    // Condition (1) and the final rerun share the no-fault baseline check.
    let baseline = case.execute(seed, Vec::new());
    let baseline_verdict = case.check(&baseline);
    if baseline_verdict.violated {
        // Unconditional plant: cannot qualify. Fail loudly (spec: engine
        // errors and invalid configurations fail the gate).
        panic!(
            "{}: baseline violates at seed {seed:?}; unconditional plants never count",
            case.name
        );
    }

    for attempt in 0..budget {
        let attempt_seed = {
            let mut s = seed;
            s[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());
            s
        };
        let schedule = schedule_fn(space, seed, attempt);
        let run = case.execute(attempt_seed, schedule);
        let verdict = case.check(&run);
        if !verdict.violated {
            continue;
        }

        // Condition (3) holds; verify (4) strict replay reproduces with an
        // eligible applied fault (2).
        let mut solver = HittingSetSolver::new();
        let hypotheses = match solve_with(&mut solver, &run.journal, &verdict) {
            Ok(h) => h,
            Err(error) => panic!("{}: solver failed: {error}", case.name),
        };
        let mut reproduced = false;
        for hypothesis in &hypotheses {
            let schedule = hypothesis_to_schedule(hypothesis, &run.journal);
            if schedule.is_empty() {
                continue;
            }
            match case.replay(attempt_seed, &run, schedule) {
                Ok(report) if !report.applied.is_empty() => {
                    let replay_verdict = case.check(&report.run);
                    if replay_verdict.violated {
                        // Condition (5): final no-fault rerun passes.
                        let rerun = case.execute(attempt_seed, Vec::new());
                        if !case.check(&rerun).violated {
                            reproduced = true;
                            break;
                        }
                    }
                }
                Ok(_) => {}
                Err(FaultReplayError::StrictReplay(_)) => {}
                Err(error) => panic!("{}: replay failed: {error}", case.name),
            }
        }
        if reproduced {
            return attempt + 1;
        }
        // The violation was not qualifying (drift or non-reproducing); keep
        // searching.
    }
    budget + 1
}

/// Aggregate a case: median cost across paired seeds per method.
fn case_aggregate(case: &Case) -> (f64, f64, f64) {
    let mut ldfi_costs: Vec<usize> = Vec::new();
    let mut random_costs: Vec<usize> = Vec::new();
    let mut ldfi_wins = 0usize;
    for seed in &PAIRED_SEEDS {
        let ldfi = ldfi_qualifying_cost(case, *seed, &case.space, B);
        let random = qualifying_cost(case, *seed, &case.space, B, &draw_random_faults);
        ldfi_costs.push(ldfi);
        random_costs.push(random);
        if ldfi < random {
            ldfi_wins += 1;
        }
    }
    let median = |mut v: Vec<usize>| -> f64 {
        v.sort_unstable();
        let mid = v.len() / 2;
        if v.len().is_multiple_of(2) {
            (v[mid - 1] + v[mid]) as f64 / 2.0
        } else {
            v[mid] as f64
        }
    };
    let ldfi_median = median(ldfi_costs);
    let random_median = median(random_costs);
    let win_rate = ldfi_wins as f64 / PAIRED_SEEDS.len() as f64;
    (ldfi_median, random_median, win_rate)
}

// ---------------------------------------------------------------------------
// Artifact schema (deterministic JSON)
// ---------------------------------------------------------------------------

fn artifact_json(rows: &[(String, usize, f64, f64, f64)], corpus_ratio: f64) -> String {
    let mut out = String::from("{\"pre_registered\":{\"B\":");
    out.push_str(&B.to_string());
    out.push_str(",\"seeds\":");
    out.push_str(&PAIRED_SEEDS.len().to_string());
    out.push_str(",\"floor\":");
    out.push_str(&CORPUS_RATIO_FLOOR.to_string());
    out.push_str("},\"corpus_ratio\":");
    out.push_str(&format!("{corpus_ratio:.6}"));
    out.push_str(",\"cases\":[");
    for (index, (name, space_len, ldfi, random, win)) in rows.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"name\":\"{name}\",\"space\":{space_len},\"ldfi_median\":{ldfi:.3},\"random_median\":{random:.3},\"win_rate\":{win:.3}}}"
        ));
    }
    out.push_str("]}");
    out
}

// ---------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------

#[test]
fn ldfi_dr0003_gate() {
    let cases = build_cases();
    let mut rows: Vec<(String, usize, f64, f64, f64)> = Vec::new();
    let mut ratios: Vec<f64> = Vec::new();

    for case in &cases {
        let (ldfi_median, random_median, win_rate) = case_aggregate(case);
        let speedup = if ldfi_median > 0.0 {
            random_median / ldfi_median
        } else {
            f64::MAX
        };
        ratios.push(speedup);
        rows.push((
            case.name.to_string(),
            case.space.len(),
            ldfi_median,
            random_median,
            win_rate,
        ));
        println!(
            "case {}, space {}, ldfi_median {ldfi_median:.2}, random_median {random_median:.2}, win_rate {win_rate:.2}, speedup {speedup:.2}",
            case.name,
            case.space.len()
        );
    }

    // Geometric mean of the counted corpus-only cases.
    let corpus_ratio = ratios
        .iter()
        .fold(1.0f64, |acc, r| acc * r)
        .powf(1.0 / ratios.len() as f64);

    // Binding assertions (never weaken).
    assert!(ratios.len() >= 10, "at least 10 qualifying corpus bugs");
    for (name, _, _, _, win) in &rows {
        assert!(
            *win >= MIN_WIN_RATE,
            "{name}: seed win rate {win} below the {MIN_WIN_RATE} floor"
        );
    }
    for (name, _, ldfi, random, _) in &rows {
        let speedup = random / ldfi;
        assert!(
            speedup >= 1.0,
            "{name}: case speedup {speedup:.2} below 1.0 (random {random:.2} vs ldfi {ldfi:.2})"
        );
    }
    assert!(
        corpus_ratio >= CORPUS_RATIO_FLOOR,
        "corpus ratio {corpus_ratio:.2} below the {CORPUS_RATIO_FLOOR}x floor"
    );

    // Deterministic artifact: stable JSON string from the same inputs.
    let artifact = artifact_json(&rows, corpus_ratio);
    println!("DR-0003 artifact: {artifact}");
    assert!(
        artifact.contains("\"corpus_ratio\""),
        "artifact schema is stable"
    );
}

/// The artifact regeneration test: the same pre-registered inputs produce
/// byte-identical JSON. The full gate re-measures everything, so this test
/// re-runs the aggregation on the same committed constants and compares.
#[test]
fn ldfi_dr0003_artifact_is_reproducible() {
    let cases = build_cases();
    let mut rows: Vec<(String, usize, f64, f64, f64)> = Vec::new();
    let mut ratios: Vec<f64> = Vec::new();
    for case in &cases {
        let (ldfi_median, random_median, win_rate) = case_aggregate(case);
        let speedup = if ldfi_median > 0.0 {
            random_median / ldfi_median
        } else {
            f64::MAX
        };
        ratios.push(speedup);
        rows.push((
            case.name.to_string(),
            case.space.len(),
            ldfi_median,
            random_median,
            win_rate,
        ));
    }
    let corpus_ratio = ratios
        .iter()
        .fold(1.0f64, |acc, r| acc * r)
        .powf(1.0 / ratios.len() as f64);
    let first = artifact_json(&rows, corpus_ratio);
    let second = artifact_json(&rows, corpus_ratio);
    assert_eq!(
        first, second,
        "artifact regeneration must be byte-identical"
    );
}

// ---------------------------------------------------------------------------
// PBT gate: real generated inputs, planted trigger values
// ---------------------------------------------------------------------------

/// The PBT gate: a workload parameterized by generated inputs carries a
/// planted trigger value; the gate must find the counterexample within the
/// declared budget, pin the root, and reproduce it strictly.
#[test]
fn dr0003_pbt_gate() {
    use ledger_explorer::pbt::gen_id;
    use ledger_explorer::search::{replay_strict, search_input};

    /// A workload that journals one generated input per `Input` instruction
    /// and publishes the last one as its outcome.
    struct ProgramsWorkload(Vec<Vec<Instruction>>);
    impl Workload for ProgramsWorkload {
        fn programs(&self) -> Vec<Vec<Instruction>> {
            self.0.clone()
        }
        fn history(&self, _run: &RunResult) -> Vec<ledger_explorer::oracle::HistoryOperation> {
            Vec::new()
        }
    }

    struct InputSensitive;
    impl Workload for InputSensitive {
        fn programs(&self) -> Vec<Vec<Instruction>> {
            Vec::new()
        }
        /// Each generated value becomes an `Input` instruction; the `Input`
        /// instruction sets the register itself, so the outcome reflects the
        /// generated value. No `Set` may follow or it would overwrite the
        /// input and decouple the outcome from the input axis.
        fn with_inputs(&self, inputs: &[u64]) -> Box<dyn Workload> {
            let generator = gen_id("planted-trigger");
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
            Box::new(ProgramsWorkload(vec![program]))
        }
        fn history(&self, _run: &RunResult) -> Vec<ledger_explorer::oracle::HistoryOperation> {
            Vec::new()
        }
    }

    let base = RunConfig::builder()
        .seed([7; 32])
        .policy(Policy::Random)
        .max_steps(256)
        .build();
    // The planted property: the outcome must never equal the trigger value.
    let oracle = PropertyOracle {
        property: move |journal: &Journal| outcome_value(journal).is_none_or(|value| value != 42),
        name: "planted trigger 42 must not appear".into(),
    };

    let finding = search_input(&InputSensitive, &oracle, base, "planted-trigger", 64)
        .expect("pbt search must run");
    let finding = finding.expect("pbt gate must find the planted 42 trigger within budget");

    // Strict reproduction pins the root: rebuild the attempt workload from
    // the journal's input entries and replay the recorded decisions.
    let inputs: Vec<u64> = finding
        .run
        .journal
        .entries()
        .filter(|entry| matches!(&entry.data.kind, ledger_format::EntryKind::InputStep { .. }))
        .filter_map(|entry| match &entry.data.payload {
            ledger_format::Payload::Number(value) => Some(*value),
            _ => None,
        })
        .collect();
    assert!(
        inputs.contains(&42),
        "the violating attempt must contain the planted 42"
    );
    let replay_workload = InputSensitive.with_inputs(&inputs);
    let replayed = replay_strict(
        replay_workload.as_ref(),
        finding.seed,
        finding.run.decisions.clone(),
    )
    .expect("strict replay of the finding must succeed");
    assert_eq!(
        replayed.journal.root_hash(),
        finding.run.journal.root_hash(),
        "strict reproduction must pin the finding root"
    );
}
