//! Search-axis tests: quadruple mutation, swarm axis, bandit campaign
//! scheduling, and the joint campaign, plus PLANTED counterexamples for the
//! three documented search axes: linearizability, quorum, and exactly-once.
//!
//! The planted tests are behavioral: each axis oracle must fire on the
//! planted violation deterministically (pinned seeds, forced virtual-time
//! ordering), and the same oracle must pass on the control workload.

use ledger_explorer::oracle::{
    ExactlyOnceValueOracle, HistoryOperation, HistoryOracle, KeyValueSpec, LinearizabilityOracle,
    Oracle, PropertyOracle, Verdict,
};
use ledger_explorer::search::{
    QuadBandit, QuadMutation, Workload, run_bandit_campaign, run_campaign_quad, run_joint_campaign,
    run_swarm_campaign, search,
};
use ledger_explorer::workloads::{MiniKvWorkload, StorageCrashWorkload};
use ledger_format::{CanonicalValue, EntryKind, EntryPayload};
use ledger_journal::Journal;
use ledger_sim::{Instruction, Policy, RunConfig, RunResult, SimFault, Simulation, SwarmConfig};

fn mini_kv_base(seed: u8) -> RunConfig {
    RunConfig::builder()
        .seed([seed; 32])
        .policy(Policy::Random)
        .max_steps(256)
        .build()
}

#[test]
fn quad_campaign_mutates_all_axes() {
    let base = mini_kv_base(4);
    let oracle = HistoryOracle::new(&MiniKvWorkload, KeyValueSpec::default());
    let mutation = QuadMutation {
        policies: vec![
            Policy::Random,
            Policy::Bandit {
                exploration_constant: 1.0,
                pct_mix: ledger_sim::Probability::new(0.1).unwrap(),
            },
        ],
        use_swarm: true,
        swarm_budget: 8,
        fault_library: Vec::new(),
        max_faults_per_run: 0,
        ..Default::default()
    };

    let report = run_campaign_quad(&MiniKvWorkload, &oracle, base.clone(), &mutation, 20)
        .expect("quad campaign must run");
    assert_eq!(report.runs_executed, 20);
    assert!(
        report
            .variants
            .iter()
            .any(|variant| variant.contains("policy=Random")),
        "Random policy must be drawn"
    );
    assert!(
        report
            .variants
            .iter()
            .any(|variant| variant.contains("policy=Bandit")),
        "Bandit policy must be drawn"
    );

    let again = run_campaign_quad(&MiniKvWorkload, &oracle, base, &mutation, 20)
        .expect("quad campaign rerun must run");
    assert_eq!(report.distinct_roots, again.distinct_roots);
    assert_eq!(report.variants, again.variants);
    assert_eq!(report.findings.len(), again.findings.len());
}

#[test]
fn swarm_campaign_finds_violation() {
    let base = mini_kv_base(9);
    let oracle = PropertyOracle {
        property: |journal: &Journal| {
            journal
                .entries()
                .all(|entry| match (&entry.data.kind, &entry.data.payload) {
                    (
                        EntryKind::Outcome,
                        EntryPayload::Outcome(ledger_format::OutcomePayload {
                            value: CanonicalValue::Unsigned(value),
                            ..
                        }),
                    ) => *value == 42,
                    _ => true,
                })
        },
        name: "storage crash must preserve committed value 42".into(),
    };

    let first = run_swarm_campaign(&StorageCrashWorkload, &oracle, base.clone(), 24)
        .expect("swarm campaign must run");
    assert_eq!(first.runs_executed, 24);

    let second = run_swarm_campaign(&StorageCrashWorkload, &oracle, base, 24)
        .expect("swarm campaign rerun must run");
    assert_eq!(first.distinct_roots, second.distinct_roots);
    assert_eq!(first.variants, second.variants);
    assert_eq!(first.findings.len(), second.findings.len());
}

#[test]
fn bandit_campaign_rewards_finding_variants() {
    let base = mini_kv_base(6);
    let base_run = Simulation::new(base.clone(), MiniKvWorkload.programs())
        .run()
        .expect("base run must succeed");
    let fault_library = base_run
        .journal
        .entries()
        .filter(|entry| matches!(entry.data.kind, EntryKind::Send))
        .map(|entry| SimFault::Drop(entry.id))
        .collect::<Vec<_>>();
    assert!(!fault_library.is_empty(), "mini-kv must journal Sends");

    let mutation = QuadMutation {
        policies: vec![Policy::Random],
        use_swarm: false,
        swarm_budget: 0,
        fault_library,
        max_faults_per_run: 2,
        ..Default::default()
    };
    let oracle = HistoryOracle::new(&MiniKvWorkload, KeyValueSpec::default());

    let report = run_bandit_campaign(&MiniKvWorkload, &oracle, base, &mutation, 1.414, 24)
        .expect("bandit campaign must run");
    assert_eq!(report.runs_executed, 24);
    assert!(report.distinct_roots >= 1);
    assert!(report.variants.len() == 24);
}

#[test]
fn joint_mode_produces_findings() {
    let base = mini_kv_base(7);
    let oracle = HistoryOracle::new(&MiniKvWorkload, KeyValueSpec::default());

    let report = run_joint_campaign(&MiniKvWorkload, &oracle, base.clone(), 64)
        .expect("joint campaign must run");
    assert_eq!(report.runs_executed, 64);
    assert!(
        !report.findings.is_empty(),
        "joint mode must keep the base finding"
    );

    // Determinism: the same seed must produce an identical campaign. The
    // findings are the observable output; compare seeds and journal roots.
    let rerun = run_joint_campaign(&MiniKvWorkload, &oracle, base.clone(), 64)
        .expect("joint campaign must run");
    assert_eq!(rerun.runs_executed, report.runs_executed);
    assert_eq!(rerun.findings.len(), report.findings.len());
    for (a, b) in rerun.findings.iter().zip(report.findings.iter()) {
        assert_eq!(a.seed, b.seed, "joint-mode finding seeds must be stable");
        assert_eq!(
            a.run.journal.root_hash(),
            b.run.journal.root_hash(),
            "joint-mode finding roots must be stable for the same seed"
        );
    }
}

#[test]
fn quad_bandit_arm_determinism() {
    let swarm = SwarmConfig::default();
    let arm_a = QuadBandit::variant_hash(&Policy::Random, &swarm, &[]);
    let arm_b = QuadBandit::variant_hash(&Policy::Replay, &swarm, &[]);
    assert_eq!(
        arm_a,
        QuadBandit::variant_hash(&Policy::Random, &swarm, &[])
    );
    assert_ne!(arm_a, arm_b);

    let mut bandit = QuadBandit::new();
    bandit.register(arm_a);
    bandit.register(arm_b);
    bandit.reward(arm_a, 1.0);

    let first = bandit.arm(1.414);
    let second = bandit.arm(1.414);
    assert_eq!(first, second);
    assert!(
        first == arm_a || first == arm_b,
        "arm must be a registered candidate"
    );
}

// ---------------------------------------------------------------------------
// Planted axis counterexamples
// ---------------------------------------------------------------------------

/// Run `programs` at `seed` and return the journal.
fn run_programs(programs: Vec<Vec<Instruction>>, seed: u8, faults: Vec<SimFault>) -> RunResult {
    let config = RunConfig::builder()
        .seed([seed; 32])
        .policy(Policy::Random)
        .max_steps(512)
        .fault_schedule(faults)
        .build();
    Simulation::new(config, programs)
        .run()
        .expect("the planted program must run")
}

/// PLANTED LINEARIZABILITY VIOLATION: a write that completes, then a read
/// that starts after it and still serves the stale value.
///
/// The writer sends value 42; the reader receives it (the receive chains the
/// send into the reader's causal past), then overwrites its register with 0
/// and reads: the read entry happens strictly after the write entry in the
/// real-time order yet returns 0. The schedule is forced: the reader blocks
/// on the receive until the writer's message is delivered, so every seed
/// produces the same non-linearizable history.
struct ReorderStaleReadWorkload;

impl Workload for ReorderStaleReadWorkload {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        vec![
            vec![
                Instruction::SendTimed {
                    to: 1,
                    payload: 42,
                    delay: 2,
                },
                Instruction::Done,
            ],
            vec![
                Instruction::Receive,
                Instruction::Set(0),
                Instruction::Outcome,
                Instruction::Done,
            ],
        ]
    }

    fn history(&self, run: &RunResult) -> Vec<HistoryOperation> {
        run.journal
            .entries()
            .filter_map(|entry| match (&entry.data.kind, &entry.data.payload) {
                (
                    EntryKind::Send,
                    EntryPayload::Send(ledger_format::SendFrame {
                        original_content, ..
                    }),
                ) if entry.data.actor == 0
                    && original_content.as_slice() == 42u64.to_le_bytes() =>
                {
                    Some(HistoryOperation::Write {
                        key: "k".into(),
                        value: 42,
                        witness: entry.id,
                    })
                }
                (
                    EntryKind::Outcome,
                    EntryPayload::Outcome(ledger_format::OutcomePayload {
                        value: CanonicalValue::Unsigned(value),
                        ..
                    }),
                ) if entry.data.actor == 1 => Some(HistoryOperation::Read {
                    key: "k".into(),
                    value: *value,
                    witness: entry.id,
                }),
                _ => None,
            })
            .collect()
    }
}

#[test]
fn linearizability_axis_catches_the_planted_stale_read() {
    let oracle = LinearizabilityOracle::new(&ReorderStaleReadWorkload, KeyValueSpec::default());
    for seed in [0u8, 3, 9] {
        let run = run_programs(ReorderStaleReadWorkload.programs(), seed, Vec::new());
        let verdict = oracle.check(&run);
        assert!(
            verdict.violated,
            "seed {seed}: the planted reorder must violate linearizability: {}",
            verdict.reason
        );
        assert!(
            verdict.reason.contains("non-linearizable"),
            "the violation reason must name the failure: {}",
            verdict.reason
        );
    }
    // The search axis flag catches the same violation on the first attempt.
    let config = RunConfig::builder()
        .seed([2; 32])
        .policy(Policy::Random)
        .max_steps(256)
        .build();
    let finding = search(&ReorderStaleReadWorkload, &oracle, config, 4)
        .expect("search must run")
        .expect("the planted reorder must be found immediately");
    assert!(finding.verdict.violated);
}

/// PLANTED QUORUM VIOLATION: a partitioned replica serves a stale ack and
/// the client accepts the first two acks instead of a majority.
///
/// Replicas A and B receive the write (42) and ack it; replica C is
/// partitioned from the writer, so its only message is a precomputed stale
/// ack (0) sent early. The client takes the first two arrivals: A's fresh
/// ack at virtual time 1 and C's stale ack at time 2, and reads 0 even
/// though a majority (A and B) acknowledged 42. Arrival order is fixed by
/// virtual time, so the plant is deterministic across seeds.
struct QuorumStaleReadWorkload;

impl Workload for QuorumStaleReadWorkload {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        vec![
            // 0: writer.
            vec![
                Instruction::SendTimed {
                    to: 1,
                    payload: 42,
                    delay: 1,
                },
                Instruction::SendTimed {
                    to: 2,
                    payload: 42,
                    delay: 4,
                },
                Instruction::SendTimed {
                    to: 3,
                    payload: 42,
                    delay: 7,
                },
                Instruction::Done,
            ],
            // 1: replica A acks fresh.
            vec![
                Instruction::Receive,
                Instruction::SendTimed {
                    to: 4,
                    payload: 42,
                    delay: 0,
                },
                Instruction::Done,
            ],
            // 2: replica B acks fresh.
            vec![
                Instruction::Receive,
                Instruction::SendTimed {
                    to: 4,
                    payload: 42,
                    delay: 0,
                },
                Instruction::Done,
            ],
            // 3: replica C never got the write (partitioned); stale ack early.
            vec![Instruction::SendTimed {
                to: 4,
                payload: 0,
                delay: 2,
            }],
            // 4: client takes the first two acks: A(42) then C(0).
            vec![
                Instruction::Receive,
                Instruction::Receive,
                Instruction::Outcome,
                Instruction::Done,
            ],
        ]
    }

    fn history(&self, _run: &RunResult) -> Vec<HistoryOperation> {
        Vec::new()
    }
}

#[test]
fn quorum_axis_catches_the_planted_stale_read() {
    // The plant needs the write to replica C partitioned away.
    let faults = vec![SimFault::Partition { src: 0, dst: 3 }];
    let oracle = PropertyOracle {
        property: |journal: &Journal| {
            let acks: Vec<u64> = journal
                .entries()
                .filter(|entry| {
                    entry.data.actor >= 1
                        && entry.data.actor <= 3
                        && entry.data.kind == EntryKind::Send
                })
                .filter_map(|entry| match &entry.data.payload {
                    EntryPayload::Send(ledger_format::SendFrame {
                        original_content, ..
                    }) => {
                        let bytes: [u8; 8] = original_content
                            .as_slice()
                            .try_into()
                            .expect("8-byte send payload");
                        Some(u64::from_le_bytes(bytes))
                    }
                    _ => None,
                })
                .collect();
            let quorum_fresh = acks.iter().filter(|value| **value == 42).count() >= 2;
            let outcome = journal
                .entries()
                .filter(|entry| entry.data.actor == 4 && entry.data.kind == EntryKind::Outcome)
                .find_map(|entry| match &entry.data.payload {
                    EntryPayload::Outcome(ledger_format::OutcomePayload {
                        value: CanonicalValue::Unsigned(value),
                        ..
                    }) => Some(*value),
                    _ => None,
                });
            // A stale read is only a quorum violation when a majority acked
            // the fresh value.
            !(quorum_fresh && outcome != Some(42))
        },
        name: "quorum read must see a majority-acked value".into(),
    };
    for seed in [0u8, 5, 11] {
        let run = run_programs(QuorumStaleReadWorkload.programs(), seed, faults.clone());
        // The partition must actually keep the write away from replica C:
        // C never journals a Recv entry.
        assert!(
            run.journal
                .entries()
                .all(|entry| entry.data.actor != 3 || entry.data.kind != EntryKind::Recv),
            "seed {seed}: replica C must never receive the write under the partition"
        );
        let verdict = oracle.check(&run);
        assert!(
            verdict.violated,
            "seed {seed}: the partitioned stale read must violate the quorum oracle"
        );
    }
    // The control topology without the stale replica and without the
    // partition must pass: two fresh acks, read of 42.
    let control = PropertyOracle {
        property: |journal: &Journal| {
            journal
                .entries()
                .filter(|entry| entry.data.kind == EntryKind::Outcome)
                .find_map(|entry| match &entry.data.payload {
                    EntryPayload::Outcome(ledger_format::OutcomePayload {
                        value: CanonicalValue::Unsigned(value),
                        ..
                    }) => Some(*value),
                    _ => None,
                })
                == Some(42)
        },
        name: "quorum control reads the fresh value".into(),
    };
    let healthy: Vec<Vec<Instruction>> = vec![
        vec![
            Instruction::SendTimed {
                to: 1,
                payload: 42,
                delay: 1,
            },
            Instruction::SendTimed {
                to: 2,
                payload: 42,
                delay: 4,
            },
            Instruction::Done,
        ],
        vec![
            Instruction::Receive,
            Instruction::SendTimed {
                to: 3,
                payload: 42,
                delay: 0,
            },
            Instruction::Done,
        ],
        vec![
            Instruction::Receive,
            Instruction::SendTimed {
                to: 3,
                payload: 42,
                delay: 0,
            },
            Instruction::Done,
        ],
        vec![
            Instruction::Receive,
            Instruction::Receive,
            Instruction::Outcome,
            Instruction::Done,
        ],
    ];
    for seed in [0u8, 5, 11] {
        let run = run_programs(healthy.clone(), seed, Vec::new());
        assert!(
            !control.check(&run).violated,
            "seed {seed}: the healthy quorum must read the fresh value"
        );
    }
}

/// PLANTED EXACTLY-ONCE VIOLATIONS: a duplicate apply and a torn final
/// apply, judged by the journal-level exactly-once value oracle.
struct DupApplyWorkload;

impl Workload for DupApplyWorkload {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        vec![vec![
            Instruction::Set(42),
            Instruction::Set(42),
            Instruction::Outcome,
            Instruction::Done,
        ]]
    }

    fn history(&self, _run: &RunResult) -> Vec<HistoryOperation> {
        Vec::new()
    }
}

struct TornApplyWorkload;

impl Workload for TornApplyWorkload {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        // The last journaled input is 3, but the visible outcome is the
        // clock value: a torn final apply.
        vec![vec![
            Instruction::Set(3),
            Instruction::ReadClock,
            Instruction::Outcome,
            Instruction::Done,
        ]]
    }

    fn history(&self, _run: &RunResult) -> Vec<HistoryOperation> {
        Vec::new()
    }
}

#[test]
fn exactly_once_axis_catches_duplicate_and_torn_applies() {
    for seed in [0u8, 7, 13] {
        let dup = run_programs(DupApplyWorkload.programs(), seed, Vec::new());
        let verdict = ExactlyOnceValueOracle.check(&dup);
        assert!(
            verdict.violated,
            "seed {seed}: the duplicate apply must violate exactly-once"
        );
        assert!(
            verdict.reason.contains("applied 2 times"),
            "the reason must name the duplicated value: {}",
            verdict.reason
        );

        let torn = run_programs(TornApplyWorkload.programs(), seed, Vec::new());
        let verdict = ExactlyOnceValueOracle.check(&torn);
        assert!(
            verdict.violated,
            "seed {seed}: the torn final apply must violate exactly-once"
        );
        assert!(
            verdict.reason.contains("torn final apply"),
            "the reason must name the torn apply: {}",
            verdict.reason
        );

        // Control: a clean single apply passes.
        let clean_programs = vec![vec![
            Instruction::Set(42),
            Instruction::Outcome,
            Instruction::Done,
        ]];
        let clean = run_programs(clean_programs, seed, Vec::new());
        assert_eq!(ExactlyOnceValueOracle.check(&clean), Verdict::pass());
    }
    // The search axis flag catches the duplicate apply on the first attempt.
    let config = RunConfig::builder()
        .seed([2; 32])
        .policy(Policy::Random)
        .max_steps(128)
        .build();
    let finding = search(&DupApplyWorkload, &ExactlyOnceValueOracle, config, 4)
        .expect("search must run")
        .expect("the duplicate apply must be found immediately");
    assert!(finding.verdict.violated);
}
