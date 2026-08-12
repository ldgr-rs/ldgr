//! End-to-end fault injection: LDFI hypotheses become executable schedules,
//! replays fork the journal, voided faults are data, and replays are
//! deterministic.

use ledger_explorer::ldfi::{FaultHypothesis, hypothesis_to_schedule, solve_ldfi};
use ledger_explorer::oracle::{HistoryOracle, KeyValueSpec};
use ledger_explorer::search::{Workload, replay_with_faults, search};
use ledger_explorer::workloads::{MiniKvWorkload, TwoPhaseCommitWorkload};
use ledger_format::{EntryKind, FaultSpec, Payload};
use ledger_sim::{FaultInjection, Policy, RunConfig, Simulation};

fn find_stale_read() -> ledger_explorer::search::Finding {
    let config = RunConfig {
        seed: [0; 32],
        policy: Policy::Random,
        max_steps: 256,
        ..RunConfig::default()
    };
    let oracle = HistoryOracle::new(&MiniKvWorkload, KeyValueSpec::default());
    search(&MiniKvWorkload, &oracle, config, 256)
        .expect("search must run")
        .expect("campaign should find the planted stale read")
}

#[test]
fn hypothesis_becomes_executable_schedule() {
    let finding = find_stale_read();
    let hypotheses = solve_ldfi(&finding.run.journal, &finding.verdict);
    let hypothesis = hypotheses
        .first()
        .expect("LDFI must produce at least one hypothesis");
    let schedule = hypothesis_to_schedule(hypothesis, &finding.run.journal);
    assert!(
        !schedule.is_empty(),
        "the hypothesis must map to an executable schedule"
    );
    let report = replay_with_faults(
        &MiniKvWorkload,
        &finding.run.journal,
        finding.seed,
        finding.run.decisions.clone(),
        schedule,
    )
    .expect("fault replay must run");
    assert!(
        report.prefix_ok,
        "prefix must not diverge before the first fault"
    );
}

#[test]
fn drop_injection_forks_journal_not_mutates_base() {
    let finding = find_stale_read();
    let base_root = finding.run.journal.root_hash();

    let send_ids = finding
        .run
        .journal
        .entries()
        .filter(|entry| matches!(entry.data.kind, ledger_format::EntryKind::Send))
        .map(|entry| entry.id)
        .collect::<Vec<_>>();
    let target = *send_ids.first().expect("the workload journals Sends");

    let report = replay_with_faults(
        &MiniKvWorkload,
        &finding.run.journal,
        finding.seed,
        finding.run.decisions.clone(),
        vec![FaultInjection::Drop(target)],
    )
    .expect("replay must run");

    assert_ne!(
        report.run.journal.root_hash(),
        base_root,
        "the faulted run must differ from the base"
    );
    assert_eq!(
        finding.run.journal.root_hash(),
        base_root,
        "the base journal must not be mutated by a fault-injected replay"
    );
}

#[test]
fn voided_fault_is_data_not_error() {
    let finding = find_stale_read();
    let ghost = [0xAB; 32];
    let report = replay_with_faults(
        &MiniKvWorkload,
        &finding.run.journal,
        finding.seed,
        finding.run.decisions.clone(),
        vec![FaultInjection::Drop(ghost)],
    )
    .expect("a voided fault must not fail the replay");
    assert_eq!(report.voided.len(), 1, "the ghost injection is voided");
    assert!(report.applied.is_empty());
    assert!(
        report.prefix_ok,
        "no fault fired, so the whole replayed run must match the base"
    );
}

#[test]
fn replay_is_deterministic_under_faults() {
    let finding = find_stale_read();
    let send_ids = finding
        .run
        .journal
        .entries()
        .filter(|entry| matches!(entry.data.kind, ledger_format::EntryKind::Send))
        .map(|entry| entry.id)
        .collect::<Vec<_>>();
    let schedule = vec![FaultInjection::Delay {
        send: send_ids[0],
        ticks: 5,
    }];

    let first = replay_with_faults(
        &MiniKvWorkload,
        &finding.run.journal,
        finding.seed,
        finding.run.decisions.clone(),
        schedule.clone(),
    )
    .expect("first replay");
    let second = replay_with_faults(
        &MiniKvWorkload,
        &finding.run.journal,
        finding.seed,
        finding.run.decisions.clone(),
        schedule,
    )
    .expect("second replay");
    assert_eq!(
        first.run.journal.root_hash(),
        second.run.journal.root_hash(),
        "the same seed and schedule must replay identically"
    );
    assert_eq!(first.applied, second.applied);
    assert_eq!(first.voided.len(), second.voided.len());
}

#[test]
fn partition_injection_changes_schedule() {
    let finding = find_stale_read();
    let base_root = finding.run.journal.root_hash();
    let report = replay_with_faults(
        &MiniKvWorkload,
        &finding.run.journal,
        finding.seed,
        finding.run.decisions.clone(),
        vec![FaultInjection::Partition { src: 0, dst: 1 }],
    )
    .expect("replay must run");
    assert_ne!(
        report.run.journal.root_hash(),
        base_root,
        "a partitioned link must change the run"
    );
}

#[test]
fn hypothesis_emits_all_fault_classes_and_replay_applies_them() {
    let config = RunConfig {
        seed: [4; 32],
        policy: Policy::Random,
        max_steps: 256,
        ..RunConfig::default()
    };
    let clean = Simulation::new(config.clone(), TwoPhaseCommitWorkload.programs())
        .run()
        .expect("two-phase commit must run");

    // Probe run: partition the link to participant 1 only. The probe matches
    // the final faulted run up to participant B's write, so the entry ids the
    // probe reports are the exact targets the final schedule must hit.
    let mut probe_config = config.clone();
    probe_config.fault_schedule = vec![FaultInjection::Partition { src: 0, dst: 1 }];
    let probe = Simulation::new(probe_config, TwoPhaseCommitWorkload.programs())
        .run()
        .expect("probe run must execute");
    let send = probe
        .journal
        .entries()
        .find(|entry| {
            entry.data.actor == 0
                && matches!(entry.data.kind, EntryKind::Send)
                && matches!(&entry.data.payload, Payload::Pair { left: 1, .. })
        })
        .map(|entry| entry.id)
        .expect("the coordinator sends Prepare to participant 1");
    let write = probe
        .journal
        .entries()
        .find(|entry| matches!(entry.data.kind, EntryKind::FsWrite) && entry.data.actor == 2)
        .map(|entry| entry.id)
        .expect("participant B journals an FsWrite");

    // A cut over one Send and one FsWrite must map to every applicable class:
    // the Send to Drop/Delay/Partition, the FsWrite to Corrupt/CrashState.
    let hypothesis = FaultHypothesis {
        events: vec![send, write],
        total_cost: 0,
        explanation: "all-classes test cut".into(),
    };
    let schedule = hypothesis_to_schedule(&hypothesis, &probe.journal);
    assert!(
        schedule
            .iter()
            .any(|f| matches!(f, FaultInjection::Delay { .. })),
        "the Send must map to a Delay"
    );
    assert!(
        schedule
            .iter()
            .any(|f| matches!(f, FaultInjection::Partition { .. })),
        "the Send must map to a Partition"
    );
    assert!(
        schedule
            .iter()
            .any(|f| matches!(f, FaultInjection::Corrupt { .. })),
        "the FsWrite must map to a Corrupt"
    );
    assert!(
        schedule
            .iter()
            .any(|f| matches!(f, FaultInjection::CrashState { .. })),
        "the FsWrite must map to a CrashState"
    );

    // Fork the run under the same seed with the fault schedule applied. The
    // Delay and Partition classes execute against the coordinator's send; the
    // Corrupt/CrashState classes execute against participant B's WAL write,
    // which is reachable because the cut link only blocks participant A.
    let send_entry = probe.journal.get(&send).expect("send entry must exist");
    let send_dst = match &send_entry.data.payload {
        Payload::Pair { left, .. } => *left as u32,
        _ => u32::MAX,
    };
    let replay_schedule: Vec<FaultInjection> = schedule
        .into_iter()
        .filter(|f| !matches!(f, FaultInjection::Drop(_)))
        .collect();
    let mut faulted_config = config.clone();
    faulted_config.fault_schedule = replay_schedule;
    let faulted = Simulation::new(faulted_config, TwoPhaseCommitWorkload.programs())
        .run()
        .expect("faulted run must execute");
    assert!(
        faulted.applied_faults.contains(&send),
        "the delayed Send must be in the applied-fault set"
    );
    assert!(
        faulted.applied_faults.contains(&write),
        "the corrupted FsWrite must be in the applied-fault set"
    );
    assert!(
        faulted.journal.entries().any(|entry| matches!(
            &entry.data.kind,
            EntryKind::Fault {
                fault: FaultSpec::Partition { src: 0, dst }
            } if *dst == send_dst
        )),
        "the partition must journal a Fault entry on the cut link"
    );
    assert!(
        faulted
            .journal
            .entries()
            .any(|entry| matches!(&entry.data.kind, EntryKind::Fault { .. })),
        "the write-side classes must journal Fault entries"
    );
    assert_ne!(
        faulted.journal.root_hash(),
        clean.journal.root_hash(),
        "the faulted fork must diverge from the clean run"
    );
}
