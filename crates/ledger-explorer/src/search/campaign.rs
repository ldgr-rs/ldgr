use super::SearchError;
use crate::monitor::{MonitorOracle, OnlineMonitor};
use crate::oracle::{Oracle, Verdict};
use crate::pbt::InputsWorkload;
use ledger_format::EntryHash;
use ledger_sim::{Instruction, RunConfig, RunResult, Simulation};
use std::collections::HashSet;

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
    pub seed: EntryHash,
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
    /// Names of monitors attached to the campaign; empty when none ran.
    pub monitors: Vec<String>,
    /// Attempts that reused a memo-cached journal root instead of re-executing.
    pub memo_hits: usize,
}

impl CampaignReport {
    /// Render the campaign's coverage as NDJSON records.
    ///
    /// Emits one record per finding, in finding order:
    /// `{"root_hex":"..","run_index":N,"finding":true}` where `root_hex` is
    /// the finding journal's root hash. Only findings carry per-run roots in
    /// a report; passing runs are covered by the trailing summary comment
    /// line `# runs=N distinct=D`.
    pub fn to_coverage_records(&self) -> String {
        let mut out = String::new();
        for (index, finding) in self.findings.iter().enumerate() {
            let root_hex = crate::certs::hash_to_hex(&finding.run.journal.root_hash());
            out.push_str(&format!(
                "{{\"root_hex\":\"{root_hex}\",\"run_index\":{index},\"finding\":true}}\n"
            ));
        }
        out.push_str(&format!(
            "# runs={} distinct={}\n",
            self.runs_executed, self.distinct_roots
        ));
        out
    }
}

/// Run a seed-varying exploration campaign, collecting findings and coverage.
pub fn run_campaign<W: Workload, O: Oracle>(
    workload: &W,
    oracle: &O,
    base: RunConfig,
    attempts: usize,
) -> Result<CampaignReport, SearchError> {
    // Explicit per-campaign clause cache scope. Campaign search itself is
    // simulation-only, but any LDFI solve derived from its findings must use
    // this campaign's cache, never a process-global store.
    let _campaign_clause_cache = crate::solver_cache::ClauseCache::new();
    let mut distinct_roots: HashSet<EntryHash> = HashSet::new();
    let mut findings: Vec<Finding> = Vec::new();

    for attempt in 0..attempts {
        let mut seed = base.seed();
        seed.0[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());
        let config = base.clone().with_seed(seed);
        let run = Simulation::new(config.clone(), workload.programs()).run()?;

        distinct_roots.insert(run.journal.root_hash());
        let verdict = super::effective_verdict(&run, oracle.check(&run));
        if verdict.violated {
            findings.push(Finding {
                seed: config.seed(),
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
        monitors: Vec::new(),
        memo_hits: 0,
    })
}

/// Merge the user-oracle verdict with the monitor-oracle verdict.
///
/// The combined verdict violates when either fires. A monitor halt contributes
/// its reason under a `monitor:` prefix, so a finding records which monitor
/// halted even when the user oracle also fired.
fn merge_monitor_verdict(mut primary: Verdict, monitored: Verdict) -> Verdict {
    if !monitored.violated {
        return primary;
    }
    let monitor_reason = format!("monitor: {}", monitored.reason);
    if primary.violated {
        primary.reason.push_str("; ");
        primary.reason.push_str(&monitor_reason);
    } else {
        primary.reason = monitor_reason;
    }
    primary.witnesses.extend(monitored.witnesses);
    primary.violated = true;
    primary
}

/// Run a seed-varying campaign under the user oracle plus online monitors.
///
/// Each run is checked by the user oracle and by a [`MonitorOracle`] replaying
/// the attached monitors. The combined verdict violates when either fires; a
/// monitor-caused violation contributes its reason under a `monitor:` prefix
/// naming the halting monitor. The report lists monitor names in attach order.
pub fn run_monitored_campaign<W: Workload, O: Oracle>(
    workload: &W,
    oracle: &O,
    base: RunConfig,
    monitors: Vec<Box<dyn OnlineMonitor>>,
    attempts: usize,
) -> Result<CampaignReport, SearchError> {
    // Explicit per-campaign clause cache scope; see `run_campaign`.
    let _campaign_clause_cache = crate::solver_cache::ClauseCache::new();
    let monitor_names = monitors
        .iter()
        .map(|monitor| monitor.name().to_string())
        .collect::<Vec<_>>();
    let mut monitor_oracle = MonitorOracle::new();
    for monitor in monitors {
        monitor_oracle = monitor_oracle.with_monitor(monitor);
    }

    let mut distinct_roots: HashSet<EntryHash> = HashSet::new();
    let mut findings: Vec<Finding> = Vec::new();

    for attempt in 0..attempts {
        let mut seed = base.seed();
        seed.0[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());
        let config = base.clone().with_seed(seed);
        // Reset monitors before the mid-run delta feed so each attempt
        // starts from a clean state; the shared monitors are also used by
        // the post-run oracle, which resets again at check time.
        monitor_oracle.reset();
        let step_monitor = monitor_oracle.to_step_monitor();
        let run = Simulation::new(config.clone(), workload.programs())
            .with_step_monitor(step_monitor)
            .run()?;

        distinct_roots.insert(run.journal.root_hash());
        let primary = super::effective_verdict(&run, oracle.check(&run));
        let monitored = monitor_oracle.check(&run);
        let verdict = merge_monitor_verdict(primary, monitored);
        if verdict.violated {
            findings.push(Finding {
                seed: config.seed(),
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
        monitors: monitor_names,
        memo_hits: 0,
    })
}

pub fn search<W: Workload, O: Oracle>(
    workload: &W,
    oracle: &O,
    base: RunConfig,
    attempts: usize,
) -> Result<Option<Finding>, SearchError> {
    super::find_first_violation(workload, oracle, &base, attempts).map(|(finding, _)| finding)
}

#[cfg(test)]
mod liveness_tests {
    use super::*;
    use crate::oracle::Verdict;
    use ledger_format::ActorId;
    use ledger_sim::{Instruction, RunConfig};

    /// A workload whose single task blocks on a receive that never has a
    /// sender: the run quiesces with a pending task.
    struct DeadlockWorkload;

    impl Workload for DeadlockWorkload {
        fn programs(&self) -> Vec<Vec<Instruction>> {
            vec![vec![Instruction::Receive]]
        }

        fn history(&self, _run: &RunResult) -> Vec<crate::oracle::HistoryOperation> {
            Vec::new()
        }
    }

    struct PassOracle;

    impl Oracle for PassOracle {
        fn check(&self, _run: &ledger_sim::RunResult) -> Verdict {
            Verdict::pass()
        }
    }

    #[test]
    fn quiesced_pending_tasks_become_liveness_findings() {
        let config = RunConfig::builder()
            .seed(EntryHash([9; 32]))
            .max_steps(64)
            .build();
        let report =
            run_campaign(&DeadlockWorkload, &PassOracle, config, 2).expect("campaign succeeds");
        assert_eq!(
            report.findings.len(),
            2,
            "every attempt must surface as a liveness finding"
        );
        assert!(
            report.findings[0].verdict.reason.contains("liveness"),
            "reason must name liveness: {}",
            report.findings[0].verdict.reason
        );
        assert!(
            !report.findings[0].verdict.witnesses.is_empty(),
            "liveness findings carry journal witnesses"
        );
    }

    #[test]
    fn monitor_halt_becomes_liveness_style_finding() {
        use ledger_format::{CanonicalValue, EntryKind, EntryPayload};
        use ledger_journal::Journal;
        // Effective verdict must treat MonitorHalt as a liveness-style
        // violation with a journal-tail witness.
        let mut journal = Journal::new();
        journal
            .append(
                EntryKind::Outcome,
                ActorId(1),
                [],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: EntryHash([0x00; 32]),
                    value: CanonicalValue::Unsigned(1),
                }),
            )
            .unwrap();
        let run = ledger_sim::RunResult {
            outcome: ledger_sim::RunOutcome::MonitorHalt("test halt".into()),
            journal_error: None,
            journal,
            decisions: vec![0],
            trace: Vec::new(),
            registers: vec![0],
            steps: 1,
            monitor_issues: Vec::new(),
            applied_faults: Vec::new(),
            origins: Vec::new(),
            protection: ledger_sim::BeltStatus::NotArmed,
        };
        let verdict = super::super::effective_verdict(&run, Verdict::pass());
        assert!(verdict.violated, "MonitorHalt must be a finding");
        assert!(
            verdict.reason.contains("monitor halt"),
            "reason must name monitor halt: {}",
            verdict.reason
        );
        assert!(
            verdict.reason.contains("test halt"),
            "reason must carry halt reason: {}",
            verdict.reason
        );
        assert!(!verdict.witnesses.is_empty());
    }

    #[test]
    fn monitored_campaign_halts_violating_runs_mid_step() {
        use crate::monitor::SafetyMonitor;
        use ledger_format::{CanonicalValue, EntryKind, EntryPayload};
        use ledger_journal::Entry;
        struct ViolatingWorkload;
        impl Workload for ViolatingWorkload {
            fn programs(&self) -> Vec<Vec<Instruction>> {
                vec![vec![
                    Instruction::Set(99),
                    Instruction::Outcome,
                    Instruction::Done,
                ]]
            }
            fn history(&self, _run: &RunResult) -> Vec<crate::oracle::HistoryOperation> {
                Vec::new()
            }
        }
        struct PassOracle;
        impl Oracle for PassOracle {
            fn check(&self, _run: &ledger_sim::RunResult) -> Verdict {
                Verdict::pass()
            }
        }
        // Halt when Outcome payload is 99.
        let monitor = SafetyMonitor::new(
            |entry: &Entry| {
                if entry.data.kind == EntryKind::Outcome {
                    !matches!(
                        &entry.data.payload,
                        EntryPayload::Outcome(ledger_format::OutcomePayload {
                            schema: _,
                            value: CanonicalValue::Unsigned(99)
                        })
                    )
                } else {
                    true
                }
            },
            "outcome 99 forbidden",
        );
        let base = RunConfig::builder()
            .seed(EntryHash([7; 32]))
            .max_steps(64)
            .build();
        let report = run_monitored_campaign(
            &ViolatingWorkload,
            &PassOracle,
            base,
            vec![Box::new(monitor)],
            2,
        )
        .expect("monitored campaign");
        assert_eq!(
            report.findings.len(),
            2,
            "every attempt must halt via the mid-run monitor"
        );
        for finding in &report.findings {
            assert!(finding.verdict.violated);
            assert!(
                finding.verdict.reason.contains("monitor"),
                "verdict must name monitor: {}",
                finding.verdict.reason
            );
            // The halted run's outcome must be MonitorHalt, and steps must be
            // bounded strictly below max.
            assert!(
                matches!(finding.run.outcome, ledger_sim::RunOutcome::MonitorHalt(_)),
                "run outcome must be MonitorHalt, got {:?}",
                finding.run.outcome
            );
            assert!(finding.run.steps < 64);
            assert!(!finding.run.journal.entries().collect::<Vec<_>>().is_empty());
        }
        assert_eq!(report.monitors, vec!["safety".to_string()]);
    }
}
