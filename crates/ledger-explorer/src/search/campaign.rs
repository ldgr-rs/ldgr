use crate::monitor::{MonitorOracle, OnlineMonitor};
use crate::oracle::{Oracle, Verdict};
use crate::pbt::InputsWorkload;
use ledger_format::Hash;
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
    pub seed: Hash,
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
) -> Result<CampaignReport, String> {
    let mut distinct_roots: HashSet<Hash> = HashSet::new();
    let mut findings: Vec<Finding> = Vec::new();

    for attempt in 0..attempts {
        let mut config = base.clone();
        config.seed_mut()[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());
        let run = Simulation::new(config.clone(), workload.programs())
            .run()
            .map_err(|error| format!("simulation failed: {error:?}"))?;

        distinct_roots.insert(run.journal.root_hash());
        let verdict = oracle.check(&run);
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
) -> Result<CampaignReport, String> {
    let monitor_names = monitors
        .iter()
        .map(|monitor| monitor.name().to_string())
        .collect::<Vec<_>>();
    let mut monitor_oracle = MonitorOracle::new();
    for monitor in monitors {
        monitor_oracle = monitor_oracle.with_monitor(monitor);
    }

    let mut distinct_roots: HashSet<Hash> = HashSet::new();
    let mut findings: Vec<Finding> = Vec::new();

    for attempt in 0..attempts {
        let mut config = base.clone();
        config.seed_mut()[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());
        let run = Simulation::new(config.clone(), workload.programs())
            .run()
            .map_err(|error| format!("simulation failed: {error:?}"))?;

        distinct_roots.insert(run.journal.root_hash());
        let primary = oracle.check(&run);
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
) -> Result<Option<Finding>, String> {
    super::find_first_violation(workload, oracle, &base, attempts).map(|(finding, _)| finding)
}
