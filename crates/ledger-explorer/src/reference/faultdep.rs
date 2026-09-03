//! Fault-triggered corpus v2: the counted Stage-2 non-vacuous scenario set.
//!
//! Every scenario here is a fault-dependent plant, unlike the corpus-v1
//! reproduction fixtures: the no-fault baseline at the pinned seed passes,
//! and only an injected fault schedule causes the violation. Each scenario
//! is a storage-semantics plant: the workload records state with SimFs
//! writes and reads the critical write back, and the planted bug is that
//! the recorded state is trusted without durability. A corrupt or crash
//! fault on the critical write then produces a wrong PRESENT value whose
//! causal path runs through the faulted write. This is the fault class the
//! hazard encoder can attribute: the cut names the faulted write, and the
//! strict replay of the witness decisions with the cut schedule reproduces.
//!
//! Each scenario pins three deterministic derivations from its own no-fault
//! baseline journal:
//!
//! - `trigger`: the pinned schedule that causes the planted violation;
//! - `fault_space`: the declared candidate vocabulary, one Corrupt and one
//!   CrashState candidate per `FsWrite` of the baseline;
//! - `support`: the explicit [`SupportExpr`] evaluated on the witness
//!   journal, so certificate claims bind a real, non-empty model.
//!
//! Decoy writes in front of the critical write widen the declared fault
//! space the way real control-plane state does: most writes are not the
//! vulnerability. The programs are single-task and deterministic, so the
//! baseline journal - and therefore every derivation - is identical at
//! every seed.

use super::ScenarioClass;
use crate::oracle::{Oracle, PropertyOracle};
use crate::search::replay_with_faults;
use crate::search::{FaultReplayError, FaultReplayReport, Finding, Workload};
use crate::support::{StaticSupportProvider, SupportExpr, all_of_ids};
use ledger_format::EntryHash;
use ledger_journal::Journal;
use ledger_sim::{Policy, RunConfig, RunResult, RuntimeError, SimFault, Simulation};

/// Support-provider version for the fault-triggered corpus. It is distinct
/// from the corpus-v1 provider version so derived clauses never cross.
pub const FAULTDEP_SUPPORT_VERSION: u64 = 2;

/// One fault-triggered scenario: a program workload whose planted bug fires
/// only under its pinned fault schedule.
pub struct FaultDepScenario {
    /// Manifest file stem under `corpora/bug-corpus-v2/`.
    pub name: &'static str,
    /// Pinned base seed. The no-fault baseline at this seed must pass.
    pub base_seed: EntryHash,
    /// Bug-class label.
    pub class: ScenarioClass,
    /// The program workload under test.
    pub workload: fn() -> Box<dyn Workload>,
    /// The oracle that judges a completed run; holds when the system is
    /// correct.
    pub oracle: fn() -> Box<dyn Oracle>,
    /// Declared candidate fault vocabulary for the random control. Derived
    /// from the no-fault baseline of the base seed, never from a violating
    /// run.
    pub fault_space: fn() -> Vec<SimFault>,
    /// The pinned triggering schedule, derived from the baseline journal.
    pub trigger: fn(&Journal) -> Vec<SimFault>,
    /// Explicit support model, evaluated on the witness journal.
    pub support: fn(&Journal) -> SupportExpr,
}

/// Build the gate run config: Random policy over the pinned seed with an
/// optional fault schedule.
fn scenario_config(seed: EntryHash, faults: Vec<SimFault>) -> RunConfig {
    RunConfig::builder()
        .seed(seed)
        .policy(Policy::Random)
        .max_steps(4096)
        .fault_schedule(faults)
        .build()
}

impl FaultDepScenario {
    /// A fresh workload instance.
    pub fn workload(&self) -> Box<dyn Workload> {
        (self.workload)()
    }

    /// A fresh oracle instance.
    pub fn oracle(&self) -> Box<dyn Oracle> {
        (self.oracle)()
    }

    /// The oracle verdict for a completed run.
    pub fn check(&self, run: &RunResult) -> crate::oracle::Verdict {
        self.oracle().check(run)
    }

    /// The no-fault baseline run at the base seed. This run must pass; it is
    /// also the derivation source for the trigger and the fault space.
    pub fn baseline(&self) -> Result<RunResult, RuntimeError> {
        Simulation::new(
            scenario_config(self.base_seed, Vec::new()),
            self.workload().programs(),
        )
        .run()
    }

    /// The canonical violating run: the baseline configuration plus the
    /// pinned trigger schedule. Fails when the baseline violates (an
    /// unconditional plant never counts) or when the trigger fails to cause
    /// the violation.
    pub fn witness(&self) -> Result<Finding, String> {
        let baseline = self
            .baseline()
            .map_err(|error| format!("{}: baseline run failed: {error}", self.name))?;
        if self.check(&baseline).violated {
            return Err(format!(
                "{}: the no-fault baseline violates; unconditional plants never count",
                self.name
            ));
        }
        let schedule = (self.trigger)(&baseline.journal);
        let run = Simulation::new(
            scenario_config(self.base_seed, schedule),
            self.workload().programs(),
        )
        .run()
        .map_err(|error| format!("{}: witness run failed: {error}", self.name))?;
        let verdict = self.check(&run);
        if !verdict.violated {
            return Err(format!(
                "{}: the pinned trigger must cause the violation",
                self.name
            ));
        }
        Ok(Finding {
            seed: self.base_seed,
            run,
            verdict,
        })
    }

    /// Strict decision replay of one schedule against a witness run.
    pub fn replay(
        &self,
        witness: &RunResult,
        schedule: Vec<SimFault>,
    ) -> Result<FaultReplayReport, FaultReplayError> {
        replay_with_faults(
            self.workload().as_ref(),
            &witness.journal,
            self.base_seed,
            witness.decisions.clone(),
            schedule,
        )
    }

    /// Versioned support provider bound to one concrete journal. The
    /// expression ids are content hashes of that journal's entries, so the
    /// model is only meaningful for the journal it was evaluated against.
    pub fn support_provider(&self, journal: &Journal) -> StaticSupportProvider {
        StaticSupportProvider::new(FAULTDEP_SUPPORT_VERSION, (self.support)(journal))
    }
}

// ---------------------------------------------------------------------------
// Derivation helpers
// ---------------------------------------------------------------------------

/// The no-fault baseline journal of one workload at one seed.
fn probe_journal(seed: EntryHash, workload: &dyn Workload) -> Journal {
    Simulation::new(scenario_config(seed, Vec::new()), workload.programs())
        .run()
        .expect("probe run must execute")
        .journal
}

/// The last `FsWrite` entry of `actor` in journal order: the critical
/// write of every scenario, which the read-back observes.
fn last_fs_write(baseline: &Journal, actor: ledger_format::ActorId) -> ledger_format::EntryHash {
    baseline
        .entries()
        .filter(|entry| {
            entry.data.kind == ledger_format::EntryKind::FsWrite && entry.data.actor == actor
        })
        .last()
        .map(|entry| entry.id)
        .unwrap_or_else(|| panic!("probe journal must contain an FsWrite of actor {actor:?}"))
}

/// Push `count` unsynced decoy writes in front of a workload's critical
/// state. Decoys widen the declared fault space the way real control-plane
/// state does: most writes are not the vulnerability.
fn push_decoys(program: &mut Vec<ledger_sim::Instruction>, count: usize, prefix: &str) {
    for index in 0..count {
        program.push(ledger_sim::Instruction::FsWrite {
            path: format!("{prefix}-{index}"),
            value: index as u64,
        });
    }
}

/// Declared vocabulary: one Corrupt and one CrashState candidate per
/// `FsWrite` of the baseline. Storage-semantics faults are the fault class
/// whose causal targets the typed support hazard sees: the faulted write is
/// declared in the explicit `SupportExpr` (`AllOf` over the critical write,
/// alternative decoy branches preserved as separate `AnyOf` groups), so a
/// hazard cut names the faulted write and the replay reproduces. Parent edges
/// alone never imply support; the encoding traverses the declared support
/// instead of flattening parents.
fn write_fault_space(seed: EntryHash, workload: &dyn Workload) -> Vec<SimFault> {
    let journal = probe_journal(seed, workload);
    journal
        .entries()
        .filter(|entry| entry.data.kind == ledger_format::EntryKind::FsWrite)
        .flat_map(|entry| {
            let write = entry.id;
            vec![
                SimFault::Corrupt { write, xor_mask: 1 },
                SimFault::Corrupt {
                    write,
                    xor_mask: 0xFF,
                },
                SimFault::CrashState { write, state: 0 },
                SimFault::CrashState { write, state: 1 },
                SimFault::CrashState { write, state: 2 },
            ]
        })
        .collect()
}

/// Oracle: the last recorded outcome must equal `expected`.
fn final_value_oracle(expected: u64, name: &'static str) -> Box<dyn Oracle> {
    Box::new(PropertyOracle {
        property: move |journal: &Journal| super::outcome_values(journal).last() == Some(&expected),
        name: name.to_string(),
    })
}

fn support_last_fs_write(journal: &Journal, actor: ledger_format::ActorId) -> SupportExpr {
    all_of_ids(std::iter::once(last_fs_write(journal, actor)))
}

// ---------------------------------------------------------------------------
// Workloads
// ---------------------------------------------------------------------------

/// A one-task storage workload: decoy writes, then the critical writes, then
/// the read-back and outcome. `critical` holds the post-decoy instructions.
fn storage_workload(
    decoys: usize,
    prefix: &str,
    critical: Vec<ledger_sim::Instruction>,
) -> Box<dyn Workload> {
    struct W(Vec<Vec<ledger_sim::Instruction>>);
    impl Workload for W {
        fn programs(&self) -> Vec<Vec<ledger_sim::Instruction>> {
            self.0.clone()
        }
        fn history(&self, _run: &RunResult) -> Vec<crate::oracle::HistoryOperation> {
            Vec::new()
        }
    }
    let mut program = Vec::new();
    push_decoys(&mut program, decoys, prefix);
    program.extend(critical);
    Box::new(W(vec![program]))
}

use ledger_sim::Instruction;

/// AZ double assign: the placement ledger records the AZ-b grant 43 and
/// reads it back. The ledger trusts the recorded grant without durability,
/// so a corrupt fault on the grant write flips the recorded shard id.
fn az_double_assign() -> Box<dyn Workload> {
    storage_workload(
        18,
        "decoy",
        vec![
            Instruction::FsWrite {
                path: "grant".into(),
                value: 43,
            },
            Instruction::FsRead {
                path: "grant".into(),
            },
            Instruction::Outcome,
        ],
    )
}

/// Instance flap: a registrar writes 24 durable blobs (each fsynced) and
/// then records the registration marker without an fsync and reads it back.
/// A crash that drops unsynced writes loses the marker: the registration is
/// not durable and the read-back oracle fails.
fn instance_flap() -> Box<dyn Workload> {
    const DURABLE: usize = 24;
    let mut program = Vec::with_capacity(DURABLE * 2 + 4);
    for index in 0..DURABLE {
        program.push(Instruction::FsWrite {
            path: format!("blob-{index}"),
            value: 42,
        });
        program.push(Instruction::FsFsync);
    }
    program.extend([
        Instruction::FsWrite {
            path: "dedup".into(),
            value: 777,
        },
        Instruction::FsRead {
            path: "dedup".into(),
        },
        Instruction::Outcome,
    ]);
    struct W(Vec<Vec<Instruction>>);
    impl Workload for W {
        fn programs(&self) -> Vec<Vec<Instruction>> {
            self.0.clone()
        }
        fn history(&self, _run: &RunResult) -> Vec<crate::oracle::HistoryOperation> {
            Vec::new()
        }
    }
    Box::new(W(vec![program]))
}

/// Config drift: the coordinator records the reconciled config 9 over the
/// stale 5 and reads the pointer back. A corrupt fault on the pointer write
/// flips the fleet onto a wrong version.
fn config_drift() -> Box<dyn Workload> {
    storage_workload(
        19,
        "decoy",
        vec![
            Instruction::FsWrite {
                path: "cfg-stale".into(),
                value: 5,
            },
            Instruction::FsWrite {
                path: "cfg".into(),
                value: 9,
            },
            Instruction::FsRead { path: "cfg".into() },
            Instruction::Outcome,
        ],
    )
}

/// Quota retry storm: the quota service records ticket 88, then records the
/// dedup marker 1 and reads it back. The marker is trusted without
/// durability: dropping the marker's path loses the dedup proof, so the
/// ticket can re-apply.
fn quota_retry_storm() -> Box<dyn Workload> {
    storage_workload(
        19,
        "decoy",
        vec![
            Instruction::FsWrite {
                path: "ticket-88".into(),
                value: 88,
            },
            Instruction::FsWrite {
                path: "dedup".into(),
                value: 1,
            },
            Instruction::FsRead {
                path: "dedup".into(),
            },
            Instruction::Outcome,
        ],
    )
}

/// Lease heartbeat: the node records the fresh lease epoch 7 over the stale
/// 6 and reads it back. A corrupt fault on the epoch write reinstates the
/// stale epoch value.
fn lease_heartbeat() -> Box<dyn Workload> {
    storage_workload(
        19,
        "decoy",
        vec![
            Instruction::FsWrite {
                path: "lease-stale".into(),
                value: 6,
            },
            Instruction::FsWrite {
                path: "lease".into(),
                value: 7,
            },
            Instruction::FsRead {
                path: "lease".into(),
            },
            Instruction::Outcome,
        ],
    )
}

/// Config publish: a fleet publisher writes 12 fsynced config shards, then
/// records the current-version pointer without an fsync and reads it back.
/// A torn write on the unsynced pointer loses the fleet's current version.
fn config_publish() -> Box<dyn Workload> {
    const SHARDS: usize = 12;
    let mut program = Vec::with_capacity(SHARDS * 2 + 4);
    for index in 0..SHARDS {
        program.push(Instruction::FsWrite {
            path: format!("cfg-{index}"),
            value: 5,
        });
        program.push(Instruction::FsFsync);
    }
    program.extend([
        Instruction::FsWrite {
            path: "current".into(),
            value: 9,
        },
        Instruction::FsRead {
            path: "current".into(),
        },
        Instruction::Outcome,
    ]);
    struct W(Vec<Vec<Instruction>>);
    impl Workload for W {
        fn programs(&self) -> Vec<Vec<Instruction>> {
            self.0.clone()
        }
        fn history(&self, _run: &RunResult) -> Vec<crate::oracle::HistoryOperation> {
            Vec::new()
        }
    }
    Box::new(W(vec![program]))
}

/// Quota dedup sector: the quota service records ticket 88 as consumed and
/// reads the marker back. A torn write on the unsynced marker corrupts the
/// record: the dedup proof no longer reads back.
fn quota_dedup_sector() -> Box<dyn Workload> {
    storage_workload(
        20,
        "decoy",
        vec![
            Instruction::FsWrite {
                path: "dedup".into(),
                value: 88,
            },
            Instruction::FsRead {
                path: "dedup".into(),
            },
            Instruction::Outcome,
        ],
    )
}

/// Drain completion: the agent records the completion marker 7 and reads it
/// back. Dropping the marker's unsynced write loses the completion proof.
fn drain_completion() -> Box<dyn Workload> {
    storage_workload(
        20,
        "decoy",
        vec![
            Instruction::FsWrite {
                path: "drain-marker".into(),
                value: 7,
            },
            Instruction::FsRead {
                path: "drain-marker".into(),
            },
            Instruction::Outcome,
        ],
    )
}

/// Dual region commit: two region commits are recorded, and the quorum
/// reads back the second region's commit as its proof. A corrupt fault on
/// the second region's commit corrupts the recorded quorum proof.
fn dual_region_commit() -> Box<dyn Workload> {
    storage_workload(
        19,
        "decoy",
        vec![
            Instruction::FsWrite {
                path: "region-a".into(),
                value: 5,
            },
            Instruction::FsWrite {
                path: "region-b".into(),
                value: 5,
            },
            Instruction::FsRead {
                path: "region-b".into(),
            },
            Instruction::Outcome,
        ],
    )
}

/// Canary promote: the canary records fleet results 42 and the promotion
/// verdict 43, which is read back. A corrupt fault on the promotion write
/// records a wrong verdict.
fn canary_promote() -> Box<dyn Workload> {
    storage_workload(
        18,
        "decoy",
        vec![
            Instruction::FsWrite {
                path: "fleet-1".into(),
                value: 42,
            },
            Instruction::FsWrite {
                path: "fleet-2".into(),
                value: 42,
            },
            Instruction::FsWrite {
                path: "promote".into(),
                value: 43,
            },
            Instruction::FsRead {
                path: "promote".into(),
            },
            Instruction::Outcome,
        ],
    )
}

// ---------------------------------------------------------------------------
// Per-scenario derivations
// ---------------------------------------------------------------------------

fn az_trigger(baseline: &Journal) -> Vec<SimFault> {
    vec![SimFault::Corrupt {
        write: last_fs_write(baseline, ledger_format::ActorId(0)),
        xor_mask: 1,
    }]
}

fn az_support(journal: &Journal) -> SupportExpr {
    support_last_fs_write(journal, ledger_format::ActorId(0))
}

fn az_space() -> Vec<SimFault> {
    write_fault_space(EntryHash([20; 32]), az_double_assign().as_ref())
}

fn flap_trigger(baseline: &Journal) -> Vec<SimFault> {
    vec![SimFault::CrashState {
        write: last_fs_write(baseline, ledger_format::ActorId(0)),
        state: 0,
    }]
}

fn flap_support(journal: &Journal) -> SupportExpr {
    support_last_fs_write(journal, ledger_format::ActorId(0))
}

fn flap_space() -> Vec<SimFault> {
    write_fault_space(EntryHash([21; 32]), instance_flap().as_ref())
}

fn drift_trigger(baseline: &Journal) -> Vec<SimFault> {
    vec![SimFault::Corrupt {
        write: last_fs_write(baseline, ledger_format::ActorId(0)),
        xor_mask: 0xFF,
    }]
}

fn drift_support(journal: &Journal) -> SupportExpr {
    support_last_fs_write(journal, ledger_format::ActorId(0))
}

fn drift_space() -> Vec<SimFault> {
    write_fault_space(EntryHash([22; 32]), config_drift().as_ref())
}

fn quota_trigger(baseline: &Journal) -> Vec<SimFault> {
    vec![SimFault::CrashState {
        write: last_fs_write(baseline, ledger_format::ActorId(0)),
        state: 1,
    }]
}

fn quota_support(journal: &Journal) -> SupportExpr {
    support_last_fs_write(journal, ledger_format::ActorId(0))
}

fn quota_space() -> Vec<SimFault> {
    write_fault_space(EntryHash([23; 32]), quota_retry_storm().as_ref())
}

fn heartbeat_trigger(baseline: &Journal) -> Vec<SimFault> {
    vec![SimFault::Corrupt {
        write: last_fs_write(baseline, ledger_format::ActorId(0)),
        xor_mask: 1,
    }]
}

fn heartbeat_support(journal: &Journal) -> SupportExpr {
    support_last_fs_write(journal, ledger_format::ActorId(0))
}

fn heartbeat_space() -> Vec<SimFault> {
    write_fault_space(EntryHash([24; 32]), lease_heartbeat().as_ref())
}

fn publish_trigger(baseline: &Journal) -> Vec<SimFault> {
    vec![SimFault::CrashState {
        write: last_fs_write(baseline, ledger_format::ActorId(0)),
        state: 2,
    }]
}

fn publish_support(journal: &Journal) -> SupportExpr {
    support_last_fs_write(journal, ledger_format::ActorId(0))
}

fn publish_space() -> Vec<SimFault> {
    write_fault_space(EntryHash([25; 32]), config_publish().as_ref())
}

fn dedup_trigger(baseline: &Journal) -> Vec<SimFault> {
    vec![SimFault::CrashState {
        write: last_fs_write(baseline, ledger_format::ActorId(0)),
        state: 2,
    }]
}

fn dedup_support(journal: &Journal) -> SupportExpr {
    support_last_fs_write(journal, ledger_format::ActorId(0))
}

fn dedup_space() -> Vec<SimFault> {
    write_fault_space(EntryHash([26; 32]), quota_dedup_sector().as_ref())
}

fn drain_trigger(baseline: &Journal) -> Vec<SimFault> {
    vec![SimFault::CrashState {
        write: last_fs_write(baseline, ledger_format::ActorId(0)),
        state: 0,
    }]
}

fn drain_support(journal: &Journal) -> SupportExpr {
    support_last_fs_write(journal, ledger_format::ActorId(0))
}

fn drain_space() -> Vec<SimFault> {
    write_fault_space(EntryHash([27; 32]), drain_completion().as_ref())
}

fn dual_trigger(baseline: &Journal) -> Vec<SimFault> {
    vec![SimFault::Corrupt {
        write: last_fs_write(baseline, ledger_format::ActorId(0)),
        xor_mask: 0xFF,
    }]
}

fn dual_support(journal: &Journal) -> SupportExpr {
    support_last_fs_write(journal, ledger_format::ActorId(0))
}

fn dual_space() -> Vec<SimFault> {
    write_fault_space(EntryHash([28; 32]), dual_region_commit().as_ref())
}

fn canary_trigger(baseline: &Journal) -> Vec<SimFault> {
    vec![SimFault::Corrupt {
        write: last_fs_write(baseline, ledger_format::ActorId(0)),
        xor_mask: 1,
    }]
}

fn canary_support(journal: &Journal) -> SupportExpr {
    support_last_fs_write(journal, ledger_format::ActorId(0))
}

fn canary_space() -> Vec<SimFault> {
    write_fault_space(EntryHash([29; 32]), canary_promote().as_ref())
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Every fault-triggered corpus-v2 scenario in manifest-name order.
pub fn faultdep_scenarios() -> Vec<FaultDepScenario> {
    vec![
        FaultDepScenario {
            name: "mini-cloud-az-double-assign",
            base_seed: EntryHash([20; 32]),
            class: ScenarioClass::CloudInfra,
            workload: az_double_assign,
            oracle: || final_value_oracle(43, "the placement ledger must hold grant 43"),
            fault_space: az_space,
            trigger: az_trigger,
            support: az_support,
        },
        FaultDepScenario {
            name: "mini-cloud-instance-flap",
            base_seed: EntryHash([21; 32]),
            class: ScenarioClass::CloudInfra,
            workload: instance_flap,
            oracle: || final_value_oracle(777, "registration marker must read back"),
            fault_space: flap_space,
            trigger: flap_trigger,
            support: flap_support,
        },
        FaultDepScenario {
            name: "mini-cloud-config-drift",
            base_seed: EntryHash([22; 32]),
            class: ScenarioClass::CloudInfra,
            workload: config_drift,
            oracle: || final_value_oracle(9, "fleet must read back the reconciled config"),
            fault_space: drift_space,
            trigger: drift_trigger,
            support: drift_support,
        },
        FaultDepScenario {
            name: "mini-cloud-quota-retry-storm",
            base_seed: EntryHash([23; 32]),
            class: ScenarioClass::CloudInfra,
            workload: quota_retry_storm,
            oracle: || final_value_oracle(1, "the dedup marker must read back"),
            fault_space: quota_space,
            trigger: quota_trigger,
            support: quota_support,
        },
        FaultDepScenario {
            name: "mini-cloud-lease-heartbeat",
            base_seed: EntryHash([24; 32]),
            class: ScenarioClass::CloudInfra,
            workload: lease_heartbeat,
            oracle: || final_value_oracle(7, "monitor must read back the fresh lease epoch"),
            fault_space: heartbeat_space,
            trigger: heartbeat_trigger,
            support: heartbeat_support,
        },
        FaultDepScenario {
            name: "mini-cloud-config-publish",
            base_seed: EntryHash([25; 32]),
            class: ScenarioClass::CloudInfra,
            workload: config_publish,
            oracle: || final_value_oracle(9, "current-version pointer must be durable"),
            fault_space: publish_space,
            trigger: publish_trigger,
            support: publish_support,
        },
        FaultDepScenario {
            name: "mini-cloud-quota-dedup-sector",
            base_seed: EntryHash([26; 32]),
            class: ScenarioClass::CloudInfra,
            workload: quota_dedup_sector,
            oracle: || final_value_oracle(88, "dedup marker must read back intact"),
            fault_space: dedup_space,
            trigger: dedup_trigger,
            support: dedup_support,
        },
        FaultDepScenario {
            name: "mini-cloud-drain-completion",
            base_seed: EntryHash([27; 32]),
            class: ScenarioClass::CloudInfra,
            workload: drain_completion,
            oracle: || final_value_oracle(7, "completion marker must read back"),
            fault_space: drain_space,
            trigger: drain_trigger,
            support: drain_support,
        },
        FaultDepScenario {
            name: "mini-cloud-dual-region-commit",
            base_seed: EntryHash([28; 32]),
            class: ScenarioClass::CloudInfra,
            workload: dual_region_commit,
            oracle: || final_value_oracle(5, "quorum must read back the region-b commit"),
            fault_space: dual_space,
            trigger: dual_trigger,
            support: dual_support,
        },
        FaultDepScenario {
            name: "mini-cloud-canary-promote",
            base_seed: EntryHash([29; 32]),
            class: ScenarioClass::CloudInfra,
            workload: canary_promote,
            oracle: || final_value_oracle(43, "promotion verdict must read back"),
            fault_space: canary_space,
            trigger: canary_trigger,
            support: canary_support,
        },
    ]
}

/// Look up one fault-triggered scenario by manifest name.
pub fn faultdep_scenario(name: &str) -> Option<FaultDepScenario> {
    faultdep_scenarios().into_iter().find(|s| s.name == name)
}
