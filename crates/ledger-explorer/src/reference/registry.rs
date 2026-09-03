use super::sims::{
    mini_2pc, mini_2pc_support, mini_cassandra, mini_cassandra_support, mini_hdfs,
    mini_hdfs_lease_expiry, mini_hdfs_lease_expiry_support, mini_hdfs_support,
    mini_kv_stale_read_support, mini_leader_stepdown, mini_leader_stepdown_support,
    mini_lease_timer_race, mini_lease_timer_race_support, mini_membership_churn,
    mini_membership_churn_support, mini_partition_retry_dup, mini_partition_retry_dup_support,
    mini_reorder_lost_update, mini_reorder_lost_update_support, mini_restart_dup_append,
    mini_restart_dup_append_support, mini_zab, mini_zab_support,
};
use crate::oracle::{HistoryOracle, KeyValueSpec, Oracle, PropertyOracle, Verdict};
use crate::search::Finding;
use crate::search::Workload as _;
use crate::workloads::MiniKvWorkload;
use ledger_format::ActorId;
use ledger_format::EntryHash;
use ledger_journal::Journal;
use ledger_sim::{Policy, RunConfig, RunResult, RuntimeError, SimFault, Simulation, TaskBuilder};

// ---------------------------------------------------------------------------
// Corpus scenario registry
// ---------------------------------------------------------------------------

/// Typed failure of a reference-scenario fault replay.
///
/// Strict-replay rejections surface as the typed
/// [`RuntimeError::StrictReplay`] source, so callers match the variant
/// instead of error text.
#[derive(Debug, thiserror::Error)]
pub enum ReferenceReplayError {
    /// The engine rejected the replay run.
    #[error("{name}: reference fault replay failed")]
    Engine {
        name: &'static str,
        #[source]
        source: RuntimeError,
    },
}

/// The Mini-KV workload as a `static` so oracles borrowing it are `'static`.
static MINI_KV: MiniKvWorkload = MiniKvWorkload;

/// How one corpus-v1 scenario executes and is judged.
pub enum CorpusRunner {
    /// Reference sim on the effect boundary: fresh task builders plus a
    /// journal property that holds only when the system is correct.
    Tasks {
        builders: fn() -> Vec<TaskBuilder>,
        property: fn(&Journal) -> bool,
    },
    /// The schedule-dependent Mini-KV program workload, found by search.
    MiniKv,
}

/// One bug-corpus-v1 scenario: the single registry the corpus gates, the
/// manifest generator, and the LDFI efficiency gate consume. Adding a
/// scenario means adding one entry here plus its committed manifest; no gate
/// may keep a private name-to-builder mapping.
pub struct CorpusScenario {
    /// Manifest file stem under `corpora/bug-corpus-v1/`.
    pub name: &'static str,
    /// Pinned base seed: the manifest seed for reference sims, the search
    /// start seed for Mini-Kv.
    pub base_seed: EntryHash,
    /// How the scenario runs and which oracle judges it.
    pub runner: CorpusRunner,
    /// Declared candidate fault space (partitions, drops, delays) for
    /// schedule exploration. The space is derived from a seed-0 probe run,
    /// never from a violating run.
    pub fault_space: fn() -> Result<Vec<SimFault>, String>,
    /// Explicit support model for this scenario's planted violation. The
    /// provider digest and version join solver cache keys, so a model change
    /// never reuses derived clauses.
    pub support: fn(&Journal) -> crate::support::SupportExpr,
}

/// Every bug-corpus-v1 scenario in manifest-name order.
pub fn corpus_scenarios() -> Vec<CorpusScenario> {
    vec![
        CorpusScenario {
            name: "mini-zab-split-brain",
            base_seed: EntryHash([1; 32]),
            runner: CorpusRunner::Tasks {
                builders: zab_builders,
                property: zab_property,
            },
            fault_space: four_link_faults,
            support: mini_zab_support,
        },
        CorpusScenario {
            name: "mini-hdfs-double-grant",
            base_seed: EntryHash([2; 32]),
            runner: CorpusRunner::Tasks {
                builders: hdfs_builders,
                property: hdfs_property,
            },
            fault_space: four_link_faults,
            support: mini_hdfs_support,
        },
        CorpusScenario {
            name: "mini-cassandra-stale-read",
            base_seed: EntryHash([3; 32]),
            runner: CorpusRunner::Tasks {
                builders: cassandra_builders,
                property: cassandra_property,
            },
            fault_space: four_link_faults,
            support: mini_cassandra_support,
        },
        CorpusScenario {
            name: "mini-2pc-coordinator-crash",
            base_seed: EntryHash([4; 32]),
            runner: CorpusRunner::Tasks {
                builders: two_pc_builders,
                property: two_pc_property,
            },
            fault_space: four_link_faults,
            support: mini_2pc_support,
        },
        CorpusScenario {
            name: "mini-leader-stepdown",
            base_seed: EntryHash([5; 32]),
            runner: CorpusRunner::Tasks {
                builders: leader_stepdown_builders,
                property: leader_stepdown_property,
            },
            fault_space: four_link_faults,
            support: mini_leader_stepdown_support,
        },
        CorpusScenario {
            name: "mini-membership-churn",
            base_seed: EntryHash([6; 32]),
            runner: CorpusRunner::Tasks {
                builders: membership_churn_builders,
                property: membership_churn_property,
            },
            fault_space: four_link_faults,
            support: mini_membership_churn_support,
        },
        CorpusScenario {
            name: "mini-hdfs-lease-expiry",
            base_seed: EntryHash([7; 32]),
            runner: CorpusRunner::Tasks {
                builders: hdfs_lease_expiry_builders,
                property: hdfs_lease_expiry_property,
            },
            fault_space: four_link_faults,
            support: mini_hdfs_lease_expiry_support,
        },
        CorpusScenario {
            name: "mini-kv-stale-read",
            base_seed: EntryHash([0; 32]),
            runner: CorpusRunner::MiniKv,
            fault_space: mini_kv_faults,
            support: mini_kv_stale_read_support,
        },
        CorpusScenario {
            name: "mini-reorder-lost-update",
            base_seed: EntryHash([8; 32]),
            runner: CorpusRunner::Tasks {
                builders: reorder_lost_update_builders,
                property: reorder_lost_update_property,
            },
            fault_space: four_link_faults,
            support: mini_reorder_lost_update_support,
        },
        CorpusScenario {
            name: "mini-lease-timer-race",
            base_seed: EntryHash([9; 32]),
            runner: CorpusRunner::Tasks {
                builders: lease_timer_race_builders,
                property: lease_timer_race_property,
            },
            fault_space: four_link_faults,
            support: mini_lease_timer_race_support,
        },
        CorpusScenario {
            name: "mini-restart-dup-append",
            base_seed: EntryHash([10; 32]),
            runner: CorpusRunner::Tasks {
                builders: restart_dup_append_builders,
                property: restart_dup_append_property,
            },
            fault_space: appender_chain_faults,
            support: mini_restart_dup_append_support,
        },
        CorpusScenario {
            name: "mini-partition-retry-dup",
            base_seed: EntryHash([11; 32]),
            runner: CorpusRunner::Tasks {
                builders: partition_retry_dup_builders,
                property: partition_retry_dup_property,
            },
            fault_space: client_server_faults,
            support: mini_partition_retry_dup_support,
        },
    ]
}

/// Cloud-infra bug class for the staged corpus v2 (Anduril-style).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScenarioClass {
    /// Jepsen-style partition/clock/nemesis and consensus bugs.
    Jepsen,
    /// Crash-consistency: durable write, lease timer, restart duplications.
    CrashConsistency,
    /// Cloud control-plane infra: AZ fencing, instance lifecycle, rollout, quota.
    CloudInfra,
}

/// Explicit class label for every scenario across v1 and the fault-triggered
/// v2 set.
pub fn scenario_class(name: &str) -> Option<ScenarioClass> {
    match name {
        "mini-zab-split-brain" => Some(ScenarioClass::Jepsen),
        "mini-hdfs-double-grant" => Some(ScenarioClass::Jepsen),
        "mini-cassandra-stale-read" => Some(ScenarioClass::Jepsen),
        "mini-2pc-coordinator-crash" => Some(ScenarioClass::CrashConsistency),
        "mini-leader-stepdown" => Some(ScenarioClass::Jepsen),
        "mini-membership-churn" => Some(ScenarioClass::Jepsen),
        "mini-hdfs-lease-expiry" => Some(ScenarioClass::CrashConsistency),
        "mini-kv-stale-read" => Some(ScenarioClass::Jepsen),
        "mini-reorder-lost-update" => Some(ScenarioClass::Jepsen),
        "mini-lease-timer-race" => Some(ScenarioClass::CrashConsistency),
        "mini-restart-dup-append" => Some(ScenarioClass::CrashConsistency),
        "mini-partition-retry-dup" => Some(ScenarioClass::Jepsen),
        "mini-cloud-az-double-assign" => Some(ScenarioClass::CloudInfra),
        "mini-cloud-instance-flap" => Some(ScenarioClass::CloudInfra),
        "mini-cloud-config-drift" => Some(ScenarioClass::CloudInfra),
        "mini-cloud-quota-retry-storm" => Some(ScenarioClass::CloudInfra),
        "mini-cloud-lease-heartbeat" => Some(ScenarioClass::CloudInfra),
        "mini-cloud-config-publish" => Some(ScenarioClass::CloudInfra),
        "mini-cloud-quota-dedup-sector" => Some(ScenarioClass::CloudInfra),
        "mini-cloud-drain-completion" => Some(ScenarioClass::CloudInfra),
        "mini-cloud-dual-region-commit" => Some(ScenarioClass::CloudInfra),
        "mini-cloud-canary-promote" => Some(ScenarioClass::CloudInfra),
        _ => None,
    }
}

/// Look up one registry entry by manifest name.
pub fn corpus_scenario(name: &str) -> Option<CorpusScenario> {
    corpus_scenarios()
        .into_iter()
        .find(|scenario| scenario.name == name)
}

impl CorpusScenario {
    /// Versioned support provider for this scenario's declared model,
    /// evaluated on a concrete journal.
    ///
    /// The expression ids are content hashes of the journal's entries, so a
    /// model built from one run's journal is only meaningful for that run.
    /// Callers pass the canonical run of the scenario (its pinned violating
    /// run, or a no-fault probe).
    pub fn support_provider(&self, journal: &Journal) -> crate::support::StaticSupportProvider {
        crate::support::StaticSupportProvider::new(1, (self.support)(journal))
    }

    /// Run the scenario at `seed` with optional injected faults under the
    /// corpus gate config (Random policy, 4096-step budget).
    pub fn run(&self, seed: EntryHash, faults: Vec<SimFault>) -> Result<RunResult, RuntimeError> {
        let config = RunConfig::builder()
            .seed(seed)
            .policy(Policy::Random)
            .max_steps(4096)
            .fault_schedule(faults)
            .build();
        match &self.runner {
            CorpusRunner::Tasks { builders, .. } => {
                Simulation::with_tasks(config, builders()).run()
            }
            CorpusRunner::MiniKv => Simulation::new(config, MINI_KV.programs()).run(),
        }
    }

    /// Boxed oracle for search and campaign APIs.
    pub fn oracle(&self) -> Box<dyn Oracle> {
        match &self.runner {
            CorpusRunner::Tasks { property, .. } => Box::new(PropertyOracle {
                property: *property,
                name: self.name.to_string(),
            }),
            CorpusRunner::MiniKv => Box::new(HistoryOracle::new(&MINI_KV, KeyValueSpec::default())),
        }
    }

    /// Oracle verdict for a completed run of this scenario.
    pub fn check(&self, run: &RunResult) -> Verdict {
        self.oracle().check(run)
    }

    /// The canonical violating run: reference sims run at the base seed;
    /// Mini-Kv searches from the base seed because its bug is
    /// schedule-dependent.
    pub fn reproduce(&self) -> Result<Finding, String> {
        match &self.runner {
            CorpusRunner::Tasks { .. } => {
                let run = self
                    .run(self.base_seed, Vec::new())
                    .map_err(|error| format!("{}: run failed: {error}", self.name))?;
                let verdict = self.check(&run);
                if !verdict.violated {
                    return Err(format!("{}: the planted bug must fire", self.name));
                }
                Ok(Finding {
                    seed: self.base_seed,
                    run,
                    verdict,
                })
            }
            CorpusRunner::MiniKv => {
                let config = RunConfig::builder()
                    .seed(self.base_seed)
                    .policy(Policy::Random)
                    .max_steps(4096)
                    .build();
                let oracle = HistoryOracle::new(&MINI_KV, KeyValueSpec::default());
                crate::search::search(&MINI_KV, &oracle, config, 256)
                    .map_err(|error| format!("{}: mini-kv search failed: {error}", self.name))?
                    .ok_or_else(|| "mini-kv-stale-read: no violating seed found".to_string())
            }
        }
    }

    /// Replay a fault schedule against a recorded witness run under its
    /// finding seed.
    ///
    /// Reference sims re-run their task builders under the same seed with
    /// the schedule injected; the Mini-Kv workload replays the witness's
    /// recorded decisions with the schedule injected (the witness-cut
    /// mechanic).
    pub fn replay_faults(
        &self,
        seed: EntryHash,
        witness: &RunResult,
        schedule: Vec<SimFault>,
    ) -> Result<RunResult, ReferenceReplayError> {
        match &self.runner {
            CorpusRunner::Tasks { builders, .. } => {
                let config = RunConfig::builder()
                    .seed(seed)
                    .policy(Policy::Random)
                    .max_steps(4096)
                    .fault_schedule(schedule)
                    .build();
                Simulation::with_tasks(config, builders())
                    .run()
                    .map_err(|source| ReferenceReplayError::Engine {
                        name: self.name,
                        source,
                    })
            }
            CorpusRunner::MiniKv => {
                let config = RunConfig::builder()
                    .seed(seed)
                    .policy(Policy::Replay)
                    .max_steps(witness.decisions.len().saturating_add(256))
                    .fault_schedule(schedule)
                    .build();
                Simulation::with_replay_strict(
                    config,
                    MINI_KV.programs(),
                    witness.decisions.clone(),
                )
                .run()
                .map_err(|source| ReferenceReplayError::Engine {
                    name: self.name,
                    source,
                })
            }
        }
    }
}

// Adapter shims: the mini constructors return owned closures, the registry
// stores plain fn pointers so every entry is a value in one table.

fn zab_builders() -> Vec<TaskBuilder> {
    mini_zab().0
}
fn zab_property(journal: &Journal) -> bool {
    (mini_zab().1)(journal)
}
fn hdfs_builders() -> Vec<TaskBuilder> {
    mini_hdfs().0
}
fn hdfs_property(journal: &Journal) -> bool {
    (mini_hdfs().1)(journal)
}
fn cassandra_builders() -> Vec<TaskBuilder> {
    mini_cassandra().0
}
fn cassandra_property(journal: &Journal) -> bool {
    (mini_cassandra().1)(journal)
}
fn two_pc_builders() -> Vec<TaskBuilder> {
    mini_2pc().0
}
fn two_pc_property(journal: &Journal) -> bool {
    (mini_2pc().1)(journal)
}
fn leader_stepdown_builders() -> Vec<TaskBuilder> {
    mini_leader_stepdown().0
}
fn leader_stepdown_property(journal: &Journal) -> bool {
    (mini_leader_stepdown().1)(journal)
}
fn membership_churn_builders() -> Vec<TaskBuilder> {
    mini_membership_churn().0
}
fn membership_churn_property(journal: &Journal) -> bool {
    (mini_membership_churn().1)(journal)
}
fn hdfs_lease_expiry_builders() -> Vec<TaskBuilder> {
    mini_hdfs_lease_expiry().0
}
fn hdfs_lease_expiry_property(journal: &Journal) -> bool {
    (mini_hdfs_lease_expiry().1)(journal)
}
fn reorder_lost_update_builders() -> Vec<TaskBuilder> {
    mini_reorder_lost_update().0
}
fn reorder_lost_update_property(journal: &Journal) -> bool {
    (mini_reorder_lost_update().1)(journal)
}
fn lease_timer_race_builders() -> Vec<TaskBuilder> {
    mini_lease_timer_race().0
}
fn lease_timer_race_property(journal: &Journal) -> bool {
    (mini_lease_timer_race().1)(journal)
}
fn restart_dup_append_builders() -> Vec<TaskBuilder> {
    mini_restart_dup_append().0
}
fn restart_dup_append_property(journal: &Journal) -> bool {
    (mini_restart_dup_append().1)(journal)
}
fn partition_retry_dup_builders() -> Vec<TaskBuilder> {
    mini_partition_retry_dup().0
}
fn partition_retry_dup_property(journal: &Journal) -> bool {
    (mini_partition_retry_dup().1)(journal)
}

/// Partition faults over a set of directed actor links.
fn link_partitions(links: &[(u32, u32)]) -> Vec<SimFault> {
    links
        .iter()
        .map(|&(src, dst)| SimFault::Partition {
            src: ActorId(src),
            dst: ActorId(dst),
        })
        .collect()
}

/// Three-actor links where actors 1 and 2 talk to actor 0 only.
fn four_link_faults() -> Result<Vec<SimFault>, String> {
    Ok(link_partitions(&[(0, 1), (0, 2), (1, 0), (2, 0)]))
}

/// Three-actor chain: client 0 to appender 1 to durable log 2.
fn appender_chain_faults() -> Result<Vec<SimFault>, String> {
    Ok(link_partitions(&[(0, 1), (1, 0), (1, 2), (2, 1)]))
}

/// Two-actor client/server links.
fn client_server_faults() -> Result<Vec<SimFault>, String> {
    Ok(link_partitions(&[(0, 1), (1, 0)]))
}

/// Mini-Kv fault space: partitions over its three actors plus drop/delay
/// candidates on every `Send` of a seed-0 probe run. The program is small
/// and deterministic, so the probe's send ids are stable across run seeds,
/// and the probe knows nothing about any violating run.
fn mini_kv_faults() -> Result<Vec<SimFault>, String> {
    let mut space = link_partitions(&[(0, 1), (0, 2), (1, 0), (1, 2), (2, 0), (2, 1)]);
    let config = RunConfig::builder()
        .seed(EntryHash([0; 32]))
        .policy(Policy::Random)
        .max_steps(512)
        .build();
    let probe = Simulation::new(config, MINI_KV.programs())
        .run()
        .map_err(|error| format!("mini-kv fault probe failed: {error}"))?;
    for entry in probe.journal.entries() {
        if entry.data.kind == ledger_format::EntryKind::Send {
            space.push(SimFault::Drop(entry.id));
            space.push(SimFault::Delay {
                send: entry.id,
                ticks: 1,
            });
        }
    }
    Ok(space)
}
