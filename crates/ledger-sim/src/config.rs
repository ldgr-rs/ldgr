//! Run configuration shared by simulation and Explorer code.

use crate::net::{DnsTable, LinkConfig};
use crate::seedtree::SeedTree;
use ledger_format::{ActorId, Hash};

/// One deterministic fault at an exact causal position (a journal entry id).
///
/// The Explorer converts LDFI hypothesis cuts into these schedules; the
/// executor applies each injection when it journals the targeted entry. The
/// name `SimFault` keeps this engine type distinct from the string-targeted
/// [`ledger_faultspec::FaultInjection`]; the bridge in `ledger-explorer`
/// converts between the two at the porting seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimFault {
    /// Drop the message sent by this `Send` entry.
    Drop(Hash),
    /// Delay delivery of this `Send` entry by `ticks`.
    Delay { send: Hash, ticks: u64 },
    /// Partition the directed link (applied when the executor starts).
    Partition { src: ActorId, dst: ActorId },
    /// Crash storage immediately after this `FsWrite` entry.
    Crash(Hash),
    /// Corrupt the stored value after this `FsWrite` entry with an xor mask.
    Corrupt { write: Hash, xor_mask: u64 },
    /// Apply the crash-state operator at index `state` after this `FsWrite`.
    CrashState { write: Hash, state: u64 },
}

/// Scheduling policy for one deterministic run.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Policy {
    /// Select a ready task from the seeded stream.
    Random,
    /// Use a bounded probabilistic concurrency schedule (PCT).
    ///
    /// `priority_changes` is the preemption budget `k`: at most `k` preemptions
    /// happen per run, and each preemption re-assigns the ready tasks'
    /// priorities. A budget of `0` never preempts and reduces to a fixed
    /// priority order. See [`crate::scheduler::Scheduler`].
    Pct { priority_changes: usize },
    /// Journal-novelty guided bandit with UCB1 exploration constant.
    ///
    /// `pct_mix` is the probability in `0.0 ..= 1.0` of injecting a PCT-style
    /// preemption instead of a pure UCB1 choice. Default is `0.1`.
    Bandit {
        exploration_constant: f64,
        pct_mix: f64,
    },
    /// Follow a previously recorded task decision sequence.
    ///
    /// When the replay sequence is exhausted the scheduler delegates to its
    /// fallback policy ([`crate::scheduler::Scheduler::with_fallback`]).
    Replay,
    /// Source-DPOR exploration base for a single run.
    ///
    /// One `Simulation::run()` under `Dpor` behaves exactly like `Random`; the
    /// [`crate::dpor::run_dpor`] driver uses the recorded trace to explore
    /// causally distinct schedules around this base run.
    Dpor,
}

impl Eq for Policy {}

/// Swarm parameters for randomized fault and network configuration.
///
/// The executor boundary consumes these: drop and delay draws gate `SimNet`
/// delivery, and the crash probability selects a post-crash state on storage
/// write.
#[derive(Debug, Clone, PartialEq)]
pub struct SwarmConfig {
    /// Drop probability for network messages (0.0 .. 1.0).
    pub drop_probability: f64,
    /// Delay probability for network messages (0.0 .. 1.0).
    pub delay_probability: f64,
    /// Maximum virtual time delay in ticks.
    pub max_delay_ticks: u64,
    /// Crash probability on storage write (0.0 .. 1.0).
    pub crash_probability: f64,
    /// Campaign budget on distinct fault classes sampled per run.
    ///
    /// This is a budget, not a semantic guarantee: once this many distinct
    /// post-crash state classes have been applied, further sampled crashes are
    /// skipped. Minimum 1.
    pub fault_classes_per_run: usize,
}

impl Default for SwarmConfig {
    fn default() -> Self {
        Self {
            drop_probability: 0.0,
            delay_probability: 0.0,
            max_delay_ticks: 0,
            crash_probability: 0.0,
            fault_classes_per_run: 2,
        }
    }
}

/// Immutable configuration for one simulation.
///
/// Construction is stable via [`RunConfig::builder`]. Direct field access is
/// crate-private; external crates use the builder and the read accessors.
/// This keeps the layout stable across features: the `fs_journaling` field
/// only exists with `sim-fs-journaling` and is handled inside the builder, so
/// callers do not need `#[cfg]` guards at construction sites.
#[derive(Debug, Clone)]
pub struct RunConfig {
    pub(crate) seed: Hash,
    pub(crate) policy: Policy,
    pub(crate) max_steps: usize,
    pub(crate) dropped_events: Vec<Hash>,
    pub(crate) swarm: SwarmConfig,
    pub(crate) links: Vec<(usize, usize, LinkConfig)>,
    pub(crate) dns: DnsTable,
    pub(crate) fault_schedule: Vec<SimFault>,
    #[cfg(feature = "sim-fs-journaling")]
    pub(crate) fs_journaling: Option<crate::simfs::JournalingMode>,
    pub(crate) monitor: bool,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            seed: [0; 32],
            policy: Policy::Random,
            max_steps: 10_000,
            dropped_events: Vec::new(),
            swarm: SwarmConfig::default(),
            links: Vec::new(),
            dns: DnsTable::new(),
            fault_schedule: Vec::new(),
            #[cfg(feature = "sim-fs-journaling")]
            fs_journaling: None,
            monitor: true,
        }
    }
}

impl RunConfig {
    /// Return a builder initialized from [`RunConfig::default`].
    pub fn builder() -> RunConfigBuilder {
        RunConfigBuilder::default()
    }

    /// Derive the seed tree for this config's root seed.
    pub fn seed_tree(&self) -> SeedTree {
        SeedTree::new(self.seed)
    }

    // -----------------------------------------------------------------------
    // Read accessors (stable API). The `fs_journaling` accessor is gated by
    // the `sim-fs-journaling` feature; only the builder hides that cfg.
    // -----------------------------------------------------------------------

    /// Root seed for all independent streams.
    pub fn seed(&self) -> Hash {
        self.seed
    }

    /// Scheduling policy for the run.
    pub fn policy(&self) -> Policy {
        self.policy
    }

    /// Maximum number of executed instructions.
    ///
    /// The executor expects `max_steps >= 1`; a budget of `0` yields an
    /// immediate `StepLimit { limit: 0 }` (deterministic, no work runs).
    pub fn max_steps(&self) -> usize {
        self.max_steps
    }

    /// Journal event hashes whose effects must be dropped.
    pub fn dropped_events(&self) -> &[Hash] {
        &self.dropped_events
    }

    /// Swarm testing parameters.
    pub fn swarm(&self) -> &SwarmConfig {
        &self.swarm
    }

    /// Per-link transport configuration.
    pub fn links(&self) -> &[(usize, usize, LinkConfig)] {
        &self.links
    }

    /// Hostname-to-actor resolution table.
    pub fn dns(&self) -> &DnsTable {
        &self.dns
    }

    /// Fault schedule injected at exact causal positions.
    pub fn fault_schedule(&self) -> &[SimFault] {
        &self.fault_schedule
    }

    /// Whether the journal-correctness monitor runs.
    pub fn monitor(&self) -> bool {
        self.monitor
    }

    /// Journaling-FS crash model.
    ///
    /// `None` keeps the black-box `DropAllUnsynced` operator (the byte-identical
    /// default). When set, the executor replays the write-ahead journal on crash.
    #[cfg(feature = "sim-fs-journaling")]
    pub fn fs_journaling(&self) -> Option<crate::simfs::JournalingMode> {
        self.fs_journaling
    }

    // -----------------------------------------------------------------------
    // Mutable accessors for in-place updates (escape hatch for campaign and
    // bridge code that mutates a config after construction).
    //
    // Prefer the builder for new code. Each accessor exposes one field; the
    // invariants documented on the builder setters apply to writes through
    // these accessors as well.
    // -----------------------------------------------------------------------

    /// Mutable root seed.
    pub fn seed_mut(&mut self) -> &mut Hash {
        &mut self.seed
    }

    /// Mutable scheduling policy.
    pub fn policy_mut(&mut self) -> &mut Policy {
        &mut self.policy
    }

    /// Mutable instruction budget.
    ///
    /// Expect `max_steps >= 1`; a budget of `0` yields an immediate
    /// `StepLimit { limit: 0 }` (deterministic, no work runs).
    pub fn max_steps_mut(&mut self) -> &mut usize {
        &mut self.max_steps
    }

    /// Mutable swarm parameters.
    pub fn swarm_mut(&mut self) -> &mut SwarmConfig {
        &mut self.swarm
    }

    /// Mutable DNS table.
    pub fn dns_mut(&mut self) -> &mut DnsTable {
        &mut self.dns
    }

    /// Mutable fault schedule.
    pub fn fault_schedule_mut(&mut self) -> &mut Vec<SimFault> {
        &mut self.fault_schedule
    }

    /// Extend the fault schedule in place.
    pub fn extend_fault_schedule(&mut self, faults: impl IntoIterator<Item = SimFault>) {
        self.fault_schedule.extend(faults);
    }
}

/// Builder for [`RunConfig`] with stable, additive setters.
///
/// Defaults mirror [`RunConfig::default`]. Call [`RunConfigBuilder::build`]
/// to finish. The `fs_journaling` setter is only available with the
/// `sim-fs-journaling` feature; without it the field stays at its default and
/// no caller `#[cfg]` is required.
#[derive(Debug, Clone)]
pub struct RunConfigBuilder {
    seed: Hash,
    policy: Policy,
    max_steps: usize,
    dropped_events: Vec<Hash>,
    swarm: SwarmConfig,
    links: Vec<(usize, usize, LinkConfig)>,
    dns: DnsTable,
    fault_schedule: Vec<SimFault>,
    #[cfg(feature = "sim-fs-journaling")]
    fs_journaling: Option<crate::simfs::JournalingMode>,
    monitor: bool,
}

impl Default for RunConfigBuilder {
    fn default() -> Self {
        Self {
            seed: [0; 32],
            policy: Policy::Random,
            max_steps: 10_000,
            dropped_events: Vec::new(),
            swarm: SwarmConfig::default(),
            links: Vec::new(),
            dns: DnsTable::new(),
            fault_schedule: Vec::new(),
            #[cfg(feature = "sim-fs-journaling")]
            fs_journaling: None,
            monitor: true,
        }
    }
}

impl RunConfigBuilder {
    /// Create a new builder from defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the root seed.
    pub fn seed(mut self, seed: Hash) -> Self {
        self.seed = seed;
        self
    }

    /// Set the scheduling policy.
    pub fn policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// Set the instruction budget.
    ///
    /// Expect `max_steps >= 1`; a budget of `0` yields an immediate
    /// `StepLimit { limit: 0 }` (deterministic, no work runs).
    pub fn max_steps(mut self, max_steps: usize) -> Self {
        self.max_steps = max_steps;
        self
    }

    /// Set the dropped-events list.
    pub fn dropped_events(mut self, dropped_events: Vec<Hash>) -> Self {
        self.dropped_events = dropped_events;
        self
    }

    /// Set swarm parameters.
    pub fn swarm(mut self, swarm: SwarmConfig) -> Self {
        self.swarm = swarm;
        self
    }

    /// Set per-link configuration.
    pub fn links(mut self, links: Vec<(usize, usize, LinkConfig)>) -> Self {
        self.links = links;
        self
    }

    /// Set the DNS table.
    pub fn dns(mut self, dns: DnsTable) -> Self {
        self.dns = dns;
        self
    }

    /// Set the fault schedule.
    pub fn fault_schedule(mut self, fault_schedule: Vec<SimFault>) -> Self {
        self.fault_schedule = fault_schedule;
        self
    }

    /// Set whether the monitor runs.
    pub fn monitor(mut self, monitor: bool) -> Self {
        self.monitor = monitor;
        self
    }

    /// Set the journaling-FS crash model.
    ///
    /// `None` keeps the black-box operator. Handled inside the builder so
    /// callers need no `#[cfg]` guard; without the feature this setter does
    /// not exist and the builder stays at its default.
    #[cfg(feature = "sim-fs-journaling")]
    pub fn fs_journaling(mut self, fs_journaling: Option<crate::simfs::JournalingMode>) -> Self {
        self.fs_journaling = fs_journaling;
        self
    }

    /// Build the [`RunConfig`].
    pub fn build(self) -> RunConfig {
        RunConfig {
            seed: self.seed,
            policy: self.policy,
            max_steps: self.max_steps,
            dropped_events: self.dropped_events,
            swarm: self.swarm,
            links: self.links,
            dns: self.dns,
            fault_schedule: self.fault_schedule,
            #[cfg(feature = "sim-fs-journaling")]
            fs_journaling: self.fs_journaling,
            monitor: self.monitor,
        }
    }
}

impl From<RunConfigBuilder> for RunConfig {
    fn from(builder: RunConfigBuilder) -> Self {
        builder.build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::LinkConfig;

    #[test]
    fn builder_default_matches_run_config_default() {
        let via_builder = RunConfig::builder().build();
        let via_default = RunConfig::default();
        assert_eq!(via_builder.seed(), via_default.seed());
        assert_eq!(via_builder.policy(), via_default.policy());
        assert_eq!(via_builder.max_steps(), via_default.max_steps());
        assert_eq!(via_builder.dropped_events(), via_default.dropped_events());
        assert_eq!(via_builder.swarm(), via_default.swarm());
        assert_eq!(via_builder.links(), via_default.links());
        assert_eq!(via_builder.dns().len(), via_default.dns().len());
        assert_eq!(via_builder.fault_schedule(), via_default.fault_schedule());
        assert_eq!(via_builder.monitor(), via_default.monitor());
        #[cfg(feature = "sim-fs-journaling")]
        assert_eq!(via_builder.fs_journaling(), via_default.fs_journaling());
    }

    #[test]
    fn builder_round_trips_all_fields() {
        let seed = [7u8; 32];
        let policy = Policy::Pct {
            priority_changes: 3,
        };
        let max_steps = 42_042;
        let dropped = vec![[1u8; 32], [2u8; 32]];
        let swarm = SwarmConfig {
            drop_probability: 0.3,
            delay_probability: 0.2,
            max_delay_ticks: 7,
            crash_probability: 0.1,
            fault_classes_per_run: 5,
        };
        let links = vec![(
            0,
            1,
            LinkConfig {
                base_delay: 5,
                jitter: 2,
                loss_probability: 0.1,
                reorder_window: 3,
            },
        )];
        let mut dns = DnsTable::new();
        dns.insert("alpha.test", 1);
        dns.insert("beta.test", 2);
        let faults = vec![SimFault::Partition { src: 0, dst: 1 }];
        let cfg = RunConfig::builder()
            .seed(seed)
            .policy(policy)
            .max_steps(max_steps)
            .dropped_events(dropped.clone())
            .swarm(swarm.clone())
            .links(links.clone())
            .dns(dns.clone())
            .fault_schedule(faults.clone())
            .monitor(false)
            .build();
        assert_eq!(cfg.seed(), seed);
        assert_eq!(cfg.policy(), policy);
        assert_eq!(cfg.max_steps(), max_steps);
        assert_eq!(cfg.dropped_events(), dropped.as_slice());
        assert_eq!(cfg.swarm(), &swarm);
        assert_eq!(cfg.links(), links.as_slice());
        assert_eq!(cfg.dns().len(), 2);
        assert_eq!(cfg.dns().resolve("alpha.test"), Some(1));
        assert_eq!(cfg.fault_schedule(), faults.as_slice());
        assert!(!cfg.monitor());
    }

    #[cfg(feature = "sim-fs-journaling")]
    #[test]
    fn fs_journaling_round_trips_via_builder() {
        use crate::simfs::JournalingMode;
        let cfg = RunConfig::builder()
            .fs_journaling(Some(JournalingMode::Writeback))
            .build();
        assert_eq!(cfg.fs_journaling(), Some(JournalingMode::Writeback));
        let cfg2 = RunConfig::builder()
            .fs_journaling(Some(JournalingMode::Data))
            .build();
        assert_eq!(cfg2.fs_journaling(), Some(JournalingMode::Data));
        let cfg3 = RunConfig::builder().fs_journaling(None).build();
        assert_eq!(cfg3.fs_journaling(), None);
    }

    #[cfg(feature = "sim-fs-journaling")]
    #[test]
    fn builder_fs_journaling_default_is_none() {
        let cfg = RunConfig::builder().build();
        assert_eq!(cfg.fs_journaling(), None);
    }
}
