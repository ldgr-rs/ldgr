//! Run configuration shared by simulation and Explorer code.

use crate::net::{DnsTable, LinkConfig};
use crate::seedtree::SeedTree;
use ledger_format::{ActorId, Hash};

/// One fault injection at an exact causal position (a journal entry id).
///
/// The Explorer converts LDFI hypothesis cuts into these schedules; the
/// executor applies each injection when it journals the targeted entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaultInjection {
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
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// Root seed for all independent streams.
    pub seed: Hash,
    pub policy: Policy,
    /// Maximum number of executed instructions.
    pub max_steps: usize,
    /// Journal event hashes whose effects must be dropped.
    pub dropped_events: Vec<Hash>,
    /// Optional swarm testing parameters.
    pub swarm: SwarmConfig,
    /// Per-link transport configuration applied to the simulated network.
    /// Absent links use the zero config, which draws nothing and stays
    /// byte-identical to the unconfigured path.
    pub links: Vec<(usize, usize, LinkConfig)>,
    /// Hostname-to-actor resolution table for the simulated network.
    /// Empty by default, which keeps journals byte-identical to the path
    /// without DNS.
    pub dns: DnsTable,
    /// Fault schedule injected at exact causal positions. Empty by default.
    pub fault_schedule: Vec<FaultInjection>,
    /// Journaling-FS crash model for the executor's crash path.
    ///
    /// `None` keeps the black-box `DropAllUnsynced` operator (the byte-identical
    /// default). When set, the executor applies the configured mode to the
    /// simulated storage and its crash path replays the write-ahead journal
    /// instead of dropping it wholesale.
    #[cfg(feature = "sim-fs-journaling")]
    pub fs_journaling: Option<crate::simfs::JournalingMode>,
    /// Run the journal-correctness monitor and the coverage check at the end
    /// of the run.
    ///
    /// The monitor walks the whole journal (O(entries)); disable it only for
    /// throughput-sensitive runs. The journal itself is unaffected: entries,
    /// ids, and roots are byte-identical either way. Defaults to true.
    pub monitor: bool,
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
    pub fn seed_tree(&self) -> SeedTree {
        SeedTree::new(self.seed)
    }
}
