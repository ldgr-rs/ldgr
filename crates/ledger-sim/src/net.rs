//! Deterministic simulated network with timed delivery queues and partitions.
//! Version 0.2: DnsTable exposes sorted `iter()` for deterministic RunConfig hashing.

use ledger_format::{FaultSpec, Hash};
use rand_core::Rng;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::time::Duration;

/// A delivered network message envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Sending actor/task ID.
    pub from: usize,
    /// Receiving actor/task ID.
    pub to: usize,
    /// Numerical or encoded payload.
    pub payload: u64,
    /// Journal entry ID of the corresponding Send event.
    pub send_id: Hash,
    /// Virtual timestamp at which this message becomes deliverable.
    pub deliver_at: u64,
}

/// Per-link transport configuration.
///
/// All fields default to the zero config, which consumes no seed-stream draws
/// and keeps journals byte-identical to the unconfigured path.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LinkConfig {
    /// Deterministic base latency in ticks added to every send on this link.
    pub base_delay: u64,
    /// Uniform jitter range in ticks: a send draws `[0, jitter]` extra ticks.
    pub jitter: u64,
    /// Message loss probability in `0.0 ..= 1.0`.
    pub loss_probability: f64,
    /// Per-link reorder window override; `0` uses the global window.
    pub reorder_window: usize,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            base_delay: 0,
            jitter: 0,
            loss_probability: 0.0,
            reorder_window: 0,
        }
    }
}

/// Deterministic hostname-to-actor resolution table.
///
/// The table is config-driven and never touched by the ambient host: a name
/// maps to exactly one task id, so resolution is identical for every run that
/// shares the config. Names that are absent resolve to `None`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DnsTable {
    names: BTreeMap<String, usize>,
}

impl DnsTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Map `name` to `actor`. Returns `true` when a prior mapping was replaced.
    pub fn insert(&mut self, name: impl Into<String>, actor: usize) -> bool {
        self.names.insert(name.into(), actor).is_some()
    }

    /// Resolve `name` to its actor task id, or `None` when the name is unknown.
    pub fn resolve(&self, name: &str) -> Option<usize> {
        self.names.get(name).copied()
    }

    /// Whether `name` is present in the table.
    pub fn contains(&self, name: &str) -> bool {
        self.names.contains_key(name)
    }

    /// Sorted iterator over hostname entries (BTreeMap order, deterministic).
    ///
    /// Exposed for the deterministic boundary hash (RunConfig canonical bytes);
    /// same config produces same hash even after DNS changes.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &usize)> {
        self.names.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Number of entries in the table.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

/// Deterministic exponential backoff delay for retry attempt `retry`.
///
/// The delay is `base * 2^retry` in microseconds, capped at `max_delay`. The
/// sequence is purely arithmetic: it draws nothing and needs no RNG, so
/// identical inputs always produce identical delays.
pub fn backoff(base: Duration, retry: u32, max_delay: Duration) -> Duration {
    let base_ticks = base.as_micros().min(u64::MAX as u128) as u64;
    let max_ticks = max_delay.as_micros().min(u64::MAX as u128) as u64;
    let ticks = base_ticks
        .saturating_mul(1u64 << retry.min(63))
        .min(max_ticks);
    Duration::from_micros(ticks)
}

/// Deterministic exponential backoff with jitter drawn from a seeded stream.
///
/// Computes [`backoff`] for the attempt, then draws one uniform value in
/// `[0, delay)` from `rng` and adds it, clamping the total to `max_delay`.
/// `rng` must come from the seed tree (for example `SeedTree::rng` or the
/// boundary's per-stream RNG) so the draw replays byte-identically. An
/// unjittered retry sequence is a subset of this: feed a stream that always
/// draws zero.
pub fn backoff_jittered(
    base: Duration,
    retry: u32,
    max_delay: Duration,
    mut rng: impl Rng,
) -> Duration {
    let delay = backoff(base, retry, max_delay);
    let ticks = delay.as_micros() as u64;
    let extra = Duration::from_micros(rng.next_u64() % ticks.max(1));
    delay.saturating_add(extra).min(max_delay)
}

/// Simulated network managing link latencies, partitions, and message queues.
#[derive(Debug, Default)]
pub struct SimNet {
    queue: VecDeque<Message>,
    // ledger-lint:allow:HashSet (partition pairs are membership-checked;
    // the set is never iterated)
    partitions: HashSet<(usize, usize)>,
    /// Optional reorder window: when nonzero, up to this many messages sharing
    /// a delivery tick are served newest-first instead of FIFO (UDP-style
    /// unordered delivery). Zero keeps strict FIFO.
    reorder_window: usize,
    /// Per-link transport configuration. Absent links use [`LinkConfig::default`].
    links: BTreeMap<(usize, usize), LinkConfig>,
}

impl SimNet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure the transport properties of one directed link.
    ///
    /// Links without an explicit config keep the zero config: no latency, no
    /// jitter, no loss, and the global reorder window.
    pub fn set_link(&mut self, from: usize, to: usize, cfg: LinkConfig) {
        self.links.insert((from, to), cfg);
    }

    pub fn link_configured(&self, from: usize, to: usize) -> bool {
        self.links.contains_key(&(from, to))
    }

    /// Return the effective config for a link (explicit or default).
    pub fn link_config(&self, from: usize, to: usize) -> LinkConfig {
        self.links.get(&(from, to)).copied().unwrap_or_default()
    }

    /// Return the effective reorder window: per-link override or the global.
    pub fn effective_reorder_window(&self, from: usize, to: usize) -> usize {
        let per_link = self
            .links
            .get(&(from, to))
            .map(|c| c.reorder_window)
            .unwrap_or(0);
        if per_link != 0 {
            per_link
        } else {
            self.reorder_window
        }
    }

    /// Send a message honoring the link config, drawing jitter and loss from
    /// the caller's seeded source.
    ///
    /// `draw(bound)` returns a uniform value in `[0, bound)`. Draws happen ONLY
    /// when the link has nonzero jitter or loss; an unconfigured link consumes
    /// zero draws. Returns `false` when the message is dropped (partitioned or
    /// lost), `true` when queued. The `deliver_at` field of `message` is
    /// recomputed from `now` plus the effective latency.
    pub fn send_via_link(
        &mut self,
        message: Message,
        now: u64,
        base_delay: u64,
        mut draw: impl FnMut(u64) -> u64,
    ) -> bool {
        if self.is_partitioned(message.from, message.to) {
            return false;
        }
        let cfg = self.link_config(message.from, message.to);
        let mut total = base_delay.saturating_add(cfg.base_delay);
        if cfg.jitter > 0 {
            // `jitter + 1` overflows at u64::MAX and would wrap the modulus to
            // zero; the saturated modulus keeps the draw defined and
            // deterministic on the builder path. The canonical codec rejects
            // `jitter == u64::MAX` outright (no representable modulus), so
            // this fallback only guards direct construction.
            total = total.saturating_add(draw(cfg.jitter.saturating_add(1)));
        }
        if cfg.loss_probability > 0.0
            && draw(1_000_000_000) < (cfg.loss_probability * 1_000_000_000.0) as u64
        {
            return false;
        }
        self.queue.push_back(Message {
            deliver_at: now.saturating_add(total),
            ..message
        });
        true
    }

    /// Toggle a directed partition: present becomes absent and vice versa.
    pub fn toggle_partition(&mut self, from: usize, to: usize) {
        if !self.partitions.remove(&(from, to)) {
            self.partitions.insert((from, to));
        }
    }

    /// Apply a fault to the network. Handles [`FaultSpec::Partition`] by
    /// toggling the partition; returns `true` when the fault was applied.
    pub fn apply_fault(&mut self, fault: &FaultSpec) -> bool {
        match fault {
            FaultSpec::Partition { src, dst } => {
                self.toggle_partition(*src as usize, *dst as usize);
                true
            }
            _ => false,
        }
    }

    /// Enable a deterministic reorder window on this link.
    ///
    /// When `window` is nonzero, messages whose `deliver_at` ties are served
    /// in reverse insertion order within a window of `window` messages, which
    /// is deterministic for a fixed send sequence. The default (0) is strict
    /// FIFO and matches the historical journal output exactly.
    pub fn set_reorder_window(&mut self, window: usize) {
        self.reorder_window = window;
    }

    pub fn reorder_window(&self) -> usize {
        self.reorder_window
    }

    /// Establish a directed network partition from `from` to `to`.
    pub fn partition(&mut self, from: usize, to: usize) {
        self.partitions.insert((from, to));
    }

    pub fn is_partitioned(&self, from: usize, to: usize) -> bool {
        self.partitions.contains(&(from, to))
    }

    /// Queue a message for delivery. Returns true if queued, false if dropped by partition.
    pub fn send(&mut self, message: Message) -> bool {
        if self.is_partitioned(message.from, message.to) {
            return false;
        }
        self.queue.push_back(message);
        true
    }

    /// Send a message with current virtual timestamp and optional delay.
    pub fn send_at(
        &mut self,
        from: usize,
        to: usize,
        payload: u64,
        send_id: Hash,
        now: u64,
        delay: u64,
    ) -> bool {
        self.send(Message {
            from,
            to,
            payload,
            send_id,
            deliver_at: now.saturating_add(delay),
        })
    }

    pub fn has_ready_message(&self, task: usize, now: u64) -> bool {
        self.queue
            .iter()
            .any(|msg| msg.to == task && msg.deliver_at <= now)
    }

    /// Return the journal entry id of the first deliverable message for `task`.
    ///
    /// The message stays queued; the id feeds the `Wake` entry parent when a
    /// blocked task is released.
    pub fn peek_ready_send_id(&self, task: usize, now: u64) -> Option<Hash> {
        self.queue
            .iter()
            .find(|msg| msg.to == task && msg.deliver_at <= now)
            .map(|msg| msg.send_id)
    }

    /// Take the first deliverable message for `task` available at `now`.
    ///
    /// With a nonzero effective reorder window (per-link override or global),
    /// the most recently queued deliverable message wins (UDP-style unordered
    /// delivery); otherwise delivery is strict FIFO.
    pub fn recv_at(&mut self, task: usize, now: u64) -> Option<Message> {
        let mut first = None;
        let mut last = None;
        for (index, message) in self.queue.iter().enumerate() {
            if message.to == task && message.deliver_at <= now {
                if first.is_none() {
                    first = Some(index);
                }
                last = Some(index);
            }
        }
        let first = first?;
        let window = self.effective_reorder_window(self.queue[first].from, task);
        let index = if window > 0 { last? } else { first };
        self.queue.remove(index)
    }

    /// Return the earliest delivery timestamp among all queued messages.
    pub fn earliest_delivery_time(&self) -> Option<u64> {
        self.queue.iter().map(|msg| msg.deliver_at).min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send_id(n: u8) -> Hash {
        let mut h = Hash::default();
        h[0] = n;
        h
    }

    #[test]
    fn link_base_delay_adds_delivery_ticks() {
        let mut net = SimNet::new();
        net.set_link(
            0,
            1,
            LinkConfig {
                base_delay: 10,
                ..LinkConfig::default()
            },
        );
        let delivered = net.send_via_link(
            Message {
                from: 0,
                to: 1,
                payload: 7,
                send_id: send_id(1),
                deliver_at: 100,
            },
            100,
            0,
            |_| 0,
        );
        assert!(delivered);
        let msg = net.recv_at(1, 110).unwrap();
        assert_eq!(msg.deliver_at, 110);
        assert_eq!(msg.payload, 7);
    }

    #[test]
    fn link_jitter_draws_only_when_configured() {
        let mut draws = 0usize;
        let mut net = SimNet::new();
        // Zero config: the draw closure must never fire.
        assert!(net.send_via_link(
            Message {
                from: 0,
                to: 1,
                payload: 1,
                send_id: send_id(1),
                deliver_at: 0
            },
            0,
            0,
            |_| {
                draws += 1;
                0
            }
        ));
        assert_eq!(draws, 0);
        // Jitter config: one draw, value added to deliver_at.
        net.set_link(
            0,
            1,
            LinkConfig {
                jitter: 9,
                ..LinkConfig::default()
            },
        );
        let mut jitter_draws = 0usize;
        assert!(net.send_via_link(
            Message {
                from: 0,
                to: 1,
                payload: 2,
                send_id: send_id(2),
                deliver_at: 100
            },
            100,
            0,
            |_| {
                jitter_draws += 1;
                7
            }
        ));
        assert_eq!(jitter_draws, 1, "jitter config must draw exactly once");
        let _ = net.recv_at(1, 200).unwrap(); // first message (deliver_at 0)
        assert_eq!(net.recv_at(1, 200).unwrap().deliver_at, 107);
    }

    #[test]
    fn link_loss_drops_deterministically() {
        let mut net = SimNet::new();
        net.set_link(
            0,
            1,
            LinkConfig {
                loss_probability: 1.0,
                ..LinkConfig::default()
            },
        );
        assert!(!net.send_via_link(
            Message {
                from: 0,
                to: 1,
                payload: 1,
                send_id: send_id(1),
                deliver_at: 0
            },
            0,
            0,
            |_| 0
        ));
        net.set_link(
            0,
            1,
            LinkConfig {
                loss_probability: 0.0,
                ..LinkConfig::default()
            },
        );
        let mut draws = 0usize;
        assert!(net.send_via_link(
            Message {
                from: 0,
                to: 1,
                payload: 2,
                send_id: send_id(2),
                deliver_at: 0
            },
            0,
            0,
            |_| {
                draws += 1;
                0
            }
        ));
        assert_eq!(draws, 0, "zero loss consumes no draws");
    }

    #[test]
    fn per_link_reorder_overrides_global() {
        let mut net = SimNet::new();
        net.set_reorder_window(2); // global reorder on
        let now = 10;
        let _ = net.send_at(0, 1, 10, send_id(1), now, 0);
        let _ = net.send_at(0, 1, 20, send_id(2), now, 0);
        // Newest-first: second message wins.
        assert_eq!(net.recv_at(1, now).unwrap().payload, 20);
    }

    #[test]
    fn toggle_partition_flips_link() {
        let mut net = SimNet::new();
        net.partition(0, 1);
        assert!(net.is_partitioned(0, 1));
        net.toggle_partition(0, 1);
        assert!(!net.is_partitioned(0, 1));
        net.toggle_partition(0, 1);
        assert!(net.is_partitioned(0, 1));
    }

    #[test]
    fn apply_partition_fault_toggles() {
        let mut net = SimNet::new();
        let fault = FaultSpec::Partition { src: 0, dst: 1 };
        assert!(net.apply_fault(&fault));
        assert!(net.is_partitioned(0, 1));
        assert!(
            !net.apply_fault(&FaultSpec::Drop),
            "non-partition faults are not applied"
        );
    }
}
