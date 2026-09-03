//! Deterministic simulated network with timed delivery queues, partitions,
//! and a bounded reorder window.
//! Version 0.2: DnsTable exposes sorted `iter()` for deterministic RunConfig hashing.

use crate::config::Probability;
use ledger_format::{ActorId, EntryHash, FaultSpec, MessageId};
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
    /// Content bytes; a scalar caller encodes its value explicitly at the
    /// API boundary.
    pub content: Vec<u8>,
    /// Journal entry ID of the corresponding Send event.
    pub send_id: EntryHash,
    /// Message identity copied from the Send entry.
    pub message_id: MessageId,
    /// Virtual timestamp at which this message becomes deliverable.
    pub deliver_at: u64,
}

impl Message {
    /// Decode the first 8 little-endian bytes as a scalar payload.
    pub fn payload(&self) -> u64 {
        let mut buf = [0u8; 8];
        let n = self.content.len().min(8);
        buf[..n].copy_from_slice(&self.content[..n]);
        u64::from_le_bytes(buf)
    }
}

/// What a bounded link does when its queue is full.
///
/// `Drop` discards the newest message and journals a `Drop` fault.
/// `Block` refuses the send without journaling a drop so the sender can
/// retry later; the `bool` send surface still reports `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QueueFullPolicy {
    /// Discard the overflowing message (default, preserves history).
    #[default]
    Drop,
    /// Refuse the send as backpressure (no drop fault journaled).
    Block,
}

/// Typed network failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetError {
    /// A bounded link queue already holds `queued` messages at capacity.
    #[error("queue full on link {from}->{to}: {queued}/{capacity}")]
    QueueFull {
        /// Sending actor.
        from: usize,
        /// Receiving actor.
        to: usize,
        /// Configured capacity.
        capacity: usize,
        /// Messages already queued for this link.
        queued: usize,
    },
    /// A reorder window exceeds the representable bound.
    #[error("invalid reorder window {window}: {reason}")]
    InvalidReorderWindow {
        /// Rejected window.
        window: usize,
        /// Why the window is invalid.
        reason: &'static str,
    },
}

/// Upper bound for a reorder window.
///
/// Windows at or below this bound always clamp to the ready count.
/// Larger windows are rejected by the validated setters and the
/// fallible recv paths so a misconfigured window fails closed.
pub const MAX_REORDER_WINDOW: usize = 65_536;

/// Per-link transport configuration.
///
/// All fields default to the zero config, which consumes no seed-stream draws
/// and keeps journals byte-identical to the unconfigured path. `capacity` is
/// `None` by default, which means unbounded and preserves the historical
/// behavior; set `Some(n)` to bound the queued messages for one directed
/// link. `queue_policy` selects drop (journaled) or block (backpressure)
/// when a bounded queue is full.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LinkConfig {
    /// Deterministic base latency in ticks added to every send on this link.
    pub base_delay: u64,
    /// Uniform jitter range in ticks: a send draws `[0, jitter]` extra ticks.
    pub jitter: u64,
    /// Message loss probability in `0.0 ..= 1.0`.
    pub loss_probability: Probability,
    /// Per-link reorder window override; `0` uses the global window.
    pub reorder_window: usize,
    /// Bound on queued messages for this directed link; `None` is unbounded.
    pub capacity: Option<usize>,
    /// Full-queue behavior for a bounded link.
    pub queue_policy: QueueFullPolicy,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            base_delay: 0,
            jitter: 0,
            loss_probability: Probability::ZERO,
            reorder_window: 0,
            capacity: None,
            queue_policy: QueueFullPolicy::Drop,
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

    /// Validate a reorder window against the representable bound.
    ///
    /// # Errors
    /// Returns [`NetError::InvalidReorderWindow`] when `window` exceeds
    /// [`MAX_REORDER_WINDOW`].
    pub fn validate_reorder_window(window: usize) -> Result<(), NetError> {
        if window > MAX_REORDER_WINDOW {
            return Err(NetError::InvalidReorderWindow {
                window,
                reason: "window exceeds the representable bound",
            });
        }
        Ok(())
    }

    /// Return the effective reorder window: per-link override or the global.
    ///
    /// A per-link `0` inherits the global window; any nonzero per-link value
    /// wins. Use a global `0` plus explicit per-link windows when one link
    /// must stay FIFO while others reorder.
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

    /// Count messages currently queued for one directed link.
    pub fn queued_for(&self, from: usize, to: usize) -> usize {
        self.queue
            .iter()
            .filter(|msg| msg.from == from && msg.to == to)
            .count()
    }

    /// Check a link capacity without mutating the queue.
    ///
    /// # Errors
    /// Returns [`NetError::QueueFull`] when the link has `Some(cap)` and
    /// already holds at least `cap` messages.
    pub fn check_capacity(&self, from: usize, to: usize) -> Result<(), NetError> {
        let cap = match self.links.get(&(from, to)).and_then(|c| c.capacity) {
            Some(cap) => cap,
            None => return Ok(()),
        };
        let queued = self.queued_for(from, to);
        if queued >= cap {
            return Err(NetError::QueueFull {
                from,
                to,
                capacity: cap,
                queued,
            });
        }
        Ok(())
    }

    /// Return the full-queue policy for a link (`Drop` when unconfigured).
    pub fn queue_policy(&self, from: usize, to: usize) -> QueueFullPolicy {
        self.links
            .get(&(from, to))
            .map(|c| c.queue_policy)
            .unwrap_or(QueueFullPolicy::Drop)
    }

    /// Fallible send honoring link capacity, jitter, and loss.
    ///
    /// The capacity check runs before any seed draw, so a full queue never
    /// perturbs the draw stream. `Ok(true)` means queued, `Ok(false)` means
    /// refused by partition or sampled loss, `Err` means the bounded queue
    /// is full. This is the [`NetError::QueueFull`] producer.
    ///
    /// # Errors
    /// Returns [`NetError::QueueFull`] when the link is at capacity.
    pub fn try_send_via_link(
        &mut self,
        message: Message,
        now: u64,
        base_delay: u64,
        mut draw: impl FnMut(u64) -> u64,
    ) -> Result<bool, NetError> {
        if self.is_partitioned(message.from, message.to) {
            return Ok(false);
        }
        // Capacity first: no draws consumed on a full queue.
        self.check_capacity(message.from, message.to)?;
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
        if cfg.loss_probability.get() > 0.0
            && draw(1_000_000_000) < (cfg.loss_probability.get() * 1_000_000_000.0) as u64
        {
            return Ok(false);
        }
        self.queue.push_back(Message {
            deliver_at: now.saturating_add(total),
            ..message
        });
        Ok(true)
    }

    /// Send a message honoring the link config, drawing jitter and loss from
    /// the caller's seeded source.
    ///
    /// `draw(bound)` returns a uniform value in `[0, bound)`. Draws happen ONLY
    /// when the link has nonzero jitter or loss; an unconfigured link consumes
    /// zero draws. Returns `false` when the message is dropped (partitioned,
    /// lost, or queue-full), `true` when queued. The `deliver_at` field of `message` is
    /// recomputed from `now` plus the effective latency. Queue-full collapses
    /// to `false` here; use [`Self::try_send_via_link`] to distinguish it.
    pub fn send_via_link(
        &mut self,
        message: Message,
        now: u64,
        base_delay: u64,
        draw: impl FnMut(u64) -> u64,
    ) -> bool {
        self.try_send_via_link(message, now, base_delay, draw)
            .unwrap_or(false)
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
                self.toggle_partition(src.0 as usize, dst.0 as usize);
                true
            }
            _ => false,
        }
    }

    /// Validated global reorder-window setter.
    ///
    /// # Errors
    /// Returns [`NetError::InvalidReorderWindow`] when `window` exceeds
    /// [`MAX_REORDER_WINDOW`].
    pub fn try_set_reorder_window(&mut self, window: usize) -> Result<(), NetError> {
        Self::validate_reorder_window(window)?;
        self.reorder_window = window;
        Ok(())
    }

    /// Validated link setter.
    ///
    /// # Errors
    /// Returns [`NetError::InvalidReorderWindow`] when the link window exceeds
    /// [`MAX_REORDER_WINDOW`].
    pub fn try_set_link(
        &mut self,
        from: usize,
        to: usize,
        cfg: LinkConfig,
    ) -> Result<(), NetError> {
        Self::validate_reorder_window(cfg.reorder_window)?;
        self.links.insert((from, to), cfg);
        Ok(())
    }

    /// Enable a deterministic reorder window on this link.
    ///
    /// When `window` is nonzero, messages whose `deliver_at` ties are served
    /// in reverse insertion order within a window of `window` messages, which
    /// is deterministic for a fixed send sequence. The default (0) is strict
    /// FIFO and matches the historical journal output exactly. Windows above
    /// [`MAX_REORDER_WINDOW`] are rejected by [`Self::try_set_reorder_window`];
    /// this setter keeps the historical infallible shape for existing callers.
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
    ///
    /// A bounded link at capacity also returns `false`; use
    /// [`Self::try_send`] to distinguish queue-full from partition.
    pub fn send(&mut self, message: Message) -> bool {
        self.try_send(message).unwrap_or(false)
    }

    /// Fallible queue respecting per-link capacity.
    ///
    /// `Ok(true)` means queued, `Ok(false)` means refused by partition.
    ///
    /// # Errors
    /// Returns [`NetError::QueueFull`] when the link is at capacity.
    pub fn try_send(&mut self, message: Message) -> Result<bool, NetError> {
        if self.is_partitioned(message.from, message.to) {
            return Ok(false);
        }
        self.check_capacity(message.from, message.to)?;
        self.queue.push_back(message);
        Ok(true)
    }

    /// Send a message with current virtual timestamp and optional delay.
    pub fn send_at(
        &mut self,
        from: usize,
        to: usize,
        payload: u64,
        send_id: EntryHash,
        now: u64,
        delay: u64,
    ) -> bool {
        self.try_send_at(from, to, payload, send_id, now, delay)
            .unwrap_or(false)
    }

    /// Fallible timed send respecting per-link capacity.
    ///
    /// # Errors
    /// Returns [`NetError::QueueFull`] when the link is at capacity.
    pub fn try_send_at(
        &mut self,
        from: usize,
        to: usize,
        payload: u64,
        send_id: EntryHash,
        now: u64,
        delay: u64,
    ) -> Result<bool, NetError> {
        self.try_send(Message {
            from,
            to,
            content: payload.to_le_bytes().to_vec(),
            message_id: MessageId::new(ActorId(from as u32), 0),
            send_id,
            deliver_at: now.saturating_add(delay),
        })
    }

    /// Send a message with an explicit identity and content bytes.
    pub fn send_at_with_identity(&mut self, message: Message, now: u64, delay: u64) -> bool {
        self.try_send_at_with_identity(message, now, delay)
            .unwrap_or(false)
    }

    /// Fallible identity send respecting per-link capacity.
    ///
    /// # Errors
    /// Returns [`NetError::QueueFull`] when the link is at capacity.
    pub fn try_send_at_with_identity(
        &mut self,
        message: Message,
        now: u64,
        delay: u64,
    ) -> Result<bool, NetError> {
        self.try_send(Message {
            deliver_at: now.saturating_add(delay),
            ..message
        })
    }

    pub fn has_ready_message(&self, task: usize, now: u64) -> bool {
        self.queue
            .iter()
            .any(|msg| msg.to == task && msg.deliver_at <= now)
    }

    /// Return the journal entry id of the deliverable message the deterministic
    /// recv path would serve next for `task`.
    ///
    /// The message stays queued; the id feeds the `Wake` entry parent when a
    /// blocked task is released. Unlike the historical FIFO peek, this honors
    /// the effective reorder window, so the `Wake` parent matches the message
    /// [`Self::recv_at`] will actually deliver. The seeded-draw path
    /// ([`Self::recv_at_drawn`]) cannot be peeked without consuming a draw,
    /// so the wake trigger stays deterministic while the `Recv` entry carries
    /// the true drawn lineage.
    pub fn peek_ready_send_id(&self, task: usize, now: u64) -> Option<EntryHash> {
        self.peek_index(task, now)
            .map(|idx| self.queue[idx].send_id)
    }

    /// Select the queue index [`Self::recv_at`] would serve, without removing.
    fn peek_index(&self, task: usize, now: u64) -> Option<usize> {
        let mut ready = self
            .queue
            .iter()
            .enumerate()
            .filter_map(|(idx, msg)| (msg.to == task && msg.deliver_at <= now).then_some(idx));
        let first = ready.next()?;
        let sender = self.queue[first].from;
        let window = self.effective_reorder_window(sender, task);
        if window == 0 {
            return Some(first);
        }
        // Bounded suffix of this link's ready messages, newest wins.
        // Collect only matching indices; the queue itself is the bound, so
        // this allocates at most one entry per queued message.
        let mut last = first;
        let mut suffix: Vec<usize> = Vec::new();
        suffix.push(first);
        for idx in ready {
            if self.queue[idx].from == sender {
                suffix.push(idx);
                last = idx;
            }
        }
        let _ = last;
        let start = suffix.len().saturating_sub(window);
        Some(suffix[suffix.len() - 1].max(suffix[start]))
    }

    /// Validated deterministic recv.
    ///
    /// # Errors
    /// Returns [`NetError::InvalidReorderWindow`] when the effective window
    /// exceeds [`MAX_REORDER_WINDOW`].
    pub fn try_recv_at(&mut self, task: usize, now: u64) -> Result<Option<Message>, NetError> {
        let window = self.effective_window_for_task(task, now)?;
        Ok(self.recv_with_window(task, now, window))
    }

    /// Validated drawn recv inside the bounded window.
    ///
    /// Window zero draws nothing and serves FIFO. A nonzero window draws
    /// exactly once.
    ///
    /// # Errors
    /// Returns [`NetError::InvalidReorderWindow`] when the effective window
    /// exceeds [`MAX_REORDER_WINDOW`].
    pub fn try_recv_at_drawn(
        &mut self,
        task: usize,
        now: u64,
        mut draw: impl FnMut(u64) -> u64,
    ) -> Result<Option<Message>, NetError> {
        let ready: Vec<usize> = self
            .queue
            .iter()
            .enumerate()
            .filter(|(_, message)| message.to == task && message.deliver_at <= now)
            .map(|(index, _)| index)
            .collect();
        let Some(first) = ready.first().copied() else {
            return Ok(None);
        };
        let sender = self.queue[first].from;
        let window = self.effective_reorder_window(sender, task);
        Self::validate_reorder_window(window)?;
        let link_candidates: Vec<usize> = ready
            .into_iter()
            .filter(|&idx| self.queue[idx].from == sender)
            .collect();
        let index = if window == 0 {
            first
        } else {
            let start = link_candidates.len().saturating_sub(window);
            let suffix = &link_candidates[start..];
            let n = suffix.len() as u64;
            suffix[(draw(n) % n) as usize]
        };
        Ok(self.queue.remove(index))
    }

    /// Effective window for the oldest ready message to `task`, validated.
    fn effective_window_for_task(&self, task: usize, now: u64) -> Result<usize, NetError> {
        let first = self
            .queue
            .iter()
            .find(|msg| msg.to == task && msg.deliver_at <= now);
        let Some(msg) = first else {
            return Ok(0);
        };
        let window = self.effective_reorder_window(msg.from, task);
        Self::validate_reorder_window(window)?;
        Ok(window)
    }

    /// Deterministic recv given an already-validated window.
    fn recv_with_window(&mut self, task: usize, now: u64, window: usize) -> Option<Message> {
        let ready: Vec<usize> = self
            .queue
            .iter()
            .enumerate()
            .filter(|(_, message)| message.to == task && message.deliver_at <= now)
            .map(|(index, _)| index)
            .collect();
        let first = *ready.first()?;
        let sender = self.queue[first].from;
        let link_candidates: Vec<usize> = ready
            .into_iter()
            .filter(|&idx| self.queue[idx].from == sender)
            .collect();
        let index = if window == 0 {
            first
        } else {
            let start = link_candidates.len().saturating_sub(window);
            link_candidates[link_candidates.len() - 1].max(link_candidates[start])
        };
        self.queue.remove(index)
    }

    /// Take the first deliverable message for `task` available at `now`.
    ///
    /// With a nonzero effective reorder window (per-link override or global),
    /// the eligible set is the bounded suffix of the ready queue: the last
    /// `window` ready messages. The newest of that suffix wins. Window zero
    /// preserves queue order (strict FIFO). Windows above
    /// [`MAX_REORDER_WINDOW`] clamp here for historical callers; use
    /// [`Self::try_recv_at`] to reject them with [`NetError`].
    pub fn recv_at(&mut self, task: usize, now: u64) -> Option<Message> {
        let first = self
            .queue
            .iter()
            .enumerate()
            .find(|(_, message)| message.to == task && message.deliver_at <= now);
        let (first_idx, sender) = match first {
            Some((idx, msg)) => (idx, msg.from),
            None => return None,
        };
        let window = self.effective_reorder_window(sender, task);
        // Historical clamping path shares the validated helper; oversized
        // windows clamp to the ready count instead of failing.
        let _ = first_idx;
        self.recv_with_window(task, now, window)
    }

    /// Take one ready message for `task`, drawing a seeded pick inside the
    /// exact bounded candidate window.
    ///
    /// Window zero draws nothing and serves the queue head (FIFO). A nonzero
    /// window limits the candidate set to the last `window` ready messages
    /// on this link and serves `candidate[draw(candidate.len())]`. Oversized
    /// windows clamp here; use [`Self::try_recv_at_drawn`] to reject them.
    pub fn recv_at_drawn(
        &mut self,
        task: usize,
        now: u64,
        draw: impl FnMut(u64) -> u64,
    ) -> Option<Message> {
        self.try_recv_at_drawn_validated(task, now, draw, false)
    }

    /// Shared drawn recv with optional validation.
    fn try_recv_at_drawn_validated(
        &mut self,
        task: usize,
        now: u64,
        mut draw: impl FnMut(u64) -> u64,
        validate: bool,
    ) -> Option<Message> {
        let ready: Vec<usize> = self
            .queue
            .iter()
            .enumerate()
            .filter(|(_, message)| message.to == task && message.deliver_at <= now)
            .map(|(index, _)| index)
            .collect();
        let first = *ready.first()?;
        let sender = self.queue[first].from;
        let window = self.effective_reorder_window(sender, task);
        if validate && window > MAX_REORDER_WINDOW {
            return None;
        }
        let link_candidates: Vec<usize> = ready
            .into_iter()
            .filter(|&idx| self.queue[idx].from == sender)
            .collect();
        let index = if window == 0 {
            first
        } else {
            let start = link_candidates.len().saturating_sub(window);
            let suffix = &link_candidates[start..];
            suffix[(draw(suffix.len() as u64) % suffix.len() as u64) as usize]
        };
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

    fn send_id(n: u8) -> EntryHash {
        let mut h = [0u8; 32];
        h[0] = n;
        EntryHash(h)
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
                content: 7u64.to_le_bytes().to_vec(),
                message_id: ledger_format::MessageId::new(ActorId(0), 0),
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
        assert_eq!(msg.payload(), 7);
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
                content: 1u64.to_le_bytes().to_vec(),
                message_id: ledger_format::MessageId::new(ActorId(0), 0),
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
                content: 2u64.to_le_bytes().to_vec(),
                message_id: ledger_format::MessageId::new(ActorId(0), 0),
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
                loss_probability: Probability::ONE,
                ..LinkConfig::default()
            },
        );
        assert!(!net.send_via_link(
            Message {
                from: 0,
                to: 1,
                content: 1u64.to_le_bytes().to_vec(),
                message_id: ledger_format::MessageId::new(ActorId(0), 0),
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
                loss_probability: Probability::ZERO,
                ..LinkConfig::default()
            },
        );
        let mut draws = 0usize;
        assert!(net.send_via_link(
            Message {
                from: 0,
                to: 1,
                content: 2u64.to_le_bytes().to_vec(),
                message_id: ledger_format::MessageId::new(ActorId(0), 0),
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
        assert_eq!(net.recv_at(1, now).unwrap().payload(), 20);
    }

    #[test]
    fn reorder_window_zero_preserves_queue_order() {
        let mut net = SimNet::new();
        let now = 10;
        for value in [10u64, 20, 30] {
            let _ = net.send_at(0, 1, value, send_id(value as u8), now, 0);
        }
        assert_eq!(net.recv_at(1, now).unwrap().payload(), 10);
        assert_eq!(net.recv_at(1, now).unwrap().payload(), 20);
        assert_eq!(net.recv_at(1, now).unwrap().payload(), 30);
    }

    #[test]
    fn reorder_window_bounds_the_candidate_suffix() {
        // Five ready messages with window 2: the eligible set is the last
        // two, and the newest of the suffix wins.
        let mut net = SimNet::new();
        net.set_reorder_window(2);
        let now = 10;
        for value in [10u64, 20, 30, 40, 50] {
            let _ = net.send_at(0, 1, value, send_id(value as u8), now, 0);
        }
        // Newest-first within the bounded window: 50, then 40, then 30.
        assert_eq!(net.recv_at(1, now).unwrap().payload(), 50);
        assert_eq!(net.recv_at(1, now).unwrap().payload(), 40);
        assert_eq!(net.recv_at(1, now).unwrap().payload(), 30);
        assert_eq!(net.recv_at(1, now).unwrap().payload(), 20);
        assert_eq!(net.recv_at(1, now).unwrap().payload(), 10);
    }

    #[test]
    fn reorder_window_larger_than_queue_clamps_to_ready_count() {
        let mut net = SimNet::new();
        net.set_reorder_window(100);
        let now = 10;
        for value in [10u64, 20, 30] {
            let _ = net.send_at(0, 1, value, send_id(value as u8), now, 0);
        }
        assert_eq!(net.recv_at(1, now).unwrap().payload(), 30);
    }

    #[test]
    fn drawn_window_serves_within_the_bounded_suffix() {
        let mut net = SimNet::new();
        net.set_reorder_window(2);
        let now = 10;
        for value in [10u64, 20, 30, 40, 50] {
            let _ = net.send_at(0, 1, value, send_id(value as u8), now, 0);
        }
        // draw(2) == 0 serves the older member of the last-two suffix.
        let first = net.recv_at_drawn(1, now, |_| 0).unwrap();
        assert_eq!(first.payload(), 40);
        // draw(2) == 1 serves the newest member.
        let second = net.recv_at_drawn(1, now, |bound| bound - 1).unwrap();
        assert_eq!(second.payload(), 50);
    }

    #[test]
    fn message_identity_survives_delay_and_reorder() {
        let mut net = SimNet::new();
        net.set_reorder_window(1);
        let now = 10;
        let _ = net.send(Message {
            from: 0,
            to: 1,
            content: 7u64.to_le_bytes().to_vec(),
            message_id: ledger_format::MessageId::new(ActorId(0), 3),
            send_id: send_id(1),
            deliver_at: now + 5,
        });
        let _ = net.send(Message {
            from: 0,
            to: 1,
            content: 8u64.to_le_bytes().to_vec(),
            message_id: ledger_format::MessageId::new(ActorId(0), 4),
            send_id: send_id(2),
            deliver_at: now,
        });
        let msg = net.recv_at(1, now + 10).unwrap();
        // Stable identity through delay: the earlier send arrives with its
        // own message identity even after a later send was queued.
        assert_eq!(msg.message_id, ledger_format::MessageId::new(ActorId(0), 4));
        assert_eq!(msg.payload(), 8);
    }

    #[test]
    fn empty_and_maximum_size_messages_deliver() {
        let mut net = SimNet::new();
        let now = 10;
        // Empty message: zero content bytes, still deliverable.
        let _ = net.send(Message {
            from: 0,
            to: 1,
            content: Vec::new(),
            message_id: ledger_format::MessageId::new(ActorId(0), 0),
            send_id: send_id(1),
            deliver_at: now,
        });
        // Maximum-size message: exactly the format cap.
        let max = vec![0xABu8; ledger_format::limits::MAX_MESSAGE_BYTES];
        let _ = net.send(Message {
            from: 0,
            to: 1,
            content: max.clone(),
            message_id: ledger_format::MessageId::new(ActorId(0), 1),
            send_id: send_id(2),
            deliver_at: now,
        });
        let empty = net.recv_at(1, now).unwrap();
        assert!(empty.content.is_empty());
        let full = net.recv_at(1, now).unwrap();
        assert_eq!(full.content.len(), ledger_format::limits::MAX_MESSAGE_BYTES);
        assert_eq!(full.content, max);
    }

    #[test]
    fn send_and_recv_frames_carry_equal_content_and_endpoints() {
        let mut net = SimNet::new();
        let now = 10;
        let content = vec![1, 2, 3, 4];
        let id = ledger_format::MessageId::new(ActorId(2), 7);
        let _ = net.send(Message {
            from: 2,
            to: 3,
            content: content.clone(),
            message_id: id,
            send_id: send_id(1),
            deliver_at: now,
        });
        let msg = net.recv_at(3, now).unwrap();
        assert_eq!(msg.from, 2);
        assert_eq!(msg.to, 3);
        assert_eq!(msg.message_id, id);
        assert_eq!(msg.content, content, "recv carries the original content");
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
        let fault = FaultSpec::Partition {
            src: ActorId(0),
            dst: ActorId(1),
        };
        assert!(net.apply_fault(&fault));
        assert!(net.is_partitioned(0, 1));
        assert!(
            !net.apply_fault(&FaultSpec::Drop),
            "non-partition faults are not applied"
        );
    }

    #[test]
    fn bounded_link_reports_queue_full_without_consuming_draws() {
        let mut net = SimNet::new();
        net.set_link(
            0,
            1,
            LinkConfig {
                capacity: Some(2),
                ..LinkConfig::default()
            },
        );
        let now = 10;
        assert!(net.send_at(0, 1, 10, send_id(1), now, 0));
        assert!(net.send_at(0, 1, 20, send_id(2), now, 0));
        // Third send exceeds capacity: bool surface collapses to false.
        assert!(!net.send_at(0, 1, 30, send_id(3), now, 0));
        // Fallible surface produces the typed QueueFull with counts.
        let err = net
            .try_send_at(0, 1, 40, send_id(4), now, 0)
            .expect_err("full queue must error");
        assert_eq!(
            err,
            NetError::QueueFull {
                from: 0,
                to: 1,
                capacity: 2,
                queued: 2,
            }
        );
        // Other links are unaffected by one link's bound.
        assert!(net.send_at(0, 2, 50, send_id(5), now, 0));
        // Draining one slot reopens the bounded link.
        assert_eq!(net.recv_at(1, now).unwrap().payload(), 10);
        assert!(net.send_at(0, 1, 30, send_id(3), now, 0));
    }

    #[test]
    fn link_via_path_reports_queue_full_before_draws() {
        let mut net = SimNet::new();
        net.set_link(
            0,
            1,
            LinkConfig {
                jitter: 5,
                capacity: Some(1),
                ..LinkConfig::default()
            },
        );
        let now = 0;
        let mut draws = 0usize;
        let first = net.try_send_via_link(
            Message {
                from: 0,
                to: 1,
                content: 1u64.to_le_bytes().to_vec(),
                message_id: ledger_format::MessageId::new(ActorId(0), 0),
                send_id: send_id(1),
                deliver_at: now,
            },
            now,
            0,
            |_| {
                draws += 1;
                0
            },
        );
        assert!(first.expect("first send queues"));
        assert_eq!(draws, 1, "queued send consumes its jitter draw");
        // Full queue: no draws consumed, typed error surfaces.
        draws = 0;
        let err = net
            .try_send_via_link(
                Message {
                    from: 0,
                    to: 1,
                    content: 2u64.to_le_bytes().to_vec(),
                    message_id: ledger_format::MessageId::new(ActorId(0), 1),
                    send_id: send_id(2),
                    deliver_at: now,
                },
                now,
                0,
                |_| {
                    draws += 1;
                    0
                },
            )
            .expect_err("full queue must error");
        assert!(matches!(err, NetError::QueueFull { .. }));
        assert_eq!(draws, 0, "a full queue must not consume draws");
    }

    #[test]
    fn unbounded_default_preserves_historical_behavior() {
        // Default capacity is None (unbounded): any burst queues.
        let mut net = SimNet::new();
        assert_eq!(net.link_config(0, 1).capacity, None);
        assert_eq!(
            net.queue_policy(0, 1),
            QueueFullPolicy::Drop,
            "unconfigured links drop on the bool surface"
        );
        let now = 0;
        for n in 0..64u8 {
            assert!(net.send_at(0, 1, u64::from(n), send_id(n), now, 0));
        }
        assert_eq!(net.queued_for(0, 1), 64);
    }

    #[test]
    fn oversized_reorder_window_fails_closed_on_validated_paths() {
        let mut net = SimNet::new();
        let bad = MAX_REORDER_WINDOW + 1;
        assert_eq!(
            net.try_set_reorder_window(bad).expect_err("must reject"),
            NetError::InvalidReorderWindow {
                window: bad,
                reason: "window exceeds the representable bound",
            }
        );
        assert_eq!(
            SimNet::validate_reorder_window(bad).expect_err("must reject"),
            NetError::InvalidReorderWindow {
                window: bad,
                reason: "window exceeds the representable bound",
            }
        );
        assert!(
            net.try_set_link(
                0,
                1,
                LinkConfig {
                    reorder_window: bad,
                    ..LinkConfig::default()
                },
            )
            .is_err(),
            "link windows validate too"
        );
        // Largest representable window sets and clamps to the ready count.
        net.try_set_reorder_window(MAX_REORDER_WINDOW)
            .expect("bound itself is valid");
        let now = 0;
        let _ = net.send_at(0, 1, 10, send_id(1), now, 0);
        assert_eq!(net.recv_at(1, now).unwrap().payload(), 10);
        assert!(
            net.try_recv_at(1, now).expect("validated recv").is_none(),
            "empty queue stays empty"
        );
    }

    #[test]
    fn peek_matches_deterministic_recv_under_a_window() {
        let mut net = SimNet::new();
        net.set_reorder_window(2);
        let now = 5;
        for value in [10u64, 20, 30] {
            let _ = net.send_at(0, 1, value, send_id(value as u8), now, 0);
        }
        // Window 2 over [10, 20, 30]: suffix is [20, 30], newest wins.
        let peeked = net.peek_ready_send_id(1, now).expect("ready");
        let delivered = net.recv_at(1, now).unwrap();
        assert_eq!(peeked, delivered.send_id);
        assert_eq!(delivered.payload(), 30);
    }

    #[test]
    fn per_link_window_overrides_global() {
        let mut net = SimNet::new();
        net.set_reorder_window(3);
        net.set_link(
            0,
            1,
            LinkConfig {
                reorder_window: 1,
                ..LinkConfig::default()
            },
        );
        assert_eq!(net.effective_reorder_window(0, 1), 1);
        assert_eq!(net.effective_reorder_window(0, 2), 3);
        assert_eq!(net.effective_reorder_window(9, 9), 3);
    }
}
