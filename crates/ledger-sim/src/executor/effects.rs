//! Executor task boundary journaling deterministic effects.
use crate::origin::OriginSource;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use crate::config::SimFault;
use crate::effects::{Effects, Fs, Net, TaskId};
use crate::net::Message;
use crate::time::Clock;
use core::convert::Infallible;
use ledger_format::{ActorId, EntryHash, EntryKind, EntryPayload, StreamId};
use ledger_format::{FaultPayload, FaultSpec, MessageId};
use rand_core::{Rng, TryRng};

use super::{BlockedOn, ExecutorShared, TaskEntry};

/// Schema digest for scalar outcomes; domain-separated so entries never collide.
pub(crate) const OUTCOME_SCHEMA: EntryHash = EntryHash([
    0x67, 0xc9, 0x3d, 0x0f, 0xb1, 0x85, 0x81, 0x56, 0xad, 0xf7, 0x35, 0x4e, 0x3e, 0x31, 0xc7, 0x8b,
    0xae, 0xba, 0x7f, 0x50, 0x63, 0x62, 0xce, 0xbf, 0xf5, 0x90, 0x43, 0x64, 0x6a, 0xf2, 0x01, 0xbc,
]);

/// Predicate digest for scalar assertions; distinct from [`OUTCOME_SCHEMA`].
pub(crate) const ASSERT_SCHEMA: EntryHash = EntryHash([
    0x2b, 0x60, 0xdd, 0xa5, 0xdb, 0x69, 0x7b, 0x0a, 0x05, 0xe0, 0x85, 0xf2, 0x38, 0xdd, 0xa7, 0x58,
    0xfb, 0x08, 0x94, 0x91, 0x78, 0xd4, 0x7a, 0xb6, 0xb0, 0x00, 0x70, 0x76, 0x06, 0xda, 0x35, 0x26,
]);

/// Outcome of a swarm network policy decision.
enum SwarmAction {
    /// Deliver the message (possibly with an extra delay).
    Deliver,
    /// Delay delivery by the given tick count.
    Delay(u64),
    /// Drop the message; a `Drop` fault was already journaled.
    Drop,
}

/// Send outcome from the checked network path.
///
/// `Queued` carries the bool send result; `QueueFull` means a bounded
/// link refused the message before any draw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SendOutcome {
    Queued(bool),
    QueueFull,
}

/// Task-facing effects handle; `Clone` shares the journal and tables.
#[derive(Clone)]
pub struct Boundary {
    pub(crate) shared: Rc<ExecutorShared>,
    task: usize,
    /// Live RNG handles; cloning the boundary never duplicates draw state.
    rng_streams: Vec<Option<StreamRng>>,
}

impl Boundary {
    /// Create a boundary for a task id inside a shared executor.
    pub(crate) fn for_task(shared: Rc<ExecutorShared>, task: usize) -> Self {
        Self {
            shared,
            task,
            rng_streams: Vec::new(),
        }
    }

    /// Record an append failure; first failure wins.
    pub fn record_journal_error(&self, error: ledger_journal::JournalError) {
        self.shared.record_journal_error(error);
    }

    /// Journal one entry with this task as the actor.
    fn append(
        &self,
        kind: EntryKind,
        parents: impl IntoIterator<Item = EntryHash>,
        payload: EntryPayload,
    ) -> Result<EntryHash, ledger_journal::JournalError> {
        let id = self
            .shared
            .journal_append(ActorId(self.task as u32), kind, parents, payload)?;
        self.shared
            .notify_entry(ActorId(self.task as u32), kind, self.task, Some(id));
        Ok(id)
    }

    /// Count one journaled entry against the actor's coverage.
    ///
    /// The storage layer journals through `SimFs` directly (it cannot reach
    /// the executor's coverage counter), so the boundary records the write
    /// after the fact to keep the coverage ledger exact.
    fn note_journaled(&self, actor: ActorId) {
        let mut coverage = self.shared.coverage.borrow_mut();
        *coverage.entry(actor).or_insert(0) += 1;
    }

    /// Draw a probability in `0.0 .. 1.0` from the `net` seed stream.
    ///
    /// The draw consumes the next monotonic offset so two draws never collide
    /// and the sequence is deterministic per run.
    fn net_draw(&self) -> f64 {
        let mut offset = self.shared.net_offset.borrow_mut();
        let value = self.shared.seed_tree.draw_u64("net", *offset);
        *offset += 1;
        value as f64 / u64::MAX as f64
    }

    /// Draw a probability in `0.0 .. 1.0` from the `fs` seed stream.
    fn fs_draw(&self) -> f64 {
        let mut offset = self.shared.fs_offset.borrow_mut();
        let value = self.shared.seed_tree.draw_u64("fs", *offset);
        *offset += 1;
        value as f64 / u64::MAX as f64
    }

    /// Apply swarm drop/delay; zero probabilities draw nothing and journals
    /// stay byte-identical.
    fn swarm_send_policy(&self, send_id: EntryHash, message_id: MessageId) -> SwarmAction {
        let swarm = &self.shared.swarm;
        if swarm.drop_probability.get() > 0.0 && self.net_draw() < swarm.drop_probability.get() {
            if let Err(error) = self.append(
                EntryKind::Fault,
                [send_id],
                EntryPayload::Fault(FaultPayload::DropMessage { message_id }),
            ) {
                self.shared.record_journal_error(error);
            }
            return SwarmAction::Drop;
        }
        if swarm.delay_probability.get() > 0.0
            && swarm.max_delay_ticks > 0
            && self.net_draw() < swarm.delay_probability.get()
        {
            let delay = self.net_draw_delay(swarm.max_delay_ticks);
            return SwarmAction::Delay(delay);
        }
        SwarmAction::Deliver
    }

    /// Draw a delay in `0 ..= max`; `u64::MAX` returns the raw draw.
    pub(crate) fn net_draw_delay(&self, max_delay_ticks: u64) -> u64 {
        let mut offset = self.shared.net_offset.borrow_mut();
        let value = self.shared.seed_tree.draw_u64("net", *offset);
        *offset += 1;
        match max_delay_ticks {
            u64::MAX => value,
            bound => value % (bound + 1),
        }
    }

    /// Maybe crash after a write; zero probability draws nothing.
    fn maybe_crash_on_write(
        &self,
        path: &str,
        write_id: ledger_format::EntryHash,
    ) -> Result<(), ledger_journal::JournalError> {
        let swarm = &self.shared.swarm;
        if swarm.crash_probability.get() <= 0.0 {
            return Ok(());
        }
        if self.fs_draw() >= swarm.crash_probability.get() {
            return Ok(());
        }
        // The probability and choice draws above always happen so the fs
        // stream offsets stay stable; only the application is gated.
        let mut offset = self.shared.fs_offset.borrow_mut();
        let choice = self.shared.seed_tree.draw_u64("fs", *offset);
        *offset += 1;
        // Canonical v2 operators targeting the just-journaled write entry;
        // the journaled operation is the one applied.
        let operation = match choice % 4 {
            0 => ledger_format::CrashOperation::DropAllUnsynced,
            1 => ledger_format::CrashOperation::DropPaths {
                paths: vec![crate::simfs::path_ref(path)],
            },
            2 => ledger_format::CrashOperation::TornWrite {
                write_entry: write_id,
                persisted_prefix: 4,
            },
            _ => ledger_format::CrashOperation::BitFlip {
                write_entry: write_id,
                offset: 0,
                bit: 0,
            },
        };
        let state_index = match operation {
            ledger_format::CrashOperation::DropAllUnsynced => 0,
            ledger_format::CrashOperation::DropPaths { .. } => 1,
            ledger_format::CrashOperation::TornWrite { .. } => 2,
            ledger_format::CrashOperation::CorruptRange { .. } => 3,
            ledger_format::CrashOperation::BitFlip { .. } => 4,
        };
        let mut fault_classes = self.shared.fault_classes_used.borrow_mut();
        if fault_classes.len() >= swarm.fault_classes_per_run.max(1) {
            return Ok(());
        }
        fault_classes.insert(state_index);
        drop(fault_classes);
        if let Err(error) = self
            .shared
            .fs
            .borrow_mut()
            .apply_crash_operation(&operation)
        {
            // A crash that cannot resolve its target must fail closed.
            self.shared
                .record_journal_error(ledger_journal::JournalError::InvalidPayload(format!(
                    "swarm crash operator rejected: {error}"
                )));
            return Ok(());
        }
        self.append(
            EntryKind::Fault,
            [],
            EntryPayload::Fault(FaultPayload::CrashActor {
                actor: ActorId(self.task as u32),
                crash_operation: operation,
            }),
        )?;
        Ok(())
    }

    /// Apply the crash model; default stays byte-identical to the black-box path.
    fn fs_crash(&self) {
        #[cfg(feature = "sim-fs-journaling")]
        if self.shared.fs_journaling.is_some() {
            self.shared.fs.borrow_mut().crash_journaled();
            return;
        }
        self.shared.fs.borrow_mut().crash();
    }

    /// Journal one entry with an explicit actor, without scheduler notification.
    fn append_for_actor(
        &self,
        actor: ActorId,
        kind: EntryKind,
        parents: impl IntoIterator<Item = EntryHash>,
        payload: EntryPayload,
    ) -> Result<EntryHash, ledger_journal::JournalError> {
        self.shared.journal_append(actor, kind, parents, payload)
    }

    /// Executor-only recv; backends without suspension do not implement it.
    pub async fn recv(&self) -> u64 {
        RecvFuture {
            shared: Rc::clone(&self.shared),
            task: self.task,
        }
        .await
    }

    /// Journal an `Outcome` entry carrying the task register (test helper).
    pub fn outcome(&self, value: u64) -> Result<EntryHash, ledger_journal::JournalError> {
        self.append(
            EntryKind::Outcome,
            [],
            EntryPayload::Outcome(ledger_format::OutcomePayload {
                schema: OUTCOME_SCHEMA,
                value: ledger_format::CanonicalValue::Unsigned(value),
            }),
        )
    }

    /// Return whether a message is currently deliverable to this task.
    pub fn has_ready_message(&self) -> bool {
        let now = self.shared.time.borrow().now();
        self.shared.net.borrow().has_ready_message(self.task, now)
    }

    /// Resolve a hostname; pure config lookup that journals nothing.
    pub fn resolve(&self, name: &str) -> Option<usize> {
        self.shared.dns.resolve(name)
    }

    /// Send a message immediately, journaling a `Send` entry.
    pub fn send(&self, to: usize, payload: u64) -> bool {
        self.send_inner(to, payload, None)
    }

    /// Send with origin capture into the session side channel.
    #[track_caller]
    pub fn send_tracked(&self, to: usize, payload: u64) -> bool {
        self.send_inner(to, payload, Some(core::panic::Location::caller().into()))
    }

    /// Snapshot the captured effect origins in append order.
    pub fn origins_snapshot(&self) -> Vec<(ledger_format::EntryHash, OriginSource)> {
        self.shared.origins.borrow().snapshot()
    }

    /// Inherit the `Send` origin onto its `Recv` entry.
    fn inherit_recv_origin(&self, recv_id: Option<EntryHash>, send_id: EntryHash) {
        if let Some(id) = recv_id {
            // Clone out before re-locking; the mutex is not reentrant.
            let inherited = self.shared.origins.borrow().get(&send_id).cloned();
            if let Some(origin) = inherited {
                self.shared.origins.borrow_mut().record(id, origin);
            }
        }
    }

    fn send_inner(&self, to: usize, payload: u64, at: Option<OriginSource>) -> bool {
        // Behavior-identical to the historical Net::send path; the origin is
        // recorded inside send_core against the journaled Send entry.
        self.send_core(to, payload, 0, at)
    }

    /// Toggle a directed partition; journals `Fault { Partition }` and applies
    /// immediately so replay follows causal order.
    pub fn apply_partition(
        &self,
        src: usize,
        dst: usize,
    ) -> Result<EntryHash, ledger_journal::JournalError> {
        let fault = FaultSpec::Partition {
            src: ActorId(src as u32),
            dst: ActorId(dst as u32),
        };
        let id = self.append(
            EntryKind::Fault,
            [],
            EntryPayload::Fault(match fault {
                FaultSpec::Partition { src, dst } => FaultPayload::Partition {
                    src,
                    dst,
                    enabled: true,
                },
                _ => FaultPayload::DropMessage {
                    message_id: MessageId::new(ActorId(self.task as u32), 0),
                },
            }),
        )?;
        let applied = self
            .shared
            .net
            .borrow_mut()
            .apply_fault(&FaultSpec::Partition {
                src: ActorId(src as u32),
                dst: ActorId(dst as u32),
            });
        debug_assert!(applied, "a partition fault always applies");
        Ok(id)
    }

    /// Timed send; identical seeds yield identical delivery order.
    pub fn send_timed(&self, to: usize, payload: u64, delay: u64) -> bool {
        self.send_core(to, payload, delay, None)
    }

    /// Single send path; delay 0 keeps unfaulted journals byte-identical.
    fn send_core(
        &self,
        to: usize,
        payload: u64,
        base_delay: u64,
        at: Option<OriginSource>,
    ) -> bool {
        self.send_bytes_inner(to, payload.to_le_bytes().to_vec(), base_delay, at)
    }

    /// Byte-send path with the authoritative sender-sequence identity.
    fn send_bytes_inner(
        &self,
        to: usize,
        content: Vec<u8>,
        base_delay: u64,
        at: Option<OriginSource>,
    ) -> bool {
        let now = self.shared.time.borrow().now();
        let message_id = self.next_message_id();
        if content.len() as u64 > ledger_format::limits::MAX_MESSAGE_BYTES as u64 {
            // Fail closed: an oversized message never reaches the queue or
            // the journal.
            self.shared
                .record_journal_error(ledger_journal::JournalError::InvalidPayload(format!(
                    "message of {} bytes exceeds the {} byte limit",
                    content.len(),
                    ledger_format::limits::MAX_MESSAGE_BYTES
                )));
            return false;
        }
        let id = match self.append(
            EntryKind::Send,
            [],
            EntryPayload::Send(ledger_format::SendFrame {
                message_id,
                from: ActorId(self.task as u32),
                to: ActorId(to as u32),
                original_content: content.clone(),
            }),
        ) {
            Ok(id) => id,
            Err(error) => {
                self.shared.record_journal_error(error);
                return false;
            }
        };
        if let Some(origin) = at {
            self.shared.origins.borrow_mut().record(id, origin);
        }
        if self.shared.dropped_events.contains(&id) {
            if let Err(error) = self.append(
                EntryKind::Fault,
                [id],
                EntryPayload::Fault(FaultPayload::DropMessage { message_id }),
            ) {
                self.shared.record_journal_error(error);
            }
            return true;
        }
        let injected_delay = match self.inject_send_fault(id, message_id) {
            Some(None) => return true,
            Some(Some(ticks)) => ticks,
            None => 0,
        };
        let total_delay = match self.swarm_send_policy(id, message_id) {
            SwarmAction::Drop => return true,
            SwarmAction::Delay(extra) => base_delay
                .saturating_add(extra)
                .saturating_add(injected_delay),
            SwarmAction::Deliver => base_delay.saturating_add(injected_delay),
        };
        let outcome = self.transmit_once(to, content.clone(), message_id, id, now, total_delay);
        // Duplicate rule: a Queued first transmission (delivered or lost,
        // retry semantics) with a Duplicate target journals
        // DuplicateMessage{ordinal 1} parented by the send, then re-transmits
        // the identical Message on the same branch. Each transmission journals
        // its own loss/queue fate. QueueFull backpressure wins (no duplicate);
        // early Drop/swarm-drop returns above never duplicate. The second
        // transmission draws in fixed order, so replay stays identical.
        if let SendOutcome::Queued(first_delivered) = outcome
            && self.duplicate_targets(id)
        {
            self.mark_fault_applied(id);
            if let Err(error) = self.append(
                EntryKind::Fault,
                [id],
                EntryPayload::Fault(FaultPayload::DuplicateMessage {
                    message_id,
                    copy_ordinal: 1,
                }),
            ) {
                self.shared.record_journal_error(error);
            }
            let second = self.transmit_once(to, content, message_id, id, now, total_delay);
            if !first_delivered {
                self.journal_net_loss(id, to, message_id);
            }
            return match second {
                SendOutcome::Queued(second_delivered) => {
                    if !second_delivered {
                        self.journal_net_loss(id, to, message_id);
                    }
                    first_delivered || second_delivered
                }
                SendOutcome::QueueFull => {
                    self.journal_queue_full(id, to, message_id);
                    first_delivered
                }
            };
        }
        match outcome {
            SendOutcome::Queued(delivered) => {
                if !delivered {
                    self.journal_net_loss(id, to, message_id);
                }
                delivered
            }
            SendOutcome::QueueFull => {
                self.journal_queue_full(id, to, message_id);
                false
            }
        }
    }

    /// Journal a bounded-queue refusal: a `Drop` fault under the drop policy,
    /// a `Block` entry under the block policy (backpressure, retryable).
    fn journal_queue_full(&self, send_id: EntryHash, to: usize, message_id: MessageId) {
        let policy = self.shared.net.borrow().queue_policy(self.task, to);
        match policy {
            crate::net::QueueFullPolicy::Drop => {
                if let Err(error) = self.append(
                    EntryKind::Fault,
                    [send_id],
                    EntryPayload::Fault(FaultPayload::DropMessage { message_id }),
                ) {
                    self.shared.record_journal_error(error);
                }
            }
            crate::net::QueueFullPolicy::Block => {
                if let Err(error) = self.append(
                    EntryKind::Block,
                    [send_id],
                    EntryPayload::Block(ledger_format::BlockPayload::Yield),
                ) {
                    self.shared.record_journal_error(error);
                }
            }
        }
    }

    /// Journal the fault class for a message the network refused: a partition
    /// when the link is partitioned, otherwise a loss drop.
    fn journal_net_loss(&self, send_id: EntryHash, to: usize, message_id: MessageId) {
        let partitioned = self.shared.net.borrow().is_partitioned(self.task, to);
        let fault = if partitioned {
            FaultSpec::Partition {
                src: ActorId(self.task as u32),
                dst: ActorId(to as u32),
            }
        } else {
            FaultSpec::Drop
        };
        let fault_payload = EntryPayload::Fault(match fault {
            FaultSpec::Partition { src, dst } => FaultPayload::Partition {
                src,
                dst,
                enabled: true,
            },
            _ => FaultPayload::DropMessage { message_id },
        });
        if let Err(error) = self.append(EntryKind::Fault, [send_id], fault_payload) {
            self.shared.record_journal_error(error);
        }
    }

    /// Checked link send distinguishing a full bounded queue from a drop.
    ///
    /// The capacity check runs before any draw, so a full queue never
    /// consumes from the `net` seed stream.
    fn send_via_link_checked(&self, message: Message, now: u64, base_delay: u64) -> SendOutcome {
        match self
            .shared
            .net
            .borrow_mut()
            .try_send_via_link(message, now, base_delay, |bound| {
                let mut offset = self.shared.net_offset.borrow_mut();
                let value = self.shared.seed_tree.draw_u64("net", *offset);
                *offset += 1;
                value % bound.max(1)
            }) {
            Ok(delivered) => SendOutcome::Queued(delivered),
            Err(crate::net::NetError::QueueFull { .. }) => SendOutcome::QueueFull,
            Err(crate::net::NetError::InvalidReorderWindow { .. }) => SendOutcome::Queued(false),
        }
    }

    /// One network transmission on the configured branch.
    ///
    /// Link-configured pairs use the checked link path; others use the
    /// direct identity path. Both shapes report `QueueFull` without draws.
    fn transmit_once(
        &self,
        to: usize,
        content: Vec<u8>,
        message_id: MessageId,
        send_id: EntryHash,
        now: u64,
        total_delay: u64,
    ) -> SendOutcome {
        if self.shared.net.borrow().link_configured(self.task, to) {
            self.send_via_link_checked(
                Message {
                    from: self.task,
                    to,
                    content,
                    message_id,
                    send_id,
                    deliver_at: now,
                },
                now,
                total_delay,
            )
        } else {
            match self.shared.net.borrow_mut().try_send_at_with_identity(
                Message {
                    from: self.task,
                    to,
                    content,
                    message_id,
                    send_id,
                    deliver_at: now,
                },
                now,
                total_delay,
            ) {
                Ok(delivered) => SendOutcome::Queued(delivered),
                Err(crate::net::NetError::QueueFull { .. }) => SendOutcome::QueueFull,
                Err(crate::net::NetError::InvalidReorderWindow { .. }) => {
                    SendOutcome::Queued(false)
                }
            }
        }
    }

    /// Whether any `Duplicate` fault targets `id`.
    fn duplicate_targets(&self, id: EntryHash) -> bool {
        self.shared.fault_schedule.iter().any(|fault| match fault {
            SimFault::Duplicate { send } => *send == id,
            _ => false,
        })
    }

    /// Return the scheduled fault injection targeting `id`, if any.
    fn schedule_injection_for(&self, id: EntryHash) -> Option<&SimFault> {
        self.shared
            .fault_schedule
            .iter()
            .find(|injection| match injection {
                SimFault::Drop(target)
                | SimFault::Delay { send: target, .. }
                | SimFault::Duplicate { send: target }
                | SimFault::Crash(target)
                | SimFault::Corrupt { write: target, .. }
                | SimFault::CrashState { write: target, .. } => *target == id,
                SimFault::Partition { .. } => false,
            })
    }

    /// Record that the fault injection for `id` took effect.
    fn mark_fault_applied(&self, id: EntryHash) {
        let mut applied = self.shared.applied_faults.borrow_mut();
        if !applied.contains(&id) {
            applied.push(id);
        }
    }

    /// Apply a scheduled fault to an outgoing message, returning the extra
    /// delay ticks in the delivered case.
    ///
    /// Returns `None` when the fault drops the message or when no fault
    /// targets it.
    fn inject_send_fault(&self, send_id: EntryHash, message_id: MessageId) -> Option<Option<u64>> {
        match self.schedule_injection_for(send_id) {
            Some(SimFault::Drop(_)) => {
                self.mark_fault_applied(send_id);
                if let Err(error) = self.append(
                    EntryKind::Fault,
                    [send_id],
                    EntryPayload::Fault(FaultPayload::DropMessage { message_id }),
                ) {
                    self.shared.record_journal_error(error);
                }
                Some(None)
            }
            Some(SimFault::Delay { send, ticks }) => {
                self.mark_fault_applied(*send);
                Some(Some(*ticks))
            }
            _ => None,
        }
    }

    /// Apply a scheduled fault to a completed storage write.
    fn inject_write_fault(
        &self,
        write_id: EntryHash,
        path: &str,
    ) -> Result<(), ledger_journal::JournalError> {
        // Crash-type faults derive their canonical operation from the shared
        // `SimFault::crash_operation_for` mapping so replay verifies the
        // same operations the executor applies. Non-crash injections are
        // matched here by construction; a missing derivation is a typed
        // error, never a panic.
        let operation = match self
            .schedule_injection_for(write_id)
            .and_then(|fault| fault.crash_operation_for(path))
        {
            Some(Ok(operation)) => Some(operation),
            Some(Err(identifier)) => {
                return Err(ledger_journal::JournalError::InvalidPayload(format!(
                    "unknown crash-state identifier {identifier}"
                )));
            }
            None => None,
        };
        match self.schedule_injection_for(write_id) {
            Some(SimFault::Crash(_)) => {
                self.mark_fault_applied(write_id);
                self.fs_crash();
                self.append(
                    EntryKind::Fault,
                    [],
                    EntryPayload::Fault(FaultPayload::CrashActor {
                        actor: ActorId(self.task as u32),
                        crash_operation: ledger_format::CrashOperation::DropAllUnsynced,
                    }),
                )?;
            }
            Some(SimFault::Corrupt { .. }) => {
                let Some(operation) = operation else {
                    return Err(ledger_journal::JournalError::InvalidPayload(
                        "corrupt fault implies a crash operation".to_string(),
                    ));
                };
                self.mark_fault_applied(write_id);
                if let Err(error) = self
                    .shared
                    .fs
                    .borrow_mut()
                    .apply_crash_operation(&operation)
                {
                    // A scheduled corruption that cannot resolve its target
                    // fails closed without fallback.
                    return Err(ledger_journal::JournalError::InvalidPayload(format!(
                        "scheduled corrupt rejected: {error}"
                    )));
                }
                self.append(
                    EntryKind::Fault,
                    [],
                    EntryPayload::Fault(FaultPayload::CrashActor {
                        actor: ActorId(self.task as u32),
                        crash_operation: operation,
                    }),
                )?;
            }
            Some(SimFault::CrashState { write, .. }) => {
                self.mark_fault_applied(*write);
                let Some(operation) = operation else {
                    return Err(ledger_journal::JournalError::InvalidPayload(
                        "crash-state fault implies a crash operation".to_string(),
                    ));
                };
                if let Err(error) = self
                    .shared
                    .fs
                    .borrow_mut()
                    .apply_crash_operation(&operation)
                {
                    return Err(ledger_journal::JournalError::InvalidPayload(format!(
                        "scheduled crash-state rejected: {error}"
                    )));
                }
                self.append(
                    EntryKind::Fault,
                    [],
                    EntryPayload::Fault(FaultPayload::CrashActor {
                        actor: ActorId(self.task as u32),
                        crash_operation: operation,
                    }),
                )?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Park the task on a sleep timer, journaling a `TimerSet` entry.
    ///
    /// The timer carries the `TimerSet` entry as its enabler so the fired
    /// `TimerFire` journals with the correct parent. Any stale `timer_fired`
    /// flag from a prior sleep is cleared so a later park cannot short-circuit.
    pub(crate) fn park_sleep(&self, ticks: u64) -> Result<(), ledger_journal::JournalError> {
        let timer_set = self.append(
            EntryKind::TimerSet,
            [],
            EntryPayload::TimerSet {
                timer_id: 0,
                deadline_ticks: ticks,
            },
        )?;
        self.shared
            .time
            .borrow_mut()
            .set_with_enabler(ticks, self.task, Some(timer_set));
        let mut tasks = self.shared.tasks.borrow_mut();
        tasks[self.task].timer_fired = false;
        tasks[self.task].blocked_on = Some(BlockedOn::Timer);
        Ok(())
    }

    /// Park the task waiting for a message, journaling a `Block` entry.
    pub(crate) fn park_message(&self) -> Result<(), ledger_journal::JournalError> {
        self.append(
            EntryKind::Block,
            [],
            EntryPayload::Block(ledger_format::BlockPayload::Yield),
        )?;
        self.shared.tasks.borrow_mut()[self.task].blocked_on = Some(BlockedOn::Message);
        Ok(())
    }

    /// Journal a `Block` entry for an explicit yield without parking.
    pub(crate) fn yield_block(&self) -> Result<(), ledger_journal::JournalError> {
        self.append(
            EntryKind::Block,
            [],
            EntryPayload::Block(ledger_format::BlockPayload::Yield),
        )?;
        Ok(())
    }

    /// Journal a `ClockRead` entry carrying the current virtual time, returning it.
    pub(crate) fn read_clock(&self) -> Result<u64, ledger_journal::JournalError> {
        let now = self.shared.time.borrow().now();
        self.append(
            EntryKind::ClockRead,
            [],
            EntryPayload::ClockRead { ticks: now },
        )?;
        Ok(now)
    }

    /// Take the next message identity for this task's send sequence.
    fn next_message_id(&self) -> MessageId {
        let mut seqs = self.shared.send_seq.borrow_mut();
        if self.task >= seqs.len() {
            seqs.resize(self.task + 1, 0);
        }
        let sequence = seqs[self.task];
        seqs[self.task] = sequence + 1;
        MessageId::new(ActorId(self.task as u32), sequence)
    }

    /// Journal a `Recv` frame for `message` and return its entry id.
    fn journal_recv(&self, message: &Message) -> Option<EntryHash> {
        match self.append(
            EntryKind::Recv,
            [message.send_id],
            EntryPayload::Recv(ledger_format::RecvFrame {
                message_id: message.message_id,
                from: ActorId(message.from as u32),
                to: ActorId(self.task as u32),
                observed_content: message.content.clone(),
            }),
        ) {
            Ok(id) => Some(id),
            Err(error) => {
                self.shared.record_journal_error(error);
                None
            }
        }
    }

    /// Take the first deliverable message for this task, journaling a `Recv`
    /// entry, and return its scalar payload.
    pub(crate) fn recv_now(&self) -> Option<u64> {
        let now = self.shared.time.borrow().now();
        let message = self.shared.recv_at_effective(self.task, now)?;
        let recv_id = self.journal_recv(&message);
        self.inherit_recv_origin(recv_id, message.send_id);
        Some(message.payload())
    }

    /// Journal an `InputStep` entry carrying a generator identity, a replay
    /// key, and the input value.
    pub(crate) fn input_step(
        &self,
        generator: u64,
        replay: u64,
        value: u64,
    ) -> Result<(), ledger_journal::JournalError> {
        self.append(
            EntryKind::InputStep,
            [],
            EntryPayload::InputStep(ledger_format::InputStepPayload {
                generator,
                replay,
                value: ledger_format::CanonicalValue::Unsigned(value),
            }),
        )?;
        Ok(())
    }

    /// Journal an `Assert` entry carrying a boolean as 1 or 0.
    pub(crate) fn assert_entry(&self, passed: bool) -> Result<(), ledger_journal::JournalError> {
        self.append(
            EntryKind::Assert,
            [],
            EntryPayload::Assert(ledger_format::AssertPayload {
                predicate: ASSERT_SCHEMA,
                passed,
                detail: ledger_format::CanonicalValue::Unsigned(u64::from(passed)),
            }),
        )?;
        Ok(())
    }

    /// Journal the terminal `Outcome` entry of a finished program.
    pub(crate) fn outcome_done(&self) -> Result<(), ledger_journal::JournalError> {
        self.append(
            EntryKind::Outcome,
            [],
            EntryPayload::Outcome(ledger_format::OutcomePayload {
                schema: OUTCOME_SCHEMA,
                value: ledger_format::CanonicalValue::Text("done".into()),
            }),
        )?;
        Ok(())
    }

    pub fn set_register(&self, value: u64) {
        self.shared.tasks.borrow_mut()[self.task].register = value;
    }

    pub fn register(&self) -> u64 {
        self.shared.tasks.borrow()[self.task].register
    }
    /// Spawn a child task, giving it a boundary bound to its own task id.
    ///
    /// The child body receives a fresh [`Boundary`] so its journaled entries
    /// use the child's actor and sequence. The parent keeps its own boundary.
    pub fn spawn_task(
        &self,
        body: impl FnOnce(Boundary) -> Pin<Box<dyn Future<Output = ()> + 'static>>,
    ) -> TaskId {
        let (id, _) = {
            let mut tasks = self.shared.tasks.borrow_mut();
            let id = tasks.len() as u64;
            let child_boundary = Boundary::for_task(Rc::clone(&self.shared), id as usize);
            let future = body(child_boundary);
            tasks.push(TaskEntry {
                future: Some(future),
                blocked_on: None,
                done: false,
                register: 0,
                timer_fired: false,
                stream_rngs: std::collections::BTreeMap::new(),
            });
            (id, ())
        };
        if let Err(error) = self.append_for_actor(
            ActorId(id as u32),
            EntryKind::Spawn,
            [],
            EntryPayload::Spawn {
                child_actor: ActorId(id as u32),
            },
        ) {
            self.shared.record_journal_error(error);
        }
        self.shared.ready.borrow_mut().push(id as usize);
        id
    }
}

/// One RNG handle; cloning clones the `Rc`, never the draw state.
#[derive(Clone)]
struct StreamRng {
    shared: Rc<ExecutorShared>,
    task: usize,
    stream: StreamId,
    /// Precomputed seed-tree label for this stream, built once per handle so
    /// the hot draw path never re-formats it.
    label: String,
}

impl TryRng for StreamRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let value = {
            let mut tasks = self.shared.tasks.borrow_mut();
            let entry = &mut tasks[self.task];
            let rng = entry
                .stream_rngs
                .entry(self.stream)
                .or_insert_with(|| self.shared.seed_tree.rng(&self.label));
            rng.next_u64()
        };
        let kind = EntryKind::RngDraw;
        match self.shared.journal_append(
            ActorId(self.task as u32),
            kind,
            [],
            EntryPayload::RngDraw(ledger_format::RngDrawPayload {
                stream: self.stream,
                draw_index: 0,
                content: value.to_le_bytes().to_vec(),
            }),
        ) {
            Ok(id) => {
                self.shared
                    .notify_entry(ActorId(self.task as u32), kind, self.task, Some(id));
            }
            Err(error) => self.shared.record_journal_error(error),
        }
        Ok(value)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        rand_core::utils::fill_bytes_via_next_word(dst, || self.try_next_u64())
    }
}

impl Effects for Boundary {
    /// Non-journaled virtual-time read (see `SimBackend::clock` docs).
    fn clock(&self) -> Clock {
        Clock::new(self.shared.time.borrow().now())
    }

    fn rng(&mut self, stream: StreamId) -> &mut impl rand_core::Rng {
        let idx = stream.0 as usize;
        while self.rng_streams.len() <= idx {
            self.rng_streams.push(None);
        }
        self.rng_streams[idx].get_or_insert_with(|| StreamRng {
            shared: Rc::clone(&self.shared),
            task: self.task,
            stream,
            label: format!("app/{}", stream.0),
        })
    }

    async fn sleep(&self, d: core::time::Duration) {
        let ticks = d.as_micros() as u64;
        let timer_set = match self.append(
            EntryKind::TimerSet,
            [],
            EntryPayload::TimerSet {
                timer_id: 0,
                deadline_ticks: ticks,
            },
        ) {
            Ok(id) => Some(id),
            Err(error) => {
                self.shared.record_journal_error(error);
                None
            }
        };
        self.shared
            .time
            .borrow_mut()
            .set_with_enabler(ticks, self.task, timer_set);
        self.shared.tasks.borrow_mut()[self.task].blocked_on = Some(BlockedOn::Timer);
        SleepFuture {
            shared: Rc::clone(&self.shared),
            task: self.task,
        }
        .await;
    }

    fn net(&self) -> &dyn Net {
        self
    }

    fn fs(&self) -> &dyn Fs {
        self
    }
}

impl Net for Boundary {
    fn send(&self, message: Message) -> bool {
        self.send_bytes_inner(message.to, message.content, 0, None)
    }

    fn recv(&self, task: usize, now: u64) -> Option<Message> {
        let message = self.shared.recv_at_effective(task, now)?;
        let recv_id = self.journal_recv(&message);
        self.inherit_recv_origin(recv_id, message.send_id);
        Some(message)
    }

    fn has_ready_message(&self, task: usize, now: u64) -> bool {
        self.shared.net.borrow().has_ready_message(task, now)
    }
}

impl Fs for Boundary {
    fn write_loc(
        &self,
        path: &str,
        value: u64,
        at: OriginSource,
    ) -> Result<EntryHash, crate::effects::FsError> {
        let id = Fs::write(self, path, value)?;
        self.shared.origins.borrow_mut().record(id, at);
        Ok(id)
    }

    fn write(&self, path: &str, value: u64) -> Result<EntryHash, crate::effects::FsError> {
        let mut journal = self.shared.journal.borrow_mut();
        let mut fs = self.shared.fs.borrow_mut();
        let id = fs.write(&mut journal, ActorId(self.task as u32), path, value)?;
        self.note_journaled(ActorId(self.task as u32));
        drop(fs);
        drop(journal);
        self.shared.notify_entry(
            ActorId(self.task as u32),
            EntryKind::FsWrite,
            self.task,
            Some(id),
        );
        self.inject_write_fault(id, path)?;
        self.maybe_crash_on_write(path, id)?;
        Ok(id)
    }

    fn fsync_loc(&self, at: OriginSource) -> Result<EntryHash, crate::effects::FsError> {
        let id = Fs::fsync(self)?;
        self.shared.origins.borrow_mut().record(id, at);
        Ok(id)
    }

    fn fsync(&self) -> Result<EntryHash, crate::effects::FsError> {
        let mut journal = self.shared.journal.borrow_mut();
        let mut fs = self.shared.fs.borrow_mut();
        let id = fs.fsync(&mut journal, ActorId(self.task as u32))?;
        self.note_journaled(ActorId(self.task as u32));
        drop(fs);
        drop(journal);
        self.shared.notify_entry(
            ActorId(self.task as u32),
            EntryKind::FsFsync,
            self.task,
            Some(id),
        );
        Ok(id)
    }

    fn read(&self, path: &str) -> Result<Option<u64>, crate::effects::FsError> {
        let mut journal = self.shared.journal.borrow_mut();
        let fs = self.shared.fs.borrow();
        let value = fs.read(&mut journal, ActorId(self.task as u32), path)?;
        self.note_journaled(ActorId(self.task as u32));
        drop(fs);
        drop(journal);
        // The FsRead entry is the actor's head; derive its signature directly.
        let read_id = self
            .shared
            .journal
            .borrow()
            .head_for_actor(ActorId(self.task as u32));
        self.shared.notify_entry(
            ActorId(self.task as u32),
            EntryKind::FsRead,
            self.task,
            read_id,
        );
        Ok(value)
    }

    fn crash(&self) {
        self.crash_impl();
    }

    fn crash_loc(&self, at: OriginSource) {
        if let Some(id) = self.crash_impl() {
            self.shared.origins.borrow_mut().record(id, at);
        }
    }
}

impl Boundary {
    /// Journal the crash-fault entry and fold storage into the post-crash
    /// state. Returns the entry id when journaling worked.
    fn crash_impl(&self) -> Option<EntryHash> {
        let id = match self.append(
            EntryKind::Fault,
            [],
            EntryPayload::Fault(FaultPayload::CrashActor {
                actor: ActorId(self.task as u32),
                crash_operation: ledger_format::CrashOperation::DropAllUnsynced,
            }),
        ) {
            Ok(id) => Some(id),
            Err(error) => {
                self.shared.record_journal_error(error);
                None
            }
        };
        self.fs_crash();
        id
    }
}

/// A sleep future that resolves when the executor fires the task's timer.
struct SleepFuture {
    shared: Rc<ExecutorShared>,
    task: usize,
}

impl Future for SleepFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<()> {
        let mut tasks = self.shared.tasks.borrow_mut();
        if tasks[self.task].timer_fired {
            tasks[self.task].timer_fired = false;
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// A receive future that parks the task until a message is deliverable.
struct RecvFuture {
    shared: Rc<ExecutorShared>,
    task: usize,
}

impl Future for RecvFuture {
    type Output = u64;

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<u64> {
        let now = self.shared.time.borrow().now();
        if let Some(message) = self.shared.recv_at_effective(self.task, now) {
            // Record a failed Recv append; the message is already consumed.
            match self.shared.journal_append(
                ActorId(self.task as u32),
                EntryKind::Recv,
                [message.send_id],
                EntryPayload::Recv(ledger_format::RecvFrame {
                    message_id: message.message_id,
                    from: ActorId(message.from as u32),
                    to: ActorId(self.task as u32),
                    observed_content: message.content.clone(),
                }),
            ) {
                Ok(id) => {
                    self.shared.notify_entry(
                        ActorId(self.task as u32),
                        EntryKind::Recv,
                        self.task,
                        Some(id),
                    );
                    let inherited = self.shared.origins.borrow().get(&message.send_id).cloned();
                    if let Some(origin) = inherited {
                        self.shared.origins.borrow_mut().record(id, origin);
                    }
                }
                Err(error) => self.shared.record_journal_error(error),
            }
            Poll::Ready(message.payload())
        } else {
            // Record a failed Block append; the park still proceeds.
            match self.shared.journal_append(
                ActorId(self.task as u32),
                EntryKind::Block,
                [],
                EntryPayload::Block(ledger_format::BlockPayload::Yield),
            ) {
                Ok(id) => {
                    self.shared.notify_entry(
                        ActorId(self.task as u32),
                        EntryKind::Block,
                        self.task,
                        Some(id),
                    );
                }
                Err(error) => self.shared.record_journal_error(error),
            }
            self.shared.tasks.borrow_mut()[self.task].blocked_on = Some(BlockedOn::Message);
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod schema_tests {
    use super::{ASSERT_SCHEMA, OUTCOME_SCHEMA};

    #[test]
    fn sim_schemas_are_bound_nonzero_and_distinct() {
        assert_ne!(
            OUTCOME_SCHEMA,
            ledger_format::EntryHash([0u8; 32]),
            "outcome must not be zeroed"
        );
        assert_ne!(
            ASSERT_SCHEMA,
            ledger_format::EntryHash([0u8; 32]),
            "assert must not be zeroed"
        );
        assert_ne!(
            OUTCOME_SCHEMA, ASSERT_SCHEMA,
            "outcome and assert digests must differ"
        );
        assert_eq!(
            OUTCOME_SCHEMA,
            ledger_format::EntryHash(*blake3::hash(b"ldgr.sim.outcome.v1").as_bytes()),
            "outcome binds its domain string"
        );
        assert_eq!(
            ASSERT_SCHEMA,
            ledger_format::EntryHash(*blake3::hash(b"ldgr.sim.assert.v1").as_bytes()),
            "assert binds its domain string"
        );
    }
}
