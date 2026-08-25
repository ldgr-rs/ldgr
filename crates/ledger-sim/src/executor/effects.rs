//! Effects boundary of the executor.
//!
//! [`Boundary`] is the task-facing handle that journals deterministic
//! effects (send, recv, sleep, clock, rng, storage) against the shared
//! executor state. The `Effects`/`Net`/`Fs` trait implementations and the
//! sleeping/receiving futures live here; the orchestration loop, the task
//! table, and the shared state stay in the module root.
use crate::origin::OriginSource;
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use crate::config::SimFault;
use crate::effects::{Effects, Fs, Net, TaskId};
use crate::net::Message;
use crate::time::Clock;
use core::convert::Infallible;
use ledger_format::{ActorId, EntryKind, FaultSpec, GenId, Hash, InputKey, Payload, StreamId};
use rand_core::{Rng, TryRng};

use super::{BlockedOn, ExecutorShared, TaskEntry};

/// Outcome of a swarm network policy decision.
enum SwarmAction {
    /// Deliver the message (possibly with an extra delay).
    Deliver,
    /// Delay delivery by the given tick count.
    Delay(u64),
    /// Drop the message; a `Drop` fault was already journaled.
    Drop,
}

/// Boundary through which a task calls deterministic effects.
///
/// A task owns one boundary for the duration of its body. The boundary is
/// `Clone` and `Rc`-shared, so child tasks spawned through it keep accessing
/// the same journal, timers, network, and storage.
#[derive(Clone)]
pub struct Boundary {
    pub(crate) shared: Rc<ExecutorShared>,
    task: usize,
    /// Live RNG handles, one slot per stream id.
    ///
    /// Each handle clones the shared state, so cloning a boundary never
    /// duplicates draw state: every stream's ChaCha20 lives in the shared task
    /// table, keyed by stream id.
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

    /// Record a journal append failure from a call site that cannot return
    /// `Err` (mirrors `ExecutorShared::record_journal_error`). The first
    /// failure wins; later failures never overwrite it.
    pub fn record_journal_error(&self, error: ledger_journal::JournalError) {
        self.shared.record_journal_error(error);
    }

    /// Journal one entry with this task as the actor.
    fn append(
        &self,
        kind: EntryKind,
        parents: impl IntoIterator<Item = Hash>,
        payload: Payload,
    ) -> Result<Hash, ledger_journal::JournalError> {
        let id = self
            .shared
            .journal_append(self.task as ActorId, kind, parents, payload)?;
        self.shared
            .notify_entry(self.task as ActorId, kind, self.task, Some(id));
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

    /// Apply a swarm drop or delay decision to a send, journaling a `Drop`
    /// fault when the message is lost.
    ///
    /// With the default zero-probability swarm this consumes no draws and
    /// returns [`SwarmAction::Deliver`] unchanged, keeping journals
    /// byte-identical to the pre-swarm path.
    fn swarm_send_policy(&self, send_id: Hash) -> SwarmAction {
        let swarm = &self.shared.swarm;
        if swarm.drop_probability > 0.0 && self.net_draw() < swarm.drop_probability {
            if let Err(error) = self.append(
                EntryKind::Fault {
                    fault: FaultSpec::Drop,
                },
                [send_id],
                Payload::Empty,
            ) {
                self.shared.record_journal_error(error);
            }
            return SwarmAction::Drop;
        }
        if swarm.delay_probability > 0.0
            && swarm.max_delay_ticks > 0
            && self.net_draw() < swarm.delay_probability
        {
            let delay = self.net_draw_delay(swarm.max_delay_ticks);
            return SwarmAction::Delay(delay);
        }
        SwarmAction::Deliver
    }

    /// Draw a swarm delay in `0 ..= max_delay_ticks` from the `net` stream.
    ///
    /// `u64::MAX` is the one bound whose modulus (`max + 1`) does not fit
    /// `u64`; there the raw draw already spans the full `0 ..= u64::MAX`
    /// range, so it is returned unchanged. Every smaller bound uses the plain
    /// remainder, which cannot overflow or wrap.
    pub(crate) fn net_draw_delay(&self, max_delay_ticks: u64) -> u64 {
        let mut offset = self.shared.net_offset.borrow_mut();
        let value = self.shared.seed_tree.draw_u64("net", *offset);
        *offset += 1;
        match max_delay_ticks {
            u64::MAX => value,
            bound => value % (bound + 1),
        }
    }

    /// Apply a swarm crash-state sample after a storage write, when configured.
    ///
    /// With `crash_probability == 0.0` this consumes no draws and returns
    /// `Ok(())`, keeping journals byte-identical to the pre-swarm path. On a
    /// sampled crash it applies a deterministic crash operator and journals
    /// `Fault { CrashState(k) }`.
    fn maybe_crash_on_write(
        &self,
        path: &str,
        value: u64,
    ) -> Result<(), ledger_journal::JournalError> {
        let swarm = &self.shared.swarm;
        if swarm.crash_probability <= 0.0 {
            return Ok(());
        }
        if self.fs_draw() >= swarm.crash_probability {
            return Ok(());
        }
        // The probability and choice draws above always happen so the fs
        // stream offsets stay stable; only the application is gated.
        let mut offset = self.shared.fs_offset.borrow_mut();
        let choice = self.shared.seed_tree.draw_u64("fs", *offset);
        *offset += 1;
        let operator = match choice % 4 {
            0 => crate::simfs::CrashOperator::DropAllUnsynced,
            1 => {
                let mut dropped = HashSet::new();
                dropped.insert(path.to_owned());
                crate::simfs::CrashOperator::DropSubset(dropped)
            }
            2 => crate::simfs::CrashOperator::TornWrite {
                path: path.to_owned(),
                partial_value: value.saturating_div(2),
            },
            _ => crate::simfs::CrashOperator::BitFlipCorruption {
                path: path.to_owned(),
                xor_mask: 1,
            },
        };
        let state_index = match operator {
            crate::simfs::CrashOperator::DropAllUnsynced => 0,
            crate::simfs::CrashOperator::DropSubset(_) => 1,
            crate::simfs::CrashOperator::TornWrite { .. } => 2,
            crate::simfs::CrashOperator::BitFlipCorruption { .. } => 3,
            crate::simfs::CrashOperator::TornWriteSectors { .. } => 4,
            crate::simfs::CrashOperator::CorruptRange { .. } => 5,
        };
        let mut fault_classes = self.shared.fault_classes_used.borrow_mut();
        if fault_classes.len() >= swarm.fault_classes_per_run.max(1) {
            return Ok(());
        }
        fault_classes.insert(state_index);
        drop(fault_classes);
        self.shared.fs.borrow_mut().apply_crash_operator(&operator);
        self.append(
            EntryKind::Fault {
                fault: FaultSpec::CrashState(state_index),
            },
            [],
            Payload::Empty,
        )?;
        Ok(())
    }

    /// Apply the configured crash model to the simulated storage.
    ///
    /// With a journaling mode configured the write-ahead journal replays
    /// before the crash operator drops unsynced state; without one the
    /// black-box `DropAllUnsynced` operator applies. The default (no mode)
    /// stays byte-identical to the historical crash path.
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
        parents: impl IntoIterator<Item = Hash>,
        payload: Payload,
    ) -> Result<Hash, ledger_journal::JournalError> {
        self.shared.journal_append(actor, kind, parents, payload)
    }

    /// Receive a message, journaling `Recv` or parking with a `Block` entry.
    ///
    /// This is an inherent method (not on the `Effects` trait): only the
    /// executor boundary can suspend on a message, so `SimBackend` and
    /// `TokioBackend` do not need to implement it.
    pub async fn recv(&self) -> u64 {
        RecvFuture {
            shared: Rc::clone(&self.shared),
            task: self.task,
        }
        .await
    }

    /// Journal an `Outcome` entry carrying the task register (test helper).
    pub fn outcome(&self, value: u64) -> Result<Hash, ledger_journal::JournalError> {
        self.append(EntryKind::Outcome, [], Payload::Number(value))
    }

    /// Return whether a message is currently deliverable to this task.
    pub fn has_ready_message(&self) -> bool {
        let now = self.shared.time.borrow().now();
        self.shared.net.borrow().has_ready_message(self.task, now)
    }

    /// Resolve a hostname to a task id from the deterministic DNS table.
    ///
    /// The table is config-driven, so the result is identical across runs
    /// that share the config. An unknown name resolves to `None`. Resolution
    /// is a pure lookup: it journals nothing and never touches the ambient
    /// host.
    pub fn resolve(&self, name: &str) -> Option<usize> {
        self.shared.dns.resolve(name)
    }

    /// Send a message immediately, journaling a `Send` entry.
    pub fn send(&self, to: usize, payload: u64) -> bool {
        self.send_inner(to, payload, None)
    }

    /// Send with origin capture: the caller's source location lands in the
    /// session side channel keyed by the Send entry hash.
    #[track_caller]
    pub fn send_tracked(&self, to: usize, payload: u64) -> bool {
        self.send_inner(to, payload, Some(core::panic::Location::caller().into()))
    }

    /// Snapshot the captured effect origins in append order.
    pub fn origins_snapshot(&self) -> Vec<(ledger_format::Hash, OriginSource)> {
        self.shared.origins.borrow().snapshot()
    }

    /// Give a Recv entry the origin of the Send that produced it, keeping
    /// lineage continuous across the network boundary.
    fn inherit_recv_origin(&self, recv_id: Option<Hash>, send_id: Hash) {
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

    /// Toggle a directed partition at the current point of the run.
    ///
    /// The toggle journals a `Fault { Partition { src, dst } }` entry and
    /// applies it to the live network immediately: subsequent sends on the
    /// (src, dst) link are refused until the same pair is toggled again. The
    /// journaled entry is the causal record of the matrix change, so a replay
    /// applies the same faults in causal order. A config-scheduled partition
    /// seeds the same matrix from run start.
    pub fn apply_partition(
        &self,
        src: usize,
        dst: usize,
    ) -> Result<Hash, ledger_journal::JournalError> {
        let fault = FaultSpec::Partition {
            src: src as ActorId,
            dst: dst as ActorId,
        };
        let id = self.append(EntryKind::Fault { fault }, [], Payload::Empty)?;
        let applied = self
            .shared
            .net
            .borrow_mut()
            .apply_fault(&FaultSpec::Partition {
                src: src as ActorId,
                dst: dst as ActorId,
            });
        debug_assert!(applied, "a partition fault always applies");
        Ok(id)
    }

    /// Send a message with a virtual-time delivery delay.
    ///
    /// Deterministic fixed-delay send used by reference simulations. The
    /// delay is added to the current virtual time, so identical seeds yield
    /// identical delivery order.
    pub fn send_timed(&self, to: usize, payload: u64, delay: u64) -> bool {
        self.send_core(to, payload, delay, None)
    }

    /// Single send path for `send` and `send_timed`.
    ///
    /// Journals `Send`, applies the fault and swarm policies, then delivers
    /// through the configured link or the direct queue. Delay 0 keeps
    /// unfaulted journals byte-identical.
    fn send_core(
        &self,
        to: usize,
        payload: u64,
        base_delay: u64,
        at: Option<OriginSource>,
    ) -> bool {
        let now = self.shared.time.borrow().now();
        let id = match self.append(
            EntryKind::Send,
            [],
            Payload::Pair {
                left: to as u64,
                right: payload,
            },
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
                EntryKind::Fault {
                    fault: FaultSpec::Drop,
                },
                [id],
                Payload::Empty,
            ) {
                self.shared.record_journal_error(error);
            }
            return true;
        }
        let injected_delay = match self.inject_send_fault(id) {
            Some(None) => return true,
            Some(Some(ticks)) => ticks,
            None => 0,
        };
        let total_delay = match self.swarm_send_policy(id) {
            SwarmAction::Drop => return true,
            SwarmAction::Delay(extra) => base_delay
                .saturating_add(extra)
                .saturating_add(injected_delay),
            SwarmAction::Deliver => base_delay.saturating_add(injected_delay),
        };
        let delivered = if self.shared.net.borrow().link_configured(self.task, to) {
            self.send_via_link(self.task, to, payload, id, now, total_delay)
        } else {
            self.shared
                .net
                .borrow_mut()
                .send_at(self.task, to, payload, id, now, total_delay)
        };
        if !delivered {
            self.journal_net_loss(id, to);
        }
        delivered
    }

    /// Journal the fault class for a message the network refused: a partition
    /// when the link is partitioned, otherwise a loss drop.
    fn journal_net_loss(&self, send_id: Hash, to: usize) {
        let partitioned = self.shared.net.borrow().is_partitioned(self.task, to);
        let fault = if partitioned {
            FaultSpec::Partition {
                src: self.task as ActorId,
                dst: to as ActorId,
            }
        } else {
            FaultSpec::Drop
        };
        if let Err(error) = self.append(EntryKind::Fault { fault }, [send_id], Payload::Empty) {
            self.shared.record_journal_error(error);
        }
    }

    /// Send a message through a configured link, drawing jitter and loss from
    /// the shared `net` seed stream offset.
    fn send_via_link(
        &self,
        from: usize,
        to: usize,
        payload: u64,
        send_id: Hash,
        now: u64,
        base_delay: u64,
    ) -> bool {
        self.shared.net.borrow_mut().send_via_link(
            Message {
                from,
                to,
                payload,
                send_id,
                deliver_at: now,
            },
            now,
            base_delay,
            |bound| {
                let mut offset = self.shared.net_offset.borrow_mut();
                let value = self.shared.seed_tree.draw_u64("net", *offset);
                *offset += 1;
                value % bound.max(1)
            },
        )
    }

    /// Return the scheduled fault injection targeting `id`, if any.
    fn schedule_injection_for(&self, id: Hash) -> Option<&SimFault> {
        self.shared
            .fault_schedule
            .iter()
            .find(|injection| match injection {
                SimFault::Drop(target)
                | SimFault::Delay { send: target, .. }
                | SimFault::Crash(target)
                | SimFault::Corrupt { write: target, .. }
                | SimFault::CrashState { write: target, .. } => *target == id,
                SimFault::Partition { .. } => false,
            })
    }

    /// Record that the fault injection for `id` took effect.
    fn mark_fault_applied(&self, id: Hash) {
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
    fn inject_send_fault(&self, send_id: Hash) -> Option<Option<u64>> {
        match self.schedule_injection_for(send_id) {
            Some(SimFault::Drop(_)) => {
                self.mark_fault_applied(send_id);
                if let Err(error) = self.append(
                    EntryKind::Fault {
                        fault: FaultSpec::Drop,
                    },
                    [send_id],
                    Payload::Empty,
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
        write_id: Hash,
        path: &str,
    ) -> Result<(), ledger_journal::JournalError> {
        match self.schedule_injection_for(write_id) {
            Some(SimFault::Crash(_)) => {
                self.mark_fault_applied(write_id);
                self.fs_crash();
                self.append(
                    EntryKind::Fault {
                        fault: FaultSpec::CrashState(0),
                    },
                    [],
                    Payload::Empty,
                )?;
            }
            Some(SimFault::Corrupt { write, xor_mask }) => {
                self.mark_fault_applied(*write);
                let operator = crate::simfs::CrashOperator::BitFlipCorruption {
                    path: path.to_owned(),
                    xor_mask: *xor_mask,
                };
                self.shared.fs.borrow_mut().apply_crash_operator(&operator);
                self.append(
                    EntryKind::Fault {
                        fault: FaultSpec::CrashState(3),
                    },
                    [],
                    Payload::Empty,
                )?;
            }
            Some(SimFault::CrashState { write, state }) => {
                self.mark_fault_applied(*write);
                let operator =
                    match *state {
                        0 => crate::simfs::CrashOperator::DropAllUnsynced,
                        1 => crate::simfs::CrashOperator::DropSubset(
                            std::collections::HashSet::from([path.to_owned()]),
                        ),
                        2 => crate::simfs::CrashOperator::TornWrite {
                            path: path.to_owned(),
                            partial_value: 0,
                        },
                        _ => crate::simfs::CrashOperator::DropAllUnsynced,
                    };
                self.shared.fs.borrow_mut().apply_crash_operator(&operator);
                self.append(
                    EntryKind::Fault {
                        fault: FaultSpec::CrashState(*state),
                    },
                    [],
                    Payload::Empty,
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
        let timer_set = self.append(EntryKind::TimerSet, [], Payload::Number(ticks))?;
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
        self.append(EntryKind::Block, [], Payload::Empty)?;
        self.shared.tasks.borrow_mut()[self.task].blocked_on = Some(BlockedOn::Message);
        Ok(())
    }

    /// Journal a `Block` entry for an explicit yield without parking.
    pub(crate) fn yield_block(&self) -> Result<(), ledger_journal::JournalError> {
        self.append(EntryKind::Block, [], Payload::Empty)?;
        Ok(())
    }

    /// Journal a `ClockRead` entry carrying the current virtual time, returning it.
    pub(crate) fn read_clock(&self) -> Result<u64, ledger_journal::JournalError> {
        let now = self.shared.time.borrow().now();
        self.append(EntryKind::ClockRead, [], Payload::Number(now))?;
        Ok(now)
    }

    /// Take the first deliverable message for this task, journaling a `Recv`
    /// entry, and return its payload.
    pub(crate) fn recv_now(&self) -> Option<u64> {
        let now = self.shared.time.borrow().now();
        let message = self.shared.net.borrow_mut().recv_at(self.task, now)?;
        let recv_id = match self.append(
            EntryKind::Recv,
            [message.send_id],
            Payload::Number(message.payload),
        ) {
            Ok(id) => Some(id),
            Err(error) => {
                // The message is already consumed; surface the failed append
                // instead of losing it on the return-None path.
                self.shared.record_journal_error(error);
                None
            }
        };
        self.inherit_recv_origin(recv_id, message.send_id);
        Some(message.payload)
    }

    /// Journal an `InputStep` entry carrying a generator identity, a replay
    /// key, and the input value.
    pub(crate) fn input_step(
        &self,
        generator: GenId,
        replay: InputKey,
        value: u64,
    ) -> Result<(), ledger_journal::JournalError> {
        self.append(
            EntryKind::InputStep { generator, replay },
            [],
            Payload::Number(value),
        )?;
        Ok(())
    }

    /// Journal an `Assert` entry carrying a boolean as 1 or 0.
    pub(crate) fn assert_entry(&self, passed: bool) -> Result<(), ledger_journal::JournalError> {
        self.append(EntryKind::Assert, [], Payload::Number(u64::from(passed)))?;
        Ok(())
    }

    /// Journal the terminal `Outcome` entry of a finished program.
    pub(crate) fn outcome_done(&self) -> Result<(), ledger_journal::JournalError> {
        self.append(EntryKind::Outcome, [], Payload::Text("done".into()))?;
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
                stream_rngs: Vec::new(),
            });
            (id, ())
        };
        if let Err(error) =
            self.append_for_actor(id as ActorId, EntryKind::Spawn, [], Payload::Empty)
        {
            self.shared.record_journal_error(error);
        }
        self.shared.ready.borrow_mut().push(id as usize);
        id
    }
}

/// One deterministic RNG stream handle sharing the boundary's draw state.
///
/// The handle clones the executor shared state, so the returned `&mut` handle
/// lives inside the boundary while the per-stream ChaCha20 state stays in the
/// task table. No `Weak` is needed: the boundary owns the handle, and the
/// shared state never points back to the boundary. Cloning a handle clones the
/// `Rc`, never the draw state.
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
            if entry.stream_rngs.len() <= self.stream as usize {
                entry.stream_rngs.resize(self.stream as usize + 1, None);
            }
            let rng = entry.stream_rngs[self.stream as usize]
                .get_or_insert_with(|| self.shared.seed_tree.rng(&self.label));
            rng.next_u64()
        };
        let kind = EntryKind::RngDraw {
            stream: self.stream,
        };
        match self
            .shared
            .journal_append(self.task as ActorId, kind, [], Payload::Number(value))
        {
            Ok(id) => {
                self.shared
                    .notify_entry(self.task as ActorId, kind, self.task, Some(id));
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
        let idx = stream as usize;
        while self.rng_streams.len() <= idx {
            self.rng_streams.push(None);
        }
        self.rng_streams[idx].get_or_insert_with(|| StreamRng {
            shared: Rc::clone(&self.shared),
            task: self.task,
            stream,
            label: format!("app/{stream}"),
        })
    }

    async fn sleep(&self, d: core::time::Duration) {
        let ticks = d.as_micros() as u64;
        let timer_set = match self.append(EntryKind::TimerSet, [], Payload::Number(ticks)) {
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
        self.send_core(message.to, message.payload, 0, None)
    }

    fn recv(&self, task: usize, now: u64) -> Option<Message> {
        let message = self.shared.net.borrow_mut().recv_at(task, now)?;
        let recv_id = match self.append(
            EntryKind::Recv,
            [message.send_id],
            Payload::Number(message.payload),
        ) {
            Ok(id) => Some(id),
            Err(error) => {
                self.shared.record_journal_error(error);
                None
            }
        };
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
    ) -> Result<Hash, ledger_journal::JournalError> {
        let id = Fs::write(self, path, value)?;
        self.shared.origins.borrow_mut().record(id, at);
        Ok(id)
    }

    fn write(&self, path: &str, value: u64) -> Result<Hash, ledger_journal::JournalError> {
        let mut journal = self.shared.journal.borrow_mut();
        let mut fs = self.shared.fs.borrow_mut();
        let id = fs.write(&mut journal, self.task as ActorId, path, value)?;
        self.note_journaled(self.task as ActorId);
        drop(fs);
        drop(journal);
        self.shared.notify_entry(
            self.task as ActorId,
            EntryKind::FsWrite,
            self.task,
            Some(id),
        );
        self.inject_write_fault(id, path)?;
        self.maybe_crash_on_write(path, value)?;
        Ok(id)
    }

    fn fsync_loc(&self, at: OriginSource) -> Result<Hash, ledger_journal::JournalError> {
        let id = Fs::fsync(self)?;
        self.shared.origins.borrow_mut().record(id, at);
        Ok(id)
    }

    fn fsync(&self) -> Result<Hash, ledger_journal::JournalError> {
        let mut journal = self.shared.journal.borrow_mut();
        let mut fs = self.shared.fs.borrow_mut();
        let id = fs.fsync(&mut journal, self.task as ActorId)?;
        self.note_journaled(self.task as ActorId);
        drop(fs);
        drop(journal);
        self.shared.notify_entry(
            self.task as ActorId,
            EntryKind::FsFsync,
            self.task,
            Some(id),
        );
        Ok(id)
    }

    fn read(&self, path: &str) -> Result<Option<u64>, ledger_journal::JournalError> {
        let mut journal = self.shared.journal.borrow_mut();
        let fs = self.shared.fs.borrow();
        let value = fs.read(&mut journal, self.task as ActorId, path)?;
        self.note_journaled(self.task as ActorId);
        drop(fs);
        drop(journal);
        // The FsRead entry is the actor's head; derive its signature directly.
        let read_id = self
            .shared
            .journal
            .borrow()
            .head_for_actor(self.task as ActorId);
        self.shared
            .notify_entry(self.task as ActorId, EntryKind::FsRead, self.task, read_id);
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
    fn crash_impl(&self) -> Option<Hash> {
        let id = match self.append(
            EntryKind::Fault {
                fault: FaultSpec::CrashState(0),
            },
            [],
            Payload::Empty,
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
        if let Some(message) = self.shared.net.borrow_mut().recv_at(self.task, now) {
            // Record a failed Recv append; the message is already consumed.
            match self.shared.journal_append(
                self.task as ActorId,
                EntryKind::Recv,
                [message.send_id],
                Payload::Number(message.payload),
            ) {
                Ok(id) => {
                    self.shared.notify_entry(
                        self.task as ActorId,
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
            Poll::Ready(message.payload)
        } else {
            // Record a failed Block append; the park still proceeds.
            match self.shared.journal_append(
                self.task as ActorId,
                EntryKind::Block,
                [],
                Payload::Empty,
            ) {
                Ok(id) => {
                    self.shared.notify_entry(
                        self.task as ActorId,
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
