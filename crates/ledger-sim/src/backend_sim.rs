//! Deterministic simulation backend implementing the Effects boundary.

use crate::effects::{Effects, Fs, Net};
use crate::net::{Message, SimNet};
use crate::origin::{OriginLog, OriginSource};
use crate::seedtree::SeedTree;
use crate::simfs::SimFs;
use crate::time::{Clock, VirtualTime};
use core::convert::Infallible;
use ledger_format::{ActorId, EntryKind, EntryPayload, FaultPayload, Hash, MessageId, StreamId};
use ledger_journal::{Journal, JournalError};
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, TryRng};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// Lock a simulation-owned mutex, recovering the value from a poisoned lock.
///
/// The simulator is single-threaded, so a poisoned lock cannot occur in
/// practice. Recovering the inner value keeps the boundary total even if a
/// panic ever interrupts a host call.
fn lock<T>(guard: &Mutex<T>) -> MutexGuard<'_, T> {
    guard.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Record the first journal-append failure into a shared slot.
///
/// Later failures never overwrite the first: the same first-wins contract as
/// the executor's `ExecutorShared::record_journal_error`, so every backend
/// reports the failure that first broke the run.
pub(crate) fn record_first_journal_error(slot: &Mutex<Option<JournalError>>, error: &JournalError) {
    let mut guard = slot.lock().unwrap_or_else(PoisonError::into_inner);
    if guard.is_none() {
        *guard = Some(error.clone());
    }
}

/// One deterministic RNG stream handle owning its ChaCha20 stream.
///
/// The handle holds the same journal and error slot as the backend, so every
/// draw journals exactly one `RngDraw` entry. Each (backend, stream) owns an
/// independent stream, so draws in one stream never perturb another.
pub struct SimStreamRng {
    rng: ChaCha20Rng,
    journal: Arc<Mutex<Journal>>,
    journal_error: Arc<Mutex<Option<JournalError>>>,
    actor: ActorId,
    stream: StreamId,
}

impl SimStreamRng {
    /// Journal one `RngDraw` entry, recording the first failure if any.
    fn append_draw(&self, value: u64) {
        match lock(&self.journal).append(
            EntryKind::RngDraw,
            self.actor,
            [],
            EntryPayload::RngDraw(ledger_format::RngDrawPayload {
                stream: self.stream,
                draw_index: 0,
                content: value.to_le_bytes().to_vec(),
            }),
        ) {
            Ok(_) => {}
            Err(error) => {
                record_first_journal_error(&self.journal_error, &error);
            }
        }
    }
}

impl TryRng for SimStreamRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let value = self.rng.next_u64();
        self.append_draw(value);
        Ok(value)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        rand_core::utils::fill_bytes_via_next_word(dst, || self.try_next_u64())
    }
}

/// Deterministic simulation backend driving discrete virtual time, the seed
/// tree, and the causal journal.
///
/// The journal, network, and storage state are interior-mutable so the
/// shared-reference `Effects` methods can journal and mutate them. All mutable
/// state sits behind a `Mutex`: the sim is single-threaded, so the mutex is
/// never contended, and `SimBackend` stays `Send + Sync`, which wasmtime host
/// functions require when the backend is stored inside a wasmtime `Store`.
pub struct SimBackend {
    time: Mutex<VirtualTime>,
    seed_tree: SeedTree,
    /// Crate-internal: the Wasm backend attaches its WASI crossings to this
    /// journal and error slot. Keep the mutexes opaque; external inspection
    /// goes through [`Self::journal_snapshot`] and [`Self::journal_error`].
    pub(crate) journal: Arc<Mutex<Journal>>,
    pub(crate) journal_error: Arc<Mutex<Option<JournalError>>>,
    net: Mutex<SimNet>,
    fs: Arc<Mutex<SimFs>>,
    actor: ActorId,
    rng_streams: Vec<Option<SimStreamRng>>,
    /// Optional shared tick sink published to WASI virtual clocks.
    tick_sink: Option<Arc<Mutex<u64>>>,
    /// Side channel of effect origins keyed by entry hash. Never serialized
    /// into the journal; see [`crate::origin`].
    origins: Mutex<OriginLog>,
}

impl SimBackend {
    /// Create a new simulation backend from a seed tree for actor 0.
    pub fn new(seed_tree: SeedTree) -> Self {
        Self::for_actor(seed_tree, 0)
    }

    /// Create a new simulation backend for a specific SUT actor.
    pub fn for_actor(seed_tree: SeedTree, actor: ActorId) -> Self {
        Self {
            time: Mutex::new(VirtualTime::default()),
            seed_tree,
            journal: Arc::new(Mutex::new(Journal::new())),
            journal_error: Arc::new(Mutex::new(None)),
            net: Mutex::new(SimNet::new()),
            fs: Arc::new(Mutex::new(SimFs::new())),
            actor,
            rng_streams: Vec::new(),
            tick_sink: None,
            origins: Mutex::new(OriginLog::default()),
        }
    }

    /// Attach a shared tick sink updated on every clock read and time advance.
    ///
    /// WASI virtual clocks in the Wasm backend read this sink so `clock_time_get`
    /// serves virtual time rather than the ambient wall clock.
    pub fn attach_tick_sink(&mut self, sink: Arc<Mutex<u64>>) {
        self.tick_sink = Some(sink);
    }

    /// Publish the current virtual time to the attached sink, if any.
    fn publish_ticks(&self) {
        if let Some(sink) = &self.tick_sink {
            let now = lock(&self.time).now();
            *lock(sink) = now;
        }
    }

    /// Return an immutable snapshot of the journaled history.
    ///
    /// The snapshot is a full copy taken under the internal lock, so it cannot
    /// alias live backend state and never changes the run. Inspection paths
    /// (entry iteration, `root_hash`, audits) use this instead of locking the
    /// shared journal.
    pub fn journal_snapshot(&self) -> Journal {
        lock(&self.journal).clone()
    }

    /// Return the first journaling failure recorded through the boundary, if any.
    pub fn journal_error(&self) -> Option<JournalError> {
        lock(&self.journal_error).clone()
    }

    /// Return the actor id this backend journals entries for.
    pub fn actor(&self) -> ActorId {
        self.actor
    }

    /// Snapshot the captured effect origins in append order.
    pub fn origins_snapshot(&self) -> Vec<(Hash, OriginSource)> {
        lock(&self.origins).snapshot()
    }

    /// Look up the origin of one journaled entry.
    pub fn origin_of(&self, id: &Hash) -> Option<OriginSource> {
        lock(&self.origins).get(id).cloned()
    }

    /// Append an entry through this backend's journaling path.
    ///
    /// The Wasm backend journals WASI crossings (`random_get`, `clock_time_get`)
    /// through this path so their entries land in the same causal DAG the
    /// native boundary writes. Returns the entry id, or None on failure.
    pub fn journal_append(
        &self,
        kind: EntryKind,
        parents: impl IntoIterator<Item = Hash>,
        payload: EntryPayload,
    ) -> Option<Hash> {
        self.append(kind, parents, payload)
    }

    fn append(
        &self,
        kind: EntryKind,
        parents: impl IntoIterator<Item = Hash>,
        payload: EntryPayload,
    ) -> Option<Hash> {
        match lock(&self.journal).append(kind, self.actor, parents, payload) {
            Ok(id) => Some(id),
            Err(error) => {
                record_first_journal_error(&self.journal_error, &error);
                None
            }
        }
    }
}

impl Effects for SimBackend {
    /// Returns virtual time without journaling.
    ///
    /// `clock()` is a non-journaled read for internal scheduling (e.g. send
    /// `deliver_at`). Journaled reads use `Instruction::ReadClock` or
    /// `Boundary::read_clock`, which emit `ClockRead`. This keeps sends
    /// byte-identical to the pre-journaling path. WASI `clock_time_get` in
    /// `WasmBackend` journals `ClockRead` because it is an observable
    /// cross-boundary effect; the two surfaces are intentionally distinct.
    fn clock(&self) -> Clock {
        self.publish_ticks();
        Clock::new(lock(&self.time).now())
    }

    fn rng(&mut self, stream: StreamId) -> &mut impl rand_core::Rng {
        let idx = stream as usize;
        while self.rng_streams.len() <= idx {
            self.rng_streams.push(None);
        }
        // The label and the ChaCha20 derivation run only when the handle is
        // first created; later acquisitions reuse the stored stream.
        self.rng_streams[idx].get_or_insert_with(|| SimStreamRng {
            rng: self.seed_tree.rng(&format!("app/{stream}")),
            journal: Arc::clone(&self.journal),
            journal_error: Arc::clone(&self.journal_error),
            actor: self.actor,
            stream,
        })
    }

    async fn sleep(&self, d: core::time::Duration) {
        let ticks = d.as_micros() as u64;
        let timer_set = self.append(
            EntryKind::TimerSet,
            [],
            EntryPayload::TimerSet {
                timer_id: 0,
                deadline_ticks: ticks,
            },
        );
        let mut time = lock(&self.time);
        time.set_with_enabler(ticks, self.actor as usize, timer_set);
        for fired in time.advance_with_enablers() {
            let parents = fired.enabler.into_iter().collect::<Vec<_>>();
            if let Some(timer_fire) = self.append(
                EntryKind::TimerFire,
                parents,
                EntryPayload::TimerFire {
                    timer_id: 0,
                    deadline_ticks: 0,
                },
            ) {
                self.append(
                    EntryKind::Wake,
                    [timer_fire],
                    EntryPayload::Wake(ledger_format::WakePayload::TimerReady { timer_id: 0 }),
                );
            }
        }
        drop(time);
        self.publish_ticks();
    }

    fn net(&self) -> &dyn Net {
        self
    }

    fn fs(&self) -> &dyn Fs {
        self
    }
}

impl Net for SimBackend {
    fn send(&self, message: Message) -> bool {
        self.send_impl(message).0
    }

    fn send_loc(&self, message: Message, at: OriginSource) -> bool {
        let (delivered, id) = self.send_impl(message);
        if let Some(id) = id {
            lock(&self.origins).record(id, at);
        }
        delivered
    }

    fn recv(&self, task: usize, now: u64) -> Option<Message> {
        let message = lock(&self.net).recv_at(task, now)?;
        let id = self.append(
            EntryKind::Recv,
            [message.send_id],
            EntryPayload::Recv(ledger_format::RecvFrame {
                // CONSUMER DEBT (lane 2): real message identity.
                message_id: MessageId::new(message.from as ActorId, message.payload),
                from: message.from as ActorId,
                to: task as ActorId,
                observed_content: message.payload.to_le_bytes().to_vec(),
            }),
        );
        // Clone the origin out before re-locking: the guard from `get` lives
        // to the end of the statement, and the mutex is not reentrant.
        let inherited = lock(&self.origins).get(&message.send_id).cloned();
        if let (Some(id), Some(origin)) = (id, inherited) {
            lock(&self.origins).record(id, origin);
        }
        Some(message)
    }

    fn has_ready_message(&self, task: usize, now: u64) -> bool {
        lock(&self.net).has_ready_message(task, now)
    }
}

impl SimBackend {
    /// Append the Send entry and hand the message to the simulated network.
    /// Returns delivery status plus the Send entry id when journaling worked.
    fn send_impl(&self, message: Message) -> (bool, Option<Hash>) {
        let Some(id) = self.append(
            EntryKind::Send,
            [],
            EntryPayload::Send(ledger_format::SendFrame {
                // CONSUMER DEBT (lane 2): real message identity.
                message_id: MessageId::new(message.from as ActorId, message.payload),
                from: message.from as ActorId,
                to: message.to as ActorId,
                original_content: message.payload.to_le_bytes().to_vec(),
            }),
        ) else {
            return (false, None);
        };
        let delivered = lock(&self.net).send(Message {
            send_id: id,
            ..message
        });
        (delivered, Some(id))
    }
}

impl Fs for SimBackend {
    fn write(&self, path: &str, value: u64) -> Result<Hash, crate::effects::FsError> {
        Ok(self.write_impl(path, value)?)
    }

    fn write_loc(
        &self,
        path: &str,
        value: u64,
        at: OriginSource,
    ) -> Result<Hash, crate::effects::FsError> {
        let id = self.write_impl(path, value)?;
        lock(&self.origins).record(id, at);
        Ok(id)
    }

    fn fsync(&self) -> Result<Hash, crate::effects::FsError> {
        Ok(self.fsync_impl()?)
    }

    fn fsync_loc(&self, at: OriginSource) -> Result<Hash, crate::effects::FsError> {
        let id = self.fsync_impl()?;
        lock(&self.origins).record(id, at);
        Ok(id)
    }

    fn read(&self, path: &str) -> Result<Option<u64>, crate::effects::FsError> {
        let mut journal = lock(&self.journal);
        let fs = lock(&*self.fs);
        Ok(fs.read(&mut journal, self.actor, path)?)
    }

    fn crash(&self) {
        self.crash_impl();
    }

    fn crash_loc(&self, at: OriginSource) {
        if let Some(id) = self.crash_impl() {
            lock(&self.origins).record(id, at);
        }
    }
}

impl SimBackend {
    fn write_impl(&self, path: &str, value: u64) -> Result<Hash, JournalError> {
        let mut journal = lock(&self.journal);
        let mut fs = lock(&*self.fs);
        fs.write(&mut journal, self.actor, path, value)
    }

    fn fsync_impl(&self) -> Result<Hash, JournalError> {
        let mut journal = lock(&self.journal);
        let mut fs = lock(&*self.fs);
        fs.fsync(&mut journal, self.actor)
    }

    /// Append the crash-fault entry and fold storage into the post-crash
    /// state. Returns the entry id when journaling worked.
    fn crash_impl(&self) -> Option<Hash> {
        let id = self.append(
            EntryKind::Fault,
            [],
            EntryPayload::Fault(FaultPayload::CrashActor {
                actor: self.actor,
                crash_operation: ledger_format::CrashOperation::DropAllUnsynced,
            }),
        );
        lock(&*self.fs).crash();
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::effects::Effects;
    use ledger_format::EntryKind;
    use ledger_journal::JournalCorrectnessMonitor;
    use rand_core::Rng;

    #[test]
    fn effects_boundary_journals_a_tiny_sut() {
        let backend = SimBackend::for_actor(SeedTree::new([5; 32]), 1);
        let mut effects = backend;
        let drawn = effects.rng(0).next_u64();
        assert_ne!(drawn, 0, "seed tree must serve a deterministic draw");

        let now = effects.clock().now();
        let _ = effects.net().send(Message {
            from: 1,
            to: 2,
            payload: 42,
            send_id: [0; 32],
            deliver_at: now,
        });
        let write_id = effects.fs().write("k", 7).unwrap();
        let _ = effects.fs().fsync().unwrap();
        futures::executor::block_on(effects.sleep(core::time::Duration::from_micros(10)));

        let journal = effects.journal_snapshot();
        assert!(journal.entries().any(|e| {
            matches!(
                &e.data.payload,
                EntryPayload::RngDraw(ledger_format::RngDrawPayload { stream: 0, .. })
            )
        }));
        assert!(journal.entries().any(|e| e.data.kind == EntryKind::Send));
        assert!(journal.entries().any(|e| e.data.kind == EntryKind::FsWrite));
        assert!(journal.entries().any(|e| e.data.kind == EntryKind::FsFsync));
        assert!(
            journal
                .entries()
                .any(|e| e.data.kind == EntryKind::TimerSet)
        );
        assert!(journal.get(&write_id).is_some());
        assert!(
            JournalCorrectnessMonitor::audit(&journal).is_empty(),
            "boundary-journaled run must be causally sound"
        );
        assert!(effects.journal_error().is_none());
    }

    #[test]
    fn app_streams_are_independent_in_sim_backend() {
        let draws = |other_stream: u32, other_count: u32, target_count: u32| -> Vec<u64> {
            let mut backend = SimBackend::new(SeedTree::new([9; 32]));
            for _ in 0..other_count {
                let _ = backend.rng(other_stream).next_u64();
            }
            (0..target_count)
                .map(|_| backend.rng(1).next_u64())
                .collect()
        };

        let sparse = draws(0, 1, 3);
        let dense = draws(0, 9, 3);
        assert_eq!(
            dense, sparse,
            "stream-1 draws must be identical regardless of stream-0 consumption"
        );
    }

    #[test]
    fn journal_snapshot_matches_live_journal_and_stays_fixed() {
        let mut backend = SimBackend::new(SeedTree::new([11; 32]));
        let _ = backend.rng(0).next_u64();
        let before = backend.journal_snapshot();
        let root_before = before.root_hash();
        assert_eq!(
            before.entries().count(),
            1,
            "one draw must journal exactly one entry"
        );

        // The snapshot is a copy: later appends must not alter it.
        let _ = backend.rng(0).next_u64();
        let after = backend.journal_snapshot();
        assert_eq!(
            before.root_hash(),
            root_before,
            "snapshot must be immutable"
        );
        assert_eq!(
            before.entries().count(),
            1,
            "snapshot must not grow with the live journal"
        );
        assert_eq!(
            after.root_hash(),
            lock(&backend.journal).root_hash(),
            "snapshot must match the live journal root"
        );
        assert_eq!(after.entries().count(), 2);
        assert!(backend.journal_error().is_none());
    }
}
