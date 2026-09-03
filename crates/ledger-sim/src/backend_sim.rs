//! Deterministic simulation backend implementing the Effects boundary.

use crate::effects::{Effects, Fs, Net};
use crate::net::{Message, SimNet};
use crate::origin::{OriginLog, OriginSource};
use crate::seedtree::SeedTree;
use crate::simfs::SimFs;
use crate::time::{Clock, VirtualTime};
use core::convert::Infallible;
use ledger_format::{ActorId, EntryHash, EntryKind, EntryPayload, FaultPayload, StreamId};
use ledger_journal::{Journal, JournalError};
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, TryRng};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// Lock a sim mutex, recovering from poisoning so the boundary stays total.
fn lock<T>(guard: &Mutex<T>) -> MutexGuard<'_, T> {
    guard.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Record the first journal-append failure; later failures never overwrite it.
pub(crate) fn record_first_journal_error(slot: &Mutex<Option<JournalError>>, error: &JournalError) {
    let mut guard = slot.lock().unwrap_or_else(PoisonError::into_inner);
    if guard.is_none() {
        *guard = Some(error.clone());
    }
}

/// One deterministic RNG stream; every draw journals one `RngDraw` entry.
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

/// Deterministic simulation backend driving virtual time, seed tree, and journal.
///
/// Interior-mutable behind `Mutex` so shared `Effects` refs can journal; the
/// sim stays single-threaded so the lock is uncontended and `Send + Sync`
/// holds for wasmtime host functions.
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
    rng_streams: BTreeMap<StreamId, SimStreamRng>,
    /// Seed-drawn picks inside the configured reorder window; `false` keeps
    /// the deterministic newest-first window.
    reorder_draw: bool,
    /// Monotonic offset for the `net` seed stream.
    net_offset: Mutex<u64>,
    /// Optional shared tick sink published to WASI virtual clocks.
    tick_sink: Option<Arc<Mutex<u64>>>,
    /// Side channel of effect origins keyed by entry hash. Never serialized
    /// into the journal; see [`crate::origin`].
    origins: Mutex<OriginLog>,
}

impl SimBackend {
    /// Create a new simulation backend from a seed tree for actor 0.
    pub fn new(seed_tree: SeedTree) -> Self {
        Self::for_actor(seed_tree, ActorId(0))
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
            rng_streams: BTreeMap::new(),
            reorder_draw: false,
            net_offset: Mutex::new(0),
            tick_sink: None,
            origins: Mutex::new(OriginLog::default()),
        }
    }

    /// Serve a seeded draw inside the reorder window instead of newest-first.
    pub fn set_reorder_draw(&mut self, reorder_draw: bool) {
        self.reorder_draw = reorder_draw;
    }

    /// Attach a tick sink so WASI clocks serve virtual time.
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

    /// Return an immutable copy of the journaled history.
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
    pub fn origins_snapshot(&self) -> Vec<(EntryHash, OriginSource)> {
        lock(&self.origins).snapshot()
    }

    /// Look up the origin of one journaled entry.
    pub fn origin_of(&self, id: &EntryHash) -> Option<OriginSource> {
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
        parents: impl IntoIterator<Item = EntryHash>,
        payload: EntryPayload,
    ) -> Option<EntryHash> {
        self.append(kind, parents, payload)
    }

    fn append(
        &self,
        kind: EntryKind,
        parents: impl IntoIterator<Item = EntryHash>,
        payload: EntryPayload,
    ) -> Option<EntryHash> {
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
    /// Non-journaled clock read for internal scheduling.
    ///
    /// Journaled reads use `Instruction::ReadClock` (`ClockRead`); WASI
    /// `clock_time_get` journals as an observable crossing.
    fn clock(&self) -> Clock {
        self.publish_ticks();
        Clock::new(lock(&self.time).now())
    }

    fn rng(&mut self, stream: StreamId) -> &mut impl rand_core::Rng {
        // The label and the ChaCha20 derivation run only when the handle is
        // first created; later acquisitions reuse the stored stream.
        self.rng_streams
            .entry(stream)
            .or_insert_with(|| SimStreamRng {
                rng: self.seed_tree.rng(&format!("app/{}", stream.0)),
                journal: Arc::clone(&self.journal),
                journal_error: Arc::clone(&self.journal_error),
                actor: self.actor,
                stream,
            })
    }

    /// Single-actor inline sleep; journals the same timer chain as the
    /// executor batch path (see the sleep-parity test).
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
        time.set_with_enabler(ticks, self.actor.0 as usize, timer_set);
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
        let message = if self.reorder_draw {
            let mut offset = lock(&self.net_offset);
            let draw = |bound: u64| -> u64 {
                let value = self.seed_tree.draw_u64("net", *offset);
                *offset += 1;
                value % bound
            };
            lock(&self.net).recv_at_drawn(task, now, draw)
        } else {
            lock(&self.net).recv_at(task, now)
        }?;
        let id = self.append(
            EntryKind::Recv,
            [message.send_id],
            EntryPayload::Recv(ledger_format::RecvFrame {
                message_id: message.message_id,
                from: ActorId(message.from as u32),
                to: ActorId(task as u32),
                observed_content: message.content.clone(),
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
    fn send_impl(&self, message: Message) -> (bool, Option<EntryHash>) {
        let Some(id) = self.append(
            EntryKind::Send,
            [],
            EntryPayload::Send(ledger_format::SendFrame {
                message_id: message.message_id,
                from: ActorId(message.from as u32),
                to: ActorId(message.to as u32),
                original_content: message.content.clone(),
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
    fn write(&self, path: &str, value: u64) -> Result<EntryHash, crate::effects::FsError> {
        Ok(self.write_impl(path, value)?)
    }

    fn write_loc(
        &self,
        path: &str,
        value: u64,
        at: OriginSource,
    ) -> Result<EntryHash, crate::effects::FsError> {
        let id = self.write_impl(path, value)?;
        lock(&self.origins).record(id, at);
        Ok(id)
    }

    fn fsync(&self) -> Result<EntryHash, crate::effects::FsError> {
        Ok(self.fsync_impl()?)
    }

    fn fsync_loc(&self, at: OriginSource) -> Result<EntryHash, crate::effects::FsError> {
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
    fn write_impl(&self, path: &str, value: u64) -> Result<EntryHash, JournalError> {
        let mut journal = lock(&self.journal);
        let mut fs = lock(&*self.fs);
        fs.write(&mut journal, self.actor, path, value)
    }

    fn fsync_impl(&self) -> Result<EntryHash, JournalError> {
        let mut journal = lock(&self.journal);
        let mut fs = lock(&*self.fs);
        fs.fsync(&mut journal, self.actor)
    }

    /// Write a byte payload at `offset` to `path` in simulated storage,
    /// recording the byte mutation in the journal.
    pub fn fs_write_bytes(
        &self,
        path: &str,
        offset: u64,
        content: Vec<u8>,
    ) -> Result<EntryHash, crate::simfs::SimFsError> {
        let mut journal = lock(&self.journal);
        let mut fs = lock(&*self.fs);
        fs.write_bytes(&mut journal, self.actor, path, offset, content)
    }

    /// Read up to `requested_len` bytes from `offset` at `path` in simulated storage,
    /// journaling the observed bytes with causal provenance parents.
    pub fn fs_read_bytes(
        &self,
        path: &str,
        offset: u64,
        requested_len: u64,
    ) -> Result<ledger_format::ObservedRead, crate::simfs::SimFsError> {
        let mut journal = lock(&self.journal);
        let fs = lock(&*self.fs);
        fs.read_bytes(&mut journal, self.actor, path, offset, requested_len)
    }

    /// Flush all dirty data for `path` to durable state, journaling `FsFsync`.
    pub fn fs_sync_path(&self, path: &str) -> Result<EntryHash, crate::simfs::SimFsError> {
        let mut journal = lock(&self.journal);
        let mut fs = lock(&*self.fs);
        fs.fsync_path(&mut journal, self.actor, path)
    }

    /// Append the crash-fault entry and fold storage into the post-crash
    /// state. Returns the entry id when journaling worked.
    fn crash_impl(&self) -> Option<EntryHash> {
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
        let backend =
            SimBackend::for_actor(SeedTree::new(ledger_format::EntryHash([5; 32])), ActorId(1));
        let mut effects = backend;
        let drawn = effects.rng(StreamId(0)).next_u64();
        assert_ne!(drawn, 0, "seed tree must serve a deterministic draw");

        let now = effects.clock().now();
        let _ = effects.net().send(Message {
            from: 1,
            to: 2,
            content: 42u64.to_le_bytes().to_vec(),
            message_id: ledger_format::MessageId::new(ActorId(1), 0),
            send_id: ledger_format::EntryHash([0; 32]),
            deliver_at: now,
        });
        let write_id = effects.fs().write("k", 7).unwrap();
        let _ = effects.fs().fsync().unwrap();
        futures::executor::block_on(effects.sleep(core::time::Duration::from_micros(10)));

        let journal = effects.journal_snapshot();
        assert!(journal.entries().any(|e| {
            matches!(
                &e.data.payload,
                EntryPayload::RngDraw(ledger_format::RngDrawPayload {
                    stream: StreamId(0),
                    ..
                })
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
        let draws = |other_stream: StreamId, other_count: u32, target_count: u32| -> Vec<u64> {
            let mut backend = SimBackend::new(SeedTree::new(ledger_format::EntryHash([9; 32])));
            for _ in 0..other_count {
                let _ = backend.rng(other_stream).next_u64();
            }
            (0..target_count)
                .map(|_| backend.rng(StreamId(1)).next_u64())
                .collect()
        };

        let sparse = draws(StreamId(0), 1, 3);
        let dense = draws(StreamId(0), 9, 3);
        assert_eq!(
            dense, sparse,
            "stream-1 draws must be identical regardless of stream-0 consumption"
        );
    }

    #[test]
    fn journal_snapshot_matches_live_journal_and_stays_fixed() {
        let mut backend = SimBackend::new(SeedTree::new(ledger_format::EntryHash([11; 32])));
        let _ = backend.rng(StreamId(0)).next_u64();
        let before = backend.journal_snapshot();
        let root_before = before.root_hash();
        assert_eq!(
            before.entries().count(),
            1,
            "one draw must journal exactly one entry"
        );

        // The snapshot is a copy: later appends must not alter it.
        let _ = backend.rng(StreamId(0)).next_u64();
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

    /// Pins the `TimerSet -TimerFire -> Wake` chain shape on both paths.
    #[test]
    fn inline_sleep_matches_quiescent_timer_chain() {
        use ledger_format::EntryPayload;
        let backend = SimBackend::new(SeedTree::new(ledger_format::EntryHash([21; 32])));
        futures::executor::block_on(backend.sleep(core::time::Duration::from_micros(7)));
        let journal = backend.journal_snapshot();
        let kinds = journal
            .entries()
            .map(|entry| entry.data.kind)
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            vec![EntryKind::TimerSet, EntryKind::TimerFire, EntryKind::Wake],
            "inline sleep journals exactly one timer chain"
        );
        let entries: Vec<_> = journal.entries().collect();
        let set_id = entries[0].id;
        let fire_id = entries[1].id;
        match &entries[1].data.payload {
            EntryPayload::TimerFire { .. } => {}
            other => panic!("second entry must be TimerFire, got {other:?}"),
        }
        assert_eq!(
            entries[1].data.parents.as_slice(),
            &[set_id],
            "TimerFire parents the TimerSet enabler"
        );
        assert_eq!(
            entries[2].data.parents.as_slice(),
            &[fire_id],
            "Wake chains the TimerFire"
        );
        match &entries[2].data.payload {
            EntryPayload::Wake(ledger_format::WakePayload::TimerReady { .. }) => {}
            other => panic!("third entry must be TimerReady wake, got {other:?}"),
        }
        assert!(
            JournalCorrectnessMonitor::audit(&journal).is_empty(),
            "timer chain must be causally sound"
        );
        // Executor parity: one sleeping task produces the same chain shape
        // (plus scheduler Spawn/RngDraw framing around it).
        let config = crate::config::RunConfig::builder()
            .seed(ledger_format::EntryHash([21; 32]))
            .max_steps(64)
            .build();
        let run = crate::runtime::Simulation::with_tasks(
            config,
            vec![Box::new(|b: crate::executor::Boundary| {
                Box::pin(async move {
                    b.sleep(core::time::Duration::from_micros(7)).await;
                })
            })],
        )
        .run()
        .expect("executor sleep run");
        let chain: Vec<_> = run
            .journal
            .entries()
            .filter(|entry| {
                matches!(
                    entry.data.kind,
                    EntryKind::TimerSet | EntryKind::TimerFire | EntryKind::Wake
                )
            })
            .collect();
        assert_eq!(chain.len(), 3, "executor journals one timer chain");
        assert_eq!(chain[0].data.kind, EntryKind::TimerSet);
        assert_eq!(chain[1].data.kind, EntryKind::TimerFire);
        assert_eq!(chain[2].data.kind, EntryKind::Wake);
        assert_eq!(chain[1].data.parents.as_slice(), &[chain[0].id]);
        assert_eq!(chain[2].data.parents.as_slice(), &[chain[1].id]);
    }
}
