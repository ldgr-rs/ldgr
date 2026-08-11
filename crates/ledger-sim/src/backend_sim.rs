//! Deterministic simulation backend implementing the Effects boundary.

use crate::effects::{Effects, Fs, Net};
use crate::net::{Message, SimNet};
use crate::seedtree::SeedTree;
use crate::simfs::SimFs;
use crate::time::{Clock, VirtualTime};
use core::convert::Infallible;
use ledger_format::{ActorId, EntryKind, FaultSpec, Hash, Payload, StreamId};
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
            EntryKind::RngDraw {
                stream: self.stream,
            },
            self.actor,
            [],
            Payload::Number(value),
        ) {
            Ok(_) => {}
            Err(error) => {
                *lock(&self.journal_error) = Some(error);
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
    journal: Arc<Mutex<Journal>>,
    journal_error: Arc<Mutex<Option<JournalError>>>,
    net: Mutex<SimNet>,
    fs: Mutex<SimFs>,
    actor: ActorId,
    rng_streams: Vec<Option<SimStreamRng>>,
    /// Optional shared tick sink published to WASI virtual clocks.
    tick_sink: Option<Arc<Mutex<u64>>>,
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
            fs: Mutex::new(SimFs::new()),
            actor,
            rng_streams: Vec::new(),
            tick_sink: None,
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

    /// Return the journaled history for inspection.
    pub fn journal(&self) -> &Arc<Mutex<Journal>> {
        &self.journal
    }

    /// Return the first journaling failure recorded through the boundary, if any.
    pub fn journal_error(&self) -> Option<JournalError> {
        lock(&self.journal_error).clone()
    }

    /// Return the actor id this backend journals entries for.
    pub fn actor(&self) -> ActorId {
        self.actor
    }

    /// Return the shared journaling error slot.
    ///
    /// Wasm boundary crossings journal through the same slot, so a failure
    /// recorded by a WASI host call surfaces through [`Self::journal_error`].
    pub fn journal_error_slot(&self) -> &Arc<Mutex<Option<JournalError>>> {
        &self.journal_error
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
        payload: Payload,
    ) -> Option<Hash> {
        self.append(kind, parents, payload)
    }

    fn append(
        &self,
        kind: EntryKind,
        parents: impl IntoIterator<Item = Hash>,
        payload: Payload,
    ) -> Option<Hash> {
        match lock(&self.journal).append(kind, self.actor, parents, payload) {
            Ok(id) => Some(id),
            Err(error) => {
                *lock(&self.journal_error) = Some(error);
                None
            }
        }
    }
}

impl Effects for SimBackend {
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
        let timer_set = self.append(EntryKind::TimerSet, [], Payload::Number(ticks));
        let mut time = lock(&self.time);
        time.set_with_enabler(ticks, self.actor as usize, timer_set);
        for fired in time.advance_with_enablers() {
            let parents = fired.enabler.into_iter().collect::<Vec<_>>();
            if let Some(timer_fire) = self.append(EntryKind::TimerFire, parents, Payload::Empty) {
                self.append(EntryKind::Wake, [timer_fire], Payload::Empty);
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
        let Some(id) = self.append(
            EntryKind::Send,
            [],
            Payload::Pair {
                left: message.to as u64,
                right: message.payload,
            },
        ) else {
            return false;
        };
        lock(&self.net).send(Message {
            send_id: id,
            ..message
        })
    }

    fn recv(&self, task: usize, now: u64) -> Option<Message> {
        let message = lock(&self.net).recv_at(task, now)?;
        self.append(
            EntryKind::Recv,
            [message.send_id],
            Payload::Number(message.payload),
        );
        Some(message)
    }

    fn has_ready_message(&self, task: usize, now: u64) -> bool {
        lock(&self.net).has_ready_message(task, now)
    }
}

impl Fs for SimBackend {
    fn write(&self, path: &str, value: u64) -> Result<Hash, JournalError> {
        let mut journal = lock(&self.journal);
        let mut fs = lock(&self.fs);
        fs.write(&mut journal, self.actor, path, value)
    }

    fn fsync(&self) -> Result<Hash, JournalError> {
        let mut journal = lock(&self.journal);
        let mut fs = lock(&self.fs);
        fs.fsync(&mut journal, self.actor)
    }

    fn read(&self, path: &str) -> Result<Option<u64>, JournalError> {
        let mut journal = lock(&self.journal);
        let fs = lock(&self.fs);
        fs.read(&mut journal, self.actor, path)
    }

    fn crash(&self) {
        self.append(
            EntryKind::Fault {
                fault: FaultSpec::CrashState(0),
            },
            [],
            Payload::Empty,
        );
        lock(&self.fs).crash();
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

        let journal = effects.journal().lock().unwrap();
        let kinds = journal.entries().map(|e| e.data.kind).collect::<Vec<_>>();
        assert!(
            kinds
                .iter()
                .any(|k| matches!(k, EntryKind::RngDraw { stream: 0 }))
        );
        assert!(kinds.iter().any(|k| matches!(k, EntryKind::Send)));
        assert!(kinds.iter().any(|k| matches!(k, EntryKind::FsWrite)));
        assert!(kinds.iter().any(|k| matches!(k, EntryKind::FsFsync)));
        assert!(kinds.iter().any(|k| matches!(k, EntryKind::TimerSet)));
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
}
