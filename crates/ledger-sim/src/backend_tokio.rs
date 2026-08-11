//! Production host backend implementing the Effects boundary.
// ledger-lint:allow (production host backend reads ambient time and OS entropy by design)

use crate::effects::{Effects, Fs, Net};
use crate::net::{Message, SimNet};
use crate::simfs::SimFs;
use crate::time::Clock;
use ledger_format::{EntryKind, FaultSpec, Hash, Payload, StreamId};
use ledger_journal::{Journal, JournalError};
use std::cell::RefCell;

/// Production host backend implementing the Effects boundary.
///
/// RECORD-ONLY mode for the network and storage surfaces. `net()` and `fs()`
/// serve the deterministic in-memory scaffolding ([`SimNet`] / [`SimFs`]) and
/// journal every crossing into a throwaway journal; they never touch the
/// ambient host. `clock`, `sleep`, and `rng` do serve the ambient host (wall
/// clock, tokio real time, OS entropy). Real TCP and filesystem passthrough
/// adapters for the `Net` / `Fs` trait shapes are future work; production use
/// must provide its own ambient adapters for those two surfaces.
#[derive(Debug, Default)]
pub struct TokioBackend {
    journal: RefCell<Journal>,
    journal_error: RefCell<Option<JournalError>>,
    net: RefCell<SimNet>,
    fs: RefCell<SimFs>,
    /// Lazily constructed OS-entropy handle.
    entropy: Option<rand_core::UnwrapErr<getrandom::SysRng>>,
}

impl TokioBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the journaled history for inspection.
    pub fn journal(&self) -> &RefCell<Journal> {
        &self.journal
    }

    fn append(
        &self,
        kind: EntryKind,
        parents: impl IntoIterator<Item = Hash>,
        payload: Payload,
    ) -> Option<Hash> {
        match self.journal.borrow_mut().append(kind, 0, parents, payload) {
            Ok(id) => Some(id),
            Err(error) => {
                *self.journal_error.borrow_mut() = Some(error);
                None
            }
        }
    }
}

impl Effects for TokioBackend {
    fn clock(&self) -> Clock {
        Clock::new(self.now_wall_ticks())
    }

    fn rng(&mut self, _stream: StreamId) -> &mut impl rand_core::Rng {
        self.entropy
            .get_or_insert(rand_core::UnwrapErr(getrandom::SysRng))
    }

    async fn sleep(&self, d: core::time::Duration) {
        tokio::time::sleep(d).await;
    }

    fn net(&self) -> &dyn Net {
        self
    }

    fn fs(&self) -> &dyn Fs {
        self
    }
}

impl TokioBackend {
    fn now_wall_ticks(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_micros() as u64)
            .unwrap_or(0)
    }
}

impl Net for TokioBackend {
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
        self.net.borrow_mut().send(Message {
            send_id: id,
            ..message
        })
    }

    fn recv(&self, task: usize, now: u64) -> Option<Message> {
        let message = self.net.borrow_mut().recv_at(task, now)?;
        self.append(
            EntryKind::Recv,
            [message.send_id],
            Payload::Number(message.payload),
        );
        Some(message)
    }

    fn has_ready_message(&self, task: usize, now: u64) -> bool {
        self.net.borrow().has_ready_message(task, now)
    }
}

impl Fs for TokioBackend {
    fn write(&self, path: &str, value: u64) -> Result<Hash, JournalError> {
        let mut journal = self.journal.borrow_mut();
        let mut fs = self.fs.borrow_mut();
        fs.write(&mut journal, 0, path, value)
    }

    fn fsync(&self) -> Result<Hash, JournalError> {
        let mut journal = self.journal.borrow_mut();
        let mut fs = self.fs.borrow_mut();
        fs.fsync(&mut journal, 0)
    }

    fn read(&self, path: &str) -> Result<Option<u64>, JournalError> {
        let mut journal = self.journal.borrow_mut();
        let fs = self.fs.borrow();
        fs.read(&mut journal, 0, path)
    }

    fn crash(&self) {
        self.append(
            EntryKind::Fault {
                fault: FaultSpec::CrashState(0),
            },
            [],
            Payload::Empty,
        );
        self.fs.borrow_mut().crash();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Record-only net/fs crossings are deterministic: two backends performing
    /// the same journaled operations produce byte-identical journals. The
    /// ambient surfaces (`clock`, `sleep`, `rng`) are never touched here.
    #[test]
    fn record_only_net_and_fs_are_deterministic() {
        let run = || {
            let backend = TokioBackend::new();
            let now = 0u64;
            assert!(backend.net().send(Message {
                from: 0,
                to: 1,
                payload: 7,
                send_id: [0; 32],
                deliver_at: now,
            }));
            assert_eq!(backend.net().recv(1, now).map(|m| m.payload), Some(7));
            assert!(backend.fs().write("k", 7).is_ok());
            backend.fs().crash();
            assert_eq!(
                backend.fs().read("k").ok().flatten(),
                None,
                "an unsynced write must be dropped by the crash"
            );
            assert!(backend.fs().write("j", 9).is_ok());
            assert!(backend.fs().fsync().is_ok());
            backend.fs().crash();
            assert_eq!(
                backend.fs().read("j").ok().flatten(),
                Some(9),
                "a synced write must survive the crash"
            );
            backend.journal().borrow().clone()
        };
        let first = run();
        let second = run();
        assert_eq!(
            first.root_hash(),
            second.root_hash(),
            "record-only crossings must journal identically across runs"
        );
        let kinds = first
            .entries()
            .map(|entry| entry.data.kind)
            .collect::<Vec<_>>();
        assert!(kinds.iter().any(|kind| matches!(kind, EntryKind::Send)));
        assert!(kinds.iter().any(|kind| matches!(kind, EntryKind::Recv)));
        assert!(kinds.iter().any(|kind| matches!(kind, EntryKind::FsWrite)));
        assert!(kinds.iter().any(|kind| matches!(kind, EntryKind::FsFsync)));
    }
}
