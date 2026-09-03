//! Production host backend implementing the Effects boundary.
// ledger-lint:allow (production host backend reads ambient time and OS entropy by design)

use crate::effects::{Effects, Fs, Net};
use crate::net::{Message, SimNet};
use crate::simfs::SimFs;
use crate::time::Clock;
use ledger_format::{ActorId, EntryHash, EntryKind, EntryPayload, FaultPayload, StreamId};
use ledger_journal::{Journal, JournalError};
use std::cell::RefCell;
use std::path::{Path, PathBuf};

/// Host-side virtual time and entropy override for deterministic testing.
///
/// `LEDGER_VIRTUAL_TICKS_PATH` virtualizes the clock, `LEDGER_VIRTUAL_SEED_HEX`
/// virtualizes entropy; the `LD_PRELOAD` shim applies the same vars to libc
/// callers so both paths virtualize consistently.
#[derive(Debug, Clone, Default)]
pub struct VirtualOverride {
    /// Path to a file containing virtual time as decimal microseconds.
    pub ticks_path: Option<PathBuf>,
    /// 64 hex chars seeding the deterministic entropy stream.
    pub seed_hex: Option<String>,
}

impl VirtualOverride {
    /// Read the override from the environment.
    ///
    /// Reads `LEDGER_VIRTUAL_TICKS_PATH` and `LEDGER_VIRTUAL_SEED_HEX`. Empty
    /// values are treated as absent. The seed is considered present only when
    /// it contains at least 16 hex digits and all its characters are hex.
    pub fn from_env() -> Self {
        let ticks_path = std::env::var_os("LEDGER_VIRTUAL_TICKS_PATH")
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty());
        let seed_hex = std::env::var("LEDGER_VIRTUAL_SEED_HEX")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .filter(|s| s.len() >= 16 && s.chars().all(|c| c.is_ascii_hexdigit()));
        Self {
            ticks_path,
            seed_hex,
        }
    }
}

/// Deterministic SplitMix64 RNG matching the C shim's `splitmix64_next`.
#[derive(Debug, Clone)]
struct VirtualRng {
    state: u64,
}

impl VirtualRng {
    fn from_hex(seed_hex: &str) -> Option<Self> {
        let hex = seed_hex.trim();
        if hex.len() < 16 {
            return None;
        }
        let mut value = 0u64;
        for ch in hex.chars().take(16) {
            let nib = ch.to_digit(16)? as u64;
            value = (value << 4) | nib;
        }
        Some(Self { state: value })
    }

    fn next_u64_inner(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
}

impl rand_core::TryRng for VirtualRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.next_u64_inner())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        rand_core::utils::fill_bytes_via_next_word(dst, || self.try_next_u64())
    }
}

/// Host RNG that is either OS entropy or a deterministic virtual stream.
#[derive(Debug)]
enum HostRng {
    Sys(rand_core::UnwrapErr<getrandom::SysRng>),
    Virtual(VirtualRng),
}

impl rand_core::TryRng for HostRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        match self {
            Self::Sys(r) => r.try_next_u64(),
            Self::Virtual(r) => r.try_next_u64(),
        }
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        match self {
            Self::Sys(r) => r.try_fill_bytes(dst),
            Self::Virtual(r) => r.try_fill_bytes(dst),
        }
    }
}

/// Virtual clock override failure; keeps its source for diagnosis.
#[derive(Debug)]
enum TickOverrideError {
    /// The override file could not be opened.
    Open(std::io::Error),
    /// Reading from the override file failed mid-stream.
    Read(std::io::Error),
    /// The file filled the whole fixed cap; its true length is unknown.
    Oversized {
        /// Byte cap enforced by the fixed reader.
        cap: usize,
    },
    /// The bytes were not valid UTF-8 text.
    Utf8(std::str::Utf8Error),
    /// The trimmed text is not a decimal u64.
    Parse {
        /// The offending trimmed text, bounded by the read cap.
        text: String,
        source: std::num::ParseIntError,
    },
}

impl std::fmt::Display for TickOverrideError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(e) => write!(f, "open: {e}"),
            Self::Read(e) => write!(f, "read: {e}"),
            Self::Oversized { cap } => write!(f, "content exceeds {cap}-byte cap"),
            Self::Utf8(e) => write!(f, "utf8: {e}"),
            Self::Parse { text, source } => write!(f, "parse '{text}': {source}"),
        }
    }
}

impl std::error::Error for TickOverrideError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Open(e) | Self::Read(e) => Some(e),
            Self::Utf8(e) => Some(e),
            Self::Parse { source, .. } => Some(source),
            Self::Oversized { .. } => None,
        }
    }
}

/// Production host backend: record-only net/fs, ambient clock/sleep/entropy
/// unless a [`VirtualOverride`] is active.
#[derive(Debug)]
pub struct TokioBackend {
    journal: RefCell<Journal>,
    journal_error: RefCell<Option<JournalError>>,
    net: RefCell<SimNet>,
    fs: RefCell<SimFs>,
    entropy: HostRng,
    virtual_override: VirtualOverride,
    /// Set when a virtual override is armed but its input fails to read or
    /// parse. While set, the clock serves the last-known-good tick value (or
    /// zero) and never falls back to ambient time, so the nondeterminism is
    /// observable instead of silent.
    override_error: std::cell::RefCell<Option<String>>,
}

impl Default for TokioBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl TokioBackend {
    pub fn new() -> Self {
        let virtual_override = VirtualOverride::from_env();
        let entropy = match &virtual_override.seed_hex {
            Some(hex) => VirtualRng::from_hex(hex)
                .map(HostRng::Virtual)
                .unwrap_or_else(|| HostRng::Sys(rand_core::UnwrapErr(getrandom::SysRng))),
            None => HostRng::Sys(rand_core::UnwrapErr(getrandom::SysRng)),
        };
        Self {
            journal: RefCell::new(Journal::new()),
            journal_error: RefCell::new(None),
            net: RefCell::new(SimNet::new()),
            fs: RefCell::new(SimFs::new()),
            entropy,
            virtual_override,
            override_error: std::cell::RefCell::new(None),
        }
    }

    /// First virtual-override input failure, if any; the clock holds
    /// last-known-good ticks while set so failure stays observable.
    pub fn virtual_override_error(&self) -> Option<String> {
        self.override_error.borrow().clone()
    }

    /// Return the journaled history for inspection.
    pub fn journal(&self) -> &RefCell<Journal> {
        &self.journal
    }

    fn append(
        &self,
        kind: EntryKind,
        parents: impl IntoIterator<Item = EntryHash>,
        payload: EntryPayload,
    ) -> Option<EntryHash> {
        match self
            .journal
            .borrow_mut()
            .append(kind, ActorId(0), parents, payload)
        {
            Ok(id) => Some(id),
            Err(error) => {
                // First-wins, matching the executor slot contract: the first
                // broken append is the one that invalidates the run.
                let mut slot = self.journal_error.borrow_mut();
                if slot.is_none() {
                    *slot = Some(error);
                }
                None
            }
        }
    }

    /// Read the virtual tick override, capped at 256 bytes per the C shim contract.
    ///
    /// # Errors
    /// Returns the typed override error with its source preserved.
    fn read_virtual_micros(path: &Path) -> Result<u64, TickOverrideError> {
        let file = std::fs::File::open(path).map_err(TickOverrideError::Open)?;
        let mut raw = [0u8; 256];
        let mut reader = std::io::BufReader::new(file);
        use std::io::Read;
        let n = reader.read(&mut raw).map_err(TickOverrideError::Read)?;
        if n == 256 {
            return Err(TickOverrideError::Oversized { cap: raw.len() });
        }
        let text = std::str::from_utf8(&raw[..n]).map_err(TickOverrideError::Utf8)?;
        let value = text
            .trim()
            .parse::<u64>()
            .map_err(|source| TickOverrideError::Parse {
                text: text.trim().to_string(),
                source,
            })?;
        Ok(value)
    }

    fn now_wall_ticks(&self) -> u64 {
        if let Some(path) = self.virtual_override.ticks_path.as_ref() {
            return match Self::read_virtual_micros(path) {
                Ok(micros) => micros,
                Err(reason) => {
                    let message = format!("ticks file {}: {reason}", path.display());
                    let mut slot = self.override_error.borrow_mut();
                    if slot.is_none() {
                        *slot = Some(message);
                    }
                    // Hold at the last-known-good value (zero here) rather
                    // than serving ambient time while an override is armed.
                    0
                }
            };
        }
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_micros() as u64)
            // Documented default: a clock before the epoch (clock skew) falls
            // back to zero ticks; this is a host ambient backend.
            .unwrap_or(0)
    }
}

impl Effects for TokioBackend {
    fn clock(&self) -> Clock {
        Clock::new(self.now_wall_ticks())
    }

    fn rng(&mut self, _stream: StreamId) -> &mut impl rand_core::Rng {
        &mut self.entropy
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

impl Net for TokioBackend {
    fn send(&self, message: Message) -> bool {
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
            EntryPayload::Recv(ledger_format::RecvFrame {
                message_id: message.message_id,
                from: ActorId(message.from as u32),
                to: ActorId(task as u32),
                observed_content: message.content.clone(),
            }),
        );
        Some(message)
    }

    fn has_ready_message(&self, task: usize, now: u64) -> bool {
        self.net.borrow().has_ready_message(task, now)
    }
}

impl Fs for TokioBackend {
    fn write(&self, path: &str, value: u64) -> Result<EntryHash, crate::effects::FsError> {
        let mut journal = self.journal.borrow_mut();
        let mut fs = self.fs.borrow_mut();
        Ok(fs.write(&mut journal, ActorId(0), path, value)?)
    }

    fn fsync(&self) -> Result<EntryHash, crate::effects::FsError> {
        let mut journal = self.journal.borrow_mut();
        let mut fs = self.fs.borrow_mut();
        Ok(fs.fsync(&mut journal, ActorId(0))?)
    }

    fn read(&self, path: &str) -> Result<Option<u64>, crate::effects::FsError> {
        let mut journal = self.journal.borrow_mut();
        let fs = self.fs.borrow();
        Ok(fs.read(&mut journal, ActorId(0), path)?)
    }

    fn crash(&self) {
        self.append(
            EntryKind::Fault,
            [],
            EntryPayload::Fault(FaultPayload::CrashActor {
                actor: ActorId(0),
                crash_operation: ledger_format::CrashOperation::DropAllUnsynced,
            }),
        );
        self.fs.borrow_mut().crash();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    /// Record-only net/fs crossings journal identically across runs.
    #[test]
    fn record_only_net_and_fs_are_deterministic() {
        let run = || {
            let backend = TokioBackend::new();
            let now = 0u64;
            assert!(backend.net().send(Message {
                from: 0,
                to: 1,
                content: 7u64.to_le_bytes().to_vec(),
                message_id: ledger_format::MessageId::new(ActorId(0), 0),
                send_id: ledger_format::EntryHash([0; 32]),
                deliver_at: now,
            }));
            assert_eq!(backend.net().recv(1, now).map(|m| m.payload()), Some(7));
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

    fn unique_temp_file(tag: &str) -> std::path::PathBuf {
        let name = format!(
            "ldgr-tick-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        std::env::temp_dir().join(name)
    }

    /// Missing file surfaces as typed `Open` with its source.
    #[test]
    fn tick_override_open_failure_is_typed_with_source() {
        let missing = unique_temp_file("missing");
        let err = TokioBackend::read_virtual_micros(&missing).unwrap_err();
        assert!(matches!(err, TickOverrideError::Open(_)), "got {err:?}");
        assert!(err.source().is_some(), "io source must stay in the chain");
    }

    /// Full-cap file surfaces as typed oversized, not a parse attempt.
    #[test]
    fn tick_override_oversized_is_typed() {
        let path = unique_temp_file("oversized");
        std::fs::write(&path, "1".repeat(512)).expect("write oversized file");
        let err = TokioBackend::read_virtual_micros(&path).unwrap_err();
        assert!(
            matches!(err, TickOverrideError::Oversized { cap: 256 }),
            "got {err:?}"
        );
        assert!(
            err.to_string().contains("256"),
            "display must cite the cap: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Non-UTF-8 bytes surface as typed utf8 with source preserved.
    #[test]
    fn tick_override_invalid_utf8_is_typed() {
        let path = unique_temp_file("utf8");
        std::fs::write(&path, [0xffu8, 0xfe]).expect("write raw bytes");
        let err = TokioBackend::read_virtual_micros(&path).unwrap_err();
        assert!(matches!(err, TickOverrideError::Utf8(_)), "got {err:?}");
        assert!(err.source().is_some(), "utf8 source must stay in the chain");
        let _ = std::fs::remove_file(&path);
    }

    /// Non-numeric text surfaces as typed parse with text and source.
    #[test]
    fn tick_override_parse_failure_is_typed_with_source() {
        let path = unique_temp_file("parse");
        std::fs::write(&path, b"not-a-number").expect("write text");
        let err = TokioBackend::read_virtual_micros(&path).unwrap_err();
        match &err {
            TickOverrideError::Parse { text, source } => {
                assert_eq!(text, "not-a-number");
                assert!(
                    source.to_string().contains("invalid digit"),
                    "source must be the ParseIntError: {source}"
                );
            }
            other => panic!("expected Parse, got {other:?}"),
        }
        assert!(
            err.to_string().contains("not-a-number"),
            "display must cite the text: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Valid decimal micros still parse.
    #[test]
    fn tick_override_valid_value_parses() {
        let path = unique_temp_file("valid");
        std::fs::write(&path, b"  12345  ").expect("write text");
        assert_eq!(TokioBackend::read_virtual_micros(&path).unwrap(), 12345);
        let _ = std::fs::remove_file(&path);
    }
}
