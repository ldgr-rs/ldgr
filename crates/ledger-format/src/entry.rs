//! Journal entry taxonomy, identifiers, and canonical encoding.

use alloc::string::String;
use alloc::vec::Vec;

use crate::cbor::{self, CborError, CborValue};

/// Stable actor identifier.
pub type ActorId = u32;

/// Stable stream identifier for deterministic randomness.
pub type StreamId = u32;

/// Generator identifier for the PBT input axis.
pub type GenId = u64;

/// Replay key for the PBT input axis.
pub type InputKey = u64;

/// A 32-byte BLAKE3 content address.
pub type Hash = [u8; 32];

/// A fault injected by the explorer into a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FaultSpec {
    /// Drops a message in flight.
    Drop,
    /// Delays a message for a fixed number of ticks.
    Delay {
        /// Delay duration in virtual time ticks.
        ticks: u64,
    },
    /// Cuts the link between two actors.
    Partition { src: ActorId, dst: ActorId },
    /// Crashes the actor.
    Crash,
    /// Corrupts a stored record.
    Corrupt,
    /// Crashes storage into a specific post-crash state index.
    CrashState(u64),
}

/// Journal event kinds defined by the Ledger specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntryKind {
    // Scheduling & time
    Spawn,
    Block,
    Wake,
    TimerSet,
    TimerFire,
    ClockRead,
    // Messaging
    Send,
    Recv,
    // Storage
    FsWrite,
    FsFsync,
    FsRead,
    // Randomness
    RngDraw {
        /// Deterministic randomness stream drawn from.
        stream: StreamId,
    },
    // Outcomes & structure
    Outcome,
    Assert,
    Snapshot,
    Epoch,
    // Input axis (PBT-in-sim)
    InputStep {
        /// Workload generator identity.
        generator: GenId,
        /// Replay key of the drawn input.
        replay: InputKey,
    },
    // Capability lifecycle
    CapRequest,
    CapGrant,
    CapInvoke,
    CapRevoke,
    // Faults injected by the explorer
    Fault {
        fault: FaultSpec,
    },
    // Durable execution steps
    StepBegin,
    StepEnd,
}

impl EntryKind {
    /// Returns the stable numeric wire tag for this kind.
    ///
    /// Tags are dense in 0..=23. A structured kind encodes its fields
    /// immediately after the tag; see [`EntryKind::encode_kind`].
    pub const fn tag(self) -> u64 {
        match self {
            Self::Spawn => 0,
            Self::Block => 1,
            Self::Wake => 2,
            Self::TimerSet => 3,
            Self::TimerFire => 4,
            Self::ClockRead => 5,
            Self::Send => 6,
            Self::Recv => 7,
            Self::FsWrite => 8,
            Self::FsFsync => 9,
            Self::FsRead => 10,
            Self::RngDraw { .. } => 11,
            Self::Outcome => 12,
            Self::Assert => 13,
            Self::Snapshot => 14,
            Self::Epoch => 15,
            Self::InputStep { .. } => 16,
            Self::CapRequest => 17,
            Self::CapGrant => 18,
            Self::CapInvoke => 19,
            Self::CapRevoke => 20,
            Self::Fault { .. } => 21,
            Self::StepBegin => 22,
            Self::StepEnd => 23,
        }
    }

    /// Appends the canonical kind encoding as one CBOR item.
    ///
    /// A unit kind encodes as `unsigned(tag)`. A structured kind encodes as an
    /// array whose first element is `unsigned(tag)` followed by its fields:
    ///
    /// - `RngDraw { stream }`: `array(2)`, `unsigned(tag)`, `unsigned(stream)`.
    /// - `InputStep { generator, replay }`: `array(3)`, `unsigned(tag)`,
    ///   `unsigned(generator)`, `unsigned(replay)`.
    /// - `Fault { fault }`: `array(2)`, `unsigned(tag)`, then the fault item
    ///   encoded by [`FaultSpec::encode_fault`].
    fn encode_kind(&self, out: &mut Vec<u8>) {
        match self {
            Self::RngDraw { stream } => {
                cbor::array(out, 2);
                cbor::unsigned(out, self.tag());
                cbor::unsigned(out, *stream as u64);
            }
            Self::InputStep { generator, replay } => {
                cbor::array(out, 3);
                cbor::unsigned(out, self.tag());
                cbor::unsigned(out, *generator);
                cbor::unsigned(out, *replay);
            }
            Self::Fault { fault } => {
                cbor::array(out, 2);
                cbor::unsigned(out, self.tag());
                fault.encode_fault(out);
            }
            _ => cbor::unsigned(out, self.tag()),
        }
    }
}

impl FaultSpec {
    /// Appends the canonical fault encoding as one CBOR item.
    ///
    /// - `Drop`: `unsigned(0)`.
    /// - `Delay { ticks }`: `array(2)`, `unsigned(1)`, `unsigned(ticks)`.
    /// - `Partition { src, dst }`: `array(3)`, `unsigned(2)`, `unsigned(src)`,
    ///   `unsigned(dst)`.
    /// - `Crash`: `unsigned(3)`.
    /// - `Corrupt`: `unsigned(4)`.
    /// - `CrashState(k)`: `array(2)`, `unsigned(5)`, `unsigned(k)`.
    fn encode_fault(&self, out: &mut Vec<u8>) {
        match self {
            Self::Drop => cbor::unsigned(out, 0),
            Self::Delay { ticks } => {
                cbor::array(out, 2);
                cbor::unsigned(out, 1);
                cbor::unsigned(out, *ticks);
            }
            Self::Partition { src, dst } => {
                cbor::array(out, 3);
                cbor::unsigned(out, 2);
                cbor::unsigned(out, *src as u64);
                cbor::unsigned(out, *dst as u64);
            }
            Self::Crash => cbor::unsigned(out, 3),
            Self::Corrupt => cbor::unsigned(out, 4),
            Self::CrashState(state) => {
                cbor::array(out, 2);
                cbor::unsigned(out, 5);
                cbor::unsigned(out, *state);
            }
        }
    }
}

/// Structured payload for a journal entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    Empty,
    Number(u64),
    Signed(i64),
    Text(String),
    Bytes(Vec<u8>),
    Pair { left: u64, right: u64 },
    Value(CborValue),
}

impl Payload {
    /// Encodes the payload into canonical CBOR bytes.
    ///
    /// Infallible by contract. The journal stores only primitive payload
    /// forms, which cannot fail to encode. Use [`Self::try_encode`] when the
    /// payload may carry a user-supplied [`CborValue`].
    pub fn encode(&self, out: &mut Vec<u8>) {
        let start = out.len();
        if self.try_encode(out).is_err() {
            out.truncate(start);
        }
    }

    /// Encodes the payload into canonical CBOR bytes, reporting the error.
    ///
    /// On error the buffer may contain partial bytes; the caller must discard
    /// the tail. The only failing case is [`Payload::Value`] holding a
    /// `-0.0`/`NaN` float or a disallowed tag.
    pub fn try_encode(&self, out: &mut Vec<u8>) -> Result<(), CborError> {
        match self {
            Self::Empty => {
                cbor::array(out, 1);
                cbor::unsigned(out, 6);
                Ok(())
            }
            Self::Number(value) => {
                cbor::array(out, 2);
                cbor::unsigned(out, 0);
                cbor::unsigned(out, *value);
                Ok(())
            }
            Self::Signed(value) => {
                cbor::array(out, 2);
                cbor::unsigned(out, 4);
                cbor::signed(out, *value);
                Ok(())
            }
            Self::Text(value) => {
                cbor::array(out, 2);
                cbor::unsigned(out, 1);
                cbor::text(out, value);
                Ok(())
            }
            Self::Bytes(value) => {
                cbor::array(out, 2);
                cbor::unsigned(out, 2);
                cbor::bytes(out, value);
                Ok(())
            }
            Self::Pair { left, right } => {
                cbor::array(out, 3);
                cbor::unsigned(out, 3);
                cbor::unsigned(out, *left);
                cbor::unsigned(out, *right);
                Ok(())
            }
            Self::Value(cbor_val) => {
                cbor::array(out, 2);
                cbor::unsigned(out, 5);
                cbor_val.try_encode(out)
            }
        }
    }
}

/// A journal entry before its content address is assigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryData {
    pub kind: EntryKind,
    pub actor: ActorId,
    pub parents: Vec<Hash>,
    pub vector_clock: Vec<u64>,
    pub sequence: u64,
    pub payload: Payload,
}

impl EntryData {
    /// Encodes all hash-covered fields in canonical CBOR.
    ///
    /// Infallible by construction. The kind encoding, actor, parents, vector
    /// clock, and sequence are structural and cannot fail. The payload encodes
    /// only primitive forms in journal entries produced by the engine; a
    /// [`Payload::Value`] carrying a non-canonical float or a disallowed tag
    /// is a caller contract violation and is omitted rather than panicked on.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let start = out.len();
        if self.encode_into(&mut out).is_err() {
            out.truncate(start);
        }
        out
    }

    /// Encodes all hash-covered fields in canonical CBOR, reporting failures.
    ///
    /// Callers that accept payloads from untrusted sources must use this path
    /// and propagate the error.
    pub fn try_canonical_bytes(&self) -> Result<Vec<u8>, CborError> {
        let mut out = Vec::new();
        self.encode_into(&mut out)?;
        Ok(out)
    }

    /// Encodes all hash-covered fields into a caller-provided buffer.
    ///
    /// Hot append paths reuse a scratch buffer to avoid one allocation per
    /// entry; the encoded bytes are identical to [`Self::try_canonical_bytes`].
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), CborError> {
        cbor::array(out, 6);
        self.kind.encode_kind(out);
        cbor::unsigned(out, self.actor as u64);
        cbor::array(out, self.parents.len());
        for parent in &self.parents {
            cbor::bytes(out, parent);
        }
        cbor::array(out, self.vector_clock.len());
        for component in &self.vector_clock {
            cbor::unsigned(out, *component);
        }
        cbor::unsigned(out, self.sequence);
        self.payload.try_encode(out)
    }
}
