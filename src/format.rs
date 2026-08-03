//! Journal entry taxonomy and canonical encoding.

use crate::cbor;

/// Stable actor identifier.
pub type ActorId = u32;

/// Stable stream identifier for deterministic randomness.
pub type StreamId = u32;

/// Journal event kinds used by the prototype.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntryKind {
    Spawn,
    Block,
    Wake,
    TimerSet,
    TimerFire,
    ClockRead,
    Send,
    Recv,
    FsWrite,
    FsFsync,
    FsRead,
    RngDraw,
    Outcome,
    Assert,
    InputStep,
    Fault,
}

impl EntryKind {
    /// Return a stable numeric wire tag.
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
            Self::RngDraw => 11,
            Self::Outcome => 12,
            Self::Assert => 13,
            Self::InputStep => 14,
            Self::Fault => 15,
        }
    }
}

/// Closed-world payload for a journal entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    Empty,
    Number(u64),
    Text(String),
    Bytes(Vec<u8>),
    Pair { left: u64, right: u64 },
}

impl Payload {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Empty => cbor::array(out, 1),
            Self::Number(value) => {
                cbor::array(out, 2);
                cbor::unsigned(out, 0);
                cbor::unsigned(out, *value);
            }
            Self::Text(value) => {
                cbor::array(out, 2);
                cbor::unsigned(out, 1);
                cbor::text(out, value);
            }
            Self::Bytes(value) => {
                cbor::array(out, 2);
                cbor::unsigned(out, 2);
                cbor::bytes(out, value);
            }
            Self::Pair { left, right } => {
                cbor::array(out, 3);
                cbor::unsigned(out, 3);
                cbor::unsigned(out, *left);
                cbor::unsigned(out, *right);
            }
        }
    }
}

/// A journal entry before its content address is assigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryData {
    pub kind: EntryKind,
    pub actor: ActorId,
    pub parents: Vec<[u8; 32]>,
    pub vector_clock: Vec<u64>,
    pub sequence: u64,
    pub payload: Payload,
}

impl EntryData {
    /// Encode all hash-covered fields in canonical CBOR.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        cbor::array(&mut out, 6);
        cbor::unsigned(&mut out, self.kind.tag());
        cbor::unsigned(&mut out, self.actor as u64);
        cbor::array(&mut out, self.parents.len());
        for parent in &self.parents {
            cbor::bytes(&mut out, parent);
        }
        cbor::array(&mut out, self.vector_clock.len());
        for component in &self.vector_clock {
            cbor::unsigned(&mut out, *component);
        }
        cbor::unsigned(&mut out, self.sequence);
        self.payload.encode(&mut out);
        out
    }
}
