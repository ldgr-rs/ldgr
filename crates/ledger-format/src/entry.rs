//! Journal entry taxonomy, identifiers, and canonical v2 encoding.
//!
//! Version 2 encodes every entry as one canonical CBOR array:
//!
//! ```text
//! EntryData = [
//!   format_version,
//!   kind_tag,
//!   actor,
//!   parents,
//!   vector_clock,
//!   sequence,
//!   typed_payload
//! ]
//! ```
//!
//! The kind tag is a plain unsigned tag; every entry kind has exactly one
//! typed payload shape. Encoding validates the kind and payload before
//! hashing, and decoding reads the kind first and calls exactly one payload
//! decoder. No generic payload fallback exists for a recognized kind.

use alloc::vec::Vec;

use crate::cbor::items::ItemReader;
use crate::cbor::{self, CborError};
use crate::limits::{
    FORMAT_VERSION, MAX_ENTRY_BYTES, MAX_PARENTS_PER_ENTRY, MAX_VECTOR_CLOCK_ACTORS,
};
use crate::path::{self, PathRef};
use crate::value::CanonicalValue;

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

/// A fault injected by the explorer into a run (schedule vocabulary).
///
/// This is the injection descriptor used by schedules and the sim boundary;
/// the journaled fault entry carries [`FaultPayload`] on the wire.
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

/// Canonical numeric tag for an entry kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntryKind {
    Spawn = 0,
    Block = 1,
    Wake = 2,
    TimerSet = 3,
    TimerFire = 4,
    ClockRead = 5,
    Send = 6,
    Recv = 7,
    FsWrite = 8,
    FsFsync = 9,
    FsRead = 10,
    RngDraw = 11,
    Outcome = 12,
    Assert = 13,
    Snapshot = 14,
    Epoch = 15,
    InputStep = 16,
    CapRequest = 17,
    CapGrant = 18,
    CapInvoke = 19,
    CapRevoke = 20,
    Fault = 21,
    StepBegin = 22,
    StepEnd = 23,
}

impl EntryKind {
    /// Returns the stable numeric wire tag.
    pub const fn tag(self) -> u64 {
        self as u64
    }

    /// Maps a numeric tag to a kind; unknown tags are rejected.
    pub fn from_tag(tag: u64) -> Option<Self> {
        Some(match tag {
            0 => Self::Spawn,
            1 => Self::Block,
            2 => Self::Wake,
            3 => Self::TimerSet,
            4 => Self::TimerFire,
            5 => Self::ClockRead,
            6 => Self::Send,
            7 => Self::Recv,
            8 => Self::FsWrite,
            9 => Self::FsFsync,
            10 => Self::FsRead,
            11 => Self::RngDraw,
            12 => Self::Outcome,
            13 => Self::Assert,
            14 => Self::Snapshot,
            15 => Self::Epoch,
            16 => Self::InputStep,
            17 => Self::CapRequest,
            18 => Self::CapGrant,
            19 => Self::CapInvoke,
            20 => Self::CapRevoke,
            21 => Self::Fault,
            22 => Self::StepBegin,
            23 => Self::StepEnd,
            _ => return None,
        })
    }
}

impl TryFrom<u64> for EntryKind {
    type Error = u64;

    fn try_from(tag: u64) -> Result<Self, Self::Error> {
        Self::from_tag(tag).ok_or(tag)
    }
}

impl TryFrom<u32> for EntryKind {
    type Error = u32;

    fn try_from(tag: u32) -> Result<Self, Self::Error> {
        Self::from_tag(tag as u64).ok_or(tag)
    }
}

/// Message identity: sender actor and the sender entry sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageId {
    /// Sending actor.
    pub sender: ActorId,
    /// Sequence of the sending actor's Send entry.
    pub sender_sequence: u64,
}

impl MessageId {
    /// Constructs a message identity.
    pub const fn new(sender: ActorId, sender_sequence: u64) -> Self {
        Self {
            sender,
            sender_sequence,
        }
    }
}

/// Scheduler and workflow discriminants with complete semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlockPayload {
    /// Records a cooperative yield without marking the actor as waiting.
    Yield,
    /// Records that the actor's deterministic inbox has no deliverable message.
    WaitMessage,
}

/// Wake payload discriminants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WakePayload {
    /// A timer fired; has one `TimerFire` parent with the same timer id.
    TimerReady { timer_id: u64 },
    /// A message became deliverable; has one `Recv` parent with the same id.
    MessageReady { message_id: MessageId },
}

/// Step-end discriminants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepEndPayload {
    /// The step function returned a value.
    Completed {
        step_id: u64,
        result: CanonicalValue,
    },
    /// The step function returned a typed application error.
    Failed { step_id: u64, error: CanonicalValue },
    /// The workflow controller cancelled the step.
    Cancelled {
        step_id: u64,
        reason: CanonicalValue,
    },
}

/// Network message frame recorded by a Send entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendFrame {
    /// Message identity; `sender` equals `from` and the entry actor.
    pub message_id: MessageId,
    /// Sending actor.
    pub from: ActorId,
    /// Receiving actor.
    pub to: ActorId,
    /// Original content bytes.
    pub original_content: Vec<u8>,
}

/// Network message frame recorded by a Recv entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecvFrame {
    /// Message identity copied from the corresponding Send entry.
    pub message_id: MessageId,
    /// Sending actor.
    pub from: ActorId,
    /// Receiving actor; equals the entry actor.
    pub to: ActorId,
    /// Observed content bytes.
    pub observed_content: Vec<u8>,
}

/// Filesystem write or metadata mutation payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsWritePayload {
    /// Writes bytes at an absolute offset.
    Write {
        path_ref: PathRef,
        offset: u64,
        content: Vec<u8>,
    },
    /// Creates an empty file; fails with `AlreadyExists` when present.
    Allocate { path_ref: PathRef },
    /// Atomically renames `from` over `to`.
    Rename {
        from_path_ref: PathRef,
        to_path_ref: PathRef,
    },
}

/// fsync persistence-barrier payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsSyncPayload {
    /// The file whose dirty state is persisted.
    pub path_ref: PathRef,
}

/// Observed result of a read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservedRead {
    /// The file does not exist.
    Missing,
    /// The file exists; content is exactly what the caller observed.
    Present { content: Vec<u8> },
}

/// Filesystem read observation payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsReadPayload {
    /// The file read.
    pub path_ref: PathRef,
    /// Absolute read offset.
    pub offset: u64,
    /// Requested byte length.
    pub requested_len: u64,
    /// Observed result.
    pub observed: ObservedRead,
}

/// Deterministic randomness draw payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RngDrawPayload {
    /// Stream drawn from.
    pub stream: StreamId,
    /// Monotonic draw index within the stream.
    pub draw_index: u64,
    /// Drawn content bytes.
    pub content: Vec<u8>,
}

/// Outcome payload binding a schema digest to a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomePayload {
    /// Domain schema digest bound in `ExecutionIdentity`.
    pub schema: Hash,
    /// The outcome value.
    pub value: CanonicalValue,
}

/// Assertion payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertPayload {
    /// Predicate schema digest bound in `ExecutionIdentity`.
    pub predicate: Hash,
    /// Whether the predicate passed.
    pub passed: bool,
    /// Observed detail.
    pub detail: CanonicalValue,
}

/// Snapshot marker payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotPayload {
    /// Content address of the snapshot state.
    pub snapshot_digest: Hash,
}

/// Epoch marker payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochPayload {
    /// Epoch identifier.
    pub epoch: u64,
}

/// PBT input-step payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputStepPayload {
    /// Workload generator identity.
    pub generator: GenId,
    /// Replay key of the drawn input.
    pub replay: InputKey,
    /// The drawn input value.
    pub value: CanonicalValue,
}

/// Capability lifecycle payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapRequestPayload {
    /// 16-byte request identifier.
    pub request: [u8; 16],
    /// Subject digest.
    pub subject: Hash,
    /// Capability digest.
    pub capability: Hash,
}

/// Capability grant payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapGrantPayload {
    /// 16-byte request identifier.
    pub request: [u8; 16],
    /// 16-byte grant identifier.
    pub grant: [u8; 16],
    /// Grant epoch.
    pub epoch: u64,
}

/// Capability invoke payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapInvokePayload {
    /// 16-byte grant identifier.
    pub grant: [u8; 16],
    /// Operation digest.
    pub operation: Hash,
}

/// Capability revoke payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapRevokePayload {
    /// 16-byte grant identifier.
    pub grant: [u8; 16],
    /// Revocation epoch.
    pub epoch: u64,
}

/// Crash-state operator carried by a CrashActor fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrashOperation {
    /// Restores all files to durable state.
    DropAllUnsynced,
    /// Restores the selected canonical paths to durable state.
    DropPaths { paths: Vec<PathRef> },
    /// Persists a prefix of one targeted dirty write.
    TornWrite {
        write_entry: Hash,
        persisted_prefix: u64,
    },
    /// Applies XOR bytes to the intersection with a targeted write range.
    CorruptRange {
        write_entry: Hash,
        offset: u64,
        xor_bytes: Vec<u8>,
    },
    /// Flips one bit inside a targeted write range.
    BitFlip {
        write_entry: Hash,
        offset: u64,
        bit: u8,
    },
}

/// Fault payload with exact canonical variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaultPayload {
    /// Drops the message identified by `message_id`.
    DropMessage { message_id: MessageId },
    /// Delays the message by `ticks`.
    DelayMessage { message_id: MessageId, ticks: u64 },
    /// Duplicates the message with a copy ordinal.
    DuplicateMessage {
        message_id: MessageId,
        copy_ordinal: u32,
    },
    /// Corrupts message content deterministically.
    CorruptMessage {
        message_id: MessageId,
        offset: u64,
        xor_bytes: Vec<u8>,
    },
    /// Cuts the link between two actors.
    Partition {
        src: ActorId,
        dst: ActorId,
        enabled: bool,
    },
    /// Crashes an actor into a post-crash state.
    CrashActor {
        actor: ActorId,
        crash_operation: CrashOperation,
    },
}

/// Durable-execution step begin payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepBeginPayload {
    /// Step identifier.
    pub step_id: u64,
    /// Step name bytes.
    pub name: Vec<u8>,
    /// Optional idempotency key.
    pub idempotency_key: Option<Vec<u8>>,
}

/// Typed payload for one entry kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryPayload {
    /// Tag 0.
    Spawn { child_actor: ActorId },
    /// Tag 1.
    Block(BlockPayload),
    /// Tag 2.
    Wake(WakePayload),
    /// Tag 3.
    TimerSet { timer_id: u64, deadline_ticks: u64 },
    /// Tag 4.
    TimerFire { timer_id: u64, deadline_ticks: u64 },
    /// Tag 5.
    ClockRead { ticks: u64 },
    /// Tag 6.
    Send(SendFrame),
    /// Tag 7.
    Recv(RecvFrame),
    /// Tag 8.
    FsWrite(FsWritePayload),
    /// Tag 9.
    FsFsync(FsSyncPayload),
    /// Tag 10.
    FsRead(FsReadPayload),
    /// Tag 11.
    RngDraw(RngDrawPayload),
    /// Tag 12.
    Outcome(OutcomePayload),
    /// Tag 13.
    Assert(AssertPayload),
    /// Tag 14.
    Snapshot(SnapshotPayload),
    /// Tag 15.
    Epoch(EpochPayload),
    /// Tag 16.
    InputStep(InputStepPayload),
    /// Tag 17.
    CapRequest(CapRequestPayload),
    /// Tag 18.
    CapGrant(CapGrantPayload),
    /// Tag 19.
    CapInvoke(CapInvokePayload),
    /// Tag 20.
    CapRevoke(CapRevokePayload),
    /// Tag 21.
    Fault(FaultPayload),
    /// Tag 22.
    StepBegin(StepBeginPayload),
    /// Tag 23.
    StepEnd(StepEndPayload),
}

impl EntryPayload {
    /// Returns the kind this payload belongs to.
    pub fn kind(&self) -> EntryKind {
        match self {
            Self::Spawn { .. } => EntryKind::Spawn,
            Self::Block(_) => EntryKind::Block,
            Self::Wake(_) => EntryKind::Wake,
            Self::TimerSet { .. } => EntryKind::TimerSet,
            Self::TimerFire { .. } => EntryKind::TimerFire,
            Self::ClockRead { .. } => EntryKind::ClockRead,
            Self::Send(_) => EntryKind::Send,
            Self::Recv(_) => EntryKind::Recv,
            Self::FsWrite(_) => EntryKind::FsWrite,
            Self::FsFsync(_) => EntryKind::FsFsync,
            Self::FsRead(_) => EntryKind::FsRead,
            Self::RngDraw(_) => EntryKind::RngDraw,
            Self::Outcome(_) => EntryKind::Outcome,
            Self::Assert(_) => EntryKind::Assert,
            Self::Snapshot(_) => EntryKind::Snapshot,
            Self::Epoch(_) => EntryKind::Epoch,
            Self::InputStep(_) => EntryKind::InputStep,
            Self::CapRequest(_) => EntryKind::CapRequest,
            Self::CapGrant(_) => EntryKind::CapGrant,
            Self::CapInvoke(_) => EntryKind::CapInvoke,
            Self::CapRevoke(_) => EntryKind::CapRevoke,
            Self::Fault(_) => EntryKind::Fault,
            Self::StepBegin(_) => EntryKind::StepBegin,
            Self::StepEnd(_) => EntryKind::StepEnd,
        }
    }

    /// Appends the canonical typed-payload encoding as one CBOR item.
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), CborError> {
        match self {
            Self::Spawn { child_actor } => {
                cbor::array(out, 1);
                cbor::unsigned(out, *child_actor as u64);
            }
            Self::Block(block) => {
                cbor::array(out, 1);
                match block {
                    BlockPayload::Yield => cbor::unsigned(out, 0),
                    BlockPayload::WaitMessage => cbor::unsigned(out, 1),
                }
            }
            Self::Wake(wake) => match wake {
                WakePayload::TimerReady { timer_id } => {
                    cbor::array(out, 2);
                    cbor::unsigned(out, 0);
                    cbor::unsigned(out, *timer_id);
                }
                WakePayload::MessageReady { message_id } => {
                    cbor::array(out, 2);
                    cbor::unsigned(out, 1);
                    encode_message_id(out, message_id);
                }
            },
            Self::TimerSet {
                timer_id,
                deadline_ticks,
            }
            | Self::TimerFire {
                timer_id,
                deadline_ticks,
            } => {
                cbor::array(out, 2);
                cbor::unsigned(out, *timer_id);
                cbor::unsigned(out, *deadline_ticks);
            }
            Self::ClockRead { ticks } => {
                cbor::array(out, 1);
                cbor::unsigned(out, *ticks);
            }
            Self::Send(frame) => {
                cbor::array(out, 4);
                encode_message_id(out, &frame.message_id);
                cbor::unsigned(out, frame.from as u64);
                cbor::unsigned(out, frame.to as u64);
                cbor::bytes(out, &frame.original_content);
            }
            Self::Recv(frame) => {
                cbor::array(out, 4);
                encode_message_id(out, &frame.message_id);
                cbor::unsigned(out, frame.from as u64);
                cbor::unsigned(out, frame.to as u64);
                cbor::bytes(out, &frame.observed_content);
            }
            Self::FsWrite(write) => match write {
                FsWritePayload::Write {
                    path_ref,
                    offset,
                    content,
                } => {
                    cbor::array(out, 4);
                    cbor::unsigned(out, 0);
                    path::encode_path_ref(out, path_ref);
                    cbor::unsigned(out, *offset);
                    cbor::bytes(out, content);
                }
                FsWritePayload::Allocate { path_ref } => {
                    cbor::array(out, 2);
                    cbor::unsigned(out, 1);
                    path::encode_path_ref(out, path_ref);
                }
                FsWritePayload::Rename {
                    from_path_ref,
                    to_path_ref,
                } => {
                    cbor::array(out, 3);
                    cbor::unsigned(out, 2);
                    path::encode_path_ref(out, from_path_ref);
                    path::encode_path_ref(out, to_path_ref);
                }
            },
            Self::FsFsync(sync) => {
                cbor::array(out, 1);
                path::encode_path_ref(out, &sync.path_ref);
            }
            Self::FsRead(read) => {
                cbor::array(out, 4);
                path::encode_path_ref(out, &read.path_ref);
                cbor::unsigned(out, read.offset);
                cbor::unsigned(out, read.requested_len);
                match &read.observed {
                    ObservedRead::Missing => {
                        cbor::array(out, 1);
                        cbor::unsigned(out, 0);
                    }
                    ObservedRead::Present { content } => {
                        cbor::array(out, 2);
                        cbor::unsigned(out, 1);
                        cbor::bytes(out, content);
                    }
                }
            }
            Self::RngDraw(draw) => {
                cbor::array(out, 3);
                cbor::unsigned(out, draw.stream as u64);
                cbor::unsigned(out, draw.draw_index);
                cbor::bytes(out, &draw.content);
            }
            Self::Outcome(outcome) => {
                cbor::array(out, 2);
                cbor::bytes(out, &outcome.schema);
                outcome.value.try_encode(out).map_err(|_| {
                    CborError::MalformedManifest("outcome value exceeds canonical bounds")
                })?;
            }
            Self::Assert(assert) => {
                cbor::array(out, 3);
                cbor::bytes(out, &assert.predicate);
                cbor::boolean(out, assert.passed);
                assert.detail.try_encode(out).map_err(|_| {
                    CborError::MalformedManifest("assert detail exceeds canonical bounds")
                })?;
            }
            Self::Snapshot(snapshot) => {
                cbor::array(out, 1);
                cbor::bytes(out, &snapshot.snapshot_digest);
            }
            Self::Epoch(epoch) => {
                cbor::array(out, 1);
                cbor::unsigned(out, epoch.epoch);
            }
            Self::InputStep(step) => {
                cbor::array(out, 3);
                cbor::unsigned(out, step.generator);
                cbor::unsigned(out, step.replay);
                step.value.try_encode(out).map_err(|_| {
                    CborError::MalformedManifest("input value exceeds canonical bounds")
                })?;
            }
            Self::CapRequest(request) => {
                cbor::array(out, 3);
                cbor::bytes(out, &request.request);
                cbor::bytes(out, &request.subject);
                cbor::bytes(out, &request.capability);
            }
            Self::CapGrant(grant) => {
                cbor::array(out, 3);
                cbor::bytes(out, &grant.request);
                cbor::bytes(out, &grant.grant);
                cbor::unsigned(out, grant.epoch);
            }
            Self::CapInvoke(invoke) => {
                cbor::array(out, 2);
                cbor::bytes(out, &invoke.grant);
                cbor::bytes(out, &invoke.operation);
            }
            Self::CapRevoke(revoke) => {
                cbor::array(out, 2);
                cbor::bytes(out, &revoke.grant);
                cbor::unsigned(out, revoke.epoch);
            }
            Self::Fault(fault) => encode_fault_payload(out, fault),
            Self::StepBegin(begin) => {
                cbor::array(out, 3);
                cbor::unsigned(out, begin.step_id);
                cbor::bytes(out, &begin.name);
                match &begin.idempotency_key {
                    Some(key) => cbor::bytes(out, key),
                    None => cbor::null(out),
                }
            }
            Self::StepEnd(end) => {
                let (discriminant, step_id, value) = match end {
                    StepEndPayload::Completed { step_id, result } => (0, *step_id, result),
                    StepEndPayload::Failed { step_id, error } => (1, *step_id, error),
                    StepEndPayload::Cancelled { step_id, reason } => (2, *step_id, reason),
                };
                cbor::array(out, 3);
                cbor::unsigned(out, discriminant);
                cbor::unsigned(out, step_id);
                value.try_encode(out).map_err(|_| {
                    CborError::MalformedManifest("step-end value exceeds canonical bounds")
                })?;
            }
        }
        Ok(())
    }
}

fn encode_message_id(out: &mut Vec<u8>, message_id: &MessageId) {
    cbor::array(out, 2);
    cbor::unsigned(out, message_id.sender as u64);
    cbor::unsigned(out, message_id.sender_sequence);
}

fn encode_fault_payload(out: &mut Vec<u8>, fault: &FaultPayload) {
    match fault {
        FaultPayload::DropMessage { message_id } => {
            cbor::array(out, 2);
            cbor::unsigned(out, 0);
            encode_message_id(out, message_id);
        }
        FaultPayload::DelayMessage { message_id, ticks } => {
            cbor::array(out, 3);
            cbor::unsigned(out, 1);
            encode_message_id(out, message_id);
            cbor::unsigned(out, *ticks);
        }
        FaultPayload::DuplicateMessage {
            message_id,
            copy_ordinal,
        } => {
            cbor::array(out, 3);
            cbor::unsigned(out, 2);
            encode_message_id(out, message_id);
            cbor::unsigned(out, *copy_ordinal as u64);
        }
        FaultPayload::CorruptMessage {
            message_id,
            offset,
            xor_bytes,
        } => {
            cbor::array(out, 4);
            cbor::unsigned(out, 3);
            encode_message_id(out, message_id);
            cbor::unsigned(out, *offset);
            cbor::bytes(out, xor_bytes);
        }
        FaultPayload::Partition { src, dst, enabled } => {
            cbor::array(out, 4);
            cbor::unsigned(out, 4);
            cbor::unsigned(out, *src as u64);
            cbor::unsigned(out, *dst as u64);
            cbor::boolean(out, *enabled);
        }
        FaultPayload::CrashActor {
            actor,
            crash_operation,
        } => {
            cbor::array(out, 3);
            cbor::unsigned(out, 5);
            cbor::unsigned(out, *actor as u64);
            match crash_operation {
                CrashOperation::DropAllUnsynced => {
                    cbor::array(out, 1);
                    cbor::unsigned(out, 0);
                }
                CrashOperation::DropPaths { paths } => {
                    cbor::array(out, 2);
                    cbor::unsigned(out, 1);
                    cbor::array(out, paths.len());
                    for path_ref in paths {
                        path::encode_path_ref(out, path_ref);
                    }
                }
                CrashOperation::TornWrite {
                    write_entry,
                    persisted_prefix,
                } => {
                    cbor::array(out, 3);
                    cbor::unsigned(out, 2);
                    cbor::bytes(out, write_entry);
                    cbor::unsigned(out, *persisted_prefix);
                }
                CrashOperation::CorruptRange {
                    write_entry,
                    offset,
                    xor_bytes,
                } => {
                    cbor::array(out, 4);
                    cbor::unsigned(out, 3);
                    cbor::bytes(out, write_entry);
                    cbor::unsigned(out, *offset);
                    cbor::bytes(out, xor_bytes);
                }
                CrashOperation::BitFlip {
                    write_entry,
                    offset,
                    bit,
                } => {
                    cbor::array(out, 4);
                    cbor::unsigned(out, 4);
                    cbor::bytes(out, write_entry);
                    cbor::unsigned(out, *offset);
                    cbor::unsigned(out, *bit as u64);
                }
            }
        }
    }
}

/// A journal entry before its content address is assigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryData {
    pub format_version: u32,
    pub kind: EntryKind,
    pub actor: ActorId,
    pub parents: Vec<Hash>,
    pub vector_clock: Vec<u64>,
    pub sequence: u64,
    pub payload: EntryPayload,
}

impl EntryData {
    /// Encodes all hash-covered fields in canonical CBOR.
    pub fn try_canonical_bytes(&self) -> Result<Vec<u8>, CborError> {
        let mut out = Vec::new();
        self.encode_into(&mut out)?;
        Ok(out)
    }

    /// Encodes all hash-covered fields into a caller-provided buffer.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), CborError> {
        let start = out.len();
        cbor::array(out, 7);
        cbor::unsigned(out, self.format_version as u64);
        cbor::unsigned(out, self.kind.tag());
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
        self.payload.encode_into(out)?;
        let encoded = out.len() - start;
        // The decoder rejects entries over the limit, so the encoder must
        // reject them too: an entry that encodes but cannot decode would be
        // written, sealed, and hash-verified, then fail on every read.
        if encoded > MAX_ENTRY_BYTES {
            out.truncate(start);
            return Err(CborError::EntryTooLarge(encoded));
        }
        Ok(())
    }

    /// Decodes an entry from canonical CBOR bytes with all bounds enforced
    /// before allocation.
    pub fn from_canonical_bytes(input: &[u8]) -> Result<Self, CborError> {
        if input.len() > MAX_ENTRY_BYTES {
            return Err(CborError::LengthOverflow);
        }
        let mut reader = ItemReader::new(input);
        let field_count = reader.read_array()?;
        if field_count != 7 {
            return Err(CborError::MalformedManifest(
                "EntryData must hold exactly 7 items",
            ));
        }
        let format_version_u64 = reader.read_unsigned()?;
        let format_version = u32::try_from(format_version_u64)
            .map_err(|_| CborError::MalformedManifest("format version exceeds u32"))?;
        if format_version != FORMAT_VERSION {
            return Err(CborError::UnsupportedVersion(format_version));
        }
        let tag = reader.read_unsigned()?;
        let kind = EntryKind::from_tag(tag).ok_or(CborError::UnknownTag(tag))?;
        let actor_u64 = reader.read_unsigned()?;
        let actor = u32::try_from(actor_u64)
            .map_err(|_| CborError::MalformedManifest("actor exceeds u32"))?;

        let parent_count = reader.read_array()?;
        if parent_count > MAX_PARENTS_PER_ENTRY {
            return Err(CborError::LengthOverflow);
        }
        let mut parents = Vec::with_capacity(parent_count);
        for _ in 0..parent_count {
            let bytes = reader.read_bytes()?;
            parents.push(
                <[u8; 32]>::try_from(bytes)
                    .map_err(|_| CborError::MalformedManifest("parent hash must be 32 bytes"))?,
            );
        }

        let vc_count = reader.read_array()?;
        if vc_count > MAX_VECTOR_CLOCK_ACTORS {
            return Err(CborError::LengthOverflow);
        }
        let mut vector_clock = Vec::with_capacity(vc_count);
        for _ in 0..vc_count {
            vector_clock.push(reader.read_unsigned()?);
        }

        let sequence = reader.read_unsigned()?;
        let payload = decode_payload(&mut reader, kind)?;
        if !reader.at_end() {
            return Err(CborError::TrailingBytes);
        }
        Ok(Self {
            format_version,
            kind,
            actor,
            parents,
            vector_clock,
            sequence,
            payload,
        })
    }
}

fn decode_payload(reader: &mut ItemReader<'_>, kind: EntryKind) -> Result<EntryPayload, CborError> {
    let payload = match kind {
        EntryKind::Spawn => {
            let n = reader.read_array()?;
            if n != 1 {
                return Err(CborError::MalformedManifest(
                    "Spawn payload must have 1 item",
                ));
            }
            let child = reader.read_unsigned()?;
            EntryPayload::Spawn {
                child_actor: u32::try_from(child)
                    .map_err(|_| CborError::MalformedManifest("child_actor exceeds u32"))?,
            }
        }
        EntryKind::Block => {
            let n = reader.read_array()?;
            if n != 1 {
                return Err(CborError::MalformedManifest(
                    "Block payload must have 1 item",
                ));
            }
            match reader.read_unsigned()? {
                0 => EntryPayload::Block(BlockPayload::Yield),
                1 => EntryPayload::Block(BlockPayload::WaitMessage),
                _ => {
                    return Err(CborError::UnsupportedType(0));
                }
            }
        }
        EntryKind::Wake => {
            let n = reader.read_array()?;
            if n != 2 {
                return Err(CborError::MalformedManifest(
                    "Wake payload must have 2 items",
                ));
            }
            match reader.read_unsigned()? {
                0 => {
                    let timer_id = reader.read_unsigned()?;
                    EntryPayload::Wake(WakePayload::TimerReady { timer_id })
                }
                1 => {
                    let message_id = decode_message_id(reader)?;
                    EntryPayload::Wake(WakePayload::MessageReady { message_id })
                }
                _ => {
                    return Err(CborError::UnsupportedType(0));
                }
            }
        }
        EntryKind::TimerSet | EntryKind::TimerFire => {
            let n = reader.read_array()?;
            if n != 2 {
                return Err(CborError::MalformedManifest(
                    "Timer payload must have 2 items",
                ));
            }
            let timer_id = reader.read_unsigned()?;
            let deadline_ticks = reader.read_unsigned()?;
            if kind == EntryKind::TimerSet {
                EntryPayload::TimerSet {
                    timer_id,
                    deadline_ticks,
                }
            } else {
                EntryPayload::TimerFire {
                    timer_id,
                    deadline_ticks,
                }
            }
        }
        EntryKind::ClockRead => {
            let n = reader.read_array()?;
            if n != 1 {
                return Err(CborError::MalformedManifest(
                    "ClockRead payload must have 1 item",
                ));
            }
            EntryPayload::ClockRead {
                ticks: reader.read_unsigned()?,
            }
        }
        EntryKind::Send => {
            let n = reader.read_array()?;
            if n != 4 {
                return Err(CborError::MalformedManifest("Send frame must have 4 items"));
            }
            let message_id = decode_message_id(reader)?;
            let from = decode_actor(reader)?;
            let to = decode_actor(reader)?;
            let original_content = reader.read_bytes()?.to_vec();
            EntryPayload::Send(SendFrame {
                message_id,
                from,
                to,
                original_content,
            })
        }
        EntryKind::Recv => {
            let n = reader.read_array()?;
            if n != 4 {
                return Err(CborError::MalformedManifest("Recv frame must have 4 items"));
            }
            let message_id = decode_message_id(reader)?;
            let from = decode_actor(reader)?;
            let to = decode_actor(reader)?;
            let observed_content = reader.read_bytes()?.to_vec();
            EntryPayload::Recv(RecvFrame {
                message_id,
                from,
                to,
                observed_content,
            })
        }
        EntryKind::FsWrite => {
            let n = reader.read_array()?;
            if !(2..=4).contains(&n) {
                return Err(CborError::MalformedManifest(
                    "FsWrite payload must have 2..=4 items",
                ));
            }
            match reader.read_unsigned()? {
                0 => {
                    if n != 4 {
                        return Err(CborError::MalformedManifest(
                            "Write payload must have 4 items",
                        ));
                    }
                    let path_ref = decode_path_ref(reader)?;
                    let offset = reader.read_unsigned()?;
                    let content = reader.read_bytes()?.to_vec();
                    EntryPayload::FsWrite(FsWritePayload::Write {
                        path_ref,
                        offset,
                        content,
                    })
                }
                1 => {
                    if n != 2 {
                        return Err(CborError::MalformedManifest(
                            "Allocate payload must have 2 items",
                        ));
                    }
                    let path_ref = decode_path_ref(reader)?;
                    EntryPayload::FsWrite(FsWritePayload::Allocate { path_ref })
                }
                2 => {
                    if n != 3 {
                        return Err(CborError::MalformedManifest(
                            "Rename payload must have 3 items",
                        ));
                    }
                    let from_path_ref = decode_path_ref(reader)?;
                    let to_path_ref = decode_path_ref(reader)?;
                    EntryPayload::FsWrite(FsWritePayload::Rename {
                        from_path_ref,
                        to_path_ref,
                    })
                }
                _ => {
                    return Err(CborError::UnsupportedType(0));
                }
            }
        }
        EntryKind::FsFsync => {
            let n = reader.read_array()?;
            if n != 1 {
                return Err(CborError::MalformedManifest(
                    "FsFsync payload must have 1 item",
                ));
            }
            let path_ref = decode_path_ref(reader)?;
            EntryPayload::FsFsync(FsSyncPayload { path_ref })
        }
        EntryKind::FsRead => {
            let n = reader.read_array()?;
            if n != 4 {
                return Err(CborError::MalformedManifest(
                    "FsRead payload must have 4 items",
                ));
            }
            let path_ref = decode_path_ref(reader)?;
            let offset = reader.read_unsigned()?;
            let requested_len = reader.read_unsigned()?;
            let observed = {
                let m = reader.read_array()?;
                if m != 1 && m != 2 {
                    return Err(CborError::MalformedManifest(
                        "observed result must have 1 or 2 items",
                    ));
                }
                match reader.read_unsigned()? {
                    0 => ObservedRead::Missing,
                    1 => {
                        let content = reader.read_bytes()?.to_vec();
                        ObservedRead::Present { content }
                    }
                    _ => {
                        return Err(CborError::UnsupportedType(0));
                    }
                }
            };
            EntryPayload::FsRead(FsReadPayload {
                path_ref,
                offset,
                requested_len,
                observed,
            })
        }
        EntryKind::RngDraw => {
            let n = reader.read_array()?;
            if n != 3 {
                return Err(CborError::MalformedManifest(
                    "RngDraw payload must have 3 items",
                ));
            }
            let stream = decode_stream(reader)?;
            let draw_index = reader.read_unsigned()?;
            let content = reader.read_bytes()?.to_vec();
            EntryPayload::RngDraw(RngDrawPayload {
                stream,
                draw_index,
                content,
            })
        }
        EntryKind::Outcome => {
            let n = reader.read_array()?;
            if n != 2 {
                return Err(CborError::MalformedManifest(
                    "Outcome payload must have 2 items",
                ));
            }
            let schema = decode_hash(reader)?;
            let value = reader
                .read_canonical_value()
                .map_err(|_| CborError::MalformedManifest("outcome value invalid"))?;
            EntryPayload::Outcome(OutcomePayload { schema, value })
        }
        EntryKind::Assert => {
            let n = reader.read_array()?;
            if n != 3 {
                return Err(CborError::MalformedManifest(
                    "Assert payload must have 3 items",
                ));
            }
            let predicate = decode_hash(reader)?;
            let passed = reader.read_bool()?;
            let detail = reader
                .read_canonical_value()
                .map_err(|_| CborError::MalformedManifest("assert detail invalid"))?;
            EntryPayload::Assert(AssertPayload {
                predicate,
                passed,
                detail,
            })
        }
        EntryKind::Snapshot => {
            let n = reader.read_array()?;
            if n != 1 {
                return Err(CborError::MalformedManifest(
                    "Snapshot payload must have 1 item",
                ));
            }
            let snapshot_digest = decode_hash(reader)?;
            EntryPayload::Snapshot(SnapshotPayload { snapshot_digest })
        }
        EntryKind::Epoch => {
            let n = reader.read_array()?;
            if n != 1 {
                return Err(CborError::MalformedManifest(
                    "Epoch payload must have 1 item",
                ));
            }
            EntryPayload::Epoch(EpochPayload {
                epoch: reader.read_unsigned()?,
            })
        }
        EntryKind::InputStep => {
            let n = reader.read_array()?;
            if n != 3 {
                return Err(CborError::MalformedManifest(
                    "InputStep payload must have 3 items",
                ));
            }
            let generator = reader.read_unsigned()?;
            let replay = reader.read_unsigned()?;
            let value = reader
                .read_canonical_value()
                .map_err(|_| CborError::MalformedManifest("input value invalid"))?;
            EntryPayload::InputStep(InputStepPayload {
                generator,
                replay,
                value,
            })
        }
        EntryKind::CapRequest => {
            let n = reader.read_array()?;
            if n != 3 {
                return Err(CborError::MalformedManifest(
                    "CapRequest payload must have 3 items",
                ));
            }
            let request = decode_bytes_16(reader)?;
            let subject = decode_hash(reader)?;
            let capability = decode_hash(reader)?;
            EntryPayload::CapRequest(CapRequestPayload {
                request,
                subject,
                capability,
            })
        }
        EntryKind::CapGrant => {
            let n = reader.read_array()?;
            if n != 3 {
                return Err(CborError::MalformedManifest(
                    "CapGrant payload must have 3 items",
                ));
            }
            let request = decode_bytes_16(reader)?;
            let grant = decode_bytes_16(reader)?;
            let epoch = reader.read_unsigned()?;
            EntryPayload::CapGrant(CapGrantPayload {
                request,
                grant,
                epoch,
            })
        }
        EntryKind::CapInvoke => {
            let n = reader.read_array()?;
            if n != 2 {
                return Err(CborError::MalformedManifest(
                    "CapInvoke payload must have 2 items",
                ));
            }
            let grant = decode_bytes_16(reader)?;
            let operation = decode_hash(reader)?;
            EntryPayload::CapInvoke(CapInvokePayload { grant, operation })
        }
        EntryKind::CapRevoke => {
            let n = reader.read_array()?;
            if n != 2 {
                return Err(CborError::MalformedManifest(
                    "CapRevoke payload must have 2 items",
                ));
            }
            let grant = decode_bytes_16(reader)?;
            let epoch = reader.read_unsigned()?;
            EntryPayload::CapRevoke(CapRevokePayload { grant, epoch })
        }
        EntryKind::Fault => EntryPayload::Fault(decode_fault_payload(reader)?),
        EntryKind::StepBegin => {
            let n = reader.read_array()?;
            if n != 3 {
                return Err(CborError::MalformedManifest(
                    "StepBegin payload must have 3 items",
                ));
            }
            let step_id = reader.read_unsigned()?;
            let name = reader.read_bytes()?.to_vec();
            let idempotency_key = match reader.read_item()? {
                crate::cbor::items::Item::Null => None,
                crate::cbor::items::Item::Bytes(b) => Some(b.to_vec()),
                _ => {
                    return Err(CborError::MalformedManifest(
                        "idempotency key must be null or bytes",
                    ));
                }
            };
            EntryPayload::StepBegin(StepBeginPayload {
                step_id,
                name,
                idempotency_key,
            })
        }
        EntryKind::StepEnd => {
            let n = reader.read_array()?;
            if n != 3 {
                return Err(CborError::MalformedManifest(
                    "StepEnd payload must have 3 items",
                ));
            }
            let discriminant = reader.read_unsigned()?;
            let step_id = reader.read_unsigned()?;
            let value = reader
                .read_canonical_value()
                .map_err(|_| CborError::MalformedManifest("step-end value invalid"))?;
            let payload = match discriminant {
                0 => StepEndPayload::Completed {
                    step_id,
                    result: value,
                },
                1 => StepEndPayload::Failed {
                    step_id,
                    error: value,
                },
                2 => StepEndPayload::Cancelled {
                    step_id,
                    reason: value,
                },
                _ => {
                    return Err(CborError::UnsupportedType(0));
                }
            };
            EntryPayload::StepEnd(payload)
        }
    };
    Ok(payload)
}

fn decode_message_id(reader: &mut ItemReader<'_>) -> Result<MessageId, CborError> {
    let n = reader.read_array()?;
    if n != 2 {
        return Err(CborError::MalformedManifest("message id must have 2 items"));
    }
    let sender = decode_actor(reader)?;
    let sender_sequence = reader.read_unsigned()?;
    Ok(MessageId {
        sender,
        sender_sequence,
    })
}

fn decode_actor(reader: &mut ItemReader<'_>) -> Result<ActorId, CborError> {
    let value = reader.read_unsigned()?;
    u32::try_from(value).map_err(|_| CborError::MalformedManifest("actor exceeds u32"))
}

fn decode_stream(reader: &mut ItemReader<'_>) -> Result<StreamId, CborError> {
    let value = reader.read_unsigned()?;
    u32::try_from(value).map_err(|_| CborError::MalformedManifest("stream exceeds u32"))
}

fn decode_hash(reader: &mut ItemReader<'_>) -> Result<Hash, CborError> {
    let bytes = reader.read_bytes()?;
    <[u8; 32]>::try_from(bytes).map_err(|_| CborError::MalformedManifest("hash must be 32 bytes"))
}

fn decode_bytes_16(reader: &mut ItemReader<'_>) -> Result<[u8; 16], CborError> {
    let bytes = reader.read_bytes()?;
    <[u8; 16]>::try_from(bytes)
        .map_err(|_| CborError::MalformedManifest("identifier must be 16 bytes"))
}

fn decode_path_ref(reader: &mut ItemReader<'_>) -> Result<PathRef, CborError> {
    let n = reader.read_array()?;
    if n != 2 {
        return Err(CborError::MalformedManifest("path ref must have 2 items"));
    }
    let path_hash = decode_hash(reader)?;
    let canonical_path = reader.read_bytes()?.to_vec();
    // The decoder recomputes and verifies path_hash; the hash check lives in
    // the journal layer where BLAKE3 is available, so here we validate the
    // canonical form and length only.
    let _ = path::canonicalize(&canonical_path)
        .map_err(|_| CborError::MalformedManifest("path ref is not canonical"))?;
    if canonical_path.len() > crate::limits::MAX_CANONICAL_PATH_BYTES {
        return Err(CborError::LengthOverflow);
    }
    Ok(PathRef {
        path_hash,
        canonical_path,
    })
}

fn decode_fault_payload(reader: &mut ItemReader<'_>) -> Result<FaultPayload, CborError> {
    let n = reader.read_array()?;
    if !(2..=4).contains(&n) {
        return Err(CborError::MalformedManifest(
            "Fault payload must have 2..=4 items",
        ));
    }
    match reader.read_unsigned()? {
        0 => {
            let message_id = decode_message_id(reader)?;
            Ok(FaultPayload::DropMessage { message_id })
        }
        1 => {
            let message_id = decode_message_id(reader)?;
            let ticks = reader.read_unsigned()?;
            Ok(FaultPayload::DelayMessage { message_id, ticks })
        }
        2 => {
            let message_id = decode_message_id(reader)?;
            let copy_ordinal = u32::try_from(reader.read_unsigned()?)
                .map_err(|_| CborError::MalformedManifest("copy_ordinal exceeds u32"))?;
            Ok(FaultPayload::DuplicateMessage {
                message_id,
                copy_ordinal,
            })
        }
        3 => {
            let message_id = decode_message_id(reader)?;
            let offset = reader.read_unsigned()?;
            let xor_bytes = reader.read_bytes()?.to_vec();
            if xor_bytes.is_empty() {
                return Err(CborError::MalformedManifest(
                    "empty XOR content is rejected",
                ));
            }
            Ok(FaultPayload::CorruptMessage {
                message_id,
                offset,
                xor_bytes,
            })
        }
        4 => {
            let src = decode_actor(reader)?;
            let dst = decode_actor(reader)?;
            let enabled = reader.read_bool()?;
            Ok(FaultPayload::Partition { src, dst, enabled })
        }
        5 => {
            let actor = decode_actor(reader)?;
            let crash_operation = decode_crash_operation(reader)?;
            Ok(FaultPayload::CrashActor {
                actor,
                crash_operation,
            })
        }
        _ => Err(CborError::UnsupportedType(0)),
    }
}

fn decode_crash_operation(reader: &mut ItemReader<'_>) -> Result<CrashOperation, CborError> {
    let n = reader.read_array()?;
    if !(1..=4).contains(&n) {
        return Err(CborError::MalformedManifest(
            "crash operation must have 1..=4 items",
        ));
    }
    match reader.read_unsigned()? {
        0 => Ok(CrashOperation::DropAllUnsynced),
        1 => {
            let m = reader.read_array()?;
            let mut paths = Vec::with_capacity(m);
            for _ in 0..m {
                paths.push(decode_path_ref(reader)?);
            }
            Ok(CrashOperation::DropPaths { paths })
        }
        2 => {
            let write_entry = decode_hash(reader)?;
            let persisted_prefix = reader.read_unsigned()?;
            Ok(CrashOperation::TornWrite {
                write_entry,
                persisted_prefix,
            })
        }
        3 => {
            let write_entry = decode_hash(reader)?;
            let offset = reader.read_unsigned()?;
            let xor_bytes = reader.read_bytes()?.to_vec();
            if xor_bytes.is_empty() {
                return Err(CborError::MalformedManifest(
                    "empty XOR content is rejected",
                ));
            }
            Ok(CrashOperation::CorruptRange {
                write_entry,
                offset,
                xor_bytes,
            })
        }
        4 => {
            let write_entry = decode_hash(reader)?;
            let offset = reader.read_unsigned()?;
            let bit = u8::try_from(reader.read_unsigned()?)
                .map_err(|_| CborError::MalformedManifest("bit exceeds u8"))?;
            if bit > 7 {
                return Err(CborError::MalformedManifest("bit must be in 0..=7"));
            }
            Ok(CrashOperation::BitFlip {
                write_entry,
                offset,
                bit,
            })
        }
        _ => Err(CborError::UnsupportedType(0)),
    }
}
