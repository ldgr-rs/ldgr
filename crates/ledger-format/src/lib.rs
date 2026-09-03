#![deny(unsafe_code)]
#![allow(missing_docs)]
#![no_std]

//! Format types, canonical RFC 8949 CBOR codec, and manifests for the Ledger DST engine.

extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

pub mod cbor;
pub mod entry;
pub mod frame;
pub mod hex;
pub mod limits;
pub mod manifest;
pub mod path;
pub mod value;

pub use cbor::{CborError, CborValue, TolerantReader, compare_canonical_keys, parse_tolerant};
pub use entry::{
    ActorId, AssertPayload, BlockPayload, CapGrantPayload, CapInvokePayload, CapRequestPayload,
    CapRevokePayload, CrashOperation, EntryData, EntryHash, EntryKind, EntryPayload, EpochPayload,
    FaultPayload, FaultSpec, FsReadPayload, FsSyncPayload, FsWritePayload, InputStepPayload,
    MessageId, ObservedRead, OutcomePayload, RecvFrame, RngDrawPayload, SendFrame, SequenceNumber,
    SnapshotPayload, StepBeginPayload, StepEndPayload, StreamId, WakePayload,
};
pub use frame::{FRAME_PREFIX_LEN, FrameError, FramePrefix};
pub use hex::{HexError, hash_from_hex, hash_to_hex};
pub use limits::{CRASH_SEMANTICS_VERSION, FORMAT_VERSION};
pub use manifest::{MANIFEST_FORMAT_VERSION, ManifestVersion, RunManifest};
pub use path::{PATH_DOMAIN, PATH_HASH_LEN, PathError, PathRef, canonicalize};
pub use value::{CanonicalValue, ValueError};
