#![deny(unsafe_code)]
#![allow(missing_docs)]
#![no_std]

//! Format types, canonical RFC 8949 CBOR codec, and manifests for the Ledger DST engine.

extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

pub mod cbor;
pub mod entry;
pub mod manifest;

pub use cbor::{CborError, CborValue, TolerantReader, compare_canonical_keys, parse_tolerant};
pub use entry::{
    ActorId, EntryData, EntryKind, FaultSpec, GenId, Hash, InputKey, Payload, StreamId,
};
pub use manifest::{MANIFEST_FORMAT_VERSION, ManifestVersion, RunManifest};
