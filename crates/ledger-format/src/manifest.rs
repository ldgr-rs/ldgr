//! Manifest schemas and format version identifiers.
//!
//! Version 2 manifest layout (canonical CBOR array of exactly 8 items):
//!
//! ```text
//! Manifest = [
//!   format_version,
//!   crash_semantics_version,
//!   execution_identity_digest,
//!   root_seed,
//!   policy,
//!   journal_root,
//!   entry_count,
//!   actor_heads
//! ]
//! ```
//!
//! The execution-identity digest moved from the version-1 extensions slot
//! into a first-class array element; the extensions map is gone. The outer
//! 16-byte frame prefix (see [`crate::frame`]) precedes the manifest bytes
//! on disk.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::cbor::{self, CborError, CborValue};
use crate::entry::{ActorId, Hash};
use crate::limits::{CRASH_SEMANTICS_VERSION, FORMAT_VERSION};

/// Current manifest format version. Version 2 is the only supported version.
pub const MANIFEST_FORMAT_VERSION: u32 = FORMAT_VERSION;

/// A manifest format version identifier.
///
/// A reader rejects any version other than [`ManifestVersion::CURRENT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ManifestVersion(pub u32);

impl ManifestVersion {
    pub const CURRENT: Self = Self(MANIFEST_FORMAT_VERSION);

    pub const fn is_supported(self) -> bool {
        self.0 == MANIFEST_FORMAT_VERSION
    }
}

/// A reproducible run manifest describing a simulation trial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunManifest {
    pub format_version: u32,
    /// Crash-semantics version bound by the manifest and `ExecutionIdentity`.
    pub crash_semantics_version: u32,
    /// Execution-identity digest of the run that produced this manifest.
    ///
    /// `None` means the run did not bind an identity; a root comparison
    /// involving this manifest must treat the identity as incomplete.
    pub execution_identity: Option<Hash>,
    pub root_seed: Hash,
    /// Scheduling policy name or parameters.
    pub policy_tag: String,
    /// Root hash of the resulting journal DAG.
    pub journal_root: Hash,
    /// Total entries executed in this trial.
    pub entry_count: u64,
    /// Actor sequence heads at end of run.
    pub actor_heads: BTreeMap<ActorId, Hash>,
}

impl RunManifest {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, CborError> {
        let mut out = Vec::new();
        cbor::array(&mut out, 8);
        cbor::unsigned(&mut out, self.format_version as u64);
        cbor::unsigned(&mut out, self.crash_semantics_version as u64);
        match &self.execution_identity {
            Some(digest) => cbor::bytes(&mut out, digest),
            None => cbor::null(&mut out),
        }
        cbor::bytes(&mut out, &self.root_seed);
        cbor::text(&mut out, &self.policy_tag);
        cbor::bytes(&mut out, &self.journal_root);
        cbor::unsigned(&mut out, self.entry_count);

        let heads: Vec<(CborValue, CborValue)> = self
            .actor_heads
            .iter()
            .map(|(actor, hash)| {
                (
                    CborValue::Unsigned(*actor as u64),
                    CborValue::Bytes(hash.to_vec()),
                )
            })
            .collect();
        CborValue::Map(heads).try_encode(&mut out)?;
        Ok(out)
    }

    /// Deserializes a manifest from canonical CBOR bytes.
    ///
    /// Version 2 is an array of exactly 8 canonical items in the order above.
    /// Any other version is rejected.
    pub fn from_canonical_bytes(input: &[u8]) -> Result<Self, CborError> {
        let value = CborValue::from_canonical_bytes(input)?;
        let CborValue::Array(items) = value else {
            return Err(CborError::MalformedManifest(
                "top-level item must be an array",
            ));
        };
        if items.len() != 8 {
            return Err(CborError::MalformedManifest(
                "array must hold exactly 8 items",
            ));
        }

        let format_version = match &items[0] {
            CborValue::Unsigned(v) if *v <= u32::MAX as u64 => *v as u32,
            _ => {
                return Err(CborError::MalformedManifest(
                    "item 0 must be the format version",
                ));
            }
        };
        if ManifestVersion(format_version) != ManifestVersion::CURRENT {
            return Err(CborError::UnsupportedVersion(format_version));
        }

        let crash_semantics_version = match &items[1] {
            CborValue::Unsigned(v) if *v <= u32::MAX as u64 => *v as u32,
            _ => {
                return Err(CborError::MalformedManifest(
                    "item 1 must be the crash-semantics version",
                ));
            }
        };
        if crash_semantics_version != CRASH_SEMANTICS_VERSION {
            return Err(CborError::UnsupportedVersion(crash_semantics_version));
        }

        let execution_identity = match &items[2] {
            CborValue::Null => None,
            CborValue::Bytes(b) => Some(<[u8; 32]>::try_from(b.as_slice()).map_err(|_| {
                CborError::MalformedManifest("execution_identity digest must be a 32-byte hash")
            })?),
            _ => {
                return Err(CborError::MalformedManifest(
                    "execution_identity must be null or a 32-byte hash",
                ));
            }
        };

        let root_seed = match &items[3] {
            CborValue::Bytes(b) => <[u8; 32]>::try_from(b.as_slice())
                .map_err(|_| CborError::MalformedManifest("root_seed must be 32 bytes"))?,
            _ => {
                return Err(CborError::MalformedManifest(
                    "root_seed must be a byte string",
                ));
            }
        };
        let policy_tag = match &items[4] {
            CborValue::Text(s) => s.clone(),
            _ => return Err(CborError::MalformedManifest("policy must be a text string")),
        };
        let journal_root = match &items[5] {
            CborValue::Bytes(b) => <[u8; 32]>::try_from(b.as_slice())
                .map_err(|_| CborError::MalformedManifest("journal_root must be 32 bytes"))?,
            _ => {
                return Err(CborError::MalformedManifest(
                    "journal_root must be a byte string",
                ));
            }
        };
        let entry_count = match &items[6] {
            CborValue::Unsigned(v) => *v,
            _ => {
                return Err(CborError::MalformedManifest(
                    "entry_count must be an unsigned integer",
                ));
            }
        };

        let actor_heads = match &items[7] {
            CborValue::Map(entries) => {
                let mut map = BTreeMap::new();
                for (key, val) in entries {
                    let actor = match key {
                        CborValue::Unsigned(a) if *a <= u32::MAX as u64 => *a as ActorId,
                        _ => {
                            return Err(CborError::MalformedManifest(
                                "actor key must be an unsigned integer",
                            ));
                        }
                    };
                    let hash = match val {
                        CborValue::Bytes(b) => {
                            <[u8; 32]>::try_from(b.as_slice()).map_err(|_| {
                                CborError::MalformedManifest("actor hash must be 32 bytes")
                            })?
                        }
                        _ => {
                            return Err(CborError::MalformedManifest(
                                "actor hash must be a byte string",
                            ));
                        }
                    };
                    map.insert(actor, hash);
                }
                map
            }
            _ => return Err(CborError::MalformedManifest("actor_heads must be a map")),
        };

        Ok(RunManifest {
            format_version,
            crash_semantics_version,
            execution_identity,
            root_seed,
            policy_tag,
            journal_root,
            entry_count,
            actor_heads,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    fn sample_manifest() -> RunManifest {
        RunManifest {
            format_version: MANIFEST_FORMAT_VERSION,
            crash_semantics_version: CRASH_SEMANTICS_VERSION,
            execution_identity: None,
            root_seed: [0x01; 32],
            policy_tag: "random".to_string(),
            journal_root: [0x02; 32],
            entry_count: 7,
            actor_heads: BTreeMap::new(),
        }
    }

    #[test]
    fn identity_digest_round_trips() {
        let mut manifest = sample_manifest();
        manifest.execution_identity = Some([0xab; 32]);
        let bytes = manifest.to_canonical_bytes().expect("manifest encodes");
        let decoded = RunManifest::from_canonical_bytes(&bytes).expect("manifest decodes");
        assert_eq!(decoded.execution_identity, Some([0xab; 32]));
        assert_eq!(decoded.to_canonical_bytes().expect("re-encode"), bytes);
    }

    #[test]
    fn identity_absent_stays_absent() {
        let manifest = sample_manifest();
        let bytes = manifest.to_canonical_bytes().expect("manifest encodes");
        let decoded = RunManifest::from_canonical_bytes(&bytes).expect("manifest decodes");
        assert_eq!(decoded.execution_identity, None);
    }

    #[test]
    fn identity_presence_changes_canonical_bytes() {
        let plain = sample_manifest();
        let mut bound = sample_manifest();
        bound.execution_identity = Some([0xab; 32]);
        assert_ne!(
            plain.to_canonical_bytes().expect("plain encodes"),
            bound.to_canonical_bytes().expect("bound encodes")
        );
    }

    #[test]
    fn wrong_version_is_rejected() {
        let mut manifest = sample_manifest();
        manifest.format_version = 1;
        let bytes = manifest.to_canonical_bytes().expect("manifest encodes");
        assert!(matches!(
            RunManifest::from_canonical_bytes(&bytes),
            Err(CborError::UnsupportedVersion(1))
        ));
    }

    #[test]
    fn wrong_crash_semantics_is_rejected() {
        let mut manifest = sample_manifest();
        manifest.crash_semantics_version = CRASH_SEMANTICS_VERSION + 1;
        let bytes = manifest.to_canonical_bytes().expect("manifest encodes");
        assert!(matches!(
            RunManifest::from_canonical_bytes(&bytes),
            Err(CborError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn wrong_identity_shape_is_rejected() {
        // Craft a manifest whose identity element is a 16-byte byte string;
        // the typed field cannot express that, so build the raw array.
        let mut bytes = Vec::new();
        cbor::array(&mut bytes, 8);
        cbor::unsigned(&mut bytes, MANIFEST_FORMAT_VERSION as u64);
        cbor::unsigned(&mut bytes, CRASH_SEMANTICS_VERSION as u64);
        cbor::bytes(&mut bytes, &[0xaa; 16]);
        cbor::bytes(&mut bytes, &[0x01; 32]);
        cbor::text(&mut bytes, "random");
        cbor::bytes(&mut bytes, &[0x02; 32]);
        cbor::unsigned(&mut bytes, 7);
        CborValue::Map(Vec::new())
            .try_encode(&mut bytes)
            .expect("actor heads encode");
        assert!(matches!(
            RunManifest::from_canonical_bytes(&bytes),
            Err(CborError::MalformedManifest(_))
        ));
    }
}
