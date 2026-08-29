//! Manifest schemas and format version identifiers.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use crate::cbor::{self, CborError, CborValue};
use crate::entry::{ActorId, Hash};

/// Extension-map key carrying the execution-identity digest in the manifest.
///
/// The digest is a 32-byte BLAKE3 hash of the canonical
/// `ledger_journal::identity::ExecutionIdentity` bytes. `ledger-format`
/// cannot depend on `ledger-journal`, so the key is a documented string
/// constant rather than a typed re-export; both sides agree on the key name
/// and the 32-byte payload shape.
const EXECUTION_IDENTITY_EXTENSION: &str = "execution_identity";

/// Current manifest format version. Version 1 is the only supported version.
pub const MANIFEST_FORMAT_VERSION: u32 = 1;

/// A manifest format version identifier.
///
/// A reader rejects any version other than [`ManifestVersion::CURRENT`]. A
/// breaking format change bumps the version and is a breaking release of
/// `ledger-format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ManifestVersion(pub u32);

impl ManifestVersion {
    pub const CURRENT: Self = Self(MANIFEST_FORMAT_VERSION);

    pub const fn is_supported(self) -> bool {
        self.0 == MANIFEST_FORMAT_VERSION
    }
}

/// A reproducible run manifest describing a simulation trial.
///
/// The canonical wire form is an array of 7 items in this order:
/// `format_version`, `root_seed`, `policy_tag`, `journal_root`, `entry_count`,
/// `actor_heads` (a map), and `extensions` (a map). The extensions map is the
/// append-only forward-compatibility slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunManifest {
    pub format_version: u32,
    pub root_seed: Hash,
    /// Scheduling policy name or parameters.
    pub policy_tag: String,
    /// Root hash of the resulting journal DAG.
    pub journal_root: Hash,
    /// Total entries executed in this trial.
    pub entry_count: u64,
    /// Actor sequence heads at end of run.
    pub actor_heads: BTreeMap<ActorId, Hash>,
    /// Reserved extension fields for append-only format evolution.
    pub extensions: BTreeMap<String, CborValue>,
    /// Execution-identity digest of the run that produced this manifest.
    ///
    /// Encoded inside [`Self::extensions`] under `execution_identity`, so the
    /// canonical wire form (array of 7 items) is unchanged. `None` means the
    /// run did not bind an identity; a root comparison involving this
    /// manifest must treat the identity as incomplete.
    pub execution_identity: Option<Hash>,
}

impl RunManifest {
    /// Serializes manifest to a structured CBOR map.
    ///
    /// This is the tolerant in-memory representation, not the canonical wire
    /// form. Use [`Self::to_canonical_bytes`] for serialization.
    pub fn to_cbor(&self) -> CborValue {
        let heads = self
            .actor_heads
            .iter()
            .map(|(k, v)| (CborValue::Unsigned(*k as u64), CborValue::Bytes(v.to_vec())))
            .collect();
        let extensions = self
            .extensions
            .iter()
            .map(|(k, v)| (CborValue::Text(k.clone()), v.clone()))
            .collect();

        let map = vec![
            (
                CborValue::Text("format_version".into()),
                CborValue::Unsigned(self.format_version as u64),
            ),
            (
                CborValue::Text("root_seed".into()),
                CborValue::Bytes(self.root_seed.to_vec()),
            ),
            (
                CborValue::Text("policy".into()),
                CborValue::Text(self.policy_tag.clone()),
            ),
            (
                CborValue::Text("journal_root".into()),
                CborValue::Bytes(self.journal_root.to_vec()),
            ),
            (
                CborValue::Text("entry_count".into()),
                CborValue::Unsigned(self.entry_count),
            ),
            (CborValue::Text("actor_heads".into()), CborValue::Map(heads)),
            (
                CborValue::Text("extensions".into()),
                CborValue::Map(extensions),
            ),
        ];

        CborValue::Map(map)
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, CborError> {
        let mut out = Vec::new();
        cbor::array(&mut out, 7);
        cbor::unsigned(&mut out, self.format_version as u64);
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

        let mut extensions = self.extensions.clone();
        if let Some(identity) = &self.execution_identity {
            extensions.insert(
                EXECUTION_IDENTITY_EXTENSION.to_string(),
                CborValue::Bytes(identity.to_vec()),
            );
        }
        let extensions: Vec<(CborValue, CborValue)> = extensions
            .iter()
            .map(|(key, val)| (CborValue::Text(key.clone()), val.clone()))
            .collect();
        CborValue::Map(extensions).try_encode(&mut out)?;

        Ok(out)
    }

    /// Deserializes a manifest from canonical CBOR bytes.
    ///
    /// Version 1 is an array of exactly 7 canonical items in the same order as
    /// [`Self::to_canonical_bytes`]. Any other version is rejected.
    pub fn from_canonical_bytes(input: &[u8]) -> Result<Self, CborError> {
        let value = CborValue::from_canonical_bytes(input)?;
        let CborValue::Array(items) = value else {
            return Err(CborError::MalformedManifest(
                "top-level item must be an array",
            ));
        };
        if items.len() != 7 {
            return Err(CborError::MalformedManifest(
                "array must hold exactly 7 items",
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

        let root_seed = match &items[1] {
            CborValue::Bytes(b) => <[u8; 32]>::try_from(b.as_slice())
                .map_err(|_| CborError::MalformedManifest("root_seed must be 32 bytes"))?,
            _ => {
                return Err(CborError::MalformedManifest(
                    "root_seed must be a byte string",
                ));
            }
        };
        let policy_tag = match &items[2] {
            CborValue::Text(s) => s.clone(),
            _ => return Err(CborError::MalformedManifest("policy must be a text string")),
        };
        let journal_root = match &items[3] {
            CborValue::Bytes(b) => <[u8; 32]>::try_from(b.as_slice())
                .map_err(|_| CborError::MalformedManifest("journal_root must be 32 bytes"))?,
            _ => {
                return Err(CborError::MalformedManifest(
                    "journal_root must be a byte string",
                ));
            }
        };
        let entry_count = match &items[4] {
            CborValue::Unsigned(v) => *v,
            _ => {
                return Err(CborError::MalformedManifest(
                    "entry_count must be an unsigned integer",
                ));
            }
        };

        let actor_heads = match &items[5] {
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

        let extensions = match &items[6] {
            CborValue::Map(entries) => {
                let mut map = BTreeMap::new();
                for (key, val) in entries {
                    let name = match key {
                        CborValue::Text(s) => s.clone(),
                        _ => {
                            return Err(CborError::MalformedManifest(
                                "extension name must be a text string",
                            ));
                        }
                    };
                    map.insert(name, val.clone());
                }
                map
            }
            _ => return Err(CborError::MalformedManifest("extensions must be a map")),
        };

        let execution_identity = match extensions.get(EXECUTION_IDENTITY_EXTENSION) {
            Some(CborValue::Bytes(b)) => {
                Some(<[u8; 32]>::try_from(b.as_slice()).map_err(|_| {
                    CborError::MalformedManifest(
                        "execution_identity extension must be a 32-byte hash",
                    )
                })?)
            }
            Some(_) => {
                return Err(CborError::MalformedManifest(
                    "execution_identity extension must be a byte string",
                ));
            }
            None => None,
        };

        Ok(RunManifest {
            format_version,
            root_seed,
            policy_tag,
            journal_root,
            entry_count,
            actor_heads,
            extensions,
            execution_identity,
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
            root_seed: [0x01; 32],
            policy_tag: "random".to_string(),
            journal_root: [0x02; 32],
            entry_count: 7,
            actor_heads: BTreeMap::new(),
            extensions: BTreeMap::new(),
            execution_identity: None,
        }
    }

    #[test]
    fn identity_extension_round_trips() {
        let mut manifest = sample_manifest();
        manifest.execution_identity = Some([0xab; 32]);
        let bytes = manifest.to_canonical_bytes().expect("manifest encodes");
        let decoded = RunManifest::from_canonical_bytes(&bytes).expect("manifest decodes");
        assert_eq!(decoded.execution_identity, Some([0xab; 32]));
        assert_eq!(decoded.to_canonical_bytes().expect("re-encode"), bytes);
    }

    #[test]
    fn identity_absent_stays_absent() {
        // A legacy manifest without the extension key decodes with no
        // identity; root comparison treats that as incomplete.
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
    fn identity_extension_rejects_wrong_shape() {
        let mut manifest = sample_manifest();
        manifest.extensions.insert(
            EXECUTION_IDENTITY_EXTENSION.to_string(),
            CborValue::Bytes(vec![1, 2, 3]),
        );
        let bytes = manifest.to_canonical_bytes().expect("manifest encodes");
        let error = RunManifest::from_canonical_bytes(&bytes)
            .expect_err("wrong-length identity must be rejected");
        assert!(matches!(error, CborError::MalformedManifest(_)));

        let mut manifest = sample_manifest();
        manifest.extensions.insert(
            EXECUTION_IDENTITY_EXTENSION.to_string(),
            CborValue::Unsigned(7),
        );
        let bytes = manifest.to_canonical_bytes().expect("manifest encodes");
        let error = RunManifest::from_canonical_bytes(&bytes)
            .expect_err("non-byte identity must be rejected");
        assert!(matches!(error, CborError::MalformedManifest(_)));
    }
}
