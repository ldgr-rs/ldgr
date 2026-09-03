//! Interchange envelope with magic, version and fidelity.
//! Bytes are `magic(4) || version_be(4) || json`; hash is BLAKE3 over them.

use crate::AdapterError;
use ledger_format::{ActorId, EntryHash, EntryKind, FaultSpec};
use serde::{Deserialize, Serialize};

pub const ENVELOPE_MAGIC: [u8; 4] = *b"LDGR";
pub const ENVELOPE_VERSION: u32 = 1;

/// Deterministic fidelity of an ingested trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Fidelity {
    BitExact,
    LineageOnly,
}

impl Fidelity {
    pub(crate) fn as_u64(self) -> u64 {
        match self {
            Self::BitExact => 0,
            Self::LineageOnly => 1,
        }
    }

    pub(crate) fn from_u64(v: u64) -> Result<Self, AdapterError> {
        match v {
            0 => Ok(Self::BitExact),
            1 => Ok(Self::LineageOnly),
            _ => Err(AdapterError::InvalidHeader),
        }
    }
}

/// Envelope header carried outside the JSON body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub media_type: String,
    pub emitter: String,
}

impl EnvelopeHeader {
    pub fn new(media_type: String, emitter: String) -> Self {
        Self {
            magic: ENVELOPE_MAGIC,
            version: ENVELOPE_VERSION,
            media_type,
            emitter,
        }
    }
}

impl Default for EnvelopeHeader {
    fn default() -> Self {
        Self::new(String::new(), String::new())
    }
}

/// Mapping from external type to journal kind with fidelity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryMapping {
    pub kind: EntryKindSerde,
    pub external_type: String,
    pub fidelity: Fidelity,
}

/// Newtype around `EntryKind` so callers can store the full variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryKindSerde(pub EntryKind);

impl From<EntryKind> for EntryKindSerde {
    fn from(k: EntryKind) -> Self {
        Self(k)
    }
}

impl From<EntryKindSerde> for EntryKind {
    fn from(s: EntryKindSerde) -> Self {
        s.0
    }
}

/// The interchange envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterchangeEnvelope {
    pub header: EnvelopeHeader,
    pub body: Vec<EntryMapping>,
}

// --- JSON representation with full fidelity ---

/// Fault spec as stored in JSON. Mirrors `ledger_format::FaultSpec` with
/// serde so the wire preserves the exact variant and its fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum FaultSpecSerde {
    Drop,
    Delay { ticks: u64 },
    Partition { src: u32, dst: u32 },
    Crash,
    Corrupt,
    CrashState(u64),
    Duplicate,
}

impl From<FaultSpec> for FaultSpecSerde {
    fn from(f: FaultSpec) -> Self {
        match f {
            FaultSpec::Drop => Self::Drop,
            FaultSpec::Delay { ticks } => Self::Delay { ticks },
            FaultSpec::Partition { src, dst } => Self::Partition {
                src: src.0,
                dst: dst.0,
            },
            FaultSpec::Crash => Self::Crash,
            FaultSpec::Corrupt => Self::Corrupt,
            FaultSpec::CrashState(s) => Self::CrashState(s),
            FaultSpec::Duplicate => Self::Duplicate,
        }
    }
}

impl From<FaultSpecSerde> for FaultSpec {
    fn from(f: FaultSpecSerde) -> Self {
        match f {
            FaultSpecSerde::Drop => Self::Drop,
            FaultSpecSerde::Delay { ticks } => Self::Delay { ticks },
            FaultSpecSerde::Partition { src, dst } => Self::Partition {
                src: ActorId(src),
                dst: ActorId(dst),
            },
            FaultSpecSerde::Crash => Self::Crash,
            FaultSpecSerde::Corrupt => Self::Corrupt,
            FaultSpecSerde::CrashState(s) => Self::CrashState(s),
            FaultSpecSerde::Duplicate => Self::Duplicate,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct JsonMapping {
    kind_tag: u64,
    external_type: String,
    fidelity: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generator: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    replay: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fault: Option<FaultSpecSerde>,
}

#[derive(Serialize, Deserialize)]
struct JsonEnvelope {
    media_type: String,
    emitter: String,
    body: Vec<JsonMapping>,
}

impl InterchangeEnvelope {
    pub fn new(header: EnvelopeHeader, body: Vec<EntryMapping>) -> Self {
        Self { header, body }
    }

    /// Aggregate fidelity. Any `LineageOnly` entry taints the envelope.
    pub fn fidelity(&self) -> Fidelity {
        if self
            .body
            .iter()
            .any(|m| m.fidelity == Fidelity::LineageOnly)
        {
            Fidelity::LineageOnly
        } else {
            Fidelity::BitExact
        }
    }

    /// Canonical bytes: `magic || version_be || json`.
    ///
    /// The JSON body carries only kind tags, external types, and fidelity;
    /// it embeds no hashes, so hash wire framing does not apply here. Hex
    /// and JSON layers stay raw by contract.
    ///
    /// # Errors
    /// Returns `AdapterError::Serialization` if JSON serialization fails.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, AdapterError> {
        let json_body = self.body.iter().map(mapping_to_json).collect::<Vec<_>>();
        let je = JsonEnvelope {
            media_type: self.header.media_type.clone(),
            emitter: self.header.emitter.clone(),
            body: json_body,
        };
        let json = serde_json::to_vec(&je)?;
        let mut out = Vec::with_capacity(8 + json.len());
        out.extend_from_slice(&self.header.magic);
        out.extend_from_slice(&self.header.version.to_be_bytes());
        out.extend_from_slice(&json);
        Ok(out)
    }

    /// Decode from `to_canonical_bytes` output.
    ///
    /// # Errors
    /// Returns `InvalidHeader` for magic mismatch, `UnsupportedVersion`
    /// for version mismatch, or `Serialization` for malformed JSON or
    /// missing structured fields.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AdapterError> {
        if bytes.len() < 8 {
            return Err(AdapterError::InvalidHeader);
        }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[0..4]);
        if magic != ENVELOPE_MAGIC {
            return Err(AdapterError::InvalidHeader);
        }
        let mut vbytes = [0u8; 4];
        vbytes.copy_from_slice(&bytes[4..8]);
        let version = u32::from_be_bytes(vbytes);
        if version != ENVELOPE_VERSION {
            return Err(AdapterError::UnsupportedVersion(version));
        }
        let json = &bytes[8..];
        let je: JsonEnvelope = serde_json::from_slice(json)?;
        let header = EnvelopeHeader {
            magic,
            version,
            media_type: je.media_type,
            emitter: je.emitter,
        };
        let mut body = Vec::with_capacity(je.body.len());
        for jm in je.body {
            let kind = json_to_kind(&jm)?;
            let fidelity = Fidelity::from_u64(jm.fidelity)?;
            body.push(EntryMapping {
                kind: EntryKindSerde(kind),
                external_type: jm.external_type,
                fidelity,
            });
        }
        Ok(Self { header, body })
    }

    /// Content-addressed BLAKE3 hash over `to_canonical_bytes`.
    ///
    /// The hash is deterministic: same body and header yield identical
    /// bytes and identical hash. Useful for deduplication and lineage.
    pub fn envelope_hash(&self) -> Result<EntryHash, AdapterError> {
        let bytes = self.to_canonical_bytes()?;
        Ok(EntryHash(*blake3::hash(&bytes).as_bytes()))
    }
}

// --- conversion helpers ---

fn mapping_to_json(m: &EntryMapping) -> JsonMapping {
    let kind = m.kind.0;
    let tag = kind.tag();
    // v2 kinds are plain tags; structured data lives in typed payloads, so
    // the envelope carries no kind-embedded fields.
    let (stream, generator, replay, fault) = (None, None, None, None);
    JsonMapping {
        kind_tag: tag,
        external_type: m.external_type.clone(),
        fidelity: m.fidelity.as_u64(),
        stream,
        generator,
        replay,
        fault,
    }
}

fn json_to_kind(jm: &JsonMapping) -> Result<EntryKind, AdapterError> {
    EntryKind::try_from(jm.kind_tag).map_err(|_| AdapterError::InvalidHeader)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_kinds() -> Vec<EntryKind> {
        vec![
            EntryKind::Spawn,
            EntryKind::Block,
            EntryKind::Wake,
            EntryKind::TimerSet,
            EntryKind::TimerFire,
            EntryKind::ClockRead,
            EntryKind::Send,
            EntryKind::Recv,
            EntryKind::FsWrite,
            EntryKind::FsFsync,
            EntryKind::FsRead,
            EntryKind::RngDraw,
            EntryKind::Outcome,
            EntryKind::Assert,
            EntryKind::Snapshot,
            EntryKind::Epoch,
            EntryKind::InputStep,
            EntryKind::CapRequest,
            EntryKind::CapGrant,
            EntryKind::CapInvoke,
            EntryKind::CapRevoke,
            EntryKind::Fault,
            EntryKind::StepBegin,
            EntryKind::StepEnd,
        ]
    }

    #[test]
    fn roundtrip_all_kinds() {
        for kind in all_kinds() {
            let env = InterchangeEnvelope::new(
                EnvelopeHeader::new("test".into(), "test".into()),
                vec![EntryMapping {
                    kind: kind.into(),
                    external_type: "x".into(),
                    fidelity: Fidelity::BitExact,
                }],
            );
            let bytes = env.to_canonical_bytes().unwrap();
            let decoded = InterchangeEnvelope::from_bytes(&bytes).unwrap();
            assert_eq!(env, decoded, "roundtrip failed for {:?}", kind);
            assert_eq!(decoded.body[0].kind.0, kind);
        }
    }

    #[test]
    fn envelope_hash_deterministic() {
        let env = InterchangeEnvelope::new(
            EnvelopeHeader::new("t".into(), "e".into()),
            vec![EntryMapping {
                kind: EntryKind::Outcome.into(),
                external_type: "otel.span".into(),
                fidelity: Fidelity::BitExact,
            }],
        );
        let h1 = env.envelope_hash().unwrap();
        let h2 = env.envelope_hash().unwrap();
        assert_eq!(h1, h2);
        // Different kind yields a different hash.
        let env2 = InterchangeEnvelope::new(
            EnvelopeHeader::new("t".into(), "e".into()),
            vec![EntryMapping {
                kind: EntryKind::Send.into(),
                external_type: "x".into(),
                fidelity: Fidelity::BitExact,
            }],
        );
        assert_ne!(h1, env2.envelope_hash().unwrap());
    }

    #[test]
    fn unknown_kind_tag_errors() {
        // An unknown kind tag fails closed instead of mapping to a kind.
        let je = JsonEnvelope {
            media_type: "t".into(),
            emitter: "e".into(),
            body: vec![JsonMapping {
                kind_tag: 99,
                external_type: "x".into(),
                fidelity: 0,
                stream: None,
                generator: None,
                replay: None,
                fault: None,
            }],
        };
        let json = serde_json::to_vec(&je).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ENVELOPE_MAGIC);
        bytes.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
        bytes.extend_from_slice(&json);
        let err = InterchangeEnvelope::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, AdapterError::InvalidHeader));
    }
}
