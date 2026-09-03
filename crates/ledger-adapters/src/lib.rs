#![deny(unsafe_code)]

//! OTel ingest adapters: external traces become content-addressed entries.
//! Fidelity is structural (`IngestedJournal`); check `is_certifiable()`
//! before producing certificates.

pub mod envelope;
pub mod otel;

pub use envelope::{EntryMapping, EnvelopeHeader, Fidelity, InterchangeEnvelope};
pub use otel::{
    OtelEvent, OtelIngestConfig, OtelSpan, ingest_otel_dedup, ingest_otel_enveloped,
    ingest_otel_file, ingest_otel_file_with_config, ingest_otel_with_fidelity, topo_order_spans,
};

use ledger_format::{EntryKind, EntryPayload};
use ledger_journal::{Journal, JournalError};

/// Adapter translation errors.
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    /// Envelope magic or structure is invalid.
    #[error("invalid envelope header")]
    InvalidHeader,
    /// Envelope version is not supported.
    #[error("unsupported envelope version {0}")]
    UnsupportedVersion(u32),
    /// Fidelity expectation was not met.
    #[error("fidelity mismatch")]
    FidelityMismatch,
    /// Envelope JSON serialization or deserialization failed.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    /// A mapping lacked a field its entry kind requires.
    #[error("invalid mapping: {0}")]
    InvalidMapping(&'static str),
    /// The OTel NDJSON input could not be read from disk.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The span batch exceeded the configured ingest budget.
    #[error("max_spans exceeded: {actual} > {limit}")]
    SpanLimitExceeded {
        /// Number of spans received.
        actual: usize,
        /// Configured `OtelIngestConfig::max_spans`.
        limit: usize,
    },
    /// One NDJSON span line failed to parse; the 1-based line number is kept.
    #[error("json parse error at line {line}: {source}")]
    SpanParse {
        /// 1-based line number of the offending record.
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    /// Cycle detected in parent edges; trail is bounded diagnostic ids.
    #[error("cycle detected: {trail:?}")]
    CycleDetected {
        /// Bounded trail of un-emitted span ids, capped at 32.
        trail: Vec<String>,
    },
    /// File exceeds total byte budget.
    #[error("file too large: limit {limit} bytes")]
    FileTooLarge {
        /// Configured `OtelIngestConfig::max_bytes`.
        limit: usize,
    },
    /// One NDJSON line exceeds the per-line byte budget.
    #[error("line too large at line {line}: limit {limit} bytes")]
    LineTooLarge {
        /// 1-based line number.
        line: usize,
        /// Configured `OtelIngestConfig::max_line_bytes`.
        limit: usize,
    },
    /// Span attributes exceed configured limits.
    #[error("attribute limit exceeded at span {span_index}: {reason}")]
    AttributeLimitExceeded {
        /// Index of offending span in the input batch.
        span_index: usize,
        /// Human-readable reason.
        reason: String,
    },
    /// Underlying journal rejected an append.
    #[error("journal error: {0}")]
    Journal(#[from] JournalError),
}

/// Content-addressed ingest result that carries fidelity structurally.
/// Check `is_certifiable()` before producing certificates.
#[derive(Debug, Clone)]
pub struct IngestedJournal {
    /// The content-addressed journal.
    pub journal: Journal,
    /// Fidelity of the source trace.
    pub fidelity: Fidelity,
    /// Envelope that produced the journal (for hash/lineage).
    pub envelope: InterchangeEnvelope,
}

impl IngestedJournal {
    /// Create a new ingested journal. Marks the journal with an `Epoch`
    /// entry when fidelity is `LineageOnly` so downstream readers that
    /// only have the `Journal` can detect it.
    pub fn new(
        mut journal: Journal,
        fidelity: Fidelity,
        envelope: InterchangeEnvelope,
    ) -> Result<Self, AdapterError> {
        mark_fidelity(&mut journal, fidelity)?;
        Ok(Self {
            journal,
            fidelity,
            envelope,
        })
    }

    /// Whether this journal may be used to produce certificates.
    /// Only `BitExact` journals are certifiable.
    pub fn is_certifiable(&self) -> bool {
        self.fidelity == Fidelity::BitExact
    }

    /// Content-addressed envelope hash.
    pub fn envelope_hash(&self) -> Result<ledger_format::EntryHash, AdapterError> {
        self.envelope.envelope_hash()
    }

    /// Assert certifiable or return `FidelityMismatch`.
    pub fn require_certifiable(&self) -> Result<(), AdapterError> {
        if self.is_certifiable() {
            Ok(())
        } else {
            Err(AdapterError::FidelityMismatch)
        }
    }
}

/// Append a fidelity marker when `LineageOnly`.
pub(crate) fn mark_fidelity(journal: &mut Journal, fidelity: Fidelity) -> Result<(), AdapterError> {
    if fidelity == Fidelity::LineageOnly {
        journal
            .append(
                EntryKind::Epoch,
                ledger_format::ActorId(0),
                [],
                EntryPayload::Epoch(ledger_format::EpochPayload { epoch: 0 }),
            )
            .map_err(AdapterError::Journal)?;
    }
    Ok(())
}
