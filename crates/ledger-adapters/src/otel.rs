// ledger-lint:allow:std::fs:: (host-side adapters read trace files on disk)

//! OTel span ingest with Layer-A lineage pipeline.
//!
//! Each span becomes one `Outcome` entry with `Text(name)` and each
//! event becomes a `Send` entry. Fidelity is carried structurally via
//! `IngestedJournal`; lineage-only ingests also receive an `Epoch`
//! marker so a bare `Journal` can still be checked.
//!
//! This module implements a true Layer-A lineage pipeline:
//! - content-addressed deduplication by the full-span content hash
//!   (`span_content_hash`: trace_id, span_id, name, parent_span_id, events,
//!   attributes) via `HashMap<Hash, ()>` so duplicate traces execute once,
//! - parent causality preservation via topo ordering, child before parent
//!   still resolves,
//! - canonical topological ordering with bounded cycle diagnostics,
//! - fidelity enforcement and attribute limits,
//! - host-daemon file ingest with streaming caps.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::path::Path;

use crate::envelope::{EntryMapping, EnvelopeHeader, Fidelity, InterchangeEnvelope};
use crate::{AdapterError, IngestedJournal, mark_fidelity};
use ledger_format::{EntryKind, Hash, Payload};
use ledger_journal::Journal;

/// An OTel event attached to a span.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OtelEvent {
    pub name: String,
}

/// An OTel span with trace context and optional parent for causality.
///
/// `parent_span_id` preserves OTel causality in the journal: when set,
/// the child's journal entry includes the parent entry's hash as an
/// observed parent. `attributes` holds span attributes for limit
/// enforcement and dedup hashing. Serde defaults keep JSON without the
/// field parsing.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OtelSpan {
    pub trace_id: String,
    pub span_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    pub name: String,
    pub events: Vec<OtelEvent>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

/// Config for the Layer-A dedup pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtelIngestConfig {
    /// Desired fidelity.
    pub fidelity: Fidelity,
    /// Whether to deduplicate spans by content hash.
    pub dedup: bool,
    /// Maximum number of spans accepted.
    pub max_spans: usize,
    /// Maximum total bytes for file ingest (default 256 MiB).
    pub max_bytes: usize,
    /// Maximum bytes per NDJSON line (default 1 MiB).
    pub max_line_bytes: usize,
    /// Maximum attributes per span (default 4096).
    pub max_attributes_per_span: usize,
    /// Maximum total attribute bytes per span (default 256 KiB).
    pub max_attribute_bytes_total: usize,
}

impl Default for OtelIngestConfig {
    fn default() -> Self {
        Self {
            fidelity: Fidelity::LineageOnly,
            dedup: true,
            max_spans: 100_000,
            max_bytes: 256 * 1024 * 1024,
            max_line_bytes: 1024 * 1024,
            max_attributes_per_span: 4096,
            max_attribute_bytes_total: 256 * 1024,
        }
    }
}

impl OtelIngestConfig {
    /// Create a new config with defaults for byte and attribute limits.
    pub fn new(fidelity: Fidelity, dedup: bool, max_spans: usize) -> Self {
        Self {
            fidelity,
            dedup,
            max_spans,
            ..Self::default()
        }
    }
}

/// Fold one length-prefixed field into the hasher as `len_be(u64) || bytes`
/// so concatenated fields stay unambiguous.
fn hash_field(hasher: &mut blake3::Hasher, field: &[u8]) {
    hasher.update(&(field.len() as u64).to_be_bytes());
    hasher.update(field);
}

/// Compute the dedup content hash over the full span identity:
/// length-prefixed `trace_id`, `span_id`, `name`, then the
/// `parent_span_id` state (absent marker byte, or present marker byte plus
/// length-prefixed value), then a canonical digest of the event sequence
/// and sorted attributes. Length prefixes keep the encoding injective;
/// identical span content always yields an identical hash.
fn span_content_hash(span: &OtelSpan) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, span.trace_id.as_bytes());
    hash_field(&mut hasher, span.span_id.as_bytes());
    hash_field(&mut hasher, span.name.as_bytes());
    match &span.parent_span_id {
        Some(parent) => {
            hasher.update(&[1]);
            hash_field(&mut hasher, parent.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    let mut events = blake3::Hasher::new();
    for event in &span.events {
        hash_field(&mut events, event.name.as_bytes());
    }
    hash_field(&mut hasher, events.finalize().as_bytes());
    // attributes sorted via BTreeMap for determinism
    let mut attr_hasher = blake3::Hasher::new();
    for (k, v) in &span.attributes {
        hash_field(&mut attr_hasher, k.as_bytes());
        hash_field(&mut attr_hasher, v.as_bytes());
    }
    hash_field(&mut hasher, attr_hasher.finalize().as_bytes());
    *hasher.finalize().as_bytes()
}

/// True if any span references a `parent_span_id` that is not present in
/// the batch-wide set of span ids. Batch-wide membership means forward
/// references never trigger this check; they resolve after topological
/// reordering. A dangling parent makes the VC non-deterministic, so the
/// batch is not BitExact-certifiable.
fn has_missing_parent(spans: &[OtelSpan]) -> bool {
    let ids: HashSet<&str> = spans.iter().map(|s| s.span_id.as_str()).collect();
    spans.iter().any(|s| {
        if let Some(parent) = &s.parent_span_id {
            !ids.contains(parent.as_str())
        } else {
            false
        }
    })
}

/// Order span indices dependency-first so every parent precedes its children.
///
/// Kahn's algorithm with an input-order tie-break: among spans whose
/// batch-local parents are all emitted, the lowest input index goes next.
/// A `parent_span_id` absent from the batch counts as a root. Duplicate
/// `span_id`s bind to their first occurrence; later occurrences cannot
/// serve as parents.
///
/// Cycle members, including self-parents, never satisfy the emission rule;
/// they are appended in input order after the acyclic prefix, so the
/// result always has `spans.len()` entries.
pub fn topo_order_spans(spans: &[OtelSpan]) -> Vec<usize> {
    let (mut order, emitted) = topo_order_with_count(spans);
    if emitted < spans.len() {
        let done: HashSet<usize> = order.iter().copied().collect();
        for i in 0..spans.len() {
            if !done.contains(&i) {
                order.push(i);
            }
        }
    }
    order
}

/// Crate-private ordering helper built on `kahn_emission`.
///
/// Returns the dependency-first emission order and the emitted count.
/// Callers must check `emitted != spans.len()` to detect cycles.
pub(crate) fn topo_order_with_count(spans: &[OtelSpan]) -> (Vec<usize>, usize) {
    kahn_emission(spans)
}

/// Kahn emission over batch-local parent edges.
///
/// Returns the dependency-first emission order plus the emitted count;
/// `emitted < spans.len()` means at least one parent cycle exists.
fn kahn_emission(spans: &[OtelSpan]) -> (Vec<usize>, usize) {
    let n = spans.len();
    let mut first_of_id: HashMap<&str, usize> = HashMap::with_capacity(n);
    for (i, span) in spans.iter().enumerate() {
        first_of_id.entry(span.span_id.as_str()).or_insert(i);
    }
    // children lists receive pushes in ascending input order, which is
    // exactly the tie-break order Kahn's ready queue needs.
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut pending_parents: Vec<usize> = vec![0; n];
    for (i, span) in spans.iter().enumerate() {
        let parent_idx = span
            .parent_span_id
            .as_deref()
            .and_then(|parent| first_of_id.get(parent));
        if let Some(&p) = parent_idx {
            children[p].push(i);
            pending_parents[i] += 1;
        }
    }
    let mut ready: BinaryHeap<Reverse<usize>> = (0..n)
        .filter(|&i| pending_parents[i] == 0)
        .map(Reverse)
        .collect();
    let mut order = Vec::with_capacity(n);
    while let Some(Reverse(i)) = ready.pop() {
        order.push(i);
        for &child in &children[i] {
            pending_parents[child] -= 1;
            if pending_parents[child] == 0 {
                ready.push(Reverse(child));
            }
        }
    }
    let emitted = order.len();
    (order, emitted)
}

/// Bounded diagnostic trail for cycles: ids of un-emitted spans capped at 32.
fn bounded_trail(spans: &[OtelSpan], order: &[usize]) -> Vec<String> {
    let emitted: HashSet<usize> = order.iter().copied().collect();
    let mut trail = Vec::new();
    for (idx, span) in spans.iter().enumerate() {
        if !emitted.contains(&idx) {
            trail.push(span.span_id.clone());
            if trail.len() >= 32 {
                break;
            }
        }
    }
    trail
}

/// Enforce attribute count and total bytes limits for a batch.
///
/// Returns `AttributeLimitExceeded` on first violation.
fn check_attribute_limits(
    spans: &[OtelSpan],
    config: &OtelIngestConfig,
) -> Result<(), AdapterError> {
    for (idx, span) in spans.iter().enumerate() {
        if span.attributes.len() > config.max_attributes_per_span {
            return Err(AdapterError::AttributeLimitExceeded {
                span_index: idx,
                reason: format!(
                    "attribute count {} exceeds limit {}",
                    span.attributes.len(),
                    config.max_attributes_per_span
                ),
            });
        }
        let total_bytes: usize = span.attributes.iter().map(|(k, v)| k.len() + v.len()).sum();
        if total_bytes > config.max_attribute_bytes_total {
            return Err(AdapterError::AttributeLimitExceeded {
                span_index: idx,
                reason: format!(
                    "attribute bytes {total_bytes} exceeds limit {}",
                    config.max_attribute_bytes_total
                ),
            });
        }
    }
    Ok(())
}

/// Validate attributes using default limits for legacy paths.
fn check_attributes_with_defaults(spans: &[OtelSpan]) -> Result<(), AdapterError> {
    let cfg = OtelIngestConfig::default();
    check_attribute_limits(spans, &cfg)
}

/// Ingest with explicit fidelity.
///
/// The `fidelity` param is honoured: `LineageOnly` journals receive an
/// `Epoch` marker (`Text("lineage-only")`), `BitExact` journals do not.
/// The marker makes `Journal`-only consumers able to reject lineage-only
/// data even if the wrapper is stripped.
///
/// Validation uses the shared ordering helper so forward parent edges
/// resolve. Cycles are rejected with `CycleDetected` and a bounded trail.
pub fn ingest_otel_with_fidelity(
    spans: Vec<OtelSpan>,
    fidelity: Fidelity,
) -> Result<Journal, AdapterError> {
    check_attributes_with_defaults(&spans)?;
    if fidelity == Fidelity::BitExact && has_missing_parent(&spans) {
        return Err(AdapterError::FidelityMismatch);
    }
    let (order, emitted) = topo_order_with_count(&spans);
    if emitted != spans.len() {
        let trail = bounded_trail(&spans, &order);
        return Err(AdapterError::CycleDetected { trail });
    }
    let mut journal = Journal::new();
    // Preserve causality via parent lookup; first-wins binding for duplicate ids.
    let mut span_id_to_hash: HashMap<String, Hash> = HashMap::new();
    for &idx in &order {
        let span = &spans[idx];
        let observed = span
            .parent_span_id
            .as_ref()
            .and_then(|pid| span_id_to_hash.get(pid).copied())
            .map(|h| vec![h])
            .unwrap_or_default();
        let hash = journal
            .append(
                EntryKind::Outcome,
                1,
                observed,
                Payload::Text(span.name.clone()),
            )
            .map_err(AdapterError::Journal)?;
        span_id_to_hash.entry(span.span_id.clone()).or_insert(hash);
        for event in &span.events {
            journal
                .append(EntryKind::Send, 1, [], Payload::Text(event.name.clone()))
                .map_err(AdapterError::Journal)?;
        }
    }
    mark_fidelity(&mut journal, fidelity)?;
    Ok(journal)
}

/// Ingest and return a structural `IngestedJournal` with envelope.
///
/// The envelope records each span/event as an `EntryMapping` with the
/// caller-supplied fidelity. The envelope hash is content-addressed
/// (BLAKE3 over canonical bytes) and can be used for dedup. Callers
/// must check `is_certifiable()` before producing certificates.
///
/// Validation uses the shared ordering helper so forward parent edges
/// resolve. Cycles are rejected with `CycleDetected` and a bounded trail.
pub fn ingest_otel_enveloped(
    spans: Vec<OtelSpan>,
    fidelity: Fidelity,
) -> Result<IngestedJournal, AdapterError> {
    check_attributes_with_defaults(&spans)?;
    if fidelity == Fidelity::BitExact && has_missing_parent(&spans) {
        return Err(AdapterError::FidelityMismatch);
    }
    let (order, emitted) = topo_order_with_count(&spans);
    if emitted != spans.len() {
        let trail = bounded_trail(&spans, &order);
        return Err(AdapterError::CycleDetected { trail });
    }
    let mut journal = Journal::new();
    let mut mappings = Vec::new();
    let mut span_id_to_hash: HashMap<String, Hash> = HashMap::new();
    for &idx in &order {
        let span = &spans[idx];
        let observed = span
            .parent_span_id
            .as_ref()
            .and_then(|pid| span_id_to_hash.get(pid).copied())
            .map(|h| vec![h])
            .unwrap_or_default();
        let hash = journal
            .append(
                EntryKind::Outcome,
                1,
                observed,
                Payload::Text(span.name.clone()),
            )
            .map_err(AdapterError::Journal)?;
        span_id_to_hash.entry(span.span_id.clone()).or_insert(hash);
        mappings.push(EntryMapping {
            kind: EntryKind::Outcome.into(),
            external_type: "otel.span".to_string(),
            fidelity,
        });
        for event in &span.events {
            journal
                .append(EntryKind::Send, 1, [], Payload::Text(event.name.clone()))
                .map_err(AdapterError::Journal)?;
            mappings.push(EntryMapping {
                kind: EntryKind::Send.into(),
                external_type: "otel.event".to_string(),
                fidelity,
            });
        }
    }
    let envelope = InterchangeEnvelope::new(
        EnvelopeHeader::new("application/otel".to_string(), "otel-ingest".to_string()),
        mappings,
    );
    IngestedJournal::new(journal, fidelity, envelope)
}

/// Layer-A lineage pipeline with content-addressed dedup and fidelity enforcement.
///
/// Deduplicates spans by the full-span content hash (`span_content_hash`:
/// trace_id, span_id, name, parent_span_id, events, attributes) using
/// `HashMap<Hash, ()>` so duplicate traces (LazyMOP 99% dup) execute once.
/// Dedup keeps the first occurrence in input order.
///
/// Causality is preserved regardless of input order: spans are reordered
/// dependency-first via the shared helper before the journal build, so a
/// child that appears before its parent still receives the parent entry
/// hash as an observed parent. Parent lookup binds to the first occurrence
/// of a duplicated `span_id`. Cycles are rejected with `CycleDetected`.
///
/// Fidelity is enforced: `BitExact` requires every referenced
/// `parent_span_id` to exist somewhere in the batch (forward references
/// resolve after reordering); otherwise returns
/// `AdapterError::FidelityMismatch`.
///
/// Determinism: same spans in same order produce the same journal root and
/// same envelope hash. Reordering an acyclic batch changes the journal only
/// where spans are causally independent; a dependency chain yields the
/// identical journal under any input permutation.
pub fn ingest_otel_dedup(
    spans: Vec<OtelSpan>,
    config: OtelIngestConfig,
) -> Result<IngestedJournal, AdapterError> {
    if spans.len() > config.max_spans {
        return Err(AdapterError::SpanLimitExceeded {
            actual: spans.len(),
            limit: config.max_spans,
        });
    }
    check_attribute_limits(&spans, &config)?;

    // Dedup phase: content-addressed by full-span hash.
    let deduped: Vec<OtelSpan> = if config.dedup {
        let mut seen: HashSet<Hash> = HashSet::new();
        let mut out = Vec::with_capacity(spans.len());
        for span in spans {
            let h = span_content_hash(&span);
            if seen.contains(&h) {
                continue;
            }
            seen.insert(h);
            out.push(span);
        }
        out
    } else {
        spans
    };

    // Attribute limits after dedup already checked pre-dedup, but deduped
    // retains same attributes, so no second check needed. Still ensure
    // post-dedup length respects cap (dedup can only shrink).
    // Cycle check via shared helper.
    let (order, emitted) = topo_order_with_count(&deduped);
    if emitted != deduped.len() {
        let trail = bounded_trail(&deduped, &order);
        return Err(AdapterError::CycleDetected { trail });
    }
    if config.fidelity == Fidelity::BitExact && has_missing_parent(&deduped) {
        return Err(AdapterError::FidelityMismatch);
    }

    // Journal build with causality.
    let mut journal = Journal::new();
    let mut mappings = Vec::new();
    let mut span_id_to_hash: HashMap<String, Hash> = HashMap::new();

    for &idx in &order {
        let span = &deduped[idx];
        let observed: Vec<Hash> = span
            .parent_span_id
            .as_ref()
            .and_then(|pid| span_id_to_hash.get(pid).copied())
            .map(|h| vec![h])
            .unwrap_or_default();
        let hash = journal
            .append(
                EntryKind::Outcome,
                1,
                observed,
                Payload::Text(span.name.clone()),
            )
            .map_err(AdapterError::Journal)?;
        // First occurrence of a span_id owns parent resolution, matching
        // topo ordering binding.
        span_id_to_hash.entry(span.span_id.clone()).or_insert(hash);
        mappings.push(EntryMapping {
            kind: EntryKind::Outcome.into(),
            external_type: "otel.span".to_string(),
            fidelity: config.fidelity,
        });
        for event in &span.events {
            journal
                .append(EntryKind::Send, 1, [], Payload::Text(event.name.clone()))
                .map_err(AdapterError::Journal)?;
            mappings.push(EntryMapping {
                kind: EntryKind::Send.into(),
                external_type: "otel.event".to_string(),
                fidelity: config.fidelity,
            });
        }
    }

    let envelope = InterchangeEnvelope::new(
        EnvelopeHeader::new("application/otel".to_string(), "otel-ingest".to_string()),
        mappings,
    );
    IngestedJournal::new(journal, config.fidelity, envelope)
}

/// Host-daemon file ingest: read newline-delimited JSON OTel spans.
///
/// Each non-empty line must be a JSON `OtelSpan`. Blank lines are skipped.
/// The file is read via `std::fs` (host daemon path, not simulation code).
/// This is the one ambient I/O exception analogous to `TokioBackend`.
///
/// Default pipeline config is `OtelIngestConfig::default()` (dedup enabled,
/// `LineageOnly`). For `BitExact` callers, use `ingest_otel_dedup` directly
/// or `ingest_otel_file_with_config`.
///
/// # Errors
/// Returns `AdapterError` variants for I/O, JSON parse, limits, or cycles.
pub fn ingest_otel_file(path: &Path) -> Result<IngestedJournal, AdapterError> {
    ingest_otel_file_with_config(path, OtelIngestConfig::default())
}

/// File ingest with explicit config and streaming caps.
///
/// Uses `BufReader` plus `.take(max_bytes + 1)` to enforce total byte cap
/// without reading the whole file into memory. Enforces per-line byte cap,
/// total byte cap, and span cap mid-stream.
/// See `ingest_otel_file` for the host-daemon allowance.
pub fn ingest_otel_file_with_config(
    path: &Path,
    config: OtelIngestConfig,
) -> Result<IngestedJournal, AdapterError> {
    use std::fs::File;
    use std::io::{BufRead, BufReader, Read};

    let file = File::open(path)?;
    let take_limit = (config.max_bytes as u64).saturating_add(1);
    // BufReader over a Take to bound total bytes without reading whole file.
    let mut reader = BufReader::new(file.take(take_limit));
    let mut spans = Vec::new();
    let mut line = String::new();
    let mut line_number: usize = 0;
    let mut total_bytes: usize = 0;
    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line)?;
        if bytes_read == 0 {
            break;
        }
        line_number += 1;
        total_bytes = total_bytes.saturating_add(bytes_read);
        if total_bytes > config.max_bytes {
            return Err(AdapterError::FileTooLarge {
                limit: config.max_bytes,
            });
        }
        if bytes_read > config.max_line_bytes {
            return Err(AdapterError::LineTooLarge {
                line: line_number,
                limit: config.max_line_bytes,
            });
        }
        // Also guard trimmed length when newline handling differs.
        if line.len() > config.max_line_bytes {
            return Err(AdapterError::LineTooLarge {
                line: line_number,
                limit: config.max_line_bytes,
            });
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Enforce per-line byte cap on trimmed payload as well.
        if trimmed.len() > config.max_line_bytes {
            return Err(AdapterError::LineTooLarge {
                line: line_number,
                limit: config.max_line_bytes,
            });
        }
        let span: OtelSpan =
            serde_json::from_str(trimmed).map_err(|source| AdapterError::SpanParse {
                line: line_number,
                source,
            })?;
        spans.push(span);
        if spans.len() > config.max_spans {
            return Err(AdapterError::SpanLimitExceeded {
                actual: spans.len(),
                limit: config.max_spans,
            });
        }
    }
    ingest_otel_dedup(spans, config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Fidelity;
    use std::io::Write;

    fn sample_spans() -> Vec<OtelSpan> {
        vec![
            OtelSpan {
                trace_id: "trace1".into(),
                span_id: "span1".into(),
                parent_span_id: None,
                name: "op-a".into(),
                events: vec![OtelEvent { name: "ev1".into() }],
                ..Default::default()
            },
            OtelSpan {
                trace_id: "trace1".into(),
                span_id: "span2".into(),
                parent_span_id: None,
                name: "op-b".into(),
                events: vec![],
                ..Default::default()
            },
        ]
    }

    fn make_span(
        trace: &str,
        id: &str,
        parent: Option<&str>,
        name: &str,
        events: Vec<OtelEvent>,
    ) -> OtelSpan {
        OtelSpan {
            trace_id: trace.into(),
            span_id: id.into(),
            parent_span_id: parent.map(Into::into),
            name: name.into(),
            events,
            ..Default::default()
        }
    }

    fn config(fidelity: Fidelity, dedup: bool) -> OtelIngestConfig {
        OtelIngestConfig {
            fidelity,
            dedup,
            max_spans: 100,
            ..Default::default()
        }
    }

    fn outcome_count(journal: &Journal) -> usize {
        journal
            .entries()
            .filter(|e| e.data.kind == EntryKind::Outcome)
            .count()
    }

    #[test]
    fn otel_ingest_lineage_only_non_empty() {
        let journal = ingest_otel_with_fidelity(sample_spans(), Fidelity::LineageOnly).unwrap();
        assert!(!journal.is_empty());
        // Journal carries lineage-only marker.
        let has_epoch = journal.entries().any(|e| e.data.kind == EntryKind::Epoch);
        assert!(has_epoch, "lineage-only must carry Epoch marker");
        let kinds: Vec<EntryKind> = journal.entries().map(|e| e.data.kind).collect();
        assert!(kinds.contains(&EntryKind::Outcome));
    }

    #[test]
    fn otel_ingest_deterministic_root() {
        let a = ingest_otel_with_fidelity(sample_spans(), Fidelity::LineageOnly).unwrap();
        let b = ingest_otel_with_fidelity(sample_spans(), Fidelity::LineageOnly).unwrap();
        assert_eq!(a.root_hash(), b.root_hash());
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn otel_empty_input_empty_journal() {
        // Empty lineage-only still gets marker? For empty spans we still mark.
        // To keep empty journal empty for BitExact, lineage-only marker is added.
        // Check both behaviours.
        let journal_be = ingest_otel_with_fidelity(vec![], Fidelity::BitExact).unwrap();
        assert!(journal_be.is_empty());
        let journal_lo = ingest_otel_with_fidelity(vec![], Fidelity::LineageOnly).unwrap();
        // lineage-only empty is not empty due to marker, which is intentional for fidelity tracking.
        assert_eq!(journal_lo.len(), 1);
        assert_eq!(
            journal_lo.entries().next().unwrap().data.kind,
            EntryKind::Epoch
        );
    }

    #[test]
    fn fidelity_preserved_lineage_only() {
        // Different fidelity yields different journal (marker) and envelope fidelity.
        let spans = sample_spans();
        let j_lo = ingest_otel_with_fidelity(spans.clone(), Fidelity::LineageOnly).unwrap();
        let j_be = ingest_otel_with_fidelity(spans.clone(), Fidelity::BitExact).unwrap();
        assert_ne!(j_lo.root_hash(), j_be.root_hash());
        // Enveloped variant preserves fidelity structurally.
        let ing_lo = ingest_otel_enveloped(spans.clone(), Fidelity::LineageOnly).unwrap();
        let ing_be = ingest_otel_enveloped(spans, Fidelity::BitExact).unwrap();
        assert!(!ing_lo.is_certifiable());
        assert!(ing_be.is_certifiable());
        assert_eq!(ing_lo.fidelity, Fidelity::LineageOnly);
        assert_eq!(ing_be.fidelity, Fidelity::BitExact);
        ing_lo.require_certifiable().unwrap_err();
        ing_be.require_certifiable().unwrap();
    }

    #[test]
    fn fidelity_enforced_via_envelope() {
        let spans = sample_spans();
        let ing = ingest_otel_enveloped(spans, Fidelity::LineageOnly).unwrap();
        assert_eq!(ing.envelope.fidelity(), Fidelity::LineageOnly);
        assert!(!ing.is_certifiable());
    }

    #[test]
    fn enveloped_deterministic() {
        let spans = sample_spans();
        let a = ingest_otel_enveloped(spans.clone(), Fidelity::BitExact).unwrap();
        let b = ingest_otel_enveloped(spans, Fidelity::BitExact).unwrap();
        assert_eq!(a.journal.root_hash(), b.journal.root_hash());
        assert_eq!(
            a.envelope.envelope_hash().unwrap(),
            b.envelope.envelope_hash().unwrap()
        );
    }

    // --- New Layer-A pipeline tests ---

    #[test]
    fn dedup_removes_duplicate_spans() {
        let span = OtelSpan {
            trace_id: "t".into(),
            span_id: "s1".into(),
            parent_span_id: None,
            name: "op".into(),
            events: vec![],
            ..Default::default()
        };
        let spans = vec![span.clone(), span.clone(), span.clone()];
        let config = OtelIngestConfig {
            fidelity: Fidelity::BitExact,
            dedup: true,
            max_spans: 10,
            ..Default::default()
        };
        let ing = ingest_otel_dedup(spans, config).unwrap();
        // Only one Outcome entry, no marker for BitExact.
        assert_eq!(ing.journal.len(), 1);
        // Without dedup, three entries.
        let config_no_dedup = OtelIngestConfig {
            fidelity: Fidelity::BitExact,
            dedup: false,
            max_spans: 10,
            ..Default::default()
        };
        let ing2 = ingest_otel_dedup(
            vec![span.clone(), span.clone(), span.clone()],
            config_no_dedup,
        )
        .unwrap();
        assert_eq!(ing2.journal.len(), 3);
    }

    #[test]
    fn dedup_determinism() {
        let spans = vec![
            OtelSpan {
                trace_id: "t".into(),
                span_id: "s1".into(),
                parent_span_id: None,
                name: "op-a".into(),
                events: vec![],
                ..Default::default()
            },
            OtelSpan {
                trace_id: "t".into(),
                span_id: "s1".into(),
                parent_span_id: None,
                name: "op-a".into(),
                events: vec![],
                ..Default::default()
            },
            OtelSpan {
                trace_id: "t".into(),
                span_id: "s2".into(),
                parent_span_id: None,
                name: "op-b".into(),
                events: vec![],
                ..Default::default()
            },
        ];
        let config = OtelIngestConfig {
            fidelity: Fidelity::LineageOnly,
            dedup: true,
            max_spans: 10,
            ..Default::default()
        };
        let a = ingest_otel_dedup(spans.clone(), config).unwrap();
        let b = ingest_otel_dedup(spans, config).unwrap();
        assert_eq!(a.journal.root_hash(), b.journal.root_hash());
        assert_eq!(
            a.envelope.envelope_hash().unwrap(),
            b.envelope.envelope_hash().unwrap()
        );
        assert_eq!(a.envelope_hash().unwrap(), b.envelope_hash().unwrap());
        assert_eq!(a.is_certifiable(), b.is_certifiable());
    }

    #[test]
    fn fidelity_mismatch_on_missing_parent() {
        let spans = vec![OtelSpan {
            trace_id: "t".into(),
            span_id: "child".into(),
            parent_span_id: Some("missing-parent".into()),
            name: "child-op".into(),
            events: vec![],
            ..Default::default()
        }];
        let config_be = OtelIngestConfig {
            fidelity: Fidelity::BitExact,
            dedup: true,
            max_spans: 10,
            ..Default::default()
        };
        let err = ingest_otel_dedup(spans.clone(), config_be).unwrap_err();
        assert!(matches!(err, AdapterError::FidelityMismatch));
        // Same spans with LineageOnly should succeed.
        let config_lo = OtelIngestConfig {
            fidelity: Fidelity::LineageOnly,
            dedup: true,
            max_spans: 10,
            ..Default::default()
        };
        let ing = ingest_otel_dedup(spans, config_lo).unwrap();
        assert!(!ing.is_certifiable());
        assert_eq!(ing.fidelity, Fidelity::LineageOnly);
    }

    #[test]
    fn parent_causality_preserved() {
        let parent = OtelSpan {
            trace_id: "t".into(),
            span_id: "parent".into(),
            parent_span_id: None,
            name: "parent-op".into(),
            events: vec![],
            ..Default::default()
        };
        let child = OtelSpan {
            trace_id: "t".into(),
            span_id: "child".into(),
            parent_span_id: Some("parent".into()),
            name: "child-op".into(),
            events: vec![],
            ..Default::default()
        };
        let config = OtelIngestConfig {
            fidelity: Fidelity::LineageOnly,
            dedup: false,
            max_spans: 10,
            ..Default::default()
        };
        let ing = ingest_otel_dedup(vec![parent.clone(), child.clone()], config).unwrap();
        // Find entries by payload text.
        let entries: Vec<_> = ing.journal.entries().collect();
        let parent_entry = entries
            .iter()
            .find(|e| e.data.payload == Payload::Text("parent-op".into()))
            .unwrap();
        let child_entry = entries
            .iter()
            .find(|e| e.data.payload == Payload::Text("child-op".into()))
            .unwrap();
        // Child should have parent's hash in its parents.
        assert!(
            child_entry.data.parents.contains(&parent_entry.id),
            "child entry parents {:?} should contain parent id {:?}",
            child_entry.data.parents,
            parent_entry.id
        );
        // Vector clock of child should be greater on actor 1 than parent's.
        assert!(child_entry.vector_clock.get(1) > parent_entry.vector_clock.get(1));
    }

    #[test]
    fn topo_order_places_parents_first_with_input_tiebreak() {
        // Input order mid(0), root(1), leaf(2); dependency chain root<-mid<-leaf.
        let spans = vec![
            make_span("t", "mid", Some("root"), "m", vec![]),
            make_span("t", "root", None, "r", vec![]),
            make_span("t", "leaf", Some("mid"), "l", vec![]),
        ];
        assert_eq!(topo_order_spans(&spans), vec![1, 0, 2]);

        // Cycle x<->y cannot be emitted; acyclic z goes first and cycle
        // members trail in input order.
        let cyclic = vec![
            make_span("t", "x", Some("y"), "x", vec![]),
            make_span("t", "y", Some("x"), "y", vec![]),
            make_span("t", "z", None, "z", vec![]),
        ];
        assert_eq!(topo_order_spans(&cyclic), vec![2, 0, 1]);
    }

    #[test]
    fn reordered_batch_bitexact_succeeds_and_preserves_causality() {
        let parent = make_span("t", "p", None, "parent-op", vec![]);
        let child = make_span("t", "c", Some("p"), "child-op", vec![]);
        let cfg = config(Fidelity::BitExact, true);

        // Child before parent in input order: BitExact must succeed now that
        // forward references resolve via topological ordering.
        let reordered = ingest_otel_dedup(vec![child.clone(), parent.clone()], cfg).unwrap();
        assert!(reordered.is_certifiable());

        let entries: Vec<_> = reordered.journal.entries().collect();
        let parent_entry = entries
            .iter()
            .find(|e| e.data.payload == Payload::Text("parent-op".into()))
            .unwrap();
        let child_entry = entries
            .iter()
            .find(|e| e.data.payload == Payload::Text("child-op".into()))
            .unwrap();
        // The child entry carries the parent entry hash as observed parent,
        // even though the parent was appended after the child arrived.
        assert_eq!(child_entry.data.parents, vec![parent_entry.id]);
        assert!(child_entry.vector_clock.get(1) > parent_entry.vector_clock.get(1));

        // Same set in dependency-first order yields the identical journal.
        let sorted = ingest_otel_dedup(vec![parent, child], cfg).unwrap();
        assert_eq!(sorted.journal.root_hash(), reordered.journal.root_hash());
        assert_eq!(
            sorted.envelope_hash().unwrap(),
            reordered.envelope_hash().unwrap()
        );
    }

    #[test]
    fn dedup_key_changes_when_events_differ() {
        let plain = make_span("t", "s1", None, "op", vec![]);
        let with_event = make_span("t", "s1", None, "op", vec![OtelEvent { name: "ev".into() }]);
        let ing =
            ingest_otel_dedup(vec![plain, with_event], config(Fidelity::BitExact, true)).unwrap();
        // Old key (trace_id || span_id || name) collapsed these; both must
        // survive as Outcome entries.
        assert_eq!(outcome_count(&ing.journal), 2);
    }

    #[test]
    fn dedup_key_changes_when_parent_differs() {
        let root = make_span("t", "s1", None, "op", vec![]);
        let nested = make_span("t", "s1", Some("p"), "op", vec![]);
        let ing =
            ingest_otel_dedup(vec![root, nested], config(Fidelity::LineageOnly, true)).unwrap();
        assert_eq!(outcome_count(&ing.journal), 2);
    }

    #[test]
    fn cycle_rejected_with_bounded_trail() {
        let a = make_span("t", "a", Some("b"), "op-a", vec![]);
        let b = make_span("t", "b", Some("a"), "op-b", vec![]);
        // Both fidelities now reject cycles with CycleDetected.
        let err_be =
            ingest_otel_dedup(vec![a.clone(), b.clone()], config(Fidelity::BitExact, true))
                .unwrap_err();
        match err_be {
            AdapterError::CycleDetected { trail } => {
                assert!(trail.len() <= 32);
                assert!(trail.contains(&"a".to_string()) || trail.contains(&"b".to_string()));
            }
            other => panic!("expected CycleDetected, got {other:?}"),
        }
        let err_lo =
            ingest_otel_dedup(vec![a, b], config(Fidelity::LineageOnly, true)).unwrap_err();
        match err_lo {
            AdapterError::CycleDetected { trail } => {
                assert!(trail.len() <= 32);
            }
            other => panic!("expected CycleDetected for lineage, got {other:?}"),
        }
        // Legacy paths also reject cycles.
        let a2 = make_span("t", "a", Some("b"), "op-a", vec![]);
        let b2 = make_span("t", "b", Some("a"), "op-b", vec![]);
        let err_env =
            ingest_otel_enveloped(vec![a2.clone(), b2.clone()], Fidelity::LineageOnly).unwrap_err();
        assert!(matches!(err_env, AdapterError::CycleDetected { .. }));
        let err_fid = ingest_otel_with_fidelity(vec![a2, b2], Fidelity::LineageOnly).unwrap_err();
        assert!(matches!(err_fid, AdapterError::CycleDetected { .. }));
        // Bounded trail capped at 32 for large cycle.
        let many: Vec<OtelSpan> = (0..50)
            .map(|i| {
                let next = (i + 1) % 50;
                make_span(
                    "t",
                    &format!("s{i}"),
                    Some(&format!("s{next}")),
                    &format!("op{i}"),
                    vec![],
                )
            })
            .collect();
        let err_many = ingest_otel_dedup(many, config(Fidelity::LineageOnly, true)).unwrap_err();
        match err_many {
            AdapterError::CycleDetected { trail } => assert!(trail.len() <= 32),
            other => panic!("expected CycleDetected for large cycle, got {other:?}"),
        }
    }

    #[test]
    fn max_spans_enforced() {
        let spans = vec![
            OtelSpan {
                trace_id: "t".into(),
                span_id: "s1".into(),
                parent_span_id: None,
                name: "op".into(),
                events: vec![],
                ..Default::default()
            },
            OtelSpan {
                trace_id: "t".into(),
                span_id: "s2".into(),
                parent_span_id: None,
                name: "op2".into(),
                events: vec![],
                ..Default::default()
            },
        ];
        let config = OtelIngestConfig {
            fidelity: Fidelity::LineageOnly,
            dedup: true,
            max_spans: 1,
            ..Default::default()
        };
        let err = ingest_otel_dedup(spans, config).unwrap_err();
        assert!(matches!(err, AdapterError::SpanLimitExceeded { .. }));
    }

    #[test]
    fn file_ingest_reads_ndjson() {
        // Write NDJSON to temp file via std::fs (allowed in test).
        let dir = std::env::temp_dir();
        let path = dir.join(format!("ldgr-otel-test-{}.ndjson", std::process::id()));
        let mut file = std::fs::File::create(&path).unwrap();
        let span1 = OtelSpan {
            trace_id: "t".into(),
            span_id: "s1".into(),
            parent_span_id: None,
            name: "op-file-a".into(),
            events: vec![],
            ..Default::default()
        };
        let span2 = OtelSpan {
            trace_id: "t".into(),
            span_id: "s2".into(),
            parent_span_id: Some("s1".into()),
            name: "op-file-b".into(),
            events: vec![OtelEvent { name: "ev".into() }],
            ..Default::default()
        };
        writeln!(file, "{}", serde_json::to_string(&span1).unwrap()).unwrap();
        writeln!(file, "{}", serde_json::to_string(&span2).unwrap()).unwrap();
        writeln!(file).unwrap(); // blank line skipped
        drop(file);

        let ing = ingest_otel_file(&path).unwrap();
        assert!(ing.journal.len() >= 2);
        assert_eq!(ing.fidelity, Fidelity::LineageOnly);
        // Cleanup.
        let _ = std::fs::remove_file(&path);

        // Determinism: second read yields same root.
        let mut file2 = std::fs::File::create(&path).unwrap();
        writeln!(file2, "{}", serde_json::to_string(&span1).unwrap()).unwrap();
        writeln!(file2, "{}", serde_json::to_string(&span2).unwrap()).unwrap();
        drop(file2);
        let ing2 = ingest_otel_file(&path).unwrap();
        assert_eq!(ing.journal.root_hash(), ing2.journal.root_hash());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn file_ingest_missing_file_errors() {
        let path = std::env::temp_dir().join(format!(
            "ldgr-nonexistent-otel-xyz-{}.ndjson",
            std::process::id()
        ));
        // Ensure the path does not exist for this pid.
        let _ = std::fs::remove_file(&path);
        let err = ingest_otel_file(&path).unwrap_err();
        assert!(matches!(err, AdapterError::Io(_)));
    }

    #[test]
    fn enveloped_bitexact_rejects_missing_parent() {
        let missing = OtelSpan {
            trace_id: "t".into(),
            span_id: "child".into(),
            parent_span_id: Some("no-such".into()),
            name: "child-op".into(),
            events: vec![],
            ..Default::default()
        };
        let err = ingest_otel_enveloped(vec![missing.clone()], Fidelity::BitExact).unwrap_err();
        assert!(matches!(err, AdapterError::FidelityMismatch));
        // LineageOnly stays lenient for the same input.
        ingest_otel_enveloped(vec![missing], Fidelity::LineageOnly).unwrap();
        let with_fid_missing = OtelSpan {
            trace_id: "t".into(),
            span_id: "child".into(),
            parent_span_id: Some("no-such".into()),
            name: "child-op".into(),
            events: vec![],
            ..Default::default()
        };
        let err2 = ingest_otel_with_fidelity(vec![with_fid_missing.clone()], Fidelity::BitExact)
            .unwrap_err();
        assert!(matches!(err2, AdapterError::FidelityMismatch));
        ingest_otel_with_fidelity(vec![with_fid_missing], Fidelity::LineageOnly).unwrap();
        // Cycle case now returns CycleDetected for both paths, checked in cycle_rejected test.
    }

    #[test]
    fn file_ingest_bails_inside_loop_on_max_spans() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("ldgr-otel-maxspans-{}.ndjson", std::process::id()));
        let mut file = std::fs::File::create(&path).unwrap();
        for i in 0..5 {
            let span = OtelSpan {
                trace_id: "t".into(),
                span_id: format!("s{i}"),
                parent_span_id: None,
                name: format!("op{i}"),
                events: vec![],
                ..Default::default()
            };
            writeln!(file, "{}", serde_json::to_string(&span).unwrap()).unwrap();
        }
        drop(file);
        let config = OtelIngestConfig {
            fidelity: Fidelity::LineageOnly,
            dedup: false,
            max_spans: 2,
            ..Default::default()
        };
        let err = ingest_otel_file_with_config(&path, config).unwrap_err();
        assert!(matches!(err, AdapterError::SpanLimitExceeded { .. }));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn envelope_hash_and_certifiable_exposed() {
        let spans = sample_spans();
        let config = OtelIngestConfig {
            fidelity: Fidelity::BitExact,
            dedup: true,
            max_spans: 10,
            ..Default::default()
        };
        let ing = ingest_otel_dedup(spans, config).unwrap();
        assert!(ing.is_certifiable());
        let h = ing.envelope_hash().unwrap();
        let h2 = ing.envelope.envelope_hash().unwrap();
        assert_eq!(h, h2);
        ing.require_certifiable().unwrap();
    }
}
