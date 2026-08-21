// Integration fixture: OTel spans ingested into a persisted journal.
// Verifies determinism, lineage causality, and byte-identical reload.

use ledger_adapters::envelope::Fidelity;
use ledger_adapters::otel::{OtelEvent, OtelIngestConfig, OtelSpan, ingest_otel_dedup};
use ledger_format::{EntryKind, Payload};
use ledger_journal::{Journal, PersistentJournal};
use std::collections::HashMap;
use std::path::PathBuf;

fn golden_spans() -> Vec<OtelSpan> {
    let trace = "4bf92f3577b34da6a3ce929d0e0e4736";
    vec![
        OtelSpan {
            trace_id: trace.to_string(),
            span_id: "span-001".to_string(),
            parent_span_id: None,
            name: "api-gateway".to_string(),
            events: vec![OtelEvent {
                name: "http.request".to_string(),
            }],
        },
        OtelSpan {
            trace_id: trace.to_string(),
            span_id: "span-002".to_string(),
            parent_span_id: Some("span-001".to_string()),
            name: "auth-service".to_string(),
            events: vec![OtelEvent {
                name: "auth.check".to_string(),
            }],
        },
        OtelSpan {
            trace_id: trace.to_string(),
            span_id: "span-003".to_string(),
            parent_span_id: Some("span-001".to_string()),
            name: "payment-service".to_string(),
            events: vec![OtelEvent {
                name: "payment.start".to_string(),
            }],
        },
        OtelSpan {
            trace_id: trace.to_string(),
            span_id: "span-004".to_string(),
            parent_span_id: Some("span-002".to_string()),
            name: "user-db".to_string(),
            events: vec![OtelEvent {
                name: "db.query".to_string(),
            }],
        },
        OtelSpan {
            trace_id: trace.to_string(),
            span_id: "span-005".to_string(),
            parent_span_id: Some("span-002".to_string()),
            name: "cache".to_string(),
            events: vec![],
        },
        OtelSpan {
            trace_id: trace.to_string(),
            span_id: "span-006".to_string(),
            parent_span_id: Some("span-003".to_string()),
            name: "payment-db".to_string(),
            events: vec![OtelEvent {
                name: "db.write".to_string(),
            }],
        },
        OtelSpan {
            trace_id: trace.to_string(),
            span_id: "span-007".to_string(),
            parent_span_id: Some("span-003".to_string()),
            name: "fraud-check".to_string(),
            events: vec![OtelEvent {
                name: "fraud.score".to_string(),
            }],
        },
        OtelSpan {
            trace_id: trace.to_string(),
            span_id: "span-008".to_string(),
            parent_span_id: Some("span-006".to_string()),
            name: "replica-write".to_string(),
            events: vec![],
        },
        OtelSpan {
            trace_id: trace.to_string(),
            span_id: "span-009".to_string(),
            parent_span_id: Some("span-007".to_string()),
            name: "risk-engine".to_string(),
            events: vec![OtelEvent {
                name: "risk.eval".to_string(),
            }],
        },
        OtelSpan {
            trace_id: trace.to_string(),
            span_id: "span-010".to_string(),
            parent_span_id: Some("span-001".to_string()),
            name: "logging".to_string(),
            events: vec![OtelEvent {
                name: "log.flush".to_string(),
            }],
        },
    ]
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ldgr-otel-fixture-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn ingest_golden() -> ledger_adapters::IngestedJournal {
    let config = OtelIngestConfig {
        fidelity: Fidelity::LineageOnly,
        dedup: true,
        max_spans: 100,
    };
    ingest_otel_dedup(golden_spans(), config)
        .unwrap_or_else(|error| panic!("golden ingest must succeed: {error}"))
}

fn map_outcomes(journal: &Journal) -> HashMap<String, ledger_format::Hash> {
    let mut out = HashMap::new();
    for entry in journal.entries() {
        if entry.data.kind == EntryKind::Outcome
            && let Payload::Text(name) = &entry.data.payload
        {
            out.insert(name.clone(), entry.id);
        }
    }
    out
}

#[test]
fn golden_spans_have_expected_shape() {
    let spans = golden_spans();
    assert!(spans.len() >= 8, "golden set must have at least 8 spans");
    assert_eq!(spans.len(), 10);
    // Depth at least 3: replica-write is at depth 3 (gateway -> payment -> db -> replica).
    let depth_of = |id: &str, spans: &[OtelSpan]| -> usize {
        let mut depth = 0;
        let mut cur = id;
        loop {
            let span = spans
                .iter()
                .find(|s| s.span_id == cur)
                .unwrap_or_else(|| panic!("span {cur} missing from golden set"));
            if let Some(parent) = &span.parent_span_id {
                depth += 1;
                cur = parent;
            } else {
                break;
            }
        }
        depth
    };
    let max_depth = spans
        .iter()
        .map(|s| depth_of(&s.span_id, &spans))
        .max()
        .unwrap_or(0);
    assert!(max_depth >= 3, "depth must be at least 3, got {max_depth}");
    // Sibling branches: auth-service has two children, payment-service has two.
    let children_of = |parent: &str| -> usize {
        spans
            .iter()
            .filter(|s| s.parent_span_id.as_deref() == Some(parent))
            .count()
    };
    assert!(
        children_of("span-002") >= 2,
        "auth-service must have siblings"
    );
    assert!(
        children_of("span-003") >= 2,
        "payment-service must have siblings"
    );
}

#[test]
fn golden_ingest_is_deterministic() {
    let a = ingest_golden();
    let b = ingest_golden();
    assert_eq!(
        a.journal.root_hash(),
        b.journal.root_hash(),
        "same golden spans must yield same root"
    );
    assert_eq!(a.journal.len(), b.journal.len());
    let ha = a
        .envelope_hash()
        .unwrap_or_else(|error| panic!("envelope hash must compute: {error}"));
    let hb = b
        .envelope_hash()
        .unwrap_or_else(|error| panic!("envelope hash must compute: {error}"));
    assert_eq!(ha, hb, "envelope hash must be deterministic");
    // Two independent ingests with same config produce identical outcome mapping.
    let map_a = map_outcomes(&a.journal);
    let map_b = map_outcomes(&b.journal);
    assert_eq!(map_a.len(), map_b.len());
    for (name, id_a) in map_a {
        let id_b = map_b
            .get(&name)
            .unwrap_or_else(|| panic!("second ingest must contain {name}"));
        assert_eq!(&id_a, id_b, "outcome id for {name} must be deterministic");
    }
}

#[test]
fn golden_ingest_preserves_lineage_causality() {
    let ing = ingest_golden();
    let journal = &ing.journal;
    let outcomes = map_outcomes(journal);
    // Every child must observe its parent entry hash and have a larger vector clock.
    for span in golden_spans() {
        if let Some(parent_id) = span.parent_span_id {
            let parent_name = golden_spans()
                .into_iter()
                .find(|s| s.span_id == parent_id)
                .map(|s| s.name)
                .unwrap_or_else(|| panic!("parent {parent_id} must exist"));
            let child_entry = journal
                .get(
                    outcomes
                        .get(&span.name)
                        .unwrap_or_else(|| panic!("missing entry for {}", span.name)),
                )
                .unwrap_or_else(|| panic!("child entry for {} must exist", span.name));
            let parent_entry = journal
                .get(
                    outcomes
                        .get(&parent_name)
                        .unwrap_or_else(|| panic!("missing parent entry for {parent_name}")),
                )
                .unwrap_or_else(|| panic!("parent entry for {parent_name} must exist"));
            assert!(
                child_entry.data.parents.contains(&parent_entry.id),
                "child {} parents {:?} must contain parent {} id {:?}",
                span.name,
                child_entry.data.parents,
                parent_name,
                parent_entry.id
            );
            assert!(
                child_entry.vector_clock.get(1) > parent_entry.vector_clock.get(1),
                "child {} clock must dominate parent {}",
                span.name,
                parent_name
            );
        }
    }
    // Sibling branches must not be causal: user-db and cache are siblings under auth-service,
    // neither should be parent of the other.
    let user_db = outcomes
        .get("user-db")
        .unwrap_or_else(|| panic!("user-db missing from ingest outcomes"));
    let cache = outcomes
        .get("cache")
        .unwrap_or_else(|| panic!("cache missing from ingest outcomes"));
    let user_entry = journal
        .get(user_db)
        .unwrap_or_else(|| panic!("user-db entry missing from journal"));
    let cache_entry = journal
        .get(cache)
        .unwrap_or_else(|| panic!("cache entry missing from journal"));
    assert!(
        !user_entry.data.parents.contains(cache),
        "siblings must not be causal"
    );
    assert!(
        !cache_entry.data.parents.contains(user_db),
        "siblings must not be causal"
    );
}

#[test]
fn golden_ingest_persists_and_reloads_byte_identical() {
    let ing = ingest_golden();
    let dir = temp_dir("persist-reload");
    let mut pj = PersistentJournal::create(&dir)
        .unwrap_or_else(|error| panic!("create persistent journal must succeed: {error}"));
    for entry in ing.journal.entries() {
        pj.append(
            entry.data.kind,
            entry.data.actor,
            entry.data.parents.iter().copied(),
            entry.data.payload.clone(),
        )
        .unwrap_or_else(|error| panic!("append must succeed: {error}"));
    }
    pj.force_seal()
        .unwrap_or_else(|error| panic!("force seal must succeed: {error}"));
    pj.write_manifest()
        .unwrap_or_else(|error| panic!("write manifest must succeed: {error}"));
    let root_before = pj.root_hash();
    let len_before = pj.len();
    drop(pj);
    let reopened = PersistentJournal::open(&dir)
        .unwrap_or_else(|error| panic!("reopen must succeed: {error}"));
    assert_eq!(
        reopened.root_hash(),
        root_before,
        "reloaded root must equal in-memory root"
    );
    assert_eq!(
        reopened.len(),
        len_before,
        "reloaded len must equal in-memory len"
    );
    assert_eq!(
        reopened.len(),
        ing.journal.len(),
        "reloaded len must equal original ingested len"
    );
    // Byte-identical entries in append order.
    for (orig, reloaded) in ing.journal.entries().zip(reopened.entries()) {
        assert_eq!(orig.id, reloaded.id, "entry id must survive reload");
        assert_eq!(orig.data, reloaded.data, "entry data must survive reload");
        assert_eq!(
            orig.vector_clock, reloaded.vector_clock,
            "vector clock must survive reload"
        );
    }
    reopened
        .verify()
        .unwrap_or_else(|error| panic!("journal must verify after reload: {error}"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn golden_ingest_reordered_input_still_preserves_causality() {
    let mut spans = golden_spans();
    spans.reverse();
    let config = OtelIngestConfig {
        fidelity: Fidelity::LineageOnly,
        dedup: true,
        max_spans: 100,
    };
    let ing = ingest_otel_dedup(spans, config)
        .unwrap_or_else(|error| panic!("reordered ingest must succeed: {error}"));
    let outcomes = map_outcomes(&ing.journal);
    // Even when input is reversed, causality still holds via topo ordering.
    for span in golden_spans() {
        if let Some(parent_id) = span.parent_span_id {
            let parent_name = golden_spans()
                .into_iter()
                .find(|s| s.span_id == parent_id)
                .unwrap_or_else(|| panic!("parent span {parent_id} missing from golden set"))
                .name;
            let child_id = outcomes
                .get(&span.name)
                .unwrap_or_else(|| panic!("{} missing from outcomes", span.name));
            let parent_entry_id = outcomes
                .get(&parent_name)
                .unwrap_or_else(|| panic!("{parent_name} missing from outcomes"));
            let child_entry = ing
                .journal
                .get(child_id)
                .unwrap_or_else(|| panic!("child entry {} missing from journal", span.name));
            let parent_entry = ing
                .journal
                .get(parent_entry_id)
                .unwrap_or_else(|| panic!("parent entry {parent_name} missing from journal"));
            assert!(
                child_entry.data.parents.contains(parent_entry_id),
                "reordered ingest: child {} must still observe parent {}",
                span.name,
                parent_name
            );
            assert!(
                child_entry.vector_clock.get(1) > parent_entry.vector_clock.get(1),
                "reordered ingest: clock must still dominate"
            );
        }
    }
}
