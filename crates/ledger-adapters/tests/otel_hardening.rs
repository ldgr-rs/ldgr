//! Hardening tests for E1 OTEL ingest.
//! Covers: topo ordering shared helper, forward edges, first-wins,
//! cycle bounded trail, file streaming caps, attribute caps,
//! deterministic roots across reorderings.

use ledger_adapters::AdapterError;
use ledger_adapters::envelope::Fidelity;
use ledger_adapters::otel::{
    OtelEvent, OtelIngestConfig, OtelSpan, ingest_otel_dedup, ingest_otel_enveloped,
    ingest_otel_file_with_config, ingest_otel_with_fidelity,
};
use ledger_format::{CanonicalValue, EntryKind, EntryPayload, OutcomePayload};
use std::collections::BTreeMap;
use std::io::Write;

fn make_span(trace: &str, id: &str, parent: Option<&str>, name: &str) -> OtelSpan {
    OtelSpan {
        trace_id: trace.into(),
        span_id: id.into(),
        parent_span_id: parent.map(Into::into),
        name: name.into(),
        events: vec![],
        ..Default::default()
    }
}

fn span_with_attrs(
    trace: &str,
    id: &str,
    parent: Option<&str>,
    name: &str,
    attrs: BTreeMap<String, String>,
) -> OtelSpan {
    OtelSpan {
        trace_id: trace.into(),
        span_id: id.into(),
        parent_span_id: parent.map(Into::into),
        name: name.into(),
        events: vec![],
        attributes: attrs,
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

fn find_entry(journal: &ledger_journal::Journal, name: &str) -> ledger_journal::Entry {
    journal
        .entries()
        .find(|e| {
            matches!(
                &e.data.payload,
                EntryPayload::Outcome(OutcomePayload {
                    value: CanonicalValue::Text(t),
                    ..
                }) if t == name
            )
        })
        .unwrap_or_else(|| panic!("missing entry {name}"))
        .clone()
}

#[test]
fn reordered_identical_across_three_paths() {
    let parent = make_span("t", "p", None, "parent-op");
    let child = make_span("t", "c", Some("p"), "child-op");
    let sorted = vec![parent.clone(), child.clone()];
    let reordered = vec![child.clone(), parent.clone()];

    // dedup path
    let cfg = config(Fidelity::BitExact, true);
    let a = ingest_otel_dedup(sorted.clone(), cfg).unwrap();
    let b = ingest_otel_dedup(reordered.clone(), cfg).unwrap();
    assert_eq!(a.journal.root_hash(), b.journal.root_hash());

    // with_fidelity path
    let a2 = ingest_otel_with_fidelity(sorted.clone(), Fidelity::BitExact).unwrap();
    let b2 = ingest_otel_with_fidelity(reordered.clone(), Fidelity::BitExact).unwrap();
    assert_eq!(a2.root_hash(), b2.root_hash());
    // enveloped path
    let a3 = ingest_otel_enveloped(sorted.clone(), Fidelity::BitExact).unwrap();
    let b3 = ingest_otel_enveloped(reordered, Fidelity::BitExact).unwrap();
    assert_eq!(a3.journal.root_hash(), b3.journal.root_hash());

    // All three sorted roots should be deterministic across paths for same fidelity
    // (they share topo ordering and same payloads, but enveloped adds no extra marker for BitExact)
    // So dedup and enveloped BitExact with same set should be identical root when dedup not shrinking.
    assert_eq!(a.journal.root_hash(), a3.journal.root_hash());
}

#[test]
fn forward_parent_preserved_all_paths() {
    let parent = make_span("t", "parent", None, "parent-op");
    let child = make_span("t", "child", Some("parent"), "child-op");
    let reordered = vec![child.clone(), parent.clone()];

    // with_fidelity
    let j = ingest_otel_with_fidelity(reordered.clone(), Fidelity::LineageOnly).unwrap();
    let pe = find_entry(&j, "parent-op");
    let ce = find_entry(&j, "child-op");
    assert!(ce.data.parents.contains(&pe.id));

    // enveloped
    let ing = ingest_otel_enveloped(reordered.clone(), Fidelity::LineageOnly).unwrap();
    let pe2 = find_entry(&ing.journal, "parent-op");
    let ce2 = find_entry(&ing.journal, "child-op");
    assert!(ce2.data.parents.contains(&pe2.id));

    // dedup
    let ing3 = ingest_otel_dedup(reordered, config(Fidelity::LineageOnly, true)).unwrap();
    let pe3 = find_entry(&ing3.journal, "parent-op");
    let ce3 = find_entry(&ing3.journal, "child-op");
    assert!(ce3.data.parents.contains(&pe3.id));
}

#[test]
fn duplicate_first_wins() {
    // Two spans share same span_id "dup" but different names, so different content hash when dedup true
    // they both survive but second should not override first for parent binding.
    let first = OtelSpan {
        trace_id: "t".into(),
        span_id: "dup".into(),
        parent_span_id: None,
        name: "first".into(),
        events: vec![],
        ..Default::default()
    };
    let second = OtelSpan {
        trace_id: "t".into(),
        span_id: "dup".into(),
        parent_span_id: None,
        name: "second".into(),
        events: vec![OtelEvent { name: "ev".into() }],
        ..Default::default()
    };
    let child = make_span("t", "child", Some("dup"), "child-op");

    // Input order: first, second, child. Dedup false so both dup ids exist.
    let cfg = OtelIngestConfig {
        fidelity: Fidelity::LineageOnly,
        dedup: false,
        max_spans: 10,
        ..Default::default()
    };
    let ing = ingest_otel_dedup(vec![first.clone(), second.clone(), child.clone()], cfg).unwrap();
    let first_entry = find_entry(&ing.journal, "first");
    let child_entry = find_entry(&ing.journal, "child-op");
    // child should observe first (first-wins)
    assert!(child_entry.data.parents.contains(&first_entry.id));

    // Also test via with_fidelity path (no dedup, but first-wins via entry().or_insert)
    let j = ingest_otel_with_fidelity(vec![first, second, child], Fidelity::LineageOnly).unwrap();
    let first_e2 = find_entry(&j, "first");
    let child_e2 = find_entry(&j, "child-op");
    assert!(child_e2.data.parents.contains(&first_e2.id));
}

#[test]
fn cycle_rejected_bounded_trail_all_paths() {
    let a = make_span("t", "a", Some("b"), "op-a");
    let b = make_span("t", "b", Some("a"), "op-b");
    // dedup
    let err = ingest_otel_dedup(
        vec![a.clone(), b.clone()],
        config(Fidelity::LineageOnly, true),
    )
    .unwrap_err();
    match err {
        AdapterError::CycleDetected { trail } => {
            assert!(trail.len() <= 32);
            assert!(trail.iter().any(|s| s == "a" || s == "b"));
        }
        other => panic!("expected CycleDetected, got {other:?}"),
    }
    // with_fidelity
    let err2 =
        ingest_otel_with_fidelity(vec![a.clone(), b.clone()], Fidelity::LineageOnly).unwrap_err();
    assert!(matches!(err2, AdapterError::CycleDetected { .. }));
    // enveloped
    let err3 = ingest_otel_enveloped(vec![a, b], Fidelity::LineageOnly).unwrap_err();
    assert!(matches!(err3, AdapterError::CycleDetected { .. }));

    // large cycle capped at 32
    let many: Vec<OtelSpan> = (0..100)
        .map(|i| {
            let nxt = (i + 1) % 100;
            make_span(
                "t",
                &format!("s{i}"),
                Some(&format!("s{nxt}")),
                &format!("op{i}"),
            )
        })
        .collect();
    let err_many = ingest_otel_dedup(many, config(Fidelity::LineageOnly, true)).unwrap_err();
    match err_many {
        AdapterError::CycleDetected { trail } => assert!(trail.len() <= 32),
        other => panic!("expected CycleDetected large, got {other:?}"),
    }
}

#[test]
fn oversized_single_line_rejected() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("ldgr-otel-linecap-{}.ndjson", std::process::id()));
    let mut f = std::fs::File::create(&path).unwrap();
    // A single span whose JSON line exceeds the per-line limit.
    let big_span = OtelSpan {
        trace_id: "t".into(),
        span_id: "s1".into(),
        parent_span_id: None,
        name: "x".repeat(500),
        events: vec![],
        ..Default::default()
    };
    let big_json = serde_json::to_string(&big_span).unwrap();
    writeln!(f, "{big_json}").unwrap();
    drop(f);
    let cfg = OtelIngestConfig {
        fidelity: Fidelity::LineageOnly,
        dedup: true,
        max_spans: 10,
        max_line_bytes: 10,
        ..Default::default()
    };
    let err = ingest_otel_file_with_config(&path, cfg).unwrap_err();
    assert!(matches!(err, AdapterError::LineTooLarge { .. }));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn file_over_max_bytes_rejected() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("ldgr-otel-filecap-{}.ndjson", std::process::id()));
    let mut f = std::fs::File::create(&path).unwrap();
    for i in 0..5 {
        let s = make_span("t", &format!("s{i}"), None, &format!("op{i}"));
        writeln!(f, "{}", serde_json::to_string(&s).unwrap()).unwrap();
    }
    drop(f);
    let cfg = OtelIngestConfig {
        fidelity: Fidelity::LineageOnly,
        dedup: true,
        max_spans: 100,
        max_bytes: 10, // tiny to trigger
        max_line_bytes: 1024 * 1024,
        ..Default::default()
    };
    let err = ingest_otel_file_with_config(&path, cfg).unwrap_err();
    assert!(matches!(err, AdapterError::FileTooLarge { .. }));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn span_cap_fires_mid_stream() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("ldgr-otel-spancap-{}.ndjson", std::process::id()));
    let mut f = std::fs::File::create(&path).unwrap();
    for i in 0..5 {
        let s = make_span("t", &format!("s{i}"), None, &format!("op{i}"));
        writeln!(f, "{}", serde_json::to_string(&s).unwrap()).unwrap();
    }
    drop(f);
    let cfg = OtelIngestConfig {
        fidelity: Fidelity::LineageOnly,
        dedup: true,
        max_spans: 2,
        ..Default::default()
    };
    let err = ingest_otel_file_with_config(&path, cfg).unwrap_err();
    assert!(matches!(err, AdapterError::SpanLimitExceeded { .. }));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn attribute_limits_enforced() {
    // count limit
    let mut attrs = BTreeMap::new();
    for i in 0..5 {
        attrs.insert(format!("k{i}"), format!("v{i}"));
    }
    let span = span_with_attrs("t", "s1", None, "op", attrs);
    let cfg = OtelIngestConfig {
        fidelity: Fidelity::LineageOnly,
        dedup: true,
        max_spans: 10,
        max_attributes_per_span: 2,
        ..Default::default()
    };
    let err = ingest_otel_dedup(vec![span], cfg).unwrap_err();
    assert!(matches!(err, AdapterError::AttributeLimitExceeded { .. }));

    // bytes limit
    let mut big_attrs = BTreeMap::new();
    big_attrs.insert("k".to_string(), "x".repeat(300 * 1024)); // 300 KiB > 256 KiB default
    let span2 = span_with_attrs("t", "s2", None, "op2", big_attrs);
    let cfg2 = OtelIngestConfig {
        fidelity: Fidelity::LineageOnly,
        dedup: true,
        max_spans: 10,
        ..Default::default()
    };
    let err2 = ingest_otel_dedup(vec![span2], cfg2).unwrap_err();
    assert!(matches!(err2, AdapterError::AttributeLimitExceeded { .. }));

    // with_fidelity path also enforces (uses default limits)
    let mut many = BTreeMap::new();
    for i in 0..5000 {
        many.insert(format!("k{i}"), "v".into());
    }
    let span3 = span_with_attrs("t", "s3", None, "op3", many);
    let err3 = ingest_otel_with_fidelity(vec![span3], Fidelity::LineageOnly).unwrap_err();
    assert!(matches!(err3, AdapterError::AttributeLimitExceeded { .. }));
}

#[test]
fn deterministic_root_across_orderings_chain() {
    // chain: root -> mid -> leaf; any input permutation of the chain should yield same root
    let root = make_span("t", "root", None, "r");
    let mid = make_span("t", "mid", Some("root"), "m");
    let leaf = make_span("t", "leaf", Some("mid"), "l");
    let perms = [
        vec![root.clone(), mid.clone(), leaf.clone()],
        vec![leaf.clone(), mid.clone(), root.clone()],
        vec![mid.clone(), root.clone(), leaf.clone()],
        vec![mid.clone(), leaf.clone(), root.clone()],
    ];
    let cfg = config(Fidelity::LineageOnly, true);
    let first = ingest_otel_dedup(perms[0].clone(), cfg).unwrap();
    let root0 = first.journal.root_hash();
    for perm in perms.iter().skip(1) {
        let ing = ingest_otel_dedup(perm.clone(), cfg).unwrap();
        assert_eq!(
            ing.journal.root_hash(),
            root0,
            "chain must be deterministic across orderings"
        );
    }
}

#[test]
fn already_sorted_stays_identical() {
    // Already sorted input must produce the pinned journal root below: the
    // topo order for a sorted chain is the identity order, so journal bytes
    // are pinned against silent uniform drift.
    const PINNED_ROOT_HEX: &str =
        "f64bcc43e7f6edc77d49c5474b830e31449f78d4c486333b692b958fa925f7da";
    let s1 = make_span("t", "s1", None, "op1");
    let s2 = make_span("t", "s2", Some("s1"), "op2");
    let s3 = make_span("t", "s3", Some("s2"), "op3");
    let sorted = vec![s1, s2, s3];
    let cfg = config(Fidelity::BitExact, false);
    let a = ingest_otel_dedup(sorted.clone(), cfg).unwrap();
    let b = ingest_otel_dedup(sorted, cfg).unwrap();
    assert_eq!(a.journal.root_hash(), b.journal.root_hash());
    let root_hex: String = a
        .journal
        .root_hash()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(root_hex, PINNED_ROOT_HEX);
    // Compare with with_fidelity path for same sorted input: should be same root for BitExact without marker differences?
    // with_fidelity BitExact root should equal dedup BitExact root for no dedup and same ordering
    let sorted2 = vec![
        make_span("t", "s1", None, "op1"),
        make_span("t", "s2", Some("s1"), "op2"),
        make_span("t", "s3", Some("s2"), "op3"),
    ];
    let j = ingest_otel_with_fidelity(sorted2, Fidelity::BitExact).unwrap();
    assert_eq!(j.root_hash(), a.journal.root_hash());
}

#[test]
fn envelope_dedup_uses_attributes() {
    let a = span_with_attrs(
        "t",
        "s1",
        None,
        "op",
        BTreeMap::from([("k".into(), "v1".into())]),
    );
    let b = span_with_attrs(
        "t",
        "s1",
        None,
        "op",
        BTreeMap::from([("k".into(), "v2".into())]),
    );
    let cfg = config(Fidelity::BitExact, true);
    let ing = ingest_otel_dedup(vec![a, b], cfg).unwrap();
    // different attributes means different content hash, both survive
    assert_eq!(
        ing.journal
            .entries()
            .filter(|e| e.data.kind == EntryKind::Outcome)
            .count(),
        2
    );
}
