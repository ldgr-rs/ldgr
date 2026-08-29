use ledger_adapters::envelope::{EntryMapping, EnvelopeHeader, Fidelity, InterchangeEnvelope};
use ledger_adapters::otel::{
    OtelEvent, OtelSpan, ingest_otel_enveloped, ingest_otel_with_fidelity,
};
use ledger_format::EntryKind;

fn sample_envelope(f: Fidelity) -> InterchangeEnvelope {
    InterchangeEnvelope::new(
        EnvelopeHeader::new("application/json".into(), "test-emitter".into()),
        vec![
            EntryMapping {
                kind: EntryKind::Outcome.into(),
                external_type: "otel.span".into(),
                fidelity: f,
            },
            EntryMapping {
                kind: EntryKind::Send.into(),
                external_type: "otel.event".into(),
                fidelity: f,
            },
        ],
    )
}

#[test]
fn envelope_roundtrip_bit_exact() {
    let e = sample_envelope(Fidelity::BitExact);
    let b = e.to_canonical_bytes().unwrap();
    let d = InterchangeEnvelope::from_bytes(&b).unwrap();
    assert_eq!(e, d);
    assert_eq!(d.fidelity(), Fidelity::BitExact);
}

#[test]
fn envelope_roundtrip_lineage() {
    let e = sample_envelope(Fidelity::LineageOnly);
    let b = e.to_canonical_bytes().unwrap();
    let d = InterchangeEnvelope::from_bytes(&b).unwrap();
    assert_eq!(e, d);
    assert_eq!(d.fidelity(), Fidelity::LineageOnly);
}

#[test]
fn envelope_magic_rejects() {
    let e = sample_envelope(Fidelity::BitExact);
    let mut w = e.clone();
    w.header.magic = *b"BAD!";
    assert!(InterchangeEnvelope::from_bytes(&w.to_canonical_bytes().unwrap()).is_err());
}

#[test]
fn envelope_version_rejects() {
    let mut e = sample_envelope(Fidelity::BitExact);
    e.header.version = 99;
    let err = InterchangeEnvelope::from_bytes(&e.to_canonical_bytes().unwrap()).unwrap_err();
    assert!(matches!(
        err,
        ledger_adapters::AdapterError::UnsupportedVersion(99)
    ));
}

#[test]
fn envelope_fidelity_aggregate() {
    let e = InterchangeEnvelope::new(
        EnvelopeHeader::new("t".into(), "e".into()),
        vec![
            EntryMapping {
                kind: EntryKind::Outcome.into(),
                external_type: "a".into(),
                fidelity: Fidelity::BitExact,
            },
            EntryMapping {
                kind: EntryKind::Send.into(),
                external_type: "b".into(),
                fidelity: Fidelity::LineageOnly,
            },
        ],
    );
    assert_eq!(e.fidelity(), Fidelity::LineageOnly);
}

#[test]
fn envelope_empty_fidelity_bit_exact() {
    let e = InterchangeEnvelope::new(EnvelopeHeader::new("t".into(), "e".into()), vec![]);
    assert_eq!(e.fidelity(), Fidelity::BitExact);
}

#[test]
fn envelope_roundtrip_rngdraw() {
    let e = InterchangeEnvelope::new(
        EnvelopeHeader::new("t".into(), "e".into()),
        vec![EntryMapping {
            kind: EntryKind::RngDraw.into(),
            external_type: "rng".into(),
            fidelity: Fidelity::BitExact,
        }],
    );
    let b = e.to_canonical_bytes().unwrap();
    let d = InterchangeEnvelope::from_bytes(&b).unwrap();
    assert_eq!(e, d);
    assert_eq!(d.body[0].kind.0, EntryKind::RngDraw);
}

#[test]
fn envelope_roundtrip_inputstep() {
    let e = InterchangeEnvelope::new(
        EnvelopeHeader::new("t".into(), "e".into()),
        vec![EntryMapping {
            kind: EntryKind::InputStep.into(),
            external_type: "input".into(),
            fidelity: Fidelity::BitExact,
        }],
    );
    let b = e.to_canonical_bytes().unwrap();
    let d = InterchangeEnvelope::from_bytes(&b).unwrap();
    assert_eq!(e, d);
    assert_eq!(d.body[0].kind.0, EntryKind::InputStep);
}

#[test]
fn envelope_roundtrip_fault() {
    let e = InterchangeEnvelope::new(
        EnvelopeHeader::new("t".into(), "e".into()),
        vec![EntryMapping {
            kind: EntryKind::Fault.into(),
            external_type: "fault".into(),
            fidelity: Fidelity::BitExact,
        }],
    );
    let b = e.to_canonical_bytes().unwrap();
    let d = InterchangeEnvelope::from_bytes(&b).unwrap();
    assert_eq!(e, d);
    assert_eq!(d.body[0].kind.0, EntryKind::Fault);
}

#[test]
fn envelope_roundtrip_all_structured_kinds() {
    let kinds = vec![
        EntryKind::RngDraw,
        EntryKind::InputStep,
        EntryKind::Fault,
        EntryKind::StepBegin,
        EntryKind::StepEnd,
    ];
    for kind in kinds {
        let e = InterchangeEnvelope::new(
            EnvelopeHeader::new("t".into(), "e".into()),
            vec![EntryMapping {
                kind: kind.into(),
                external_type: "x".into(),
                fidelity: Fidelity::BitExact,
            }],
        );
        let b = e.to_canonical_bytes().unwrap();
        let d = InterchangeEnvelope::from_bytes(&b).unwrap();
        assert_eq!(e, d);
        assert_eq!(d.body[0].kind.0, kind);
    }
}

#[test]
fn envelope_hash_deterministic() {
    let e = sample_envelope(Fidelity::BitExact);
    let h1 = e.envelope_hash().unwrap();
    let h2 = e.envelope_hash().unwrap();
    assert_eq!(h1, h2);
}

#[test]
fn envelope_hash_differs_on_kind() {
    let e1 = InterchangeEnvelope::new(
        EnvelopeHeader::new("t".into(), "e".into()),
        vec![EntryMapping {
            kind: EntryKind::RngDraw.into(),
            external_type: "x".into(),
            fidelity: Fidelity::BitExact,
        }],
    );
    let e2 = InterchangeEnvelope::new(
        EnvelopeHeader::new("t".into(), "e".into()),
        vec![EntryMapping {
            kind: EntryKind::Send.into(),
            external_type: "x".into(),
            fidelity: Fidelity::BitExact,
        }],
    );
    assert_ne!(e1.envelope_hash().unwrap(), e2.envelope_hash().unwrap());
}

#[test]
fn otel_ingest_lineage_only_non_empty_and_no_cert() {
    let spans = vec![OtelSpan {
        trace_id: "trace1".into(),
        span_id: "span1".into(),
        parent_span_id: None,
        name: "op-a".into(),
        events: vec![OtelEvent { name: "ev1".into() }],
        ..Default::default()
    }];
    let journal = ingest_otel_with_fidelity(spans, Fidelity::LineageOnly).unwrap();
    assert!(!journal.is_empty());
    // LineageOnly never produces certificates; check fidelity via envelope and wrapper.
    let env = InterchangeEnvelope::new(
        EnvelopeHeader::new("otel".into(), "test".into()),
        vec![EntryMapping {
            kind: EntryKind::Outcome.into(),
            external_type: "otel.span".into(),
            fidelity: Fidelity::LineageOnly,
        }],
    );
    assert_eq!(env.fidelity(), Fidelity::LineageOnly);
    // IngestedJournal must not be certifiable.
    let ing = ingest_otel_enveloped(
        vec![OtelSpan {
            trace_id: "t".into(),
            span_id: "s".into(),
            parent_span_id: None,
            name: "op".into(),
            events: vec![],
            ..Default::default()
        }],
        Fidelity::LineageOnly,
    )
    .unwrap();
    assert!(!ing.is_certifiable());
    assert!(matches!(
        ing.require_certifiable().unwrap_err(),
        ledger_adapters::AdapterError::FidelityMismatch
    ));
}

#[test]
fn otel_ingest_deterministic() {
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
    let a = ingest_otel_with_fidelity(spans.clone(), Fidelity::LineageOnly).unwrap();
    let b = ingest_otel_with_fidelity(spans, Fidelity::LineageOnly).unwrap();
    assert_eq!(a.root_hash(), b.root_hash());
}

#[test]
fn fidelity_flag_preserved_roundtrip() {
    let e = sample_envelope(Fidelity::LineageOnly);
    let b = e.to_canonical_bytes().unwrap();
    let d = InterchangeEnvelope::from_bytes(&b).unwrap();
    assert_eq!(d.body[0].fidelity, Fidelity::LineageOnly);
}

#[test]
fn serialization_error_propagated() {
    // Corrupt JSON via invalid envelope bytes.
    let e = sample_envelope(Fidelity::BitExact);
    let mut b = e.to_canonical_bytes().unwrap();
    // Corrupt JSON part.
    if b.len() > 10 {
        b[10] = 0xFF;
        b[11] = 0xFF;
    }
    let err = InterchangeEnvelope::from_bytes(&b).unwrap_err();
    assert!(matches!(
        err,
        ledger_adapters::AdapterError::Serialization(_)
    ));
}

#[test]
fn otel_enveloped_certifiable_only_bitexact() {
    let spans = vec![OtelSpan {
        trace_id: "t".into(),
        span_id: "s".into(),
        parent_span_id: None,
        name: "op".into(),
        events: vec![],
        ..Default::default()
    }];
    let lo = ingest_otel_enveloped(spans.clone(), Fidelity::LineageOnly).unwrap();
    let be = ingest_otel_enveloped(spans, Fidelity::BitExact).unwrap();
    assert!(!lo.is_certifiable());
    assert!(be.is_certifiable());
    // Envelope hash is deterministic.
    let h_lo = lo.envelope_hash().unwrap();
    let h_be = be.envelope_hash().unwrap();
    assert_ne!(h_lo, h_be);
}
