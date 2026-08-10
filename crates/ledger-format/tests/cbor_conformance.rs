use std::collections::BTreeMap;

use ledger_format::cbor::{self, CborError, CborValue};
use ledger_format::{EntryData, EntryKind, FaultSpec, Payload, RunManifest};

#[test]
fn cbor_enforces_canonical_key_sorting() {
    let map_items = vec![
        (CborValue::Text("longer_key".into()), CborValue::Unsigned(1)),
        (CborValue::Text("a".into()), CborValue::Unsigned(2)),
        (CborValue::Text("b".into()), CborValue::Unsigned(3)),
    ];

    let val = CborValue::Map(map_items);
    let bytes = val.to_canonical_bytes();

    let decoded = CborValue::from_canonical_bytes(&bytes).unwrap();
    if let CborValue::Map(entries) = decoded {
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].0, CborValue::Text("a".into()));
        assert_eq!(entries[1].0, CborValue::Text("b".into()));
        assert_eq!(entries[2].0, CborValue::Text("longer_key".into()));
    } else {
        panic!("expected Map value");
    }
}

#[test]
fn cbor_rejects_non_canonical_integers() {
    let non_canonical_u8 = vec![0x18, 0x17];
    assert_eq!(
        CborValue::from_canonical_bytes(&non_canonical_u8),
        Err(CborError::NonCanonicalIntegerEncoding)
    );

    let non_canonical_u16 = vec![0x19, 0x00, 0xff];
    assert_eq!(
        CborValue::from_canonical_bytes(&non_canonical_u16),
        Err(CborError::NonCanonicalIntegerEncoding)
    );

    let non_canonical_u32 = vec![0x1a, 0x00, 0x00, 0xff, 0xff];
    assert_eq!(
        CborValue::from_canonical_bytes(&non_canonical_u32),
        Err(CborError::NonCanonicalIntegerEncoding)
    );
}

#[test]
fn cbor_rejects_trailing_bytes() {
    let mut bytes = Vec::new();
    cbor::unsigned(&mut bytes, 42);
    bytes.push(0x00);
    assert_eq!(
        CborValue::from_canonical_bytes(&bytes),
        Err(CborError::TrailingBytes)
    );
}

#[test]
fn cbor_round_trips_nested_structures() {
    let val = CborValue::Array(vec![
        CborValue::Unsigned(100),
        CborValue::Negative(41),
        CborValue::Text("deterministic".into()),
        CborValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
        CborValue::Bool(true),
        CborValue::Null,
    ]);

    let bytes = val.to_canonical_bytes();
    let decoded = CborValue::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(val, decoded);
}

fn entry(kind: EntryKind, actor: u32, payload: Payload) -> EntryData {
    EntryData {
        kind,
        actor,
        parents: vec![],
        vector_clock: vec![],
        sequence: 0,
        payload,
    }
}

#[test]
fn payload_empty_round_trips() {
    // Payload::Empty encodes as array(1) followed by discriminant 6: [0x81, 0x06].
    let mut out = Vec::new();
    Payload::Empty.encode(&mut out);
    assert_eq!(out, vec![0x81, 0x06]);

    // In a full entry the payload is the final element of the 6-item array.
    let data = entry(EntryKind::Spawn, 0, Payload::Empty);
    let bytes = data.canonical_bytes();
    assert_eq!(bytes[0], 0x86);
    assert!(bytes.ends_with(&[0x81, 0x06]));
}

#[test]
fn floats_encode_minimal_width() {
    // 1.0 is exactly representable in half precision: 0x3c00.
    assert_eq!(
        CborValue::Float(1.0).try_to_canonical_bytes().unwrap(),
        vec![0xf9, 0x3c, 0x00]
    );
    // 1.5 is also exactly representable in half precision: 0x3e00, so the
    // minimal width is half, not single.
    assert_eq!(
        CborValue::Float(1.5).try_to_canonical_bytes().unwrap(),
        vec![0xf9, 0x3e, 0x00]
    );
    // 1 + 2^-13 is not half-representable but round-trips through f32: single.
    let single_val = 1.0 + 2.0_f64.powi(-13);
    assert_eq!(
        CborValue::Float(single_val)
            .try_to_canonical_bytes()
            .unwrap(),
        vec![0xfa, 0x3f, 0x80, 0x04, 0x00]
    );
    // A large value not representable in f32: double.
    let big_bytes = CborValue::Float(1e100).try_to_canonical_bytes().unwrap();
    assert_eq!(big_bytes[0], 0xfb);
    assert_eq!(big_bytes.len(), 9);
    assert_eq!(
        CborValue::Float(-0.0).try_to_canonical_bytes(),
        Err(CborError::NonCanonicalFloat)
    );
    assert_eq!(
        CborValue::Float(f64::NAN).try_to_canonical_bytes(),
        Err(CborError::NonCanonicalFloat)
    );
}

#[test]
fn floats_reject_non_canonical() {
    // 1.5 encoded as double fits f32: non-canonical.
    let double_1_5 = [0xfb, 0x3f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(
        CborValue::from_canonical_bytes(&double_1_5),
        Err(CborError::NonCanonicalFloat)
    );
    let neg_zero = [0xfb, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(
        CborValue::from_canonical_bytes(&neg_zero),
        Err(CborError::NonCanonicalFloat)
    );
    let nan = [0xfb, 0x7f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(
        CborValue::from_canonical_bytes(&nan),
        Err(CborError::NonCanonicalFloat)
    );
    // 1.0 as single fits f16: non-canonical.
    let single_1_0 = [0xfa, 0x3f, 0x80, 0x00, 0x00];
    assert_eq!(
        CborValue::from_canonical_bytes(&single_1_0),
        Err(CborError::NonCanonicalFloat)
    );
    let half_neg_zero = [0xf9, 0x80, 0x00];
    assert_eq!(
        CborValue::from_canonical_bytes(&half_neg_zero),
        Err(CborError::NonCanonicalFloat)
    );
    let half_nan = [0xf9, 0x7e, 0x00];
    assert_eq!(
        CborValue::from_canonical_bytes(&half_nan),
        Err(CborError::NonCanonicalFloat)
    );

    // Minimal-width floats still decode: half 1.0 and single 1 + 2^-13.
    let half_1_0 = CborValue::from_canonical_bytes(&[0xf9, 0x3c, 0x00]).unwrap();
    assert_eq!(half_1_0, CborValue::Float(1.0));
    let single_val = CborValue::from_canonical_bytes(&[0xfa, 0x3f, 0x80, 0x04, 0x00]).unwrap();
    assert_eq!(single_val, CborValue::Float(1.0 + 2.0_f64.powi(-13)));
}

#[test]
fn all_half_precision_patterns_round_trip() {
    // Every f16 bit pattern must either decode to a canonical float that
    // re-encodes to the same bytes, or be rejected as -0.0 / NaN. This guards
    // the manual half-precision conversion against regressions.
    for bits in 0u16..=u16::MAX {
        let bytes = [0xf9, (bits >> 8) as u8, bits as u8];
        match CborValue::from_canonical_bytes(&bytes) {
            Ok(value) => {
                let reencoded = value.to_canonical_bytes();
                assert_eq!(reencoded, bytes.to_vec(), "f16 pattern {bits:#06x}");
            }
            Err(CborError::NonCanonicalFloat) => {}
            Err(other) => panic!("f16 pattern {bits:#06x} rejected with {other:?}"),
        }
    }
}

#[test]
fn unknown_tag_rejected() {
    // Tag 0 is not on the allowlist (empty by policy).
    assert_eq!(
        CborValue::from_canonical_bytes(&[0xc0, 0x00]),
        Err(CborError::UnknownTag(0))
    );
    // The encoder refuses to emit disallowed tags too.
    let tagged = CborValue::Tag(0, Box::new(CborValue::Unsigned(1)));
    assert_eq!(
        tagged.try_to_canonical_bytes(),
        Err(CborError::UnknownTag(0))
    );
}

#[test]
fn duplicate_map_key_rejected_on_encode() {
    let val = CborValue::Map(vec![
        (CborValue::Unsigned(1), CborValue::Unsigned(10)),
        (CborValue::Unsigned(1), CborValue::Unsigned(20)),
    ]);
    assert_eq!(
        val.try_to_canonical_bytes(),
        Err(CborError::DuplicateMapKey)
    );
    // Distinct values whose canonical key bytes collide are also rejected.
    let val = CborValue::Map(vec![
        (CborValue::Unsigned(24), CborValue::Unsigned(1)),
        (CborValue::Unsigned(24), CborValue::Unsigned(2)),
    ]);
    assert_eq!(
        val.try_to_canonical_bytes(),
        Err(CborError::DuplicateMapKey)
    );
}

#[test]
fn hostile_input_never_panics() {
    // Huge array / map / byte / text counts (2^64 - 1) must not over-allocate.
    // Deep nesting exceeds the depth limit. Indefinite-length forms, truncated
    // headers and payloads, short counts, and non-shortest integers complete
    // the hostile set.
    let hostile: Vec<Vec<u8>> = vec![
        vec![0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        vec![0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        vec![0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        vec![0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        {
            let mut deep = vec![0x81; 201];
            deep.push(0x00);
            deep
        },
        vec![0x9f],
        vec![0xbf],
        vec![0xff],
        vec![0x5f],
        vec![0x7f],
        vec![0x18],
        vec![0x19, 0x01],
        vec![0x1a, 0x00, 0x00],
        vec![0x1b, 0x00, 0x00, 0x00, 0x00, 0x00],
        vec![0xf9, 0x3c],
        vec![0xfa, 0x3f, 0x80],
        vec![0xfb, 0x3f, 0xf8, 0x00],
        Vec::new(),
        vec![0x82, 0x01],
        vec![
            0x82, 0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
        ],
        vec![0x18, 0x00],
    ];

    for input in hostile {
        let result = CborValue::from_canonical_bytes(&input);
        assert!(
            result.is_err(),
            "hostile input {:02x?} must be rejected, got {:?}",
            input,
            result
        );
    }
}

#[test]
fn tolerant_reader_accepts_superset_forms() {
    let reader = cbor::TolerantReader::new();

    // Indefinite-length array: accepted by the tolerant reader, rejected by
    // the canonical decoder.
    let indefinite_array = vec![0x9f, 0x01, 0x02, 0xff];
    assert_eq!(
        CborValue::from_canonical_bytes(&indefinite_array),
        Err(CborError::IndefiniteLengthForbidden)
    );
    assert_eq!(
        reader.parse(&indefinite_array),
        Ok(CborValue::Array(vec![
            CborValue::Unsigned(1),
            CborValue::Unsigned(2),
        ]))
    );

    // Indefinite-length map.
    let indefinite_map = vec![0xbf, 0x01, 0x02, 0xff];
    assert_eq!(
        CborValue::from_canonical_bytes(&indefinite_map),
        Err(CborError::IndefiniteLengthForbidden)
    );
    assert_eq!(
        reader.parse(&indefinite_map),
        Ok(CborValue::Map(vec![(
            CborValue::Unsigned(1),
            CborValue::Unsigned(2),
        )]))
    );

    // Indefinite-length byte string, single chunk.
    let indefinite_bytes = vec![0x5f, 0x41, 0x61, 0xff];
    assert_eq!(
        CborValue::from_canonical_bytes(&indefinite_bytes),
        Err(CborError::IndefiniteLengthForbidden)
    );
    assert_eq!(
        reader.parse(&indefinite_bytes),
        Ok(CborValue::Bytes(vec![0x61]))
    );

    // Indefinite-length byte string, multiple chunks concatenated in order.
    let indefinite_bytes_multi = vec![0x5f, 0x41, 0x61, 0x42, 0x62, 0x63, 0xff];
    assert_eq!(
        CborValue::from_canonical_bytes(&indefinite_bytes_multi),
        Err(CborError::IndefiniteLengthForbidden)
    );
    assert_eq!(
        reader.parse(&indefinite_bytes_multi),
        Ok(CborValue::Bytes(vec![0x61, 0x62, 0x63]))
    );

    // Indefinite-length byte string with a nested indefinite chunk.
    let indefinite_bytes_nested = vec![0x5f, 0x5f, 0x41, 0x61, 0xff, 0xff];
    assert_eq!(
        CborValue::from_canonical_bytes(&indefinite_bytes_nested),
        Err(CborError::IndefiniteLengthForbidden)
    );
    assert_eq!(
        reader.parse(&indefinite_bytes_nested),
        Ok(CborValue::Bytes(vec![0x61]))
    );

    // Indefinite-length text string, multiple chunks concatenated in order.
    let indefinite_text = vec![0x7f, 0x61, 0x61, 0x61, 0x62, 0xff];
    assert_eq!(
        CborValue::from_canonical_bytes(&indefinite_text),
        Err(CborError::IndefiniteLengthForbidden)
    );
    assert_eq!(
        reader.parse(&indefinite_text),
        Ok(CborValue::Text("ab".into()))
    );

    // Non-shortest integer: 24 encoded in the two-byte form.
    let non_shortest = vec![0x19, 0x00, 0x18];
    assert_eq!(
        CborValue::from_canonical_bytes(&non_shortest),
        Err(CborError::NonCanonicalIntegerEncoding)
    );
    assert_eq!(reader.parse(&non_shortest), Ok(CborValue::Unsigned(24)));
    // Non-shortest integer: 23 encoded in the one-byte-extra form.
    let non_shortest_23 = vec![0x18, 0x17];
    assert_eq!(
        CborValue::from_canonical_bytes(&non_shortest_23),
        Err(CborError::NonCanonicalIntegerEncoding)
    );
    assert_eq!(reader.parse(&non_shortest_23), Ok(CborValue::Unsigned(23)));

    // Duplicate map keys are kept in order.
    let duplicate_keys = vec![0xa2, 0x00, 0x01, 0x00, 0x02];
    assert_eq!(
        CborValue::from_canonical_bytes(&duplicate_keys),
        Err(CborError::DuplicateMapKey)
    );
    assert_eq!(
        reader.parse(&duplicate_keys),
        Ok(CborValue::Map(vec![
            (CborValue::Unsigned(0), CborValue::Unsigned(1)),
            (CborValue::Unsigned(0), CborValue::Unsigned(2)),
        ]))
    );

    // Non-minimal float width: 1.5 encoded as a double.
    let non_minimal_float = [0xfb, 0x3f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(
        CborValue::from_canonical_bytes(&non_minimal_float),
        Err(CborError::NonCanonicalFloat)
    );
    assert_eq!(reader.parse(&non_minimal_float), Ok(CborValue::Float(1.5)));

    // Non-minimal float width: 1.0 encoded as a single that fits half.
    let non_minimal_single = [0xfa, 0x3f, 0x80, 0x00, 0x00];
    assert_eq!(
        CborValue::from_canonical_bytes(&non_minimal_single),
        Err(CborError::NonCanonicalFloat)
    );
    assert_eq!(reader.parse(&non_minimal_single), Ok(CborValue::Float(1.0)));

    // Unknown semantic tag: the tolerant reader stores it.
    let unknown_tag = vec![0xc0, 0x00];
    assert_eq!(
        CborValue::from_canonical_bytes(&unknown_tag),
        Err(CborError::UnknownTag(0))
    );
    assert_eq!(
        reader.parse(&unknown_tag),
        Ok(CborValue::Tag(0, Box::new(CborValue::Unsigned(0))))
    );

    // -0.0 and NaN as double.
    let neg_zero_double = [0xfb, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(
        CborValue::from_canonical_bytes(&neg_zero_double),
        Err(CborError::NonCanonicalFloat)
    );
    assert_eq!(reader.parse(&neg_zero_double), Ok(CborValue::Float(-0.0)));
    let nan_double = [0xfb, 0x7f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(
        CborValue::from_canonical_bytes(&nan_double),
        Err(CborError::NonCanonicalFloat)
    );
    assert_eq!(reader.parse(&nan_double), Ok(CborValue::Float(f64::NAN)));

    // -0.0 and NaN as half.
    let neg_zero_half = [0xf9, 0x80, 0x00];
    assert_eq!(
        CborValue::from_canonical_bytes(&neg_zero_half),
        Err(CborError::NonCanonicalFloat)
    );
    assert_eq!(reader.parse(&neg_zero_half), Ok(CborValue::Float(-0.0)));
    let nan_half = [0xf9, 0x7e, 0x00];
    assert_eq!(
        CborValue::from_canonical_bytes(&nan_half),
        Err(CborError::NonCanonicalFloat)
    );
    match reader.parse(&nan_half) {
        Ok(CborValue::Float(value)) => assert!(value.is_nan()),
        other => panic!("half NaN must parse to a NaN float, got {other:?}"),
    }

    // A non-shortest length header for a container is also accepted.
    let non_shortest_array_len = vec![0x98, 0x00];
    assert_eq!(
        CborValue::from_canonical_bytes(&non_shortest_array_len),
        Err(CborError::NonCanonicalIntegerEncoding)
    );
    assert_eq!(
        reader.parse(&non_shortest_array_len),
        Ok(CborValue::Array(Vec::new()))
    );

    // The free-function entry point matches the reader.
    assert_eq!(
        cbor::parse_tolerant(&non_shortest_array_len),
        Ok(CborValue::Array(Vec::new()))
    );
}

#[test]
fn tolerant_reader_enforces_depth_limit() {
    // Deeply nested input is rejected with DepthLimitExceeded, never a stack
    // overflow. The default limit matches the canonical decoder.
    let mut deep = vec![0x81; 300];
    deep.push(0x00);
    assert_eq!(
        cbor::parse_tolerant(&deep),
        Err(CborError::DepthLimitExceeded)
    );
    assert_eq!(
        CborValue::from_canonical_bytes(&deep),
        Err(CborError::DepthLimitExceeded)
    );

    // A custom shallow limit rejects 5-level nesting.
    let five_deep = vec![0x81, 0x81, 0x81, 0x81, 0x81, 0x00];
    let shallow = cbor::TolerantReader::with_max_depth(4);
    assert_eq!(
        shallow.parse(&five_deep),
        Err(CborError::DepthLimitExceeded)
    );

    // The same limit accepts exactly 4 levels of nesting.
    let four_deep = vec![0x81, 0x81, 0x81, 0x81, 0x00];
    let expected = CborValue::Array(vec![CborValue::Array(vec![CborValue::Array(vec![
        CborValue::Array(vec![CborValue::Unsigned(0)]),
    ])])]);
    assert_eq!(shallow.parse(&four_deep), Ok(expected));
}

#[test]
fn entry_kind_structured_encoding_stable() {
    let rng = entry(EntryKind::RngDraw { stream: 7 }, 0, Payload::Empty);
    assert_eq!(
        rng.canonical_bytes(),
        vec![0x86, 0x82, 0x0b, 0x07, 0x00, 0x80, 0x80, 0x00, 0x81, 0x06]
    );

    let step = entry(
        EntryKind::InputStep {
            generator: 2,
            replay: 3,
        },
        0,
        Payload::Empty,
    );
    assert_eq!(
        step.canonical_bytes(),
        vec![
            0x86, 0x83, 0x10, 0x02, 0x03, 0x00, 0x80, 0x80, 0x00, 0x81, 0x06
        ]
    );

    let crash = entry(
        EntryKind::Fault {
            fault: FaultSpec::CrashState(3),
        },
        0,
        Payload::Empty,
    );
    assert_eq!(
        crash.canonical_bytes(),
        vec![
            0x86, 0x82, 0x15, 0x82, 0x05, 0x03, 0x00, 0x80, 0x80, 0x00, 0x81, 0x06
        ]
    );

    let delay = entry(
        EntryKind::Fault {
            fault: FaultSpec::Delay { ticks: 100 },
        },
        0,
        Payload::Empty,
    );
    assert_eq!(
        delay.canonical_bytes(),
        vec![
            0x86, 0x82, 0x15, 0x82, 0x01, 0x18, 0x64, 0x00, 0x80, 0x80, 0x00, 0x81, 0x06
        ]
    );

    let partition = entry(
        EntryKind::Fault {
            fault: FaultSpec::Partition { src: 1, dst: 2 },
        },
        0,
        Payload::Empty,
    );
    assert_eq!(
        partition.canonical_bytes(),
        vec![
            0x86, 0x82, 0x15, 0x83, 0x02, 0x01, 0x02, 0x00, 0x80, 0x80, 0x00, 0x81, 0x06
        ]
    );

    let drop = entry(
        EntryKind::Fault {
            fault: FaultSpec::Drop,
        },
        0,
        Payload::Empty,
    );
    assert_eq!(
        drop.canonical_bytes(),
        vec![0x86, 0x82, 0x15, 0x00, 0x00, 0x80, 0x80, 0x00, 0x81, 0x06]
    );

    for data in [&rng, &step, &crash, &delay, &partition, &drop] {
        assert_eq!(data.canonical_bytes(), data.canonical_bytes());
    }
}

#[test]
fn manifest_round_trip_and_version_reject() {
    let manifest = RunManifest {
        format_version: 1,
        root_seed: [7u8; 32],
        policy_tag: "bandit".into(),
        journal_root: [9u8; 32],
        entry_count: 1234,
        actor_heads: BTreeMap::from([(1u32, [1u8; 32]), (2u32, [2u8; 32])]),
        extensions: BTreeMap::new(),
    };

    let bytes = manifest.to_canonical_bytes().unwrap();
    assert_eq!(bytes[0], 0x87);

    let decoded = RunManifest::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(decoded, manifest);

    // A manifest declaring version 2 must be rejected.
    let mut bad = bytes.clone();
    bad[1] = 0x02;
    assert_eq!(
        RunManifest::from_canonical_bytes(&bad),
        Err(CborError::UnsupportedVersion(2))
    );
}
