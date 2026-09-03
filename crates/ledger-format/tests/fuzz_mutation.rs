//! Deterministic mutation harness for the zero-trust parser boundary.
//!
//! Extends the curated hostile-input tests in `conformance.rs` to mutated and
//! random bytes. Every reader must either decode the input or return an
//! error, never panic. Fixed seeds make the harness byte-identical on every
//! run, so it is a load-bearing gate in regular CI. The libFuzzer targets in
//! `crates/ledger-format/fuzz/` extend the same property with coverage-guided
//! search.

use std::collections::BTreeMap;

use ledger_format::cbor::{self, CborValue};
use ledger_format::{EntryData, EntryKind, RunManifest};

/// Mutation rounds per seed. Bounded so the harness finishes fast in CI.
const ROUNDS_PER_SEED: usize = 1500;

/// Fixed seeds keep every run byte-identical.
const SEEDS: [u64; 4] = [0xba5e_1d00, 0x5eed_cafe, 0xc0f_feee, 0xdead_beef];

/// Bytes that exercise decode-path corners when planted anywhere.
const CORNER_BYTES: [u8; 12] = [
    0x00, 0x18, 0x1b, 0x5f, 0x7f, 0x9f, 0xbf, 0xc0, 0xf9, 0xfb, 0xff, 0xf6,
];

/// Deterministic splitmix64 PRNG.
///
/// The harness must be byte-identical across runs, so the PRNG is seeded
/// from a constant and never touches ambient entropy.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn next_usize(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }

    fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }
}

/// Seed corpus of valid inputs the harness mutates.
///
/// The entries cover unit, structured, and fault kinds plus the full manifest
/// wire form, so mutations hit every CBOR structure the engine writes.
fn seed_corpus() -> Vec<Vec<u8>> {
    let entries: Vec<(EntryKind, ledger_format::EntryPayload)> = [
        (
            EntryKind::Spawn,
            ledger_format::EntryPayload::Spawn {
                child_actor: ledger_format::ActorId(7),
            },
        ),
        (
            EntryKind::Send,
            ledger_format::EntryPayload::Send(ledger_format::SendFrame {
                message_id: ledger_format::MessageId::new(ledger_format::ActorId(7), 0),
                from: ledger_format::ActorId(7),
                to: ledger_format::ActorId(1),
                original_content: b"hello determinism".to_vec(),
            }),
        ),
        (
            EntryKind::RngDraw,
            ledger_format::EntryPayload::RngDraw(ledger_format::RngDrawPayload {
                stream: ledger_format::StreamId(7),
                draw_index: 0,
                content: 42u64.to_le_bytes().to_vec(),
            }),
        ),
        (
            EntryKind::InputStep,
            ledger_format::EntryPayload::InputStep(ledger_format::InputStepPayload {
                generator: 2,
                replay: 3,
                value: ledger_format::CanonicalValue::Unsigned(5),
            }),
        ),
        (
            EntryKind::Fault,
            ledger_format::EntryPayload::Fault(ledger_format::FaultPayload::Partition {
                src: ledger_format::ActorId(1),
                dst: ledger_format::ActorId(2),
                enabled: true,
            }),
        ),
        (
            EntryKind::Fault,
            ledger_format::EntryPayload::Fault(ledger_format::FaultPayload::CrashActor {
                actor: ledger_format::ActorId(7),
                crash_operation: ledger_format::CrashOperation::DropAllUnsynced,
            }),
        ),
        (
            EntryKind::FsWrite,
            ledger_format::EntryPayload::FsWrite(ledger_format::FsWritePayload::Allocate {
                path_ref: ledger_format::PathRef {
                    path_hash: [0xcc; 32],
                    canonical_path: b"/data/f".to_vec(),
                },
            }),
        ),
    ]
    .to_vec();
    let mut corpus: Vec<Vec<u8>> = entries
        .iter()
        .map(|(kind, payload)| {
            EntryData {
                format_version: ledger_format::FORMAT_VERSION,
                kind: *kind,
                actor: ledger_format::ActorId(7),
                parents: smallvec::smallvec![
                    ledger_format::EntryHash([0xaa; 32]),
                    ledger_format::EntryHash([0xbb; 32])
                ],
                vector_clock: vec![1, 2, 3],
                sequence: ledger_format::SequenceNumber(4),
                payload: payload.clone(),
            }
            .try_canonical_bytes()
            .expect("seed entry encodes")
        })
        .collect();

    let manifest = RunManifest {
        format_version: ledger_format::FORMAT_VERSION,
        crash_semantics_version: ledger_format::CRASH_SEMANTICS_VERSION,
        execution_identity: None,
        root_seed: ledger_format::EntryHash([7u8; 32]),
        policy_tag: "pct".into(),
        journal_root: ledger_format::EntryHash([9u8; 32]),
        entry_count: 42,
        actor_heads: BTreeMap::from([
            (
                ledger_format::ActorId(0),
                ledger_format::EntryHash([1u8; 32]),
            ),
            (
                ledger_format::ActorId(1),
                ledger_format::EntryHash([2u8; 32]),
            ),
        ]),
    };
    corpus.push(
        manifest
            .to_canonical_bytes()
            .expect("seed manifest encodes"),
    );

    let nested = CborValue::Array(vec![
        CborValue::Map(vec![(
            CborValue::Text("actor".into()),
            CborValue::Array(vec![CborValue::Unsigned(0), CborValue::Unsigned(1)]),
        )]),
        CborValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
        CborValue::Float(1.5),
    ]);
    corpus.push(nested.to_canonical_bytes().unwrap());

    corpus
}

/// Applies one deterministic mutation to `base`.
fn mutate(rng: &mut SplitMix64, base: &[u8]) -> Vec<u8> {
    let mut out = base.to_vec();
    match rng.next_usize(7) {
        0 => {
            if !out.is_empty() {
                let index = rng.next_usize(out.len());
                out[index] ^= 1u8 << rng.next_usize(8);
            }
        }
        1 => {
            if !out.is_empty() {
                let index = rng.next_usize(out.len());
                out[index] = rng.next_u8();
            }
        }
        2 => {
            if !out.is_empty() {
                let index = rng.next_usize(out.len());
                out[index] = CORNER_BYTES[rng.next_usize(CORNER_BYTES.len())];
            }
        }
        3 => {
            let index = rng.next_usize(out.len() + 1);
            out.insert(index, rng.next_u8());
        }
        4 => {
            if !out.is_empty() {
                let index = rng.next_usize(out.len());
                out.remove(index);
            }
        }
        5 => {
            if !out.is_empty() {
                let index = rng.next_usize(out.len());
                let byte = out[index];
                let insert_at = rng.next_usize(out.len() + 1);
                out.insert(insert_at, byte);
            }
        }
        _ => {
            let len = rng.next_usize(out.len() + 1);
            out.truncate(len);
        }
    }
    out
}

/// Builds a random byte buffer of bounded length, exercising arbitrary input.
fn random_buffer(rng: &mut SplitMix64) -> Vec<u8> {
    let len = rng.next_usize(65);
    (0..len).map(|_| rng.next_u8()).collect()
}

/// Reports a reader panic with the exact input so it can become a regression
/// test. Never returns.
fn panic_payload(payload: Box<dyn std::any::Any + Send>, reader: &str, bytes: &[u8]) -> ! {
    let detail = if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_string()
    };
    panic!("{reader} panicked on input {:02x?}: {detail}", bytes);
}

/// Runs every zero-trust reader over `bytes` and asserts none panics.
///
/// The tolerant reader is a superset: any input the canonical decoder
/// accepts, the tolerant reader must also accept to the same value.
fn run_readers(bytes: &[u8]) {
    let canonical = match std::panic::catch_unwind(|| CborValue::from_canonical_bytes(bytes)) {
        Ok(result) => result,
        Err(payload) => panic_payload(payload, "canonical decoder", bytes),
    };
    let _ = std::panic::catch_unwind(|| RunManifest::from_canonical_bytes(bytes))
        .unwrap_or_else(|payload| panic_payload(payload, "manifest reader", bytes));
    let tolerant = std::panic::catch_unwind(|| cbor::TolerantReader::new().parse(bytes))
        .unwrap_or_else(|payload| panic_payload(payload, "tolerant reader", bytes));

    if let Ok(value) = canonical {
        let parsed = tolerant.unwrap_or_else(|err| {
            panic!(
                "tolerant reader rejected canonical input {:02x?}: {err:?}",
                bytes
            )
        });
        assert_eq!(
            parsed, value,
            "canonical and tolerant readers disagree on {:02x?}",
            bytes
        );
    }
}

#[test]
fn mutation_harness_never_panics() {
    let corpus = seed_corpus();
    assert!(corpus.len() >= 8, "seed corpus too small: {}", corpus.len());
    for seed in &corpus {
        assert!(
            CborValue::from_canonical_bytes(seed).is_ok(),
            "seed input must decode canonically"
        );
        assert!(
            cbor::TolerantReader::new().parse(seed).is_ok(),
            "seed input must parse tolerantly"
        );
    }

    let manifest = RunManifest {
        format_version: ledger_format::FORMAT_VERSION,
        crash_semantics_version: ledger_format::CRASH_SEMANTICS_VERSION,
        execution_identity: None,
        root_seed: ledger_format::EntryHash([7u8; 32]),
        policy_tag: "pct".into(),
        journal_root: ledger_format::EntryHash([9u8; 32]),
        entry_count: 42,
        actor_heads: BTreeMap::from([
            (
                ledger_format::ActorId(0),
                ledger_format::EntryHash([1u8; 32]),
            ),
            (
                ledger_format::ActorId(1),
                ledger_format::EntryHash([2u8; 32]),
            ),
        ]),
    };
    let manifest_bytes = manifest
        .to_canonical_bytes()
        .expect("seed manifest encodes");
    assert!(
        RunManifest::from_canonical_bytes(&manifest_bytes).is_ok(),
        "seed manifest must decode"
    );

    let mut checks = 0usize;
    for &seed in &SEEDS {
        let mut rng = SplitMix64(seed);
        for _ in 0..ROUNDS_PER_SEED {
            let bytes = if rng.next_usize(4) == 0 {
                random_buffer(&mut rng)
            } else {
                let base = &corpus[rng.next_usize(corpus.len())];
                mutate(&mut rng, base)
            };
            run_readers(&bytes);
            checks += 1;
        }
    }
    assert_eq!(
        checks,
        ROUNDS_PER_SEED * SEEDS.len(),
        "mutation rounds must match the fixed budget"
    );
}
