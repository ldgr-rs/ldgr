//! Differential property test for the persistent vector clock.
//!
//! The production `VectorClock` is backed by an immutable rpds red-black tree.
//! This test replays the same random program of `incremented` and `merge`
//! operations against a reference implementation built on `std`'s `BTreeMap`
//! with the original (pre-rpds) semantics. The two must produce byte-identical
//! canonical encodings and identical `get` / `happens-before` results for every
//! generated clock.

use std::collections::BTreeMap;

use ledger_format::{ActorId, cbor};
use ledger_journal::VectorClock;
use proptest::prelude::*;

const ACTOR_UNIVERSE: u32 = 8;

/// Old-semantics reference implementation on a `BTreeMap`.
fn increment_ref(clock: &BTreeMap<ActorId, u64>, actor: ActorId) -> BTreeMap<ActorId, u64> {
    let mut next = clock.clone();
    let value = next.entry(actor).or_default();
    *value = value.saturating_add(1);
    next
}

fn merge_ref(
    left: &BTreeMap<ActorId, u64>,
    right: &BTreeMap<ActorId, u64>,
) -> BTreeMap<ActorId, u64> {
    let mut merged = left.clone();
    for (&actor, &value) in right {
        merged
            .entry(actor)
            .and_modify(|current| *current = (*current).max(value))
            .or_insert(value);
    }
    merged
}

fn encode_ref(clock: &BTreeMap<ActorId, u64>) -> Vec<u8> {
    let mut out = Vec::with_capacity(clock.len() * 2);
    cbor::map(&mut out, clock.len());
    for (&actor, &value) in clock {
        cbor::unsigned(&mut out, actor as u64);
        cbor::unsigned(&mut out, value);
    }
    out
}

fn happens_before_or_equal_ref(
    left: &BTreeMap<ActorId, u64>,
    right: &BTreeMap<ActorId, u64>,
) -> bool {
    left.iter()
        .all(|(&actor, &value)| value <= right.get(&actor).copied().unwrap_or(0))
}

proptest! {
    /// Arbitrary program of `incremented` and `merge` operations over a small
    /// actor universe. Both implementations consume the identical program.
    #[test]
    fn differential_against_btreemap(
        ops in prop::collection::vec((0u8..2u8, 0u8..200u8), 1..64usize),
    ) {
        let mut impl_pool: Vec<VectorClock> = vec![VectorClock::new()];
        let mut ref_pool: Vec<BTreeMap<ActorId, u64>> = vec![BTreeMap::new()];

        for (op, param) in ops {
            let (impl_clock, ref_clock) = match op {
                0 => {
                    let actor = (param as ActorId % ACTOR_UNIVERSE) + 1;
                    let base_impl = impl_pool.last().unwrap();
                    let base_ref = ref_pool.last().unwrap();
                    (base_impl.incremented(actor), increment_ref(base_ref, actor))
                }
                _ => {
                    let idx = param as usize % impl_pool.len();
                    let base_impl = impl_pool.last().unwrap();
                    let base_ref = ref_pool.last().unwrap();
                    (
                        base_impl.merge(&impl_pool[idx]),
                        merge_ref(base_ref, &ref_pool[idx]),
                    )
                }
            };

            assert_eq!(
                impl_clock.encode(),
                encode_ref(&ref_clock),
                "encoded bytes diverge from the reference"
            );
            assert_eq!(impl_clock.len(), ref_clock.len());
            for actor in 1..=ACTOR_UNIVERSE as ActorId {
                assert_eq!(
                    impl_clock.get(actor),
                    ref_clock.get(&actor).copied().unwrap_or(0),
                    "get diverges for actor {actor}"
                );
            }

            impl_pool.push(impl_clock);
            ref_pool.push(ref_clock);
        }

        for i in 0..impl_pool.len() {
            for j in 0..impl_pool.len() {
                let impl_left = &impl_pool[i];
                let impl_right = &impl_pool[j];
                let ref_left = &ref_pool[i];
                let ref_right = &ref_pool[j];
                let ref_hb = happens_before_or_equal_ref(ref_left, ref_right);
                assert_eq!(
                    impl_left.happens_before_or_equal(impl_right),
                    ref_hb,
                    "happens_before_or_equal diverges for pair ({i}, {j})"
                );
                let ref_strict = ref_hb && ref_left != ref_right;
                assert_eq!(
                    impl_left.happens_before(impl_right),
                    ref_strict,
                    "happens_before diverges for pair ({i}, {j})"
                );
                let ref_concurrent = !happens_before_or_equal_ref(ref_left, ref_right)
                    && !happens_before_or_equal_ref(ref_right, ref_left);
                assert_eq!(
                    impl_left.concurrent_with(impl_right),
                    ref_concurrent,
                    "concurrent_with diverges for pair ({i}, {j})"
                );
            }
        }
    }
}
