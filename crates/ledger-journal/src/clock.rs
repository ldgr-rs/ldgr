//! Vector clocks and causal happens-before relations.
//!
//! A vector clock summarizes the causal history of an entry: for every actor,
//! the number of that actor's entries the entry depends on. Two clocks are
//! ordered component-wise. Unrelated clocks are concurrent.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
use ledger_format::{ActorId, cbor};
use rpds::RedBlackTreeMapSync;

/// A compact vector-clock summary.
///
/// Backed by a persistent red-black tree with structural sharing: an update
/// copies only the O(log n) touched path, so `incremented` is cheap and
/// forks cost O(1). The `_sync` Arc-backed variant keeps the clock `Send +
/// Sync` inside `Arc<Entry>`. Semantics match a plain `BTreeMap`.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct VectorClock(RedBlackTreeMapSync<ActorId, u64>);

impl fmt::Debug for VectorClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("VectorClock")
            .field(&self.iter().collect::<BTreeMap<ActorId, u64>>())
            .finish()
    }
}

impl VectorClock {
    pub fn new() -> Self {
        Self(RedBlackTreeMapSync::new_sync())
    }

    /// Merge two clocks by component-wise maximum.
    ///
    /// Returns a new clock; neither input is mutated. A lockstep walk over
    /// the two ascending iterators merges in O(#actors).
    pub fn merge(&self, other: &Self) -> Self {
        if self.0.is_empty() {
            return Self(other.0.clone());
        }
        if other.0.is_empty() {
            return Self(self.0.clone());
        }
        let mut left = self.0.iter().peekable();
        let mut right = other.0.iter().peekable();
        let mut merged = Vec::with_capacity(self.0.size() + other.0.size());
        while let (Some((lactor, lval)), Some((ractor, rval))) = (left.peek(), right.peek()) {
            match lactor.cmp(ractor) {
                Ordering::Less => {
                    merged.push((**lactor, **lval));
                    left.next();
                }
                Ordering::Greater => {
                    merged.push((**ractor, **rval));
                    right.next();
                }
                Ordering::Equal => {
                    merged.push((**lactor, (**lval).max(**rval)));
                    left.next();
                    right.next();
                }
            }
        }
        merged.extend(left.map(|(actor, value)| (*actor, *value)));
        merged.extend(right.map(|(actor, value)| (*actor, *value)));
        Self(merged.into_iter().collect())
    }

    /// Increment the component for an actor.
    ///
    /// Returns a new clock; the receiver is not mutated. The insert copies
    /// only the touched tree path, O(log #actors).
    pub fn incremented(&self, actor: ActorId) -> Self {
        let next = self.0.get(&actor).copied().unwrap_or(0).saturating_add(1);
        Self(self.0.insert(actor, next))
    }

    pub fn get(&self, actor: ActorId) -> u64 {
        self.0.get(&actor).copied().unwrap_or(0)
    }

    /// Return true when this clock happens before or equals another clock.
    pub fn happens_before_or_equal(&self, other: &Self) -> bool {
        self.0
            .iter()
            .all(|(actor, value)| *value <= other.get(*actor))
    }

    /// Return true when this clock strictly happens before another clock.
    pub fn happens_before(&self, other: &Self) -> bool {
        self.happens_before_or_equal(other) && self != other
    }

    /// Return true when two clocks are concurrent (neither happens before the other).
    pub fn concurrent_with(&self, other: &Self) -> bool {
        !self.happens_before_or_equal(other) && !other.happens_before_or_equal(self)
    }

    /// Encode clock into canonical CBOR map bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    /// Encode clock into a caller-provided buffer.
    ///
    /// Hot append paths reuse a scratch buffer to avoid one allocation per
    /// entry.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        cbor::map(out, self.0.size());
        for (actor, value) in self.0.iter() {
            cbor::unsigned(out, *actor as u64);
            cbor::unsigned(out, *value);
        }
    }

    /// Return `(actor, value)` pairs in ascending actor order.
    pub fn iter(&self) -> impl Iterator<Item = (ActorId, u64)> + '_ {
        self.0.iter().map(|(actor, value)| (*actor, *value))
    }

    pub fn len(&self) -> usize {
        self.0.size()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Construct a clock from an actor-to-count entry iterator.
    #[cfg(any(feature = "std", test))]
    pub(crate) fn from_map(entries: impl IntoIterator<Item = (ActorId, u64)>) -> Self {
        Self(entries.into_iter().collect())
    }

    /// Return an owned clock sharing this clock's structure.
    ///
    /// The persistent tree shares its root, so this is O(1) regardless of the
    /// actor count.
    pub fn compact(&self) -> Self {
        Self(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn decode_clock(bytes: &[u8]) -> BTreeMap<ActorId, u64> {
        ledger_format::CborValue::from_canonical_bytes(bytes)
            .map(|value| {
                let mut map = BTreeMap::new();
                if let ledger_format::CborValue::Map(entries) = value {
                    for (key, val) in entries {
                        let actor = match key {
                            ledger_format::CborValue::Unsigned(v) => v as ActorId,
                            _ => 0,
                        };
                        let count = match val {
                            ledger_format::CborValue::Unsigned(v) => v,
                            _ => 0,
                        };
                        map.insert(actor, count);
                    }
                }
                map
            })
            .unwrap_or_default()
    }

    #[test]
    fn merge_is_commutative() {
        let a = VectorClock::from_actor(1, 3).merge(&VectorClock::from_actor(2, 5));
        let b = VectorClock::from_actor(2, 5).merge(&VectorClock::from_actor(1, 3));
        assert_eq!(a, b);
    }

    #[test]
    fn merge_is_associative() {
        let a = VectorClock::from_actor(1, 2);
        let b = VectorClock::from_actor(2, 4);
        let c = VectorClock::from_actor(3, 1);
        assert_eq!(a.merge(&b).merge(&c), a.merge(&b.merge(&c)));
    }

    #[test]
    fn merge_takes_component_maximum() {
        let a = VectorClock::from_actor(1, 3).merge(&VectorClock::from_actor(2, 1));
        let b = VectorClock::from_actor(1, 1).merge(&VectorClock::from_actor(2, 5));
        let merged = a.merge(&b);
        assert_eq!(merged.get(1), 3);
        assert_eq!(merged.get(2), 5);
    }

    #[test]
    fn merge_does_not_mutate_inputs() {
        let a = VectorClock::from_actor(1, 3);
        let b = VectorClock::from_actor(1, 7);
        let merged = a.merge(&b);
        assert_eq!(a.get(1), 3);
        assert_eq!(b.get(1), 7);
        assert_eq!(merged.get(1), 7);
    }

    #[test]
    fn incremented_does_not_mutate_receiver() {
        let a = VectorClock::from_actor(1, 3);
        let b = a.incremented(1);
        assert_eq!(a.get(1), 3);
        assert_eq!(b.get(1), 4);
    }

    #[test]
    fn happens_before_orders_dependent_clocks() {
        let base = VectorClock::from_actor(1, 2);
        let later = base.incremented(1);
        assert!(base.happens_before(&later));
        assert!(!later.happens_before(&base));
    }

    #[test]
    fn happens_before_rejects_unrelated_clocks() {
        let a = VectorClock::from_actor(1, 5);
        let b = VectorClock::from_actor(2, 5);
        assert!(!a.happens_before(&b));
        assert!(!b.happens_before(&a));
        assert!(a.concurrent_with(&b));
    }

    #[test]
    fn equal_clocks_are_not_strictly_ordered() {
        let a = VectorClock::from_actor(1, 2);
        let b = a.compact();
        assert_eq!(a, b);
        assert!(!a.happens_before(&b));
        assert!(!a.concurrent_with(&b));
        assert!(a.happens_before_or_equal(&b));
    }

    #[test]
    fn encode_round_trips_through_iter() {
        let clock = VectorClock::from_actor(1, 2).merge(&VectorClock::from_actor(9, 4));
        let bytes = clock.encode();
        assert!(!bytes.is_empty());
        assert_eq!(decode_clock(&bytes), clock.iter().collect());
    }

    #[test]
    fn encode_emits_ascending_actor_keys() {
        let clock = VectorClock::from_actor(9, 1)
            .merge(&VectorClock::from_actor(2, 1))
            .merge(&VectorClock::from_actor(7, 1))
            .merge(&VectorClock::from_actor(1, 1));
        let decoded = decode_clock(&clock.encode());
        let keys: Vec<ActorId> = decoded.keys().copied().collect();
        assert_eq!(keys, vec![1, 2, 7, 9]);
    }

    #[test]
    fn merge_with_empty_yields_equal_content() {
        let a = VectorClock::from_actor(1, 3).merge(&VectorClock::new());
        let b = VectorClock::new().merge(&VectorClock::from_actor(1, 3));
        assert_eq!(a, b);
        assert_eq!(a.get(1), 3);
        assert_eq!(a.iter().collect::<BTreeMap<_, _>>(), [(1, 3)].into());
    }

    #[test]
    fn len_counts_active_actors() {
        let clock = VectorClock::from_actor(1, 2).merge(&VectorClock::from_actor(9, 4));
        assert_eq!(clock.len(), 2);
        assert_eq!(VectorClock::new().len(), 0);
    }

    impl VectorClock {
        fn from_actor(actor: ActorId, value: u64) -> Self {
            let mut clock = VectorClock::new();
            for _ in 0..value {
                clock = clock.incremented(actor);
            }
            clock
        }
    }
}
