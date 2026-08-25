//! Effect origin capture: where in system-under-test source a journaled
//! effect happened.
//!
//! Origins live in a per-session side channel keyed by entry hash. They never
//! enter journal bytes, hashes, or roots: two runs with capture enabled and
//! disabled must produce byte-identical journals. Wasm guests and programmatic
//! runs report [`OriginSource::Unknown`]; native callers get source locations
//! through the tracked aliases on [`crate::effects::{NetExt, FsExt}`].

use core::panic::Location;

use ledger_format::Hash;

/// Source location of the system-under-test call that produced an effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectOrigin {
    pub file: &'static str,
    pub line: u32,
    pub column: u32,
}

impl EffectOrigin {
    /// Capture the current call site. Only meaningful on functions marked
    /// `#[track_caller]`.
    #[track_caller]
    pub fn caller() -> Self {
        Self::from(Location::caller())
    }
}

impl From<&'static Location<'static>> for EffectOrigin {
    fn from(location: &'static Location<'static>) -> Self {
        Self {
            file: location.file(),
            line: location.line(),
            column: location.column(),
        }
    }
}

/// Provenance of one journaled effect.
///
/// The Span variant is where OpenTelemetry ingest lands later (span name plus
/// trace id instead of a Rust call site); it is declared now so adding it to
/// the wire-adjacent surface later stays additive.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum OriginSource {
    /// Native caller captured through `#[track_caller]`.
    Source(EffectOrigin),
    /// Foreign-process or guest effect with span-level provenance.
    Span { name: Box<str>, trace_id: [u8; 16] },
    /// No provenance available (guests, programmatic runs).
    #[default]
    Unknown,
}

impl From<&'static Location<'static>> for OriginSource {
    fn from(location: &'static Location<'static>) -> Self {
        Self::Source(EffectOrigin::from(location))
    }
}

/// Side-channel log of effect origins, keyed by journal entry hash.
///
/// Never serialized into journals or manifests; lives only as long as the
/// backend session. Deterministic by construction: the same seed produces the
/// same entries, so replay repopulates the same origins.
#[derive(Default)]
pub(crate) struct OriginLog {
    // ledger-lint:allow:HashMap (keyed by entry hash; append order comes
    // from the side Vec, never from map iteration)
    map: std::collections::HashMap<Hash, OriginSource>,
    order: Vec<Hash>,
}

impl OriginLog {
    pub fn record(&mut self, id: Hash, source: OriginSource) {
        if matches!(source, OriginSource::Unknown) {
            return;
        }
        if self.map.insert(id, source).is_none() {
            self.order.push(id);
        }
    }

    pub fn get(&self, id: &Hash) -> Option<&OriginSource> {
        self.map.get(id)
    }

    /// Snapshot in append order.
    pub fn snapshot(&self) -> Vec<(Hash, OriginSource)> {
        self.order
            .iter()
            .map(|id| (*id, self.map[id].clone()))
            .collect()
    }
}
