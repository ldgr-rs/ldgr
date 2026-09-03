//! Effect origin capture: SUT source location per journaled effect.
//!
//! Origins stay in a per-session side channel keyed by entry hash and never
//! enter journal bytes, so capture on/off yields byte-identical journals.

use core::panic::Location;

use ledger_format::EntryHash;

/// Source location of the system-under-test call that produced an effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectOrigin {
    pub file: &'static str,
    pub line: u32,
    pub column: u32,
}

impl EffectOrigin {
    /// Capture the current call site; requires `#[track_caller]`.
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

/// Provenance of one journaled effect; `Span` reserves the OTel ingest shape.
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

/// Side-channel origin log keyed by entry hash; never serialized.
#[derive(Default)]
pub(crate) struct OriginLog {
    // ledger-lint:allow:HashMap (keyed by entry hash; append order comes
    // from the side Vec, never from map iteration)
    map: std::collections::HashMap<EntryHash, OriginSource>,
    order: Vec<EntryHash>,
}

impl OriginLog {
    pub fn record(&mut self, id: EntryHash, source: OriginSource) {
        if matches!(source, OriginSource::Unknown) {
            return;
        }
        if self.map.insert(id, source).is_none() {
            self.order.push(id);
        }
    }

    pub fn get(&self, id: &EntryHash) -> Option<&OriginSource> {
        self.map.get(id)
    }

    /// Snapshot in append order.
    pub fn snapshot(&self) -> Vec<(EntryHash, OriginSource)> {
        self.order
            .iter()
            .map(|id| (*id, self.map[id].clone()))
            .collect()
    }
}
