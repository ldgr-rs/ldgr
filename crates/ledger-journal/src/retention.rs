//! Journal retention tiers.
//!
//! The engine keeps three retention tiers: hot, warm, and cold. Every tier is
//! non-destructive. The durable base is one content-addressed archive file,
//! `archive.ldgr`, plus the manifest. Archived segments stay recoverable and
//! byte-identical to loose segment files.
//!
//! - Hot: all sealed segments stay loose on disk.
//! - Warm: fault-relevant segments and the newest two segments stay loose;
//!   the rest move into the archive.
//! - Cold: all sealed segments move into the archive. Only the manifest and
//!   the archive remain.
//!
//! A snapshot cannot reconstruct a journal DAG, so a tier that deletes
//! history would change the root hash. The warm tier is therefore non-lossy:
//! every archived segment can be re-extracted, so a cold store opens
//! byte-identically to a hot store with the same content.

/// Retention tier of a journal store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RetentionClass {
    /// Full journal kept loose.
    Hot,
    /// Fault-relevant and newest segments loose; the rest archived.
    Warm,
    /// All segments archived; manifest and archive only.
    Cold,
}

/// Number of newest sealed segments kept loose in the warm tier.
pub const KEEP_TAIL: usize = 2;

impl RetentionClass {
    pub fn max_of(a: Self, b: Self) -> Self {
        a.max(b)
    }

    /// Encode the class as one byte for the manifest.
    #[cfg(feature = "std")]
    pub(crate) fn to_u8(self) -> u8 {
        match self {
            Self::Hot => 0,
            Self::Warm => 1,
            Self::Cold => 2,
        }
    }

    /// Decode the class from one manifest byte.
    #[cfg(feature = "std")]
    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Hot),
            1 => Some(Self::Warm),
            2 => Some(Self::Cold),
            _ => None,
        }
    }
}
