//! Journal retention tiers: hot, warm, and cold.
//!
//! Every tier is non-destructive. Warm keeps fault-relevant and newest two
//! loose; cold archives all. Archived segments stay recoverable.

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

    #[cfg(feature = "std")]
    pub(crate) fn to_u8(self) -> u8 {
        match self {
            Self::Hot => 0,
            Self::Warm => 1,
            Self::Cold => 2,
        }
    }

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
