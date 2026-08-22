// ledger-lint:allow - host daemon / non-sim passthrough, like TokioBackend
//! Deterministic clock facade.
//!
//! Why a wrapper: direct `Instant::now` or `SystemTime::now` would break
//! determinism under `sim`. This module routes to virtual time when compiled
//! with `sim` and to the ambient clock otherwise, so the same SUT source stays
//! deterministic in sim and live in production.

use core::time::Duration;

/// Deterministic clock handle.
///
/// In `sim-link` mode the handle captures virtual time at creation. In
/// non-sim and `sim` IPC mode it is a zero-cost marker that reads system time
/// on demand. IPC runs are deterministic server-side via `rt-server`.
#[derive(Debug, Clone, Copy)]
pub struct SimClock {
    #[cfg(feature = "sim-link")]
    ticks: u64,
    #[cfg(not(feature = "sim-link"))]
    _private: (),
}

impl SimClock {
    /// Snapshot the current time.
    ///
    /// In `sim-link` mode this value comes from `VirtualTime` via the executor.
    /// Outside `sim-link` it comes from `SystemTime`. IPC mode is ambient
    /// locally and deterministic server-side.
    pub fn now(&self) -> Duration {
        #[cfg(feature = "sim-link")]
        {
            Duration::from_micros(self.ticks)
        }
        #[cfg(not(feature = "sim-link"))]
        {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
        }
    }

    /// Raw tick value (microseconds) for sim-mode expiry math.
    pub fn ticks(&self) -> u64 {
        #[cfg(feature = "sim-link")]
        {
            self.ticks
        }
        #[cfg(not(feature = "sim-link"))]
        {
            self.now().as_micros() as u64
        }
    }

    #[cfg(feature = "sim-link")]
    pub(crate) fn from_ticks(ticks: u64) -> Self {
        Self { ticks }
    }

    #[cfg(not(feature = "sim-link"))]
    pub(crate) fn ambient() -> Self {
        Self { _private: () }
    }
}

/// Free function that returns current time as a duration since the virtual epoch.
///
/// In `sim-link` mode this returns zero. Callers inside a run should prefer
/// a `Handle`-bound clock which reads authoritative virtual time; this free
/// function exists for code that has no handle yet and still needs a
/// deterministic value.
pub fn now() -> Duration {
    #[cfg(feature = "sim-link")]
    {
        // No executor context available: fall back to epoch. Callers inside a
        // `Handle` should use `Handle::clock` instead. Keeping this deterministic
        // (zero) is safer than touching the ambient clock.
        Duration::ZERO
    }
    #[cfg(not(feature = "sim-link"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sim_clock_ticks_roundtrip() {
        #[cfg(feature = "sim-link")]
        {
            let c = SimClock::from_ticks(42);
            assert_eq!(c.ticks(), 42);
            assert_eq!(c.now(), Duration::from_micros(42));
        }
        #[cfg(not(feature = "sim-link"))]
        {
            let c = SimClock::ambient();
            let _ = c.now();
            let _ = c.ticks();
        }
    }

    #[test]
    fn free_now_is_deterministic_in_sim() {
        let a = now();
        let b = now();
        #[cfg(feature = "sim-link")]
        assert_eq!(a, b);
        #[cfg(not(feature = "sim-link"))]
        {
            // Outside sim-link, time moves forward monotonically.
            assert!(a <= b);
        }
    }
}
