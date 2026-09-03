// ledger-lint:allow:SystemTime::now() - host daemon / non-sim passthrough, like TokioBackend
//! Deterministic clock facade: virtual time under `sim`, ambient clock otherwise.

use core::time::Duration;

use thiserror::Error;

/// Typed clock failure.
///
/// Clocks come from a live [`crate::Handle`] inside a run. There is no
/// ambient free clock: SUT code without a run context fails closed here
/// instead of reading wall time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ClockError {
    /// No deterministic run context backs this handle (sim-link without a
    /// live boundary, or local use under sim IPC where the server owns time).
    #[error("no run context: clock unavailable outside a run; use Handle::clock inside run")]
    NoContext,
    /// Local clocks do not cross the IPC boundary; issue an engine effect.
    #[error("local clock unavailable under sim IPC; use server-side effects")]
    IpcLocal,
}

/// Deterministic clock handle.
#[derive(Debug, Clone, Copy)]
pub struct SimClock {
    #[cfg(feature = "sim-link")]
    ticks: u64,
    #[cfg(not(feature = "sim-link"))]
    _private: (),
}

impl SimClock {
    /// Snapshot the current time.
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

    /// Raw tick value (microseconds).
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

    #[cfg(not(any(feature = "sim", feature = "sim-link")))]
    pub(crate) fn ambient() -> Self {
        Self { _private: () }
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
        #[cfg(not(any(feature = "sim", feature = "sim-link")))]
        {
            let c = SimClock::ambient();
            let _ = c.now();
            let _ = c.ticks();
        }
        #[cfg(all(feature = "sim", not(feature = "sim-link")))]
        {
            // Local clocks are unavailable under sim IPC; the type still
            // exposes the typed errors.
            let _ = ClockError::IpcLocal;
        }
    }

    #[test]
    fn clock_error_is_typed() {
        let error = ClockError::NoContext;
        assert_eq!(
            error.to_string(),
            "no run context: clock unavailable outside a run; use Handle::clock inside run"
        );
        assert_eq!(
            ClockError::IpcLocal.to_string(),
            "local clock unavailable under sim IPC; use server-side effects"
        );
    }
}
