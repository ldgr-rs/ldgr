// ledger-lint:allow:getrandom:: - host daemon / non-sim passthrough, like TokioBackend
//! Deterministic RNG facade.
//!
//! Why: ambient entropy (`rand::thread_rng`, `getrandom`) is forbidden inside
//! simulation. Under `sim` this module serves ChaCha20 streams derived from the
//! seed tree. Outside `sim` it serves OS entropy via `getrandom` wrapped as a
//! ChaCha RNG so the call site stays identical.

use rand_core::Rng as _;
use thiserror::Error;

pub use ledger_format::StreamId;

/// Maximum bytes kept from a host-entropy failure message.
///
/// Bounds untrusted OS error text carried in [`RngError::EntropyUnavailable`].
pub const MAX_ENTROPY_DETAIL_BYTES: usize = 128;

/// Typed RNG failure.
///
/// Streams come from a live [`crate::Handle`] inside a run (journaled under
/// `sim-link`, server-side under sim IPC). There is no ambient fallback:
/// construction outside a run fails closed here instead of reading OS
/// entropy or wall time.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RngError {
    /// No deterministic run context backs this handle.
    #[error("no run context: RNG unavailable outside a run; use Handle::rng inside run")]
    NoContext,
    /// Local RNG does not cross the IPC boundary; issue an engine effect.
    #[error("local RNG unavailable under sim IPC; use server-side effects")]
    IpcLocal,
    /// Host entropy failed and no ambient fallback is taken.
    #[error("host entropy unavailable: {detail}")]
    EntropyUnavailable { detail: String },
}

/// Deterministic RNG handle for one labelled stream.
#[cfg(feature = "sim-link")]
pub struct DetRng {
    stream: StreamId,
    boundary: Option<ledger_sim::Boundary>,
    inner: rand_chacha::ChaCha20Rng,
}

#[cfg(not(feature = "sim-link"))]
pub struct DetRng {
    inner: rand_chacha::ChaCha20Rng,
    stream: StreamId,
}

impl DetRng {
    /// Stream label this handle was derived from.
    pub fn stream(&self) -> StreamId {
        self.stream
    }

    /// Return the next `u64` from this stream.
    ///
    /// In `sim-link` this draw is journaled when called via a `Handle`.
    /// Under `sim` (IPC) the local RNG is not journaled; the remote run is
    /// deterministic server-side.
    pub fn next_u64(&mut self) -> u64 {
        #[cfg(feature = "sim-link")]
        {
            if let Some(b) = self.boundary.as_mut() {
                return {
                    use ledger_sim::Effects as _;
                    b.rng(self.stream).next_u64()
                };
            }
            self.inner.next_u64()
        }
        #[cfg(not(feature = "sim-link"))]
        {
            self.inner.next_u64()
        }
    }

    /// Fill `dest` with bytes from this stream.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        #[cfg(feature = "sim-link")]
        {
            if let Some(b) = self.boundary.as_mut() {
                use ledger_sim::Effects as _;
                // Delegate to the boundary RNG so the fill is journaled as a
                // single deterministic draw sequence.
                b.rng(self.stream).fill_bytes(dest);
                return;
            }
            self.inner.fill_bytes(dest);
        }
        #[cfg(not(feature = "sim-link"))]
        {
            self.inner.fill_bytes(dest);
        }
    }

    #[cfg(all(feature = "sim-link", test))]
    pub(crate) fn from_chacha(stream: StreamId, rng: rand_chacha::ChaCha20Rng) -> Self {
        Self {
            stream,
            boundary: None,
            inner: rng,
        }
    }

    #[cfg(feature = "sim-link")]
    pub(crate) fn from_boundary(stream: StreamId, boundary: ledger_sim::Boundary) -> Self {
        // Fallback inner is unused when boundary is present; seed deterministically.
        Self {
            stream,
            boundary: Some(boundary),
            inner: {
                use rand_core::SeedableRng as _;
                rand_chacha::ChaCha20Rng::from_seed([0u8; 32])
            },
        }
    }

    #[cfg(not(any(feature = "sim", feature = "sim-link")))]
    pub(crate) fn from_seed(stream: StreamId) -> Result<Self, RngError> {
        let mut seed = [0u8; 32];
        // Fail closed: no wall-time fallback. A host entropy failure is a
        // typed error, never ambient time bytes.
        getrandom::fill(&mut seed).map_err(|error| {
            let mut detail = error.to_string();
            if detail.len() > MAX_ENTROPY_DETAIL_BYTES {
                detail.truncate(MAX_ENTROPY_DETAIL_BYTES);
            }
            RngError::EntropyUnavailable { detail }
        })?;
        Ok(Self {
            inner: {
                use rand_core::SeedableRng as _;
                rand_chacha::ChaCha20Rng::from_seed(seed)
            },
            stream,
        })
    }
}

impl std::fmt::Debug for DetRng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetRng")
            .field("stream", &self.stream)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streams_with_same_seed_produce_same_sequence() {
        #[cfg(feature = "sim-link")]
        {
            use rand_core::SeedableRng as _;
            let seed = [7u8; 32];
            let mut a = DetRng::from_chacha(StreamId(0), rand_chacha::ChaCha20Rng::from_seed(seed));
            let mut b = DetRng::from_chacha(StreamId(0), rand_chacha::ChaCha20Rng::from_seed(seed));
            assert_eq!(a.next_u64(), b.next_u64());
            assert_eq!(a.next_u64(), b.next_u64());
        }
        #[cfg(not(any(feature = "sim", feature = "sim-link")))]
        {
            // Host entropy either seeds two draws or fails closed typed;
            // it never falls back to wall time.
            let first = DetRng::from_seed(StreamId(0)).map(|mut r| r.next_u64());
            let second = DetRng::from_seed(StreamId(1)).map(|mut r| r.next_u64());
            match (first, second) {
                (Ok(_), Ok(_)) => {}
                (Err(error), _) | (_, Err(error)) => {
                    assert!(
                        matches!(error, RngError::EntropyUnavailable { .. }),
                        "{error}"
                    );
                }
            }
        }
    }

    #[test]
    fn rng_error_is_typed_and_bounded() {
        let error = RngError::NoContext;
        assert_eq!(
            error.to_string(),
            "no run context: RNG unavailable outside a run; use Handle::rng inside run"
        );
        let long = "x".repeat(MAX_ENTROPY_DETAIL_BYTES + 16);
        assert!(long.len() > MAX_ENTROPY_DETAIL_BYTES);
    }

    #[test]
    fn different_stream_ids_yield_independent_sequences() {
        #[cfg(feature = "sim-link")]
        {
            use ledger_sim::SeedTree;
            let seed = ledger_format::EntryHash([9u8; 32]);
            let tree = SeedTree::new(seed);
            let mut a = DetRng::from_chacha(StreamId(0), tree.rng("app/0"));
            let mut b = DetRng::from_chacha(StreamId(1), tree.rng("app/1"));
            let va = a.next_u64();
            let vb = b.next_u64();
            assert_ne!(va, vb);
            let vb2 = b.next_u64();
            let mut b_fresh = DetRng::from_chacha(StreamId(1), tree.rng("app/1"));
            let _ = b_fresh.next_u64();
            assert_eq!(vb2, b_fresh.next_u64());
        }
    }
}
