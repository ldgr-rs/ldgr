// ledger-lint:allow - host daemon / non-sim passthrough, like TokioBackend
//! Deterministic RNG facade.
//!
//! Why: ambient entropy (`rand::thread_rng`, `getrandom`) is forbidden inside
//! simulation. Under `sim` this module serves ChaCha20 streams derived from the
//! seed tree. Outside `sim` it serves OS entropy via `getrandom` wrapped as a
//! ChaCha RNG so the call site stays identical.

use rand_core::Rng as _;

pub use ledger_format::StreamId;

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

    #[cfg(feature = "sim-link")]
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

    #[cfg(not(feature = "sim-link"))]
    pub(crate) fn from_seed(stream: StreamId) -> Self {
        let mut seed = [0u8; 32];
        if getrandom::fill(&mut seed).is_err() {
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            seed[0..16].copy_from_slice(&t.to_le_bytes());
            seed[16..32].copy_from_slice(&t.to_le_bytes());
        }
        Self {
            inner: {
                use rand_core::SeedableRng as _;
                rand_chacha::ChaCha20Rng::from_seed(seed)
            },
            stream,
        }
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
            let mut a = DetRng::from_chacha(0, rand_chacha::ChaCha20Rng::from_seed(seed));
            let mut b = DetRng::from_chacha(0, rand_chacha::ChaCha20Rng::from_seed(seed));
            assert_eq!(a.next_u64(), b.next_u64());
            assert_eq!(a.next_u64(), b.next_u64());
        }
        #[cfg(not(feature = "sim-link"))]
        {
            let mut r = DetRng::from_seed(0);
            let _ = r.next_u64();
            let mut s = DetRng::from_seed(1);
            let _ = s.next_u64();
        }
    }

    #[test]
    fn different_stream_ids_yield_independent_sequences() {
        #[cfg(feature = "sim-link")]
        {
            use ledger_sim::SeedTree;
            let seed = [9u8; 32];
            let tree = SeedTree::new(seed);
            let mut a = DetRng::from_chacha(0, tree.rng("app/0"));
            let mut b = DetRng::from_chacha(1, tree.rng("app/1"));
            let va = a.next_u64();
            let vb = b.next_u64();
            assert_ne!(va, vb);
            let vb2 = b.next_u64();
            let mut b_fresh = DetRng::from_chacha(1, tree.rng("app/1"));
            let _ = b_fresh.next_u64();
            assert_eq!(vb2, b_fresh.next_u64());
        }
    }
}
