// ledger-lint:allow - test-only probe; verifies thread-local registry isolation
//! Cooperative task spawning facade.
//!
//! Why a wrapper: `std::thread::spawn` and ambient `tokio::spawn` break the
//! single-threaded deterministic scheduling invariant. Under `sim-link` this
//! module backs `Handle::spawn`, which forwards to `Boundary::spawn_task`.
//! Outside `sim-link` `Handle::spawn` forwards to `tokio` (including `sim`
//! IPC mode, where the remote run is deterministic server-side).

use ledger_format::Hash;

/// Opaque task identifier returned by `spawn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaskId(pub u64);

/// Content-addressed task identifier.
///
/// Hashes `name` and `input_hash` with BLAKE3 to produce a stable `TaskId` so
/// tasks can be deduped across runs (CAM idea). The same `(name, input)`
/// always yields the same id on every platform; different inputs yield
/// uncorrelated ids. The sentinel `0` is never returned.
pub fn task_id_for(name: &str, input_hash: Hash) -> TaskId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(name.as_bytes());
    hasher.update(&input_hash);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest.as_bytes()[..8]);
    let mut id = u64::from_le_bytes(bytes);
    if id == 0 {
        id = 1;
    }
    TaskId(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_id_is_copy() {
        let a = TaskId(1);
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn task_id_for_is_deterministic_and_nonzero() {
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let id_a = task_id_for("worker", h1);
        let id_b = task_id_for("worker", h1);
        let id_c = task_id_for("worker", h2);
        let id_d = task_id_for("other", h1);
        assert_eq!(id_a, id_b);
        assert_ne!(id_a, id_c);
        assert_ne!(id_a, id_d);
        assert_ne!(id_a.0, 0);
    }

    #[cfg(not(feature = "sim-link"))]
    #[test]
    fn handle_spawn_returns_id() {
        // Under `sim` (IPC) `run` needs a live engine binary; skip when absent.
        #[cfg(all(feature = "sim", not(feature = "sim-link")))]
        {
            let has_engine = std::env::var_os("LEDGER_ENGINE_BIN").is_some()
                || std::path::Path::new(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../target/debug/ledger"
                ))
                .exists();
            if !has_engine {
                eprintln!("skipping: no engine binary for IPC transport");
                return;
            }
        }
        let res = crate::runtime::run(crate::runtime::RunConfig::default(), |handle| async move {
            let id = handle.spawn(|_| Box::pin(async {}));
            assert!(id.0 >= 1);
        });
        // Under sim/IPC caller programs cannot cross the boundary; the run
        // must refuse them instead of executing anything else. Direct
        // executors really poll this closure, so the local step count
        // applies only there.
        #[cfg(all(feature = "sim", not(feature = "sim-link")))]
        assert!(matches!(
            res,
            Err(crate::runtime::RuntimeError::ProgramNotTransportable)
        ));
        #[cfg(not(all(feature = "sim", not(feature = "sim-link"))))]
        assert_eq!(res.expect("run must succeed").steps, 0);
    }
}
