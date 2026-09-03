//! Cooperative task spawning facade (single-threaded deterministic schedule).

use ledger_format::EntryHash;

/// Opaque task identifier returned by `spawn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaskId(pub u64);

/// Content-addressed task identifier: BLAKE3(`name`, `input_hash`).
/// Same input yields same id; sentinel `0` is never returned.
pub fn task_id_for(name: &str, input_hash: EntryHash) -> TaskId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(name.as_bytes());
    hasher.update(&input_hash.0);
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
        let h1 = ledger_format::EntryHash([1u8; 32]);
        let h2 = ledger_format::EntryHash([2u8; 32]);
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
        // Under `sim` (IPC) the refusal happens before any engine spawn
        // (`Main::into_workload` rejects closures), so no engine binary or
        // env probe is needed here.
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
