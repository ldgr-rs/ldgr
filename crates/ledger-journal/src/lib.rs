#![deny(unsafe_code)]
#![allow(missing_docs)]
#![no_std]

//! Content-addressed causal DAG journal, vector clocks, and segment store.
//!
//! The journal is immutable and content-addressed, with cheap forking and
//! vector-clock happens-before summaries. A correctness monitor re-derives
//! the clocks, so the journal is self-verifying without re-execution. An
//! append-only on-disk segment store provides zstd-at-seal compression and
//! WAL-shaped crash recovery.

extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

#[cfg(feature = "std")]
pub mod archive;
pub mod clock;
pub mod dag;
pub mod monitor;
#[cfg(feature = "std")]
pub mod persistent;
pub mod retention;
#[cfg(feature = "std")]
pub mod segment;
pub mod slice;
pub mod snapshot;
#[cfg(feature = "std")]
pub mod snapshot_store;

pub use clock::VectorClock;
pub use dag::{BatchEntry, Entry, EntryFrame, Journal, JournalError};
pub use monitor::{JournalCorrectnessMonitor, MonitorIssue, VerificationReport};
#[cfg(feature = "std")]
pub use persistent::PersistentJournal;
pub use retention::RetentionClass;
#[cfg(feature = "std")]
pub use segment::{SealedSegment, SegmentStore, SegmentWriter};
pub use snapshot::{Snapshot, SnapshotManager};
#[cfg(feature = "std")]
pub use snapshot_store::SnapshotStore;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use ledger_format::{EntryKind, Payload};

    #[test]
    fn append_adds_local_parent_and_increments_clock() {
        let mut journal = Journal::new();
        let first = journal
            .append(
                EntryKind::InputStep {
                    generator: 0,
                    replay: 0,
                },
                1,
                [],
                Payload::Number(1),
            )
            .unwrap();
        let second = journal
            .append(EntryKind::Outcome, 1, [], Payload::Number(2))
            .unwrap();
        let entry = journal.get(&second).unwrap();
        assert_eq!(entry.data.parents, vec![first]);
        assert_eq!(entry.vector_clock.get(1), 2);
    }

    #[test]
    fn correctness_monitor_verifies_valid_journal() {
        let mut journal = Journal::new();
        journal
            .append(
                EntryKind::InputStep {
                    generator: 0,
                    replay: 0,
                },
                1,
                [],
                Payload::Number(1),
            )
            .unwrap();
        journal
            .append(EntryKind::Outcome, 1, [], Payload::Number(2))
            .unwrap();

        let report = JournalCorrectnessMonitor::verify(&journal).unwrap();
        assert_eq!(report.entries_audited, 2);
        assert_eq!(report.actors_count, 1);
        assert_eq!(report.root_hash, journal.root_hash());
    }

    #[test]
    fn fork_replay_passes_fidelity_check() {
        let mut original = Journal::new();
        for i in 0..10 {
            original
                .append(EntryKind::Outcome, 1, [], Payload::Number(i))
                .unwrap();
        }
        let fork = original.fork();
        JournalCorrectnessMonitor::verify_replay_fidelity(&original, &fork).unwrap();
    }
}
