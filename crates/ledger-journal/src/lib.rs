#![deny(unsafe_code)]
#![allow(missing_docs)]
#![no_std]

//! Content-addressed causal DAG journal, vector clocks, and segment store.
//!
//! Immutable entries with cheap forking; monitor re-derives clocks.
//! Segments provide zstd-at-seal compression and WAL recovery.

extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

#[cfg(feature = "std")]
pub mod archive;
pub mod clock;
pub mod dag;
pub mod identity;
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
pub use identity::{CRASH_SEMANTICS_VERSION, ExecutionIdentity, ResourceLimits};
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
    use ledger_format::{ActorId, EntryHash, EntryKind, EntryPayload};

    fn outcome(value: u64) -> EntryPayload {
        EntryPayload::Outcome(ledger_format::OutcomePayload {
            schema: EntryHash([0x00; 32]),
            value: ledger_format::CanonicalValue::Unsigned(value),
        })
    }

    #[test]
    fn append_adds_local_parent_and_increments_clock() {
        let mut journal = Journal::new();
        let first = journal
            .append(
                EntryKind::InputStep,
                ActorId(1),
                [],
                EntryPayload::InputStep(ledger_format::InputStepPayload {
                    generator: 0,
                    replay: 0,
                    value: ledger_format::CanonicalValue::Unsigned(1),
                }),
            )
            .unwrap();
        let second = journal
            .append(EntryKind::Outcome, ActorId(1), [], outcome(2))
            .unwrap();
        let entry = journal.get(&second).unwrap();
        assert_eq!(entry.data.parents.as_slice(), [first].as_slice());
        assert_eq!(entry.vector_clock.get(ActorId(1)), 2);
    }

    #[test]
    fn correctness_monitor_verifies_valid_journal() {
        let mut journal = Journal::new();
        journal
            .append(
                EntryKind::InputStep,
                ActorId(1),
                [],
                EntryPayload::InputStep(ledger_format::InputStepPayload {
                    generator: 0,
                    replay: 0,
                    value: ledger_format::CanonicalValue::Unsigned(1),
                }),
            )
            .unwrap();
        journal
            .append(EntryKind::Outcome, ActorId(1), [], outcome(2))
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
                .append(EntryKind::Outcome, ActorId(1), [], outcome(i))
                .unwrap();
        }
        let fork = original.fork();
        JournalCorrectnessMonitor::verify_replay_fidelity(&original, &fork).unwrap();
    }
}
