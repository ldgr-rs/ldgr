#![cfg(feature = "std")]
//! On-disk snapshot persistence tests.
//!
//! Snapshots fire every `interval` entries per actor. They are recorded in
//! memory and appended to `snapshots.ldgr`. A reopen must restore the recorded
//! snapshots and validate them against the replayed journal.

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;

use ledger_format::{EntryKind, Payload};
use ledger_journal::{JournalError, PersistentJournal, Snapshot};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ldgr-snapshots-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

fn build(journal: &mut PersistentJournal, count: u64) {
    for i in 0..count {
        journal
            .append(EntryKind::Outcome, 1, [], Payload::Number(i))
            .unwrap();
    }
}

fn recorded(journal: &PersistentJournal) -> Vec<Snapshot> {
    journal.snapshots().all().cloned().collect()
}

#[test]
fn snapshot_round_trip_persists_and_reopens() {
    let dir = temp_dir("round-trip");
    let expected = {
        let mut journal = PersistentJournal::create_with_interval(&dir, 10).unwrap();
        build(&mut journal, 100);
        let snapshots = recorded(&journal);
        assert!(
            snapshots.len() >= 9,
            "snapshots must fire every 10 entries for one actor"
        );
        for snapshot in &snapshots {
            snapshot.validate().unwrap();
        }
        snapshots
    };
    let reopened = PersistentJournal::open(&dir).unwrap();
    assert_eq!(recorded(&reopened), expected);
    for snapshot in recorded(&reopened) {
        snapshot.validate().unwrap();
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn truncated_snapshot_file_is_detected_on_open() {
    let dir = temp_dir("truncated");
    {
        let mut journal = PersistentJournal::create_with_interval(&dir, 5).unwrap();
        build(&mut journal, 50);
    }
    let path = dir.join("snapshots.ldgr");
    let len = fs::metadata(&path).unwrap().len();
    let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.set_len(len - 4).unwrap();
    let result = PersistentJournal::open(&dir);
    assert!(
        matches!(
            result,
            Err(JournalError::SnapshotHashMismatch) | Err(JournalError::SnapshotStoreError(_))
        ),
        "a truncated snapshot tail must be detected on open"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn corrupted_snapshot_bytes_are_detected_on_open() {
    let dir = temp_dir("corrupted");
    {
        let mut journal = PersistentJournal::create_with_interval(&dir, 5).unwrap();
        build(&mut journal, 50);
    }
    let path = dir.join("snapshots.ldgr");
    let len = fs::metadata(&path).unwrap().len();
    let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::Start(len / 2)).unwrap();
    file.write_all(&[0xff, 0xee, 0xdd]).unwrap();
    let result = PersistentJournal::open(&dir);
    assert!(
        matches!(
            result,
            Err(JournalError::SnapshotHashMismatch) | Err(JournalError::SnapshotStoreError(_))
        ),
        "corrupted snapshot bytes must be detected on open"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn snapshots_survive_seal_and_reopen() {
    let dir = temp_dir("seal-reopen");
    let expected = {
        let mut journal = PersistentJournal::create_with_interval(&dir, 5).unwrap();
        build(&mut journal, 20);
        journal.force_seal().unwrap();
        build(&mut journal, 20);
        recorded(&journal)
    };
    let reopened = PersistentJournal::open(&dir).unwrap();
    assert_eq!(recorded(&reopened), expected);
    assert!(
        reopened.snapshots().all().all(|snapshot| {
            snapshot.validate().is_ok() && reopened.get(&snapshot.entry_id).is_some()
        }),
        "every loaded snapshot must validate against the restored journal"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn append_after_reopen_extends_the_snapshot_stream() {
    let dir = temp_dir("append-after-open");
    let recorded_before = {
        let mut journal = PersistentJournal::create_with_interval(&dir, 5).unwrap();
        build(&mut journal, 20);
        let recorded = recorded(&journal);
        drop(journal);
        recorded
    };
    let reopened = PersistentJournal::open_with_interval(&dir, 5).unwrap();
    assert_eq!(recorded(&reopened), recorded_before);
    drop(reopened);
    let mut reopened = PersistentJournal::open_with_interval(&dir, 5).unwrap();
    build(&mut reopened, 10);
    drop(reopened);
    let reopened_again = PersistentJournal::open(&dir).unwrap();
    assert_eq!(
        reopened_again.snapshots().all().count(),
        5,
        "three snapshots before the reopen plus two after must all survive"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn snapshot_referencing_missing_entry_fails_validation_on_open() {
    let dir = temp_dir("missing-entry");
    {
        let mut journal = PersistentJournal::create_with_interval(&dir, 5).unwrap();
        build(&mut journal, 20);
        journal.force_seal().unwrap();
    }
    // Drop the only sealed segment so the referenced snapshot entries vanish.
    let seg = dir.join("segment-000000.seg");
    fs::remove_file(&seg).unwrap();
    let result = PersistentJournal::open(&dir);
    assert!(matches!(
        result,
        Err(JournalError::MissingParent(_)) | Err(JournalError::SnapshotStoreError(_))
    ));
    let _ = fs::remove_dir_all(&dir);
}
