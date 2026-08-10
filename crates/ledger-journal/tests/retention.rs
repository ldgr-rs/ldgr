//! Retention tier tests for the `PersistentJournal` and `SegmentStore`.
//!
//! Retention is archive-based and non-destructive. A store retained to cold
//! reopens byte-identically to a hot store of the same content. Raising the
//! class re-extracts archived segments back to loose files.

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use ledger_format::{EntryKind, FaultSpec, Hash, Payload};
use ledger_journal::{Journal, JournalError, PersistentJournal, RetentionClass, SegmentStore};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ldgr-retention-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

/// Return the loose sealed segment files present in a directory, sorted.
fn loose_segment_files(dir: &Path) -> Vec<String> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy().into_owned();
        if name.starts_with("segment-") && name.ends_with(".seg") {
            names.push(name);
        }
    }
    names.sort();
    names
}

/// Append a deterministic mixed stream across three sealed segments.
///
/// Segment 1 carries Outcome and Fault entries; segment 2 carries an Assert.
/// The remaining frames are pure-effect Send entries.
fn append_mixed_stream(journal: &mut PersistentJournal) {
    for seg in 0..3u64 {
        for i in 0..40 {
            let kind = match (seg, i) {
                (1, 0) => EntryKind::Outcome,
                (1, 5) => EntryKind::Fault {
                    fault: FaultSpec::Drop,
                },
                (2, 10) => EntryKind::Assert,
                _ => EntryKind::Send,
            };
            journal
                .append(kind, 1, [], Payload::Number(seg * 40 + i))
                .unwrap();
        }
        journal.force_seal().unwrap();
    }
}

/// Append a stream where only segment 1 is fault-relevant.
///
/// Segment 0 is pure-effect Send. Segment 1 opens with an Outcome. Segment 2
/// is pure-effect Recv and is the newest tail.
fn append_warm_stream(journal: &mut PersistentJournal) {
    for i in 0..40 {
        journal
            .append(EntryKind::Send, 1, [], Payload::Number(i))
            .unwrap();
    }
    journal.force_seal().unwrap();
    journal
        .append(EntryKind::Outcome, 1, [], Payload::Number(1000))
        .unwrap();
    for i in 0..39 {
        journal
            .append(EntryKind::FsWrite, 1, [], Payload::Number(i))
            .unwrap();
    }
    journal.force_seal().unwrap();
    for i in 0..40 {
        journal
            .append(EntryKind::Recv, 1, [], Payload::Number(i))
            .unwrap();
    }
    journal.force_seal().unwrap();
}

#[test]
fn cold_archives_all_and_reopens_identical() {
    let dir = temp_dir("cold-identical");
    let expected_root = {
        let mut journal = PersistentJournal::create(&dir).unwrap();
        append_mixed_stream(&mut journal);
        let root = journal.root_hash();
        let len = journal.len();
        journal.set_retention(RetentionClass::Cold).unwrap();
        assert!(
            loose_segment_files(&dir).is_empty(),
            "cold must leave no loose segments"
        );
        assert!(
            dir.join("archive.ldgr").is_file(),
            "cold must write the archive"
        );
        drop(journal);
        let reopened = PersistentJournal::open(&dir).unwrap();
        assert_eq!(reopened.len(), len);
        assert_eq!(reopened.root_hash(), root);
        root
    };
    let control_dir = temp_dir("cold-control");
    {
        let mut journal = PersistentJournal::create(&control_dir).unwrap();
        append_mixed_stream(&mut journal);
        let reopened = PersistentJournal::open(&control_dir).unwrap();
        assert_eq!(
            reopened.root_hash(),
            expected_root,
            "a cold store must reopen byte-identically to a hot store"
        );
    }
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&control_dir);
}

#[test]
fn warm_keeps_fault_relevant_and_tail() {
    let dir = temp_dir("warm");
    let expected_root = {
        let mut journal = PersistentJournal::create(&dir).unwrap();
        append_warm_stream(&mut journal);
        let root = journal.root_hash();
        journal.set_retention(RetentionClass::Warm).unwrap();
        assert_eq!(
            loose_segment_files(&dir),
            vec![
                "segment-000001.seg".to_string(),
                "segment-000002.seg".to_string(),
            ],
            "fault-relevant and newest-two segments stay loose"
        );
        assert!(
            dir.join("archive.ldgr").is_file(),
            "warm must write the archive"
        );
        drop(journal);
        let reopened = PersistentJournal::open(&dir).unwrap();
        assert_eq!(reopened.root_hash(), root);
        assert_eq!(reopened.len(), 120);
        root
    };
    let control_dir = temp_dir("warm-control");
    {
        let mut journal = PersistentJournal::create(&control_dir).unwrap();
        append_warm_stream(&mut journal);
        assert_eq!(journal.root_hash(), expected_root);
    }
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&control_dir);
}

#[test]
fn cold_archive_verifiable_on_read() {
    let dir = temp_dir("corrupt-archive");
    {
        let mut journal = PersistentJournal::create(&dir).unwrap();
        append_mixed_stream(&mut journal);
        journal.set_retention(RetentionClass::Cold).unwrap();
    }
    let path = dir.join("archive.ldgr");
    let len = fs::metadata(&path).unwrap().len();
    assert!(len > 64, "archive must hold more than the header");
    let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::Start(len / 2)).unwrap();
    file.write_all(&[0xff, 0xee, 0xdd]).unwrap();
    drop(file);
    let result = PersistentJournal::open(&dir);
    assert!(
        matches!(result, Err(JournalError::ArchiveHashMismatch)),
        "a corrupted archive must fail open with an archive hash mismatch"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn raising_retention_reextracts() {
    let dir = temp_dir("reextract");
    let mut journal = Journal::new();
    let mut entries = Vec::new();
    for i in 0..240 {
        let id = journal
            .append(EntryKind::Send, 1, [], Payload::Number(i))
            .unwrap();
        entries.push(journal.get(&id).unwrap().clone());
    }
    let mut store = SegmentStore::new(&dir).unwrap();
    for chunk in entries.chunks(80) {
        for entry in chunk {
            store.append(entry).unwrap();
        }
        store.seal_writer().unwrap();
    }
    store.set_retention(RetentionClass::Cold).unwrap();
    assert!(loose_segment_files(&dir).is_empty());
    for entry in &entries {
        assert!(
            store.get(&entry.id).unwrap().is_some(),
            "cold must still serve every entry from the archive"
        );
    }
    store.set_retention(RetentionClass::Hot).unwrap();
    assert_eq!(
        loose_segment_files(&dir).len(),
        3,
        "raising to hot must restore every loose file"
    );
    for entry in &entries {
        assert!(
            store.get(&entry.id).unwrap().is_some(),
            "hot must serve every entry from loose files"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn retention_class_ordering() {
    assert!(RetentionClass::Hot < RetentionClass::Warm);
    assert!(RetentionClass::Warm < RetentionClass::Cold);
    assert_eq!(
        RetentionClass::max_of(RetentionClass::Hot, RetentionClass::Cold),
        RetentionClass::Cold
    );
    assert_eq!(
        RetentionClass::max_of(RetentionClass::Warm, RetentionClass::Hot),
        RetentionClass::Warm
    );
    assert_eq!(
        RetentionClass::max_of(RetentionClass::Cold, RetentionClass::Warm),
        RetentionClass::Cold
    );
}

#[test]
fn warm_is_nonlossy_determinism() {
    let warm_dir = temp_dir("warm-nonlossy");
    let hot_dir = temp_dir("hot-nonlossy");
    {
        let mut journal = PersistentJournal::create(&warm_dir).unwrap();
        append_warm_stream(&mut journal);
        journal.set_retention(RetentionClass::Warm).unwrap();
    }
    {
        let mut journal = PersistentJournal::create(&hot_dir).unwrap();
        append_warm_stream(&mut journal);
    }
    let warm = PersistentJournal::open(&warm_dir).unwrap();
    let hot = PersistentJournal::open(&hot_dir).unwrap();
    assert_eq!(
        warm.root_hash(),
        hot.root_hash(),
        "warm retention must not change the determinism root"
    );
    assert_eq!(warm.len(), hot.len());
    let warm_ids: Vec<Hash> = warm.entries().map(|entry| entry.id).collect();
    let hot_ids: Vec<Hash> = hot.entries().map(|entry| entry.id).collect();
    assert_eq!(warm_ids, hot_ids, "append order must be identical");
    let _ = fs::remove_dir_all(&warm_dir);
    let _ = fs::remove_dir_all(&hot_dir);
}
