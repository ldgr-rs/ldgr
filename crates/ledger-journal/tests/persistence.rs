#![cfg(feature = "std")]
//! End-to-end persistence tests for the `PersistentJournal` facade.
//!
//! These tests exercise the real file path: a journal appends through the
//! facade into a segment store, then a fresh `PersistentJournal` is opened from
//! the same directory and must reproduce an identical DAG.

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;

use ledger_format::{EntryKind, EntryPayload, GenId, Hash, InputKey};
use ledger_journal::{Journal, PersistentJournal, VectorClock};

const WAL_FILE: &str = "wal.bin";

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ldgr-persistence-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

/// Append `count` varied entries across several actors.
///
/// Each entry observes its own actor's previous entry and one other actor's
/// previous entry, so the DAG is deeply cross-linked. Kinds, payloads, and
/// timer/RNG-style variety are rotated per entry.
fn build_stream(journal: &mut PersistentJournal, count: usize) -> Vec<Hash> {
    const ACTORS: usize = 4;
    let mut last: Vec<Option<Hash>> = vec![None; ACTORS];
    let mut ids = Vec::with_capacity(count);
    for i in 0..count {
        let actor = (i % ACTORS) as u32 + 1;
        let kind = match i % 6 {
            0 => EntryKind::Outcome,
            1 => EntryKind::InputStep,
            2 => EntryKind::RngDraw,
            3 => EntryKind::TimerSet,
            4 => EntryKind::Send,
            _ => EntryKind::Assert,
        };
        let value = i as u64;
        // v2 payloads are kind-specific; the payload derives from the kind.
        let payload = match kind {
            EntryKind::Outcome => EntryPayload::Outcome(ledger_format::OutcomePayload {
                schema: [0x00; 32],
                value: if i % 3 == 0 {
                    ledger_format::CanonicalValue::Unsigned(value)
                } else {
                    ledger_format::CanonicalValue::Text(format!("payload-{i:04}"))
                },
            }),
            EntryKind::InputStep => EntryPayload::InputStep(ledger_format::InputStepPayload {
                generator: (i as GenId) % 3,
                replay: i as InputKey,
                value: ledger_format::CanonicalValue::Unsigned(value),
            }),
            EntryKind::RngDraw => EntryPayload::RngDraw(ledger_format::RngDrawPayload {
                stream: (i % 7) as u32,
                draw_index: value,
                content: vec![(i % 251) as u8; 8 + (i % 16)],
            }),
            EntryKind::TimerSet => EntryPayload::TimerSet {
                timer_id: value,
                deadline_ticks: value.wrapping_mul(3),
            },
            EntryKind::Send => EntryPayload::Send(ledger_format::SendFrame {
                message_id: ledger_format::MessageId::new(actor, value),
                from: actor,
                to: (actor % 4) + 1,
                original_content: value.to_le_bytes().to_vec(),
            }),
            _ => EntryPayload::Assert(ledger_format::AssertPayload {
                predicate: [0x00; 32],
                passed: i % 2 == 0,
                detail: ledger_format::CanonicalValue::Unsigned(value),
            }),
        };
        let mut observed = Vec::new();
        if let Some(hash) = last[actor as usize - 1] {
            observed.push(hash);
        }
        if let Some(hash) = last[actor as usize % ACTORS] {
            observed.push(hash);
        }
        let id = journal.append(kind, actor, observed, payload).unwrap();
        last[actor as usize - 1] = Some(id);
        ids.push(id);
    }
    ids
}

/// Snapshot of the append-order entry stream used for equality checks.
#[derive(Debug)]
struct EntryStream {
    ids: Vec<Hash>,
    data_bytes: Vec<Vec<u8>>,
    clocks: Vec<VectorClock>,
}

impl EntryStream {
    fn capture(journal: &PersistentJournal) -> Self {
        let mut ids = Vec::new();
        let mut data_bytes = Vec::new();
        let mut clocks = Vec::new();
        for entry in journal.entries() {
            ids.push(entry.id);
            data_bytes.push(entry.data.try_canonical_bytes().unwrap());
            clocks.push(entry.vector_clock.clone());
        }
        Self {
            ids,
            data_bytes,
            clocks,
        }
    }

    fn assert_identical(&self, reopened: &PersistentJournal) {
        assert_eq!(reopened.len(), self.ids.len());
        assert_eq!(
            reopened.entries().count(),
            self.ids.len(),
            "entry iteration count must match"
        );
        let mut stream = reopened.entries();
        for (i, ((expected_id, expected_bytes), expected_clock)) in self
            .ids
            .iter()
            .zip(&self.data_bytes)
            .zip(&self.clocks)
            .enumerate()
        {
            let entry = stream.next().unwrap();
            assert_eq!(entry.id, *expected_id, "entry {i} id must match");
            assert_eq!(
                entry.data.try_canonical_bytes().unwrap(),
                *expected_bytes,
                "entry {i} canonical bytes must match"
            );
            assert_eq!(
                entry.vector_clock, *expected_clock,
                "entry {i} vector clock must match"
            );
        }
        for (i, (id, expected_clock)) in self.ids.iter().zip(&self.clocks).enumerate() {
            let entry = reopened.get(id).expect("every id must resolve");
            assert_eq!(
                entry.vector_clock, *expected_clock,
                "looked-up entry {i} vector clock must match"
            );
        }
    }
}

#[test]
fn round_trip_reconstructs_identical_journal_across_seal_and_tail() {
    let dir = temp_dir("round-trip");
    let expected = {
        let mut journal = PersistentJournal::create(&dir).unwrap();
        build_stream(&mut journal, 5_000);
        journal.force_seal().unwrap();
        build_stream(&mut journal, 100);
        journal.write_manifest().unwrap();
        assert!(
            !journal.segments().is_empty(),
            "seal must produce a segment"
        );
        assert!(
            journal.buffered_count() > 0,
            "buffered tail must survive alongside the sealed segment"
        );
        let stream = EntryStream::capture(&journal);
        let root = journal.root_hash();
        let len = journal.len();
        let sealed = journal.segments().len();
        drop(journal);
        let reopened = PersistentJournal::open(&dir).unwrap();
        assert_eq!(reopened.len(), len);
        assert_eq!(reopened.root_hash(), root);
        assert_eq!(reopened.segments().len(), sealed);
        stream
    };
    let reopened = PersistentJournal::open(&dir).unwrap();
    expected.assert_identical(&reopened);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn wal_truncation_recovers_last_complete_frame_through_facade() {
    let dir = temp_dir("wal-truncation");
    let pre_corruption_root = {
        let mut journal = PersistentJournal::create(&dir).unwrap();
        build_stream(&mut journal, 300);
        assert_eq!(journal.segments().len(), 0, "no seal before corruption");
        let root = journal.root_hash();
        let stream = EntryStream::capture(&journal);
        drop(journal);
        // Simulate a crash mid-write: a partial frame appended to the WAL.
        {
            let wal_path = dir.join(WAL_FILE);
            let mut file = fs::OpenOptions::new().append(true).open(&wal_path).unwrap();
            file.write_all(&0u64.to_le_bytes()).unwrap();
            file.write_all(&[0xde, 0xad, 0xbe, 0xef]).unwrap();
        }
        let reopened = PersistentJournal::open(&dir).unwrap();
        assert_eq!(
            reopened.root_hash(),
            root,
            "recovery must restore the in-memory root"
        );
        stream.assert_identical(&reopened);
        root
    };
    let final_reopen = PersistentJournal::open(&dir).unwrap();
    assert_eq!(final_reopen.root_hash(), pre_corruption_root);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn corrupt_sealed_tail_is_dropped_and_buffered_tail_reconstructs() {
    let dir = temp_dir("corrupt-sealed-tail");
    let tail_root = {
        let mut journal = PersistentJournal::create(&dir).unwrap();
        build_stream(&mut journal, 100);
        journal.force_seal().unwrap();
        journal.write_manifest().unwrap();
        // Append a buffered tail from fresh actors so the tail does not
        // reference the sealed segment that will be dropped.
        for i in 0..50 {
            journal
                .append(
                    EntryKind::Outcome,
                    7,
                    [],
                    EntryPayload::Outcome(ledger_format::OutcomePayload {
                        schema: [0x00; 32],
                        value: ledger_format::CanonicalValue::Unsigned(100 + i),
                    }),
                )
                .unwrap();
        }
        let mut reference = Journal::new();
        for i in 0..50 {
            reference
                .append(
                    EntryKind::Outcome,
                    7,
                    [],
                    EntryPayload::Outcome(ledger_format::OutcomePayload {
                        schema: [0x00; 32],
                        value: ledger_format::CanonicalValue::Unsigned(100 + i),
                    }),
                )
                .unwrap();
        }
        let tail_root = reference.root_hash();
        // Corrupt the trailer of the sealed segment.
        let seg_path = dir.join("segment-000000.seg");
        let len = fs::metadata(&seg_path).unwrap().len();
        let mut file = fs::OpenOptions::new().write(true).open(&seg_path).unwrap();
        file.seek(SeekFrom::Start(len - 4)).unwrap();
        file.write_all(&[0xff, 0xff, 0xff, 0xff]).unwrap();
        tail_root
    };
    let reopened = PersistentJournal::open(&dir).unwrap();
    assert_eq!(
        reopened.segments().len(),
        0,
        "the corrupt sealed tail must be dropped on open"
    );
    assert_eq!(reopened.len(), 50, "only the buffered tail survives");
    assert_eq!(reopened.root_hash(), tail_root);
    let _ = fs::remove_dir_all(&dir);
}
