//! SimFs-backed WASI filesystem shadow tests.
#![cfg(feature = "backend-wasm")]

mod common;

use ledger_format::EntryKind;
use ledger_journal::JournalCorrectnessMonitor;
use ledger_sim::{SeedTree, WasmBackend};

#[test]
fn wasm_fs_write_read_roundtrip() {
    let wasm = common::guest_wasm_bytes();
    let seed = [9u8; 32];
    let mut first = WasmBackend::from_wasm(SeedTree::new(seed), &wasm).expect("wasm backend");
    let out1 = first.run_export("run_fs").expect("run_fs");
    let text1 = String::from_utf8_lossy(&out1);
    assert!(
        text1.contains("read=42"),
        "run_fs must log read=42, got {text1:?} out {out1:?}"
    );
    let journal1 = first.journal_snapshot();
    let kinds: Vec<EntryKind> = journal1.entries().map(|e| e.data.kind).collect();
    assert!(
        kinds.iter().any(|k| matches!(k, EntryKind::FsWrite)),
        "journal must contain FsWrite, got {kinds:?}"
    );
    assert!(
        kinds.iter().any(|k| matches!(k, EntryKind::FsRead)),
        "journal must contain FsRead, got {kinds:?}"
    );
    assert!(
        JournalCorrectnessMonitor::audit(&journal1).is_empty(),
        "journal must be causally sound, issues: {:?}",
        JournalCorrectnessMonitor::audit(&journal1)
    );
    // Determinism across two fresh runs.
    let mut second = WasmBackend::from_wasm(SeedTree::new(seed), &wasm).expect("wasm backend");
    let out2 = second.run_export("run_fs").expect("run_fs second");
    assert_eq!(out1, out2, "run_fs output must be deterministic");
    let journal2 = second.journal_snapshot();
    assert_eq!(
        journal1.root_hash(),
        journal2.root_hash(),
        "journal roots must be deterministic"
    );
}

#[test]
fn wasm_fs_crash_drops_unsynced() {
    let wasm = common::guest_wasm_bytes();
    let seed = [11u8; 32];
    let mut first = WasmBackend::from_wasm(SeedTree::new(seed), &wasm).expect("wasm backend");
    let out1 = first.run_export("run_fs_crash").expect("run_fs_crash");
    let text1 = String::from_utf8_lossy(&out1);
    // Absent read is -1 sentinel (or 0). Check deterministic sentinel.
    assert!(
        text1.contains("read_after_crash=-1") || text1.contains("read_after_crash=0"),
        "crash read must be absent sentinel, got {text1:?}"
    );
    let journal1 = first.journal_snapshot();
    let kinds: Vec<EntryKind> = journal1.entries().map(|e| e.data.kind).collect();
    assert!(
        kinds.iter().any(|k| matches!(k, EntryKind::FsWrite)),
        "journal must contain FsWrite, got {kinds:?}"
    );
    assert!(
        kinds.iter().any(|k| matches!(k, EntryKind::FsRead)),
        "journal must contain FsRead, got {kinds:?}"
    );
    assert!(
        kinds.iter().any(|k| matches!(k, EntryKind::Fault)),
        "journal must contain Fault(CrashState) after crash, got {kinds:?}"
    );
    // Determinism: second run same seed yields same sentinel.
    let mut second = WasmBackend::from_wasm(SeedTree::new(seed), &wasm).expect("wasm backend");
    let out2 = second
        .run_export("run_fs_crash")
        .expect("run_fs_crash second");
    assert_eq!(out1, out2, "crash output must be deterministic");
    let journal2 = second.journal_snapshot();
    assert_eq!(
        journal1.root_hash(),
        journal2.root_hash(),
        "crash journal roots must be deterministic"
    );
}
