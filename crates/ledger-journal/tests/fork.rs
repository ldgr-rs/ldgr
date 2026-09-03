#![cfg(feature = "std")]
//! Content-addressed fork tests.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use ledger_format::{ActorId, EntryHash, EntryKind, EntryPayload};
use ledger_journal::PersistentJournal;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ldgr-fork-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

fn build(journal: &mut PersistentJournal, count: u64) -> Vec<EntryHash> {
    let mut ids = Vec::with_capacity(count as usize);
    for i in 0..count {
        let id = journal
            .append(
                EntryKind::Outcome,
                ActorId(1),
                [],
                EntryPayload::Outcome(ledger_format::OutcomePayload {
                    schema: EntryHash([0x00; 32]),
                    value: ledger_format::CanonicalValue::Unsigned(i),
                }),
            )
            .unwrap();
        ids.push(id);
    }
    ids
}

fn entry_ids(journal: &PersistentJournal) -> Vec<EntryHash> {
    journal.entries().map(|entry| entry.id).collect()
}

fn segment_inodes(dir: &Path) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if name.starts_with("segment-") && name.ends_with(".seg") {
            out.insert(name, fs::metadata(&path).unwrap().ino());
        }
    }
    out
}

#[test]
fn fork_shares_sealed_segments_via_hardlink() {
    let parent_dir = temp_dir("share-parent");
    let fork_dir = temp_dir("share-fork");
    let parent = {
        let mut parent = PersistentJournal::create(&parent_dir).unwrap();
        build(&mut parent, 100);
        parent.force_seal().unwrap();
        parent.write_manifest().unwrap();
        parent
    };
    let fork = parent.fork(&fork_dir).unwrap();
    assert_eq!(fork.len(), parent.len());
    assert_eq!(fork.segments().len(), parent.segments().len());
    assert!(
        !fork.segments().is_empty(),
        "the parent must have at least one sealed segment to share"
    );

    let parent_inodes = segment_inodes(&parent_dir);
    let fork_inodes = segment_inodes(&fork_dir);
    assert_eq!(
        fork_inodes.len(),
        parent_inodes.len(),
        "the fork must reference one file per shared segment"
    );
    for (name, fork_ino) in &fork_inodes {
        let parent_ino = parent_inodes
            .get(name)
            .expect("segment must exist in parent");
        assert_eq!(
            fork_ino, parent_ino,
            "segment {name} must be a hard link, not a copy"
        );
    }
    assert_eq!(entry_ids(&fork), entry_ids(&parent));
    let _ = fs::remove_dir_all(&parent_dir);
    let _ = fs::remove_dir_all(&fork_dir);
}

#[test]
fn fork_diverges_independently() {
    let parent_dir = temp_dir("diverge-parent");
    let fork_dir = temp_dir("diverge-fork");
    let (parent_root, fork_root) = {
        let mut parent = PersistentJournal::create(&parent_dir).unwrap();
        build(&mut parent, 100);
        parent.force_seal().unwrap();
        parent.write_manifest().unwrap();
        let mut fork = parent.fork(&fork_dir).unwrap();
        build(&mut parent, 20);
        build(&mut fork, 30);
        (parent.root_hash(), fork.root_hash())
    };
    assert_ne!(parent_root, fork_root);

    let reopened_parent = PersistentJournal::open(&parent_dir).unwrap();
    let reopened_fork = PersistentJournal::open(&fork_dir).unwrap();
    assert_eq!(reopened_parent.root_hash(), parent_root);
    assert_eq!(reopened_fork.root_hash(), fork_root);
    assert_ne!(reopened_parent.root_hash(), reopened_fork.root_hash());
    reopened_parent.verify().unwrap();
    reopened_fork.verify().unwrap();
    let _ = fs::remove_dir_all(&parent_dir);
    let _ = fs::remove_dir_all(&fork_dir);
}

#[test]
fn fork_preserves_prefix() {
    let parent_dir = temp_dir("prefix-parent");
    let fork_dir = temp_dir("prefix-fork");
    let parent_ids = {
        let mut parent = PersistentJournal::create(&parent_dir).unwrap();
        let ids = build(&mut parent, 100);
        parent.force_seal().unwrap();
        parent.write_manifest().unwrap();
        ids
    };
    let tail_ids = {
        let parent = PersistentJournal::open(&parent_dir).unwrap();
        let mut fork = parent.fork(&fork_dir).unwrap();
        build(&mut fork, 25)
    };

    let reopened_fork = PersistentJournal::open(&fork_dir).unwrap();
    let expected: Vec<EntryHash> = parent_ids.iter().chain(&tail_ids).copied().collect();
    assert_eq!(entry_ids(&reopened_fork), expected);

    let reopened_parent = PersistentJournal::open(&parent_dir).unwrap();
    assert_eq!(entry_ids(&reopened_parent), parent_ids);
    let _ = fs::remove_dir_all(&parent_dir);
    let _ = fs::remove_dir_all(&fork_dir);
}

#[test]
fn fork_seal_reopen_roundtrip() {
    let parent_dir = temp_dir("seal-parent");
    let fork_dir = temp_dir("seal-fork");
    let parent_root = {
        let mut parent = PersistentJournal::create(&parent_dir).unwrap();
        build(&mut parent, 100);
        parent.force_seal().unwrap();
        parent.write_manifest().unwrap();
        parent.root_hash()
    };
    let fork_root = {
        let parent = PersistentJournal::open(&parent_dir).unwrap();
        let mut fork = parent.fork(&fork_dir).unwrap();
        build(&mut fork, 20);
        fork.force_seal().unwrap();
        fork.write_manifest().unwrap();
        fork.root_hash()
    };

    let reopened_fork = PersistentJournal::open(&fork_dir).unwrap();
    assert_eq!(reopened_fork.root_hash(), fork_root);
    assert_eq!(reopened_fork.len(), 120);
    assert_eq!(
        reopened_fork.segments().len(),
        2,
        "fork must keep the shared segment and add its own"
    );
    reopened_fork.verify().unwrap();

    let reopened_parent = PersistentJournal::open(&parent_dir).unwrap();
    assert_eq!(reopened_parent.root_hash(), parent_root);
    assert_eq!(reopened_parent.len(), 100);
    reopened_parent.verify().unwrap();
    let _ = fs::remove_dir_all(&parent_dir);
    let _ = fs::remove_dir_all(&fork_dir);
}

#[test]
fn fork_covers_unsealed_parent_tail() {
    let parent_dir = temp_dir("unsealed-parent");
    let fork_dir = temp_dir("unsealed-fork");
    let all_parent_ids = {
        let mut parent = PersistentJournal::create(&parent_dir).unwrap();
        let ids = build(&mut parent, 80);
        parent.write_manifest().unwrap();
        ids
    };
    let tail_ids = {
        let parent = PersistentJournal::open(&parent_dir).unwrap();
        assert_eq!(parent.segments().len(), 0, "parent must be unsealed");
        let mut fork = parent.fork(&fork_dir).unwrap();
        build(&mut fork, 10)
    };
    let reopened_fork = PersistentJournal::open(&fork_dir).unwrap();
    let expected: Vec<EntryHash> = all_parent_ids.iter().chain(&tail_ids).copied().collect();
    assert_eq!(
        entry_ids(&reopened_fork),
        expected,
        "fork must cover the parent's unsealed prefix"
    );
    reopened_fork.verify().unwrap();
    let _ = fs::remove_dir_all(&parent_dir);
    let _ = fs::remove_dir_all(&fork_dir);
}

/// Copy fallback must produce a correct fork across devices.
#[test]
fn fork_copy_fallback_produces_correct_fork() {
    let parent_dir = std::env::current_dir().unwrap().join(format!(
        "target/ldgr-fork-copy-parent-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&parent_dir);
    fs::create_dir_all(&parent_dir).unwrap();
    let fork_dir = temp_dir("copy-fork");
    let parent = {
        let mut parent = PersistentJournal::create(&parent_dir).unwrap();
        build(&mut parent, 100);
        parent.force_seal().unwrap();
        parent.write_manifest().unwrap();
        parent
    };
    let fork = parent.fork(&fork_dir).unwrap();
    assert_eq!(entry_ids(&fork), entry_ids(&parent));
    let reopened = PersistentJournal::open(&fork_dir).unwrap();
    assert_eq!(reopened.root_hash(), parent.root_hash());
    reopened.verify().unwrap();

    #[cfg(unix)]
    {
        let parent_dev = fs::metadata(&parent_dir).unwrap().dev();
        let fork_dev = fs::metadata(&fork_dir).unwrap().dev();
        if parent_dev != fork_dev {
            let parent_ino = fs::metadata(parent_dir.join("segment-000000.seg"))
                .map(|meta| meta.ino())
                .ok();
            let fork_ino = fs::metadata(fork_dir.join("segment-000000.seg"))
                .map(|meta| meta.ino())
                .ok();
            if let (Some(parent_ino), Some(fork_ino)) = (parent_ino, fork_ino) {
                assert_ne!(
                    parent_ino, fork_ino,
                    "across devices the fork must fall back to copying the segment"
                );
            }
        }
    }
    let _ = fs::remove_dir_all(&parent_dir);
    let _ = fs::remove_dir_all(&fork_dir);
}

#[test]
fn fork_materializes_archived_segments() {
    let parent_dir = temp_dir("archived-parent");
    let fork_dir = temp_dir("archived-fork");
    let parent = {
        let mut parent = PersistentJournal::create(&parent_dir).unwrap();
        build(&mut parent, 100);
        parent.force_seal().unwrap();
        parent
            .set_retention(ledger_journal::RetentionClass::Cold)
            .unwrap();
        assert!(
            segment_inodes(&parent_dir).is_empty(),
            "Cold retention must remove every loose segment file from the parent"
        );
        parent
    };
    let fork = parent.fork(&fork_dir).unwrap();
    assert_eq!(entry_ids(&fork), entry_ids(&parent));
    assert!(
        !fork.segments().is_empty(),
        "the fork must materialize the archived segments as loose files"
    );
    let reopened = PersistentJournal::open(&fork_dir).unwrap();
    assert_eq!(reopened.root_hash(), parent.root_hash());
    reopened.verify().unwrap();
    let _ = fs::remove_dir_all(&parent_dir);
    let _ = fs::remove_dir_all(&fork_dir);
}
