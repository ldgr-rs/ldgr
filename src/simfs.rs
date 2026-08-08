//! Minimal in-memory file model with explicit write and read provenance.

use std::collections::BTreeMap;

use crate::format::{EntryKind, Payload};
use crate::journal::{Hash, Journal, JournalError};

/// A small page-cache file system for prototype workloads.
#[derive(Debug, Default)]
pub struct SimFs {
    values: BTreeMap<String, (u64, Hash)>,
    synced: BTreeMap<String, (u64, Hash)>,
}

impl SimFs {
    /// Write a value and record its causal write event.
    pub fn write(
        &mut self,
        journal: &mut Journal,
        actor: u32,
        path: &str,
        value: u64,
    ) -> Result<Hash, JournalError> {
        let id = journal.append(
            EntryKind::FsWrite,
            actor,
            [],
            Payload::Pair {
                left: path.len() as u64,
                right: value,
            },
        )?;
        self.values.insert(path.to_owned(), (value, id));
        Ok(id)
    }

    /// Persist all dirty values.
    pub fn fsync(&mut self, journal: &mut Journal, actor: u32) -> Result<Hash, JournalError> {
        let id = journal.append(EntryKind::FsFsync, actor, [], Payload::Empty)?;
        self.synced = self.values.clone();
        Ok(id)
    }

    /// Read a value and include the observed write as a parent.
    pub fn read(
        &self,
        journal: &mut Journal,
        actor: u32,
        path: &str,
    ) -> Result<Option<u64>, JournalError> {
        let Some((value, write)) = self.values.get(path).copied() else {
            journal.append(EntryKind::FsRead, actor, [], Payload::Text(path.to_owned()))?;
            return Ok(None);
        };
        journal.append(
            EntryKind::FsRead,
            actor,
            [write],
            Payload::Pair {
                left: path.len() as u64,
                right: value,
            },
        )?;
        Ok(Some(value))
    }

    /// Simulate a crash by dropping dirty, unsynced values.
    pub fn crash(&mut self) {
        self.values = self.synced.clone();
    }
}
