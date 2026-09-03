//! Retention policy and the segment manifest.
// ledger-lint:allow:fs:: (storage infrastructure uses the ambient filesystem by design)

use std::collections::BTreeMap;
use std::format;
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::string::ToString;
use std::sync::Arc;
use std::vec::Vec;

use crate::archive::{ARCHIVE_FILE, ArchiveStore};
use crate::dag::JournalError;
use crate::retention::{KEEP_TAIL, RetentionClass};

use super::{
    ArchivedSegment, MANIFEST_FILE, MANIFEST_RECORD_META_LEN, SealedSegment, SegmentStore,
    segment_file_name, segment_io,
};

impl SegmentStore {
    /// Enforce the current retention class over every sealed segment.
    pub fn retain(&mut self) -> Result<(), JournalError> {
        let existing = ArchiveStore::load(&self.dir)?;
        let mut archive_map: BTreeMap<u64, Vec<u8>> = existing.into_iter().collect();
        let tail_start = self.newest_tail_start();

        let mut pending_append: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut needs_rebuild = false;
        for segment in &self.sealed {
            let want_loose = self.should_keep_loose(segment, tail_start);
            let in_archive = archive_map.contains_key(&segment.id);
            if want_loose && in_archive {
                let bytes = match archive_map.remove(&segment.id) {
                    Some(bytes) => bytes,
                    None => {
                        return Err(JournalError::SegmentCorrupt(format!(
                            "archived segment {} is missing",
                            segment.id
                        )));
                    }
                };
                write_loose_file(&self.dir, segment.id, &bytes)?;
                needs_rebuild = true;
            } else if !want_loose && !in_archive {
                let path = self.dir.join(segment.file_name());
                let bytes = fs::read(&path).map_err(segment_io)?;
                pending_append.push((segment.id, bytes));
            }
        }

        if needs_rebuild {
            for (ordinal, bytes) in &pending_append {
                archive_map.insert(*ordinal, bytes.clone());
            }
            let mut records: Vec<(u64, Vec<u8>)> = archive_map
                .iter()
                .map(|(ordinal, bytes)| (*ordinal, bytes.clone()))
                .collect();
            records.sort_by_key(|(ordinal, _)| *ordinal);
            if records.is_empty() {
                match fs::remove_file(self.dir.join(ARCHIVE_FILE)) {
                    Ok(()) => {}
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                    Err(err) => return Err(segment_io(err)),
                }
            } else {
                ArchiveStore::write_all(&self.dir, &records)?;
            }
        } else if !pending_append.is_empty() {
            let mut archive = ArchiveStore::new(&self.dir)?;
            for (ordinal, bytes) in &pending_append {
                archive.append(*ordinal, bytes)?;
            }
        }

        let mut new_archived: Vec<ArchivedSegment> = archive_map
            .into_iter()
            .map(|(id, bytes)| ArchivedSegment {
                id,
                bytes: Arc::new(bytes),
            })
            .collect();
        let mut archived_ids: hashbrown::HashSet<u64> = new_archived.iter().map(|a| a.id).collect();
        for (ordinal, bytes) in pending_append {
            if archived_ids.insert(ordinal) {
                new_archived.push(ArchivedSegment {
                    id: ordinal,
                    bytes: Arc::new(bytes),
                });
            }
        }
        new_archived.sort_by_key(|archived| archived.id);
        self.archived = new_archived;

        let loose_remove: hashbrown::HashSet<u64> = self.archived.iter().map(|a| a.id).collect();
        for segment in &self.sealed {
            if loose_remove.contains(&segment.id) {
                let path = self.dir.join(segment.file_name());
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                    Err(err) => return Err(segment_io(err)),
                }
            }
        }
        self.write_manifest()?;
        Ok(())
    }

    fn should_keep_loose(&self, segment: &SealedSegment, tail_start: u64) -> bool {
        match self.retention {
            RetentionClass::Hot => true,
            RetentionClass::Warm => segment.contains_fault_relevant || segment.id >= tail_start,
            RetentionClass::Cold => false,
        }
    }

    fn newest_tail_start(&self) -> u64 {
        let mut ids: Vec<u64> = self.sealed.iter().map(|segment| segment.id).collect();
        ids.sort_unstable();
        if ids.len() <= KEEP_TAIL {
            return 0;
        }
        ids[ids.len() - KEEP_TAIL]
    }

    /// Persist the manifest describing all sealed segments.
    pub fn write_manifest(&self) -> Result<(), JournalError> {
        let path = self.dir.join(MANIFEST_FILE);
        let tmp_path = self.dir.join(format!("{MANIFEST_FILE}.tmp"));
        {
            let mut file = BufWriter::new(File::create(&tmp_path).map_err(segment_io)?);
            let mut prefix = Vec::new();
            ledger_format::frame::encode_prefix(
                &mut prefix,
                ledger_format::frame::MAGIC_STORE_MANIFEST,
                0,
            );
            file.write_all(&prefix).map_err(segment_io)?;
            file.write_all(&2u32.to_be_bytes()).map_err(segment_io)?;
            file.write_all(&[self.retention.to_u8()])
                .map_err(segment_io)?;
            file.write_all(&(self.sealed.len() as u64).to_be_bytes())
                .map_err(segment_io)?;
            let archived_ids: hashbrown::HashSet<u64> =
                self.archived.iter().map(|a| a.id).collect();
            for segment in &self.sealed {
                file.write_all(&segment.id.to_be_bytes())
                    .map_err(segment_io)?;
                file.write_all(&segment.entry_count.to_be_bytes())
                    .map_err(segment_io)?;
                file.write_all(&segment.uncompressed_len.to_be_bytes())
                    .map_err(segment_io)?;
                file.write_all(&segment.compressed_len.to_be_bytes())
                    .map_err(segment_io)?;
                file.write_all(&segment.sample_interval.to_be_bytes())
                    .map_err(segment_io)?;
                file.write_all(&(segment.samples.len() as u64).to_be_bytes())
                    .map_err(segment_io)?;
                file.write_all(&segment.root_hash.0).map_err(segment_io)?;
                let archived = u8::from(archived_ids.contains(&segment.id));
                let flags = archived | (u8::from(segment.contains_fault_relevant) << 1);
                file.write_all(&[flags]).map_err(segment_io)?;
            }
            file.flush().map_err(segment_io)?;
            file.get_ref().sync_all().map_err(segment_io)?;
        }
        fs::rename(&tmp_path, &path).map_err(segment_io)?;
        Ok(())
    }

    pub(crate) fn read_manifest(
        &self,
        path: &Path,
    ) -> Result<(RetentionClass, Vec<ManifestEntry>), JournalError> {
        let mut file = File::open(path).map_err(segment_io)?;
        let mut prefix_bytes = [0u8; ledger_format::frame::FRAME_PREFIX_LEN];
        file.read_exact(&mut prefix_bytes).map_err(segment_io)?;
        ledger_format::frame::parse_prefix(
            &prefix_bytes,
            ledger_format::frame::MAGIC_STORE_MANIFEST,
        )
        .map_err(|err| {
            JournalError::SegmentCorrupt(format!("store manifest prefix invalid: {err:?}"))
        })?;
        let mut version = [0u8; 4];
        file.read_exact(&mut version).map_err(segment_io)?;
        let version = u32::from_be_bytes(version);
        if version != 2 {
            return Err(JournalError::SegmentCorrupt(
                "unsupported manifest version".to_string(),
            ));
        }
        let retention = {
            let mut byte = [0u8; 1];
            file.read_exact(&mut byte).map_err(segment_io)?;
            RetentionClass::from_u8(byte[0]).ok_or_else(|| {
                JournalError::SegmentCorrupt("invalid retention class in manifest".to_string())
            })?
        };
        let mut count = [0u8; 8];
        file.read_exact(&mut count).map_err(segment_io)?;
        let count = u64::from_be_bytes(count);
        let mut entries = Vec::new();
        for _ in 0..count {
            let mut id = [0u8; 8];
            file.read_exact(&mut id).map_err(segment_io)?;
            let id = u64::from_be_bytes(id);
            file.seek(SeekFrom::Current(MANIFEST_RECORD_META_LEN as i64))
                .map_err(segment_io)?;
            let flags = {
                let mut flags = [0u8; 1];
                file.read_exact(&mut flags).map_err(segment_io)?;
                flags[0]
            };
            entries.push(ManifestEntry {
                id,
                fault_relevant: flags & 0x02 != 0,
            });
        }
        Ok((retention, entries))
    }
}
pub(crate) struct ManifestEntry {
    pub(crate) id: u64,
    pub(crate) fault_relevant: bool,
}

/// Write a sealed segment to its loose file atomically.
pub(crate) fn write_loose_file(dir: &Path, id: u64, bytes: &[u8]) -> Result<(), JournalError> {
    let file_name = segment_file_name(id);
    let tmp_path = dir.join(format!("{file_name}.tmp"));
    {
        let mut file = BufWriter::new(File::create(&tmp_path).map_err(segment_io)?);
        file.write_all(bytes).map_err(segment_io)?;
        file.flush().map_err(segment_io)?;
        file.get_ref().sync_all().map_err(segment_io)?;
    }
    fs::rename(&tmp_path, dir.join(&file_name)).map_err(segment_io)?;
    Ok(())
}
