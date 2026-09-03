//! Journal append handling and the error slot.
//!
//! All journal writes funnel through [`ExecutorShared::journal_append`] and
//! [`ExecutorShared::journal_append_batch`] so the coverage ledger and the
//! single-shot journal-error slot stay exact. The first append failure from
//! a call site that cannot return `Err` lands in
//! [`ExecutorShared::journal_error`] and surfaces through
//! [`crate::runtime::RunResult::journal_error`] at run end.
use super::ExecutorShared;
use ledger_format::{ActorId, EntryHash, EntryKind, EntryPayload};
use ledger_journal::BatchEntry;

impl ExecutorShared {
    /// Take one ready message for `task`, honoring the configured reorder
    /// semantics: the deterministic newest-first pick by default, or a
    /// seeded draw inside the bounded candidate window when `reorder_draw`
    /// is set. The draw consumes from the `net` seed stream only when a
    /// window is actually configured, keeping window-zero journals
    /// byte-identical to the plain path.
    pub(crate) fn recv_at_effective(&self, task: usize, now: u64) -> Option<crate::net::Message> {
        let mut net = self.net.borrow_mut();
        if !self.reorder_draw {
            return net.recv_at(task, now);
        }
        let mut offset = self.net_offset.borrow_mut();
        let draw = |bound: u64| -> u64 {
            let value = self.seed_tree.draw_u64("net", *offset);
            *offset += 1;
            value % bound
        };
        net.recv_at_drawn(task, now, draw)
    }

    /// Append one entry and count it against the actor's coverage.
    pub(crate) fn journal_append(
        &self,
        actor: ActorId,
        kind: EntryKind,
        parents: impl IntoIterator<Item = EntryHash>,
        payload: EntryPayload,
    ) -> Result<EntryHash, ledger_journal::JournalError> {
        let id = self
            .journal
            .borrow_mut()
            .append(kind, actor, parents, payload)?;
        let mut coverage = self.coverage.borrow_mut();
        *coverage.entry(actor).or_insert(0) += 1;
        Ok(id)
    }

    /// Append a group of entries in order and count each against its actor's
    /// coverage.
    ///
    /// Byte-identical to looping [`Self::journal_append`]; see
    /// [`Journal::append_batch`] for the equality contract. Coverage counts
    /// only land on full success, matching the all-or-nothing use of a run
    /// that hits an append error (the run is terminal then).
    pub(crate) fn journal_append_batch(
        &self,
        batch: Vec<BatchEntry>,
    ) -> Result<Vec<EntryHash>, ledger_journal::JournalError> {
        let actors: Vec<ActorId> = batch.iter().map(|entry| entry.actor).collect();
        let ids = self.journal.borrow_mut().append_batch(batch)?;
        let mut coverage = self.coverage.borrow_mut();
        for actor in actors {
            *coverage.entry(actor).or_insert(0) += 1;
        }
        Ok(ids)
    }

    /// Hash the vector-clock shape of a journaled entry into a stable u64.
    ///
    /// Returns `None` when the entry is absent from the journal.
    fn entry_vc_signature(&self, id: EntryHash) -> Option<u64> {
        let journal = self.journal.borrow();
        let entry = journal.get(&id)?;
        let digest = blake3::hash(&entry.vector_clock.encode());
        let bytes: [u8; 8] = digest.as_bytes()[..8].try_into().ok()?;
        Some(u64::from_le_bytes(bytes))
    }

    /// Forward an entry emission to the scheduler novelty model.
    ///
    /// The vector-clock signature is derived from the journaled entry, so the
    /// bandit can reward novel VC branch patterns. Only the bandit policy
    /// consumes novelty, so the signature hash is skipped under every other
    /// policy. Journal contents are unaffected by the skip.
    pub(crate) fn notify_entry(
        &self,
        actor: ActorId,
        kind: EntryKind,
        task_id: usize,
        entry_id: Option<EntryHash>,
    ) {
        let bandit_active = self.scheduler.borrow().novelty_active();
        if !bandit_active {
            return;
        }
        let signature = entry_id.and_then(|id| self.entry_vc_signature(id));
        self.scheduler
            .borrow_mut()
            .on_entry_emitted(actor, kind, task_id, signature);
    }

    /// Record a failed append from a call site that cannot return `Err`.
    ///
    /// The first failure wins; later failures never overwrite it. The debug
    /// assert catches double-recording early, because a second append failure
    /// means the journal is already unusable for replay.
    pub(crate) fn record_journal_error(&self, error: ledger_journal::JournalError) {
        let mut slot = self.journal_error.borrow_mut();
        debug_assert!(
            slot.is_none(),
            "journal append failed after an earlier failure this run"
        );
        if slot.is_none() {
            *slot = Some(error);
        }
    }
}
