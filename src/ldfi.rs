//! Bounded lineage-driven fault hypothesis generation.

use crate::format::EntryKind;
use crate::journal::{Hash, Journal};
use crate::oracle::Verdict;

/// A candidate fault cut. This prototype does not claim a MaxSAT certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultCut {
    /// Faultable journal event.
    pub event: Hash,
    /// Cost used for ranking.
    pub cost: u64,
    /// Why the event is in the witness closure.
    pub reason: String,
}

/// Generate a bounded, cost-ranked fault cut from oracle witnesses.
pub fn suggest_cut(journal: &Journal, verdict: &Verdict) -> Vec<FaultCut> {
    let mut candidates = Vec::new();
    for witness in &verdict.witnesses {
        let Ok(closure) = journal.causal_closure(*witness) else {
            continue;
        };
        for id in closure {
            let Some(entry) = journal.get(&id) else {
                continue;
            };
            let cost = match entry.data.kind {
                EntryKind::Send => 2,
                EntryKind::TimerFire => 3,
                EntryKind::FsRead | EntryKind::FsWrite => 4,
                _ => continue,
            };
            if !candidates
                .iter()
                .any(|candidate: &FaultCut| candidate.event == id)
            {
                candidates.push(FaultCut {
                    event: id,
                    cost,
                    reason: format!("faultable {:?} in witness closure", entry.data.kind),
                });
            }
        }
    }
    candidates.sort_by_key(|candidate| candidate.cost);
    candidates
}
