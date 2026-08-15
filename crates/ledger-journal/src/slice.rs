//! Causal slicing, backward closures, forward impact cones, and subgraphs.

use alloc::sync::Arc;
use alloc::vec::Vec;
use hashbrown::{HashMap, HashSet};

use crate::dag::{Journal, JournalError, JournalState};
use ledger_format::Hash;

impl Journal {
    /// Return the causal backward closure of a single entry.
    pub fn causal_closure(&self, start: Hash) -> Result<Vec<Hash>, JournalError> {
        self.causal_slice(&[start])
    }

    /// Return the joint backward causal closure of multiple target entries.
    pub fn causal_slice(&self, targets: &[Hash]) -> Result<Vec<Hash>, JournalError> {
        for target in targets {
            if self.get(target).is_none() {
                return Err(JournalError::MissingParent(*target));
            }
        }
        let mut seen = HashSet::new();
        let mut stack: Vec<Hash> = targets.to_vec();
        while let Some(id) = stack.pop() {
            if seen.insert(id)
                && let Some(entry) = self.get(&id)
            {
                for parent in &entry.data.parents {
                    if !seen.contains(parent) {
                        stack.push(*parent);
                    }
                }
            }
        }
        Ok(self
            .order()
            .iter()
            .chain(self.state.overlay_order.iter())
            .copied()
            .filter(|id| seen.contains(id))
            .collect())
    }

    /// Return the forward impact cone of a set of source entries.
    pub fn forward_cone(&self, sources: &[Hash]) -> Vec<Hash> {
        let mut affected = HashSet::new();
        for src in sources {
            affected.insert(*src);
        }
        for entry in self.entries() {
            if entry
                .data
                .parents
                .iter()
                .any(|parent| affected.contains(parent))
            {
                affected.insert(entry.id);
            }
        }
        self.order()
            .iter()
            .chain(self.state.overlay_order.iter())
            .copied()
            .filter(|id| affected.contains(id))
            .collect()
    }

    /// Return the causal slice of the targets, closed forward over its boundary.
    ///
    /// The backward closure keeps every parent of a member. The forward cone
    /// adds the entries that consume the sliced boundary events, and the
    /// result is re-closed backward so every parent is present and the slice
    /// is replayable.
    pub fn causal_slice_forward(&self, targets: &[Hash]) -> Result<Vec<Hash>, JournalError> {
        let backward = self.causal_slice(targets)?;
        let forward = self.forward_cone(&backward);
        self.causal_slice(&forward)
    }

    /// Construct a subgraph Journal containing only the requested hashes (in topological order).
    pub fn subgraph(&self, hashes: &[Hash]) -> Result<Self, JournalError> {
        let set: HashSet<Hash> = hashes.iter().copied().collect();
        let mut sub_entries = HashMap::new();
        let mut sub_heads = HashMap::new();
        let mut sub_order = Vec::new();

        for id in self.order().iter().chain(self.state.overlay_order.iter()) {
            if set.contains(id)
                && let Some(arc_entry) = self.get_arc(id)
            {
                sub_heads.insert(arc_entry.data.actor, *id);
                sub_entries.insert(*id, arc_entry);
                sub_order.push(*id);
            }
        }

        Ok(Self {
            state: Arc::new(JournalState {
                base: Arc::new(sub_entries),
                overlay: HashMap::new(),
                heads: sub_heads,
                order: Arc::new(sub_order),
                overlay_order: Vec::new(),
            }),
            scratch: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_format::{EntryKind, Payload};

    #[test]
    fn causal_slice_forward_includes_consumers_of_boundary_inputs() {
        let mut journal = Journal::new();
        let boundary = journal
            .append(EntryKind::Send, 1, [], Payload::Number(1))
            .expect("append must succeed");
        let witness = journal
            .append(EntryKind::Assert, 1, [], Payload::Number(0))
            .expect("append must succeed");
        let consumer = journal
            .append(EntryKind::Recv, 2, [boundary], Payload::Number(1))
            .expect("append must succeed");

        let backward = journal
            .causal_slice(&[witness])
            .expect("backward slice must succeed");
        assert!(
            !backward.contains(&consumer),
            "the backward-only slice must drop the consumer"
        );

        let forward = journal
            .causal_slice_forward(&[witness])
            .expect("forward-closed slice must succeed");
        assert!(
            forward.contains(&consumer),
            "the forward closure must keep the consumer of the boundary input"
        );
        assert!(forward.contains(&boundary));
        assert!(forward.contains(&witness));

        let subgraph = journal
            .subgraph(&forward)
            .expect("the forward-closed slice must be a valid subgraph");
        assert_eq!(subgraph.len(), forward.len());
        assert!(
            subgraph.get(&witness).is_some(),
            "replaying the sliced journal must keep the violation witness"
        );
        assert!(
            subgraph.get(&consumer).is_some(),
            "replaying the sliced journal must keep the boundary consumer"
        );
    }
}
