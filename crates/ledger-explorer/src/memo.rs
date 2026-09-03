#![deny(unsafe_code)]

//! Content-addressed campaign memo for variant dedup. Keys on the canonical
//! variant plus input and replay hashes; per-campaign only, never global.

use ledger_format::EntryHash;
use ledger_sim::{Policy, SimFault, SwarmConfig};
use std::collections::HashMap;

/// Entry stored per memo key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoEntry {
    /// The memo key itself (blake3 of the canonical variant bytes plus
    /// input and replay extensions). Stored for debugging.
    pub run_config_hash: EntryHash,
    /// Journal root of the run that produced this entry.
    pub journal_root: EntryHash,
    /// Whether the root was distinct at insertion time.
    pub distinct: bool,
}

/// Campaign memo. A hit reuses the cached root without re-executing.
#[derive(Debug, Clone, Default)]
pub struct CampaignMemo {
    cache: HashMap<EntryHash, MemoEntry>,
}

impl CampaignMemo {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    pub fn get(&self, key: &EntryHash) -> Option<&MemoEntry> {
        self.cache.get(key)
    }

    pub fn insert(&mut self, key: EntryHash, entry: MemoEntry) -> Option<MemoEntry> {
        self.cache.insert(key, entry)
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    pub fn contains(&self, key: &EntryHash) -> bool {
        self.cache.contains_key(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&EntryHash, &MemoEntry)> {
        self.cache.iter()
    }

    pub fn clear(&mut self) {
        self.cache.clear();
    }
}

/// Hash PBT inputs: `BLAKE3(len || inputs[*])`.
pub fn hash_inputs(inputs: &[u64]) -> EntryHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(inputs.len() as u64).to_le_bytes());
    for value in inputs {
        hasher.update(&value.to_le_bytes());
    }
    EntryHash(*hasher.finalize().as_bytes())
}

/// Canonical variant bytes. Single layout source for memo keys and arm
/// hashes. Keys on (policy, swarm, faults) only; never extend with `RunConfig`.
pub fn canonical_variant_bytes(
    policy: &Policy,
    swarm: &SwarmConfig,
    faults: &[SimFault],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    match policy {
        Policy::Random => bytes.push(0),
        Policy::Pct { priority_changes } => {
            bytes.push(1);
            bytes.extend_from_slice(&priority_changes.to_le_bytes());
        }
        Policy::Bandit {
            exploration_constant,
            pct_mix,
        } => {
            bytes.push(2);
            bytes.extend_from_slice(&exploration_constant.to_bits().to_le_bytes());
            bytes.extend_from_slice(&pct_mix.get().to_bits().to_le_bytes());
        }
        Policy::Replay => bytes.push(3),
        Policy::Dpor => bytes.push(4),
    }
    bytes.extend_from_slice(&swarm.drop_probability.get().to_bits().to_le_bytes());
    bytes.extend_from_slice(&swarm.delay_probability.get().to_bits().to_le_bytes());
    bytes.extend_from_slice(&swarm.max_delay_ticks.to_le_bytes());
    bytes.extend_from_slice(&swarm.crash_probability.get().to_bits().to_le_bytes());
    bytes.extend_from_slice(&swarm.fault_classes_per_run.to_le_bytes());
    bytes.extend_from_slice(&(faults.len() as u64).to_le_bytes());
    for fault in faults {
        match fault {
            SimFault::Drop(id) => {
                bytes.push(0);
                bytes.extend_from_slice(&id.0);
            }
            SimFault::Delay { send, ticks } => {
                bytes.push(1);
                bytes.extend_from_slice(&send.0);
                bytes.extend_from_slice(&ticks.to_le_bytes());
            }
            SimFault::Partition { src, dst } => {
                bytes.push(2);
                bytes.extend_from_slice(&src.0.to_le_bytes());
                bytes.extend_from_slice(&dst.0.to_le_bytes());
            }
            SimFault::Crash(id) => {
                bytes.push(3);
                bytes.extend_from_slice(&id.0);
            }
            SimFault::Corrupt { write, xor_mask } => {
                bytes.push(4);
                bytes.extend_from_slice(&write.0);
                bytes.extend_from_slice(&xor_mask.to_le_bytes());
            }
            SimFault::CrashState { write, state } => {
                bytes.push(5);
                bytes.extend_from_slice(&write.0);
                bytes.extend_from_slice(&state.to_le_bytes());
            }
            SimFault::Duplicate { send } => {
                bytes.push(6);
                bytes.extend_from_slice(&send.0);
            }
        }
    }
    bytes
}

/// Campaign attempt key. Domain separators keep `None` apart from `Some(empty)`.
pub fn memo_key(
    policy: &Policy,
    swarm: &SwarmConfig,
    faults: &[SimFault],
    input_hash: Option<EntryHash>,
    replay: Option<&[usize]>,
    seed: Option<EntryHash>,
) -> EntryHash {
    let variant_bytes = canonical_variant_bytes(policy, swarm, faults);
    let variant_digest = blake3::hash(&variant_bytes);
    let mut hasher = blake3::Hasher::new();
    hasher.update(variant_digest.as_bytes());
    hasher.update(&[0xA0]);
    if let Some(hash) = input_hash {
        hasher.update(&hash.0);
        hasher.update(&[0xA1]);
    } else {
        hasher.update(&[0x00]);
    }
    if let Some(decisions) = replay {
        hasher.update(&(decisions.len() as u64).to_le_bytes());
        for decision in decisions {
            hasher.update(&(*decision as u64).to_le_bytes());
        }
        hasher.update(&[0xA2]);
    } else {
        hasher.update(&[0x01]);
    }
    if let Some(s) = seed {
        hasher.update(&s.0);
        hasher.update(&[0xA3]);
    } else {
        hasher.update(&[0x02]);
    }
    EntryHash(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_sim::SwarmConfig;

    fn test_swarm() -> SwarmConfig {
        SwarmConfig {
            drop_probability: ledger_sim::Probability::new(0.1).unwrap(),
            delay_probability: ledger_sim::Probability::new(0.2).unwrap(),
            max_delay_ticks: 4,
            crash_probability: ledger_sim::Probability::new(0.05).unwrap(),
            fault_classes_per_run: 2,
        }
    }

    #[test]
    fn memo_key_deterministic() {
        let swarm = test_swarm();
        let k1 = memo_key(&Policy::Random, &swarm, &[], None, None, None);
        let k2 = memo_key(&Policy::Random, &swarm, &[], None, None, None);
        assert_eq!(k1, k2);
    }

    #[test]
    fn memo_key_differs_on_policy() {
        let swarm = test_swarm();
        let k1 = memo_key(&Policy::Random, &swarm, &[], None, None, None);
        let k2 = memo_key(&Policy::Replay, &swarm, &[], None, None, None);
        assert_ne!(k1, k2);
    }

    #[test]
    fn memo_key_differs_on_input_hash() {
        let swarm = test_swarm();
        let h1 = hash_inputs(&[1, 2, 3]);
        let h2 = hash_inputs(&[4, 5, 6]);
        let k1 = memo_key(&Policy::Random, &swarm, &[], Some(h1), None, None);
        let k2 = memo_key(&Policy::Random, &swarm, &[], Some(h2), None, None);
        let k3 = memo_key(&Policy::Random, &swarm, &[], None, None, None);
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
        assert_ne!(k2, k3);
    }

    #[test]
    fn memo_key_differs_on_replay() {
        let swarm = test_swarm();
        let k1 = memo_key(&Policy::Random, &swarm, &[], None, Some(&[1, 2, 3]), None);
        let k2 = memo_key(&Policy::Random, &swarm, &[], None, Some(&[1, 2, 4]), None);
        let k3 = memo_key(&Policy::Random, &swarm, &[], None, None, None);
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
    }

    #[test]
    fn memo_key_differs_on_seed() {
        let swarm = test_swarm();
        let k1 = memo_key(
            &Policy::Random,
            &swarm,
            &[],
            None,
            None,
            Some(EntryHash([1; 32])),
        );
        let k2 = memo_key(
            &Policy::Random,
            &swarm,
            &[],
            None,
            None,
            Some(EntryHash([2; 32])),
        );
        let k3 = memo_key(&Policy::Random, &swarm, &[], None, None, None);
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
    }

    #[test]
    fn hash_inputs_deterministic_and_distinct() {
        let h1 = hash_inputs(&[10, 20]);
        let h2 = hash_inputs(&[10, 20]);
        let h3 = hash_inputs(&[10, 21]);
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn campaign_memo_insert_and_get() {
        let mut memo = CampaignMemo::new();
        let swarm = test_swarm();
        let key = memo_key(&Policy::Random, &swarm, &[], None, None, None);
        let entry = MemoEntry {
            run_config_hash: key,
            journal_root: EntryHash([7; 32]),
            distinct: true,
        };
        assert!(memo.get(&key).is_none());
        memo.insert(key, entry);
        assert_eq!(memo.get(&key), Some(&entry));
        assert_eq!(memo.len(), 1);
        assert!(!memo.is_empty());
    }

    #[test]
    fn memo_dedup_saves_duplicate_pulls() {
        // 8 attempts over 4 variants dedup to 4 runs.
        let swarm = test_swarm();
        let policies = [
            Policy::Random,
            Policy::Replay,
            Policy::Pct {
                priority_changes: 1,
            },
            Policy::Pct {
                priority_changes: 2,
            },
        ];
        let mut memo = CampaignMemo::new();
        let mut distinct_inserted = 0usize;
        let attempts = 8usize;
        let variants = 4usize;
        for attempt in 0..attempts {
            let policy = &policies[attempt % variants];
            let key = memo_key(policy, &swarm, &[], None, None, None);
            if memo.get(&key).is_none() {
                let entry = MemoEntry {
                    run_config_hash: key,
                    journal_root: {
                        let mut root = EntryHash([0u8; 32]);
                        root.0[0] = attempt as u8;
                        root.0[1] = match policy {
                            Policy::Random => 0,
                            Policy::Replay => 1,
                            Policy::Pct { .. } => 2,
                            Policy::Bandit { .. } => 3,
                            Policy::Dpor => 4,
                        };
                        root
                    },
                    distinct: true,
                };
                memo.insert(key, entry);
                distinct_inserted += 1;
            }
        }
        assert_eq!(distinct_inserted, variants);
        assert!(distinct_inserted < attempts);
        assert_eq!(memo.len(), variants);
    }

    #[test]
    fn memo_determinism_across_builds() {
        let swarm = test_swarm();
        let inputs_a = hash_inputs(&[1, 2, 3]);
        let inputs_b = hash_inputs(&[1, 2, 3]);
        assert_eq!(inputs_a, inputs_b);
        let k1 = memo_key(
            &Policy::Random,
            &swarm,
            &[],
            Some(inputs_a),
            Some(&[5, 6]),
            None,
        );
        let k2 = memo_key(
            &Policy::Random,
            &swarm,
            &[],
            Some(inputs_b),
            Some(&[5, 6]),
            None,
        );
        assert_eq!(k1, k2);
    }

    #[test]
    fn memo_key_extends_variant_hash() {
        // Input or replay extensions must change the key.
        let swarm = test_swarm();
        let base = memo_key(&Policy::Random, &swarm, &[], None, None, None);
        let with_input = memo_key(
            &Policy::Random,
            &swarm,
            &[],
            Some(hash_inputs(&[42])),
            None,
            None,
        );
        let with_replay = memo_key(&Policy::Random, &swarm, &[], None, Some(&[0, 1]), None);
        let with_both = memo_key(
            &Policy::Random,
            &swarm,
            &[],
            Some(hash_inputs(&[42])),
            Some(&[0, 1]),
            None,
        );
        assert_ne!(base, with_input);
        assert_ne!(base, with_replay);
        assert_ne!(with_input, with_replay);
        assert_ne!(with_input, with_both);
        assert_ne!(with_replay, with_both);
    }
}
