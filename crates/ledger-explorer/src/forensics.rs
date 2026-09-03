//! Causal motif extraction and failure lift metrics (Statistical Bug Isolation).

use ledger_format::EntryKind;
use ledger_journal::Journal;
use ledger_sim::RunResult;
use std::collections::{HashMap, HashSet};

/// Failure-probability lift of one causal motif.
#[derive(Debug, Clone, PartialEq)]
pub struct MotifLift {
    /// Motif label, for example `"Send->Recv"`.
    pub motif: String,
    pub in_failing: usize,
    pub in_passing: usize,
    /// Add-1 smoothed failure-probability lift.
    pub lift: f64,
}

/// Rank motifs by add-1 smoothed failure lift. Rare motifs excluded.
pub fn rank_motifs_by_lift(
    labeled: &[(RunResult, bool)],
    min_occurrences: usize,
) -> Vec<MotifLift> {
    if labeled.is_empty() {
        return Vec::new();
    }
    let failing_total = labeled.iter().filter(|(_, failing)| *failing).count();
    let passing_total = labeled.len() - failing_total;
    if failing_total == 0 || passing_total == 0 {
        return Vec::new();
    }

    let mut failing_counts: HashMap<(EntryKind, EntryKind), usize> = HashMap::new();
    let mut passing_counts: HashMap<(EntryKind, EntryKind), usize> = HashMap::new();
    for (run, failing) in labeled {
        let target = if *failing {
            &mut failing_counts
        } else {
            &mut passing_counts
        };
        for motif in distinct_transitions(&run.journal) {
            *target.entry(motif).or_insert(0) += 1;
        }
    }

    let mut motifs: HashSet<(EntryKind, EntryKind)> = failing_counts.keys().copied().collect();
    motifs.extend(passing_counts.keys().copied());

    let mut lifts = Vec::new();
    for motif in motifs {
        let in_failing = failing_counts.get(&motif).copied().unwrap_or(0);
        let in_passing = passing_counts.get(&motif).copied().unwrap_or(0);
        if in_failing + in_passing < min_occurrences {
            continue;
        }
        let failing_rate = (in_failing + 1) as f64 / (failing_total + 1) as f64;
        let passing_rate = (in_passing + 1) as f64 / (passing_total + 1) as f64;
        lifts.push(MotifLift {
            motif: motif_label(motif),
            in_failing,
            in_passing,
            lift: failing_rate / passing_rate,
        });
    }

    lifts.sort_by(|a, b| {
        b.lift
            .partial_cmp(&a.lift)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.motif.cmp(&b.motif))
    });
    lifts
}

fn distinct_transitions(journal: &Journal) -> HashSet<(EntryKind, EntryKind)> {
    // Causal order, not append order, so concurrent interleavings map together.
    let mut ordered: Vec<_> = journal.entries().collect();
    ordered.sort_by(|a, b| {
        let sum_a: u64 = a.vector_clock.iter().map(|(_, v)| v).sum();
        let sum_b: u64 = b.vector_clock.iter().map(|(_, v)| v).sum();
        sum_a
            .cmp(&sum_b)
            .then(a.data.actor.cmp(&b.data.actor))
            .then(a.data.sequence.cmp(&b.data.sequence))
            .then(a.id.cmp(&b.id))
    });
    let mut seen = HashSet::new();
    let mut prev: Option<EntryKind> = None;
    for entry in ordered {
        if let Some(p) = prev {
            seen.insert((p, entry.data.kind));
        }
        prev = Some(entry.data.kind);
    }
    seen
}

fn motif_label(motif: (EntryKind, EntryKind)) -> String {
    format!("{:?}->{:?}", motif.0, motif.1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_format::ActorId;
    use ledger_format::EntryHash;
    use ledger_format::{CanonicalValue, EntryPayload};

    fn chain_journal(entries: &[(EntryKind, u64)]) -> Journal {
        let mut journal = Journal::new();
        for (kind, value) in entries {
            let payload = match kind {
                EntryKind::Send => EntryPayload::Send(ledger_format::SendFrame {
                    message_id: ledger_format::MessageId::new(ActorId(1), 0),
                    from: ActorId(1),
                    to: ActorId(1),
                    original_content: value.to_le_bytes().to_vec(),
                }),
                EntryKind::Recv => EntryPayload::Recv(ledger_format::RecvFrame {
                    message_id: ledger_format::MessageId::new(ActorId(1), 0),
                    from: ActorId(1),
                    to: ActorId(1),
                    observed_content: value.to_le_bytes().to_vec(),
                }),
                EntryKind::Assert => EntryPayload::Assert(ledger_format::AssertPayload {
                    predicate: EntryHash([0x00; 32]),
                    passed: *value != 0,
                    detail: CanonicalValue::Unsigned(*value),
                }),
                _ => unreachable!("fixture kinds"),
            };
            journal
                .append(*kind, ActorId(1), [], payload)
                .expect("append must succeed");
        }
        journal
    }

    fn run(journal: Journal) -> RunResult {
        RunResult {
            outcome: ledger_sim::RunOutcome::Completed,
            journal_error: None,
            journal,
            decisions: Vec::new(),
            trace: Vec::new(),
            registers: Vec::new(),
            steps: 0,
            monitor_issues: Vec::new(),
            applied_faults: Vec::new(),
            origins: Vec::new(),
            protection: ledger_sim::BeltStatus::NotArmed,
        }
    }

    #[test]
    fn rank_motifs_puts_failing_motif_first() {
        let failing = run(chain_journal(&[
            (EntryKind::Send, 1),
            (EntryKind::Recv, 1),
            (EntryKind::Assert, 0),
        ]));
        let passing_recv = run(chain_journal(&[(EntryKind::Send, 2), (EntryKind::Recv, 2)]));
        let passing_send = run(chain_journal(&[(EntryKind::Send, 3), (EntryKind::Send, 4)]));

        let labeled = vec![
            (failing.clone(), true),
            (failing.clone(), true),
            (failing.clone(), true),
            (passing_recv, false),
            (passing_send.clone(), false),
            (passing_send, false),
        ];

        let ranked = rank_motifs_by_lift(&labeled, 1);
        assert!(!ranked.is_empty());
        assert_eq!(ranked[0].motif, "Recv->Assert");
        assert_eq!(ranked[0].in_failing, 3);
        assert_eq!(ranked[0].in_passing, 0);
        assert!(
            ranked[0].lift > ranked[1].lift,
            "the failing motif must rank above the rest"
        );
        for pair in ranked.windows(2) {
            assert!(
                pair[0].lift >= pair[1].lift,
                "motifs must be sorted by descending lift"
            );
        }
    }

    #[test]
    fn min_occurrences_excludes_rare_motifs() {
        let failing = run(chain_journal(&[
            (EntryKind::Send, 1),
            (EntryKind::Assert, 0),
        ]));
        let passing = run(chain_journal(&[(EntryKind::Send, 2), (EntryKind::Recv, 2)]));
        let labeled = vec![(failing, true), (passing.clone(), false), (passing, false)];
        let ranked = rank_motifs_by_lift(&labeled, 2);
        assert!(
            ranked.iter().all(|m| m.motif != "Send->Assert"),
            "a motif in fewer than two runs must be excluded"
        );
    }

    #[test]
    fn all_passing_runs_yield_no_lifts() {
        let passing = run(chain_journal(&[(EntryKind::Send, 1)]));
        let labeled = vec![(passing.clone(), false), (passing, false)];
        assert!(rank_motifs_by_lift(&labeled, 1).is_empty());
    }
}
