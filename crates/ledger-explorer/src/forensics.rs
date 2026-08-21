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

/// Rank entry-kind transition motifs by failure-probability lift.
///
/// Each labeled run contributes one boolean presence per distinct transition.
/// The lift is the ratio of the add-1 smoothed failing rate to the add-1
/// smoothed passing rate, so no division by zero is possible. Motifs in fewer
/// than `min_occurrences` runs total are excluded.
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
    let mut seen = HashSet::new();
    let mut prev: Option<EntryKind> = None;
    for entry in journal.entries() {
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
    use ledger_format::Payload;

    fn chain_journal(entries: &[(EntryKind, Payload)]) -> Journal {
        let mut journal = Journal::new();
        for (kind, payload) in entries {
            journal
                .append(*kind, 1, [], payload.clone())
                .expect("append must succeed");
        }
        journal
    }

    fn run(journal: Journal) -> RunResult {
        RunResult {
            journal_error: None,
            journal,
            decisions: Vec::new(),
            trace: Vec::new(),
            registers: Vec::new(),
            steps: 0,
            monitor_issues: Vec::new(),
            applied_faults: Vec::new(),
        }
    }

    #[test]
    fn rank_motifs_puts_failing_motif_first() {
        let failing = run(chain_journal(&[
            (EntryKind::Send, Payload::Number(1)),
            (EntryKind::Recv, Payload::Number(1)),
            (EntryKind::Assert, Payload::Number(0)),
        ]));
        let passing_recv = run(chain_journal(&[
            (EntryKind::Send, Payload::Number(2)),
            (EntryKind::Recv, Payload::Number(2)),
        ]));
        let passing_send = run(chain_journal(&[
            (EntryKind::Send, Payload::Number(3)),
            (EntryKind::Send, Payload::Number(4)),
        ]));

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
            (EntryKind::Send, Payload::Number(1)),
            (EntryKind::Assert, Payload::Number(0)),
        ]));
        let passing = run(chain_journal(&[
            (EntryKind::Send, Payload::Number(2)),
            (EntryKind::Recv, Payload::Number(2)),
        ]));
        let labeled = vec![(failing, true), (passing.clone(), false), (passing, false)];
        let ranked = rank_motifs_by_lift(&labeled, 2);
        assert!(
            ranked.iter().all(|m| m.motif != "Send->Assert"),
            "a motif in fewer than two runs must be excluded"
        );
    }

    #[test]
    fn all_passing_runs_yield_no_lifts() {
        let passing = run(chain_journal(&[(EntryKind::Send, Payload::Number(1))]));
        let labeled = vec![(passing.clone(), false), (passing, false)];
        assert!(rank_motifs_by_lift(&labeled, 1).is_empty());
    }
}
