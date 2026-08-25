//! Coyote-style online monitors consuming per-step journal deltas.
//!
//! Monitors observe each journal entry in append order and can halt on safety
//! violations or warn on liveness bound pressure. The [`MonitorOracle`] replays
//! a completed [`RunResult`] journal through each monitor in deterministic
//! order and aggregates halts into a [`Verdict`].

use ledger_format::{EntryKind, Hash};
use ledger_journal::Entry;
use ledger_sim::RunResult;
use std::cell::RefCell;

use crate::oracle::{Oracle, Verdict};

/// Action returned by an online monitor for one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MonitorAction {
    /// Continue execution.
    Continue,
    /// Non-violation warning (e.g. liveness gap approaching bound).
    Warn(String),
    /// Safety violation found online; the run must be flagged.
    Halt(String),
}

/// Online monitor that observes journal entries one by one.
pub trait OnlineMonitor {
    /// Observe one journal entry in append order.
    fn on_entry(&mut self, entry: &Entry) -> MonitorAction;
    /// Observe quiescence after the last entry.
    fn on_quiescence(&mut self) -> MonitorAction;
    /// Human-readable monitor name.
    fn name(&self) -> &str;
    /// Reset per-run state before replaying a new journal.
    ///
    /// Default is a no-op for stateless monitors. Stateful monitors (e.g.
    /// [`LivenessMonitor`]) reset counters so a single oracle remains reusable
    /// across campaign runs.
    fn reset(&mut self) {}
}

/// Oracle that replays the journal through a set of online monitors.
///
/// Deterministic: replay order is [`Journal::entries`] append order and no
/// ambient state is consulted.
pub struct MonitorOracle {
    monitors: RefCell<Vec<Box<dyn OnlineMonitor>>>,
    warnings: RefCell<Vec<String>>,
}

impl Default for MonitorOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl MonitorOracle {
    /// Create an empty monitor oracle.
    pub fn new() -> Self {
        Self {
            monitors: RefCell::new(Vec::new()),
            warnings: RefCell::new(Vec::new()),
        }
    }

    /// Append a monitor and return the oracle for chaining.
    pub fn with_monitor(self, monitor: Box<dyn OnlineMonitor>) -> Self {
        self.monitors.borrow_mut().push(monitor);
        self
    }

    /// Warnings surfaced by the last [`Oracle::check`] run.
    ///
    /// A warning is a non-violation signal (for example a liveness gap at
    /// its bound); halts stay in the [`Verdict`]. Empty before the first
    /// check or when no monitor warned.
    pub fn warnings(&self) -> Vec<String> {
        self.warnings.borrow().clone()
    }
}

impl Oracle for MonitorOracle {
    fn check(&self, run: &RunResult) -> Verdict {
        let mut witnesses: Vec<Hash> = Vec::new();
        let mut reasons: Vec<String> = Vec::new();
        let mut warns: Vec<String> = Vec::new();

        let mut monitors = self.monitors.borrow_mut();
        for monitor in monitors.iter_mut() {
            monitor.reset();
        }

        for entry in run.journal.entries() {
            for monitor in monitors.iter_mut() {
                match monitor.on_entry(entry) {
                    MonitorAction::Continue => {}
                    MonitorAction::Warn(reason) => {
                        warns.push(format!("{}: {reason}", monitor.name()));
                    }
                    MonitorAction::Halt(reason) => {
                        witnesses.push(entry.id);
                        reasons.push(format!("{}: {}", monitor.name(), reason));
                    }
                }
            }
        }

        for monitor in monitors.iter_mut() {
            match monitor.on_quiescence() {
                MonitorAction::Continue => {}
                MonitorAction::Warn(reason) => {
                    warns.push(format!("{} (quiescence): {reason}", monitor.name()));
                }
                MonitorAction::Halt(reason) => {
                    reasons.push(format!("{} (quiescence): {}", monitor.name(), reason));
                    // Provide a witness for quiescence halts when the journal
                    // is non-empty so Verdict always carries a causal entry.
                    if witnesses.is_empty()
                        && let Some(last) = run.journal.entries().last()
                    {
                        witnesses.push(last.id);
                    }
                }
            }
        }

        *self.warnings.borrow_mut() = warns;

        if reasons.is_empty() {
            Verdict::pass()
        } else {
            Verdict {
                violated: true,
                witnesses,
                reason: reasons.join("; "),
            }
        }
    }
}

/// Safety monitor that halts when the invariant predicate is false.
///
/// The invariant receives each entry; return `true` to continue, `false` to
/// halt. Only entries where the predicate is false cause a halt.
pub struct SafetyMonitor {
    invariant: Box<dyn Fn(&Entry) -> bool>,
    message: String,
    name: String,
}

impl SafetyMonitor {
    /// Create a safety monitor.
    ///
    /// `invariant` returns `true` for safe entries, `false` for violations.
    pub fn new<F>(invariant: F, message: impl Into<String>) -> Self
    where
        F: Fn(&Entry) -> bool + 'static,
    {
        Self {
            invariant: Box::new(invariant),
            message: message.into(),
            name: "safety".into(),
        }
    }

    /// Override the monitor name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }
}

impl OnlineMonitor for SafetyMonitor {
    fn on_entry(&mut self, entry: &Entry) -> MonitorAction {
        if (self.invariant)(entry) {
            MonitorAction::Continue
        } else {
            MonitorAction::Halt(self.message.clone())
        }
    }

    fn on_quiescence(&mut self) -> MonitorAction {
        MonitorAction::Continue
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// Liveness monitor that warns then halts when steps between occurrences of
/// `expected_kind` exceed `max_gap_steps`.
///
/// Eventually-style bound: every `max_gap_steps` entries an occurrence of
/// `expected_kind` must appear. Gaps are counted in journal append order.
pub struct LivenessMonitor {
    expected_kind: EntryKind,
    max_gap_steps: usize,
    steps_since: usize,
    seen: bool,
    name: String,
}

impl LivenessMonitor {
    /// Create a liveness monitor.
    pub fn new(expected_kind: EntryKind, max_gap_steps: usize) -> Self {
        Self {
            expected_kind,
            max_gap_steps,
            steps_since: 0,
            seen: false,
            name: format!("liveness:{:?}", expected_kind),
        }
    }

    /// Override the monitor name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Current gap since last occurrence.
    pub fn gap(&self) -> usize {
        self.steps_since
    }
}

impl OnlineMonitor for LivenessMonitor {
    fn on_entry(&mut self, entry: &Entry) -> MonitorAction {
        if entry.data.kind == self.expected_kind {
            self.steps_since = 0;
            self.seen = true;
            MonitorAction::Continue
        } else {
            self.steps_since += 1;
            if self.steps_since > self.max_gap_steps {
                MonitorAction::Halt(format!(
                    "gap {} exceeds max {} for {:?}",
                    self.steps_since, self.max_gap_steps, self.expected_kind
                ))
            } else if self.steps_since == self.max_gap_steps {
                MonitorAction::Warn(format!(
                    "gap {} at max {} for {:?}",
                    self.steps_since, self.max_gap_steps, self.expected_kind
                ))
            } else {
                MonitorAction::Continue
            }
        }
    }

    fn on_quiescence(&mut self) -> MonitorAction {
        if self.steps_since > self.max_gap_steps {
            MonitorAction::Halt(format!(
                "quiescence: trailing gap {} exceeds max {} for {:?}",
                self.steps_since, self.max_gap_steps, self.expected_kind
            ))
        } else if self.steps_since == self.max_gap_steps && self.max_gap_steps > 0 {
            MonitorAction::Warn(format!(
                "quiescence: trailing gap at bound {} for {:?}",
                self.max_gap_steps, self.expected_kind
            ))
        } else if !self.seen && self.steps_since == 0 {
            // Empty journal with no occurrences: only halt if bound is 0 and we
            // expect at least one occurrence. For max_gap > 0 an empty journal
            // has not yet exceeded the bound.
            MonitorAction::Continue
        } else {
            MonitorAction::Continue
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn reset(&mut self) {
        self.steps_since = 0;
        self.seen = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_format::{EntryKind, Payload};
    use ledger_journal::Journal;
    use ledger_sim::{Instruction, Policy, RunConfig, RunResult};

    fn empty_run_with_journal(journal: Journal) -> RunResult {
        RunResult {
            journal_error: None,
            journal,
            decisions: Vec::new(),
            trace: Vec::new(),
            registers: Vec::new(),
            steps: 0,
            monitor_issues: Vec::new(),
            applied_faults: Vec::new(),
            origins: Vec::new(),
        }
    }

    fn journal_with_outcomes(payloads: &[u64]) -> (Journal, Vec<Hash>) {
        let mut journal = Journal::new();
        let mut ids = Vec::new();
        for payload in payloads {
            let id = journal
                .append(EntryKind::Outcome, 1, [], Payload::Number(*payload))
                .unwrap();
            ids.push(id);
        }
        (journal, ids)
    }

    #[test]
    fn safety_monitor_halts_on_bad_outcome_payload() {
        // Halt when Outcome payload equals 99.
        let monitor = SafetyMonitor::new(
            |entry: &Entry| {
                if entry.data.kind == EntryKind::Outcome {
                    !matches!(&entry.data.payload, Payload::Number(99))
                } else {
                    true
                }
            },
            "bad outcome 99",
        );
        let (journal, ids) = journal_with_outcomes(&[1, 99, 2]);
        let run = empty_run_with_journal(journal);
        let oracle = MonitorOracle::new().with_monitor(Box::new(monitor));
        let verdict = oracle.check(&run);
        assert!(verdict.violated, "safety monitor must halt on bad payload");
        assert_eq!(verdict.witnesses.len(), 1);
        assert_eq!(verdict.witnesses[0], ids[1]);
        assert!(verdict.reason.contains("bad outcome 99"));
        assert!(verdict.reason.contains("safety"));
    }

    #[test]
    fn safety_monitor_passes_when_invariant_holds() {
        let monitor = SafetyMonitor::new(
            |entry: &Entry| {
                if entry.data.kind == EntryKind::Outcome {
                    !matches!(&entry.data.payload, Payload::Number(99))
                } else {
                    true
                }
            },
            "bad outcome 99",
        );
        let (journal, _) = journal_with_outcomes(&[1, 2, 3]);
        let run = empty_run_with_journal(journal);
        let oracle = MonitorOracle::new().with_monitor(Box::new(monitor));
        let verdict = oracle.check(&run);
        assert!(!verdict.violated);
        assert!(verdict.witnesses.is_empty());
    }

    #[test]
    fn liveness_warns_then_halts_past_gap() {
        let mut monitor = LivenessMonitor::new(EntryKind::Outcome, 2);
        let mut journal = Journal::new();
        // Three non-Outcome entries.
        let id1 = journal
            .append(EntryKind::Send, 1, [], Payload::Number(1))
            .unwrap();
        let id2 = journal
            .append(EntryKind::Send, 1, [], Payload::Number(2))
            .unwrap();
        let id3 = journal
            .append(EntryKind::Send, 1, [], Payload::Number(3))
            .unwrap();

        let e1 = journal.get(&id1).unwrap().clone();
        let e2 = journal.get(&id2).unwrap().clone();
        let e3 = journal.get(&id3).unwrap().clone();

        assert_eq!(monitor.on_entry(&e1), MonitorAction::Continue);
        assert_eq!(monitor.gap(), 1);
        let warn = monitor.on_entry(&e2);
        assert!(
            matches!(warn, MonitorAction::Warn(_)),
            "gap at bound must warn"
        );
        assert_eq!(monitor.gap(), 2);
        let halt = monitor.on_entry(&e3);
        assert!(
            matches!(halt, MonitorAction::Halt(_)),
            "gap past bound must halt"
        );
        assert_eq!(monitor.gap(), 3);

        // Reset and verify that Occurrence resets gap.
        monitor.reset();
        let outcome_id = journal
            .append(EntryKind::Outcome, 1, [], Payload::Number(0))
            .unwrap();
        let outcome_entry = journal.get(&outcome_id).unwrap().clone();
        assert_eq!(monitor.on_entry(&outcome_entry), MonitorAction::Continue);
        assert_eq!(monitor.gap(), 0);
    }

    #[test]
    fn liveness_warn_does_not_cause_oracle_violation() {
        // Max gap 2, journal with exactly 2 non-Outcome entries: only Warn, no Halt.
        let monitor = LivenessMonitor::new(EntryKind::Outcome, 2);
        let mut journal = Journal::new();
        journal
            .append(EntryKind::Send, 1, [], Payload::Number(1))
            .unwrap();
        journal
            .append(EntryKind::Send, 1, [], Payload::Number(2))
            .unwrap();
        let run = empty_run_with_journal(journal);
        let oracle = MonitorOracle::new().with_monitor(Box::new(monitor));
        let verdict = oracle.check(&run);
        assert!(!verdict.violated, "warn at bound must not be a violation");
        assert!(verdict.witnesses.is_empty());
        // The Warn must not be swallowed: it surfaces via the accessor. Both
        // the entry-time warn and the quiescence-time warn are collected.
        let warnings = oracle.warnings();
        assert_eq!(
            warnings.len(),
            2,
            "both warns must be collected: {warnings:?}"
        );
        assert!(
            warnings.iter().all(|warning| warning.contains("liveness")),
            "each warning names its monitor: {warnings:?}"
        );
        assert!(
            warnings[0].contains("gap 2"),
            "the entry warning carries the monitor reason: {warnings:?}"
        );
        assert!(
            warnings[1].contains("quiescence"),
            "the quiescence warning is tagged with its phase: {warnings:?}"
        );
    }

    #[test]
    fn warnings_reset_between_checks() {
        let monitor = LivenessMonitor::new(EntryKind::Outcome, 2);
        let mut journal = Journal::new();
        journal
            .append(EntryKind::Send, 1, [], Payload::Number(1))
            .unwrap();
        journal
            .append(EntryKind::Send, 1, [], Payload::Number(2))
            .unwrap();
        let oracle = MonitorOracle::new().with_monitor(Box::new(monitor));
        let _ = oracle.check(&empty_run_with_journal(journal));
        assert!(!oracle.warnings().is_empty());

        // A second run with no gap pressure replaces the stale warnings.
        let mut clean = Journal::new();
        clean
            .append(EntryKind::Outcome, 1, [], Payload::Number(0))
            .unwrap();
        let _ = oracle.check(&empty_run_with_journal(clean));
        assert!(
            oracle.warnings().is_empty(),
            "warnings must reset per check"
        );
    }

    #[test]
    fn liveness_halts_past_gap_via_oracle() {
        let monitor = LivenessMonitor::new(EntryKind::Outcome, 2);
        let mut journal = Journal::new();
        journal
            .append(EntryKind::Send, 1, [], Payload::Number(1))
            .unwrap();
        journal
            .append(EntryKind::Send, 1, [], Payload::Number(2))
            .unwrap();
        journal
            .append(EntryKind::Send, 1, [], Payload::Number(3))
            .unwrap();
        let run = empty_run_with_journal(journal);
        let oracle = MonitorOracle::new().with_monitor(Box::new(monitor));
        let verdict = oracle.check(&run);
        assert!(verdict.violated);
        assert_eq!(verdict.witnesses.len(), 1);
        assert!(verdict.reason.contains("gap"));
    }

    #[test]
    fn liveness_resets_on_expected_kind() {
        let monitor = LivenessMonitor::new(EntryKind::Outcome, 1);
        let mut journal = Journal::new();
        journal
            .append(EntryKind::Send, 1, [], Payload::Number(1))
            .unwrap();
        journal
            .append(EntryKind::Outcome, 1, [], Payload::Number(0))
            .unwrap();
        journal
            .append(EntryKind::Send, 1, [], Payload::Number(2))
            .unwrap();
        // Gap is 1 at bound -> Warn, not Halt, because Outcome reset gap.
        let run = empty_run_with_journal(journal);
        let oracle = MonitorOracle::new().with_monitor(Box::new(monitor));
        let verdict = oracle.check(&run);
        assert!(!verdict.violated, "gap reset by Outcome must avoid halt");
    }

    #[test]
    fn oracle_aggregates_multiple_halts() {
        let safety_a = SafetyMonitor::new(
            |entry: &Entry| !matches!(&entry.data.payload, Payload::Number(10)),
            "payload 10 forbidden",
        )
        .with_name("monitor-a");
        let safety_b = SafetyMonitor::new(
            |entry: &Entry| !matches!(&entry.data.payload, Payload::Number(20)),
            "payload 20 forbidden",
        )
        .with_name("monitor-b");

        let mut journal = Journal::new();
        let id_a = journal
            .append(EntryKind::Outcome, 1, [], Payload::Number(10))
            .unwrap();
        let id_b = journal
            .append(EntryKind::Outcome, 1, [], Payload::Number(20))
            .unwrap();
        let run = empty_run_with_journal(journal);
        let oracle = MonitorOracle::new()
            .with_monitor(Box::new(safety_a))
            .with_monitor(Box::new(safety_b));
        let verdict = oracle.check(&run);
        assert!(verdict.violated);
        // Two halts: first monitor halts on id_a, second on id_b.
        // Also first monitor does not halt on id_b and second not on id_a, so total 2 witnesses.
        assert_eq!(verdict.witnesses.len(), 2);
        assert!(verdict.witnesses.contains(&id_a));
        assert!(verdict.witnesses.contains(&id_b));
        assert!(verdict.reason.contains("monitor-a"));
        assert!(verdict.reason.contains("monitor-b"));
    }

    #[test]
    fn oracle_aggregates_multiple_halts_same_entry() {
        // Two monitors halting on the same entry should produce two witness entries (same id duplicated) or two reasons.
        let safety_a = SafetyMonitor::new(|_: &Entry| false, "always halt a").with_name("a");
        let safety_b = SafetyMonitor::new(|_: &Entry| false, "always halt b").with_name("b");
        let mut journal = Journal::new();
        let id = journal
            .append(EntryKind::Outcome, 1, [], Payload::Number(1))
            .unwrap();
        let run = empty_run_with_journal(journal);
        let oracle = MonitorOracle::new()
            .with_monitor(Box::new(safety_a))
            .with_monitor(Box::new(safety_b));
        let verdict = oracle.check(&run);
        assert!(verdict.violated);
        // Both monitors halt on the same entry -> 2 witnesses (same id twice)
        assert_eq!(verdict.witnesses.len(), 2);
        assert!(verdict.witnesses.iter().all(|w| *w == id));
        assert!(verdict.reason.contains("always halt a"));
        assert!(verdict.reason.contains("always halt b"));
    }

    #[test]
    fn verdict_witnesses_carry_halted_ids() {
        let monitor = SafetyMonitor::new(
            |entry: &Entry| entry.data.kind != EntryKind::Outcome,
            "no outcome allowed",
        );
        let mut journal = Journal::new();
        let id1 = journal
            .append(EntryKind::Send, 1, [], Payload::Number(1))
            .unwrap();
        let id2 = journal
            .append(EntryKind::Outcome, 1, [], Payload::Number(0))
            .unwrap();
        let id3 = journal
            .append(EntryKind::Send, 1, [], Payload::Number(2))
            .unwrap();
        let run = empty_run_with_journal(journal);
        let oracle = MonitorOracle::new().with_monitor(Box::new(monitor));
        let verdict = oracle.check(&run);
        assert!(verdict.violated);
        assert_eq!(verdict.witnesses, vec![id2]);
        // Ensure non-halted ids are not in witnesses.
        assert!(!verdict.witnesses.contains(&id1));
        assert!(!verdict.witnesses.contains(&id3));
        assert!(verdict.reason.contains("no outcome"));
    }

    #[test]
    fn integration_with_oracle_trait_generic() {
        fn accepts_oracle<O: Oracle>(oracle: &O, run: &RunResult) -> Verdict {
            oracle.check(run)
        }
        let monitor = SafetyMonitor::new(|_: &Entry| true, "never halt");
        let oracle = MonitorOracle::new().with_monitor(Box::new(monitor));
        let (journal, _) = journal_with_outcomes(&[1]);
        let run = empty_run_with_journal(journal);
        let verdict = accepts_oracle(&oracle, &run);
        assert!(!verdict.violated);
    }

    #[test]
    fn integration_with_run_campaign() {
        // Verify MonitorOracle compiles where Oracle trait objects are used via run_campaign generic.
        use crate::search::{Workload, run_campaign};

        struct DummyWorkload;
        impl Workload for DummyWorkload {
            fn programs(&self) -> Vec<Vec<Instruction>> {
                vec![vec![
                    Instruction::Set(1),
                    Instruction::Outcome,
                    Instruction::Done,
                ]]
            }
            fn history(&self, _run: &RunResult) -> Vec<crate::oracle::HistoryOperation> {
                Vec::new()
            }
        }

        let workload = DummyWorkload;
        // Monitor that never halts.
        let oracle = MonitorOracle::new()
            .with_monitor(Box::new(SafetyMonitor::new(|_: &Entry| true, "never")));
        let base = RunConfig::builder()
            .seed([1; 32])
            .policy(Policy::Random)
            .max_steps(64)
            .build();
        let report = run_campaign(&workload, &oracle, base, 2).unwrap();
        assert_eq!(report.runs_executed, 2);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn integration_with_run_campaign_finds_violation() {
        use crate::search::{Workload, run_campaign};

        struct DummyWorkload;
        impl Workload for DummyWorkload {
            fn programs(&self) -> Vec<Vec<Instruction>> {
                vec![vec![
                    Instruction::Set(99),
                    Instruction::Outcome,
                    Instruction::Done,
                ]]
            }
            fn history(&self, _run: &RunResult) -> Vec<crate::oracle::HistoryOperation> {
                Vec::new()
            }
        }

        let workload = DummyWorkload;
        // Halt when Outcome payload 99 is observed.
        let oracle = MonitorOracle::new().with_monitor(Box::new(SafetyMonitor::new(
            |entry: &Entry| {
                if entry.data.kind == EntryKind::Outcome {
                    !matches!(&entry.data.payload, Payload::Number(99))
                } else {
                    true
                }
            },
            "outcome 99 forbidden",
        )));
        let base = RunConfig::builder()
            .seed([2; 32])
            .policy(Policy::Random)
            .max_steps(64)
            .build();
        let report = run_campaign(&workload, &oracle, base, 2).unwrap();
        assert_eq!(
            report.findings.len(),
            2,
            "every run contains the forbidden outcome"
        );
        for finding in report.findings {
            assert!(finding.verdict.violated);
            assert!(!finding.verdict.witnesses.is_empty());
        }
    }

    #[test]
    fn oracle_replay_order_is_journal_append_order() {
        // Ensure deterministic replay: monitors see entries in journal append order.
        struct OrderMonitor {
            seen: std::cell::RefCell<Vec<u64>>,
        }
        impl OnlineMonitor for OrderMonitor {
            fn on_entry(&mut self, entry: &Entry) -> MonitorAction {
                if let Payload::Number(v) = entry.data.payload {
                    self.seen.borrow_mut().push(v);
                }
                MonitorAction::Continue
            }
            fn on_quiescence(&mut self) -> MonitorAction {
                MonitorAction::Continue
            }
            fn name(&self) -> &str {
                "order"
            }
        }
        let monitor = OrderMonitor {
            seen: RefCell::new(Vec::new()),
        };
        let mut journal = Journal::new();
        for v in [10, 20, 30] {
            journal
                .append(EntryKind::Outcome, 1, [], Payload::Number(v))
                .unwrap();
        }
        let run = empty_run_with_journal(journal);
        let oracle = MonitorOracle::new().with_monitor(Box::new(monitor));
        let _ = oracle.check(&run);
        // The monitor's seen Vec was moved into oracle; we cannot inspect directly.
        // Instead test via a monitor that halts and check witnesses order matches append order.
        let halt_on_20 = SafetyMonitor::new(
            |entry: &Entry| !matches!(&entry.data.payload, Payload::Number(20)),
            "halt on 20",
        );
        let mut journal2 = Journal::new();
        let _id10 = journal2
            .append(EntryKind::Outcome, 1, [], Payload::Number(10))
            .unwrap();
        let id20 = journal2
            .append(EntryKind::Outcome, 1, [], Payload::Number(20))
            .unwrap();
        let _id30 = journal2
            .append(EntryKind::Outcome, 1, [], Payload::Number(30))
            .unwrap();
        let run2 = empty_run_with_journal(journal2);
        let oracle2 = MonitorOracle::new().with_monitor(Box::new(halt_on_20));
        let verdict = oracle2.check(&run2);
        assert_eq!(verdict.witnesses, vec![id20]);
    }

    #[test]
    fn monitor_oracle_is_reusable_across_runs() {
        // Liveness monitor state must reset between checks.
        let monitor = LivenessMonitor::new(EntryKind::Outcome, 1);
        let oracle = MonitorOracle::new().with_monitor(Box::new(monitor));

        let mut j1 = Journal::new();
        j1.append(EntryKind::Send, 1, [], Payload::Number(1))
            .unwrap();
        j1.append(EntryKind::Send, 1, [], Payload::Number(2))
            .unwrap(); // gap 2 >1 => halt
        let run1 = empty_run_with_journal(j1);
        let v1 = oracle.check(&run1);
        assert!(v1.violated, "first run should halt");

        let mut j2 = Journal::new();
        j2.append(EntryKind::Outcome, 1, [], Payload::Number(0))
            .unwrap(); // resets gap
        let run2 = empty_run_with_journal(j2);
        let v2 = oracle.check(&run2);
        assert!(
            !v2.violated,
            "second run after reset must not carry over gap"
        );
    }

    #[test]
    fn safety_monitor_on_quiescence_is_noop() {
        let mut monitor = SafetyMonitor::new(|_: &Entry| false, "always halt");
        let journal = Journal::new();
        let entry = journal.entries().next();
        assert!(entry.is_none());
        // on_quiescence must be Continue even though on_entry would Halt.
        assert_eq!(monitor.on_quiescence(), MonitorAction::Continue);
    }

    #[test]
    fn deterministic_no_ambient() {
        // Two identical journals must produce identical verdicts.
        let mk_oracle = || {
            MonitorOracle::new().with_monitor(Box::new(SafetyMonitor::new(
                |e: &Entry| !matches!(&e.data.payload, Payload::Number(42)),
                "no 42",
            )))
        };
        let (j1, _) = journal_with_outcomes(&[42]);
        let (j2, _) = journal_with_outcomes(&[42]);
        let r1 = empty_run_with_journal(j1);
        let r2 = empty_run_with_journal(j2);
        let v1 = mk_oracle().check(&r1);
        let v2 = mk_oracle().check(&r2);
        assert_eq!(v1, v2);
        assert!(v1.violated);
    }
}
