# Oracles

An oracle is a predicate over a run. It looks at the journal and says pass or fail. When it fails, it returns a reason and the entry hashes that witness the violation. Those witnesses are what LDFI and minimization use to shrink the counterexample.

## History oracles

The most common oracle for storage workloads checks the history view. A workload exposes a history by mapping journal entries to `HistoryOperation` values: writes and reads with keys, values, and witness hashes. The explorer then checks properties over that history.

The built-in `HistoryOracle` for key-value workloads checks two things:

- Every input value is applied at most once. A duplicate is a violation.
- When inputs exist and an outcome exists, the outcome matches the last applied input. A mismatch is a torn final apply.

This covers exactly-once application and end-to-end read correctness. The oracle is scoped to a single input stream and a single outcome stream. A history maps each journaled operation to a read or a write with witness hashes - the scaffolded mini-KV workload shows the mapping pattern end to end.

## Property and monitor oracles

You can also write predicates directly over the journal without a history view. Two common forms:

- **Property oracles** - a closure over the journal. Return `false` to report a violation, with outcome and assertion entries as witnesses.
- **Monitor oracles** - the journal-correctness monitor audits every run for structural defects and reports them as findings. Callers decide how to react.

Both plug into the same campaign. A campaign can run a primary oracle and a monitor oracle together. Either one failing produces a finding.

## Differential oracles

`ledger diff` compares two seeds for first divergence. It runs both seeds and reports the first journal entry and schedule position where they differ. Use it to check that a replay matches or that a change does not alter behavior.

```bash
ledger diff --seed-a 1 --seed-b 2 --max-steps 256
```

## How findings surface

`sim` and `ldfi` surface oracle results directly:

```bash
ledger sim --seed 42 --runs 100
# Violation detected: <reason>
# Journal root: <hex>
# Steps executed: <n>
# Witnesses: <hash> ...

ledger ldfi --seed 42 --attempts 64
# LDFI hypotheses:
#   cut[0]: 1 event(s), cost 2 - Minimum hitting set cut ...
```

With `--json` or `--ndjson`, the same fields appear as JSON:

```bash
ledger --json sim --seed 42 --runs 100
ledger --ndjson sim --runs 20 | jq .
```

Each finding in the JSON includes the reason, the journal root, the step count, and the witness hashes. Minimization preserves those witnesses while shrinking the schedule.

## Writing your own oracle

Keep the interface small. Implement `Oracle::check(&RunResult) -> Verdict` where `Verdict` is either `pass()` or `fail(witnesses, reason)`. A witness is a journal entry hash; collect them as you walk the journal so a violation points at the entries that prove it. Keep witness sets small and relevant - the minimizer works on what you return.

Host-side oracle code may read the journal, the run's registers, and the history view. It must not depend on wall time, ambient RNG, or external state.

Minimal example:

```rust
use ledger_explorer::{Oracle, Verdict};
use ledger_sim::RunResult;
use ledger_explorer::oracle::witnesses_from_journal;

struct NoBadOutcome;

impl Oracle for NoBadOutcome {
    fn check(&self, run: &RunResult) -> Verdict {
        let has_bad = run.journal.entries().any(|e| {
            // inspect entry kind and payload
            false // replace with your predicate
        });
        if has_bad {
            Verdict::fail(witnesses_from_journal(&run.journal), "bad outcome observed")
        } else {
            Verdict::pass()
        }
    }
}
```

Tips:

- Start from `HistoryOracle` when your workload has reads and writes. It already handles the common cases.
- Keep oracles deterministic. The same journal must always yield the same verdict.
- Test the oracle with `cargo test -p ledger-explorer`. Seed the run, assert on the verdict, and check the witnesses.
