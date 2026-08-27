# Replay and minimize

This lesson takes a violation and shrinks it. You verify same-build replay for a configured seed, minimize a schedule, and diff two seeds.

## Replay a seed

`repro` executes one configured run, replays its recorded decisions, and compares the two journal roots:

```bash
cargo run -p ledger-cli -- repro --seed 7
cargo run -p ledger-cli -- repro --seed 7 --policy random --max-steps 256
```

Flags for `repro` (see `ledger repro --help`):

- `--seed` (default 0)
- `--policy` with `random`, `pct`, `bandit`, `replay` (default `random`)
- `--exploration-constant` (default 1.414)
- `--priority-changes` (default 8)
- `--max-steps` (default 256)

Global flags also apply: `--json`, `--ndjson`, `--deadline-ms MS`, `-v` / `-q`.

Run it twice with the same build and flags. The journal root matches. If you change the build, policy, or `max-steps`, the root can change. Keep all run inputs identical for a strict comparison.

With `--json`, `repro` prints `reproducible` and `journal_root`. A command error exits with code 1. A root mismatch is reported as `reproducible: false` and currently exits with code 0, so scripts must inspect the field.

## Minimize a failing schedule

`minimize` delta-debugs the schedule that led to the violation. It keeps the failure and removes choices that do not matter:

```bash
cargo run -p ledger-cli -- minimize --seed 7 --runs 256
```

Flags for `minimize` (see `ledger minimize --help`):

- `--seed` (default 0)
- `--policy` with `random`, `pct`, `bandit`, `replay` (default `random`)
- `--exploration-constant` (default 1.414)
- `--priority-changes` (default 8)
- `--max-steps` (default 256)
- `--runs` (default 256)

A reduced schedule is easier to read, faster to replay, and better to use in a regression test. Delta debugging produces a 1-minimal result over the candidates that it tests. It does not guarantee the globally smallest possible schedule. Keep the seed, run configuration, and minimized decisions with the report.

Run with `--json` when you want a machine-readable minimized result.

## Compare two seeds

`diff` shows the first divergence between two explorations:

```bash
cargo run -p ledger-cli -- diff --seed-a 1 --seed-b 2 --max-steps 256
```

Flags for `diff` (see `ledger diff --help`):

- `--seed-a` (default 1)
- `--seed-b` (default 2)
- `--max-steps` (default 256)

Use it when a seed passes and another fails, or when you want to see where two policies diverge. The output points at the first entry that differs. Both seeds run under the same max-steps, so compare like with like.

Add `--json` to diff when you want a stable shape for scripts.

## Try the full loop

```bash
cargo run -p ledger-cli -- sim --seed 7 --runs 20
cargo run -p ledger-cli -- repro --seed 7 --policy bandit --max-steps 256
cargo run -p ledger-cli -- minimize --seed 7 --runs 100
cargo run -p ledger-cli -- diff --seed-a 7 --seed-b 8 --max-steps 256
```

You find a violation, verify a replay, shrink a schedule, and compare two seeds. The same build, configuration, seed, and inputs produce the same roots on the controlled execution path.

Keep the minimized seed for your regression set. Store it with the journal root so future runs can assert no drift.

You can rerun the minimized case through `--json` and retain its root with the regression. Campaign certificates are a separate artifact. Against a journal, their minimality extension checks bounded derivation-path coverage and inclusion minimality, and records a solver-derived lower bound. It does not prove global schedule minimality.

## Why minimal matters

A full campaign schedule has many irrelevant orderings. Minimization removes tested decisions while preserving the oracle violation. Keep the short case with its build, workload, configuration, and journal root. `ledger repro` verifies a configured seed by replay. `ledger format --check` only validates canonical CBOR encoding.

Short cases also make reviews easier. A reviewer can read ten steps, not two hundred. The signal stands out and the fix is clear.

## Tips

- Start small: minimize with `--runs 100` first, then raise it if the failure needs more search.
- Keep policy and max-steps stable across repro, minimize, and diff for like-with-like comparison.
- Save the minimized output next to the bug report. Future CI can replay it as a regression gate.

## What to read next

- `finding-bugs-with-ldfi.md` - rank fault sets for the same violation.
- `../guides/cli-reference.md` - full flag tables for `repro`, `minimize`, and `diff`.
- `../concepts.md` - how the journal gives byte-identical replay.

## See also

- `../guides/cli-reference.md` has the full table for every ledger command.
