# Replay and minimize

This lesson takes a violation and shrinks it. You replay a seed to prove it is identical, minimize the schedule, and diff two seeds.

## Replay a seed

Replay verifies that the same seed gives the same journal root:

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

Run it twice. The journal root matches both times. If you change any flag, the root can change, but that new root is also deterministic. Keep the policy and max-steps identical for a strict replay.

With `--json`, `repro` prints the root and steps in a stable shape for scripts. Exit code is 0 on a successful replay, 1 on mismatch or failure.

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

The minimized schedule is much smaller than the original. A smaller schedule is easier to read, faster to replay, and better to attach to a bug report. The certificate that ships with the finding still checks. Keep the minimized seed and file it with the report.

Run with `--json` when you want a machine shape for the minimized output. Add `-v` if you want to see which choices were kept.

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

You find a violation, replay it exactly, shrink it, and compare the failing seed to a passing one. Each step is deterministic, so you can run the loop on any machine and get the same roots.

Keep the minimized seed for your regression set. Store it with the journal root so future runs can assert no drift.

You can also re-run the minimized case through `--json` and check the certificate step that ships with the finding. A smaller case still carries the same proof that the failure happened.

## Why minimal matters

A full campaign schedule has many irrelevant orderings. Minimization keeps only the orderings that the oracle needs to see the violation. You get a short, deterministic reproduction you can paste into an issue, replay on any machine, and verify with `ledger format --check` or `ledger repro`. That short case is also cheaper to keep as a regression test.

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
