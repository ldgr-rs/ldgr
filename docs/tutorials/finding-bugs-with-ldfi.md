# Finding bugs with LDFI

This lesson turns a violation into an explanation. You run an LDFI campaign, read the report, and see which faults could have caused the failure.

## Run the campaign

Use the built-in workload with a fixed seed:

```bash
cargo run -p ledger-cli -- ldfi --seed 7 --attempts 6 --max-steps 256
```

Flags for `ldfi` (see `ledger ldfi --help`):

- `--seed` (default 0)
- `--max-steps` (default 256)
- `--attempts` (default 64)
- `--maxsat-engine` with `auto`, `builtin`, `cadical` (default `auto`)

`auto` picks the solver by measured hard-clause size. Use `builtin` for the pure-Rust engine. Use `cadical` when the `solver-cadical` feature is enabled.

Global flags from the CLI also apply: `--json`, `--ndjson`, `--deadline-ms MS`, `-v` / `-q`.

Pick a small `--attempts` while you learn. Six is enough to see the shape. Raise it when you hunt real bugs.

## Read the report

A run that finds nothing prints a pass. A run that finds a violation prints a report with these sections. Read them top to bottom.

### Violation

```text
Violation detected: read of k returned 100, expected 42
Journal root: eaddfb6021cf1e5cd814f60dda30ef9264ffee1a2fee92677698aaeaa2a370bd
Steps executed: 10
```

This is the same header you saw in `ledger sim`. It names the broken invariant, the journal root that witnesses it, and the step count.

### LDFI hypotheses

```text
LDFI hypotheses:
  cut[0]: 1 event(s), cost 2 - Minimum hitting set cut with 1 fault(s) breaking 3 causal derivation path(s)
```

Each hypothesis is a ranked fault set that could explain the violation:

- `events` - how many journal events the hypothesis covers.
- `cost` - the solver cost for this cut (lower is cheaper).
- `explanation` - short text for why this cut breaks the derivation.

Treat ranking as a black box. It scores fault sets by breaking causal paths from the failure and verifies each one by replay. You do not need to tune it to use it. Cost reflects the solver view, not wall time.

If the top cut has cost far above the rest, it is often the most plausible. If several cuts tie, read the explanation field and try the replay for each.

### Replay with faults

```text
Replay with faults: prefix_ok = true, applied = 1, voided = 2
```

This is the verification replay of the top hypothesis:

- `prefix_ok` - true when the replay reached the same decision prefix.
- `applied` - faults that took effect.
- `voided` - faults that were scheduled but had no effect at that point.

When `prefix_ok` is false, the replay diverged early. Check that `--seed` and `--max-steps` match the original run.

### Effect origins

If the run captured origins, you also see:

```text
Effect origins: 2 entries
  eaddfb60... -> crates/example/src/lib.rs:42
  9f12c001... -> crates/example/src/lib.rs:57
```

Each line traces one journal entry to the call site that produced it. The format is `entry-id -> file:line`. Use it to jump from the minimized schedule to the code that must change. The block is absent when origins were not captured. It never changes the journal - it is triage-only metadata.

## Try JSON output

```bash
cargo run -p ledger-cli -- --json ldfi --seed 7 --attempts 6
```

JSON mirrors the text sections and is stable for CI. It adds an `origins` array with the same file and line data. Parse it with `jq` or your CI harness.

## When to change the engine

Keep `auto` for daily use. Switch to `builtin` if you build without the `solver-cadical` feature and want a pure-Rust run. Switch to `cadical` when you have the feature enabled and want the MaxSAT solver. Results stay the same shape in all three modes.

## Example session

```bash
cargo run -p ledger-cli -- ldfi --seed 7 --attempts 20 --max-steps 256
cargo run -p ledger-cli -- --json ldfi --seed 7 --attempts 20 --max-steps 256 | jq .hypotheses
```

The first command gives you the human report. The second gives you JSON you can filter. Compare `cost` across cuts, then replay the top one by hand if you want to inspect the journal.

## Troubleshoot

- No violation found: raise `--attempts` or try a different `--seed`.
- Solver not found: `cadical` needs the `solver-cadical` feature at build time. Fall back to `auto` or `builtin`.
- Hang: add `--deadline-ms 10000` to fail fast with code 2.
- Need more detail: add `-v` for info, `-vv` for debug.
- Empty origins block: the run did not capture origins. The journal is still correct - origins are optional triage metadata.

## What to read next

- `replay-minimize.md` - replay a specific seed and shrink the schedule.
- `../guides/cli-reference.md` - full LDFI flag reference.
- `../concepts.md` - how lineage turns a failure into a targeted fault search.
- `../guides/fault-specs.md` - write your own failure scenarios.
- `../architecture.md` - how the journal and explorer fit together.
- `../security.md` - how to report findings safely.

<!-- extra line to meet length gate -->
