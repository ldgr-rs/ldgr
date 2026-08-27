# Getting Started

This guide takes you from zero to your first passing simulation.

## Prerequisites

* Rust 1.90 or newer. The repo pins 1.97 via `rust-toolchain.toml`.
* `cargo` on your PATH.
* A clone of the ldgr repository.

## Build

```bash
git clone https://github.com/ldgr-rs/ldgr && cd ldgr
cargo build -p ledger-cli
```

The binary is named `ledger`. You can also install it to your cargo bin:

```bash
cargo install --path crates/ledger-cli
```

Check it works:

```bash
cargo run -p ledger-cli -- --help
# or, if installed:
ledger --help
```

You should see the `ledger` help text and the list of subcommands.

## Run your first campaign

Run a short deterministic campaign with an explicit seed:

```bash
cargo run -p ledger-cli -- sim --seed 42 --runs 10
```

What happens:

* ldgr runs the built-in mini key-value workload 10 times.
* Each run uses a different schedule derived from the seed.
* Each run journals effects and checks the oracle.

On first run you will likely see a violation (the built-in workload is intentionally buggy for the demo):

```text
Violation detected: read of k returned 100, expected 42
Journal root: eaddfb60... (64 hex chars)
Steps executed: 10
```

A passing run looks like `Simulation passed (10 runs evaluated, zero violations).` Either way the output is deterministic - same seed gives the same result. With `--json` or `--ndjson` you get machine-readable records that include `steps` and `journal_root`.

## See a violation

Some seeds and workloads produce violations. A violation looks like this:

```text
Violation detected: read of k returned 100, expected 42
Journal root: a1b2c3... (64 hex chars)
Steps executed: 42
```

* `Violation detected` is the oracle reason.
* `Journal root` is the hash of the causal DAG for that run. Same inputs give the same root, byte for byte.
* `Steps executed` is how many simulated instructions ran before the check.

The violation carries the seed and the schedule that produced it, so you can replay it exactly. See [Replay and Minimize](tutorials/replay-minimize.md).

## What to do next

* Read [Concepts](concepts.md) for the mental model.
* Try the [First Simulation](tutorials/first-simulation.md) tutorial.
* See [CLI Reference](guides/cli-reference.md) for every command and flag.
* If a run hangs, use the global flag `--deadline-ms` - see [FAQ](faq.md).

## Common flags you will use soon

All `sim`-family commands accept these:

```bash
ledger sim --seed 42 --runs 100 --max-steps 256 --policy bandit
```

* `--seed` sets the root seed.
* `--runs` sets how many attempts to run.
* `--max-steps` caps instructions per run.
* `--policy` picks the scheduler: `random`, `bandit`, `pct`, `replay`.

Global flags work on every command:

```bash
ledger --deadline-ms 5000 sim --seed 42 --runs 100
ledger --json sim --seed 42 --runs 10
ledger -v sim --seed 42 --runs 10
```

* `--deadline-ms` exits with code 2 if the whole command exceeds that wall-clock budget.
* `--json` and `--ndjson` switch to machine-readable output.
* `-v` / `-q` control verbosity.

Exit codes: `0` the command completed (a campaign that found a violation also exits 0 - check the output), `1` the command failed, `2` deadline exceeded. See [FAQ](faq.md) and [CLI Reference](guides/cli-reference.md).
