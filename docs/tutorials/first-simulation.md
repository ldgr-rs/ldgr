# First simulation

This lesson runs your first deterministic campaign. You build the CLI, run a campaign, and verify that the same seed always gives the same journal.

## Prerequisites

- Rust 1.90 or newer (1.97 pinned in `rust-toolchain.toml`)
- A clone of the ldgr repo

## Build the CLI

```bash
git clone https://github.com/k5602/ldgr && cd ldgr
cargo build -p ledger-cli
```

The binary is `ledger`. You can also use `cargo run -p ledger-cli --` in place of `ledger`.

## Run a campaign

Run the default mini key-value campaign:

```bash
cargo run -p ledger-cli -- sim --seed 0 --runs 20
```

Try the full flag set for `sim` (see `ledger sim --help`):

- `--seed` (default 0)
- `--policy` with `random`, `pct`, `bandit`, `replay` (default `bandit`)
- `--exploration-constant` (default 1.414)
- `--priority-changes` (default 8, for `pct`)
- `--max-steps` (default 256)
- `--runs` (default 100)

Global flags work on every command:

- `-j` / `--json` and `--ndjson` for machine output
- `-v` / `-q` for verbosity
- `--deadline-ms MS` exits with code 2 if the run hangs

## Run with JSON when you need it

Add `--json` for a stable machine shape. The fields match the text output: status, journal root, and steps. Use it in scripts and CI.

```bash
cargo run -p ledger-cli -- --json sim --seed 7 --runs 20
```

Exit codes are stable: `0` the command completed (a violation is in the output, not the exit code), `1` the command failed, `2` the deadline fired. See [CLI Reference](../guides/cli-reference.md).

## Read the output

A typical run prints one of two results:

```text
Simulation passed (20 runs evaluated, zero violations).
```

Or, if a run violates the oracle:

```text
Violation detected: read of k returned 100, expected 42
Journal root: eaddfb6021cf1e5cd814f60dda30ef9264ffee1a2fee92677698aaeaa2a370bd
Steps executed: 10
```

Each line means:

- `Violation detected` - the oracle saw a broken invariant and gives a short reason.
- `Journal root` - hex of the content-addressed DAG root for this run.
- `Steps executed` - how many scheduler steps ran before the check.

## Prove determinism

Run the same command again with the same seed:

```bash
cargo run -p ledger-cli -- sim --seed 7 --runs 20
cargo run -p ledger-cli -- sim --seed 7 --runs 20
```

Compare the two outputs. The journal root and steps match byte for byte. Same seed, same config, same inputs give the same journal. That is the core guarantee.

## Change the seed

Now change the seed:

```bash
cargo run -p ledger-cli -- sim --seed 8 --runs 20
```

You explore a different set of interleavings. The journal root and the set of violations can change, but each seed still replays identically.

Try a different policy to see how exploration changes:

```bash
cargo run -p ledger-cli -- sim --seed 7 --policy random --runs 20
cargo run -p ledger-cli -- sim --seed 7 --policy pct --priority-changes 4 --runs 20
```

`bandit` adapts as it learns. `random` picks uniformly. `pct` limits priority changes. Same seed under the same policy still gives the same journal.

## Troubleshoot

- No output or wrong flags: check `ledger sim --help`.
- Hang: add `--deadline-ms 5000` to fail fast with code 2 and a diagnostic.
- Need more detail: add `-v` for info, `-vv` for debug. Use `-q` to quiet.

## What to read next

- `finding-bugs-with-ldfi.md` - turn a violation into a ranked fault hypothesis.
- `replay-minimize.md` - replay a seed exactly and shrink it to a minimal schedule.
- `../guides/cli-reference.md` - full flag reference for every command.
