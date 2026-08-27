# FAQ

## How is this different from a normal test suite?

A normal test runs your code once on the real environment. ldgr runs your system many times against a simulated world with different interleavings and faults, journals every effect and checks an oracle after each run. When it finds a bug, it hands you a replayable artifact.

## Why does deterministic replay matter?

It makes a controlled failure repeatable. With the same build, configuration, seed, and inputs, replay checks the same decisions and journal bytes. After a fix, you can run the same case and compare the resulting root and verdict. A different build or configuration can produce a different result.

## Can I test my real network code?

No, not directly. Simulation code must not reach for real sockets, real clocks, real randomness or real disk. You port the effectful parts to the effects boundary - virtual time, seeded random streams, SimNet and SimFs. See [Architecture](architecture.md) for the boundary rules. Host-side tooling, adapters and the worker can use real I/O.

## What happens when a run hangs?

Use the global flag `--deadline-ms`. It sets a wall-clock budget for the whole command.

```bash
ledger --deadline-ms 5000 sim --seed 42 --runs 100
```

If the command exceeds the budget, it prints a diagnostic and exits with code 2. A livelocked or deadlocked simulation also surfaces as a finding with a liveness reason, so you can minimize and replay it like any other violation.

## What do exit codes mean?

* `0` - the command completed. A campaign that found a violation also exits 0; the violation is in the output, not the exit code.
* `1` - the command failed: bad usage, unreadable input, a journal error, or `format --check` rejected a file.
* `2` - deadline exceeded. The `--deadline-ms` watchdog fired.

To fail a CI job on a finding, parse the output: `"status":"violation"` with `--json` or `--ndjson`, or the line `Violation detected` in plain output. See [CI Integration](guides/ci-integration.md).

## Is this a fuzzer?

The campaign loop is a schedule and fault fuzzer over deterministic executions. Each attempt picks a derived seed, runs the workload under a different schedule, and checks the oracle. Under a fixed build and configuration, counterexamples replay byte-identically. Schedule minimization produces a 1-minimal result over the tested candidates. The project calls this deterministic simulation testing because it ranges over schedules and faults, not only bytes.

## Does it work with async Rust and tokio?

Yes. The engine ships a tokio backend for virtual time and seeded scheduling, and there is a `wasm32-wasip1` guest path for Wasm. Keep the boundary rules and the cooperative scheduler in mind; port async code to use the simulated effects.

## What languages can I use?

The engine is Rust. Guests can be polyglot via `wasm32-wasip1` - any language that can target that wasm profile can run as a guest. The CLI, worker and adapters are Rust as well.

## How do I choose a scheduling policy?

Policies are the `--policy` values on `sim`, `repro` and `minimize`: `random`, `bandit`, `pct` and `replay`. Start with the default (`bandit` for campaigns, `random` for replay). `replay` follows a recorded decision list; `pct` and `bandit` add guided exploration.

## How do I cite or compare this to other tools?

ldgr journals effects in a causal DAG, uses lineage to target fault hypotheses, and minimizes schedules. Campaigns can carry verifiable fault-cut evidence. Property testing usually shrinks inputs; ldgr also shrinks controlled schedules. Real-cluster tools exercise wider deployment surfaces. ldgr exercises code behind its effects boundary and provides inspectable journal roots.

## What is the license?

Three license layers, on purpose:

* Contracts and codecs - `ledger-format`, `ledger-journal`, `wasm-guest`: MIT OR Apache-2.0. Embed them freely.
* Engine - `ledger-sim`, `ledger-explorer`: AGPL-3.0-or-later, with a commercial license available.
* Tooling - CLI, worker, adapters, rt, lint, flow, faultspec: Apache-2.0.

`xtask licenses` enforces the split in CI. See the license table in the README and the `LICENSE`, `LICENSE-MIT`, `LICENSE-APACHE`, and `LICENSE-AGPL-3.0` files at the repo root for the current text.

## How do I report a security issue?

See [Security](security.md) for the private contact and what to include.

## How do I contribute?

See `CONTRIBUTING.md` at the repo root, then open an issue or a pull request. Keep simulation code on the effects boundary and run `cargo run -p ledger-lint -- crates/` before you push.
