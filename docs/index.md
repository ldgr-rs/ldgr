# ldgr Documentation

ldgr is an open, self-hostable deterministic simulation testing engine in Rust. It journals simulated effects in a content-addressed causal DAG. Same build, seed, config and inputs produce a byte-identical journal. It helps you find and shrink concurrency and distributed-systems bugs through schedule exploration, lineage-driven fault injection, deterministic replay and counterexample minimization.

This site is the user-facing docs. It explains how to use ldgr, not how ldgr is built inside.

## Navigation

### Learn

| Page | What you find |
| --- | --- |
| [Getting Started](getting-started.md) | Install ldgr and run your first simulation |
| [Concepts](concepts.md) | Mental model for deterministic simulation, journals and fault injection |
| [First Simulation](tutorials/first-simulation.md) | Step-by-step tutorial for your first campaign |
| [Finding Bugs with LDFI](tutorials/finding-bugs-with-ldfi.md) | Tutorial for fault injection driven bug finding |
| [Replay and Minimize](tutorials/replay-minimize.md) | Tutorial for replay and shrinking a counterexample |

### How-to

| Page | What you find |
| --- | --- |
| [CLI Reference](guides/cli-reference.md) | Every ledger command, flag and exit code |
| [Workloads](guides/workloads.md) | How to describe a workload for simulation |
| [Fault Specs](guides/fault-specs.md) | How to write failure-spec scenarios |
| [Oracles](guides/oracles.md) | How to write an oracle that decides pass or fail |
| [CI Integration](guides/ci-integration.md) | How to run ldgr in CI |
| [Environment Variables](guides/environment-variables.md) | Every env var ldgr reads |

### Understand

| Page | What you find |
| --- | --- |
| [Architecture](architecture.md) | High-level crate layout and the determinism boundary |
| [Security](security.md) | Threat model and reporting |
| [FAQ](faq.md) | Common questions and answers |
| [Roadmap](../ROADMAP.md) | What ships today and what comes next |

## Where to start

New to ldgr? Read [Getting Started](getting-started.md), then [Concepts](concepts.md). If you want to jump to commands, see [CLI Reference](guides/cli-reference.md).

Source code lives at the repository root. Run `cargo run -p ledger-cli -- --help` for the current help text on your build.
