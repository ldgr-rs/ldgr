# Architecture

This document describes how ldgr fits together at a user level.

## Crate layout

The workspace points inward toward the journal and format layers. The
direction is the dependency direction.

```text
ledger-format -> ledger-journal -> ledger-sim -> ledger-explorer -> ledger-cli
       |               |               |                  |
       |               |               |                  +-> ledger-worker
       |               |               +-> ledger-faultspec, ledger-flow, ledger-adapters
       +-> ledger-lint, ldgr-rt, wasm-guest, xtask
```

A second view shows how a system under test connects:

```text
 your SUT --> ldgr-rt (Apache facade) --> effects boundary
   wasm guest ------------------------------'      |
                                                 v
        faultspec (scenarios) --> ledger-sim (simulated world)
                                       | journals effects
                                       v
                             ledger-journal (causal DAG)
                                       | evidence
                                       v
               ledger-explorer (search, LDFI, minimizer, certificates)

 ledger-cli ties it together; ledger-worker runs campaigns over UDS or gRPC;
 ledger-adapters turns OpenTelemetry spans into journal envelopes.
```

| Crate | Role in one line |
| --- | --- |
| `ledger-format` | Canonical CBOR, entry types, hashes, and the `.ldgr` framing |
| `ledger-journal` | Causal DAG, vector clocks, segments, and persistence |
| `ledger-sim` | Effects boundary, scheduler, virtual time, SimNet, SimFs, and backends |
| `ledger-explorer` | Search, LDFI, minimization, and certificates |
| `ledger-cli` | The `ledger` binary that wires the crates together |
| `ledger-worker` | Queue draining, task execution, and artifact publication |
| `ledger-faultspec` | Failure-spec DSL, its parser, and scenario library |
| `ledger-flow` | Step logging over the journal for durable execution |
| `ledger-adapters` | OTel span ingest into journal envelopes |
| `ldgr-rt` | Porting facade for systems under test and the IPC boundary |
| `rt-server` | AGPL runtime engine server backing SUT IPC transports |
| `ledger-lint` | Static check that simulation paths avoid ambient APIs |
| `wasm-guest` | Deterministic `wasm32-wasip1` guest example |
| `xtask` | Workspace automation: license boundary and environment doctor |

`ledger-cli` is the composition root. Use explicit `-p` or `--workspace`
flags for checks. Do not infer workspace state from a bare `cargo test`.

The license split follows the same layers: contracts and codecs are
MIT OR Apache-2.0, the engine is AGPL-3.0-or-later, and tooling is
Apache-2.0. See the license table in the README.

## The determinism contract

A simulation must produce the same bytes from the same inputs. Same build,
same seed, same configuration, and same workload produce the same effect
order, the same journal entries, and the same output. The engine upholds this
by requiring simulation code to use the effects boundary.

As a user, you follow five rules inside simulation code:

1. Use `VirtualTime` or `Effects::clock().now()`. Never read the ambient wall clock.
2. Use `SeedTree` or `Effects::rng(stream)`. Never call ambient random or OS entropy.
3. Use cooperative tasks through the simulation executor. Never spawn OS threads.
4. Use `SimFs`. Never touch the raw filesystem.
5. Use `SimNet`. Never touch raw sockets.

Host-side code - the CLI, the worker, adapters, and explicit sentinels - may
use host facilities at a clear boundary. That code stays out of the
simulation path.

`ledger-lint` enforces the contract. Run it over simulation paths:

```bash
cargo run -p ledger-lint -- crates/ledger-sim crates/wasm-guest
```

The scanner reports any ambient API that slipped in. Keep explicit
`// ledger-lint:allow` markers only where the boundary is intentional and
reviewed. Never add a marker to hide a leak. Fix the boundary instead.

## The `.ldgr` artifact

A `.ldgr` run manifest is a canonical CBOR descriptor. It pins the format
version, root seed, policy tag, journal root, entry count, actor heads, and
extension fields. It does not contain the complete journal history inline.
A portable finding consists of the manifest plus its referenced journal
material and compatible workload build.

Inspect a manifest:

```bash
ledger format corpora/bug-corpus-v1/mini-kv-stale-read.ldgr --check
```

The check validates canonical deterministic CBOR encoding. It does not replay
the run.

## Replay and minimization

`ledger repro` executes the built-in workload for a seed, replays its recorded
decisions, and compares journal roots. `ledger minimize` searches for a failing
run and applies schedule delta debugging. Its result is 1-minimal over the
tested candidate set, not necessarily the globally smallest possible schedule.

Both rely on the same guarantee: the same build, configuration, seed, and
inputs produce the same controlled effect order and journal bytes. If two such
runs disagree on a journal root, the controlled execution path has drifted.

## Builds and checks

Build the CLI from source:

```bash
cargo run -p ledger-cli -- --help
cargo run -p ledger-cli -- sim --help
```

Common checks before you push:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --all-features
```

For Wasm guests, build the guest first:

```bash
cargo build --target wasm32-wasip1 -p wasm-guest
```
