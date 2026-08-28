<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-lockup-dark.svg">
    <img src="docs/assets/logo-lockup-light.svg" alt="ldgr" width="280">
  </picture>

  <h1>Deterministic simulation testing for distributed systems</h1>

  <p><strong>Find concurrency failures. Replay controlled runs. Reduce them to portable test cases.</strong></p>

  <p>
    <a href="https://github.com/ldgr-rs/ldgr/actions/workflows/ci.yml"><img src="https://github.com/ldgr-rs/ldgr/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <a href="https://github.com/ldgr-rs/ldgr/actions/workflows/corpus-gate.yml"><img src="https://github.com/ldgr-rs/ldgr/actions/workflows/corpus-gate.yml/badge.svg" alt="corpus gate"></a>
    <a href="https://github.com/ldgr-rs/ldgr/actions/workflows/wasm-polyglot.yml"><img src="https://github.com/ldgr-rs/ldgr/actions/workflows/wasm-polyglot.yml/badge.svg" alt="Wasm polyglot"></a>
    <a href="https://github.com/ldgr-rs/ldgr/actions/workflows/format-conformance.yml"><img src="https://github.com/ldgr-rs/ldgr/actions/workflows/format-conformance.yml/badge.svg" alt="format conformance"></a>
    <a href="#license"><img src="https://img.shields.io/badge/license-Apache--2.0%20%2F%20AGPL--3.0-blue" alt="Apache 2.0 and AGPL 3.0 licenses"></a>
  </p>
</div>

ldgr puts concurrent code inside a controlled world. It explores schedules and
faults, checks your oracle, and records every effect in a causal journal. When a
run fails, you get deterministic evidence that you can replay, compare, and
minimize.

The contract is precise: the same build, run configuration, seed, and inputs
produce the same effect order and journal bytes. ldgr controls time, randomness,
scheduling, network, and storage through an explicit effects boundary.

## Try it

Rust 1.90 or newer is required. The repository pins Rust 1.97.1.

```sh
git clone https://github.com/ldgr-rs/ldgr
cd ldgr
cargo run -p ledger-cli -- sim --seed 0
```

This runs the intentionally faulty Mini-KV workload under many deterministic
schedules. Each run records a content-addressed journal and checks the key-value
history against an oracle.

<div align="center">
  <img src="docs/assets/demo.gif" alt="ldgr runs sim, repro, LDFI, and minimization against the Mini-KV workload" width="800">
</div>

The recording uses four CLI paths: `sim` finds a violation, `repro` records and
replays one configured run, `ldfi` derives and executes a fault hypothesis, and
`minimize` reduces the failing schedule. The shown `10 -> 1` reduction belongs
to this fixture; it is not a universal reduction guarantee.

## Why

Production concurrency bugs cost you twice. The first failure pages you. The
second failure is the attempt to reproduce an interleaving that depended on
wall-clock timing, host randomness, or thread scheduling.

ldgr replaces those ambient inputs with controlled effects. A failure becomes a
repeatable run with a journal root, not a log fragment that may never happen
again.

## Bugs travel as files

A `.ldgr` run manifest is a small canonical CBOR descriptor. It pins the format
version, root seed, scheduling policy, journal root, entry count, actor heads,
and extension fields. The manifest identifies a run; it does not contain the
complete journal history inline.

The repository contains 16 deterministic corpus manifests. Each is 190 to 260
bytes:

```sh
$ wc -c corpora/bug-corpus-v1/mini-kv-stale-read.ldgr
225 corpora/bug-corpus-v1/mini-kv-stale-read.ldgr
```

Check that a manifest uses canonical RFC 8949 deterministic CBOR:

```sh
$ cargo run -p ledger-cli -- format \
    corpora/bug-corpus-v1/mini-kv-stale-read.ldgr --check
[ok] corpora/bug-corpus-v1/mini-kv-stale-read.ldgr: canonical
```

`format --check` validates encoding. Replay also needs the compatible workload,
build, run configuration, and referenced journal material. Rust and an in-repo
Go fixture encoder produce byte-identical CBOR across the conformance corpus.

The roadmap includes **ldgrhub**, a public registry for findings and their
referenced journals. It is not shipped today. See the [roadmap](ROADMAP.md).

## Continue the workflow

```sh
cargo run -p ledger-cli -- repro --seed 0
cargo run -p ledger-cli -- minimize --seed 0 --runs 256
cargo run -p ledger-cli -- ldfi --seed 0 --attempts 64
cargo run -p ledger-cli -- --json sim --seed 0
```

`repro` executes a run, replays its recorded decisions, and compares journal
roots. `minimize` uses schedule delta debugging. `ldfi` reasons backward from a
violation and executes its top fault hypothesis. Use `cert verify <FILE>` to
verify an existing campaign certificate.

See [Getting started](docs/getting-started.md) for setup and the
[CLI reference](docs/guides/cli-reference.md) for every command and flag.

## What you get

- **Controlled deterministic execution.** Virtual time, seeded random streams,
  cooperative scheduling, SimNet, and SimFs replace ambient host effects.
- **A causal journal.** Each effect records its causal parents, vector clock,
  actor sequence, and payload in a content-addressed DAG.
- **Schedule and fault exploration.** Random, PCT, bandit, replay, and bounded single-base DPOR
  paths explore interleavings. LDFI uses journal lineage to rank fault cuts.
- **Focused counterexamples.** Causal slicing and delta debugging produce a
  1-minimal result for the tested candidate set. This is not a claim of the
  globally smallest possible reproduction.
- **Bounded certificate validation.** Campaigns can carry unsigned in-toto
  statements with recorded solver data. Statement validation enforces schema
  and size bounds. Journal binding checks the subject root and confirms that
  recorded cut members are faultable entries in the supplied journal.
- **Native and Wasm paths.** Differential tests compare covered native and
  `wasm32-wasip1` workloads by output bytes and journal root.
- **A determinism tripwire.** `ledger-lint` makes forbidden ambient APIs a CI
  failure on simulation paths.
- **A deterministic corpus.** Twelve reproduced fixtures and four synthetic
  cloud scenarios cover consensus, crash-consistency, and infrastructure fault
  classes.

## Evidence

The repository keeps claims next to executable checks:

| Claim | Evidence and scope |
| --- | --- |
| Determinism | The [self-check](crates/ledger-sim/tests/self_check.rs) runs one workload 10,000 times with the same build and seed, then compares journal roots. The [corpus gate](.github/workflows/corpus-gate.yml) runs it in release mode. |
| Million-entry minimization | The [minimization gate](crates/ledger-explorer/tests/minimize_gate.rs) requires at least 1 million entries, preserves the violation, and requires at least 90 percent reduction for that fixture. |
| Corpus reproduction | The [v2 corpus gate](crates/ledger-explorer/tests/corpus_v2_gate.rs) exercises 16 pinned scenarios and requires LDFI reproduction across all three scenario classes. |
| LDFI efficiency | The [efficiency gate](crates/ledger-explorer/tests/ldfi_efficiency.rs) reports every leg. Its 5x floor applies to sparse legs and the combined fixture set, not the corpus-only aggregate. |
| Native/Wasm parity | The [differential suite](crates/ledger-sim/tests/wasm_differential.rs) compares output and journal roots for covered workloads. |
| Canonical format | The [format workflow](.github/workflows/format-conformance.yml) runs Rust validation and an in-repo Go encoder over the same golden fixtures. |
| Performance | Criterion sources record targets and methodology for [journal storage](crates/ledger-journal/benches/storage.rs), [simulation throughput](crates/ledger-sim/benches/sim_throughput.rs), and [solver scaling](crates/ledger-explorer/benches/solver_scaling.rs). CI compiles all benches; only explicit release gates enforce rates or budgets. |

These checks cover defined fixtures and boundaries. They are evidence, not a
claim that every workload has the same performance or reduction ratio.

## How it compares

| | Replay model | Fault injection | Reduction | Self-hosted |
| --- | --- | --- | --- | --- |
| Property testing (`proptest`, Hypothesis) | Inputs | No | Inputs | Yes |
| MadSim | Tokio-compatible simulation | Random | Manual | Yes |
| Jepsen | Real clusters | Nemeses | System-specific analysis | Yes |
| Antithesis | Deterministic hypervisor | Yes | Automated | No |
| **ldgr** | Controlled effects and causal journal | Random and lineage-driven | Schedule and journal reduction, fault-cut evidence | Yes |

These tools test different boundaries. Property testing is usually enough for
pure deterministic functions. Jepsen and hypervisor systems exercise wider real
system surfaces. ldgr is for code that can run behind its effects boundary and
needs local, inspectable causal evidence.

## How it fits together

```text
SUT or Wasm guest
        |
        v
controlled effects boundary
        |
        v
ledger-sim -> ledger-journal -> ledger-explorer
                                  |
                                  v
                      replay, LDFI, minimization
```

`ledger-cli` is the local composition root. `ldgr-rt` is the Apache-2.0 porting
facade. `ledger-worker` runs campaigns over UDS or gRPC. `ledger-adapters`
converts OpenTelemetry spans into lineage-only journals; OTel ingest does not
carry deterministic replay or certificate claims.

See [Architecture](docs/architecture.md) for crate boundaries and the full
determinism contract.

## Current limits

- Simulation code must use the effects boundary. Arbitrary external processes,
  OS threads, real hardware, unsupported syscalls, and unsimulated FFI remain
  outside the controlled model.
- The current Wasm target is `wasm32-wasip1`. Filesystem virtualization uses
  WASI Preview 1.
- Cross-build solver changes can select different fault cuts with equal minimum
  cost. Seed-only corpus roots and same-build replay retain their stated
  invariants.
- OpenTelemetry ingest gives approximate lineage only. It does not provide
  deterministic replay or certificates.
- Current certificates are unsigned. Wave 1 validates bounded statements and
  binds recorded solver data to a supplied journal. It does not derive stronger
  causal claims from journal parent paths. Signing and tenant keys remain
  roadmap work.

## The name and mark

ldgr is "ledger" without the vowels, the way you might write it beside an
architecture diagram. The mark is a four-node causal diamond: one seed forks to
two concurrent effects, then converges into a journal root.

## Development gates

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --all-features --profile ci
cargo test --workspace --doc
cargo run -p ledger-lint -- crates/
cargo run -p xtask -- licenses
```

Wasm work also needs:

```sh
cargo build --target wasm32-wasip1 -p wasm-guest
```

## Status

The journal, native simulator, `wasm32-wasip1` backend, LDFI, minimization,
corpus gates, OTel ingest, worker transports, and CLI paths above exist today.
The evidence currently comes from repository fixtures and synthetic workloads.
The repository does not yet document a finding in an external production
system.

See the [documentation index](docs/index.md) and [roadmap](ROADMAP.md) for the
current surface and planned work. If a claim here drifts from the executable
checks, treat this file as wrong and open an issue.

## License

| Layer | Crates | License |
| --- | --- | --- |
| Contracts and codecs | `ledger-format`, `ledger-journal`, `wasm-guest` | MIT OR Apache-2.0 |
| Engine | `ledger-sim`, `ledger-explorer` | AGPL-3.0-or-later; commercial license available |
| Tooling | CLI, worker, adapters, rt, lint, flow, faultspec | Apache-2.0 |

Embed the contracts freely. Use the engine under the AGPL, including for
commercial work. If AGPL section 13 does not fit your deployment, ask about the
commercial license. See [CONTRIBUTING.md](CONTRIBUTING.md) and the license files.
`xtask licenses` enforces the split in CI.

## Trademark

The name ldgr and the project branding are trademarks of the ldgr maintainers.
See [NOTICE](NOTICE). Forks are welcome under the licenses above; please rename
yours.

## Contributing

Issues and pull requests are welcome. Start with
[CONTRIBUTING.md](CONTRIBUTING.md). Engine contributions carry a DCO sign-off
plus the inbound grant that keeps dual licensing possible.
