# ldgr (Ledger)

`ldgr` is the open, self-hostable deterministic simulation testing (DST)
engine described in `docs/`. It unifies:

- a content-addressed causal DAG journal (`crates/ledger-journal`,
  `crates/ledger-format`);
- a controlled single-threaded cooperative execution environment
  (`crates/ledger-sim`);
- backward lineage-driven search: LDFI, schedule-space exploration,
  generation, and minimization (`crates/ledger-explorer`);
- durable-execution step logging over the journal (`crates/ledger-flow`);
- a failure-scenario DSL with a canonical fault library
  (`crates/ledger-faultspec`);
- OTel span ingest into journal envelopes (`crates/ledger-adapters`);
- a campaign task-execution daemon speaking the worker/control-plane contract
  over UDS/gRPC (`crates/ledger-worker`);
- the Apache-2.0 SUT porting facade (`crates/ldgr-rt`);
- the deterministic Wasm guest (`crates/wasm-guest`);
- a static scanner for forbidden ambient APIs (`crates/ledger-lint`);
- the unified `ledger` CLI (`crates/ledger-cli`).

The format, journal, and Wasm guest crates (`ledger-format`, `ledger-journal`,
`wasm-guest`) are MIT OR Apache-2.0. The engine crates
(`ledger-sim`, `ledger-explorer`) are AGPL-3.0-or-later: anyone may use, modify,
and redistribute them, and section 13 keeps hosted services source-disclosing.
Teams that must link or embed the engine without AGPL obligations can buy a
commercial license. `ldgr-rt` and the remaining tooling crates are Apache-2.0.
and the crate LICENSE files.

## Build and test

```sh
cargo check --workspace --all-targets
cargo nextest run --workspace --all-features   # requires cargo-nextest
cargo test --workspace --doc                   # doctests
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo bench -p ledger-journal --bench storage  # criterion benchmarks
cargo run -p xtask -- licenses               # license split gate
cargo build --target wasm32-wasip1 -p wasm-guest  # build guest before wasm tests
```

## Simulate the mini-KV stale-read campaign

```sh
cargo run -p ledger-cli -- sim
```

The CLI supports `sim`, `repro`, `minimize`, `diff`, `doctor`, `init`,
`format`, `ldfi`, `faults`, `completions`, `ingest`, `cert`, `coverage`, and
`scaffold`, plus a hidden `rt-server` used by the ldgr-rt facade over IPC. Pass
`--json` anywhere in argv for JSON output; repeat `-v` for more detail.

The reference workloads live in `crates/ledger-explorer/examples/`
(`minikv`, `two_phase_commit`) and the corpus tests in
`crates/ledger-explorer/tests/`.

## Determinism rules

Never read the ambient wall clock, invoke ambient random generators, spawn OS
threads, or perform raw file/network I/O inside a simulation. Route all such
effects through `Effects` (virtual time, seeded RNG streams, simulated
network, simulated file system). `ledger-lint` enforces this at compile time.
