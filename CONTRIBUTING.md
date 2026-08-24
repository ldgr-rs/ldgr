# Contributing to ldgr

Thank you for your interest in `ldgr`. Contributions of all kinds are welcome: bug reports, documentation, tests, reference simulations, and code. This guide explains how to get started and what we expect from pull requests.

## Table of contents

- [Code of conduct](#code-of-conduct)
- [Ways to contribute](#ways-to-contribute)
- [Development setup](#development-setup)
- [Project structure](#project-structure)
- [A note on determinism](#a-note-on-determinism)
- [Workflow](#workflow)
- [Pull request checklist](#pull-request-checklist)
- [Code review](#code-review)
- [Style guide](#style-guide)
- [Recognition](#recognition)
- [License](#license)

## Code of conduct

Be respectful and constructive. We welcome contributors of all experience levels and backgrounds. Harassment, personal attacks, and aggressive language are not acceptable. The full standards and enforcement process are in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md); by participating you agree to uphold them.

## Ways to contribute

- **Report a bug.** Before opening an issue, search the existing issues for a duplicate. Include the `ledger` version or commit, the command you ran, the expected result, and the actual result. Attach a reproduction if you have one.
- **Suggest a feature.** Open an issue that states the problem you are trying to solve and a sketch of the solution. We prefer small, focused proposals over large redesigns.
- **Improve documentation.** Fixing typos, clarifying confusing sections, and adding examples are always appreciated.
- **Add tests or reference simulations.** The corpus of protocol-faithful mini simulations (ZAB, HDFS lease, Cassandra gossip) is a living part of the test suite.
- **Review pull requests.** Feedback from fresh eyes is valuable, even without deep domain knowledge.

## Development setup

Prerequisites:

- Rust 1.97.1 via `rustup`. The repo pins the channel in `rust-toolchain.toml`, so `rustup` selects it automatically.
- `cargo-nextest` for the test suite: `cargo install cargo-nextest`.
- The `wasm32-wasip1` target for the Wasm track: `rustup target add wasm32-wasip1`.

Build and test:

```sh
cargo check --workspace --all-targets
cargo nextest run --workspace --all-features
cargo test --workspace --doc
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

Before running the Wasm tests, build the guest:

```sh
cargo build --target wasm32-wasip1 -p wasm-guest
```

## Project structure

| Directory | Purpose |
| :--- | :--- |
| `crates/ledger-format` | Canonical CBOR codec, entry types, hashing. |
| `crates/ledger-journal` | Causal DAG, vector clocks, segments, snapshots. |
| `crates/ledger-sim` | The deterministic simulation runtime and Effects boundary. |
| `crates/ledger-lint` | Static scanner for forbidden ambient APIs. |
| `crates/ledger-explorer` | Search, LDFI, minimization, oracles, reference sims. |
| `crates/ledger-flow` | Durable-execution step logging. |
| `crates/ledger-cli` | The `ledger` command-line tool. |
| `docs/` | The design and verification documents (source of truth). |
| `corpora/` | Planted-leak and bug-corpus fixtures. |

## A note on determinism

`ldgr` is a deterministic simulation engine. Code that runs inside a simulation must never read the ambient wall clock, ambient randomness, OS threads, the real filesystem, or the real network. Every one of those sources breaks reproducibility, which is the entire point of the project. The determinism rules are listed in `AGENTS.md`; `ledger-lint` enforces them automatically.

When you add code to a crate that runs under simulation, follow those rules and make sure your tests are deterministic too. A test that depends on wall time or scheduling order will not pass review.

## Workflow

1. **Open an issue first** for anything larger than a small fix. We would rather spend five minutes aligning on direction than reject a week of work. Bug fixes and doc typos can go straight to a pull request.
2. **Fork** the repository and clone your fork. Add the upstream remote.
3. **Create a topic branch** from `main`, named `type/short-description` (for example `fix/segments-manifest` or `feat/wasm-replay`).
4. **Make your change**, keeping it focused on one problem. Add or update tests.
5. **Run the gates** listed in the pull request checklist below.
6. **Push** and open a pull request against `main`. If it is work in progress, open it as a draft.

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
feat: add LDFI fault execution and replay semantics

Explain what and why in the body when it is not obvious.
```

Common types: `feat`, `fix`, `refactor`, `chore`, `docs`, `test`.

## Pull request checklist

Before opening a pull request, verify:

- [ ] `cargo fmt --all -- --check` passes.
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes with zero warnings.
- [ ] `cargo nextest run --workspace --all-features` passes.
- [ ] New or changed behavior has tests, and the tests are deterministic.
- [ ] Documentation (`docs/` or the relevant doc comments) is updated in the same change.
- [ ] The change does not touch the wire format, entry kinds, or hashes without a deliberate format-version bump.
- [ ] The change is scoped to one problem.

## Code review

We aim to respond to pull requests within about a week. Review focuses on correctness first, then safety and determinism, then maintainability:

- Does the code preserve the determinism guarantees?
- Are all error paths handled explicitly?
- Do the tests cover the new behavior, including the failure modes?
- Would a new contributor understand the change in one read?

If a review asks for changes, push the updates to the same branch. When the conversation settles and CI is green, a maintainer merges.

## Style guide

- Rust edition 2024, formatted with `rustfmt` (run `cargo fmt --all`).
- No `unwrap()` or `expect()` in production library code; propagate errors with `?`.
- Typed errors over strings: define error enums, use `thiserror` where it helps.
- Comments explain why, not what. The full comment style is in `AGENTS.md`.
- Keep public APIs backward compatible.

## Recognition

Every accepted contribution is credited. Contributors are thanked in pull request threads and appear in release notes. Small contributions count: tests, docs, and reproductions all matter.

## License

The workspace uses a per-crate license split: the engine crates (`ledger-sim`,
`ledger-explorer`) are AGPL-3.0-or-later, the format and journal crates are
MIT OR Apache-2.0, and the remaining tooling is Apache-2.0. See
[LICENSE](LICENSE), [LICENSE-AGPL-3.0](LICENSE-AGPL-3.0),
[LICENSE-MIT](LICENSE-MIT), and [LICENSE-APACHE](LICENSE-APACHE), plus the
`license` field in each crate's `Cargo.toml`. `cargo run -p xtask -- licenses`
enforces the split in CI, and also enforces the license-boundary architecture:
only declared composition roots may import AGPL engine code, library edges to
the engine must be optional features, and codec crates are pinned to the
contract layers.

The engine is dual-licensed: AGPL-3.0-or-later for open use, and a paid
commercial license for teams that must link or embed the engine without AGPL
obligations. To make that possible the project needs copyright control over
engine contributions. By contributing you agree to the Developer Certificate
of Origin, and you grant the project a perpetual, worldwide, royalty-free
license to redistribute your contribution under the license of the crate it
lands in and to sublicense it under the commercial engine license. You retain
copyright in your own work. This mirrors the inbound-license (CLA) model used
by AGPL projects that dual-license commercially.
