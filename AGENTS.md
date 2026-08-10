# AGENTS.md

`ldgr` (Ledger) is an open, self-hostable deterministic simulation testing (DST) engine in Rust. It journals every simulated effect into a content-addressed causal DAG and uses that journal to drive schedule exploration, lineage-driven fault injection (LDFI), and minimization.

Toolchain: Rust edition 2024, MSRV 1.90, pinned channel 1.97 (`rust-toolchain.toml`).

## Orientation

The `docs/` tree is the source of truth. Update it in the same change that updates behavior.

## Commands

Run from the workspace root. The test suite needs `cargo-nextest` (`cargo install cargo-nextest`).

| Task | Command |
| :--- | :--- |
| Check | `cargo check --workspace --all-targets` |
| Test | `cargo nextest run --workspace --all-features` |
| One test | `cargo nextest run -p <crate> --test <file> --all-features` |
| Doctests | `cargo test --workspace --doc` |
| Lint | `cargo clippy --workspace --all-targets --all-features -- -D warnings` |
| Format | `cargo fmt --all -- --check` (fix: `cargo fmt --all`) |
| Benchmarks | `cargo bench -p ledger-journal --bench storage` (nextest does not run benches) |
| Licenses | `cargo run -p xtask -- licenses` |
| Lint-rules gate | `cargo run -p ledger-lint -- crates/` |
| Run CLI | `cargo run -p ledger-cli -- sim` |

Wasm prerequisites: build the guest before any wasm test (`cargo build --target wasm32-wasip1 -p wasm-guest`), and pass `--features backend-wasm` for the wasm test binaries. Do not run `cargo fmt --all` while another agent edits a different crate concurrently; use `cargo fmt -p <crate>` instead.

## Workspace

| Crate | Role |
| :--- | :--- |
| `ledger-format` | Canonical RFC 8949 CBOR codec, entry kinds, BLAKE3 hashing. `no_std`, `std` feature. |
| `ledger-journal` | Causal DAG, vector clocks, segment store, snapshots, retention tiers. `no_std`, `std` feature (storage gated). |
| `ledger-sim` | Effects boundary, virtual time, SimNet, SimFs, scheduler, seed tree, Wasm backend. |
| `ledger-lint` | Static scanner for forbidden ambient APIs. |
| `ledger-explorer` | Oracles, LDFI, minimizer, campaign search, reference sims. |
| `ledger-flow` | Durable-execution step logging over the journal. |
| `ledger-cli` | The `ledger` command-line application. |
| `wasm-guest` | The deterministic Wasm guest (`wasm32-wasip1`). |
| `xtask` | License and repo checks. |

Tests live under `crates/<crate>/tests/`. Corpora live under `corpora/` (`planted-leaks/`, `bug-corpus-v1/`).

## Determinism rules (non-negotiable)

Code that runs inside a simulation must not touch the ambient host:

1. Never read the ambient wall clock (`std::time::Instant::now()`, `std::time::SystemTime::now()`). Use `VirtualTime` or `Effects::clock().now()`.
2. Never invoke ambient randomness (`rand::thread_rng()`, `getrandom`). Draw from `SeedTree` streams or `Effects::rng(stream)`.
3. Never spawn OS threads (`std::thread::spawn`). Use cooperative tasks via `Simulation::with_tasks` or `Effects::spawn()`.
4. Never do raw file I/O (`std::fs`). Route it through `SimFs`.
5. Never do raw network I/O (`std::net`). Route it through `SimNet`.

`ledger-lint` enforces these statically. `// ledger-lint:allow` exempts a file, or a pattern via `// ledger-lint:allow:<SUB>`. The `TokioBackend` production passthrough is the one deliberate exception and is allow-marked.

A deterministic run must be byte-identical when repeated with the same seed: same journal root, same decisions, same output. Executor-parity goldens and the 10^4-run self-check gate this.

## Code style

- Run `cargo fmt --all` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` before declaring work done. Zero warnings.
- No `unwrap()` or `expect()` in production library paths. Propagate with `?`. Tests may use them.
- Typed errors: `Result<T, E>` with explicit error enums (thiserror in the workspace). Do not swallow errors with `let _ =` unless the discard is intentional and commented.
- Prefer borrowing over `.clone()`; `&str` over `String`, `&[T]` over `Vec<T>` in parameters.
- Encode invariants in types. Library crates carry `#![deny(unsafe_code)]`; `unsafe` is limited to `wasm-guest`'s wasm32 extern imports.
- `ledger-format` and `ledger-journal` stay `no_std`-compatible. Gate std-only code (storage, I/O) behind the `std` feature and verify `cargo check -p <crate> --no-default-features`.
- Keep public APIs backward compatible. A wire-format, entry-kind, or hash change is breaking and bumps the format version.
- No dead code, unused imports, or `TODO` without a tracked issue.
- Design principles: correctness before safety before maintainability before performance. Make illegal states unrepresentable. Validate input at every boundary. Add an abstraction only once there are two concrete cases.

## Comments

- Explain why, not what. Delete comments that restate the code.
- Short, active, plain English.
- Doc comments on public items: one short purpose line, then non-obvious `# Errors`, `# Panics`, or invariants. Prose, not bullet restatements.
- Preserve `// ledger-lint:allow` markers and code blocks inside doc comments (they are doctests).

## Testing

- Every change ships with tests. New public behavior needs a unit test; cross-crate behavior needs an integration test in the owning crate's `tests/`.
- Use property tests (proptest) for encoding, hashing, and merge/order laws.
- Tests are deterministic by construction: no wall time, ambient entropy, or thread scheduling.
- Run the evidence gates before finishing: `cargo test -p ledger-sim --test self_check --release` (10^4-run determinism); `cargo test -p ledger-explorer --test minimize_gate --release` (minimize >= 90%); `cargo test -p ledger-explorer --test corpus_v1_gate` (bit-exact corpus); `cargo test -p ledger-sim --features backend-wasm --test wasm_differential --test wasm_corpus_bug` (Wasm parity and corpus bug).

## Git workflow

- Conventional Commits: `feat:`, `fix:`, `refactor:`, `chore:`, `docs:`, `test:`. Example: `feat: add LDFI fault execution and replay semantics`.
- One logical change per commit or PR. Keep PRs small.
- Do not commit unless the user asks. Never commit secrets or generated artifacts (`target/` is ignored).

## Boundaries

- **Always**: run `cargo fmt --check`, clippy, and the affected tests before declaring a task complete; follow the determinism rules; update `docs/` in the same change when behavior changes; add tests for new behavior.
- **Ask first**: adding a dependency; changing `.github/` workflows; changing a wire format, entry kind, or hash; changing a public API; touching the license split or the `Cargo.toml` feature surface.
- **Never**: commit secrets; add ambient time, entropy, threads, fs, or net to simulation code; edit `target/`; reference plan artifacts in code comments.

## Responsibilities

- **User Responsibility**: for any changes the user makes to the codebase, including but not limited to adding new features, fixing bugs, and refactoring code, as well as any other changes that are necessary to maintain the codebase, the user is responsible for committing those changes and ensuring that they are properly reviewed.
