# AGENTS.md

## Scope and project purpose

These instructions apply to the `ldgr` workspace. There are no narrower
`AGENTS.md` files in the current tree. A future nested file may narrow these
rules, but it may not weaken determinism, safety, security, format, or
validation requirements.

`ldgr` is an open, self-hostable deterministic simulation testing engine in
Rust. It journals simulated effects in a content-addressed causal DAG and uses
that journal for schedule exploration, lineage-driven fault injection (LDFI),
replay, and minimization.

The project uses Rust edition 2024. Its MSRV is 1.90. Development and CI use
Rust 1.97.1, pinned in `rust-toolchain.toml`.

## Source of truth and repository state

- `Cargo.toml` is the workspace and dependency source of truth.
- `rust-toolchain.toml` is the toolchain and target source of truth.
- `README.md` is the user-facing entry point.
- `docs/` contains the design source of truth.
- `crates/ledger-format/proto/ledger/control/v1/control.proto` is the source
  of truth for the control-plane wire contract.
- `corpora/` contains planted ambient-API leaks and deterministic bug fixtures.

Start work with:

```sh
git status --short --branch
git diff --stat
find . -name AGENTS.md -print
```

The worktree may contain user-owned or uncommitted changes. Preserve them.
Read affected files and diffs before editing. Never use destructive commands
such as `git reset --hard`, `git checkout --`, `git clean`, or broad
recursive deletion unless the user requests that exact operation. Do not
commit, amend, push, or create a branch unless the user asks.

## Workspace architecture

The dependency direction is inward toward the format and journal layers:

```text
ledger-format -> ledger-journal -> ledger-sim -> ledger-explorer -> ledger-cli
       |              |              |              |
       |              |              |              +-> ledger-worker
       |              |              +-> ledger-flow, ledger-adapters
       +-> ledger-faultspec, ledger-lint, ldgr-rt, wasm-guest, xtask
```

Use manifests and `cargo tree` to confirm this diagram when the workspace
changes. The main crate roles are:

| Crate or path | Role |
| --- | --- |
| `ledger-format` | `no_std` canonical CBOR, entries, hashes, manifests, and protocol source |
| `ledger-journal` | Causal DAG, vector clocks, persistence, segments, snapshots, and retention |
| `ledger-sim` | Effects boundary, scheduler, virtual time, SimNet, SimFs, Wasm backend, and sentinel |
| `ledger-explorer` | Oracles, search, LDFI, MaxSAT, minimization, certificates, and campaigns |
| `ledger-faultspec` | Failure-spec DSL parser, compiler, and scenario library |
| `ledger-flow` | Durable-execution step logging over the journal |
| `ledger-adapters` | OTel span ingest and journal envelopes |
| `ledger-cli` | `ledger` command-line composition root |
| `ledger-worker` | Queue draining, task execution, UDS/gRPC transport, and artifact publication |
| `ldgr-rt` | Apache-2.0 SUT porting facade and IPC boundary |
| `ledger-lint` | Static scanner for forbidden ambient APIs |
| `wasm-guest` | Deterministic `wasm32-wasip1` guest |
| `guests/` | Polyglot Wasm guest sources and prebuilt guest notes |
| `xtask` | License and environment checks |

`ledger-cli` is the only default Cargo member. Use explicit `--workspace`
or `-p` arguments for validation. Do not infer architecture or completion
from a bare `cargo test` or `cargo check`.

The license split is enforced by `cargo run -p xtask -- licenses`. Do not
infer license safety from crate names or docs. Several integration-shaped
crates currently depend directly on engine crates. Any change to those
dependencies, crate licenses, or process-boundary assumptions needs explicit
license and architecture review.

## Determinism boundary

Simulation code must not read ambient host state. It must use explicit effects
interfaces:

1. Use `VirtualTime` or `Effects::clock().now()`, never ambient wall-clock
   APIs.
2. Use `SeedTree` or `Effects::rng(stream)`, never ambient randomness,
   `getrandom`, or thread-local RNGs.
3. Use cooperative tasks through the simulation executor, never OS threads or
   thread scheduling as a source of behavior.
4. Use `SimFs`, never raw filesystem I/O.
5. Use `SimNet`, never raw network I/O.

Host-side tooling, the worker, the CLI, the runtime facade, adapters, and
sentinel code may use host facilities only at an explicit boundary. Keep that
code out of the simulation path. Preserve and justify
`// ledger-lint:allow` and `// ledger-lint:allow:<PATTERN>` markers. Do not
add an allow marker to hide a leak. Fix the boundary or add a focused test.

A deterministic run with the same build, seed, configuration, and inputs must
produce the same effect order, journal entries, decisions, and output bytes.
When a feature intentionally permits cross-build variation, document the
affected artifact and preserve the stated invariant, such as equal minimal
cost and certificate validity.

## Format, protocol, and API invariants

Treat these as compatibility boundaries:

- Do not change canonical CBOR, entry kinds, hash inputs, journal roots,
  manifests, or `.ldgr` framing without an approved format change and version
  review.
- Do not change `ledger.control.v1` fields, field numbers, RPCs, or wire
  semantics without updating the proto source, generated bindings,
  compatibility tests, and docs together. Keep changes additive within a
  version unless a version bump is approved.
- Do not change public APIs, feature names, default features, crate licenses,
  or process boundaries without approval. Deprecate before removal when the
  compatibility policy requires it.
- Validate untrusted input at every boundary. Bound lengths and counts. Validate
  hashes, hex, paths, URLs, queue records, and protobuf fields before use.
- UDS endpoints must use a private directory and restrictive socket permissions
  and must authenticate the peer where the platform supports peer credentials.
  Never put secrets in logs or URLs.

For journal or Wasm performance work, preserve semantics first. Batch encoding
or storage around per-entry hashes is allowed only if every entry ID, parent,
root, effect count, actor order, and recovery result remains byte-identical.
Never merge independent entry hashes into one hash. Measure before and after;
do not promote a performance lever from an estimate alone.

## Implementation rules

- Prefer explicit types and invariants over convention. Make invalid states
  hard to construct.
- Propagate typed errors with `Result<T, E>` and `?`. Add context at the
  boundary. Do not replace useful errors with an unstructured string when the
  source error can be preserved.
- Do not use `unwrap()` or `expect()` in production library paths. Tests may
  use them only for setup or assertions whose failure is meaningful.
- Do not discard a `Result` with `let _ =` unless the discard is intentional,
  safe, and documented at that line. Journal and persistence errors must never
  disappear on a replay path.
- Prefer borrowing over cloning. Avoid unbounded allocation, unchecked casts,
  silent truncation, and hidden global state.
- Keep `ledger-format` and `ledger-journal` `no_std` compatible. Gate
  storage, I/O, and other `std` code behind the existing feature surface.
- Library crates should retain `#![deny(unsafe_code)]`. Unsafe code is limited
  to the existing Wasm or sentinel boundary and must state its safety contract.
- Keep comments short and explain why, not what. Public documentation must
  state purpose and non-obvious errors, panics, safety, or invariants.
- Do not add TODO, FIXME, sprint, audit-stage, or plan-only markers to
  production code. Record deferred work in a durable design document or issue.
  Existing design docs may describe planned or deferred work when the status is
  explicit and does not claim implementation.
- Keep generated files generated. Edit their source schema or generator, then
  regenerate and test. Do not hand-edit generated output to make a build pass.
- Avoid unrelated cleanup in a behavior change. Keep one logical change per
  patch and preserve public paths unless the change includes migration work.

## Tests and validation

Every behavior change needs a test. Use unit tests for local invariants,
property tests for encoding, hashing, ordering, and merge laws, and integration
tests under the owning crate for cross-crate behavior. Tests must be
deterministic and must assert behavior, not only implementation details.

Run the smallest relevant checks first, then the full gates when practical:

```sh
# Fast local checks
cargo fmt -p <crate> -- --check
cargo check -p <crate> --all-targets
cargo nextest run -p <crate> --all-features

# Workspace gates
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --all-features --profile ci -E 'not binary(pg_queue)'
cargo test --workspace --doc
cargo run -p ledger-lint -- crates/
cargo run -p xtask -- licenses
cargo run -p xtask -- doctor

# no_std and feature surfaces
cargo check -p ledger-format --no-default-features
cargo check -p ledger-journal --no-default-features
cargo check -p ldgr-rt --all-targets
cargo check -p ldgr-rt --all-targets --features sim
cargo check -p ldgr-rt --all-targets --features sim-link

# Wasm prerequisites and parity
cargo build --target wasm32-wasip1 -p wasm-guest
cargo test -p ledger-sim --features backend-wasm --test wasm_differential --test wasm_corpus_bug

# Evidence gates
cargo test -p ledger-sim --test self_check --release
cargo test -p ledger-explorer --test minimize_gate --release
cargo test -p ledger-explorer --test corpus_v1_gate
cargo test -p ledger-explorer --test mcs_corpus_gate
cargo test -p ledger-sim --features backend-wasm --test wasm_differential --test wasm_corpus_bug
cargo build --release --target wasm32-wasip1 -p wasm-guest
cargo test --release -p ledger-sim --features backend-wasm --test wasm_throughput_gate
```

The worker has separate feature and service requirements. Run these when the
worker, protocol, or control-plane surface changes:

```sh
cargo check -p ledger-worker --all-features --all-targets
cargo clippy -p ledger-worker --all-features --all-targets -- -D warnings
cargo nextest run -p ledger-worker --test cross_boundary --all-features --profile ci
cargo nextest run -p ledger-worker --features grpc --test cross_boundary --profile ci
cargo nextest run -p ledger-worker --features pg --test pg_queue --profile ci
```

The Postgres test needs a live Postgres service. The gRPC test needs the
protobuf toolchain. Do not turn an unavailable required service into a passing
skip. Report the missing prerequisite and run the other checks.

CI also runs checks that need extra tools or services. Run the applicable leg
when changing its surface: `cargo hack` for feature combinations,
`cargo audit` for the locked dependency graph, `buf lint` for the protobuf
module, the format-conformance tests for cross-language encoding, and the
polyglot Wasm workflow for guest changes. Inspect the workflow files for the
exact tool versions and service setup.

Benchmarks are evidence, not correctness tests. Use Criterion benches only
after correctness gates pass. Record the command, build profile, feature set,
hardware, and comparison baseline for any performance claim. Benchmark output
belongs in ignored build directories unless the user asks for a report.

## Hardening and audit workflow

For a broad audit, begin in read-only mode:

1. Map the repository, manifests, docs, feature matrix, CI, tests, and current
   Git state.
2. Split independent audits by concern. Useful concerns are docs-versus-code,
   dead or duplicate code, comment hygiene, technical debt, test quality,
   security boundaries, performance evidence, and public API coherence.
3. Require each auditor finding to use:
   `severity(P0 blocking|P1 should-fix|P2 nice)|file:line|evidence|recommended action`.
4. Deduplicate findings and triage them before implementation. Recheck every
   plan claim against the current worktree; plans can be stale or describe a
   different branch.

For implementation work, use one implementer per disjoint write set. Do not
let parallel agents edit the same file. Review each completed task in this
order:

1. Spec compliance review.
2. Code quality and security review.
3. Focused tests and the required gates for the affected boundary.

If a review finds a defect, fix it and repeat that review. Do not treat an
implementer's self-review as a substitute for independent review. Do not put
temporary plan text or agent instructions in source comments.

## Change boundaries and approval points

Ask before:

- adding or changing a dependency;
- changing `.github/`, `.gitlab-ci.yml`, release automation, or supply-chain
  policy;
- changing a wire format, entry kind, hash, journal-root rule, or protocol;
- changing a public API, feature surface, crate license, or process boundary;
- changing generated protocol files or the format version;
- changing performance acceptance thresholds or deterministic output policy.

Do not declare work complete until the affected tests pass, the relevant docs
are updated, formatting and lint checks are clean, and any skipped gate is
named with its reason. Do not claim a plan is complete when it is only
validated, triaged, or benchmarked.
