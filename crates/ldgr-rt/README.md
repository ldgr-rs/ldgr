# ldgr-rt

Drop-in deterministic runtime facade for the ldgr simulation engine.

With `--features sim` the same async SUT code runs under the deterministic executor (virtual time, seeded RNG, partitioned SimNet, journaling) over a process boundary. Without the feature it runs under `tokio` with ambient time and OS entropy.

`sim` is IPC-only: the facade spawns the `ledger` engine binary (`LEDGER_ENGINE_BIN` or `ledger` on PATH) and talks to `ledger rt-server` over a Unix socket, so the SUT crate stays Apache-2.0 without linking AGPL `ledger-sim`. For workspace iteration the `sim-link` feature keeps the direct `ledger-sim` link (`cargo run -p ldgr-rt --features sim-link`).

## What executes, per feature set

| Feature set | `run(config, my_closure)` | `run_named(config, name)` |
| --- | --- | --- |
| none (default) | Runs YOUR closure on a current-thread tokio runtime (`LocalSet`, non-`Send` friendly). No journal: `journal_root` is `None`. | Runs the closure registered under `name` via `register_workload`; unknown names return `RuntimeError::UnknownWorkload`. |
| `sim-link` | Runs YOUR closure on the in-process deterministic executor; returns the journaled journal root. Same registry semantics as default. | As above; server-side workloads are not reachable. |
| `sim` (IPC) | Refuses loudly with `RuntimeError::ProgramNotTransportable`: caller programs do not cross the process boundary, and nothing else is executed in their place. | Sends `name` to the engine, which runs its registered server workload (`"kv"`) and returns the deterministic journal root. |

Registration is thread-local and takes a factory (`fn() -> TaskMain`) because programs are consume-once; re-registering a name replaces its factory. Under IPC the client registry has no effect - the engine resolves its own workload names.

Deferred transport hardening: true remote program execution needs either WASM program transport or a remote-effects protocol with a local deterministic scheduler (local tokio scheduling would break journal determinism); both are control-plane-scale work recorded here rather than stubbed in code. Peer-credential checks (SO_PEERCRED) of the engine connection are also still open; sockets already live in freshly created mode-0700 directories.

Examples:
- `cargo run -p ldgr-rt --example mini_kv` (tokio)
- `cargo run -p ldgr-rt --example mini_kv --features sim-link` (direct link, workspace tests)
- SUT-side named runs under `sim` via `ldgr_rt::run_named(config, "kv")` (IPC; requires the engine binary resolved from `LEDGER_ENGINE_BIN`, the workspace `target/debug/ledger`, or `ledger` on PATH)
