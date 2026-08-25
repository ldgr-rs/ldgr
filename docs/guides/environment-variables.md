# Environment variables

ldgr reads a small set of environment variables. All of them are host-side configuration for tooling, attestation, or the worker. Simulation code never reads the environment. The lint enforces this on simulation paths.

## Variables

| Variable | Used by | Default | Description |
| ---------- | --------- | --------- | ------------- |
| `LEDGER_ATTESTATION_BASE` | `ledger cert verify`, campaign certificate emission and verification | `https://ledger.invalid` | Base URI for attestation predicates and build types. Override to point at your deployment domain. |
| `LEDGER_ENGINE_BIN` | `ldgr-rt` facade | unset | Path to the `ldgr-rt` IPC engine binary. When set, the facade spawns that binary for simulation runs. |
| `LEDGER_ARTIFACT_TOKEN` | `ledger-worker` | unset | Bearer token for worker artifact publication. |
| `LEDGER_SENTINEL_BELT` | `ledger-sim` sentinel belt | unset | When set, arms the belt harness that interposes ambient calls. |
| `LD_PRELOAD` | `ledger-sim` sentinel belt | unset | Read by the belt harness to prepend its shim. Managed by the harness. Do not set it by hand for normal runs. |
| `LEDGER_PROBE_MODE` | `ledger-sim` sentinel probe binary | unset | Mode flag for the `sentinel_probe` helper. |
| `LEDGER_VIRTUAL_TICKS_PATH` | `ledger-sim` tokio backend | unset | Path where virtual ticks are recorded for the tokio shim. |
| `LEDGER_VIRTUAL_SEED_HEX` | `ledger-sim` tokio backend | unset | Hex seed for the tokio shim's virtual clock. |
| `LEDGER_BUILDER_ID` | nightly campaign example (`nightly_swarm_campaign.rs`) | `nightly-swarm-campaign` | Builder identity stamped into nightly campaign provenance. |
| `LEDGER_PROFILE_FINGERPRINT` | nightly campaign example | unset | Optional profile fingerprint for nightly campaign attestation. |
| `LEDGER_CERT_OUT` | nightly campaign example | unset | When set, write the campaign certificate JSON to this path. |
| `XDG_RUNTIME_DIR` | `ledger-worker` socket directory | `std::env::temp_dir()` fallback | Base directory for the worker's private Unix socket. |
| `CARGO_FEATURE_SENTINEL` | `ledger-sim` build script | set by Cargo | Cargo sets this when the `sentinel` feature is enabled. Not for manual use. |
| `CARGO_CFG_TARGET_OS` | `ledger-sim` build script | set by Cargo | Cargo sets this to the target OS. Not for manual use. |
| `OUT_DIR` | `ledger-sim` build script | set by Cargo | Cargo sets this to the build output directory. Not for manual use. |

## Scoping rules

- `LEDGER_ATTESTATION_BASE` and `XDG_RUNTIME_DIR` are the only variables most users need to set. The rest are for specific components or examples.
- Simulation workloads must not call `std::env::var`. Pass inputs through seeds, effects, or the workload's history. The lint reports `env::var` in simulation paths.
- Worker socket paths are private directories with restrictive permissions. The worker derives the path from `XDG_RUNTIME_DIR` when available and falls back to the system temp directory. Do not put secrets in URLs or logs.

## Where to set them

- **Local shell** - `export LEDGER_ATTESTATION_BASE=...` before running `ledger` or `cargo run`.
- **`.env` file** - copy `.env.example` to `.env` at the repo root. Load it with `direnv`, `dotenv`, or `set -a; source .env; set +a`. Do not commit `.env`.
- **CI** - set them as encrypted secrets or variables in your provider. In GitHub Actions, add them under Settings > Secrets and reference them as `${{ secrets.LEDGER_ARTIFACT_TOKEN }}`.
- **Systemd / Docker** - pass them in the unit file (`Environment=`) or `docker run -e` / compose `environment:` block.

Precedence is simple: the process environment wins. There is no config file that overrides an exported variable. If a variable is unset, the default in the table applies.

## Local development with `.env.example`

The repo ships `.env.example` with every supported variable, commented defaults, and a short note per entry. Copy it and fill in only what you need:

```bash
cp .env.example .env
# edit .env, then
set -a; source .env; set +a
cargo run -p ledger-cli -- doctor
```

Keep `.env` out of version control. The example file is the contract for what the toolchain reads. If you add a new variable to the code, add it to `.env.example` in the same change.

## Example

```bash
# Point attestation at your domain
export LEDGER_ATTESTATION_BASE=https://attest.example.com

# Run the worker with artifact publishing
export LEDGER_ARTIFACT_TOKEN=your-token
cargo run -p ledger-worker

# Nightly campaign with provenance
export LEDGER_BUILDER_ID=my-builder
export LEDGER_CERT_OUT=./cert.json
cargo run --example nightly_swarm_campaign -p ledger-explorer
```

See `.env.example` at the repo root for a copy-paste template.
