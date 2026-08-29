# CLI reference

All commands run through `ledger`. Global flags apply to every command.

```bash
cargo run -p ledger-cli -- [GLOBAL FLAGS] <COMMAND> [ARGS]
# or, after install
ledger [GLOBAL FLAGS] <COMMAND> [ARGS]
```

## Global flags

| Flag | Description |
| ------ | ------------- |
| `-j`, `--json` | Emit machine-readable JSON. Conflicts with `--ndjson`. |
| `--ndjson` | Emit one JSON object per line. Conflicts with `--json`. |
| `--deadline-ms <MS>` | Wall-clock deadline for the whole command in milliseconds. On expiry the runner prints a diagnostic and exits with code 2. |
| `-v`, `-vv`, `-vvv` | Increase verbosity. |
| `-q`, `-qq` | Decrease verbosity. |

## Exit codes

| Code | Meaning |
| ------ | --------- |
| 0 | The command completed. A campaign that found a violation also exits 0 - the violation is in the output, not the exit code. |
| 1 | The command failed: bad usage, unreadable input, a journal error, or `format --check` rejected a file. |
| 2 | Deadline exceeded. `--deadline-ms` expired before the command finished. |

## `ledger sim`

Run a deterministic simulation campaign.

```bash
ledger sim [--seed <U64>] [--policy random|pct|bandit|replay] \
  [--exploration-constant <F64>] [--priority-changes <N>] \
  [--max-steps <N>] [--runs <N>]
```

| Flag | Default | Description |
| ------ | --------- | ------------- |
| `--seed` | 0 | Root seed for the campaign. |
| `--policy` | bandit | Scheduling policy. |
| `--exploration-constant` | 1.414 | Exploration constant for the bandit policy. |
| `--priority-changes` | 8 | Priority-change budget for the pct policy. |
| `--max-steps` | 256 | Maximum instructions per run. |
| `--runs` | 100 | Number of campaign attempts. |

Example:

```bash
ledger sim --seed 42 --runs 50 --max-steps 256
ledger sim --policy pct --priority-changes 4 --json
```

## `ledger repro`

Replay a seed and verify the journal root.

```bash
ledger repro [--seed <U64>] [--policy <POLICY>] \
  [--exploration-constant <F64>] [--priority-changes <N>] [--max-steps <N>]
```

Flags match `sim` except there is no `--runs`. Uses the same defaults: `seed 0`, `policy random`, `exploration-constant 1.414`, `priority-changes 8`, `max-steps 256`.

Example:

```bash
ledger repro --seed 42 --max-steps 256
```

## `ledger minimize`

Minimize a failing run using schedule-delta debugging.

```bash
ledger minimize [--seed <U64>] [--policy <POLICY>] \
  [--exploration-constant <F64>] [--priority-changes <N>] \
  [--max-steps <N>] [--runs <N>]
```

| Flag | Default |
| ------ | --------- |
| `--seed` | 0 |
| `--policy` | random |
| `--exploration-constant` | 1.414 |
| `--priority-changes` | 8 |
| `--max-steps` | 256 |
| `--runs` | 256 |

Example:

```bash
ledger minimize --seed 42 --runs 200
```

## `ledger diff`

Compare two seeds or runs for first divergence.

```bash
ledger diff [--seed-a <U64>] [--seed-b <U64>] [--max-steps <N>]
```

| Flag | Default |
|------|---------|
| `--seed-a` | 1 |
| `--seed-b` | 2 |
| `--max-steps` | 256 |

Example:

```bash
ledger diff --seed-a 1 --seed-b 2 --max-steps 512
```

## `ledger doctor`

Verify environment determinism and toolchain health. No arguments.

```bash
ledger doctor
```

## `ledger init`

Initialize a new `.ldgr` project template.

```bash
ledger init [DIR] [--force] [--sut]
```

| Argument/Flag | Description |
| --------------- | ------------- |
| `DIR` | Target directory. Default is the current directory. |
| `--force` | Overwrite existing files. |
| `--sut` | Scaffold an ldgr-rt based SUT crate. |

Example:

```bash
ledger init my-project --sut
```

## `ledger format`

Inspect a `.ldgr` or CBOR file.

```bash
ledger format <FILE> [--check]
```

| Argument/Flag | Description |
|---------------|-------------|
| `<FILE>` | The `.ldgr` or CBOR file to verify. |
| `--check` | Verify canonical RFC 8949 Core Deterministic CBOR encoding. |

Example:

```bash
ledger format corpora/bug-corpus-v1/mini-kv-stale-read.ldgr --check
```

## `ledger ldfi`

Run an LDFI campaign and execute the top fault hypothesis.

```bash
ledger ldfi [--seed <U64>] [--max-steps <N>] [--attempts <N>] \
  [--maxsat-engine auto|builtin|cadical]
```

| Flag | Default | Description |
| ------ | --------- | ------------- |
| `--seed` | 0 | Root seed for the campaign. |
| `--max-steps` | 256 | Maximum instructions per run. |
| `--attempts` | 64 | Number of campaign attempts. |
| `--maxsat-engine` | auto | Fault-solver engine. `auto` picks a suitable engine automatically; `builtin` forces the pure-Rust engine; `cadical` forces MaxSAT. |

Example:

```bash
ledger ldfi --seed 7 --attempts 100 --maxsat-engine auto
```

## `ledger completions`

Print shell completion scripts to stdout.

```bash
ledger completions <bash|zsh|fish|powershell|elvish>
```

Example:

```bash
ledger completions bash > ~/.completions/ledger.bash
```

## `ledger ingest`

Ingest OTel NDJSON spans into a content-addressed journal.

```bash
ledger ingest --input <PATH> [--fidelity lineage-only|bit-exact]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | (required) | Path to newline-delimited JSON OTel spans. |
| `--fidelity` | lineage-only | Fidelity mode. |

Example:

```bash
ledger ingest --input traces.json --fidelity lineage-only
```

## `ledger cert verify`

Verify a campaign certificate JSON file.

```bash
ledger cert verify <FILE> [--journal <DIR>] [--op statement|journal|inclusion-minimal]
```

| Flag | Default | Description |
|------|---------|-------------|
| `<FILE>` | (required) | Path to the certificate JSON file. |
| `--journal` | None | Directory of the persisted journal for journal-anchored validation. |
| `--op` | statement | Selected operation: `statement` (schema/size checks), `journal` (journal-anchored proof), or `inclusion-minimal` (verifies cut minimality). `--journal` is required for `journal` and `inclusion-minimal`. |

Examples:

```bash
ledger cert verify cert.json
ledger cert verify cert.json --journal /path/to/journal --op inclusion-minimal
```

## `ledger faults`

Failure-spec scenario operations.

```bash
ledger faults compile --file <PATH>
ledger faults apply --file <PATH> --seed-hex <64-HEX> [--workload kv]
```

| Subcommand | Flag | Description |
| ------------ | ------ | ------------- |
| `compile` | `--file` | Path to the scenario DSL file. |
| `apply` | `--file` | Path to the scenario DSL file. |
| `apply` | `--seed-hex` | 64-hex-character root seed for the run. |
| `apply` | `--workload` | Workload to run. Default `kv`. |

Examples:

```bash
ledger faults compile --file scenario.fspec
ledger faults apply --file scenario.fspec --seed-hex ab12... --workload kv
```

## `ledger coverage`

Export exploration coverage (distinct roots / scenario space).

```bash
ledger coverage --input <PATH> [--format lcov|sarif|jacoco]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | (required) | Path to NDJSON of `{root_hex, run_index, finding}` lines. |
| `--format` | lcov | Export format. |

Example:

```bash
ledger coverage --input coverage.ndjson --format lcov > lcov.info
```

## `ledger scaffold`

Scaffold a consensus-family example crate (mini-Raft, Mini-KV, 2PC).

```bash
ledger scaffold [--template consensus|kv|2pc] <DIR> [--force]
```

| Flag | Default | Description |
| ------ | --------- | ------------- |
| `--template` | consensus | Template to scaffold. |
| `DIR` | (required) | Target directory for the scaffolded crate. |
| `--force` | false | Overwrite existing files. |

Example:

```bash
ledger scaffold --template kv ./my-kv --force
```

## `ledger rt-server` (hidden)

An internal IPC server for the SUT facade. Hidden from help output; not for direct use.

## Common patterns

```bash
# Bound every run in CI
ledger --deadline-ms 30000 sim --runs 100

# Machine-readable output for scripting
ledger --json sim --runs 20 > findings.json
ledger --ndjson sim --runs 20 | jq .

# Verbose campaign
ledger -v sim --seed 7 --policy bandit
```
