# CI integration

Run ldgr in the same pipeline that builds your system. A campaign is a test. A failure is a small artifact you can replay anywhere.

## GitHub Actions

```yaml
name: sim
on: [push, pull_request]

jobs:
  ldgr:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: "1.97.1"
      - name: Build ldgr
        run: cargo build -p ledger-cli
      - name: Run campaign
        run: |
          cargo run -p ledger-cli -- --deadline-ms 30000 sim --seed 42 --runs 100 | tee sim.log
          if grep -q "Violation detected" sim.log; then
            echo "::error::ldgr found a violation"
            exit 1
          fi
      - name: Upload finding
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: finding
          paths: |
            sim.log
            findings.json
```

Notes:

- Fix the seed in CI. `42` is arbitrary. A fixed seed is reproducible. Rotate it on a schedule if you want more coverage over time.
- A campaign that finds a violation still exits `0` - the violation is in the output. Fail the job by parsing it, as the example does. Exit `1` means the command itself failed. Exit `2` is a deadline expiry.
- Use `--deadline-ms` to bound every job. Without it a hung run hangs the job. `30000` is a reasonable starting point for small workloads.

## GitLab CI

```yaml
ldgr:
  image: rust:1.97
  script:
    - cargo build -p ledger-cli
    - cargo run -p ledger-cli -- --deadline-ms 30000 sim --seed 42 --runs 100 | tee sim.log
    - if grep -q "Violation detected" sim.log; then exit 1; fi
  artifacts:
    when: on_failure
    paths:
      - sim.log
      - findings.json
```

## Caching

Cache the Cargo `target` directory between runs. The engine rebuilds often and the cache saves minutes.

```yaml
- uses: Swatinem/rust-cache@v2
```

If your runner supports it, cache `~/.cargo/registry` as well.

## Machine-readable output

Use `--json` or `--ndjson` when you need to parse results.

```bash
# One JSON object for the whole campaign
cargo run -p ledger-cli -- --json sim --seed 42 --runs 20 > findings.json

# One line per attempt, easy to stream
cargo run -p ledger-cli -- --ndjson sim --seed 42 --runs 20 | jq -c 'select(.status=="violation")'

# LDFI and format checks also support --json
cargo run -p ledger-cli -- --json ldfi --seed 42 --attempts 64
cargo run -p ledger-cli -- --json format --check /tmp/initdoc/repro.ldgr
```

## Coverage and artifacts

Export coverage when you have NDJSON coverage records (`{root_hex, run_index, finding}` per line) and upload it with your usual coverage flow:

```bash
cargo run -p ledger-cli -- coverage --input coverage.ndjson --format lcov > lcov.info
```

Keep `.ldgr` manifests when you have them, such as `repro.ldgr` from `ledger init`. A manifest is a small canonical descriptor that pins a run root. Keep it with the compatible workload build, run configuration, and referenced journal material:

```bash
cargo run -p ledger-cli -- format /tmp/initdoc/repro.ldgr --check
cargo run -p ledger-cli -- repro --seed 42
```

The first command validates canonical CBOR encoding. The second command runs and verifies the built-in seed-based replay path; it does not load the manifest.

## Exit codes in CI

| Code | Action |
| ------ | -------- |
| 0 | Command completed. Check the output for violations - a finding does not change the exit code. |
| 1 | Fail the job. The command itself failed (bad usage, unreadable input, journal error). |
| 2 | Fail the job. Investigate as a hang or liveness issue. Retry with a higher `--deadline-ms` to confirm. |
