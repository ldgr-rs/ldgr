# Prebuilt polyglot guests (optional drop-in)

This directory holds prebuilt `.wasm` guest artifacts built by the
workflow `.github/workflows/wasm-polyglot.yml`. It is intentionally
empty in the repository. The polyglot workflow builds the artifacts
here and fails when any of them is missing; other jobs and local runs
skip gracefully when the directory is empty.

## How it works

- If `guests/prebuilt/<name>.wasm` exists, tests use it. The mixed-
  topology test `crates/ledger-sim/tests/wasm_mixed_topology.rs` checks
  `Path::exists` for each prebuilt artifact at runtime:
  `guests/prebuilt/go.wasm`, `guests/prebuilt/zig.wasm`,
  `guests/prebuilt/c.wasm`, `guests/prebuilt/emscripten.wasm`. Each
  present artifact is loaded as a named instance and must print its
  marker and produce deterministic journals across two runs. When
  absent, it prints a skip notice and passes.

- If the directory is empty (the default), all wasm tests still pass.
  The Rust `wasm-guest` (`crates/wasm-guest`, `wasm32-wasip1`) remains
  the only required guest; it is built with
  `cargo build --target wasm32-wasip1 -p wasm-guest`.

## Building locally

Build any guest from `guests/` into this directory:

```
# Go (requires tinygo)
tinygo build -o guests/prebuilt/go.wasm -target wasi guests/go/main.go

# Zig (requires zig)
zig build-exe -target wasm32-freestanding -O ReleaseSmall -fno-entry --export=run -femit-bin=guests/prebuilt/zig.wasm guests/zig/main.zig

# C (requires clang with wasm32 target)
clang --target=wasm32 -nostdlib -Wl,--no-entry -Wl,--export=run -o guests/prebuilt/c.wasm guests/c/main.c
```

See `guests/README.md` for all exact build commands and verification
steps (`wasm2wat ... | grep '(export "run"'`).

## CI

Workflow `.github/workflows/wasm-polyglot.yml` builds guests into this
directory with required toolchains and fails when a build or artifact
is missing. The main `ci.yml` does not require this directory; it is
additive.

## Determinism

Prebuilt guests share the same deterministic host facilities as the Rust
guest: the seed tree (`wasi.random` stream) and virtual clock. Guests
that call `ledger_*` or WASI `random_get` / `clock_time_get` cross the
same host-call boundary and journal identically. Mixed-topology runs
share one `SeedTree` across named instances; scheduling points remain
host-call boundaries, so two runs with the same seed produce byte-
identical journal roots.

## Adding a new guest

1. Add source under `guests/<lang>/`.
2. Document the exact build command in `guests/README.md`.
3. Build to `guests/prebuilt/<lang>.wasm` when testing.
4. Extend `wasm_mixed_topology.rs` or add a new test that loads the
   guest with `WasmBackend::load_guest_multi`.

Do not commit large `.wasm` files without discussion. Prebuilt files
in this directory are typically `.gitignore`'d and built on demand.
