# Polyglot guests (W2)

This directory holds minimal polyglot guest sources that compile to
`wasm32` and export a `run` entry point. Each guest is intentionally
tiny: it writes a marker string to stdout through WASI `fd_write` so
the host can assert the guest ran deterministically. The host captures
stdout deterministically and journals host-call effects on the shared
seed tree and virtual clock. Guests share the same deterministic
facilities; scheduling points remain host-call boundaries.

## Sources

- `go/main.go` -- TinyGo WASI guest. Exports `run` via `//export run`.
- `zig/main.zig` -- Zig wasm32 guest. No libc. Exports `run` via
  WASI `fd_write`.
- `c/main.c` -- C freestanding wasm guest. No libc. Exports `run` via
  WASI `fd_write`.
- `emscripten/main.c` -- Emscripten freestanding wasm guest. No libc.
  Exports `run` via WASI `fd_write`.

## Build commands (exact)

All commands are offline except for the toolchain itself. The
workflow `.github/workflows/wasm-polyglot.yml` requires every toolchain
and every guest build: a missing toolchain or a failed build fails the
job. Local runs without the toolchain cannot build the guests.

### Go (TinyGo)

TinyGo WASI preview1 (stable, recommended):

```
tinygo build -o guests/prebuilt/go.wasm -target wasi guests/go/main.go
```

TinyGo WASI preview2 / component model (deferred; the host backend is
preview1-only until a component path exists):

```
tinygo build -o guests/prebuilt/go.wasm -target wasip2 guests/go/main.go
```

Verify:

```
wasm2wat guests/prebuilt/go.wasm | grep -q '(export "run"'
```

### Zig

Freestanding (no libc, matches W2 spec):

```
zig build-exe -target wasm32-freestanding -O ReleaseSmall -fno-entry --export=run -femit-bin=guests/prebuilt/zig.wasm guests/zig/main.zig
```

Alternative freestanding with explicit memory export:

```
zig build-exe -target wasm32-freestanding -O ReleaseSmall -fno-entry --export=run --export-memory -femit-bin=guests/prebuilt/zig.wasm guests/zig/main.zig
```

WASI variant (links WASI libc, also valid):

```
zig build-exe guests/zig/main.zig -target wasm32-wasi -O ReleaseSmall -femit-bin=guests/prebuilt/zig.wasm
```

Verify:

```
wasm2wat guests/prebuilt/zig.wasm | grep -q '(export "run"'
```

### C (clang / emscripten)

Clang freestanding (matches W2 spec):

```
clang --target=wasm32 -nostdlib -Wl,--no-entry -Wl,--export=run -o guests/prebuilt/c.wasm guests/c/main.c
```

Emscripten standalone (from `c` source):

```
emcc guests/c/main.c -o guests/prebuilt/c.wasm -s STANDALONE_WASM -s EXPORTED_FUNCTIONS=_run
```

Verify:

```
wasm2wat guests/prebuilt/c.wasm | grep -q '(export "run"'
```

### Emscripten (emsdk)

Freestanding (no libc, matches task spec):

```
emcc guests/emscripten/main.c -O3 -o guests/prebuilt/emscripten.wasm -sSTANDALONE_WASM -sEXPORTED_FUNCTIONS=_run --no-entry
```

Verify:

```
wasm2wat guests/prebuilt/emscripten.wasm | grep -q '(export "run"'
```

## Output

Builds emit to `guests/prebuilt/<name>.wasm`. See
`guests/prebuilt/README.md` for the drop-in path used by tests.
The mixed-topology test
`crates/ledger-sim/tests/wasm_mixed_topology.rs` executes every
present prebuilt guest: each must load, run, print its marker, and be
deterministic. When no guests are present the test skips with a notice;
the polyglot workflow guarantees the guests exist before it runs that
test, so the test executes with real artifacts in that job.

## CI

Workflow `.github/workflows/wasm-polyglot.yml` requires the four
toolchains (TinyGo 0.37.0 with pinned sha256, Zig 0.16.0, Emscripten
emsdk 4.0.23, clang with lld), builds all guests into
`guests/prebuilt/`, asserts each artifact exports `run` with
`wasm2wat`, asserts the four artifacts exist, then runs the
mixed-topology test and the wasm gates with `--features backend-wasm`.
A missing toolchain or artifact fails the job. See that workflow for
the exact steps.

## Design notes

- WASI is the universal compile target; each language reaches the full
  engine (journal, LDFI, minimizer) with no runtime surgery.
- Guests are intentionally minimal. Real workloads cross the `ledger`
  host boundary (`ledger_rng_u64`, `ledger_log`, `ledger_sleep`) or
  use virtualized WASI (`random_get`, `clock_time_get`). Polyglot
  guests can adopt those imports as needed; the current WASI-stdout
  path proves topology and determinism without extra imports.
