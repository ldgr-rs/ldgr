// Package main is a TinyGo WASI guest for ldgr.
//
// The guest exports `run` which prints "go-guest-ok" to stdout through WASI
// fd_write. The host captures stdout deterministically, so the output is the
// observable effect used by the mixed-topology test.
//
// Build with TinyGo. CI builds this guest and fails when the toolchain
// or the build is missing; see .github/workflows/wasm-polyglot.yml.
// The output artifact is a required drop-in at
// guests/prebuilt/go.wasm; see guests/prebuilt/README.md.
//
// TinyGo WASI preview1 (stable):
//   tinygo build -o guests/prebuilt/go.wasm -target wasi guests/go/main.go
//
// TinyGo WASI preview2 / component model (deferred; the host backend is
// preview1-only until a component path exists):
//   tinygo build -o guests/prebuilt/go.wasm -target wasip2 guests/go/main.go
//
// Verify the export:
//   wasm2wat guests/prebuilt/go.wasm | grep -q '(export "run"'
//
// This file intentionally uses only stdlib printing. No ledger host imports
// are needed; WASI stdout is the scheduling-free observable boundary. Each
// host-call boundary (WASI fd_write) is a deterministic scheduling point
// served by the host WASI virtualization on the shared seed tree and virtual
// clock.
package main

import "fmt"

//export run
func run() {
	fmt.Println("go-guest-ok")
}

func main() {}
