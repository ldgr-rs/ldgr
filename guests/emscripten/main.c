// Emscripten WASI guest for ldgr.
// Exports `run` which writes "emcc-guest-ok\n" to stdout (fd 1) through
// WASI preview1 fd_write. No libc is used; the module is freestanding.
// The host captures stdout deterministically; see WasmBackend docs for
// shared seed-tree and virtual clock behavior: scheduling points remain
// host-call boundaries and both guests share the same deterministic clock
// and RNG streams.
//
// Build with Emscripten. CI builds this guest and fails when the
// toolchain or the build is missing; see
// .github/workflows/wasm-polyglot.yml. The output artifact is a
// required drop-in at guests/prebuilt/emscripten.wasm; see
// guests/prebuilt/README.md.
//
// Emscripten freestanding (matches task spec):
//   emcc guests/emscripten/main.c -O3 -o guests/prebuilt/emscripten.wasm -sSTANDALONE_WASM -sEXPORTED_FUNCTIONS=_run --no-entry
//
// Verify the export:
//   wasm2wat guests/prebuilt/emscripten.wasm | grep -q '(export "run"'

__attribute__((import_module("wasi_snapshot_preview1"), import_name("fd_write")))
int fd_write(int fd, const void *iovs, int iovs_len, int *nwritten);

struct iovec {
    const char *buf;
    unsigned int buf_len;
};

__attribute__((visibility("default")))
void run(void) {
    const char msg[] = "emcc-guest-ok\n";
    struct iovec iov = {msg, 14};
    int nwritten;
    fd_write(1, &iov, 1, &nwritten);
}
