// Zig WASI guest for ldgr.
// Exports `run` which writes "zig-guest-ok\n" to stdout (fd 1) through
// WASI preview1 fd_write. No libc is used. The host captures stdout
// deterministically; see WasmBackend docs for shared seed-tree and virtual
// clock behavior: scheduling points remain host-call boundaries and both
// guests share the same deterministic clock and RNG streams.
//
// Build with Zig. CI builds this guest and fails when the toolchain or
// the build is missing; see .github/workflows/wasm-polyglot.yml.
// The output artifact is a required drop-in at guests/prebuilt/zig.wasm;
// see guests/prebuilt/README.md.
//
// Freestanding (no libc, matches task spec):
//   zig build-exe -target wasm32-freestanding -O ReleaseSmall -fno-entry --export=run -femit-bin=guests/prebuilt/zig.wasm guests/zig/main.zig
// Alternative with export-memory:
//   zig build-exe -target wasm32-freestanding -O ReleaseSmall -fno-entry --export=run --export-memory -femit-bin=guests/prebuilt/zig.wasm guests/zig/main.zig
// WASI variant (links WASI libc, also valid):
//   zig build-exe guests/zig/main.zig -target wasm32-wasi -O ReleaseSmall -femit-bin=guests/prebuilt/zig.wasm
//
// Verify the export:
//   wasm2wat guests/prebuilt/zig.wasm | grep -q '(export "run"'

const IoVec = extern struct {
    base: [*]const u8,
    len: usize,
};

extern "wasi_snapshot_preview1" fn fd_write(fd: i32, iovs: [*]const IoVec, iovs_len: usize, nwritten: *usize) usize;

export fn run() void {
    const msg = "zig-guest-ok\n";
    var iov = IoVec{ .base = msg.ptr, .len = msg.len };
    var nwritten: usize = 0;
    _ = fd_write(1, @ptrCast(&iov), 1, &nwritten);
}
