//! Shared helpers for the Wasm integration tests.

/// Load the compiled guest module from the workspace target directory.
///
/// Build it with `cargo build --target wasm32-wasip1 -p wasm-guest`.
pub fn guest_wasm_bytes() -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/wasm32-wasip1/debug/wasm_guest.wasm");
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "guest artifact missing at {}; run `cargo build --target wasm32-wasip1 -p wasm-guest` first. error: {error}",
            path.display()
        )
    })
}
