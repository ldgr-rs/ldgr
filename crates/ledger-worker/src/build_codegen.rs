// ledger-lint:allow - shared proto-codegen driver for the build script and its tests
// Fail-closed proto codegen driver shared by `build.rs` and its tests.
//
// `build.rs` includes this file to regenerate the tonic/prost bindings for
// the `grpc` feature; the integration test in
// `crates/ledger-worker/tests/codegen_fail_closed.rs` includes the same
// file to prove the error paths without a `protoc` binary.

use std::path::{Path, PathBuf};

/// Paths the grpc codegen step writes: the proto source of truth, its
/// include roots, and the out dir inside the source tree.
pub struct CodegenPaths {
    /// `ledger.control.v1` contract source.
    pub proto: PathBuf,
    /// Directories searched for imports.
    pub includes: Vec<PathBuf>,
    /// Directory the generated bindings are written into.
    pub out_dir: PathBuf,
}

/// Resolve every codegen path from the crate manifest directory.
pub fn codegen_paths(manifest_dir: &Path) -> CodegenPaths {
    CodegenPaths {
        proto: manifest_dir.join("../ledger-format/proto/ledger/control/v1/control.proto"),
        includes: vec![manifest_dir.join("../ledger-format/proto")],
        out_dir: manifest_dir.join("src/gen"),
    }
}

/// Run the codegen driver fail-closed.
///
/// Directory creation errors abort the build with the failing path, and the
/// `compile` step runs only after the out dir exists. A failed compile aborts
/// the build: no stale checked-in bindings are used as a silent fallback.
///
/// # Errors
/// Returns the first failure as `Box<dyn std::error::Error>` so `build.rs`
/// can propagate it with `?`.
pub fn regenerate<F>(manifest_dir: &Path, compile: F) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnOnce(&CodegenPaths) -> Result<(), Box<dyn std::error::Error>>,
{
    let paths = codegen_paths(manifest_dir);
    std::fs::create_dir_all(&paths.out_dir).map_err(|err| {
        Box::<dyn std::error::Error>::from(std::io::Error::new(
            err.kind(),
            format!(
                "ledger-worker codegen: cannot create out dir {}: {err}",
                paths.out_dir.display()
            ),
        ))
    })?;
    compile(&paths)
}