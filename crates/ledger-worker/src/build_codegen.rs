// ledger-lint:allow - shared proto-codegen driver for the build script and its tests
// Fail-closed proto codegen driver shared by `build.rs` and its tests.

use std::path::{Path, PathBuf};

/// Paths the grpc codegen step writes.
pub struct CodegenPaths {
    pub proto: PathBuf,
    pub includes: Vec<PathBuf>,
    pub out_dir: PathBuf,
}

/// Resolve every codegen path from the crate manifest directory.
pub fn codegen_paths(manifest_dir: &Path) -> CodegenPaths {
    CodegenPaths {
        proto: manifest_dir.join("../ledger-format/proto/ledger/control/v2/control.proto"),
        includes: vec![manifest_dir.join("../ledger-format/proto")],
        out_dir: manifest_dir.join("src/gen"),
    }
}

/// Run the codegen driver fail-closed.
///
/// # Errors
/// Returns the first failure so `build.rs` can propagate it with `?`.
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