//! Fail-closed proto codegen driver tests.
//!
//! The driver is shared with `build.rs` through `include!`; these tests
//! exercise the pure error paths without a `protoc` binary: directory
//! creation failures propagate and the compile step is skipped. The missing-
//! protoc failure itself is proven by building with `--features grpc` and a
//! bogus `PROTOC` binary (CI leg), because the tonic-prost call needs the
//! prost-build dependency graph that this crate's library does not link.

include!("../src/build_codegen.rs");

use std::sync::{Arc, Mutex};

fn temp_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("ldgr-codegen-{tag}-{}", std::process::id()))
}

#[test]
fn codegen_paths_resolve_contract_and_out_dir() {
    let manifest_dir = Path::new("/repo/crates/ledger-worker");
    let paths = codegen_paths(manifest_dir);
    // join() keeps the `..` segment lexically; the contract resolves into
    // the sibling ledger-format crate.
    assert_eq!(
        paths.proto,
        PathBuf::from(
            "/repo/crates/ledger-worker/../ledger-format/proto/ledger/control/v2/control.proto"
        )
    );
    assert_eq!(
        paths.out_dir,
        PathBuf::from("/repo/crates/ledger-worker/src/gen")
    );
    assert!(
        paths
            .includes
            .iter()
            .any(|dir| dir == &PathBuf::from("/repo/crates/ledger-worker/../ledger-format/proto"))
    );
}

#[test]
fn regenerate_creates_out_dir_before_compile() {
    let dir = temp_dir("ok");
    let _ = std::fs::remove_dir_all(&dir);
    let manifest_dir = dir.join("crates/ledger-worker");
    let ran = Arc::new(Mutex::new(false));
    let ran_for_closure = Arc::clone(&ran);
    let result = regenerate(&manifest_dir, |paths| {
        assert!(
            paths.out_dir.is_dir(),
            "out dir must exist before the compile step"
        );
        *ran_for_closure.lock().unwrap() = true;
        Ok(())
    });
    assert!(result.is_ok(), "regenerate failed: {result:?}");
    assert!(
        *ran.lock().unwrap(),
        "compile step must run after dir creation"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn regenerate_propagates_dir_creation_error_and_skips_compile() {
    let dir = temp_dir("blocked");
    let _ = std::fs::remove_dir_all(&dir);
    let manifest_dir = dir.join("crates/ledger-worker");
    std::fs::create_dir_all(manifest_dir.join("src")).expect("create src dir");
    // A regular file where the gen dir must live makes create_dir_all fail.
    std::fs::write(manifest_dir.join("src/gen"), b"not a directory").expect("write blocker");
    let ran = Arc::new(Mutex::new(false));
    let ran_for_closure = Arc::clone(&ran);
    let result = regenerate(&manifest_dir, |_| {
        *ran_for_closure.lock().unwrap() = true;
        Ok(())
    });
    let err = result.expect_err("create_dir_all failure must fail the build");
    assert!(
        !*ran.lock().unwrap(),
        "compile step must not run after a dir error"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("src/gen"),
        "error must name the out dir, got {msg}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn regenerate_propagates_compile_error() {
    let dir = temp_dir("compile");
    let _ = std::fs::remove_dir_all(&dir);
    let manifest_dir = dir.join("crates/ledger-worker");
    let err = regenerate(&manifest_dir, |_| {
        Err(Box::<dyn std::error::Error>::from(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "protoc: command not found",
        )))
    })
    .expect_err("compile failure must propagate");
    assert!(err.to_string().contains("protoc"), "got {err}");
    let _ = std::fs::remove_dir_all(&dir);
}
