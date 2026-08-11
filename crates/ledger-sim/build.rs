//! Build the process-belt interposition shim when the sentinel feature is on.
//!
//! The cc crate only produces static archives, but LD_PRELOAD needs a shared
//! object. This script drives the detected C compiler directly with `-shared`.
// ledger-lint:allow:env::var (build script reads cargo metadata, not simulation code)

use std::env;

fn main() {
    let sentinel_on = env::var("CARGO_FEATURE_SENTINEL").is_ok();
    let target_linux = env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "linux");
    if sentinel_on && target_linux {
        let out_dir = env::var("OUT_DIR").expect("OUT_DIR is always set by cargo");
        let shim_path = format!("{out_dir}/libsentinel_shim.so");
        let compiler = cc::Build::new().get_compiler();
        let mut cmd = std::process::Command::new(compiler.path());
        cmd.args(compiler.args());
        cmd.args(["-fPIC", "-shared", "-o", &shim_path]);
        cmd.arg("src/sentinel_shim.c");
        let status = cmd.status().expect("C compiler must run");
        assert!(status.success(), "failed to build the sentinel shim");
        println!("cargo:rustc-cfg=sentinel_shim_built");
        println!("cargo:rustc-env=SENTINEL_SHIM_PATH={shim_path}");
        println!("cargo:rerun-if-changed=src/sentinel_shim.c");
    }
}
