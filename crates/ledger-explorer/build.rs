//! Emit compile-time build facts for execution identity.
//!
//! The target triple and build profile are captured here and re-emitted as
//! rustc env vars so the identity capture in `src/identity.rs` reads them
//! with `option_env!`. The other build facts (revision, dirty state,
//! toolchain) are consumed directly from the `LDGR_*` build environment by
//! `option_env!` in `src/identity.rs`.
// ledger-lint:allow:env::var (build script reads cargo metadata, not simulation code)

use std::env;

fn main() {
    if let Ok(target) = env::var("TARGET") {
        println!("cargo:rustc-env=LDGR_TARGET={target}");
    }
    if let Ok(profile) = env::var("PROFILE") {
        println!("cargo:rustc-env=LDGR_BUILD_PROFILE={profile}");
    }
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=PROFILE");
    println!("cargo:rerun-if-env-changed=LDGR_ENGINE_SHA");
    println!("cargo:rerun-if-env-changed=LDGR_DIRTY");
    println!("cargo:rerun-if-env-changed=LDGR_TOOLCHAIN");
}
