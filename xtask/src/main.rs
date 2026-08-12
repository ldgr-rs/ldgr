//! Workspace automation: `cargo xtask licenses`, `cargo xtask doctor`.
//!
//! `licenses` enforces the crate-level licensing split in CI:
//!
//! - `ledger-sim`, `ledger-explorer`: AGPL-3.0-or-later (the engine).
//! - `ledger-format`, `ledger-journal`, `wasm-guest`: MIT OR Apache-2.0.
//! - everything else: Apache-2.0.
//!
//! `doctor` checks the onboarding environment: pinned toolchain, committed
//! lockfile, wasm target, and workflow files.
//!
//! Exits 0 when every check passes, 1 otherwise.

use std::path::Path;

fn expected_license(crate_name: &str) -> &'static str {
    match crate_name {
        "ledger-sim" | "ledger-explorer" => "AGPL-3.0-or-later",
        "ledger-format" | "ledger-journal" | "wasm-guest" => "MIT OR Apache-2.0",
        _ => "Apache-2.0",
    }
}

fn workspace_license(root: &Path) -> String {
    let text = std::fs::read_to_string(root.join("Cargo.toml")).expect("read workspace Cargo.toml");
    let mut in_package = false;
    for line in text.lines() {
        if line.trim() == "[workspace.package]" {
            in_package = true;
            continue;
        }
        if in_package && line.trim().starts_with('[') {
            break;
        }
        if in_package
            && let Some(value) = line.split_once('=')
            && value.0.trim() == "license"
        {
            return value.1.trim().trim_matches('"').to_string();
        }
    }
    panic!("[workspace.package] license not found");
}

fn license_from_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed == "license.workspace = true" {
        return Some("workspace".to_string());
    }
    if let Some((key, value)) = trimmed.split_once('=')
        && key.trim() == "license"
    {
        return Some(value.trim().trim_matches('"').to_string());
    }
    None
}

fn cmd_licenses(root: &Path) {
    let crates_dir = root.join("crates");
    let workspace_license = workspace_license(root);
    let mut failures = 0usize;

    for entry in std::fs::read_dir(&crates_dir).expect("crates/ must exist") {
        let dir = entry.expect("read_dir entry").path();
        if !dir.is_dir() {
            continue;
        }
        let name = dir
            .file_name()
            .expect("crate dir name")
            .to_string_lossy()
            .to_string();
        let manifest = dir.join("Cargo.toml");
        if !manifest.exists() {
            continue;
        }
        let text = std::fs::read_to_string(&manifest).expect("read Cargo.toml");
        let license_line = text
            .lines()
            .find(|line| {
                let t = line.trim_start();
                t.starts_with("license") || t.starts_with("license.workspace")
            })
            .and_then(license_from_line)
            .unwrap_or_default();
        let actual = if license_line == "workspace" {
            workspace_license.clone()
        } else {
            license_line
        };
        let expected = expected_license(&name);
        if actual != expected {
            eprintln!("license mismatch: {name}: expected {expected}, got {actual:?}");
            failures += 1;
        } else {
            println!("ok: {name} ({actual})");
        }
    }

    if failures > 0 {
        eprintln!("{failures} license violation(s)");
        std::process::exit(1);
    }
    println!("licenses: all crates match the AGPL/Apache/MIT split");
}

fn check(name: &str, ok: bool, failures: &mut usize) {
    if ok {
        println!("ok: {name}");
    } else {
        eprintln!("fail: {name}");
        *failures += 1;
    }
}

fn git_tracks(root: &Path, path: &str) -> bool {
    let output = std::process::Command::new("git")
        .args(["ls-files", "--error-unmatch", path])
        .current_dir(root)
        .output();
    output.map(|out| out.status.success()).unwrap_or(false)
}

fn cmd_doctor(root: &Path) {
    let mut failures = 0usize;

    let toolchain_text = std::fs::read_to_string(root.join("rust-toolchain.toml"));
    let toolchain_ok = toolchain_text
        .as_deref()
        .ok()
        .is_some_and(|text| text.contains("1.97"));
    check(
        "rust-toolchain.toml exists and pins channel 1.97",
        toolchain_ok,
        &mut failures,
    );

    let wasm_ok = toolchain_text
        .as_deref()
        .ok()
        .is_some_and(|text| text.contains("wasm32-wasip1"));
    check(
        "wasm32-wasip1 target declared in rust-toolchain.toml",
        wasm_ok,
        &mut failures,
    );

    let lockfile_ok = root.join("Cargo.lock").exists() && git_tracks(root, "Cargo.lock");
    check(
        "Cargo.lock exists at the repo root and is tracked by git",
        lockfile_ok,
        &mut failures,
    );

    let workflows_dir = root.join(".github").join("workflows");
    let workflows_ok = workflows_dir.is_dir();
    check(
        ".github/workflows directory exists",
        workflows_ok,
        &mut failures,
    );
    if workflows_ok {
        let mut files: Vec<_> = std::fs::read_dir(&workflows_dir)
            .expect("read workflows dir")
            .map(|entry| entry.expect("workflows dir entry").path())
            .filter(|path| {
                path.extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext == "yml" || ext == "yaml")
            })
            .collect();
        files.sort();
        if files.is_empty() {
            check("at least one workflow file present", false, &mut failures);
        }
        for file in files {
            let name = file
                .file_name()
                .expect("workflow file name")
                .to_string_lossy()
                .to_string();
            let ok = std::fs::read_to_string(&file)
                .map(|text| !text.trim().is_empty() && text.contains("jobs:"))
                .unwrap_or(false);
            let label = format!("workflow {name} is non-empty and declares jobs");
            check(&label, ok, &mut failures);
        }
        println!(
            "note: workflow YAML gets a structural check only; full parsing needs a yaml dependency and is skipped"
        );
    }

    if failures > 0 {
        eprintln!("{failures} doctor check(s) failed");
        std::process::exit(1);
    }
    println!("doctor: environment is ready (toolchain, lockfile, wasm target, workflows)");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: cargo xtask <licenses|doctor>");
        std::process::exit(2);
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must live one level below the workspace root");

    match args[1].as_str() {
        "licenses" => cmd_licenses(root),
        "doctor" => cmd_doctor(root),
        other => {
            eprintln!("unknown subcommand: {other}");
            eprintln!("usage: cargo xtask <licenses|doctor>");
            std::process::exit(2);
        }
    }
}
