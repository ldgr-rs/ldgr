//! Workspace automation: `cargo xtask licenses`, `cargo xtask doctor`.
//! `licenses` enforces the crate license split and the license-boundary
//! architecture; `doctor` checks the onboarding environment.

use std::path::Path;
use std::path::PathBuf;

/// Composition roots allowed to import AGPL engine code.
const COMPOSITION_ROOTS: [&str; 3] = ["ledger-cli", "ledger-worker", "rt-server"];

/// Codec crates pinned to contract layers.
const CODEC_CRATES: [&str; 1] = ["ledger-adapters"];

/// Journal persistence internals codec crates must not touch.
const JOURNAL_INTERNALS: [&str; 4] = [
    "ledger_journal::segment::",
    "ledger_journal::persistent",
    "ledger_journal::snapshot_store",
    "ledger_journal::archive::",
];

/// Role dependencies codec crates must not grow.
const ROLE_DEPENDENCIES: [&str; 1] = ["tokio"];

fn expected_license(crate_name: &str) -> &'static str {
    match crate_name {
        "ledger-sim" | "ledger-explorer" | "rt-server" => "AGPL-3.0-or-later",
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

/// Package name declared in a manifest's `[package]` section.
fn package_name(manifest_text: &str) -> Option<String> {
    let mut in_package = false;
    for line in manifest_text.lines() {
        if line.trim() == "[package]" {
            in_package = true;
            continue;
        }
        if in_package && line.trim().starts_with('[') {
            break;
        }
        if in_package
            && let Some((key, value)) = line.split_once('=')
            && key.trim() == "name"
        {
            return Some(value.trim().trim_matches('"').to_string());
        }
    }
    None
}

/// Workspace-internal dependency names declared under `[dependencies]`.
/// A name counts when it matches a known workspace crate, which covers both
/// explicit `path = ...` forms and `workspace = true` inheritance.
/// Dev and build dependencies do not propagate to consumers and are skipped.
/// When `mandatory_only` is true, optional dependencies are excluded.
fn internal_dependencies(
    manifest_text: &str,
    workspace_names: &[String],
    mandatory_only: bool,
) -> Vec<String> {
    let mut in_deps = false;
    let mut found = Vec::new();
    for line in manifest_text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_deps = trimmed == "[dependencies]";
            continue;
        }
        if in_deps
            && let Some((key, val)) = trimmed.split_once('=')
            && workspace_names.iter().any(|n| n == key.trim())
        {
            if mandatory_only && val.contains("optional = true") {
                continue;
            }
            found.push(key.trim().to_string());
        }
    }
    found.sort();
    found.dedup();
    found
}

/// True when any transitive path from `start` reaches an AGPL crate.
fn reaches_agpl(start: &str, graph: &[(String, Vec<String>)], agpl: &[&str]) -> bool {
    let mut stack: Vec<&str> = vec![start];
    let mut seen: Vec<String> = Vec::new();
    while let Some(current) = stack.pop() {
        if agpl.contains(&current) && current != start {
            return true;
        }
        if let Some((_, deps)) = graph.iter().find(|(name, _)| name == current) {
            for dep in deps {
                if !seen.contains(dep) {
                    seen.push(dep.clone());
                    stack.push(dep);
                }
            }
        }
    }
    false
}

/// Source files under a directory tree, recursive.
fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = match std::fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// True when every direct AGPL dependency of a crate is optional and absent
/// from its default feature set: the AGPL edge exists only when a consumer
/// opts in.
fn agpl_edges_opt_in(manifest_text: &str, direct_agpl: &[&str]) -> bool {
    if direct_agpl.is_empty() {
        return false;
    }
    let mut in_deps = false;
    let mut in_features = false;
    let mut all_optional = true;
    for line in manifest_text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_deps = trimmed == "[dependencies]";
            in_features = trimmed == "[features]";
            continue;
        }
        if in_deps
            && let Some((key, value)) = trimmed.split_once('=')
            && direct_agpl.contains(&key.trim())
            && !value.contains("optional")
        {
            all_optional = false;
        }
        if in_features
            && let Some((key, value)) = trimmed.split_once('=')
            && key.trim() == "default"
            && direct_agpl.iter().any(|d| value.contains(d))
        {
            all_optional = false;
        }
    }
    all_optional
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

    // --- license-boundary architecture graph ---
    let mut manifests: Vec<(String, PathBuf, String)> = Vec::new();
    let mut collect = |dir: &Path| {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let manifest = path.join("Cargo.toml");
                if path.is_dir() && manifest.exists() {
                    let text = std::fs::read_to_string(&manifest).unwrap_or_default();
                    let name = package_name(&text).unwrap_or_else(|| {
                        path.file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default()
                    });
                    manifests.push((name, path, text));
                }
            }
        }
    };
    collect(&crates_dir);
    collect(&root.join("xtask"));

    let names: Vec<String> = manifests.iter().map(|(n, _, _)| n.clone()).collect();
    let graph: Vec<(String, Vec<String>)> = manifests
        .iter()
        .map(|(name, _, text)| (name.clone(), internal_dependencies(text, &names, false)))
        .collect();
    let mandatory_graph: Vec<(String, Vec<String>)> = manifests
        .iter()
        .map(|(name, _, text)| (name.clone(), internal_dependencies(text, &names, true)))
        .collect();
    let agpl: Vec<&str> = manifests
        .iter()
        .filter(|(name, _, _)| expected_license(name) == "AGPL-3.0-or-later")
        .map(|(name, _, _)| name.as_str())
        .collect();

    for (name, deps) in &graph {
        println!("deps: {name} -> {}", deps.join(", "));
    }

    for (name, _, _) in &manifests {
        if expected_license(name) == "AGPL-3.0-or-later" {
            continue;
        }
        if COMPOSITION_ROOTS.contains(&name.as_str()) {
            println!("ok: {name} may import AGPL engine code (declared composition root)");
            continue;
        }
        let mandatory_reaches = reaches_agpl(name, &mandatory_graph, &agpl);
        let direct_agpl: Vec<&str> = graph
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, deps)| {
                deps.iter()
                    .filter(|d| agpl.contains(&d.as_str()))
                    .map(|d| d.as_str())
                    .collect()
            })
            .unwrap_or_default();

        if mandatory_reaches {
            eprintln!(
                "license boundary violation: {name} must not reach AGPL crates {agpl:?}; \
                 only composition roots {COMPOSITION_ROOTS:?} may import the engine, \
                 and library edges must be optional"
            );
            failures += 1;
        } else if !direct_agpl.is_empty() {
            let text = manifests
                .iter()
                .find(|(n, _, _)| n == name)
                .map(|(_, _, t)| t.as_str())
                .unwrap_or("");
            if agpl_edges_opt_in(text, &direct_agpl) {
                println!("ok: {name} reaches AGPL only behind optional, non-default features");
            } else {
                eprintln!(
                    "license boundary violation: {name} directly depends on AGPL crates {direct_agpl:?} without optional configuration"
                );
                failures += 1;
            }
        } else {
            println!("ok: {name} stays clear of AGPL transitive deps");
        }
    }

    // --- codec-crate boundaries ---
    for codec in CODEC_CRATES {
        let Some((_, dir, text)) = manifests.iter().find(|(n, _, _)| n == codec) else {
            continue;
        };
        let allowed_engines = ["ledger-format", "ledger-journal"];
        let adapter_deps = internal_dependencies(text, &names, false);
        let engine_deps: Vec<&String> = adapter_deps
            .iter()
            .filter(|d| d.starts_with("ledger-") || d.starts_with("ldgr-"))
            .collect();
        let mut codec_failures = 0usize;
        for dep in engine_deps {
            if !allowed_engines.contains(&dep.as_str()) {
                eprintln!(
                    "codec boundary violation: {codec} depends on {dep}; codec crates may \
                     depend only on contract layers {allowed_engines:?}"
                );
                failures += 1;
                codec_failures += 1;
            }
        }
        for pattern in JOURNAL_INTERNALS {
            let hits: Vec<PathBuf> = rust_sources(dir)
                .into_iter()
                .filter(|path| {
                    std::fs::read_to_string(path)
                        .map(|source| source.contains(pattern))
                        .unwrap_or(false)
                })
                .collect();
            if !hits.is_empty() {
                eprintln!(
                    "codec boundary violation: {codec} references journal internal {pattern} in {} file(s); \
                     codecs speak envelopes and entry kinds only",
                    hits.len()
                );
                failures += 1;
                codec_failures += 1;
            }
        }
        for role_dep in ROLE_DEPENDENCIES {
            if text
                .lines()
                .any(|line| line.trim().starts_with(role_dep) && line.contains('='))
            {
                eprintln!(
                    "codec boundary violation: {codec} declares role dependency {role_dep}; \
                     runtime/queue behavior belongs to worker and control-plane repos"
                );
                failures += 1;
                codec_failures += 1;
            }
        }
        if codec_failures == 0 {
            println!("ok: {codec} stays a contract-layer codec");
        }
    }

    if failures > 0 {
        eprintln!("{failures} total violation(s)");
        std::process::exit(1);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_dependencies_skip_dev_and_external() {
        let manifest = "\
[dependencies]\n\nledger-journal = { path = ../ledger-journal }\nserde_json = 1\ntokio.workspace = true\n\n[dev-dependencies]\nledger-explorer = { path = ../ledger-explorer }\n";
        let ws = vec!["ledger-journal".to_string(), "ledger-explorer".to_string()];
        let deps = internal_dependencies(manifest, &ws, false);
        assert_eq!(deps, vec!["ledger-journal".to_string()]);
    }

    #[test]
    fn agpl_reachability_detects_transitive_chain() {
        let graph = vec![
            ("app".to_string(), vec!["mid".to_string()]),
            ("mid".to_string(), vec!["ledger-sim".to_string()]),
            ("ledger-sim".to_string(), vec![]),
        ];
        assert!(reaches_agpl("app", &graph, &["ledger-sim"]));
        assert!(!reaches_agpl("ledger-sim", &graph, &["ledger-sim"]));
        let clean = vec![
            ("app".to_string(), vec!["util".to_string()]),
            ("util".to_string(), vec![]),
        ];
        assert!(!reaches_agpl("app", &clean, &["ledger-sim"]));
    }

    #[test]
    fn package_and_internals_parsing() {
        assert_eq!(
            package_name("[package]\nname = \"x\"\n"),
            Some("x".to_string())
        );
        assert_eq!(package_name("[dependencies]\nname = \"y\"\n"), None);
    }
}
