//! `ledger scaffold consensus` templates.
// ledger-lint:allow (host application; writes template files on disk)

use std::fs;
use std::path::{Path, PathBuf};

use crate::scaffold::{ScaffoldError, ScaffoldReport};

const CONSENSUS_MAIN: &str = r#"use ledger_explorer::reference::mini_raft;
use ledger_sim::{Policy, RunConfig, Simulation};
use ledger_explorer::oracle::{Oracle, PropertyOracle};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut seed = [0u8; 32];
    if let Some(arg) = std::env::args().nth(1) {
        // A non-numeric seed argument falls back to the all-zero default.
        if let Ok(v) = arg.parse::<u64>() {
            seed[..8].copy_from_slice(&v.to_le_bytes());
        }
    }
    let mut findings = 0;
    for attempt in 0..16 {
        let mut s = seed;
        s[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());
        let cfg = RunConfig::builder().seed(s).policy(Policy::Random).max_steps(4096).build();
        let (builders, oracle) = mini_raft();
        let run = Simulation::with_tasks(cfg, builders).run()?;
        let v = PropertyOracle { property: oracle, name: "mini-raft".into() }.check(&run);
        if v.violated { findings += 1; }
    }
    println!("findings: {findings}");
    Ok(())
}
"#;

const KV_MAIN: &str = r#"use ledger_explorer::search::search;
use ledger_explorer::workloads::MiniKvWorkload;
use ledger_explorer::{HistoryOracle, KeyValueSpec};
use ledger_sim::{Policy, RunConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let w = MiniKvWorkload;
    let o = HistoryOracle::new(&w, KeyValueSpec::default());
    let cfg = RunConfig::builder().seed([0; 32]).policy(Policy::Random).max_steps(256).build();
    if let Some(f) = search(&w, &o, cfg, 100)? {
        println!("finding: {}", f.verdict.reason);
        println!("findings: 1");
    } else {
        println!("findings: 0");
    }
    Ok(())
}
"#;

const TWO_PC_MAIN: &str = r#"use ledger_explorer::search::search;
use ledger_explorer::workloads::TwoPhaseCommitWorkload;
use ledger_explorer::oracle::AssertionOracle;
use ledger_sim::{Policy, RunConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let w = TwoPhaseCommitWorkload;
    let o = AssertionOracle;
    let cfg = RunConfig::builder().seed([0; 32]).policy(Policy::Random).max_steps(256).build();
    if let Some(f) = search(&w, &o, cfg, 100)? {
        println!("finding: {}", f.verdict.reason);
        println!("findings: 1");
    } else {
        println!("findings: 0");
    }
    Ok(())
}
"#;

/// Scaffold a consensus-family template into `dir`.
///
/// `template` is `consensus` | `kv` | `2pc`. Creates `Cargo.toml` and
/// `src/main.rs`. Refuses to overwrite existing files unless `force` is true.
pub fn scaffold_consensus(
    dir: &Path,
    template: &str,
    force: bool,
) -> Result<ScaffoldReport, ScaffoldError> {
    let chosen = match template {
        "consensus" => CONSENSUS_MAIN,
        "kv" => KV_MAIN,
        "2pc" => TWO_PC_MAIN,
        other => {
            return Err(ScaffoldError::UnknownTemplate(other.to_string()));
        }
    };
    fs::create_dir_all(dir).map_err(|error| ScaffoldError::CreateDir {
        path: dir.to_path_buf(),
        error,
    })?;
    let src_dir = dir.join("src");
    fs::create_dir_all(&src_dir).map_err(|error| ScaffoldError::CreateDir {
        path: src_dir.clone(),
        error,
    })?;
    let package_name = sanitize_package_name(dir);
    let explorer_path = locate_crate_path(dir, "crates/ledger-explorer");
    let sim_path = locate_crate_path(dir, "crates/ledger-sim");
    let cargo = consensus_cargo_toml(&package_name, &explorer_path, &sim_path);
    let targets: Vec<(PathBuf, Vec<u8>)> = vec![
        (dir.join("Cargo.toml"), cargo.into_bytes()),
        (src_dir.join("main.rs"), chosen.as_bytes().to_vec()),
    ];
    if !force {
        for (path, _) in &targets {
            if path.exists() {
                return Err(ScaffoldError::RefuseOverwrite(path.clone()));
            }
        }
    }
    let mut report = ScaffoldReport {
        dir: dir.to_path_buf(),
        created: Vec::new(),
        skipped: Vec::new(),
    };
    for (path, bytes) in targets {
        fs::write(&path, &bytes).map_err(|error| ScaffoldError::Write {
            path: path.clone(),
            error,
        })?;
        report.created.push(path);
    }
    Ok(report)
}

fn sanitize_package_name(dir: &Path) -> String {
    if let Some(name) = dir.file_name().and_then(|s| s.to_str()) {
        let mut out = String::with_capacity(name.len());
        for ch in name.chars() {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                out.push(ch.to_ascii_lowercase());
            } else if ch == '.' || ch == ' ' {
                out.push('-');
            }
        }
        if !out.is_empty() {
            if out
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit() || c == '-')
            {
                return format!("scaffold-{out}");
            }
            return out;
        }
    }
    "scaffold-consensus".into()
}

fn locate_crate_path(dir: &Path, crate_rel: &str) -> String {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = normalize_path(&manifest_dir.join("../../"));
    let target = normalize_path(&repo_root.join(crate_rel));
    let from_abs = if dir.is_absolute() {
        normalize_path(dir)
    } else {
        std::env::current_dir()
            .map(|cwd| normalize_path(&cwd.join(dir)))
            .unwrap_or_else(|_| normalize_path(dir))
    };
    if let Some(rel) = relative_path(&from_abs, &target) {
        rel.display().to_string()
    } else {
        target.display().to_string()
    }
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            _ => out.push(comp.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        out
    }
}

fn relative_path(from: &Path, to: &Path) -> Option<PathBuf> {
    let from_comps: Vec<_> = from.components().collect();
    let to_comps: Vec<_> = to.components().collect();
    let mut common = 0usize;
    for (a, b) in from_comps.iter().zip(to_comps.iter()) {
        if a == b {
            common += 1;
        } else {
            break;
        }
    }
    if common == 0 {
        return None;
    }
    let mut rel = PathBuf::new();
    for _ in common..from_comps.len() {
        rel.push("..");
    }
    for comp in to_comps.iter().skip(common) {
        rel.push(comp.as_os_str());
    }
    if rel.as_os_str().is_empty() {
        Some(PathBuf::from("."))
    } else {
        Some(rel)
    }
}

fn consensus_cargo_toml(package_name: &str, explorer_path: &str, sim_path: &str) -> String {
    format!(
        r#"[package]
name = "{package_name}"
version = "0.1.0"
edition = "2024"
description = "Scaffolded ledger consensus example"

[dependencies]
ledger-explorer = {{ path = "{explorer_path}" }}
ledger-sim = {{ path = "{sim_path}" }}

[workspace]
"#
    )
}

#[cfg(test)]
mod tests {
    use super::{CONSENSUS_MAIN, KV_MAIN, TWO_PC_MAIN};

    #[test]
    fn templates_under_100_lines() {
        assert!(
            CONSENSUS_MAIN.lines().count() < 100,
            "consensus template must be <100 lines"
        );
        assert!(
            KV_MAIN.lines().count() < 100,
            "kv template must be <100 lines"
        );
        assert!(
            TWO_PC_MAIN.lines().count() < 100,
            "2pc template must be <100 lines"
        );
    }

    #[test]
    fn consensus_template_calls_mini_raft() {
        assert!(
            CONSENSUS_MAIN.contains("mini_raft"),
            "consensus template must contain mini_raft marker"
        );
    }

    #[test]
    fn kv_template_calls_mini_kv() {
        assert!(
            KV_MAIN.contains("MiniKvWorkload"),
            "kv template must contain MiniKvWorkload"
        );
    }

    #[test]
    fn two_pc_template_calls_two_pc() {
        assert!(
            TWO_PC_MAIN.contains("TwoPhaseCommitWorkload"),
            "2pc template must contain TwoPhaseCommitWorkload"
        );
    }
}
