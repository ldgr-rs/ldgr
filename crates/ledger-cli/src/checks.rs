//! `ledger doctor` environment checks.
// ledger-lint:allow (host application; doctor reads toolchain files and runs
//   rustc/cargo, unlike simulation code)

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct CheckOutcome {
    /// Check name, also used as the report label.
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct DoctorReport {
    /// Individual check outcomes in display order.
    pub outcomes: Vec<CheckOutcome>,
}

impl DoctorReport {
    pub fn all_ok(&self) -> bool {
        self.outcomes.iter().all(|outcome| outcome.ok)
    }

    /// Renders the report as one line per check.
    ///
    /// Each line is `[ok] <check>: <detail>` or `[FAIL] <check>: <detail>`.
    pub fn render(&self) -> Vec<String> {
        self.outcomes
            .iter()
            .map(|outcome| {
                let tag = if outcome.ok { "[ok]" } else { "[FAIL]" };
                format!("{tag} {}: {}", outcome.name, outcome.detail)
            })
            .collect()
    }
}

pub fn run_doctor(root: &Path) -> DoctorReport {
    let outcomes = vec![
        check_toolchain(root),
        check_lockfile(root),
        check_crate_graph(root),
        check_ci_parity(root),
        check_format_conformance(),
    ];
    DoctorReport { outcomes }
}

/// Verifies the pinned toolchain channel matches the installed rustc.
fn check_toolchain(root: &Path) -> CheckOutcome {
    const NAME: &str = "toolchain";
    let manifest = root.join("rust-toolchain.toml");
    let content = match fs::read_to_string(&manifest) {
        Ok(text) => text,
        Err(error) => {
            return CheckOutcome {
                name: NAME,
                ok: false,
                detail: format!("cannot read rust-toolchain.toml: {error}"),
            };
        }
    };
    let Some(channel) = toml_value(&content, "channel") else {
        return CheckOutcome {
            name: NAME,
            ok: false,
            detail: "rust-toolchain.toml has no channel line".into(),
        };
    };
    let output = match Command::new("rustc").arg("--version").output() {
        Ok(output) => output,
        Err(error) => {
            return CheckOutcome {
                name: NAME,
                ok: false,
                detail: format!("cannot run rustc: {error}"),
            };
        }
    };
    if !output.status.success() {
        return CheckOutcome {
            name: NAME,
            ok: false,
            detail: "rustc --version failed".into(),
        };
    }
    let version_line = String::from_utf8_lossy(&output.stdout);
    let installed = version_line.split_whitespace().nth(1).unwrap_or("?");
    let pinned_specific_version = channel
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_digit());
    if pinned_specific_version && installed != channel {
        return CheckOutcome {
            name: NAME,
            ok: false,
            detail: format!("pinned channel {channel} but installed rustc {installed}"),
        };
    }
    CheckOutcome {
        name: NAME,
        ok: true,
        detail: format!("rustc {installed} matches pinned channel {channel}"),
    }
}

/// Verifies Cargo.lock exists and `cargo metadata --no-deps` parses it.
fn check_lockfile(root: &Path) -> CheckOutcome {
    const NAME: &str = "lockfile";
    let lockfile = root.join("Cargo.lock");
    if !lockfile.is_file() {
        return CheckOutcome {
            name: NAME,
            ok: false,
            detail: "Cargo.lock is missing".into(),
        };
    }
    let manifest = root.join("Cargo.toml");
    let output = Command::new("cargo")
        .args(["metadata", "--no-deps", "--manifest-path"])
        .arg(&manifest)
        .output();
    let output = match output {
        Ok(output) => output,
        Err(error) => {
            return CheckOutcome {
                name: NAME,
                ok: false,
                detail: format!("cannot run cargo metadata: {error}"),
            };
        }
    };
    if output.status.success() {
        CheckOutcome {
            name: NAME,
            ok: true,
            detail: "Cargo.lock present and cargo metadata parses it".into(),
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.lines().next().unwrap_or("unknown error");
        CheckOutcome {
            name: NAME,
            ok: false,
            detail: format!("cargo metadata failed: {detail}"),
        }
    }
}

/// Verifies every workspace member manifest declares a package name and license.
fn check_crate_graph(root: &Path) -> CheckOutcome {
    const NAME: &str = "crate graph";
    let root_manifest = match fs::read_to_string(root.join("Cargo.toml")) {
        Ok(text) => text,
        Err(error) => {
            return CheckOutcome {
                name: NAME,
                ok: false,
                detail: format!("cannot read workspace Cargo.toml: {error}"),
            };
        }
    };
    let members = workspace_members(&root_manifest);
    if members.is_empty() {
        return CheckOutcome {
            name: NAME,
            ok: false,
            detail: "no [workspace.members] found in Cargo.toml".into(),
        };
    }
    let mut bad: Vec<String> = Vec::new();
    for member in &members {
        let manifest_path = root.join(member).join("Cargo.toml");
        let text = match fs::read_to_string(&manifest_path) {
            Ok(text) => text,
            Err(error) => {
                bad.push(format!("{member}: cannot read manifest ({error})"));
                continue;
            }
        };
        let package = package_section(&text);
        if package.name.is_none() {
            bad.push(format!("{member}: missing [package] name"));
        }
        if package.license.is_none() && !package.publish_false {
            bad.push(format!("{member}: missing license line"));
        }
    }
    if bad.is_empty() {
        CheckOutcome {
            name: NAME,
            ok: true,
            detail: format!(
                "{} workspace member manifest(s) parse with name and license",
                members.len()
            ),
        }
    } else {
        CheckOutcome {
            name: NAME,
            ok: false,
            detail: bad.join("; "),
        }
    }
}

/// Verifies the CI workflow file carries the expected gate markers.
fn check_ci_parity(root: &Path) -> CheckOutcome {
    const NAME: &str = "ci parity";
    let ci = root.join(".github/workflows/ci.yml");
    let content = match fs::read_to_string(&ci) {
        Ok(text) => text,
        Err(error) => {
            return CheckOutcome {
                name: NAME,
                ok: false,
                detail: format!("cannot read .github/workflows/ci.yml: {error}"),
            };
        }
    };
    let has_test_gate = content.contains("cargo nextest run --workspace");
    let has_license_gate = content
        .lines()
        .any(|line| line.contains("xtask") && line.contains("licenses"));
    if has_test_gate && has_license_gate {
        CheckOutcome {
            name: NAME,
            ok: true,
            detail: "ci.yml contains the nextest and license gate markers".into(),
        }
    } else {
        CheckOutcome {
            name: NAME,
            ok: false,
            detail: format!(
                "ci.yml markers missing: nextest={has_test_gate} license_gate={has_license_gate}"
            ),
        }
    }
}

/// Verifies a typed entry payload round-trips through the canonical codec.
fn check_format_conformance() -> CheckOutcome {
    const NAME: &str = "format conformance";
    use ledger_format::{
        ActorId, EntryData, EntryKind, EntryPayload, FsWritePayload, PathRef, SequenceNumber,
    };
    let path = b"/tmp/f".to_vec();
    let entry = EntryData {
        format_version: ledger_format::limits::FORMAT_VERSION,
        kind: EntryKind::FsWrite,
        actor: ActorId(1),
        parents: Default::default(),
        vector_clock: vec![0],
        sequence: SequenceNumber(0),
        payload: EntryPayload::FsWrite(FsWritePayload::Write {
            path_ref: PathRef::new([0u8; 32], path),
            offset: 42,
            content: vec![100],
        }),
    };
    let encoded = match entry.try_canonical_bytes() {
        Ok(bytes) => bytes,
        Err(error) => {
            return CheckOutcome {
                name: NAME,
                ok: false,
                detail: format!("cannot encode sample payload: {error}"),
            };
        }
    };
    let decoded = match EntryData::from_canonical_bytes(&encoded) {
        Ok(value) => value,
        Err(error) => {
            return CheckOutcome {
                name: NAME,
                ok: false,
                detail: format!("canonical decode failed: {error}"),
            };
        }
    };
    let roundtrip_ok = decoded == entry && decoded.try_canonical_bytes() == Ok(encoded);
    CheckOutcome {
        name: NAME,
        ok: roundtrip_ok,
        detail: if roundtrip_ok {
            "typed entry payload round-trips through canonical CBOR".into()
        } else {
            "canonical round-trip produced different bytes".into()
        },
    }
}

struct PackageInfo {
    name: Option<String>,
    license: Option<String>,
    publish_false: bool,
}

/// Extracts the `[package]` section of a manifest.
///
/// A manifest that lacks `[package]` yields a section with no fields. The scan
/// is line-based and accepts `license` and `license.workspace` forms.
fn package_section(text: &str) -> PackageInfo {
    let mut info = PackageInfo {
        name: None,
        license: None,
        publish_false: false,
    };
    let mut in_package = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "[package]" {
            in_package = true;
            continue;
        }
        if in_package && trimmed.starts_with('[') {
            break;
        }
        if !in_package {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        match key.trim() {
            "name" => info.name = Some(value.trim().trim_matches('"').to_string()),
            "license" | "license.workspace" => info.license = Some(value.trim().to_string()),
            "publish" => info.publish_false = value.trim() == "false",
            _ => {}
        }
    }
    info
}

/// Returns the `[workspace.members]` list of a root manifest.
///
/// Accepts both the `[workspace.members]` table form and the `members = [...]`
/// key inside the `[workspace]` table, single-line or multi-line.
fn workspace_members(root_manifest: &str) -> Vec<String> {
    let mut members = Vec::new();
    let mut section: Option<&str> = None;
    let mut collecting = false;
    for line in root_manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            collecting = false;
            section = Some(trimmed);
            continue;
        }
        if collecting {
            if let Some(name) = member_name(trimmed) {
                members.push(name);
            }
            if trimmed == "]" || trimmed.ends_with(']') {
                collecting = false;
            }
            continue;
        }
        if section == Some("[workspace.members]") {
            if let Some(name) = member_name(trimmed) {
                members.push(name);
            }
            continue;
        }
        if section == Some("[workspace]")
            && let Some((key, rest)) = trimmed.split_once('=')
            && key.trim() == "members"
        {
            let rest = rest.trim();
            if rest.starts_with('[') {
                let inner = rest.trim_start_matches('[').trim_end_matches(']');
                for item in inner.split(',') {
                    let item = item.trim().trim_matches('"');
                    if !item.is_empty() {
                        members.push(item.to_string());
                    }
                }
                if !rest.ends_with(']') {
                    collecting = true;
                }
            }
        }
    }
    members
}

fn member_name(trimmed: &str) -> Option<String> {
    let item = trimmed.trim_end_matches(',').trim();
    if item.is_empty() || item == "]" {
        return None;
    }
    item.strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .map(str::to_string)
}

fn toml_value(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        let Some((name, value)) = trimmed.split_once('=') else {
            continue;
        };
        if name.trim() == key {
            return Some(value.trim().trim_matches('"').to_string());
        }
    }
    None
}

/// Locates the repository root by walking up for `rust-toolchain.toml`.
///
/// Stops after six levels so a stray install directory cannot be walked
/// indefinitely.
pub fn find_repo_root(start: &Path) -> PathBuf {
    let mut current = Some(start);
    for _ in 0..6 {
        let Some(dir) = current else { break };
        if dir.join("rust-toolchain.toml").is_file() {
            return dir.to_path_buf();
        }
        current = dir.parent();
    }
    start.to_path_buf()
}
