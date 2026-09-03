//! Scan: no old payload shapes or alternate format paths remain.
//!
//! The banned tokens name removed scalar shapes, the legacy crash operator,
//! and prior-format decoder paths. Any resurrection in tracked Rust sources
//! fails this test.

use std::fs;
use std::path::Path;

/// Banned tokens: old payload shapes, legacy crash operator, prior decoders.
const BANNED: &[&str] = &[
    "Payload::Value",
    "Payload::Number",
    "Payload::Pair",
    "payload: Payload",
    "CrashOperator",
    "apply_crash_operator",
    "decode_v1_",
    "legacy_payload",
    "LegacyEntryPayload",
];

fn repo_root() -> &'static Path {
    // Crate manifest is two levels below the workspace root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root from crate manifest")
}

fn rust_sources(root: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if entry.file_name() == "target" {
                continue;
            }
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_old_payload_shapes_or_alternate_format_paths() {
    let mut sources = Vec::new();
    rust_sources(repo_root(), &mut sources);
    assert!(
        sources.len() > 200,
        "scan walked {} rust sources; expected the full workspace",
        sources.len()
    );
    let mut hits: Vec<(String, usize, &str)> = Vec::new();
    for source in sources {
        // The BANNED list lives here; do not scan the scan itself.
        if source.ends_with("tests/repo_hygiene.rs") {
            continue;
        }
        let text = fs::read_to_string(&source).unwrap_or_default();
        for (line_number, line) in text.lines().enumerate() {
            for token in BANNED {
                if line.contains(token) {
                    hits.push((
                        source
                            .strip_prefix(repo_root())
                            .unwrap_or(&source)
                            .display()
                            .to_string(),
                        line_number + 1,
                        token,
                    ));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "old payload shapes or alternate format paths remain:\n{}",
        hits.iter()
            .map(|(file, line, token)| format!("{file}:{line}: {token}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
