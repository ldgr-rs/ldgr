//! Repository hygiene gate for the worker crate.
//!
//! The worker is a pure client with no database dependency: the external
//! control plane owns persistence. This suite scans the worker's source
//! tree and manifest and fails when database code or dependencies appear,
//! so a reintroduced Postgres/River/SQL path cannot land silently.

/// Database-adjacent tokens that must never appear in the worker crate.
const FORBIDDEN_TOKENS: &[&str] = &[
    "tokio-postgres",
    "postgres",
    "sqlx",
    "sqlite",
    "river.job",
    "pg_dsn",
    "pg-queue",
];

#[test]
fn worker_source_has_no_database_code() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    // Scan every tracked source file (src, tests) plus the manifest. The
    // generated bindings and Cargo.lock are excluded: they mirror the wire
    // contract and the workspace lockfile, not worker code.
    let mut paths = Vec::new();
    for sub in ["src", "tests", "build.rs"] {
        let dir = std::path::Path::new(manifest_dir).join(sub);
        if dir.is_dir() {
            collect_rs_files(&dir, &mut paths);
        } else if dir.is_file() {
            paths.push(dir);
        }
    }
    // The scan file itself names the forbidden tokens; exclude it so the
    // gate does not trip on its own vocabulary.
    paths.retain(|p| p.file_name().is_some_and(|n| n != "repo_hygiene.rs"));
    paths.push(std::path::Path::new(manifest_dir).join("Cargo.toml"));

    let mut offenders: Vec<String> = Vec::new();
    for path in paths {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for token in FORBIDDEN_TOKENS {
            // Case-insensitive match so `Postgres`, `postgres`, and
            // `POSTGRES` all trip the gate.
            let lower = text.to_ascii_lowercase();
            if lower.contains(&token.to_ascii_lowercase()) {
                offenders.push(format!("{}: {}", path.display(), token));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "worker must not contain database code or dependencies:\n{}",
        offenders.join("\n")
    );
}

fn collect_rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}
