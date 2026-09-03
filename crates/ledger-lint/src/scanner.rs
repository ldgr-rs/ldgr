//! Static scanner detecting forbidden ambient APIs in deterministic codebase paths.
// ledger-lint:allow (the pattern table and leak tests must reference forbidden APIs by definition)

use std::fs;
use std::path::{Path, PathBuf};

use walkdir::{DirEntry, WalkDir};

/// Forbidden ambient API patterns for simulation paths.
pub const FORBIDDEN_PATTERNS: &[(&str, &str)] = &[
    (
        "Instant::now()",
        "std::time::Instant reads wall-clock time; use Effects::now_ticks()",
    ),
    (
        "SystemTime::now()",
        "std::time::SystemTime reads wall-clock time; use Effects::now_ticks()",
    ),
    (
        "rand::thread_rng()",
        "rand::thread_rng() uses OS entropy; use SeedTree / Effects::rng()",
    ),
    (
        "thread::spawn",
        "std::thread::spawn introduces uncontrolled concurrency; use Simulation::with_tasks / Boundary::spawn_task",
    ),
    ("std::fs::", "Ambient std::fs bypasses SimFs; use SimFs"),
    ("std::net::", "Ambient std::net bypasses SimNet; use SimNet"),
    (
        "env::var",
        "std::env::var reads ambient environment; pass inputs via Effects / SeedTree",
    ),
    (
        "wasm_time::",
        "wasm_time reads ambient time; use VirtualTime / Effects",
    ),
    (
        "web_time::",
        "web_time reads ambient time; use VirtualTime / Effects",
    ),
    (
        "instant::",
        "instant crate reads ambient time; use VirtualTime / Effects",
    ),
    (
        "getrandom::getrandom",
        "getrandom reads OS entropy; use SeedTree / Effects::rng",
    ),
    (
        "getrandom::fill",
        "getrandom::fill reads OS entropy; use SeedTree / Effects::rng",
    ),
    (
        "libc::clock_gettime",
        "libc clock reads ambient time; use VirtualTime / Effects",
    ),
    (
        "libc::gettimeofday",
        "libc gettimeofday reads ambient time; use VirtualTime / Effects",
    ),
    (
        "libc::getrandom",
        "libc getrandom reads OS entropy; use SeedTree",
    ),
    (
        "libc::getentropy",
        "libc getentropy reads OS entropy; use SeedTree",
    ),
    (
        "libc::time",
        "libc time() reads ambient time; use VirtualTime",
    ),
    (
        "getauxval",
        "getauxval locates the vDSO page for ambient clock reads; use VirtualTime / Effects",
    ),
    (
        "fn time()",
        "FFI time() reads ambient wall clock; use VirtualTime / Effects",
    ),
    (
        "fn gettimeofday(",
        "FFI gettimeofday reads ambient wall clock; use VirtualTime / Effects",
    ),
    (
        "fn clock_gettime(",
        "FFI clock_gettime reads ambient wall clock; use VirtualTime / Effects",
    ),
    ("rdrand", "RDRAND reads hardware entropy; use SeedTree"),
    ("rdseed", "RDSEED reads hardware entropy; use SeedTree"),
    ("syscall(", "raw syscall bypasses the sim boundary"),
    (
        "std::env::args",
        "ambient process args; pass inputs via Effects",
    ),
];

/// Bare-module prefixes for `use std::fs;`-style imports (segment-start match).
const BARE_PREFIX_PATTERNS: &[(&str, &str)] = &[
    ("fs::", "Ambient std::fs bypasses SimFs; use SimFs"),
    ("net::", "Ambient std::net bypasses SimNet; use SimNet"),
    (
        "getrandom::",
        "getrandom crate reads OS entropy; use SeedTree / Effects::rng",
    ),
    ("env::args", "ambient process args; pass inputs via Effects"),
];

/// Simulation-path prefixes where hash-iteration order is a replay risk.
const WARN_SCOPE_PREFIXES: &[&str] = &[
    "crates/ledger-sim/src/",
    "crates/wasm-guest/src/",
    "crates/ldgr-rt/src/",
    "guests/",
];

/// Warn-level patterns for the simulation path.
const WARN_PATTERNS: &[(&str, &str)] = &[
    (
        "HashMap",
        "hash-map iteration order is unstable across builds; sort before iterating, derive order from the journal, or use BTreeMap; allow-marker lookup-only use",
    ),
    (
        "HashSet",
        "hash-set iteration order is unstable across builds; sort before iterating or use BTreeSet; allow-marker membership-only use",
    ),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintViolation {
    pub pattern: String,
    pub line_number: usize,
    pub line_content: String,
    pub advice: String,
}

/// Marker exempting a file from forbidden patterns (file-scoped).
pub const ALLOW_MARKER: &str = "ledger-lint:allow";

/// Prefix for per-pattern allow directives.
const ALLOW_PREFIX: &str = "ledger-lint:allow:";

/// Return true when `source` carries a full-file allow marker.
fn has_full_allow_marker(source: &str) -> bool {
    source.lines().any(|line| {
        let mut rest = line;
        while let Some(idx) = rest.find(ALLOW_MARKER) {
            if !rest[idx + ALLOW_MARKER.len()..].starts_with(':') {
                return true;
            }
            rest = &rest[idx + 1..];
        }
        false
    })
}

fn collect_pattern_exemptions(source: &str) -> Vec<String> {
    let mut exemptions = Vec::new();
    for line in source.lines() {
        let mut rest = line;
        while let Some(idx) = rest.find(ALLOW_PREFIX) {
            let after = &rest[idx + ALLOW_PREFIX.len()..];
            let end = after.find(char::is_whitespace).unwrap_or(after.len());
            let sub = &after[..end];
            if !sub.is_empty() {
                exemptions.push(sub.to_string());
            }
            rest = &rest[idx + 1..];
        }
    }
    exemptions
}

/// Result of scanning one source path (file or directory tree).
#[derive(Debug, Default)]
pub struct ScanResult {
    /// Files that produced at least one violation, paired with their violations.
    pub violating_files: Vec<(PathBuf, Vec<LintViolation>)>,
    /// Files that produced at least one warn-level finding, paired with them.
    pub warning_files: Vec<(PathBuf, Vec<LintViolation>)>,
    /// Number of source files scanned, excluding allow-marked files.
    pub files_scanned: usize,
    /// Non-fatal errors encountered while walking directories or reading files.
    pub errors: Vec<String>,
}

impl ScanResult {
    pub fn total_violations(&self) -> usize {
        self.violating_files
            .iter()
            .map(|(_path, violations)| violations.len())
            .sum()
    }

    /// Total warn-level findings across all scanned files.
    pub fn total_warnings(&self) -> usize {
        self.warning_files
            .iter()
            .map(|(_path, warnings)| warnings.len())
            .sum()
    }

    fn scan_file(&mut self, path: &Path) {
        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(err) => {
                self.errors
                    .push(format!("cannot read {}: {err}", path.display()));
                return;
            }
        };
        if has_full_allow_marker(&content) {
            return;
        }
        self.files_scanned += 1;
        let violations = scan_source(&content);
        if !violations.is_empty() {
            self.violating_files.push((path.to_path_buf(), violations));
        }
        let warnings = scan_warnings(path, &content);
        if !warnings.is_empty() {
            self.warning_files.push((path.to_path_buf(), warnings));
        }
    }
}

/// Scan a source file or a directory tree of `.rs` files.
/// Directories walk recursively, skipping `target/`, hidden, and `tests/`.
pub fn scan_rs_files(path: &Path) -> ScanResult {
    let mut result = ScanResult::default();
    if path.is_file() {
        result.scan_file(path);
        return result;
    }
    if !path.is_dir() {
        result.errors.push(format!(
            "path is not a file or directory: {}",
            path.display()
        ));
        return result;
    }
    for entry in WalkDir::new(path).into_iter().filter_entry(should_descend) {
        match entry {
            Ok(entry) if entry.file_type().is_file() && is_rs_file(entry.path()) => {
                result.scan_file(entry.path());
            }
            Ok(_) => {}
            Err(err) => result.errors.push(err.to_string()),
        }
    }
    result
}

fn should_descend(entry: &DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return true;
    }
    let name = entry.file_name().to_string_lossy();
    if name.as_ref() == "target"
        || name.as_ref().starts_with('.')
        || name.as_ref() == "tests"
        || name.as_ref() == "gen"
    {
        return false;
    }
    true
}

fn is_rs_file(path: &Path) -> bool {
    path.extension().and_then(|ext| ext.to_str()) == Some("rs")
}

/// Scan Rust source code for forbidden ambient API occurrences.
pub fn scan_source(source: &str) -> Vec<LintViolation> {
    if has_full_allow_marker(source) {
        return Vec::new();
    }
    let exemptions = collect_pattern_exemptions(source);
    let exempted: Vec<bool> = FORBIDDEN_PATTERNS
        .iter()
        .map(|(pattern, _)| exemptions.iter().any(|sub| pattern.contains(sub)))
        .collect();
    let bare_exempted: Vec<bool> = BARE_PREFIX_PATTERNS
        .iter()
        .map(|(pattern, _)| exemptions.iter().any(|sub| pattern.contains(sub)))
        .collect();
    let mut violations = Vec::new();
    let mut in_block_comment = false;
    for (line_idx, line) in source.lines().enumerate() {
        let code = strip_comments(line, &mut in_block_comment);
        let trimmed = code.trim();
        if trimmed.is_empty() || is_import_line(trimmed) {
            continue;
        }
        for (idx, &(pattern, advice)) in FORBIDDEN_PATTERNS.iter().enumerate() {
            if exempted[idx] {
                continue;
            }
            if code.contains(pattern) {
                violations.push(LintViolation {
                    pattern: pattern.to_string(),
                    line_number: line_idx + 1,
                    line_content: trimmed.to_string(),
                    advice: advice.to_string(),
                });
            }
        }
        for (idx, &(pattern, advice)) in BARE_PREFIX_PATTERNS.iter().enumerate() {
            if bare_exempted[idx] {
                continue;
            }
            if contains_bare_prefix(&code, pattern) {
                violations.push(LintViolation {
                    pattern: pattern.to_string(),
                    line_number: line_idx + 1,
                    line_content: trimmed.to_string(),
                    advice: advice.to_string(),
                });
            }
        }
    }
    violations
}

/// Return true when `path` is inside the warn scope for hash collections.
fn is_warn_scoped(path: &Path) -> bool {
    let text = path.to_string_lossy().replace('\\', "/");
    WARN_SCOPE_PREFIXES
        .iter()
        .any(|prefix| text.starts_with(prefix))
}

/// Scan one source file for warn-level determinism risks.
pub fn scan_warnings(path: &Path, source: &str) -> Vec<LintViolation> {
    if !is_warn_scoped(path) || has_full_allow_marker(source) {
        return Vec::new();
    }
    let exemptions = collect_pattern_exemptions(source);
    let exempted: Vec<bool> = WARN_PATTERNS
        .iter()
        .map(|(pattern, _)| exemptions.iter().any(|sub| pattern.contains(sub)))
        .collect();
    let mut warnings = Vec::new();
    let mut in_block_comment = false;
    for (line_idx, line) in source.lines().enumerate() {
        let code = strip_comments(line, &mut in_block_comment);
        let trimmed = code.trim();
        if trimmed.is_empty() || is_import_line(trimmed) {
            continue;
        }
        for (idx, &(pattern, advice)) in WARN_PATTERNS.iter().enumerate() {
            if exempted[idx] {
                continue;
            }
            if code.contains(pattern) {
                warnings.push(LintViolation {
                    pattern: pattern.to_string(),
                    line_number: line_idx + 1,
                    line_content: trimmed.to_string(),
                    advice: advice.to_string(),
                });
            }
        }
    }
    warnings
}

/// Remove line and block comments from one source line.
fn strip_comments(line: &str, in_block_comment: &mut bool) -> String {
    let bytes = line.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut pos = 0;
    if *in_block_comment {
        match find_bytes(bytes, b"*/", 0) {
            Some(end) => {
                *in_block_comment = false;
                pos = end + 2;
            }
            None => return String::new(),
        }
    }
    while pos < bytes.len() {
        if bytes[pos..].starts_with(b"//") {
            break;
        }
        if bytes[pos..].starts_with(b"/*") {
            match find_bytes(bytes, b"*/", pos + 2) {
                Some(end) => {
                    pos = end + 2;
                    continue;
                }
                None => {
                    *in_block_comment = true;
                    break;
                }
            }
        }
        out.push(bytes[pos]);
        pos += 1;
    }
    // Lossy: an undecodable line keeps its bytes as U+FFFD so detection still
    // sees the surrounding code instead of an empty string.
    String::from_utf8_lossy(&out).into_owned()
}

fn find_bytes(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    haystack
        .get(start..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| offset + start)
}

/// Return true when `code` contains `prefix` at a path-segment start.
fn contains_bare_prefix(code: &str, prefix: &str) -> bool {
    let bytes = code.as_bytes();
    let needle = prefix.as_bytes();
    let mut start = 0;
    while let Some(idx) = find_bytes(bytes, needle, start) {
        if idx == 0 {
            return true;
        }
        let before = bytes[idx - 1];
        if !before.is_ascii_alphanumeric() && before != b'_' && before != b':' {
            return true;
        }
        start = idx + 1;
    }
    false
}

/// Return true when `trimmed` is a `use` import line.
fn is_import_line(trimmed: &str) -> bool {
    trimmed.starts_with("use ") || trimmed.starts_with("pub use ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_forbidden_ambient_clock() {
        let code = r#"
            fn do_work() {
                let t = Instant::now();
            }
        "#;
        let v = scan_source(code);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].pattern, "Instant::now()");
    }

    #[test]
    fn detects_forbidden_randomness() {
        let code = "let mut rng = rand::thread_rng();";
        let v = scan_source(code);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].pattern, "rand::thread_rng()");
    }

    #[test]
    fn detects_env_var_reads() {
        let code = "let seed = std::env::var(\"SEED\").unwrap_or_default();";
        let v = scan_source(code);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].pattern, "env::var");
    }

    #[test]
    fn hashmap_warn_fires_only_inside_simulation_scope() {
        let code = "fn f() { let m: HashMap<u8, u8> = HashMap::new(); }";
        let in_scope = Path::new("crates/ledger-sim/src/x.rs");
        let out_of_scope = Path::new("crates/ledger-cli/src/x.rs");
        let warnings = scan_warnings(in_scope, code);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].pattern, "HashMap");
        assert!(scan_warnings(out_of_scope, code).is_empty());
    }

    #[test]
    fn imports_and_allow_markers_skip_hash_warnings() {
        let code = "use std::collections::HashMap;\n\
                    // ledger-lint:allow:HashMap (lookup-only fd map)\n\
                    fn f(m: HashMap<u8, u8>) {}";
        let in_scope = Path::new("crates/ledger-sim/src/x.rs");
        assert!(scan_warnings(in_scope, code).is_empty());
    }

    #[test]
    fn full_file_allow_suppresses_hash_warnings() {
        let code = "// ledger-lint:allow (host passthrough)\n\
                    fn f(s: HashSet<u8>) {}";
        let in_scope = Path::new("crates/ledger-sim/src/x.rs");
        assert!(scan_warnings(in_scope, code).is_empty());
    }

    #[test]
    fn allow_marker_suppresses_all_violations() {
        let code = r#"// ledger-lint:allow (production passthrough backend reads ambient time by design)
fn now() -> u64 {
    let t = SystemTime::now();
}"#;
        assert!(scan_source(code).is_empty());
    }

    #[test]
    fn per_pattern_allow_exempts_only_matching_pattern() {
        let code = r#"// ledger-lint:allow:Instant::now()
let t = std::time::Instant::now();
let _ = std::fs::read_to_string("state.json");"#;
        let v = scan_source(code);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].pattern, "std::fs::");
    }

    #[test]
    fn per_pattern_allow_keeps_other_patterns_active() {
        let code = r#"// ledger-lint:allow:rdrand
let _ = std::arch::x86_64::_rdrand64_step(&mut v);
let _seed = std::env::var("SEED");"#;
        let v = scan_source(code);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].pattern, "env::var");
    }

    #[test]
    fn comment_after_code_is_ignored() {
        let code = "let t = Instant::now(); // let _ = SystemTime::now();";
        let v = scan_source(code);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].pattern, "Instant::now()");
    }

    #[test]
    fn block_comment_spanning_lines_is_ignored() {
        let code = "/*\n * let _ = SystemTime::now();\n * let _ = Instant::now();\n*/";
        assert!(scan_source(code).is_empty());
    }

    #[test]
    fn code_after_closed_block_comment_is_scanned() {
        let code = "/* block */ let t = Instant::now();";
        let v = scan_source(code);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].pattern, "Instant::now()");
    }

    #[test]
    fn import_line_is_ignored() {
        let code = "use std::fs::{self, File};\nfn main() {}";
        assert!(scan_source(code).is_empty());
    }

    #[test]
    fn pub_use_import_line_is_ignored() {
        let code = "pub use std::fs::File;\nfn main() {}";
        assert!(scan_source(code).is_empty());
    }

    #[test]
    fn bare_fs_prefix_after_use_import_is_flagged() {
        let code = "use std::fs;\nfn main() { let _ = fs::read(\"state.bin\"); }";
        let v = scan_source(code);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].pattern, "fs::");
    }

    #[test]
    fn fully_qualified_fs_reports_single_violation() {
        let code = "let _ = std::fs::read(\"state.bin\");";
        let v = scan_source(code);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].pattern, "std::fs::");
    }

    #[test]
    fn bare_net_prefix_after_use_import_is_flagged() {
        let code = "use std::net;\nlet _stream = net::TcpStream::connect(\"127.0.0.1:8080\");";
        let v = scan_source(code);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].pattern, "net::");
    }

    #[test]
    fn unrelated_module_shadowing_fs_is_not_flagged() {
        let code = "let _ = simfs::read_dir(\".\");";
        assert!(scan_source(code).is_empty());
    }

    #[test]
    fn per_pattern_allow_exempts_bare_fs_prefix() {
        let code = r#"// ledger-lint:allow:fs:: (storage module uses the ambient filesystem)
use std::fs;
fn load() { let _ = fs::read("state.bin"); }"#;
        assert!(scan_source(code).is_empty());
    }

    #[test]
    fn detects_getrandom_fill_and_bare_prefix() {
        let fill = "let mut buf = [0u8; 32]; getrandom::fill(&mut buf).unwrap();";
        let v = scan_source(fill);
        assert!(v.iter().any(|vi| vi.pattern == "getrandom::fill"));
        let bare =
            "use getrandom;\nfn f() { let mut b = [0u8; 32]; let _ = getrandom::fill(&mut b); }";
        let v2 = scan_source(bare);
        assert!(
            v2.iter()
                .any(|vi| vi.pattern == "getrandom::" || vi.pattern == "getrandom::fill")
        );
        let allow = "// ledger-lint:allow:getrandom::\nlet mut b = [0u8; 32]; getrandom::fill(&mut b).unwrap();";
        assert!(scan_source(allow).is_empty());
    }

    #[test]
    fn detects_bare_env_args_and_allows_it() {
        let bare = "use std::env;\nfn main() { let _ = env::args().collect::<Vec<_>>(); }";
        let v = scan_source(bare);
        assert!(v.iter().any(|vi| vi.pattern == "env::args"));
        let allow = "// ledger-lint:allow:env::args\nuse std::env;\nfn main() { let _ = env::args().collect::<Vec<_>>(); }";
        assert!(scan_source(allow).is_empty());
    }
}
