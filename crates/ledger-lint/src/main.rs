// ledger-lint:allow:env::args (CLI entrypoint reads process args)
//! CLI executable for ledger-lint scanner.

use ledger_lint::{LintViolation, ScanResult, scan_rs_files};
use std::env;
use std::path::Path;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: ledger-lint <path-to-source-file-or-dir>...");
        process::exit(1);
    }

    let mut aggregate = ScanResult::default();
    for target in &args[1..] {
        let path = Path::new(target);
        if !path.exists() {
            aggregate
                .errors
                .push(format!("target does not exist: {target}"));
            continue;
        }
        let result = scan_rs_files(path);
        aggregate.files_scanned += result.files_scanned;
        aggregate.errors.extend(result.errors);
        aggregate.violating_files.extend(result.violating_files);
    }

    for (file, violations) in &aggregate.violating_files {
        print_report(file, violations);
    }

    let total = aggregate.total_violations();
    println!(
        "ledger-lint: scanned {} source file(s); {} violation(s) in {} file(s).",
        aggregate.files_scanned,
        total,
        aggregate.violating_files.len()
    );
    for err in &aggregate.errors {
        eprintln!("ledger-lint: {err}");
    }
    if total > 0 || !aggregate.errors.is_empty() {
        process::exit(1);
    }
}

fn print_report(file: &Path, violations: &[LintViolation]) {
    println!(
        "{}: {} determinism violation(s) found:",
        file.display(),
        violations.len()
    );
    for violation in violations {
        println!(
            "  Line {}: `{}`",
            violation.line_number, violation.line_content
        );
        println!("    Advice: {}", violation.advice);
    }
}
