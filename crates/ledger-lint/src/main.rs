// ledger-lint:allow:env::args (CLI entrypoint reads process args)
//! CLI executable for ledger-lint scanner.

use ledger_lint::{LintViolation, ScanResult, scan_rs_files};
use std::env;
use std::path::Path;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    let deny_warnings = args.iter().any(|arg| arg == "--deny-warnings");
    let targets: Vec<&String> = args
        .iter()
        .skip(1)
        .filter(|arg| *arg != "--deny-warnings")
        .collect();
    if targets.is_empty() {
        eprintln!("Usage: ledger-lint [--deny-warnings] <path-to-source-file-or-dir>...");
        process::exit(1);
    }

    let mut aggregate = ScanResult::default();
    for target in targets {
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
        aggregate.warning_files.extend(result.warning_files);
    }

    for (file, violations) in &aggregate.violating_files {
        print_report(file, violations);
    }

    let total = aggregate.total_violations();
    let total_warnings = aggregate.total_warnings();
    println!(
        "ledger-lint: scanned {} source file(s); {} violation(s) in {} file(s); {} warn-level finding(s) in {} file(s).",
        aggregate.files_scanned,
        total,
        aggregate.violating_files.len(),
        total_warnings,
        aggregate.warning_files.len()
    );
    for (file, warnings) in &aggregate.warning_files {
        print_warn_report(file, warnings);
    }
    for err in &aggregate.errors {
        eprintln!("ledger-lint: {err}");
    }
    if total > 0 || !aggregate.errors.is_empty() || (deny_warnings && total_warnings > 0) {
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

fn print_warn_report(file: &Path, warnings: &[LintViolation]) {
    println!(
        "{}: {} warn-level determinism finding(s):",
        file.display(),
        warnings.len()
    );
    for warning in warnings {
        println!("  Line {}: `{}`", warning.line_number, warning.line_content);
        println!("    Advice: {}", warning.advice);
    }
}
