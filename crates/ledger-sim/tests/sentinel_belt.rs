//! Process-belt leak sentinel integration tests.
//!
//! Every probe runs in a subprocess, so the seccomp and RDTSC filters never
//! touch the test harness. The probe binary is located through the env var
//! cargo sets for package bins during integration tests.

#![cfg(all(feature = "sentinel", target_os = "linux"))]

use ledger_sim::sentinel_belt::{DetectionReport, run_detected};
use ledger_sim::{LeakClass, Sentinel};
use std::path::PathBuf;
use std::process::Command;

fn probe_command() -> Command {
    Command::new(probe_path())
}

/// Locate the probe binary.
///
/// Cargo sets CARGO_BIN_EXE_sentinel_probe when it compiles this test, but
/// clippy --all-targets does not. The fallback derives the profile directory
/// from the running test executable.
fn probe_path() -> PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_sentinel_probe") {
        return PathBuf::from(path);
    }
    let exe = std::env::current_exe().expect("current test executable must resolve");
    let profile = exe
        .parent()
        .and_then(|dir| dir.parent())
        .expect("test executable must live under a profile directory");
    profile.join("sentinel-probe")
}

#[test]
fn ld_preload_flags_ambient_calls() {
    let mut cmd = probe_command();
    cmd.env("LEDGER_PROBE_MODE", "ambient");
    let report = run_detected(&mut cmd).expect("probe must run under the shim");
    assert!(
        report.detected_calls.contains(&"getrandom"),
        "getrandom must be flagged, got {:?}",
        report.detected_calls
    );
    assert!(
        report.detected_calls.contains(&"clock_gettime"),
        "clock_gettime must be flagged, got {:?}",
        report.detected_calls
    );
    assert!(
        report.detected_calls.contains(&"time"),
        "time must be flagged, got {:?}",
        report.detected_calls
    );
}

#[test]
fn ld_preload_clean_run_is_quiet() {
    let mut cmd = probe_command();
    cmd.env("LEDGER_PROBE_MODE", "clean");
    let report = run_detected(&mut cmd).expect("probe must run under the shim");
    assert!(
        report.detected_calls.is_empty(),
        "clean probe leaked ambient calls: {:?}",
        report.detected_calls
    );
}

/// The shim must catch clock reads even when glibc would serve them from the
/// vDSO: the probe calls the PLT symbols directly and the interposition logs
/// them.
#[test]
fn shim_catches_vdso_resident_clock_reads() {
    let mut cmd = probe_command();
    cmd.env("LEDGER_PROBE_MODE", "vdsoclk");
    let report = run_detected(&mut cmd).expect("probe must run under the shim");
    assert!(
        report.detected_calls.contains(&"clock_gettime"),
        "clock_gettime must be flagged, got {:?}",
        report.detected_calls
    );
    assert!(
        report.detected_calls.contains(&"gettimeofday"),
        "gettimeofday must be flagged, got {:?}",
        report.detected_calls
    );
}

/// The run-entry belt hook installs the denylist and the RDTSC trap when the
/// belt is armed. Runs in a subprocess because installing the kill filter
/// would affect any code sharing the test thread.
#[test]
fn belt_activates_when_armed() {
    let output = probe_command()
        .env("LEDGER_PROBE_MODE", "belt")
        .output()
        .expect("probe must spawn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "probe failed: {stdout}");
    assert!(
        stdout.contains("belt-status: Active"),
        "belt must report Active, got: {stdout}"
    );
}

/// The public run path leaves the belt unarmed by default so host processes
/// and test harnesses are not permanently constrained with seccomp filters.
#[test]
fn run_path_defaults_to_not_armed() {
    let output = probe_command()
        .env("LEDGER_PROBE_MODE", "simulate")
        .output()
        .expect("probe must spawn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "probe failed: {stdout}");
    assert!(stdout.contains("simulate-ok"), "got: {stdout}");
    assert!(
        stdout.contains("belt=Some(NotArmed)"),
        "run must report NotArmed by default, got: {stdout}"
    );
}

/// A falsy `LEDGER_SENTINEL_BELT` explicitly opts the process out of the belt.
#[test]
fn run_path_belt_disabled_via_env_reports_not_armed() {
    let output = probe_command()
        .env("LEDGER_PROBE_MODE", "simulate")
        .env("LEDGER_SENTINEL_BELT", "0")
        .output()
        .expect("probe must spawn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "probe failed: {stdout}");
    assert!(stdout.contains("simulate-ok"), "got: {stdout}");
    assert!(
        stdout.contains("belt=Some(NotArmed)"),
        "run must report NotArmed when disabled, got: {stdout}"
    );
}

/// A full sim run must complete under the armed belt: the run entry hook
/// installs the seccomp denylist and the RDTSC trap, and the deterministic
/// run loop stays clear of the blocked syscalls.
#[test]
fn run_path_completes_under_armed_belt() {
    let output = probe_command()
        .env("LEDGER_PROBE_MODE", "simulate")
        .env("LEDGER_SENTINEL_BELT", "1")
        .output()
        .expect("probe must spawn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "probe failed: {stdout}");
    assert!(stdout.contains("simulate-ok"), "got: {stdout}");
    assert!(
        stdout.contains("belt=Some(Active"),
        "run must report Active, got: {stdout}"
    );
}

/// The RDRAND/RDSEED opcode scan must run over the process image without
/// error and return a bool report.
#[test]
fn rdrand_rdseed_scan_reports_without_error() {
    let present =
        ledger_sim::sentinel_belt::scan_rdrand_rdseed().expect("opcode scan must not fail");
    // Any bool is a valid report; the value itself is informational.
    let _ = present;
}

#[test]
fn seccomp_denies_getrandom() {
    let output = probe_command()
        .env("LEDGER_PROBE_MODE", "seccomp")
        .output()
        .expect("probe must spawn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !output.status.success(),
        "seccomp filter must kill the probe"
    );
    assert!(
        !stdout.contains("seccomp-survived"),
        "getrandom must not return under the filter"
    );
    assert!(
        !stdout.contains("seccomp-install-failed"),
        "seccomp filter must install cleanly"
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn tsc_trap_signals() {
    let output = probe_command()
        .env("LEDGER_PROBE_MODE", "tsc")
        .output()
        .expect("probe must spawn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("tsc-trapped"),
        "rdtsc must not survive the trap"
    );
    assert!(
        !stdout.contains("tsc-install-failed"),
        "tsc trap must install cleanly"
    );
}

#[test]
fn sentinel_records_leak_classes() {
    let report = DetectionReport {
        detected_calls: vec!["getrandom", "clock_gettime", "rdtsc"],
    };
    let sentinel = Sentinel::from_detection(&report);
    assert!(sentinel.has_leaks());
    assert!(sentinel.leaks().contains(&LeakClass::AmbientRng));
    assert!(sentinel.leaks().contains(&LeakClass::WallClock));
    assert!(sentinel.leaks().contains(&LeakClass::TimestampCounter));
}

#[test]
fn from_detection_ignores_unknown_names() {
    let report = DetectionReport {
        detected_calls: vec!["readlink", "getrandom"],
    };
    let sentinel = Sentinel::from_detection(&report);
    assert!(sentinel.has_leaks());
    assert!(sentinel.leaks().contains(&LeakClass::AmbientRng));
    assert_eq!(sentinel.leaks().len(), 1);
}
