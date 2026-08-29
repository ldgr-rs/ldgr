//! D1 acceptance: a real external canary through the IPC effect path, plus
//! the three explorer services over the canary-shaped workload.
//!
//! Part one spawns the AGPL `rt-server` and the Apache `rt-canary` binaries,
//! lets the canary drive the deterministic engine through the shim, and
//! checks the run is deterministic across two separate processes.
//!
//! Part two runs the campaign, strict replay, and minimizer services over
//! [`CanaryWorkload`], whose instruction programs mirror the canary's effect
//! stream (the planted assertion is what the campaign oracle detects).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use ledger_explorer::oracle::AssertionOracle;
use ledger_explorer::services::{minimize_finding, replay_strict, run_campaign};
use ledger_format::hash_to_hex;
use ledger_sim::{Policy, RunConfig};
use rt_server::{CanaryWorkload, session_identity};

fn canary_bin() -> PathBuf {
    let server = PathBuf::from(env!("CARGO_BIN_EXE_rt-server"));
    let dir = server
        .parent()
        .expect("server binary has a parent directory");
    let example = dir.join("examples").join("canary");
    if example.exists() {
        return example;
    }
    let direct = dir.join("canary");
    if direct.exists() {
        return direct;
    }
    let _ = Command::new("cargo")
        .args([
            "build",
            "--example",
            "canary",
            "-p",
            "ldgr-rt",
            "--features",
            "sim",
        ])
        .output();
    if example.exists() {
        return example;
    }
    example
}

fn wait_for_socket(path: &Path, attempts: u64) -> bool {
    for _ in 0..attempts {
        if path.exists() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    path.exists()
}

fn run_canary_binary(socket: &Path, identity: [u8; 32]) -> (String, bool) {
    let output = Command::new(canary_bin())
        .arg("--socket")
        .arg(socket)
        .arg("--identity")
        .arg(hash_to_hex(&identity))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("canary binary runs");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    (stdout, output.status.success())
}

#[test]
fn external_canary_drives_the_engine_deterministically() {
    let seed = [42u8; 32];
    let identity = session_identity(seed);

    let socket_dir = std::env::temp_dir().join(format!("ldgr-d1-{}", std::process::id()));
    std::fs::create_dir_all(&socket_dir).expect("socket dir");
    let socket = socket_dir.join("engine.sock");

    let mut server = Command::new(env!("CARGO_BIN_EXE_rt-server"))
        .arg("--socket")
        .arg(&socket)
        .arg("--seed")
        .arg(hash_to_hex(&seed))
        .spawn()
        .expect("server spawns");
    assert!(
        wait_for_socket(&socket, 500),
        "rt-server must bind its socket"
    );

    let (first_out, first_ok) = run_canary_binary(&socket, identity);
    assert!(first_ok, "first canary run must succeed: {first_out}");

    // Second canary run against the same server must reproduce the root.
    let (second_out, second_ok) = run_canary_binary(&socket, identity);
    assert!(second_ok, "second canary run must succeed: {second_out}");

    let root_of = |out: &str| -> String {
        out.lines()
            .find_map(|line| line.strip_prefix("root "))
            .map(str::to_string)
            .expect("canary prints a root")
    };
    assert_eq!(
        root_of(&first_out),
        root_of(&second_out),
        "the external canary must be deterministic across processes"
    );

    let entries_of = |out: &str| -> u64 {
        out.lines()
            .find_map(|line| line.strip_prefix("entries "))
            .and_then(|s| s.parse().ok())
            .expect("canary prints an entry count")
    };
    assert!(
        entries_of(&first_out) >= 3,
        "the engine must journal the canary's effects"
    );

    let _ = server.kill();
    let _ = server.wait();
    let _ = std::fs::remove_dir_all(&socket_dir);
}

#[test]
fn explorer_services_run_over_the_canary_workload() {
    let config = RunConfig::builder()
        .seed([0; 32])
        .policy(Policy::Random)
        .max_steps(256)
        .build();
    let workload = CanaryWorkload;
    let oracle = AssertionOracle;

    let report = run_campaign(&workload, &oracle, config, 16).expect("campaign runs");
    let finding = report
        .findings
        .first()
        .expect("the planted assertion must produce a finding");

    let reproduced = replay_strict(&workload, finding.seed, finding.run.decisions.clone())
        .expect("strict replay reproduces");
    assert!(
        matches!(reproduced.outcome, ledger_sim::RunOutcome::Completed),
        "strict replay must complete"
    );

    let repro = minimize_finding(&workload, &oracle, finding, "canary").expect("minimizer runs");
    assert!(
        repro.decisions.len() <= finding.run.decisions.len(),
        "minimization must not grow the decision stream"
    );
}
