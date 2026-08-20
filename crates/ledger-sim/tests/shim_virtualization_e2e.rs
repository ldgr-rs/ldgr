//! End-to-end LD_PRELOAD virtualization run test.
//!
//! Earlier coverage only scanned the shim bytes for symbol strings. Here the
//! built shim is preloaded into the probe child for real, and the test asserts
//! the virtualized clock and entropy values from the child stdout.

#![cfg(all(feature = "sentinel", target_os = "linux"))]

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

/// Unique suffix source for temp file names; avoids wall-clock reads.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Locate the probe binary the same way tests/sentinel_belt.rs does.
///
/// Cargo sets CARGO_BIN_EXE_sentinel-probe when it compiles this test, but
/// clippy --all-targets does not. The fallback derives the profile directory
/// from the running test executable.
fn probe_path() -> PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_sentinel-probe") {
        return PathBuf::from(path);
    }
    let exe = std::env::current_exe().expect("current test executable must resolve");
    let profile = exe
        .parent()
        .and_then(|dir| dir.parent())
        .expect("test executable must live under a profile directory");
    profile.join("sentinel-probe")
}

/// Build a collision-free temp path under the system temp dir.
fn temp_name(prefix: &str) -> PathBuf {
    let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "ldgr-shim-e2e-{prefix}-{}-{id}",
        std::process::id()
    ))
}

/// Spawn the probe under the preload shim and return raw stdout bytes.
///
/// Mirrors `run_detected`: the shim is prepended to any inherited LD_PRELOAD.
/// Virtual env vars and the sentinel log are cleared first so parent leakage
/// cannot perturb assertions.
fn run_probe(mode: &str, extra_env: &[(&str, OsString)]) -> Vec<u8> {
    let shim = ledger_sim::shim_path();
    assert!(
        shim.is_file(),
        "sentinel shim must exist at {}",
        shim.display()
    );
    let mut cmd = Command::new(probe_path());
    cmd.env("LEDGER_PROBE_MODE", mode);
    cmd.env_remove("LEDGER_SENTINEL_LOG");
    cmd.env_remove("LEDGER_VIRTUAL_TICKS_PATH");
    cmd.env_remove("LEDGER_VIRTUAL_SEED_HEX");
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    let mut preload = shim.to_string_lossy().into_owned();
    if let Some(existing) = std::env::var_os("LD_PRELOAD") {
        preload.push(':');
        preload.push_str(&existing.to_string_lossy());
    }
    cmd.env("LD_PRELOAD", preload);
    let output = cmd.output().expect("probe child must spawn");
    assert!(
        output.status.success(),
        "probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// Parse a virtclk line "sec=<u64> nsec=<u64>" into its two values.
fn parse_virtclk(stdout_bytes: &[u8]) -> (u64, u64) {
    let text = String::from_utf8(stdout_bytes.to_vec()).expect("probe stdout must be utf8");
    let line = text.trim();
    let Some((sec_field, nsec_field)) = line.split_once(' ') else {
        panic!("unexpected virtclk output: {text:?}");
    };
    let sec = sec_field
        .strip_prefix("sec=")
        .unwrap_or_else(|| panic!("missing sec= prefix in {text:?}"))
        .parse::<u64>()
        .expect("sec must parse as u64");
    let nsec = nsec_field
        .strip_prefix("nsec=")
        .unwrap_or_else(|| panic!("missing nsec= prefix in {text:?}"))
        .parse::<u64>()
        .expect("nsec must parse as u64");
    (sec, nsec)
}

/// Parse a virtrnd line "rnd=<hex>" into the reported byte buffer.
fn parse_rnd_hex(stdout_bytes: &[u8]) -> Vec<u8> {
    let text = String::from_utf8(stdout_bytes.to_vec()).expect("probe stdout must be utf8");
    let hex = text
        .trim()
        .strip_prefix("rnd=")
        .unwrap_or_else(|| panic!("unexpected virtrnd output: {text:?}"));
    assert_eq!(hex.len() % 2, 0, "hex length must be even: {hex:?}");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex byte must parse"))
        .collect()
}

/// One SplitMix64 step; matches the shim's documented stream contract.
fn splitmix64_next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Reference virtual entropy stream: state seeds from the first 16 hex chars,
/// each 8-byte block is one SplitMix64 step emitted little-endian.
fn expected_virtual_bytes(seed_hex: &str, len: usize) -> Vec<u8> {
    let mut state =
        u64::from_str_radix(&seed_hex[..16], 16).expect("seed prefix must be 16 hex chars");
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let block = splitmix64_next(&mut state);
        let take = (len - out.len()).min(8);
        for i in 0..take {
            out.push((block >> (i * 8)) as u8);
        }
    }
    out
}

/// The shim must serve the ticks file through clock_gettime with an exact
/// micros-to-(sec, nsec) split when preloaded into a child process.
#[test]
fn virtual_clock_serves_exact_ticks() {
    const TICKS_MICROS: u64 = 1_700_000_001_234_567;
    let ticks = temp_name("ticks");
    std::fs::write(&ticks, format!("{TICKS_MICROS}\n")).expect("write ticks file");
    let stdout = run_probe(
        "virtclk",
        &[("LEDGER_VIRTUAL_TICKS_PATH", ticks.clone().into_os_string())],
    );
    // Intentional discard: temp cleanup is best effort and never masks the run.
    let _ = std::fs::remove_file(&ticks);
    let (sec, nsec) = parse_virtclk(&stdout);
    assert_eq!(sec, TICKS_MICROS / 1_000_000, "seconds must match exactly");
    assert_eq!(
        nsec,
        (TICKS_MICROS % 1_000_000) * 1_000,
        "nanoseconds must match exactly"
    );
}

/// Two child runs under the same virtual env must print identical bytes.
#[test]
fn virtual_clock_repeat_run_is_byte_identical() {
    let ticks = temp_name("ticks-det");
    std::fs::write(&ticks, "42\n").expect("write ticks file");
    let env = [("LEDGER_VIRTUAL_TICKS_PATH", ticks.clone().into_os_string())];
    let first = run_probe("virtclk", &env);
    let second = run_probe("virtclk", &env);
    // Intentional discard: temp cleanup is best effort and never masks the run.
    let _ = std::fs::remove_file(&ticks);
    assert_eq!(
        first, second,
        "same virtual env must produce identical stdout bytes"
    );
}

/// The shim entropy stream must be deterministic across runs, nonzero, equal
/// to the documented SplitMix64 contract, and seed dependent.
#[test]
fn virtual_seed_stream_is_deterministic_and_matches_contract() {
    const SEED_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const SEED_B: &str = "ffffffffffffffff0123456789abcdef0123456789abcdef0123456789abcdef";
    let first = run_probe("virtrnd", &[("LEDGER_VIRTUAL_SEED_HEX", SEED_A.into())]);
    let second = run_probe("virtrnd", &[("LEDGER_VIRTUAL_SEED_HEX", SEED_A.into())]);
    let other_seed = run_probe("virtrnd", &[("LEDGER_VIRTUAL_SEED_HEX", SEED_B.into())]);

    let stream_a = parse_rnd_hex(&first);
    assert_eq!(
        stream_a,
        parse_rnd_hex(&second),
        "same seed must give identical entropy bytes"
    );
    assert_eq!(stream_a.len(), 16, "probe requests 16 entropy bytes");
    assert!(
        stream_a.iter().any(|byte| *byte != 0),
        "virtual entropy must not collapse to zeros"
    );
    assert_eq!(
        stream_a,
        expected_virtual_bytes(SEED_A, 16),
        "shim stream must match the documented SplitMix64 contract"
    );
    assert_ne!(
        stream_a,
        parse_rnd_hex(&other_seed),
        "different seeds must give different entropy bytes"
    );
}
