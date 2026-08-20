//! Virtual override for TokioBackend and shim smoke.

use ledger_sim::{Effects, TokioBackend, VirtualOverride};
use rand_core::Rng;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[test]
fn virtual_override_clock_and_rng_deterministic() {
    let _env_guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());

    // Save original env to restore after the test.
    let orig_ticks = std::env::var_os("LEDGER_VIRTUAL_TICKS_PATH");
    let orig_seed = std::env::var_os("LEDGER_VIRTUAL_SEED_HEX");

    // Create a temp file that holds virtual time as decimal micros.
    let ticks_path = std::env::temp_dir().join(format!(
        "ldgr-virtual-ticks-{}-{}.txt",
        std::process::id(),
        // Use a monotonic counter derived from time to avoid collisions.
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let expected_micros: u64 = 1_234_567_890;
    std::fs::write(&ticks_path, format!("{expected_micros}\n")).expect("write ticks file");

    // 64 hex chars seed. First 16 chars determine SplitMix64 state.
    let seed_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    unsafe {
        std::env::set_var("LEDGER_VIRTUAL_TICKS_PATH", &ticks_path);
        std::env::set_var("LEDGER_VIRTUAL_SEED_HEX", seed_hex);
    }

    // Verify VirtualOverride reads the env correctly.
    let ov = VirtualOverride::from_env();
    assert!(
        ov.ticks_path.is_some(),
        "VirtualOverride must capture ticks path"
    );
    assert_eq!(
        ov.ticks_path.as_ref().unwrap(),
        &ticks_path,
        "ticks path mismatch"
    );
    assert_eq!(ov.seed_hex.as_deref(), Some(seed_hex), "seed hex mismatch");

    // Clock must return the file value.
    let backend = TokioBackend::new();
    let clock_now = backend.clock().now();
    assert_eq!(
        clock_now, expected_micros,
        "virtual clock must equal file value"
    );

    // RNG must be deterministic: two backends with same seed produce same sequence.
    let mut backend_a = TokioBackend::new();
    let mut backend_b = TokioBackend::new();
    let seq_a: Vec<u64> = (0..5).map(|_| backend_a.rng(0).next_u64()).collect();
    let seq_b: Vec<u64> = (0..5).map(|_| backend_b.rng(0).next_u64()).collect();
    assert_eq!(
        seq_a, seq_b,
        "RNG sequences must be identical for same seed"
    );
    assert!(
        seq_a.iter().any(|v| *v != 0),
        "RNG sequence must not be all zeros"
    );
    // Consecutive draws must differ (SplitMix64 advances each call).
    assert_ne!(seq_a[0], seq_a[1], "consecutive RNG draws must differ");

    // Cleanup env and file before asserting fallback behavior.
    unsafe {
        std::env::remove_var("LEDGER_VIRTUAL_TICKS_PATH");
        std::env::remove_var("LEDGER_VIRTUAL_SEED_HEX");
    }
    let _ = std::fs::remove_file(&ticks_path);

    // Restore original env if any.
    if let Some(v) = &orig_ticks {
        unsafe {
            std::env::set_var("LEDGER_VIRTUAL_TICKS_PATH", v);
        }
    }
    if let Some(v) = &orig_seed {
        unsafe {
            std::env::set_var("LEDGER_VIRTUAL_SEED_HEX", v);
        }
    }

    // After clearing virtual env, a fresh backend must not return the virtual value
    // (it falls back to wall time). We cannot assert wall time equals anything,
    // only that it was constructed without the virtual path.
    let ov_cleared = VirtualOverride::from_env();
    if orig_ticks.is_none() && orig_seed.is_none() {
        assert!(
            ov_cleared.ticks_path.is_none(),
            "ticks path must be absent after cleanup"
        );
        assert!(
            ov_cleared.seed_hex.is_none(),
            "seed hex must be absent after cleanup"
        );
    }

    // Also verify that writing a new ticks value is picked up per-construction.
    // Re-establish for a second virtual read check.
    let ticks_path2 = std::env::temp_dir().join(format!(
        "ldgr-virtual-ticks2-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(1)
    ));
    let second_micros: u64 = 9_999_111;
    std::fs::write(&ticks_path2, format!("{second_micros}")).expect("write ticks2");
    unsafe {
        std::env::set_var("LEDGER_VIRTUAL_TICKS_PATH", &ticks_path2);
        std::env::remove_var("LEDGER_VIRTUAL_SEED_HEX");
    }
    let backend2 = TokioBackend::new();
    assert_eq!(
        backend2.clock().now(),
        second_micros,
        "second virtual clock must equal second file value"
    );
    let _ = std::fs::remove_file(&ticks_path2);
    unsafe {
        std::env::remove_var("LEDGER_VIRTUAL_TICKS_PATH");
    }
    if let Some(v) = orig_ticks {
        unsafe {
            std::env::set_var("LEDGER_VIRTUAL_TICKS_PATH", v);
        }
    }
    if let Some(v) = orig_seed {
        unsafe {
            std::env::set_var("LEDGER_VIRTUAL_SEED_HEX", v);
        }
    }

    // Suppress unused warning for PathBuf import when not using sentinel feature.
    let _ = PathBuf::from("/tmp");
}

#[cfg(all(feature = "sentinel", target_os = "linux"))]
#[test]
fn shim_contains_virtual_symbols() {
    let path = ledger_sim::shim_path();
    assert!(
        path.is_file(),
        "sentinel shim must exist at {}",
        path.display()
    );
    let bytes = std::fs::read(&path).expect("read shim .so");
    for needle in [
        b"LEDGER_VIRTUAL_TICKS_PATH".as_slice(),
        b"LEDGER_VIRTUAL_SEED_HEX".as_slice(),
    ] {
        let found = bytes.windows(needle.len()).any(|window| window == needle);
        assert!(
            found,
            "shim must contain {}",
            String::from_utf8_lossy(needle)
        );
    }
    // Ensure the virtual PRNG helper is present (string from symbol table not required,
    // check that the file is a plausible ELF: starts with 0x7f ELF).
    assert!(
        bytes.starts_with(b"\x7fELF"),
        "shim must be an ELF shared object"
    );
}

/// When `LEDGER_VIRTUAL_TICKS_PATH` is armed but its file is missing, the
/// clock must hold at zero and record an override error instead of silently
/// serving ambient wall time.
#[test]
fn virtual_override_missing_ticks_file_fails_closed() {
    let _env_guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());

    let orig_ticks = std::env::var_os("LEDGER_VIRTUAL_TICKS_PATH");
    let missing = std::env::temp_dir().join(format!(
        "ldgr-virtual-missing-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));

    unsafe {
        std::env::set_var("LEDGER_VIRTUAL_TICKS_PATH", &missing);
    }

    let backend = TokioBackend::new();
    // Armed override + unreadable input: clock holds at zero, never ambient.
    assert_eq!(backend.clock().now(), 0);
    let error = backend
        .virtual_override_error()
        .expect("override error must be recorded");
    assert!(
        error.contains(&missing.display().to_string()),
        "error must name the ticks path: {error}"
    );

    match orig_ticks {
        Some(value) => unsafe {
            std::env::set_var("LEDGER_VIRTUAL_TICKS_PATH", value);
        },
        None => unsafe {
            std::env::remove_var("LEDGER_VIRTUAL_TICKS_PATH");
        },
    }
}

/// A ticks file exceeding the 256-byte cap is a parse failure, not a silent
/// fallback to ambient time.
#[test]
fn virtual_override_oversized_ticks_file_fails_closed() {
    let _env_guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());

    let orig_ticks = std::env::var_os("LEDGER_VIRTUAL_TICKS_PATH");
    let oversized = std::env::temp_dir().join(format!(
        "ldgr-virtual-oversized-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::write(&oversized, "1".repeat(512)).expect("write oversized ticks file");

    unsafe {
        std::env::set_var("LEDGER_VIRTUAL_TICKS_PATH", &oversized);
    }

    let backend = TokioBackend::new();
    assert_eq!(backend.clock().now(), 0);
    let error = backend
        .virtual_override_error()
        .expect("override error must be recorded");
    assert!(error.contains("256"), "error must cite the cap: {error}");

    match orig_ticks {
        Some(value) => unsafe {
            std::env::set_var("LEDGER_VIRTUAL_TICKS_PATH", value);
        },
        None => unsafe {
            std::env::remove_var("LEDGER_VIRTUAL_TICKS_PATH");
        },
    }
    let _ = std::fs::remove_file(&oversized);
}
