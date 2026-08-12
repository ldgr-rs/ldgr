use ledger_lint::{scan_rs_files, scan_source};
use ledger_sim::{LeakClass, Sentinel};
use std::collections::BTreeSet;
use std::path::Path;

#[test]
fn planted_leak_wall_clock_flagged_by_lint() {
    let source = r#"
        pub fn leaking_handler() {
            let start = std::time::Instant::now();
            let _ = start.elapsed();
        }
    "#;
    let violations = scan_source(source);
    assert!(!violations.is_empty(), "Instant::now() must be flagged");
    assert_eq!(violations[0].pattern, "Instant::now()");
}

#[test]
fn planted_leak_system_time_flagged_by_lint() {
    let source = "let now = std::time::SystemTime::now();";
    let violations = scan_source(source);
    assert!(!violations.is_empty(), "SystemTime::now() must be flagged");
    assert_eq!(violations[0].pattern, "SystemTime::now()");
}

#[test]
fn planted_leak_ambient_rng_flagged_by_lint() {
    let source = "let mut rng = rand::thread_rng();";
    let violations = scan_source(source);
    assert!(!violations.is_empty(), "rand::thread_rng() must be flagged");
    assert_eq!(violations[0].pattern, "rand::thread_rng()");
}

#[test]
fn planted_leak_raw_thread_flagged_by_lint() {
    let source = "let handle = std::thread::spawn(|| { 42 });";
    let violations = scan_source(source);
    assert!(!violations.is_empty(), "thread::spawn must be flagged");
    assert_eq!(violations[0].pattern, "thread::spawn");
}

#[test]
fn planted_leak_ambient_fs_flagged_by_lint() {
    let source = "let _ = std::fs::read_to_string(\"state.json\");";
    let violations = scan_source(source);
    assert!(!violations.is_empty(), "std::fs must be flagged");
    assert_eq!(violations[0].pattern, "std::fs::");
}

#[test]
fn planted_leak_ambient_net_flagged_by_lint() {
    let source = "let socket = std::net::UdpSocket::bind(\"127.0.0.1:8080\");";
    let violations = scan_source(source);
    assert!(!violations.is_empty(), "std::net must be flagged");
    assert_eq!(violations[0].pattern, "std::net::");
}

#[test]
fn planted_leak_env_var_flagged_by_lint() {
    let source = "let seed = std::env::var(\"SEED\");";
    let violations = scan_source(source);
    assert!(!violations.is_empty(), "env::var must be flagged");
    assert_eq!(violations[0].pattern, "env::var");
}

#[test]
fn planted_leak_wasm_time_flagged_by_lint() {
    let source = "let _start = wasm_time::Instant::now();";
    let violations = scan_source(source);
    assert!(
        violations.iter().any(|v| v.pattern == "wasm_time::"),
        "wasm_time:: must be flagged"
    );
}

#[test]
fn planted_leak_web_time_flagged_by_lint() {
    let source = "let _start = web_time::Instant::now();";
    let violations = scan_source(source);
    assert!(
        violations.iter().any(|v| v.pattern == "web_time::"),
        "web_time:: must be flagged"
    );
}

#[test]
fn planted_leak_instant_crate_flagged_by_lint() {
    let source = "let _start = instant::Instant::now();";
    let violations = scan_source(source);
    assert!(
        violations.iter().any(|v| v.pattern == "instant::"),
        "instant:: must be flagged"
    );
}

#[test]
fn planted_leak_getrandom_flagged_by_lint() {
    let source = "let mut buf = [0u8; 32];\ngetrandom::getrandom(&mut buf);";
    let violations = scan_source(source);
    assert!(
        violations
            .iter()
            .any(|v| v.pattern == "getrandom::getrandom"),
        "getrandom::getrandom must be flagged"
    );
}

#[test]
fn planted_leak_libc_clock_gettime_flagged_by_lint() {
    let source =
        "let mut ts = std::mem::zeroed();\nlibc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);";
    let violations = scan_source(source);
    assert!(
        violations
            .iter()
            .any(|v| v.pattern == "libc::clock_gettime"),
        "libc::clock_gettime must be flagged"
    );
}

#[test]
fn planted_leak_libc_gettimeofday_flagged_by_lint() {
    let source = "let mut tv = std::mem::zeroed();\nlibc::gettimeofday(&mut tv, std::ptr::null());";
    let violations = scan_source(source);
    assert!(
        violations.iter().any(|v| v.pattern == "libc::gettimeofday"),
        "libc::gettimeofday must be flagged"
    );
}

#[test]
fn planted_leak_libc_getrandom_flagged_by_lint() {
    let source = "let mut buf = [0u8; 32];\nlibc::getrandom(buf.as_mut_ptr(), buf.len(), 0);";
    let violations = scan_source(source);
    assert!(
        violations.iter().any(|v| v.pattern == "libc::getrandom"),
        "libc::getrandom must be flagged"
    );
}

#[test]
fn planted_leak_libc_getentropy_flagged_by_lint() {
    let source = "let mut buf = [0u8; 32];\nlibc::getentropy(buf.as_mut_ptr(), buf.len());";
    let violations = scan_source(source);
    assert!(
        violations.iter().any(|v| v.pattern == "libc::getentropy"),
        "libc::getentropy must be flagged"
    );
}

#[test]
fn planted_leak_libc_time_flagged_by_lint() {
    let source = "let _secs = libc::time(std::ptr::null_mut());";
    let violations = scan_source(source);
    assert!(
        violations.iter().any(|v| v.pattern == "libc::time"),
        "libc::time must be flagged"
    );
}

#[test]
fn planted_leak_vdso_clock_flagged_by_lint() {
    let source =
        "let mut _vdso_base = 0usize;\nlet _vdso_base = libc::getauxval(libc::AT_SYSINFO_EHDR);";
    let violations = scan_source(source);
    assert!(
        violations.iter().any(|v| v.pattern == "getauxval"),
        "getauxval must be flagged"
    );
}

#[test]
fn planted_leak_ffi_wall_clock_flagged_by_lint() {
    let source = "extern \"C\" {\n    fn time() -> i64;\n}\nlet _secs = unsafe { time() };";
    let violations = scan_source(source);
    assert!(
        violations.iter().any(|v| v.pattern == "fn time()"),
        "extern \"C\" time() must be flagged"
    );
}

#[test]
fn planted_leak_rdrand_flagged_by_lint() {
    let source = "let mut val: u64 = 0;\nlet _ok = std::arch::x86_64::_rdrand64_step(&mut val);";
    let violations = scan_source(source);
    assert!(
        violations.iter().any(|v| v.pattern == "rdrand"),
        "rdrand must be flagged"
    );
}

#[test]
fn planted_leak_rdseed_flagged_by_lint() {
    let source = "let mut val: u64 = 0;\nlet _ok = std::arch::x86_64::_rdseed64_step(&mut val);";
    let violations = scan_source(source);
    assert!(
        violations.iter().any(|v| v.pattern == "rdseed"),
        "rdseed must be flagged"
    );
}

#[test]
fn planted_leak_raw_syscall_flagged_by_lint() {
    let source = "let fd = unsafe { syscall(libc::SYS_open, b\"path\".as_ptr(), libc::O_RDONLY) };";
    let violations = scan_source(source);
    assert!(
        violations.iter().any(|v| v.pattern == "syscall("),
        "syscall( must be flagged"
    );
}

#[test]
fn planted_leak_std_env_args_flagged_by_lint() {
    let source = "let _args: Vec<String> = std::env::args().collect();";
    let violations = scan_source(source);
    assert!(
        violations.iter().any(|v| v.pattern == "std::env::args"),
        "std::env::args must be flagged"
    );
}

#[test]
fn per_pattern_allow_exempts_only_matching_pattern() {
    let source = r#"// ledger-lint:allow:Instant::now()
        let t = std::time::Instant::now();
        let _ = std::fs::read_to_string("state.json");
    "#;
    let violations = scan_source(source);
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].pattern, "std::fs::");
}

#[test]
fn plain_allow_marker_exempts_entire_file() {
    let source = r#"// ledger-lint:allow
        let t = std::time::Instant::now();
        let _ = std::fs::read_to_string("state.json");
    "#;
    assert!(scan_source(source).is_empty());
}

#[test]
fn planted_leak_corpus_fully_flagged_by_directory_scan() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpora/planted-leaks");
    let result = scan_rs_files(&corpus);
    assert!(result.errors.is_empty(), "scan errors: {:?}", result.errors);
    assert_eq!(
        result.files_scanned, 15,
        "all fifteen planted leaks must be scanned"
    );
    let flagged: BTreeSet<String> = result
        .violating_files
        .iter()
        .filter_map(|(path, _)| path.file_name().and_then(|name| name.to_str()))
        .map(str::to_string)
        .collect();
    for file in [
        "wall_clock.rs",
        "system_time.rs",
        "thread_rng.rs",
        "thread_spawn.rs",
        "raw_fs.rs",
        "raw_net.rs",
        "env_var.rs",
        "wasm_time.rs",
        "instant_crate.rs",
        "getrandom_call.rs",
        "libc_clock.rs",
        "rdrand_intrinsic.rs",
        "raw_syscall.rs",
        "vdso_clock.rs",
        "ffi_wall_clock.rs",
    ] {
        assert!(flagged.contains(file), "planted leak not flagged: {file}");
    }
    assert_eq!(
        result.total_violations(),
        18,
        "each planted leak must be flagged at least once"
    );
}

#[test]
fn allow_marked_backend_file_skipped_by_directory_scan() {
    let backend =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/ledger-sim/src/backend_tokio.rs");
    let result = scan_rs_files(&backend);
    assert!(result.errors.is_empty(), "scan errors: {:?}", result.errors);
    assert!(
        result.violating_files.is_empty(),
        "allow-marked file must be skipped"
    );
}

#[test]
fn directory_scan_flags_instant_without_marker() {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpora/planted-leaks/wall_clock.rs");
    let result = scan_rs_files(&fixture);
    assert_eq!(result.files_scanned, 1);
    assert_eq!(result.total_violations(), 1);
    assert_eq!(result.violating_files[0].1[0].pattern, "Instant::now()");
}

#[test]
fn sentinel_tracks_and_reports_runtime_leak_classes() {
    let mut sentinel = Sentinel::new();
    sentinel.record_leak(LeakClass::WallClock);
    sentinel.record_leak(LeakClass::AmbientRng);
    sentinel.record_leak(LeakClass::RawThread);
    sentinel.record_leak(LeakClass::UnsimulatedIo);
    sentinel.record_leak(LeakClass::EnvVarEntropy);

    assert!(sentinel.has_leaks());
    assert_eq!(sentinel.leaks().len(), 5);
}
