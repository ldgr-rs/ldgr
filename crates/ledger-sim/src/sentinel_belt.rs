//! Process-belt leak sentinel: LD_PRELOAD shim, seccomp denylist, RDTSC trap,
//! and hardware-entropy opcode scan.
//!
//! Probes run in subprocesses so filters never break the harness; the run
//! entry hooks `activate_process_belt` before the sim starts on Linux.
// ledger-lint:allow:env::var (belt harness reads LD_PRELOAD to prepend the shim)
// ledger-lint:allow:std::fs:: (belt harness writes and parses the shim log file)
// ledger-lint:allow:rdrand (the leak-class table must name the tsc-class intrinsics)
// ledger-lint:allow:rdseed (the leak-class table must name the tsc-class intrinsics)

use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::sentinel::{BeltStatus, EffectiveProtection, LeakClass, ProtectionMode, Sentinel};

/// Classic BPF load of a 32-bit word at an absolute seccomp_data offset.
const BPF_LD_W_ABS: u16 = 0x20;

/// Classic BPF jump-equal against an immediate kernel value.
const BPF_JMP_JEQ_K: u16 = 0x15;

/// Classic BPF return with an immediate action code.
const BPF_RET_K: u16 = 0x06;

/// seccomp_data arch field offset in bytes.
const SECCOMP_ARCH_OFFSET: u32 = 4;

/// seccomp_data syscall-number field offset in bytes.
const SECCOMP_NR_OFFSET: u32 = 0;

/// Shim-logged ambient APIs; the shim interposes the PLT, so only direct
/// `__vdso` calls or inlined copies escape it.
const INTERPOSED_CALLS: &[&str] = &[
    "getrandom",
    "getentropy",
    "clock_gettime",
    "gettimeofday",
    "time",
];

/// First byte of the RDRAND/RDSEED two-byte opcode.
const RDRAND_PREFIX: u8 = 0x0F;

/// Second byte of the RDRAND/RDSEED two-byte opcode.
const RDRAND_OPCODE: u8 = 0xC7;

/// Per-mapping scan window cap; text segments never approach this size.
const SCAN_CAP: u64 = 64 * 1024 * 1024;

/// Unique counter for sentinel log file names.
static LOG_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Process-wide belt arm switch; armed by `arm_belt`.
static ARMED: AtomicBool = AtomicBool::new(false);

/// True once the seccomp denylist and RDTSC trap are installed.
///
/// Seccomp filters cannot be removed, so a second install would only stack an
/// identical filter. The guard makes repeated run-entry hooks idempotent.
static BELT_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Belt status recorded by the last run-entry hook call.
///
/// Replaceable per-run status: each run overwrites the slot so a later
/// successful install does not report stale state from an earlier failure.
static LAST_BELT_STATUS: OnceLock<Mutex<Option<BeltStatus>>> = OnceLock::new();

fn belt_status_slot() -> &'static Mutex<Option<BeltStatus>> {
    LAST_BELT_STATUS.get_or_init(|| Mutex::new(None))
}

/// Ambient calls detected by one probe run under the interposition shim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionReport {
    /// Names of the interposed functions that fired, sorted and deduplicated.
    pub detected_calls: Vec<&'static str>,
}

/// Result of a complete process-belt installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessBeltStatus {
    /// The seccomp denylist is installed.
    pub seccomp_installed: bool,
    /// The RDTSC SIGSEGV trap is installed.
    pub rdtsc_trapped: bool,
    /// RDRAND/RDSEED opcodes were found in an executable mapping.
    pub rdrand_rdseed_present: bool,
}

/// Sentinel belt errors are defined in `crate::sentinel` so the error type
/// exists on every platform; the belt module re-exports it unchanged.
pub use crate::sentinel::SentinelError;

/// Return the path of the built interposition shim.
pub fn shim_path() -> PathBuf {
    PathBuf::from(env!("SENTINEL_SHIM_PATH"))
}

/// Install a seccomp denylist killing the process on ambient syscalls.
///
/// Blocks OS-entropy and ambient-clock syscalls; call only in a subprocess.
/// Irrevocable and process-wide. `KILL_PROCESS` is used because the
/// single-threaded sim has no supervisor for `USER_NOTIF`; a kill can never
/// become a `RunResult`. RDRAND/RDSEED are instructions outside seccomp; see
/// `scan_rdrand_rdseed`.
pub fn install_seccomp_denylist() -> Result<(), SentinelError> {
    let Some(arch) = native_audit_arch() else {
        return Err(SentinelError::UnsupportedArch);
    };
    let syscalls = deny_syscalls();
    let mut program: Vec<libc::sock_filter> = Vec::with_capacity(4 + syscalls.len() * 2);
    program.push(bpf_stmt(BPF_LD_W_ABS, SECCOMP_ARCH_OFFSET));
    program.push(bpf_jump(BPF_JMP_JEQ_K, arch, 1, 0));
    program.push(bpf_stmt(BPF_RET_K, libc::SECCOMP_RET_KILL_PROCESS));
    program.push(bpf_stmt(BPF_LD_W_ABS, SECCOMP_NR_OFFSET));
    for syscall in syscalls {
        // Kernel syscall ids are small constants; u32 holds every arch's set.
        program.push(bpf_jump(BPF_JMP_JEQ_K, syscall as u32, 0, 1));
        program.push(bpf_stmt(BPF_RET_K, libc::SECCOMP_RET_KILL_PROCESS));
    }
    program.push(bpf_stmt(BPF_RET_K, libc::SECCOMP_RET_ALLOW));

    let mut prog = libc::sock_fprog {
        // Program length is 4 + 2 per denied syscall (at most 4), far below
        // the u16 cap; the BPF kernel contract requires this field.
        len: program.len() as u16,
        filter: program.as_mut_ptr(),
    };
    #[allow(unsafe_code)] // seccomp/prctl ffi: kernel contract requires raw syscall pointers
    unsafe {
        let ret = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if ret != 0 {
            return Err(SentinelError::Prctl("PR_SET_NO_NEW_PRIVS", errno()));
        }
        let ret = libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &mut prog as *mut libc::sock_fprog,
        );
        if ret != 0 {
            return Err(SentinelError::Prctl("PR_SET_SECCOMP", errno()));
        }
    }
    Ok(())
}

/// Trap RDTSC reads with SIGSEGV; call only inside a subprocess.
pub fn trap_rdtsc() -> Result<(), SentinelError> {
    #[allow(unsafe_code)] // seccomp/prctl ffi: kernel contract requires raw syscall pointers
    unsafe {
        let ret = libc::prctl(libc::PR_SET_TSC, libc::PR_TSC_SIGSEGV, 0, 0, 0);
        if ret != 0 {
            return Err(SentinelError::Prctl("PR_SET_TSC", errno()));
        }
    }
    Ok(())
}

/// Allow RDTSC reads by clearing the PR_SET_TSC trap.
pub fn allow_rdtsc() -> Result<(), SentinelError> {
    #[allow(unsafe_code)] // seccomp/prctl ffi: kernel contract requires raw syscall pointers
    unsafe {
        let ret = libc::prctl(libc::PR_SET_TSC, libc::PR_TSC_ENABLE, 0, 0, 0);
        if ret != 0 {
            return Err(SentinelError::Prctl("PR_SET_TSC", errno()));
        }
    }
    Ok(())
}

/// RAII guard trapping RDTSC while armed; restores `PR_TSC_ENABLE` on drop.
#[derive(Debug)]
pub struct TscTrapGuard {
    active: bool,
    activation_error: Option<SentinelError>,
}

impl TscTrapGuard {
    /// Arm when the belt is armed; failures stay queryable via
    /// [`TscTrapGuard::activation_error`].
    pub fn arm_if_armed() -> Self {
        Self::arm_for_effective(effective_protection_from_env())
    }

    /// Arm when effective protection demands it; `None` stays inactive.
    pub fn arm_for_effective(effective: EffectiveProtection) -> Self {
        if effective.is_enabled() {
            match trap_rdtsc() {
                Ok(()) => Self {
                    active: true,
                    activation_error: None,
                },
                Err(error) => Self {
                    active: false,
                    activation_error: Some(error),
                },
            }
        } else {
            Self {
                active: false,
                activation_error: None,
            }
        }
    }

    /// Arm for a host mode; `Some` overrides env, `None` falls back to env.
    pub fn arm_for_host(host: Option<ProtectionMode>) -> Self {
        Self::arm_for_effective(effective_protection(host))
    }

    /// Typed activation failure, when the RDTSC trap could not be installed.
    ///
    /// `None` means the trap is active or was never requested.
    pub fn activation_error(&self) -> Option<&SentinelError> {
        self.activation_error.as_ref()
    }
}

impl Drop for TscTrapGuard {
    fn drop(&mut self) {
        if self.active
            && let Err(error) = allow_rdtsc()
        {
            eprintln!("ledger-sim sentinel: RDTSC trap restore failed: {error}");
        }
    }
}

/// Arm the process belt for the next sim run.
///
/// The run entry hook installs the seccomp denylist and the RDTSC trap
/// before the sim starts when armed. `arm_belt` forces arming on.
pub fn arm_belt() {
    ARMED.store(true, Ordering::Relaxed);
}

/// Armed by `arm_belt` or a truthy `LEDGER_SENTINEL_BELT`; the env read is a
/// host-side gate that never feeds the journal.
#[cfg(test)]
fn belt_armed() -> bool {
    if ARMED.load(Ordering::Relaxed) {
        return true;
    }
    !matches!(
        crate::sentinel::belt_env_mode(std::env::var_os("LEDGER_SENTINEL_BELT").as_deref()),
        crate::sentinel::BeltMode::Disabled
    )
}

/// Effective protection derived from env only (host None).
fn effective_protection_from_env() -> EffectiveProtection {
    effective_protection(None)
}

/// Effective protection: host option if set, else env mode.
///
/// `None` means disabled (env Disabled with no host) and keeps not-armed behavior.
/// `arm_belt()` counts as an explicit host-side arming request.
fn effective_protection(host: Option<ProtectionMode>) -> EffectiveProtection {
    if let Some(mode) = host {
        return mode.into();
    }
    if ARMED.load(Ordering::Relaxed) {
        return match crate::sentinel::belt_env_mode(
            std::env::var_os("LEDGER_SENTINEL_BELT").as_deref(),
        ) {
            crate::sentinel::BeltMode::Required => EffectiveProtection::Required,
            _ => EffectiveProtection::BestEffort,
        };
    }
    crate::sentinel::belt_env_mode(std::env::var_os("LEDGER_SENTINEL_BELT").as_deref()).into()
}

/// Seed the thread hasher before the denylist installs; otherwise the first
/// post-install collection would hit the blocked syscall and die.
fn pre_warm_ambient_entropy() {
    // Deliberate discard: the map exists only to seed the hasher here.
    // ledger-lint:allow:HashMap (compile probe; never populated)
    let _ = std::collections::HashMap::<u64, u64>::new();
}

/// Install the full process belt: seccomp denylist, RDTSC trap, opcode scan.
///
/// Reuses the same primitives the subprocess probes exercise, so the runtime
/// path and the belt tests share one implementation.
pub fn install_process_belt() -> Result<ProcessBeltStatus, SentinelError> {
    install_seccomp_denylist()?;
    trap_rdtsc()?;
    let rdrand_rdseed_present = scan_rdrand_rdseed()?;
    Ok(ProcessBeltStatus {
        seccomp_installed: true,
        rdtsc_trapped: true,
        rdrand_rdseed_present,
    })
}

/// Run-entry hook: warms entropy caches, then installs denylist and RDTSC
/// trap when armed. Once-per-process; a kill from the filter can never
/// become a `RunResult`.
pub fn activate_process_belt() -> BeltStatus {
    activate_process_belt_for_effective(effective_protection_from_env())
}

/// Belt install for a host mode; `Some` attempts regardless of env,
/// `Required` must reach `Active`. Shared by `Simulation` and `Executor`.
pub fn activate_process_belt_for_effective(effective: EffectiveProtection) -> BeltStatus {
    // Warm this thread's entropy caches before the filter installs, so the
    // sim's own collections never hit the blocked OS-entropy syscall.
    pre_warm_ambient_entropy();
    if !effective.is_enabled() {
        let status = BeltStatus::NotArmed;
        record_belt_status(&status);
        return status;
    };
    if BELT_INSTALLED.load(Ordering::Relaxed) {
        if let Some(status) = belt_status() {
            return status;
        }
        // The installed mark exists but no status was recorded. Never fabricate an `Active`
        // claim with a made-up scan result: fall through to a real install,
        // whose stacked denylist is identical and harmless.
        return install_and_record();
    }
    // Not yet installed: respect the legacy arm gate as a hint but attempt
    // installation for any effective Required/BestEffort regardless of env.
    // The legacy `belt_armed` check is irrelevant now: effective Some already
    // demands an attempt. We directly install.
    install_and_record()
}

/// Install the process belt once and record its status.
///
/// The status record happens BEFORE the installed mark: a concurrent
/// observer must never see the mark without a recorded report, or it could
/// fabricate an `Active` claim carrying no scan result.
fn install_and_record() -> BeltStatus {
    install_and_record_with(install_process_belt)
}

/// [`install_and_record`] with an injectable installer, so the ordering and
/// fall-through invariants are unit-testable without real seccomp.
fn install_and_record_with(
    install: impl FnOnce() -> Result<ProcessBeltStatus, SentinelError>,
) -> BeltStatus {
    match install() {
        Ok(belt) => {
            let status = BeltStatus::Active {
                rdrand_rdseed_present: belt.rdrand_rdseed_present,
            };
            if belt.rdrand_rdseed_present {
                eprintln!(
                    "ledger-sim sentinel: RDRAND/RDSEED opcodes present in an executable \
                     mapping; hardware entropy bypasses user-space control"
                );
            }
            record_belt_status(&status);
            BELT_INSTALLED.store(true, Ordering::Relaxed);
            status
        }
        Err(error) => {
            let status = BeltStatus::Failed(error);
            eprintln!("ledger-sim sentinel: {status}");
            record_belt_status(&status);
            status
        }
    }
}

/// Belt status recorded by the last run-entry hook call.
///
/// Returns None when no run has called the hook yet. The status is host state,
/// never journaled, so it does not affect determinism.
pub fn belt_status() -> Option<BeltStatus> {
    belt_status_slot()
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
}

/// Record the belt status for this run, replacing any prior per-run status.
///
/// The installed flag remains immutable (OnceLock/AtomicBool); the per-run
/// status slot is replaceable so a failed install followed by success reports fresh.
fn record_belt_status(status: &BeltStatus) {
    if let Ok(mut guard) = belt_status_slot().lock() {
        *guard = Some(status.clone());
    }
}

/// True when RDRAND/RDSEED encodings appear in an executable mapping.
/// Presence warns only; unrelated bytes can match.
pub fn scan_rdrand_rdseed() -> Result<bool, SentinelError> {
    let maps = std::fs::read_to_string("/proc/self/maps")
        .map_err(|error| SentinelError::Io(std::sync::Arc::new(error)))?;
    let mut found = false;
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let Some(range) = fields.next() else {
            continue;
        };
        let Some(perms) = fields.next() else {
            continue;
        };
        let Some(offset) = fields.next() else {
            continue;
        };
        let Some(_dev) = fields.next() else {
            continue;
        };
        let Some(inode) = fields.next() else {
            continue;
        };
        let Some(path) = fields.next() else {
            continue;
        };
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let Ok(start) = u64::from_str_radix(start, 16) else {
            continue;
        };
        let Ok(end) = u64::from_str_radix(end, 16) else {
            continue;
        };
        let Ok(file_offset) = u64::from_str_radix(offset, 16) else {
            continue;
        };
        let Ok(inode) = inode.parse::<u64>() else {
            continue;
        };
        if end <= start || !perms.contains('x') || inode == 0 || path.starts_with('[') {
            continue;
        }
        let len = (end - start) as usize;
        if len as u64 > SCAN_CAP {
            continue;
        }
        // Best-effort scan: an unreadable or unmappable file simply contributes
        // no evidence; the scan result stays the verdict.
        if let Ok(mut file) = std::fs::File::open(path)
            && file.seek(SeekFrom::Start(file_offset)).is_ok()
        {
            let mut buf = vec![0u8; len];
            if file.read_exact(&mut buf).is_ok() && scan_for_rdrand_rdseed(&buf) {
                found = true;
            }
        }
    }
    Ok(found)
}

/// True when `bytes` holds the `0F C7 F0..FF` RDRAND/RDSEED pattern.
fn scan_for_rdrand_rdseed(bytes: &[u8]) -> bool {
    bytes.windows(3).any(|window| {
        window[0] == RDRAND_PREFIX && window[1] == RDRAND_OPCODE && (window[2] & 0xF0) == 0xF0
    })
}

/// Run `cmd` under the shim and report which ambient calls fired.
pub fn run_detected(cmd: &mut Command) -> Result<DetectionReport, SentinelError> {
    let shim = shim_path();
    if !shim.is_file() {
        return Err(SentinelError::ShimMissing(shim));
    }
    let log_path = std::env::temp_dir().join(format!(
        "sentinel-{}-{}.log",
        std::process::id(),
        LOG_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut preload = shim.to_string_lossy().into_owned();
    if let Some(existing) = std::env::var_os("LD_PRELOAD") {
        preload.push(':');
        preload.push_str(&existing.to_string_lossy());
    }
    cmd.env("LD_PRELOAD", preload);
    cmd.env("LEDGER_SENTINEL_LOG", &log_path);
    let status = cmd
        .status()
        .map_err(|error| SentinelError::Io(std::sync::Arc::new(error)))?;
    if !status.success() {
        // Deliberate best-effort cleanup; the failing exit status is the error.
        let _ = std::fs::remove_file(&log_path);
        return Err(SentinelError::NonZeroExit(status));
    }
    let content = match std::fs::read_to_string(&log_path) {
        Ok(content) => content,
        // A quiet probe never triggers the shim, so no log file is created.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(SentinelError::Io(std::sync::Arc::new(error))),
    };
    // Deliberate best-effort cleanup of the probe log after parsing.
    let _ = std::fs::remove_file(&log_path);
    Ok(parse_log(&content))
}

impl Sentinel {
    /// Build a sentinel from a detection report.
    pub fn from_detection(report: &DetectionReport) -> Self {
        let mut sentinel = Sentinel::new();
        for call in &report.detected_calls {
            if let Some(class) = leak_class_for(call) {
                sentinel.record_leak(class);
            }
        }
        sentinel
    }
}

/// Map an ambient function name to its leak class.
fn leak_class_for(call: &str) -> Option<LeakClass> {
    match call {
        "getrandom" | "getentropy" => Some(LeakClass::AmbientRng),
        "clock_gettime" | "gettimeofday" | "time" => Some(LeakClass::WallClock),
        "rdtsc" | "rdrand" | "rdseed" => Some(LeakClass::TimestampCounter),
        _ => None,
    }
}

/// Parse the shim log into a sorted, deduplicated report.
fn parse_log(content: &str) -> DetectionReport {
    let mut calls = Vec::new();
    for &known in INTERPOSED_CALLS {
        if content.lines().any(|line| line.trim() == known) {
            calls.push(known);
        }
    }
    DetectionReport {
        detected_calls: calls,
    }
}

/// Syscall numbers denied by the seccomp filter.
fn deny_syscalls() -> Vec<libc::c_long> {
    let mut syscalls = vec![
        libc::SYS_getrandom,
        libc::SYS_gettimeofday,
        libc::SYS_clock_gettime,
    ];
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    syscalls.push(libc::SYS_time);
    #[cfg(target_arch = "riscv32")]
    syscalls.push(libc::SYS_clock_gettime64);
    syscalls
}

/// Native seccomp architecture id, or None when this arch is unsupported.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "x86"))]
fn native_audit_arch() -> Option<u32> {
    #[cfg(target_arch = "x86_64")]
    let arch: u32 = 0xC000_003E;
    #[cfg(target_arch = "aarch64")]
    let arch: u32 = 0xC000_00B7;
    #[cfg(target_arch = "x86")]
    let arch: u32 = 0x4000_0003;
    Some(arch)
}

/// Unsupported architectures cannot install a correct filter.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "x86")))]
fn native_audit_arch() -> Option<u32> {
    None
}

/// Build a load-or-return BPF statement.
fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

/// Build a conditional-jump BPF instruction.
fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Return the last errno as an integer.
fn errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .map_or(0, |value| value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_rdrand_encoding() {
        assert!(scan_for_rdrand_rdseed(&[0x90, 0x0F, 0xC7, 0xF0, 0x90]));
    }

    #[test]
    fn detects_rdseed_encoding() {
        assert!(scan_for_rdrand_rdseed(&[0x0F, 0xC7, 0xFF]));
    }

    #[test]
    fn ignores_unrelated_byte_patterns() {
        assert!(!scan_for_rdrand_rdseed(&[0x0F, 0xC7, 0x0F]));
        assert!(!scan_for_rdrand_rdseed(&[0x0F, 0xC8, 0xF0]));
        assert!(!scan_for_rdrand_rdseed(&[0x0F, 0xC7, 0xE0]));
    }

    /// Never fabricates `Active`: the installed mark without a record still
    /// resolves through the real installer.
    #[test]
    fn installed_mark_without_record_never_fabricates_active() {
        // Reset global for this test: separate immutable installed flag from
        // replaceable per-run status.
        BELT_INSTALLED.store(false, Ordering::Relaxed);
        *belt_status_slot().lock().expect("lock") = None;
        let status = install_and_record_with(|| {
            Ok(ProcessBeltStatus {
                seccomp_installed: true,
                rdtsc_trapped: true,
                rdrand_rdseed_present: true,
            })
        });
        assert_eq!(
            status,
            BeltStatus::Active {
                rdrand_rdseed_present: true
            },
            "the real scan result must be reported, not a fabricated one"
        );
        // The install mark is set only after the status record: a concurrent
        // observer that hits the mark already finds the report in place.
        assert!(BELT_INSTALLED.load(Ordering::Relaxed));
        assert_eq!(
            belt_status(),
            Some(BeltStatus::Active {
                rdrand_rdseed_present: true
            })
        );
        // A failing installer keeps the typed error inside the variant and
        // overwrites the per-run status slot so later runs report fresh state;
        // the immutable installed flag stays true.
        let failed = install_and_record_with(|| Err(SentinelError::Prctl("PR_SET_TSC", 22)));
        assert_eq!(
            failed,
            BeltStatus::Failed(SentinelError::Prctl("PR_SET_TSC", 22)),
            "the typed error must round-trip through the Failed variant"
        );
        assert_eq!(
            belt_status(),
            Some(BeltStatus::Failed(SentinelError::Prctl("PR_SET_TSC", 22))),
            "per-run status is replaceable, so failed overwrites prior Active"
        );
        assert!(BELT_INSTALLED.load(Ordering::Relaxed));
    }

    #[test]
    fn failed_then_success_reports_fresh_status() {
        // Prove replaceable per-run slot: failed -> successful reports fresh.
        BELT_INSTALLED.store(false, Ordering::Relaxed);
        *belt_status_slot().lock().expect("lock") = None;
        let failed = install_and_record_with(|| Err(SentinelError::Prctl("PR_SET_TSC", 22)));
        assert_eq!(
            failed,
            BeltStatus::Failed(SentinelError::Prctl("PR_SET_TSC", 22))
        );
        assert_eq!(
            belt_status(),
            Some(BeltStatus::Failed(SentinelError::Prctl("PR_SET_TSC", 22)))
        );
        assert!(!BELT_INSTALLED.load(Ordering::Relaxed));
        let success = install_and_record_with(|| {
            Ok(ProcessBeltStatus {
                seccomp_installed: true,
                rdtsc_trapped: true,
                rdrand_rdseed_present: false,
            })
        });
        assert_eq!(
            success,
            BeltStatus::Active {
                rdrand_rdseed_present: false
            }
        );
        assert_eq!(
            belt_status(),
            Some(BeltStatus::Active {
                rdrand_rdseed_present: false
            }),
            "successful install after failed must report fresh Active"
        );
        assert!(BELT_INSTALLED.load(Ordering::Relaxed));
    }

    /// Guard reports a typed failure instead of claiming an uninstalled trap.
    #[test]
    fn tsc_guard_state_matches_belt_state() {
        let was_armed = belt_armed();
        let guard = TscTrapGuard::arm_if_armed();
        if was_armed {
            match guard.activation_error() {
                Some(SentinelError::Prctl(..)) => {
                    // Trap unavailable: the guard stays inactive and the
                    // failure is typed, never silent.
                }
                Some(other) => panic!("unexpected typed activation failure: {other}"),
                None => {
                    // Trap installed: the guard is active and the drop below
                    // restores PR_TSC_ENABLE.
                }
            }
        } else {
            assert!(
                guard.activation_error().is_none(),
                "an unarmed belt must not attempt or report a trap"
            );
        }
        drop(guard);
    }
}
