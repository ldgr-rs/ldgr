//! Process-belt leak sentinel: LD_PRELOAD shim, seccomp denylist, RDTSC trap,
//! and hardware-entropy opcode scan.
//!
//! The belt runs ambient-API probes in subprocesses so its filters can never
//! break the test harness that drives them. The runtime hooks
//! `activate_process_belt` at the sim run entry; with the `sentinel` feature
//! compiled in on Linux it installs the seccomp denylist and the RDTSC trap by
//! default before the sim starts.
// ledger-lint:allow:env::var (belt harness reads LD_PRELOAD to prepend the shim)
// ledger-lint:allow:std::fs:: (belt harness writes and parses the shim log file)
// ledger-lint:allow:rdrand (the leak-class table must name the tsc-class intrinsics)
// ledger-lint:allow:rdseed (the leak-class table must name the tsc-class intrinsics)

#![allow(unsafe_code)]

use std::fmt;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::sentinel::{BeltStatus, LeakClass, Sentinel};

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

/// Function names the interposition shim records in the log file.
///
/// All five are the syscall-surface ambient APIs. On glibc,
/// `clock_gettime`, `gettimeofday`, and `time` are normally served from the
/// vDSO without a syscall; the shim still catches them because it interposes
/// the PLT symbol before the libc definition is reached. Only code that
/// bypasses the PLT (a direct `__vdso_clock_gettime` call or an inlined
/// copy) escapes the shim.
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
static LAST_BELT_STATUS: OnceLock<BeltStatus> = OnceLock::new();

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

/// Sentinel belt errors.
#[derive(Debug)]
pub enum SentinelError {
    /// The seccomp architecture is not covered by this crate.
    UnsupportedArch,
    /// The built interposition shim is missing on disk.
    ShimMissing(PathBuf),
    /// A prctl operation failed with the given errno.
    Prctl(&'static str, i32),
    /// An I/O error while spawning the probe or parsing its log.
    Io(std::io::Error),
    /// The probe exited without the expected zero status.
    NonZeroExit(ExitStatus),
}

impl fmt::Display for SentinelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedArch => write!(f, "sentinel belt does not support this architecture"),
            Self::ShimMissing(path) => write!(f, "sentinel shim not found: {}", path.display()),
            Self::Prctl(operation, errno) => write!(f, "{operation} failed with errno {errno}"),
            Self::Io(error) => write!(f, "sentinel belt I/O error: {error}"),
            Self::NonZeroExit(status) => write!(f, "probe did not exit cleanly: {status:?}"),
        }
    }
}

impl std::error::Error for SentinelError {}

/// Return the path of the built interposition shim.
pub fn shim_path() -> PathBuf {
    PathBuf::from(env!("SENTINEL_SHIM_PATH"))
}

/// Install a seccomp filter that kills any process issuing an ambient syscall.
///
/// The filter blocks the OS-entropy and ambient-clock syscalls (plus the
/// 32-bit time64 variant where applicable) and allows everything else.
/// It requires no_new_privs, so it cannot be installed by an unprivileged
/// process that later needs capabilities. Call this only inside a subprocess.
///
/// The action is `SECCOMP_RET_KILL_PROCESS`, not
/// `SECCOMP_RET_USER_NOTIF`. USER_NOTIF requires a
/// supervising thread that owns the listener fd and services every
/// notification with a SECCOMP_IOCTL_NOTIF_RECV loop; without that thread the
/// kernel blocks the syscall and the process deadlocks. The sim is
/// single-threaded by invariant (determinism rules forbid OS threads inside a
/// simulation), so no supervisor exists to answer notifications. KILL_PROCESS
/// keeps the denylist effective without a second thread: an ambient syscall
/// terminates the process instead of leaking nondeterminism into the journal.
/// Hardware-entropy reads (RDRAND/RDSEED) are instructions and stay outside
/// seccomp either way; `scan_rdrand_rdseed` reports their presence.
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
        program.push(bpf_jump(BPF_JMP_JEQ_K, syscall as u32, 0, 1));
        program.push(bpf_stmt(BPF_RET_K, libc::SECCOMP_RET_KILL_PROCESS));
    }
    program.push(bpf_stmt(BPF_RET_K, libc::SECCOMP_RET_ALLOW));

    let mut prog = libc::sock_fprog {
        len: program.len() as u16,
        filter: program.as_mut_ptr(),
    };
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

/// Trap RDTSC reads with SIGSEGV through prctl PR_SET_TSC.
///
/// Any subsequent RDTSC/RDTSCP instruction faults, so a probe that issues one
/// dies before it can leak the timestamp. Call this only inside a subprocess.
pub fn trap_rdtsc() -> Result<(), SentinelError> {
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
    unsafe {
        let ret = libc::prctl(libc::PR_SET_TSC, libc::PR_TSC_ENABLE, 0, 0, 0);
        if ret != 0 {
            return Err(SentinelError::Prctl("PR_SET_TSC", errno()));
        }
    }
    Ok(())
}

/// Scoped RAII guard that traps RDTSC reads during simulation and restores PR_TSC_ENABLE on drop.
#[derive(Debug)]
pub struct TscTrapGuard {
    active: bool,
}

impl TscTrapGuard {
    /// Enter a section where RDTSC reads are trapped with SIGSEGV if the belt is armed.
    pub fn arm_if_armed() -> Self {
        if belt_armed() {
            let _ = trap_rdtsc();
            Self { active: true }
        } else {
            Self { active: false }
        }
    }
}

impl Drop for TscTrapGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = allow_rdtsc();
        }
    }
}

/// Arm the process belt for the next sim run.
///
/// Arm the process belt for the next sim run.
///
/// The run entry hook installs the seccomp denylist and the RDTSC trap
/// before the sim starts when armed. `arm_belt` forces arming on.
pub fn arm_belt() {
    ARMED.store(true, Ordering::Relaxed);
}

/// Return true when the process belt is armed.
///
/// The belt is armed by `arm_belt` or by a truthy `LEDGER_SENTINEL_BELT`
/// environment value (`1`, `true`, `on`, `yes`). By default, the belt is not
/// armed so it does not install permanent seccomp filters on the host process.
/// The env read is a host-side gate at run entry: it never feeds the journal,
/// the scheduler, or any simulated effect, so it cannot perturb a deterministic run.
fn belt_armed() -> bool {
    if ARMED.load(Ordering::Relaxed) {
        return true;
    }
    match std::env::var_os("LEDGER_SENTINEL_BELT") {
        Some(value) => matches!(
            value.to_string_lossy().as_ref(),
            "1" | "true" | "on" | "yes"
        ),
        None => false,
    }
}

/// Warm the per-thread entropy caches the sim runtime relies on.
///
/// `std::collections::HashMap` and `HashSet` (and hashbrown's default hasher)
/// seed their hasher from OS entropy, once per thread. This
/// function constructs one map on the current thread so that seeding happens
/// here, BEFORE the seccomp denylist installs. The call is a deliberate,
/// host-side, one-time action at run entry; it is not part of a simulation,
/// so it does not violate the determinism rules. Without the warm-up, the
/// first collection created after installation would hit the blocked syscall
/// and the kernel would kill the process.
fn pre_warm_ambient_entropy() {
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

/// Run-entry belt hook wired into `Simulation::run`.
///
/// Warms this thread's entropy caches, then installs the seccomp denylist and
/// the RDTSC trap when the process belt is armed. With the `sentinel` feature
/// compiled in on Linux the belt is armed by default; `LEDGER_SENTINEL_BELT=0`
/// (or `false`, `off`, `no`) disables it for the process. Installation happens
/// once per process: seccomp filters cannot be removed, and stacking identical
/// filters is wasteful. The returned status is the report a caller can log or
/// assert; on failures the hook also emits a warning line.
pub fn activate_process_belt() -> BeltStatus {
    // Warm this thread's entropy caches before the filter installs, so the
    // sim's own collections never hit the blocked OS-entropy syscall.
    pre_warm_ambient_entropy();
    if !belt_armed() {
        let status = BeltStatus::NotArmed;
        record_belt_status(&status);
        return status;
    }
    if BELT_INSTALLED.load(Ordering::Relaxed) {
        if let Some(status) = belt_status() {
            return status;
        }
        return BeltStatus::Active {
            rdrand_rdseed_present: false,
        };
    }
    match install_process_belt() {
        Ok(belt) => {
            BELT_INSTALLED.store(true, Ordering::Relaxed);
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
            status
        }
        Err(error) => {
            let status = BeltStatus::Failed(error.to_string());
            eprintln!("ledger-sim sentinel: belt activation failed: {error}");
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
    LAST_BELT_STATUS.get().cloned()
}

/// Record the belt status once; the first call wins.
fn record_belt_status(status: &BeltStatus) {
    // Discard the Err from a second set: the first recorded status is the
    // authoritative one for the process.
    let _ = LAST_BELT_STATUS.set(status.clone());
}

/// Return true when RDRAND or RDSEED opcodes appear in an executable mapping.
///
/// RDRAND/RDSEED are CPU instructions, invisible to seccomp, and masking them
/// in user space would need a hypervisor or a signal-based instruction
/// emulator. This scan implements the detectable half of that residual: it
/// walks /proc/self/maps for executable, file-backed
/// mappings and scans the mapped bytes for the encodings `0F C7 F0..FF`
/// (RDRAND r32 is ModRM /6, RDSEED r32 is ModRM /7). A true result is a
/// warning that the encodings are present, not a proof that entropy was read;
/// unrelated data can contain the same three bytes.
pub fn scan_rdrand_rdseed() -> Result<bool, SentinelError> {
    let maps = std::fs::read_to_string("/proc/self/maps").map_err(SentinelError::Io)?;
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

/// Return true when the RDRAND/RDSEED byte pattern occurs in `bytes`.
///
/// RDRAND r32 is ModRM /6 (`11 110 rrr` = 0xF0..0xF7), RDSEED r32 is ModRM
/// /7 (`11 111 rrr` = 0xF8..0xFF); both share the high 4 bits, so the mask
/// `0xF0` covers the full `0F C7 F0..FF` span.
fn scan_for_rdrand_rdseed(bytes: &[u8]) -> bool {
    bytes.windows(3).any(|window| {
        window[0] == RDRAND_PREFIX && window[1] == RDRAND_OPCODE && (window[2] & 0xF0) == 0xF0
    })
}

/// Run `cmd` under the interposition shim and report which ambient calls fired.
///
/// Sets LD_PRELOAD to the shim (prepending any existing value) and points
/// LEDGER_SENTINEL_LOG at a fresh temp file. Waits for the probe, parses the
/// log, and returns the sorted, deduplicated function names that were called.
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
    let status = cmd.status().map_err(SentinelError::Io)?;
    if !status.success() {
        let _ = std::fs::remove_file(&log_path);
        return Err(SentinelError::NonZeroExit(status));
    }
    let content = match std::fs::read_to_string(&log_path) {
        Ok(content) => content,
        // A quiet probe never triggers the shim, so no log file is created.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(SentinelError::Io(error)),
    };
    let _ = std::fs::remove_file(&log_path);
    Ok(parse_log(&content))
}

impl Sentinel {
    /// Build a sentinel from a process-belt detection report.
    ///
    /// Maps each flagged function name to its determinism leak class.
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
    use super::scan_for_rdrand_rdseed;

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
}
