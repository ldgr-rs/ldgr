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

/// Install a seccomp filter that kills any process issuing an ambient syscall.
///
/// The filter blocks the OS-entropy and ambient-clock syscalls (plus the
/// 32-bit time64 variant where applicable) and allows everything else.
/// It requires no_new_privs, so it cannot be installed by an unprivileged
/// process that later needs capabilities. Call this only inside a subprocess.
///
/// The filter is process-wide and irrevocable once installed. The action is
/// `SECCOMP_RET_KILL_PROCESS`, not `SECCOMP_RET_USER_NOTIF`. USER_NOTIF
/// requires a supervising thread that owns the listener fd and services every
/// notification with a SECCOMP_IOCTL_NOTIF_RECV loop; without that thread the
/// kernel blocks the syscall and the process deadlocks. The sim is
/// single-threaded by invariant (determinism rules forbid OS threads inside a
/// simulation), so no supervisor exists to answer notifications. KILL_PROCESS
/// keeps the denylist effective without a second thread: an ambient syscall
/// terminates the process instead of leaking nondeterminism into the journal.
/// Because the kill is delivered by the kernel as a process-wide termination,
/// it kills the whole sim process mid-run and that outcome can never become a
/// normal run error (no `RunResult` or `RuntimeError` can be produced from a
/// killed process). Hardware-entropy reads (RDRAND/RDSEED) are instructions and
/// stay outside seccomp either way; `scan_rdrand_rdseed` reports their
/// presence.
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

/// Trap RDTSC reads with SIGSEGV through prctl PR_SET_TSC.
///
/// Any subsequent RDTSC/RDTSCP instruction faults, so a probe that issues one
/// dies before it can leak the timestamp. Call this only inside a subprocess.
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

/// Scoped RAII guard that traps RDTSC reads during simulation and restores PR_TSC_ENABLE on drop.
#[derive(Debug)]
pub struct TscTrapGuard {
    active: bool,
    activation_error: Option<SentinelError>,
}

impl TscTrapGuard {
    /// Enter a section where RDTSC reads are trapped with SIGSEGV if the belt is armed.
    ///
    /// The guard is active only when the trap really installed. A failed
    /// activation stays queryable via [`TscTrapGuard::activation_error`] so
    /// the run entry can propagate the typed error instead of pretending the
    /// trap is in place.
    pub fn arm_if_armed() -> Self {
        Self::arm_for_effective(effective_protection_from_env())
    }

    /// Enter a section where RDTSC reads are trapped when effective protection demands it.
    ///
    /// When effective protection is `Some`, the trap is attempted regardless of the
    /// env arming gate; when `None` (env Disabled with no host option) the guard stays inactive.
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

    /// Enter a section where RDTSC reads are trapped for a host-requested mode.
    ///
    /// Host option `Some` overrides env; `None` falls back to env mode.
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

/// Return true when the process belt is armed.
///
/// The belt is armed by `arm_belt` or by a truthy `LEDGER_SENTINEL_BELT`
/// environment value (`1`, `true`, `on`, `yes`, `required`). By default, the
/// belt is not armed so it does not install permanent seccomp filters on the
/// host process. The env read is a host-side gate at run entry: it never feeds
/// the journal, the scheduler, or any simulated effect, so it cannot perturb a
/// deterministic run. Env parsing is delegated to [`crate::sentinel::belt_env_mode`]
/// so callers can test the pure mapping.
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

/// Run-entry belt hook wired into `Simulation::run`.
///
/// Warms this thread's entropy caches, then installs the seccomp denylist and
/// the RDTSC trap when the process belt is armed. The belt is NOT armed by
/// default: `LEDGER_SENTINEL_BELT` must be set to `1`, `true`, `on`, `yes`, or
/// `required`, or [`arm_belt`] must be called. Installation happens once per
/// process: seccomp filters cannot be removed, so the denylist is process-wide
/// and irrevocable; stacking identical filters is wasteful; a status record
/// accompanies the install so later calls report it instead of reinstalling.
/// The filter uses `SECCOMP_RET_KILL_PROCESS`, which kills the whole sim
/// process mid-run if an ambient syscall is issued after activation and that
/// termination can never become a normal `RunResult` or `RuntimeError`.
/// The returned status is the report a caller can log or assert; on failures
/// the hook also emits a warning line.
pub fn activate_process_belt() -> BeltStatus {
    activate_process_belt_for_effective(effective_protection_from_env())
}

/// Attempt belt installation for a host-requested protection mode.
///
/// When `host` is `Some`, installation is attempted regardless of the env gate.
/// When `host` is `None`, env mode is used and `Disabled` keeps not-armed behavior.
/// `Required` must be `Active` to succeed; `BestEffort` always returns status.
///
/// This is the common execution boundary entry: both `Simulation::run` and
/// direct `Executor::run` route through it so no path bypasses enforcement.
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

    /// The belt-mark/status-record ordering and the fall-through rule: even
    /// when the installed mark is present without a local record (the
    /// first-call race), the hook must resolve through the real installer and
    /// report its actual scan result - never a fabricated `Active` claim with
    /// a made-up scan.
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

    /// The TSC guard must never claim an active trap it did not install, and
    /// a failed activation must surface the typed error instead of being
    /// swallowed. The guard's shape follows the belt state; on kernels
    /// without `PR_SET_TSC` the armed path reports a typed `Prctl` failure.
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
