//! Probe binary for the process-belt leak sentinel.
//!
//! Each mode exercises one belt surface so the integration tests can observe
//! interposition, seccomp, RDTSC trapping, runtime wiring, and opcode scans
//! from outside the process.
// ledger-lint:allow:SystemTime::now() (probe deliberately triggers ambient time calls)
// ledger-lint:allow:libc::time (probe deliberately triggers ambient time calls)
// ledger-lint:allow:libc::clock_gettime (probe deliberately triggers ambient time calls)
// ledger-lint:allow:libc::gettimeofday (probe deliberately triggers ambient time calls)
// ledger-lint:allow:libc::getrandom (probe deliberately triggers ambient entropy calls)
// ledger-lint:allow:getrandom:: (probe deliberately triggers ambient entropy calls)
// ledger-lint:allow:env::var (probe reads its own mode from the environment)

use std::process::ExitCode;

fn main() -> ExitCode {
    let mode = std::env::var("LEDGER_PROBE_MODE").unwrap_or_default();
    match mode.as_str() {
        "ambient" => ambient(),
        "clean" => clean(),
        #[cfg(all(feature = "sentinel", target_os = "linux"))]
        "seccomp" => seccomp(),
        #[cfg(all(feature = "sentinel", target_os = "linux"))]
        "tsc" => tsc(),
        #[cfg(all(feature = "sentinel", target_os = "linux"))]
        "belt" => belt(),
        #[cfg(all(feature = "sentinel", target_os = "linux"))]
        "simulate" => simulate(),
        #[cfg(all(feature = "sentinel", target_os = "linux"))]
        "vdsoclk" => vdsoclk(),
        #[cfg(all(feature = "sentinel", target_os = "linux"))]
        "virtclk" => virtclk(),
        #[cfg(all(feature = "sentinel", target_os = "linux"))]
        "virtrnd" => virtrnd(),
        _ => {
            println!("probe-unknown-mode");
            ExitCode::from(3)
        }
    }
}

/// Fire every interposed ambient API once.
fn ambient() -> ExitCode {
    let mut buf = [0u8; 8];
    // Deliberate ambient call; the probe verifies the belt's reaction.
    let _ = getrandom::fill(&mut buf);
    // Deliberate ambient call; the probe verifies the belt's reaction.
    let _ = std::time::SystemTime::now();
    // Safety: a null output pointer is a valid libc::time argument.
    // Deliberate ambient call; the probe verifies the belt's reaction.
    let _ = unsafe { libc::time(std::ptr::null_mut()) };
    println!("probe-done");
    ExitCode::SUCCESS
}

/// Perform only deterministic work; the interposed APIs must stay quiet.
fn clean() -> ExitCode {
    std::thread::sleep(std::time::Duration::from_millis(5));
    println!("probe-done");
    ExitCode::SUCCESS
}

/// Install the seccomp denylist and attempt an ambient read.
#[cfg(all(feature = "sentinel", target_os = "linux"))]
fn seccomp() -> ExitCode {
    if let Err(error) = ledger_sim::install_seccomp_denylist() {
        println!("seccomp-install-failed: {error}");
        return ExitCode::from(2);
    }
    let mut buf = [0u8; 8];
    match getrandom::fill(&mut buf) {
        Ok(()) => println!("seccomp-survived"),
        Err(error) => println!("seccomp-blocked: {error:?}"),
    }
    println!("probe-done");
    ExitCode::SUCCESS
}

/// Trap RDTSC and then execute one read; the kernel must deliver SIGSEGV.
#[cfg(all(feature = "sentinel", target_os = "linux"))]
fn tsc() -> ExitCode {
    #[cfg(not(target_arch = "x86_64"))]
    {
        println!("tsc-unavailable");
        return ExitCode::SUCCESS;
    }
    #[cfg(target_arch = "x86_64")]
    {
        if let Err(error) = ledger_sim::trap_rdtsc() {
            println!("tsc-install-failed: {error}");
            return ExitCode::from(2);
        }
        // Safety: _rdtsc has no side effects on memory; the trap does the work.
        // Deliberate ambient call; the probe verifies the TSC trap.
        let _ = unsafe { std::arch::x86_64::_rdtsc() };
        println!("tsc-trapped");
    }
    ExitCode::SUCCESS
}

/// Arm the belt and install it; prints the activation status.
#[cfg(all(feature = "sentinel", target_os = "linux"))]
fn belt() -> ExitCode {
    ledger_sim::arm_belt();
    let status = ledger_sim::activate_process_belt();
    println!("belt-status: {status:?}");
    ExitCode::SUCCESS
}

/// Run a mini sim through the public run path and print the belt report.
///
/// When LEDGER_SENTINEL_BELT is set, the run entry hook arms the belt first;
/// the sim then runs under the seccomp denylist and the RDTSC trap.
#[cfg(all(feature = "sentinel", target_os = "linux"))]
fn simulate() -> ExitCode {
    let config = ledger_sim::RunConfig::builder()
        .seed(ledger_format::EntryHash([42; 32]))
        .policy(ledger_sim::Policy::Random)
        .max_steps(128)
        .build();
    let programs = vec![
        vec![
            ledger_sim::Instruction::Send { to: 1, payload: 7 },
            ledger_sim::Instruction::Done,
        ],
        vec![
            ledger_sim::Instruction::Receive,
            ledger_sim::Instruction::Outcome,
            ledger_sim::Instruction::Done,
        ],
    ];
    match ledger_sim::Simulation::new(config, programs).run() {
        Ok(run) => {
            let belt = ledger_sim::belt_status();
            println!("simulate-ok steps={} belt={belt:?}", run.steps);
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!("simulate-error: {error}");
            ExitCode::from(2)
        }
    }
}

/// Fire the vDSO-resident clock entry points directly through the PLT.
#[cfg(all(feature = "sentinel", target_os = "linux"))]
fn vdsoclk() -> ExitCode {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // Deliberate ambient call; the probe verifies the vDSO clock path.
    let _ = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    // Deliberate ambient call; the probe verifies the vDSO clock path.
    let _ = unsafe { libc::gettimeofday(&mut tv, std::ptr::null_mut()) };
    println!("probe-done");
    ExitCode::SUCCESS
}

/// Print the raw CLOCK_REALTIME result as "sec=<u64> nsec=<u64>".
///
/// The e2e virtualization test asserts exact values from this line, so the
/// call must go through the PLT where the shim interposes it.
#[cfg(all(feature = "sentinel", target_os = "linux"))]
fn virtclk() -> ExitCode {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    if ret != 0 {
        println!("virtclk-error");
        return ExitCode::from(2);
    }
    println!("sec={} nsec={}", ts.tv_sec as u64, ts.tv_nsec as u64);
    ExitCode::SUCCESS
}

/// Fill a fixed buffer through the PLT getrandom symbol and print hex.
///
/// The direct libc call keeps the interposition path explicit: the
/// getrandom crate may issue the raw syscall and bypass the shim.
#[cfg(all(feature = "sentinel", target_os = "linux"))]
fn virtrnd() -> ExitCode {
    let mut buf = [0u8; 16];
    let mut off = 0usize;
    while off < buf.len() {
        let n = unsafe { libc::getrandom(buf[off..].as_mut_ptr().cast(), buf.len() - off, 0) };
        if n <= 0 {
            println!("virtrnd-error");
            return ExitCode::from(2);
        }
        off += n as usize;
    }
    print!("rnd=");
    for byte in buf {
        print!("{byte:02x}");
    }
    println!();
    ExitCode::SUCCESS
}
