//! Probe binary for the process-belt leak sentinel.
//!
//! Each mode exercises one belt surface so the integration tests can observe
//! interposition, seccomp, RDTSC trapping, runtime wiring, and opcode scans
//! from outside the process.
// ledger-lint:allow:SystemTime::now() (probe deliberately triggers ambient time calls)
// ledger-lint:allow:libc::time (probe deliberately triggers ambient time calls)
// ledger-lint:allow:libc::clock_gettime (probe deliberately triggers ambient time calls)
// ledger-lint:allow:libc::gettimeofday (probe deliberately triggers ambient time calls)
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
        _ => {
            println!("probe-unknown-mode");
            ExitCode::from(3)
        }
    }
}

/// Fire every interposed ambient API once.
fn ambient() -> ExitCode {
    let mut buf = [0u8; 8];
    let _ = getrandom::fill(&mut buf);
    let _ = std::time::SystemTime::now();
    // Safety: a null output pointer is a valid libc::time argument.
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
    if let Err(error) = ledger_sim::sentinel_belt::install_seccomp_denylist() {
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
        if let Err(error) = ledger_sim::sentinel_belt::trap_rdtsc() {
            println!("tsc-install-failed: {error}");
            return ExitCode::from(2);
        }
        // Safety: _rdtsc has no side effects on memory; the trap does the work.
        let _ = unsafe { std::arch::x86_64::_rdtsc() };
        println!("tsc-trapped");
    }
    ExitCode::SUCCESS
}

/// Arm the belt and install it; prints the activation status.
#[cfg(all(feature = "sentinel", target_os = "linux"))]
fn belt() -> ExitCode {
    ledger_sim::sentinel_belt::arm_belt();
    let status = ledger_sim::sentinel::activate_process_belt();
    println!("belt-status: {status:?}");
    ExitCode::SUCCESS
}

/// Run a mini sim through the public run path and print the belt report.
///
/// When LEDGER_SENTINEL_BELT is set, the run entry hook arms the belt first;
/// the sim then runs under the seccomp denylist and the RDTSC trap.
#[cfg(all(feature = "sentinel", target_os = "linux"))]
fn simulate() -> ExitCode {
    let config = ledger_sim::RunConfig {
        seed: [42; 32],
        policy: ledger_sim::Policy::Random,
        max_steps: 128,
        ..ledger_sim::RunConfig::default()
    };
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
            let belt = ledger_sim::sentinel_belt::belt_status();
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
    let _ = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let _ = unsafe { libc::gettimeofday(&mut tv, std::ptr::null_mut()) };
    println!("probe-done");
    ExitCode::SUCCESS
}
