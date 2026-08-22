//! Public-contract proof: this file must compile and pass identically under
//! default, `sim`, and `sim-link` builds. Every public item is constructed or
//! exercised here with one bound set, so a signature or variant that drifts
//! between feature combinations breaks all three builds at once. The dead
//! code below is intentional: it is type-checked per build but never run.

use core::future::Future;
use core::pin::Pin;
use core::time::Duration;

use ledger_format::ActorId;

use ldgr_rt::{
    Conn, DetRng, Handle, IpcFault, JournalFault, RunConfig, RunResult, RuntimeError, SimClock,
    StreamId, TaskId, TaskMain, VERSION, shared_network,
};

/// Exhaustive match: fails to compile if any variant goes missing under a
/// feature combination.
fn name_runtime_error(error: &RuntimeError) -> &'static str {
    match error {
        RuntimeError::StepLimit { .. } => "step_limit",
        RuntimeError::Journal(_) => "journal",
        RuntimeError::Ipc(_) => "ipc",
        RuntimeError::MissingRoot => "missing_root",
        RuntimeError::UnknownWorkload { .. } => "unknown_workload",
        RuntimeError::ProgramNotTransportable => "program_not_transportable",
        RuntimeError::Runtime(_) => "runtime",
    }
}

/// `journal_root` and `steps` are public fields under every feature set.
fn construct_run_result() -> RunResult {
    RunResult {
        journal_root: None,
        steps: 0,
    }
}

/// Fault wrappers are nameable and constructible without optional deps.
fn construct_faults() -> (JournalFault, IpcFault) {
    (
        JournalFault::from_message("journal fault"),
        IpcFault::from_message("ipc fault"),
    )
}

/// The program alias is nameable everywhere; the erased future stays non-Send.
#[allow(dead_code)]
type ErasedProgram = TaskMain;
const _: Option<TaskMain> = None;
#[allow(dead_code)]
type AssertNonSend = Pin<Box<dyn Future<Output = ()>>>;

/// Every `Handle` method callable with one bound set under every feature set.
#[allow(dead_code)]
fn exercise_handle(handle: &mut Handle) -> TaskId {
    let _: ActorId = handle.actor();
    let _: [u8; 32] = handle.seed();
    let _: SimClock = handle.clock();
    let _rebound: Handle = handle.with_actor(1);
    let _sent: bool = handle.net_send(1, 7);
    let _: Conn = handle.conn(0, 1);
    let stream: StreamId = 0;
    let _: DetRng = handle.rng(stream);
    let _: u64 = handle.rng_next_u64(stream);
    let _installed: Option<Handle> = Handle::current();
    let _shared = shared_network();
    let id: TaskId = handle.spawn(|child| {
        let _: ActorId = child.actor();
        Box::pin(async {})
    });
    id
}

/// Registration and named dispatch keep one signature everywhere.
#[allow(dead_code)]
fn exercise_registration(build: fn() -> TaskMain) -> Result<RunResult, RuntimeError> {
    ldgr_rt::register_workload("contract-workload", build);
    ldgr_rt::run_named(RunConfig::default(), "contract-workload")
}

/// Named dispatch on direct-executor backends must execute the CALLER's
/// registered program end-to-end, not some stand-in workload.
#[cfg(not(all(feature = "sim", not(feature = "sim-link"))))]
#[test]
fn registered_named_run_executes_the_caller_program() {
    use core::cell::Cell;
    thread_local! {
        static RAN: Cell<bool> = const { Cell::new(false) };
    }
    fn factory() -> TaskMain {
        Box::new(|_handle| {
            Box::pin(async {
                RAN.with(|ran| ran.set(true));
            })
        })
    }

    ldgr_rt::register_workload("public-contract-wl", factory);
    let res = ldgr_rt::run_named(
        RunConfig::builder().seed([23u8; 32]).max_steps(512).build(),
        "public-contract-wl",
    );
    assert!(res.is_ok(), "{res:?}");
    assert!(
        RAN.with(Cell::get),
        "the registered program itself must have executed"
    );
}

/// Async surface: sleep and net_recv share one signature everywhere.
#[allow(dead_code)]
async fn exercise_handle_async(handle: &Handle) {
    handle.sleep(Duration::from_millis(1)).await;
    let _: u64 = handle.net_recv().await;
}

/// `run` accepts one bound set everywhere: plain futures, no Send bound.
#[allow(dead_code)]
fn exercise_run_signature(config: RunConfig) -> Result<RunResult, RuntimeError> {
    ldgr_rt::run(config.clone(), |handle| async move {
        let _ = handle.clock().now();
    })?;
    ldgr_rt::run(config, |_handle| async {})
}

#[test]
fn version_probe_and_pure_helpers_are_available_everywhere() {
    assert!(!VERSION.is_empty());
    ldgr_rt::probe();
    let hash = [9u8; 32];
    let first = ldgr_rt::task_id_for("workload", hash);
    let second = ldgr_rt::task_id_for("workload", hash);
    assert_eq!(first, second);
    assert_ne!(first.0, 0);
}

#[test]
fn public_types_construct_identically_under_every_combo() {
    let result = construct_run_result();
    assert_eq!(result.steps, 0);
    assert!(result.journal_root.is_none());

    let (journal, ipc) = construct_faults();
    assert_eq!(journal.message(), "journal fault");
    assert_eq!(ipc.message(), "ipc fault");
    // Source chains stay walkable where they exist.
    assert!(core::error::Error::source(&journal).is_none());

    let config = RunConfig::builder().seed([1u8; 32]).max_steps(8).build();
    assert_eq!(config.seed(), [1u8; 32]);
    assert_eq!(RunConfig::default().max_steps, 10_000);

    let error = RuntimeError::StepLimit { limit: 3 };
    assert_eq!(name_runtime_error(&error), "step_limit");

    let _id = TaskId(1);
}

/// Mirror of `ipc::EngineProcess::resolve_engine_path` precedence so tests
/// decide IPC testability exactly like production: empty `LEDGER_ENGINE_BIN`
/// falls through, a set-but-missing binary is a setup error, and an installed
/// `ledger` on PATH avoids false skips.
// ledger-lint:allow - host-side test probes ambient env by design
#[cfg(all(feature = "sim", not(feature = "sim-link")))]
fn resolve_engine_for_test() -> Option<std::path::PathBuf> {
    if let Ok(env) = std::env::var("LEDGER_ENGINE_BIN") {
        let path = std::path::PathBuf::from(&env);
        if path.exists() {
            return Some(path);
        }
        if !env.trim().is_empty() {
            panic!(
                "LEDGER_ENGINE_BIN is set to {env} but the binary does not exist; \
                 build ledger-cli or clear LEDGER_ENGINE_BIN"
            );
        }
    }
    let candidate =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/ledger");
    if candidate.exists() {
        return Some(candidate);
    }
    for dir in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        let installed = dir.join("ledger");
        if installed.is_file() {
            return Some(installed);
        }
    }
    None
}

/// `run` installs the thread-local handle for the duration of the program,
/// and refuses caller programs loudly under IPC-only builds instead of
/// polling them against some other workload.
#[test]
fn handle_current_is_installed_inside_run() {
    #[cfg(all(feature = "sim", not(feature = "sim-link")))]
    {
        let error =
            ldgr_rt::run(RunConfig::default(), |_handle| async {}).expect_err("must refuse");
        assert!(
            matches!(error, RuntimeError::ProgramNotTransportable),
            "{error}"
        );
    }
    #[cfg(not(all(feature = "sim", not(feature = "sim-link"))))]
    {
        let res = ldgr_rt::run(
            RunConfig::builder().seed([3u8; 32]).max_steps(256).build(),
            |handle| async move {
                assert!(
                    Handle::current().is_some(),
                    "run must install Handle::current"
                );
                handle.sleep(Duration::from_millis(1)).await;
            },
        );
        assert!(res.is_ok(), "{res:?}");
    }
}

/// Under `sim` (IPC) `run_named` reaches the engine's registered server
/// workloads over the socket and yields a deterministic journal root.
/// Skipped without an engine binary, resolved with production precedence.
#[cfg(all(feature = "sim", not(feature = "sim-link")))]
#[test]
fn named_run_reaches_server_workload_under_ipc() {
    if resolve_engine_for_test().is_none() {
        eprintln!("skipping: no engine binary for IPC transport");
        return;
    }
    let config = RunConfig::builder().seed([21u8; 32]).max_steps(256).build();
    let a = ldgr_rt::run_named(config.clone(), "kv").expect("named kv run must succeed");
    let b = ldgr_rt::run_named(config, "kv").expect("named kv rerun must succeed");
    assert_eq!(a.journal_root, b.journal_root, "server roots deterministic");
    assert!(a.journal_root.is_some());
}
