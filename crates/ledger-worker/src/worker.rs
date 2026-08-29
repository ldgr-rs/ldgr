use std::sync::Arc;
use std::time::Duration;

use ledger_explorer::search::Workload;
use ledger_format::Hash;
use ledger_sim::{Instruction, Simulation};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::artifact::{ArtifactSink, NoopSink, WORKER_BUILDER_ID, certificate_json, checksum_hex};
use crate::config::WorkerConfig;
use crate::queue::{InMemoryQueue, Task, TaskQueue};

/// Result of a successful task execution.
#[derive(Debug, Clone)]
pub struct WorkerResult {
    /// Task identifier.
    pub task_id: String,
    /// Journal root hash after execution.
    pub journal_root: Hash,
    /// Number of steps executed.
    pub steps: usize,
    /// Findings count from the pre-run explorer campaign.
    pub campaign_findings: usize,
    /// Execution-identity digest assembled by the worker for this task.
    ///
    /// `None` when the worker build data is incomplete (no source revision
    /// captured at compile time); such results must be treated as
    /// identity-incomplete by the control plane.
    pub execution_identity: Option<Hash>,
}

/// Errors from worker execution.
#[derive(Debug, Error)]
pub enum WorkerError {
    /// The queued run_config hash did not match the recomputed canonical
    /// hash; the deterministic boundary rejects the task.
    #[error("run_config_hash mismatch for task {task_id}")]
    HashMismatch {
        /// Identifier of the rejected task.
        task_id: String,
    },
    /// The task pinned an execution-identity digest that differs from the
    /// identity the worker assembled for it; the run is rejected before
    /// execution.
    #[error("execution identity mismatch for task {task_id}")]
    IdentityMismatch {
        /// Identifier of the rejected task.
        task_id: String,
    },
    /// The task pinned an execution-identity digest but the worker build
    /// data is incomplete, so no comparable identity exists; the run is
    /// rejected before execution.
    #[error("execution identity incomplete for task {task_id}")]
    IdentityIncomplete {
        /// Identifier of the rejected task.
        task_id: String,
    },
    /// The run config cannot be encoded canonically (a non-finite float), so
    /// no boundary hash can exist for it; execution rejects the task.
    #[error("run config cannot be encoded canonically for task {task_id}: {reason}")]
    InvalidConfig {
        /// Identifier of the rejected task.
        task_id: String,
        /// Canonical-encoding error text.
        reason: String,
    },
    /// The explorer pre-run campaign failed.
    #[error(transparent)]
    Campaign(#[from] ledger_explorer::services::ServiceError),
    /// The deterministic simulation run failed.
    #[error("simulation failed: {0}")]
    Sim(#[from] ledger_sim::RuntimeError),
    /// Task execution panicked on the blocking pool.
    #[error("execution join failed: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("task {0} was cancelled before completion")]
    Cancelled(String),
    #[error("task {task_id} failed after {attempts}/{max_attempts} attempts: {detail}")]
    TaskFailed {
        task_id: String,
        attempts: u32,
        max_attempts: u32,
        detail: String,
    },
}

pub struct Worker {
    /// Worker configuration.
    pub config: WorkerConfig,
    queue: Box<dyn TaskQueue>,
    artifact_sink: Arc<dyn ArtifactSink>,
}

impl Worker {
    /// Create a new worker with the default no-op artifact sink.
    pub fn new(config: WorkerConfig, queue: Box<dyn TaskQueue>) -> Self {
        Self {
            config,
            queue,
            artifact_sink: Arc::new(NoopSink),
        }
    }

    /// Attach an artifact sink used for best-effort certificate publication.
    pub fn with_artifact_sink(mut self, sink: Arc<dyn ArtifactSink>) -> Self {
        self.artifact_sink = sink;
        self
    }

    /// Pull one task and run it to completion.
    ///
    /// Returns `Ok(None)` when the queue is empty. On success the journal
    /// root is returned and the lease is acked, marking the task done. On
    /// failure the attempt is charged against [`Task::max_attempts`]: the
    /// queue requeues while attempts remain and retires the task once the
    /// budget is exhausted. Deterministic boundary: the queued
    /// `run_config_hash` (if present) must match the recomputed canonical
    /// hash, enforcing same RunConfigHash -> same root.
    ///
    /// Certificate publication through the artifact sink is best-effort:
    /// sink errors are logged and never fail the task.
    pub fn run_one(&mut self) -> Result<Option<WorkerResult>, WorkerError> {
        let task = match self.queue.pull() {
            Some(task) => task,
            None => return Ok(None),
        };
        let task_id = task.id.clone();
        match execute_task(task) {
            Ok(result) => {
                publish_result_certificate(
                    self.artifact_sink.as_ref(),
                    &result,
                    Some(WORKER_BUILDER_ID),
                    Some(&self.config.profile_hex8),
                );
                self.queue.ack(&result.task_id);
                Ok(Some(result))
            }
            Err(err) => Err(route_failure(self.queue.as_mut(), &task_id, err)),
        }
    }
}

/// Charge a failed execution against the queue's attempt accounting.
///
/// Maps the queue's routing decision onto [`WorkerError::TaskFailed`]; when
/// the queue does not track leases (stub default) the original error is
/// returned unchanged.
pub fn route_failure(queue: &mut dyn TaskQueue, task_id: &str, err: WorkerError) -> WorkerError {
    match queue.report_failure(task_id) {
        Some(crate::queue::AttemptOutcome::Retried {
            attempts,
            max_attempts,
        }) => WorkerError::TaskFailed {
            task_id: task_id.to_string(),
            attempts,
            max_attempts,
            detail: err.to_string(),
        },
        Some(crate::queue::AttemptOutcome::Exhausted { attempts }) => WorkerError::TaskFailed {
            task_id: task_id.to_string(),
            attempts,
            max_attempts: attempts,
            detail: err.to_string(),
        },
        None => err,
    }
}

/// Publish a task certificate through `sink`, best-effort.
///
/// Renders the minimal task certificate (journal root as subject; the full
/// [`ledger_explorer::certs::CampaignCertificate`] derives from a
/// [`ledger_explorer::CampaignReport`], which the worker does not
/// produce), computes its BLAKE3 checksum, and
/// uploads it as `certificate.json`. When set, `builder_id` lands in
/// `predicate.runDetails.builder.id` and `profile_fingerprint_hex8` in
/// `predicate.extensions.runtimeProfile`, binding the certificate to the
/// runtime that produced it. Every failure mode is logged and swallowed on
/// purpose: artifact publication must never fail a completed, deterministic
/// task.
pub fn publish_result_certificate(
    sink: &dyn ArtifactSink,
    result: &WorkerResult,
    builder_id: Option<&str>,
    profile_fingerprint_hex8: Option<&str>,
) {
    let cert = match certificate_json(
        &result.task_id,
        &result.journal_root,
        result.steps,
        result.campaign_findings,
        builder_id,
        profile_fingerprint_hex8,
    ) {
        Ok(cert) => cert,
        Err(err) => {
            eprintln!(
                "ledger-worker: certificate render failed for {}: {err}",
                result.task_id
            );
            return;
        }
    };
    let checksum = checksum_hex(&cert);
    match sink.upload(&result.task_id, "certificate.json", &cert, &checksum) {
        Ok(url) => eprintln!(
            "ledger-worker: published certificate.json for {} to {url}",
            result.task_id
        ),
        Err(err) => eprintln!(
            "ledger-worker: certificate upload for {} skipped (best-effort): {err}",
            result.task_id
        ),
    }
}

/// Execute a pulled task while periodically extending its lease.
///
/// Runs [`execute_task`] on the blocking pool and extends the lease by
/// `lease` every `heartbeat` period until execution finishes, so tasks that
/// outlive the original lease deadline are not reclaimed mid-run. The first
/// tick fires immediately; that extension of a fresh lease is harmless.
///
/// On success the lease is acked (task done). On failure the attempt is
/// charged through the queue's accounting and a typed error is returned.
///
/// # Errors
/// Returns [`WorkerError`] when execution fails or the blocking pool panics.
pub async fn execute_with_heartbeat(
    queue: Arc<Mutex<InMemoryQueue>>,
    task: Task,
    heartbeat: Duration,
    lease: Duration,
) -> Result<WorkerResult, WorkerError> {
    // Guard against a zero interval (lease_timeout < 3ms), which panics.
    let heartbeat = heartbeat.max(Duration::from_millis(1));
    let task_id = task.id.clone();
    let mut exec = tokio::task::spawn_blocking(move || execute_task(task));
    let mut ticker = tokio::time::interval(heartbeat);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let result = loop {
        tokio::select! {
            res = &mut exec => {
                match res {
                    Ok(inner) => break inner,
                    Err(e) => return Err(e.into()),
                }
            }
            _ = ticker.tick() => {
                let extended = queue.lock().await.extend_lease(&task_id, lease);
                if !extended {
                    eprintln!("ledger-worker: heartbeat found no lease for {task_id}");
                }
            }
        }
    };
    match result {
        Ok(ok) => {
            queue.lock().await.ack(&ok.task_id);
            Ok(ok)
        }
        Err(err) => {
            let mut q = queue.lock().await;
            Err(route_failure(&mut *q, &task_id, err))
        }
    }
}

pub struct SmallWorkload(Vec<Vec<Instruction>>);

impl Workload for SmallWorkload {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        self.0.clone()
    }

    fn history(
        &self,
        _run: &ledger_sim::RunResult,
    ) -> Vec<ledger_explorer::oracle::HistoryOperation> {
        Vec::new()
    }
}

/// Execute a single task through the deterministic simulation.
///
/// Shared helper used by [`Worker::run_one`], [`execute_with_heartbeat`], and
/// [`crate::proto::serve_uds_real`] so the UDS boundary and the in-process
/// dispatcher run identical logic. Validates the queued `run_config_hash`,
/// exercises the explorer campaign, and runs the simulation to produce the
/// journal root.
///
pub fn execute_task(task: crate::queue::Task) -> Result<WorkerResult, WorkerError> {
    // Always recompute and compare. A task without a stored hash (its config
    // failed canonical encoding at push time) is rejected here, so no task
    // runs with an unverifiable boundary hash.
    let computed = crate::proto::run_config_hash(&task.run_config).map_err(|error| {
        WorkerError::InvalidConfig {
            task_id: task.id.clone(),
            reason: error.to_string(),
        }
    })?;
    if let Some(stored) = task.run_config_hash
        && stored != computed
    {
        return Err(WorkerError::HashMismatch {
            task_id: task.id.clone(),
        });
    }
    // Identity gate runs before the simulation: a pinned identity that does
    // not match the worker's own assembly (or that cannot be compared because
    // the worker build data is incomplete) rejects the task.
    let execution_identity = task_identity(&task, computed)?;
    if let Some(pin) = task.execution_identity {
        let Some(assembled) = execution_identity else {
            return Err(WorkerError::IdentityIncomplete {
                task_id: task.id.clone(),
            });
        };
        if assembled != pin {
            return Err(WorkerError::IdentityMismatch {
                task_id: task.id.clone(),
            });
        }
    }
    let workload = workload_for(&task.workload);
    let oracle = AlwaysPassOracle;
    let campaign =
        ledger_explorer::services::run_campaign(&workload, &oracle, task.run_config.clone(), 1)?;
    let campaign_findings = campaign.findings.len();
    let run = Simulation::new(task.run_config.clone(), workload.programs()).run()?;
    Ok(WorkerResult {
        task_id: task.id,
        journal_root: run.journal.root_hash(),
        steps: run.steps,
        campaign_findings,
        execution_identity,
    })
}

/// Assemble the worker's execution-identity digest for one task.
///
/// The build segment comes from the worker binary's compile-time capture; the
/// run segment comes from the task's run config and workload selector. Returns
/// `None` when the worker build data is incomplete.
fn task_identity(
    task: &crate::queue::Task,
    run_config_digest: Hash,
) -> Result<Option<Hash>, WorkerError> {
    use ledger_explorer::identity::{EngineBuild, IdentityContext};
    let build = EngineBuild::detect();
    let context = IdentityContext {
        sut_revision: None,
        sut_dirty: false,
        sut_artifact_digest: None,
        guest_digest: None,
        workload_id: task.workload.clone(),
        // The program selector binds which program set was chosen; the
        // workload provider owns the program-by-program binding.
        program_digest: *blake3::hash(task.workload.as_bytes()).as_bytes(),
        input_digests: Vec::new(),
        backend: "sim".to_string(),
        runtime_profile: crate::RuntimeProfile::detect().fingerprint_hex8(),
        run_config_digest,
        seed_tree_root: task.run_config.seed(),
        faultspec_digest: None,
        oracle_version: None,
        support_provider_version: None,
        resource_limits: ledger_journal::ResourceLimits {
            max_steps: task.run_config.max_steps() as u64,
        },
    };
    Ok(ledger_explorer::identity::assemble_identity(&build, &context).digest())
}

pub fn workload_for(name: &str) -> SmallWorkload {
    match name {
        "kv" => SmallWorkload(vec![
            vec![Instruction::Send { to: 1, payload: 42 }, Instruction::Done],
            vec![
                Instruction::Receive,
                Instruction::Outcome,
                Instruction::Done,
            ],
        ]),
        _ => SmallWorkload(vec![vec![
            Instruction::Set(0),
            Instruction::Outcome,
            Instruction::Done,
        ]]),
    }
}

struct AlwaysPassOracle;

impl ledger_explorer::oracle::Oracle for AlwaysPassOracle {
    fn check(&self, _run: &ledger_sim::RunResult) -> ledger_explorer::oracle::Verdict {
        ledger_explorer::oracle::Verdict {
            violated: false,
            witnesses: Vec::new(),
            reason: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WorkerConfig;
    use crate::queue::{InMemoryQueue, Task};
    use ledger_sim::RunConfig;
    use std::time::Duration;

    #[test]
    fn pinned_identity_rejects_before_execution() {
        // A pinned identity must reject the task before the simulation runs,
        // either because the worker build data is incomplete (dev builds) or
        // because the assembled identity differs (any build). Both arms are
        // fail-closed; neither lets a mismatched task execute.
        let mut task = Task::new("pinned", RunConfig::default(), "trivial");
        task.execution_identity = Some([0xab; 32]);
        let error = execute_task(task).expect_err("pinned identity must reject the task");
        assert!(
            matches!(
                error,
                WorkerError::IdentityIncomplete { .. } | WorkerError::IdentityMismatch { .. }
            ),
            "fail-closed identity rejection, got {error:?}"
        );
    }

    #[test]
    fn unpinned_task_records_its_identity() {
        let task = Task::new("unpinned", RunConfig::default(), "trivial");
        let result = execute_task(task).expect("unpinned task must run");
        // The recorded digest follows the worker build: complete builds carry
        // a digest, incomplete builds carry None (the control plane treats
        // None as identity-incomplete).
        let _ = result.execution_identity;
        assert_eq!(result.task_id, "unpinned");
    }

    #[test]
    fn run_one_produces_deterministic_root() {
        let config = WorkerConfig::default();
        let mut q = InMemoryQueue::new(Duration::from_secs(30));
        let run_config = RunConfig::builder().seed([11u8; 32]).build();
        q.push(Task::new("task-1", run_config.clone(), "trivial"));
        q.push(Task::new("task-2", run_config, "trivial"));
        let mut worker = Worker::new(config, Box::new(q));
        let first = worker.run_one().unwrap().unwrap();
        let second = worker.run_one().unwrap().unwrap();
        // Same RunConfig and workload produce same root via determinism boundary.
        assert_eq!(first.journal_root, second.journal_root);
    }

    #[test]
    fn run_one_returns_none_when_empty() {
        let config = WorkerConfig::default();
        let q = InMemoryQueue::new(Duration::from_secs(30));
        let mut worker = Worker::new(config, Box::new(q));
        assert!(worker.run_one().unwrap().is_none());
    }

    #[test]
    fn run_one_validates_queued_hash() {
        let config = WorkerConfig::default();
        let mut q = InMemoryQueue::new(Duration::from_secs(30));
        let run_config = RunConfig::builder().seed([9u8; 32]).build();
        // Push correctly hashes at queue layer.
        q.push(Task::new("ok", run_config.clone(), "trivial"));
        let mut worker = Worker::new(config, Box::new(q));
        assert!(worker.run_one().unwrap().is_some());
        // Now craft a task with tampered hash to ensure boundary rejects mismatch.
        let bad_hash = [0xffu8; 32];
        let mut bad_task = crate::queue::Task::new("bad", run_config.clone(), "trivial");
        bad_task.run_config_hash = Some(bad_hash);
        // Directly inject bad task via a custom queue to bypass push hashing.
        struct BadQueue(crate::queue::Task);
        impl crate::queue::TaskQueue for BadQueue {
            fn pull(&mut self) -> Option<crate::queue::Task> {
                Some(self.0.clone())
            }
            fn len(&self) -> usize {
                1
            }
        }
        let mut worker2 = Worker::new(WorkerConfig::default(), Box::new(BadQueue(bad_task)));
        let err = worker2.run_one().unwrap_err();
        assert!(matches!(err, WorkerError::HashMismatch { .. }));
        let _ = run_config;
    }

    #[test]
    fn fabricated_task_id_hash_is_not_a_simulation_root() {
        // Pins the fake-root removal: a blake3(task_id) value must never
        // equal a real journal root, so a reintroduced stub fallback on any
        // transport would fail loudly against this boundary.
        let run_config = RunConfig::builder().seed([17u8; 32]).build();
        let workload = SmallWorkload(vec![vec![
            Instruction::Set(0),
            Instruction::Outcome,
            Instruction::Done,
        ]]);
        let real_root = Simulation::new(run_config.clone(), workload.programs())
            .run()
            .unwrap()
            .journal
            .root_hash();
        let fabricated_root = *blake3::hash(b"task-1").as_bytes();
        assert_ne!(
            real_root, fabricated_root,
            "blake3(task_id) must not equal a real simulation root"
        );
    }

    #[test]
    fn run_one_routes_failure_through_attempt_accounting() {
        struct FailingQueue {
            leased: Option<Task>,
        }
        impl crate::queue::TaskQueue for FailingQueue {
            fn pull(&mut self) -> Option<Task> {
                self.leased.take()
            }
            fn len(&self) -> usize {
                usize::from(self.leased.is_some())
            }
            fn report_failure(&mut self, _task_id: &str) -> Option<crate::queue::AttemptOutcome> {
                Some(crate::queue::AttemptOutcome::Exhausted { attempts: 3 })
            }
        }
        // The tampered hash forces the execution error; routing wraps it.
        let mut doomed = Task::new("doomed", RunConfig::default(), "trivial");
        doomed.run_config_hash = Some([0xffu8; 32]);
        let queue = FailingQueue {
            leased: Some(doomed),
        };
        let mut worker = Worker::new(WorkerConfig::default(), Box::new(queue));
        let err = worker.run_one().unwrap_err();
        match err {
            WorkerError::TaskFailed {
                task_id,
                attempts,
                max_attempts,
                ..
            } => {
                assert_eq!(task_id, "doomed");
                assert_eq!(attempts, 3);
                assert_eq!(max_attempts, 3);
            }
            other => panic!("expected TaskFailed, got {other}"),
        }
    }

    #[test]
    fn run_one_publishes_certificate_best_effort() {
        use crate::artifact::{ArtifactError, ArtifactSink, checksum_hex};

        #[allow(clippy::type_complexity)]
        struct RecordingSink(std::sync::Mutex<Vec<(String, String, Vec<u8>, String)>>);
        impl ArtifactSink for RecordingSink {
            fn get_upload_url(&self, task_id: &str, name: &str) -> Result<String, ArtifactError> {
                Ok(format!("noop://{task_id}/{name}"))
            }
            fn confirm(
                &self,
                _task_id: &str,
                _name: &str,
                _checksum_hex: &str,
            ) -> Result<(), ArtifactError> {
                Ok(())
            }
            fn upload(
                &self,
                task_id: &str,
                name: &str,
                bytes: &[u8],
                checksum_hex: &str,
            ) -> Result<String, ArtifactError> {
                self.0.lock().unwrap().push((
                    task_id.to_string(),
                    name.to_string(),
                    bytes.to_vec(),
                    checksum_hex.to_string(),
                ));
                self.get_upload_url(task_id, name)
            }
        }

        struct FailingSink;
        impl ArtifactSink for FailingSink {
            fn get_upload_url(&self, _: &str, _: &str) -> Result<String, ArtifactError> {
                Err(ArtifactError::Contract(
                    crate::artifact::Phase::UrlFetch,
                    "control plane down",
                ))
            }
            fn confirm(&self, _: &str, _: &str, _: &str) -> Result<(), ArtifactError> {
                Ok(())
            }
            fn upload(
                &self,
                task_id: &str,
                name: &str,
                _bytes: &[u8],
                _checksum: &str,
            ) -> Result<String, ArtifactError> {
                self.get_upload_url(task_id, name)
            }
        }

        let sink = std::sync::Arc::new(RecordingSink(std::sync::Mutex::new(Vec::new())));
        let mut q = InMemoryQueue::new(Duration::from_secs(30));
        q.push(Task::new("cert-task", RunConfig::default(), "trivial"));
        let mut worker =
            Worker::new(WorkerConfig::default(), Box::new(q)).with_artifact_sink(sink.clone());
        let result = worker.run_one().unwrap().expect("task must succeed");
        let uploads = sink.0.lock().unwrap();
        assert_eq!(uploads.len(), 1);
        assert_eq!(uploads[0].0, "cert-task");
        assert_eq!(uploads[0].1, "certificate.json");
        assert!(!uploads[0].2.is_empty());
        // Checksum travels with the exact bytes handed to the sink.
        assert_eq!(uploads[0].3, checksum_hex(&uploads[0].2));
        drop(uploads);
        let _ = result;

        // A broken sink must not fail the task.
        let mut q = InMemoryQueue::new(Duration::from_secs(30));
        q.push(Task::new("still-runs", RunConfig::default(), "trivial"));
        let mut worker = Worker::new(WorkerConfig::default(), Box::new(q))
            .with_artifact_sink(std::sync::Arc::new(FailingSink));
        let done = worker
            .run_one()
            .unwrap()
            .expect("sink failure is not fatal");
        assert_eq!(done.task_id, "still-runs");
    }

    #[tokio::test]
    async fn heartbeat_keeps_lease_alive_during_execution() {
        use std::sync::Arc;
        // Short timeouts: lease 60ms, heartbeat 20ms (lease/3).
        let lease = Duration::from_millis(60);
        let queue = Arc::new(Mutex::new(InMemoryQueue::new(lease)));
        queue
            .lock()
            .await
            .push(Task::new("hb-task", RunConfig::default(), "trivial"));
        let task = queue.lock().await.pull().unwrap();

        let result = execute_with_heartbeat(Arc::clone(&queue), task, lease / 3, lease)
            .await
            .expect("execution must succeed");
        assert_eq!(result.task_id, "hb-task");

        // The executor acks on success: the task sits in the terminal done
        // list and no lease remains.
        assert_eq!(queue.lock().await.leased_len(), 0);
        let done = queue.lock().await.done();
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].id, "hb-task");
        assert_eq!(done[0].status, crate::queue::TaskStatus::Done);

        // A second execution with no live lease still completes; heartbeats
        // report the missing lease instead of failing the task.
        queue
            .lock()
            .await
            .push(Task::new("hb-orphan", RunConfig::default(), "trivial"));
        let orphan = queue.lock().await.pull().unwrap();
        let id = orphan.id.clone();
        // Remove the lease behind the executor's back to hit the warning path.
        {
            let mut q = queue.lock().await;
            assert!(q.cancel(&id));
        }
        let res = execute_with_heartbeat(Arc::clone(&queue), orphan, lease / 3, lease).await;
        assert!(res.is_ok(), "missing lease must not fail execution");
    }
}
