// ledger-lint:allow - host daemon / non-sim passthrough, like TokioBackend
//! Lease-accounting in-memory queue backend.
//!
//! [`InMemoryQueue`] answers every lease-deadline question from the injected
//! [`Clock`], so expiry behavior is deterministic in tests without sleeping
//! on the wall clock.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use super::{AttemptOutcome, Task, TaskQueue, TaskStatus};

/// Clock used for lease deadlines.
///
/// Production uses wall time; tests inject a manual clock so lease expiry
/// is exercised deterministically without sleeping.
type Clock = Box<dyn Fn() -> Instant + Send + Sync>;

/// In-memory queue with lease semantics for tests and standalone mode.
pub struct InMemoryQueue {
    queue: VecDeque<Task>,
    lease_timeout: Duration,
    leased: HashMap<String, (Task, Instant)>,
    failed: Vec<Task>,
    cancelled: Vec<Task>,
    done: Vec<Task>,
    now: Clock,
}

impl InMemoryQueue {
    /// Create an empty queue.
    pub fn new(lease_timeout: Duration) -> Self {
        Self {
            queue: VecDeque::new(),
            lease_timeout,
            leased: HashMap::new(),
            failed: Vec::new(),
            cancelled: Vec::new(),
            done: Vec::new(),
            now: Box::new(Instant::now),
        }
    }

    /// Create an empty queue over an injected clock (tests only).
    ///
    /// The clock answers every lease-deadline question, so tests advance it
    /// manually and never sleep on the wall clock.
    #[cfg(test)]
    pub(crate) fn with_clock(lease_timeout: Duration, now: Clock) -> Self {
        Self {
            queue: VecDeque::new(),
            lease_timeout,
            leased: HashMap::new(),
            failed: Vec::new(),
            cancelled: Vec::new(),
            done: Vec::new(),
            now,
        }
    }

    /// Push a task into the queue, plumbing the deterministic hash.
    ///
    /// The task is (re)entered in the [`TaskStatus::Queued`] state; attempts
    /// already charged are preserved so re-pushed tasks keep their budget.
    pub fn push(&mut self, mut task: Task) {
        // Compute the deterministic boundary hash so same RunConfigHash ->
        // same root holds across queue and worker layers. The hash is dropped
        // only for a config the canonical encoder rejects (a non-finite
        // float); execution then fails with `WorkerError::InvalidConfig`
        // instead of running an unverifiable task.
        task.run_config_hash = crate::proto::run_config_hash(&task.run_config).ok();
        task.status = TaskStatus::Queued;
        self.queue.push_back(task);
    }

    /// Acknowledge completion of a task and release its lease.
    pub fn ack(&mut self, task_id: &str) {
        if let Some((mut task, _)) = self.leased.remove(task_id) {
            task.status = TaskStatus::Done;
            self.done.push(task);
        }
    }

    /// Charge one failed execution attempt against a taken task.
    ///
    /// Used by the `UploadResult` path where `take_by_id` already removed
    /// the task; the budget accounting mirrors `report_failure`.
    pub fn record_taken_task_failure(&mut self, mut task: Task) -> AttemptOutcome {
        task.attempts += 1;
        if task.attempts >= task.max_attempts {
            task.status = TaskStatus::Failed;
            let attempts = task.attempts;
            self.failed.push(task);
            AttemptOutcome::Exhausted { attempts }
        } else {
            let attempts = task.attempts;
            let max_attempts = task.max_attempts;
            task.status = TaskStatus::Queued;
            self.queue.push_back(task);
            AttemptOutcome::Retried {
                attempts,
                max_attempts,
            }
        }
    }

    /// Charge one failed execution attempt against a leased task.
    ///
    /// Requeues the task while attempts remain in its budget and retires it
    /// to the failed list once `attempts >= max_attempts`. Returns `None`
    /// when no live lease exists for `task_id`.
    pub fn report_failure(&mut self, task_id: &str) -> Option<AttemptOutcome> {
        let (task, _) = self.leased.remove(task_id)?;
        Some(self.retire_or_requeue(task))
    }

    /// Charge one attempt and route the task per its remaining budget.
    fn retire_or_requeue(&mut self, mut task: Task) -> AttemptOutcome {
        task.attempts += 1;
        if task.attempts >= task.max_attempts {
            task.status = TaskStatus::Failed;
            let attempts = task.attempts;
            self.failed.push(task);
            AttemptOutcome::Exhausted { attempts }
        } else {
            let attempts = task.attempts;
            let max_attempts = task.max_attempts;
            task.status = TaskStatus::Queued;
            self.queue.push_back(task);
            AttemptOutcome::Retried {
                attempts,
                max_attempts,
            }
        }
    }

    /// Extend the active lease deadline of a leased task by `extra`.
    ///
    /// Returns false when the task is not currently leased.
    pub fn extend_lease(&mut self, task_id: &str, extra: Duration) -> bool {
        match self.leased.get_mut(task_id) {
            Some((_, deadline)) => {
                *deadline += extra;
                true
            }
            None => false,
        }
    }

    /// Cancel a queued or leased task.
    ///
    /// Cancellation is terminal: the task moves to the cancelled list and
    /// never requeues. Returns false when no queued or leased task matches.
    pub fn cancel(&mut self, task_id: &str) -> bool {
        if let Some(pos) = self.queue.iter().position(|t| t.id == task_id)
            && let Some(mut task) = self.queue.remove(pos)
        {
            task.status = TaskStatus::Cancelled;
            self.cancelled.push(task);
            return true;
        }
        if let Some((mut task, _)) = self.leased.remove(task_id) {
            task.status = TaskStatus::Cancelled;
            self.cancelled.push(task);
            return true;
        }
        false
    }

    fn reclaim_expired(&mut self) {
        let now = (self.now)();
        let expired: Vec<String> = self
            .leased
            .iter()
            .filter_map(|(id, (_, deadline))| {
                if *deadline <= now {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();
        for id in expired {
            if let Some((task, _)) = self.leased.remove(&id) {
                self.retire_or_requeue(task);
            }
        }
    }

    /// Number of leased tasks.
    pub fn leased_len(&self) -> usize {
        self.leased.len()
    }

    /// Snapshot of terminally failed tasks (attempt budget exhausted).
    pub fn failed(&self) -> Vec<Task> {
        self.failed.clone()
    }

    /// Snapshot of cancelled tasks.
    pub fn cancelled(&self) -> Vec<Task> {
        self.cancelled.clone()
    }

    /// Snapshot of successfully acknowledged tasks.
    pub fn done(&self) -> Vec<Task> {
        self.done.clone()
    }

    /// Remove and return a task by id, searching both queued and leased slots.
    ///
    /// Used by the standalone drain loop to take a task by id. Terminal
    /// tasks (failed, cancelled, done) are never returned.
    /// tasks (failed, cancelled, done) are never returned.
    pub fn take_by_id(&mut self, task_id: &str) -> Option<Task> {
        if let Some(pos) = self.queue.iter().position(|t| t.id == task_id) {
            return self.queue.remove(pos);
        }
        if let Some((task, _)) = self.leased.remove(task_id) {
            return Some(task);
        }
        None
    }
}

impl TaskQueue for InMemoryQueue {
    fn pull(&mut self) -> Option<Task> {
        self.reclaim_expired();
        let mut task = self.queue.pop_front()?;
        task.status = TaskStatus::Leased;
        let deadline = (self.now)() + self.lease_timeout;
        self.leased
            .insert(task.id.clone(), (task.clone(), deadline));
        Some(task)
    }

    fn len(&self) -> usize {
        self.queue.len()
    }

    fn ack(&mut self, task_id: &str) {
        self.ack(task_id);
    }

    fn report_failure(&mut self, task_id: &str) -> Option<AttemptOutcome> {
        self.report_failure(task_id)
    }
}

#[cfg(test)]
mod tests {
    use super::super::DEFAULT_MAX_ATTEMPTS;
    use super::{AttemptOutcome, Clock, InMemoryQueue, Instant, Task, TaskQueue, TaskStatus};
    use ledger_sim::RunConfig;
    use std::sync::Arc;
    use std::time::Duration;

    fn test_task(id: &str) -> Task {
        Task::new(id, RunConfig::default(), "trivial")
    }
    /// Manual clock: advancing it moves every lease deadline without
    /// sleeping on the wall clock, so expiry tests are deterministic.
    #[derive(Clone)]
    struct FakeClock {
        inner: Arc<std::sync::Mutex<Instant>>,
    }
    impl FakeClock {
        fn new() -> Self {
            Self {
                inner: Arc::new(std::sync::Mutex::new(Instant::now())),
            }
        }

        fn advance(&self, by: Duration) {
            let mut slot = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *slot += by;
        }

        fn as_clock(&self) -> Clock {
            let inner = Arc::clone(&self.inner);
            Box::new(move || {
                *inner
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
            })
        }
    }
    #[test]
    fn in_memory_pull_returns_tasks_fifo() {
        let mut q = InMemoryQueue::new(Duration::from_secs(60));
        q.push(test_task("a"));
        q.push(test_task("b"));
        assert_eq!(q.len(), 2);
        let first = q.pull().unwrap();
        assert_eq!(first.id, "a");
        assert_eq!(q.len(), 1);
        assert_eq!(q.leased_len(), 1);
        let second = q.pull().unwrap();
        assert_eq!(second.id, "b");
        assert!(q.is_empty());
    }
    #[test]
    fn lease_expires_and_requeues() {
        let clock = FakeClock::new();
        let mut q = InMemoryQueue::with_clock(Duration::from_secs(10), clock.as_clock());
        q.push(test_task("leased"));
        let pulled = q.pull().unwrap();
        assert_eq!(pulled.id, "leased");
        assert!(q.is_empty());
        assert_eq!(q.leased_len(), 1);

        // Within the lease the task stays leased and cannot be pulled.
        clock.advance(Duration::from_secs(9));
        assert_eq!(q.leased_len(), 1);
        assert!(q.pull().is_none());

        // Past the deadline the lease expires and the task requeues.
        clock.advance(Duration::from_secs(2));
        let again = q.pull().unwrap();
        assert_eq!(again.id, "leased");
    }
    #[test]
    fn ack_releases_lease_without_requeue() {
        let mut q = InMemoryQueue::new(Duration::from_secs(60));
        q.push(test_task("ack-me"));
        let pulled = q.pull().unwrap();
        q.ack(&pulled.id);
        assert_eq!(q.leased_len(), 0);
        assert!(q.pull().is_none());
    }
    #[test]
    fn new_task_starts_queued_with_default_budget() {
        let t = test_task("fresh");
        assert_eq!(t.status, TaskStatus::Queued);
        assert_eq!(t.attempts, 0);
        assert_eq!(t.max_attempts, DEFAULT_MAX_ATTEMPTS);
        assert!(!t.status.is_terminal());
    }
    #[test]
    fn expiry_increments_attempts_then_fails_at_max() {
        let clock = FakeClock::new();
        let mut q = InMemoryQueue::with_clock(Duration::from_secs(10), clock.as_clock());
        let mut task = test_task("budget");
        task.max_attempts = 3;
        q.push(task);

        // Two expirations requeue with a charged attempt each. A pulled task
        // comes back in the Leased state by contract.
        let first = q.pull().unwrap();
        clock.advance(Duration::from_secs(11));
        let retried = q.pull().unwrap();
        assert_eq!(retried.id, first.id);
        assert_eq!(retried.attempts, 1);
        assert_eq!(retried.status, TaskStatus::Leased);

        clock.advance(Duration::from_secs(11));
        let second_retry = q.pull().unwrap();
        assert_eq!(second_retry.attempts, 2);

        // Third expiration exhausts the budget: terminal failure, no requeue.
        clock.advance(Duration::from_secs(11));
        assert!(q.pull().is_none());
        assert_eq!(q.leased_len(), 0);
        let failed = q.failed();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].id, "budget");
        assert_eq!(failed[0].attempts, 3);
        assert_eq!(failed[0].status, TaskStatus::Failed);
        assert!(failed[0].status.is_terminal());
    }
    #[test]
    fn report_failure_requeues_then_exhausts() {
        let mut q = InMemoryQueue::new(Duration::from_secs(60));
        let mut task = test_task("rf");
        task.max_attempts = 2;
        q.push(task);
        let pulled = q.pull().unwrap();

        let outcome = q.report_failure(&pulled.id);
        assert_eq!(
            outcome,
            Some(AttemptOutcome::Retried {
                attempts: 1,
                max_attempts: 2
            })
        );
        assert_eq!(q.len(), 1);

        let again = q.pull().unwrap();
        let outcome = q.report_failure(&again.id);
        assert_eq!(outcome, Some(AttemptOutcome::Exhausted { attempts: 2 }));
        assert_eq!(q.failed().len(), 1);
        assert!(q.pull().is_none());
        // No lease means nothing to charge.
        assert_eq!(q.report_failure(&again.id), None);
    }
    #[test]
    fn extend_lease_keeps_task_alive_past_original_deadline() {
        let clock = FakeClock::new();
        let mut q = InMemoryQueue::with_clock(Duration::from_secs(30), clock.as_clock());
        q.push(test_task("hb"));
        let pulled = q.pull().unwrap();

        // Steady-state heartbeat: extend by lease/3 every lease/3 so the
        // deadline stays roughly one lease ahead without growing. Ten ticks
        // (100s of fake time) keep the task alive far past the 30s deadline.
        for _ in 0..10 {
            clock.advance(Duration::from_secs(10));
            assert!(q.extend_lease(&pulled.id, Duration::from_secs(10)));
        }
        assert_eq!(q.leased_len(), 1);
        assert!(q.failed().is_empty());

        // Without further extension the lease lapses within one lease and
        // charges exactly one attempt on reclaim.
        clock.advance(Duration::from_secs(31));
        let again = q.pull().unwrap();
        assert_eq!(again.id, "hb");
        assert_eq!(again.attempts, 1);
    }
    #[test]
    fn extend_lease_false_when_not_leased() {
        let mut q = InMemoryQueue::new(Duration::from_secs(60));
        q.push(test_task("idle"));
        assert!(!q.extend_lease("idle", Duration::from_secs(1)));
        assert!(!q.extend_lease("missing", Duration::from_secs(1)));
        let pulled = q.pull().unwrap();
        assert!(q.extend_lease(&pulled.id, Duration::from_secs(1)));
        q.ack(&pulled.id);
        assert!(!q.extend_lease(&pulled.id, Duration::from_secs(1)));
    }
    #[test]
    fn cancel_is_terminal_from_queued_and_leased() {
        let mut q = InMemoryQueue::new(Duration::from_secs(60));
        q.push(test_task("c1"));
        q.push(test_task("c2"));
        // Both are still queued here; cancellation works from the queue.
        assert!(q.cancel("c1"));
        assert!(q.cancel("c2"));
        assert!(q.pull().is_none());
        let cancelled = q.cancelled();
        assert_eq!(cancelled.len(), 2);
        assert!(cancelled.iter().all(|t| t.status == TaskStatus::Cancelled));

        // Cancelling an unknown or already-terminal task reports false.
        assert!(!q.cancel("c1"));
        assert!(!q.cancel("ghost"));

        // A leased task can be cancelled too.
        q.push(test_task("c3"));
        let pulled = q.pull().unwrap();
        assert!(q.cancel(&pulled.id));
        assert_eq!(q.leased_len(), 0);
        assert_eq!(q.cancelled().len(), 3);
    }
    #[test]
    fn ack_marks_done_and_done_is_terminal() {
        let mut q = InMemoryQueue::new(Duration::from_secs(60));
        q.push(test_task("ok"));
        let pulled = q.pull().unwrap();
        q.ack(&pulled.id);
        assert_eq!(q.leased_len(), 0);
        let done = q.done();
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].id, "ok");
        assert_eq!(done[0].status, TaskStatus::Done);
        assert!(done[0].status.is_terminal());
        // Terminal tasks never requeue and are not returned by take_by_id.
        assert!(q.pull().is_none());
        assert!(q.take_by_id("ok").is_none());
    }
    #[test]
    fn push_computes_run_config_hash() {
        let mut q = InMemoryQueue::new(Duration::from_secs(60));
        let run_config = RunConfig::builder().seed([7u8; 32]).build();
        let expected = crate::proto::run_config_hash(&run_config).unwrap();
        q.push(Task::new("hashed", run_config, "trivial"));
        let task = q.pull().unwrap();
        assert_eq!(task.run_config_hash, Some(expected));
    }
    #[test]
    fn dns_affects_queued_hash() {
        let mut dns_a = ledger_sim::DnsTable::new();
        dns_a.insert("a.test", 1);
        let mut dns_b = ledger_sim::DnsTable::new();
        dns_b.insert("b.test", 1);
        let cfg_a = RunConfig::builder().seed([3u8; 32]).dns(dns_a).build();
        let cfg_b = RunConfig::builder().seed([3u8; 32]).dns(dns_b).build();
        let mut q = InMemoryQueue::new(Duration::from_secs(60));
        q.push(Task::new("ta", cfg_a, "trivial"));
        q.push(Task::new("tb", cfg_b, "trivial"));
        let ha = q.pull().unwrap().run_config_hash.unwrap();
        let hb = q.pull().unwrap().run_config_hash.unwrap();
        assert_ne!(ha, hb);
    }
}
