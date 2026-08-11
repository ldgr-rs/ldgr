//! Discrete virtual time and timer queue.

use ledger_format::Hash;
use std::cmp::Ordering;
use std::collections::BinaryHeap;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct Timer {
    deadline: u64,
    sequence: u64,
    task: usize,
    enabler: Option<Hash>,
}

impl Ord for Timer {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .deadline
            .cmp(&self.deadline)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

impl PartialOrd for Timer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A timer that fired during time advance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerFired {
    pub task: usize,
    /// Journal entry that enabled this timer, if any.
    pub enabler: Option<Hash>,
}

/// Snapshot of the virtual clock.
///
/// Production backends wrap their ambient time as a tick value; simulation
/// backends report the current discrete virtual time. One tick is one
/// microsecond.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clock {
    ticks: u64,
}

impl Clock {
    pub const fn new(ticks: u64) -> Self {
        Self { ticks }
    }

    pub const fn now(&self) -> u64 {
        self.ticks
    }

    /// Return this snapshot as a virtual clock without timers.
    pub fn to_virtual_time(&self) -> VirtualTime {
        VirtualTime::from_ticks(self.ticks)
    }
}

/// A deterministic virtual clock and timer priority queue.
#[derive(Debug, Default, Clone)]
pub struct VirtualTime {
    now: u64,
    sequence: u64,
    timers: BinaryHeap<Timer>,
}

impl VirtualTime {
    pub const fn now(&self) -> u64 {
        self.now
    }

    /// Build a virtual clock fixed at a tick value.
    ///
    /// Used by production pass-through backends to present their ambient time
    /// as a virtual-clock snapshot.
    pub fn from_ticks(now: u64) -> Self {
        Self {
            now,
            sequence: 0,
            timers: BinaryHeap::new(),
        }
    }

    /// Add a timer for a task without a journaled enabler.
    pub fn set(&mut self, delay: u64, task: usize) {
        self.set_with_enabler(delay, task, None);
    }

    /// Add a timer for a task, recording the journal entry that enabled it.
    ///
    /// The enabler becomes the parent of the `TimerFire` entry journaled when
    /// this timer fires.
    pub fn set_with_enabler(&mut self, delay: u64, task: usize, enabler: Option<Hash>) {
        self.sequence += 1;
        self.timers.push(Timer {
            deadline: self.now.saturating_add(delay),
            sequence: self.sequence,
            task,
            enabler,
        });
    }

    /// Advance to the next timer deadline and return all tasks released at that time.
    pub fn advance(&mut self) -> Vec<usize> {
        self.advance_with_enablers()
            .into_iter()
            .map(|f| f.task)
            .collect()
    }

    /// Advance to the next timer deadline, returning each fired timer with its enabler.
    pub fn advance_with_enablers(&mut self) -> Vec<TimerFired> {
        let Some(next) = self.timers.peek().copied() else {
            return Vec::new();
        };
        self.now = next.deadline;
        let mut ready = Vec::new();
        while self
            .timers
            .peek()
            .is_some_and(|timer| timer.deadline == self.now)
        {
            if let Some(timer) = self.timers.pop() {
                ready.push(TimerFired {
                    task: timer.task,
                    enabler: timer.enabler,
                });
            }
        }
        ready
    }

    /// Jump the clock forward to a deadline.
    ///
    /// The caller must have already fired every timer with an earlier
    /// deadline. Time advances only when no task can run (quiescence).
    pub fn advance_to(&mut self, deadline: u64) {
        debug_assert!(deadline >= self.now, "virtual time cannot move backward");
        self.now = deadline;
    }
}
