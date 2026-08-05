//! Discrete virtual time.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct Timer {
    deadline: u64,
    sequence: u64,
    task: usize,
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

/// A deterministic virtual clock and timer queue.
#[derive(Debug, Default)]
pub struct VirtualTime {
    now: u64,
    sequence: u64,
    timers: BinaryHeap<Timer>,
}

impl VirtualTime {
    /// Return the current virtual time.
    pub const fn now(&self) -> u64 {
        self.now
    }

    /// Add a timer for a task.
    pub fn set(&mut self, delay: u64, task: usize) {
        self.sequence += 1;
        self.timers.push(Timer {
            deadline: self.now.saturating_add(delay),
            sequence: self.sequence,
            task,
        });
    }

    /// Advance to the next timer and return all tasks released at that time.
    pub fn advance(&mut self) -> Vec<usize> {
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
                ready.push(timer.task);
            }
        }
        ready
    }
}
