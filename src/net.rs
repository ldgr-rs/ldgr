//! Deterministic in-process network model.

use std::collections::VecDeque;

/// A delivered network message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Sending task.
    pub from: usize,
    /// Receiving task.
    pub to: usize,
    /// Opaque message payload.
    pub payload: u64,
    /// Journal id for the send event.
    pub send_id: [u8; 32],
}

/// Network state with explicit partitions and FIFO delivery.
#[derive(Debug, Default)]
pub struct SimNet {
    queue: VecDeque<Message>,
    partitions: Vec<(usize, usize)>,
}

impl SimNet {
    /// Partition traffic between two tasks.
    pub fn partition(&mut self, from: usize, to: usize) {
        if !self.partitions.contains(&(from, to)) {
            self.partitions.push((from, to));
        }
    }

    /// Remove a partition.
    pub fn heal(&mut self, from: usize, to: usize) {
        self.partitions.retain(|pair| *pair != (from, to));
    }

    /// Queue a message unless the link is partitioned.
    pub fn send(&mut self, message: Message) -> bool {
        if self.partitions.contains(&(message.from, message.to)) {
            return false;
        }
        self.queue.push_back(message);
        true
    }

    /// Take the first queued message for a receiver.
    pub fn recv(&mut self, task: usize) -> Option<Message> {
        let index = self.queue.iter().position(|message| message.to == task)?;
        self.queue.remove(index)
    }

    /// Return whether a message is waiting for a receiver.
    pub fn has_message(&self, task: usize) -> bool {
        self.queue.iter().any(|message| message.to == task)
    }
}
