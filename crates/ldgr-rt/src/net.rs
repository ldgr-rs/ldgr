//! Message-based network facade.
//!
//! Why: raw `std::net` is forbidden inside simulation. This module exposes a
//! minimal `Conn` channel between two logical actors. Under `sim` it forwards
//! to `SimNet` (partition-aware, timed delivery). Outside `sim` it is an
//! in-process rendezvous channel with no network effects.
//!
//! The `Conn` stores [`ActorId`] explicitly so a [`Handle`] bound to one actor
//! can send as that actor (`Handle::with_actor`). The shared in-process net
//! keeps the same partition and queue semantics as `SimNet` but without virtual
//! time - a thin drop-in facade.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use ledger_format::ActorId;

/// Logical connection between two actors.
#[derive(Debug, Clone)]
pub struct Conn {
    from: ActorId,
    to: ActorId,
    shared: SharedNetwork,
}

#[derive(Debug, Default)]
pub(crate) struct SharedNet {
    // Queue preserves insertion order to keep FIFO per actor pair.
    queue: VecDeque<Message>,
    // ledger-lint:allow:HashSet (partition pairs are membership-checked;
    // the set is never iterated)
    partitions: std::collections::HashSet<(ActorId, ActorId)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Message {
    from: ActorId,
    to: ActorId,
    payload: u64,
}

impl Conn {
    /// Create a connection from `from` to `to` over the given shared network.
    pub fn new(from: ActorId, to: ActorId, shared: SharedNetwork) -> Self {
        Self { from, to, shared }
    }

    /// Create an isolated in-process connection pair for non-sim use.
    pub fn isolated(from: ActorId, to: ActorId) -> Self {
        Self {
            from,
            to,
            shared: SharedNetwork::default(),
        }
    }

    /// Send a payload. Returns `false` when the link is partitioned.
    pub fn send(&self, payload: u64) -> bool {
        let mut net = match self.shared.inner().lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        if net.partitions.contains(&(self.from, self.to)) {
            return false;
        }
        net.queue.push_back(Message {
            from: self.from,
            to: self.to,
            payload,
        });
        drop(net);
        self.shared.notify().notify_waiters();
        true
    }

    /// Non-blocking receive for `to` matching this connection's destination.
    pub fn recv(&self) -> Option<u64> {
        let mut net = match self.shared.inner().lock() {
            Ok(g) => g,
            Err(_) => return None,
        };
        let pos = net
            .queue
            .iter()
            .position(|m| m.from == self.from && m.to == self.to)?;
        net.queue.remove(pos).map(|m| m.payload)
    }

    /// Whether a message is ready for this connection's destination.
    pub fn has_ready(&self) -> bool {
        let net = match self.shared.inner().lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        net.queue
            .iter()
            .any(|m| m.from == self.from && m.to == self.to)
    }

    /// Partition this directed link. Further sends return `false`.
    pub fn partition(&self) {
        // Recover from a poisoned lock (impossible in the single-threaded
        // sim) so the partition is never silently dropped.
        let mut net = self
            .shared
            .inner()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        net.partitions.insert((self.from, self.to));
    }

    /// Whether this link is currently partitioned.
    pub fn is_partitioned(&self) -> bool {
        self.shared
            .inner()
            .lock()
            .map(|net| net.partitions.contains(&(self.from, self.to)))
            .unwrap_or(false)
    }

    pub fn from(&self) -> ActorId {
        self.from
    }

    pub fn to(&self) -> ActorId {
        self.to
    }
}

/// Shared in-process network backing non-sim `Conn`s.
///
/// The handle is opaque: the internal mutex never leaves this module, so link
/// state can only change through [`Conn`] methods or the crate-internal net.
/// Create one with [`shared_network`] and share it by cloning.
#[derive(Debug, Clone, Default)]
pub struct SharedNetwork {
    inner: Arc<Mutex<SharedNet>>,
    notify: Arc<tokio::sync::Notify>,
}

impl SharedNetwork {
    /// Crate-internal access to the guarded net state.
    pub(crate) fn inner(&self) -> &Arc<Mutex<SharedNet>> {
        &self.inner
    }

    /// Crate-internal access to the notification primitive.
    pub(crate) fn notify(&self) -> &Arc<tokio::sync::Notify> {
        &self.notify
    }
}

impl SharedNet {
    /// Remove the oldest queued message addressed to `actor` from any sender.
    ///
    /// Why destination-based: receivers must not depend on knowing or
    /// scanning sender ids, so receives work across the full actor id space.
    pub(crate) fn recv_for(&mut self, actor: ActorId) -> Option<u64> {
        let pos = self.queue.iter().position(|m| m.to == actor)?;
        self.queue.remove(pos).map(|m| m.payload)
    }
}

/// Create a shared network with one shared queue (non-sim path).
pub fn shared_network() -> SharedNetwork {
    SharedNetwork::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_format::ActorId;

    #[test]
    fn send_recv_roundtrip() {
        let net = shared_network();
        let a = Conn::new(ActorId(0), ActorId(1), net.clone());
        let b = Conn::new(ActorId(1), ActorId(0), net.clone());
        assert!(a.send(42));
        assert!(a.has_ready());
        assert_eq!(
            Conn::new(ActorId(0), ActorId(1), net.clone()).recv(),
            Some(42)
        );
        assert!(!a.has_ready());
        assert!(b.send(7));
        assert_eq!(
            Conn::new(ActorId(1), ActorId(0), net.clone()).recv(),
            Some(7)
        );
    }

    #[test]
    fn partition_blocks_send() {
        let c = Conn::isolated(ActorId(0), ActorId(1));
        c.partition();
        assert!(c.is_partitioned());
        assert!(!c.send(1));
    }

    #[test]
    fn fifo_between_same_pair() {
        let c = Conn::isolated(ActorId(0), ActorId(1));
        let _ = c.send(1);
        let _ = c.send(2);
        assert_eq!(c.recv(), Some(1));
        assert_eq!(c.recv(), Some(2));
    }

    #[test]
    fn actor_ids_are_stored_explicitly() {
        let c = Conn::isolated(ActorId(5), ActorId(9));
        assert_eq!(c.from(), ActorId(5));
        assert_eq!(c.to(), ActorId(9));
        let _ = c.send(123);
        // Different actor pair does not see the message.
        let other = Conn::new(ActorId(5), ActorId(8), c.shared.clone());
        assert!(!other.has_ready());
        assert!(c.has_ready());
    }

    #[test]
    fn recv_for_delivers_across_full_id_space_in_fifo_order() {
        let mut net = SharedNet::default();
        net.queue.push_back(Message {
            from: ActorId(20),
            to: ActorId(21),
            payload: 1,
        });
        net.queue.push_back(Message {
            from: ActorId(u32::MAX),
            to: ActorId(21),
            payload: 2,
        });
        net.queue.push_back(Message {
            from: ActorId(0),
            to: ActorId(22),
            payload: 3,
        });
        assert_eq!(net.recv_for(ActorId(21)), Some(1));
        assert_eq!(net.recv_for(ActorId(21)), Some(2));
        // Actor 20 never receives mail addressed elsewhere; unknown actors
        // find nothing.
        assert_eq!(net.recv_for(ActorId(20)), None);
        assert_eq!(net.recv_for(ActorId(u32::MAX)), None);
        assert_eq!(net.recv_for(ActorId(22)), Some(3));
    }
}
