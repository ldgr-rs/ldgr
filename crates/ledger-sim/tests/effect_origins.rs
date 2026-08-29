//! Effect-origin capture: side-channel population, format neutrality, and
//! default delegation for backends without origin support.

use ledger_sim::{Effects, FsExt, Net, NetExt, OriginSource, SeedTree, SimBackend};

fn fresh_backend() -> SimBackend {
    SimBackend::for_actor(SeedTree::new([7; 32]), 1)
}

fn message(to: usize) -> ledger_sim::Message {
    ledger_sim::Message {
        from: 1,
        to,
        content: 42u64.to_le_bytes().to_vec(),
        message_id: ledger_format::MessageId::new(1, 0),
        send_id: [0; 32],
        deliver_at: 0,
    }
}

#[test]
fn tracked_calls_record_origins_keyed_by_entry_hash() {
    let backend = fresh_backend();
    let send_line = line!() + 1;
    let delivered = backend.net().send_tracked(message(2));
    assert!(delivered);
    let write_id = backend
        .fs()
        .write_tracked("k", 7)
        .expect("tracked write journals");

    let origins = backend.origins_snapshot();
    assert_eq!(origins.len(), 2, "send and write must both record");

    for (id, source) in &origins {
        assert!(backend.journal_snapshot().get(id).is_some());
        match source {
            OriginSource::Source(origin) => {
                assert!(
                    origin.file.ends_with("effect_origins.rs"),
                    "origin must point at the SUT call site, got {}",
                    origin.file
                );
            }
            other => panic!("native calls must capture Source origins, got {other:?}"),
        }
    }

    let (_, send_origin) = &origins[0];
    let OriginSource::Source(origin) = send_origin else {
        panic!("send origin must be a Source");
    };
    assert_eq!(
        origin.line, send_line,
        "origin line is the tracked call site"
    );

    let write_origin = backend.origin_of(&write_id).expect("write origin recorded");
    assert!(matches!(write_origin, OriginSource::Source(_)));
}

#[test]
fn recv_inherits_the_origin_of_its_send() {
    let backend = fresh_backend();
    backend.net().send_tracked(message(2));

    // Deliver the sent message to its target task and receive it through
    // the boundary.
    {
        let now = backend.clock().now();
        let _ = backend.net().recv(2, now);
    }

    let origins = backend.origins_snapshot();
    assert_eq!(origins.len(), 2, "recv must inherit, not add a new origin");
}

#[test]
fn capture_never_changes_journal_bytes() {
    // Identical effect sequences through tracked and untracked paths must
    // produce identical journal roots: origins live outside the journal.
    let run = |tracked: bool| {
        let backend = fresh_backend();
        if tracked {
            backend.net().send_tracked(message(2));
            let _ = backend.fs().write_tracked("k", 7);
            let _ = backend.fs().fsync_tracked();
        } else {
            let _ = backend.net().send(message(2));
            let _ = backend.fs().write("k", 7);
            let _ = backend.fs().fsync();
        }
        (
            backend.journal_snapshot().root_hash(),
            backend.origins_snapshot().len(),
        )
    };

    let (plain_root, plain_origins) = run(false);
    let (tracked_root, tracked_origins) = run(true);
    assert_eq!(plain_root, tracked_root, "origins must not perturb the DAG");
    assert_eq!(plain_origins, 0);
    assert_eq!(tracked_origins, 3);
}

#[test]
fn loc_variants_delegate_to_base_behavior_by_default() {
    // A minimal Net impl without origin support keeps working through the
    // tracked alias and the explicit variant alike.
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingNet {
        sends: AtomicUsize,
    }

    impl Net for CountingNet {
        fn send(&self, _message: ledger_sim::Message) -> bool {
            self.sends.fetch_add(1, Ordering::Relaxed);
            true
        }

        fn recv(&self, _task: usize, _now: u64) -> Option<ledger_sim::Message> {
            None
        }

        fn has_ready_message(&self, _task: usize, _now: u64) -> bool {
            false
        }
    }

    let net = CountingNet {
        sends: AtomicUsize::new(0),
    };
    assert!(net.send_loc(message(3), OriginSource::Unknown));
    assert!(net.send_tracked(message(3)));
    assert_eq!(net.sends.load(Ordering::Relaxed), 2);
}
