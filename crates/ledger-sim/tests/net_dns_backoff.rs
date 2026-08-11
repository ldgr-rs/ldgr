//! DNS resolution and exponential backoff modeling for the simulated network.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use ledger_format::EntryKind;
use ledger_sim::{DnsTable, RunConfig, SeedTree, Simulation, backoff, backoff_jittered};

fn boxed(
    future: impl Future<Output = ()> + 'static,
) -> Pin<Box<dyn Future<Output = ()> + 'static>> {
    Box::pin(future)
}

#[test]
fn dns_resolves_known_names_and_rejects_unknown() {
    let mut dns = DnsTable::new();
    dns.insert("coordinator", 1);
    dns.insert("replica-a", 2);
    assert_eq!(dns.resolve("coordinator"), Some(1));
    assert_eq!(dns.resolve("replica-a"), Some(2));
    assert_eq!(dns.resolve("absent"), None);
    assert!(dns.contains("coordinator"));
    assert!(!dns.contains("absent"));
}

#[test]
fn dns_resolution_is_deterministic_across_identical_configs() {
    let build = || {
        let mut dns = DnsTable::new();
        dns.insert("alpha", 3);
        dns.insert("beta", 7);
        dns
    };
    let a = build();
    let b = build();
    assert_eq!(a, b, "identical configs must build identical tables");
    assert_eq!(a.resolve("alpha"), b.resolve("alpha"));
    assert_eq!(a.resolve("beta"), b.resolve("beta"));
    assert_eq!(a.resolve("missing"), b.resolve("missing"));
}

#[test]
fn backoff_is_exponential_and_monotonic_until_cap() {
    let base = Duration::from_micros(1);
    let max = Duration::from_micros(10_000);
    let mut previous = Duration::ZERO;
    for retry in 0..10 {
        let delay = backoff(base, retry, max);
        assert_eq!(
            delay.as_micros(),
            1u128 << retry,
            "retry {retry} must double the base delay"
        );
        assert!(delay > previous, "retry {retry} must grow the delay");
        previous = delay;
    }
    assert_eq!(
        backoff(base, 20, max),
        max,
        "the delay must cap at max_delay"
    );
    assert_eq!(backoff(Duration::ZERO, 5, max), Duration::ZERO);
}

#[test]
fn backoff_jitter_is_deterministic_per_seed_and_varies_across_seeds() {
    let base = Duration::from_micros(100);
    let max = Duration::from_micros(100_000);
    let sequence = |seed: u8| -> Vec<Duration> {
        let tree = SeedTree::new([seed; 32]);
        let mut rng = tree.rng("test/backoff");
        (0..8)
            .map(|retry| backoff_jittered(base, retry, max, &mut rng))
            .collect()
    };
    assert_eq!(sequence(1), sequence(1), "same seed must repeat");
    assert_ne!(
        sequence(1),
        sequence(2),
        "different seeds must draw different jitter"
    );
    for pair in sequence(1).windows(2) {
        assert!(pair[1] > pair[0], "jittered backoff must keep growing");
    }
}

#[test]
fn dns_resolve_send_recv_sim_is_deterministic() {
    let run = |seed: u8| {
        let mut dns = DnsTable::new();
        dns.insert("peer", 1);
        let config = RunConfig {
            seed: [seed; 32],
            max_steps: 512,
            dns,
            ..RunConfig::default()
        };
        Simulation::with_tasks(
            config,
            vec![
                Box::new(|boundary| {
                    boxed(async move {
                        let peer = boundary.resolve("peer").unwrap();
                        assert_eq!(peer, 1);
                        let _ = boundary.send(peer, 7);
                    })
                }),
                Box::new(|boundary| {
                    boxed(async move {
                        let value = boundary.recv().await;
                        let _ = boundary.outcome(value);
                    })
                }),
            ],
        )
        .run()
        .unwrap()
    };
    let a = run(42);
    let b = run(42);
    assert_eq!(a.journal.root_hash(), b.journal.root_hash());
    assert_eq!(a.decisions, b.decisions);
    let kinds = a
        .journal
        .entries()
        .map(|entry| entry.data.kind)
        .collect::<Vec<_>>();
    assert!(kinds.iter().any(|kind| matches!(kind, EntryKind::Send)));
    assert!(kinds.iter().any(|kind| matches!(kind, EntryKind::Recv)));
    assert!(a.monitor_issues.is_empty());
}
