// Test target per 08-engineering 5.1: unwrap/expect are allowed in test code;
// clone/collect style lints are also relaxed under -D warnings.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::redundant_clone,
    clippy::needless_collect
)]
use ledger_sim::{LeakClass, Sentinel};

#[test]
fn sentinel_tracks_and_reports_runtime_leak_classes() {
    let mut sentinel = Sentinel::new();
    sentinel.record_leak(LeakClass::WallClock);
    sentinel.record_leak(LeakClass::AmbientRng);
    sentinel.record_leak(LeakClass::RawThread);
    sentinel.record_leak(LeakClass::UnsimulatedIo);
    sentinel.record_leak(LeakClass::EnvVarEntropy);

    assert!(sentinel.has_leaks());
    assert_eq!(sentinel.leaks().len(), 5);
}
