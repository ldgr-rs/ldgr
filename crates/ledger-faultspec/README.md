# ledger-faultspec

Failure-scenario DSL for the ldgr engine.

A small line-oriented language for declaring faults - `drop`, `partition`, `crash-restart`, `corrupt`, `torn-write`, `clock-skew`, `bounded-latency` - plus the parser (`parser.rs`), the compiler to engine fault types (`compiler.rs`, `FaultInjection`), and the canonical 8-scenario library with known outcomes (`library.rs`: partition, crash-restart, corruption, clock-skew, torn-write, bounded-latency, leader-stepdown, membership-churn).

Example (from the parser tests):

```
scenario drop-test
drop 30% of leader->replica Msgs for 5s every 60s
```

The crate stays Apache-2.0: it builds on `ledger-format` types, so the same DSL text yields the same neutral fault entries and schedule deterministically without requiring a live journal. The deterministic mapping from `FaultInjection` to the engine's hash-targeted `SimFault` lives in `ledger-explorer` (`faultspec_bridge`), which owns the BLAKE3 hashing. Pub fields `faults` and `schedule` are read by `faultspec_bridge`.
