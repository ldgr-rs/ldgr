# Roadmap

This file lists what ldgr can do today and where it is heading. It carries
no dates: items move when they are ready, and the order below is intent,
not a schedule. The [honest status](README.md#honest-status) rule applies
here too - if this file drifts from reality, open an issue.

## Shipped

Works today, gated in CI.

- Deterministic simulation engine: virtual time, seeded scheduling, and a
  simulated network and filesystem. Same build, seed, config, and inputs
  produce a byte-identical journal.
- Causal journal: a content-addressed DAG of effects with crash-recovery
  semantics, sealed `.ldgr` artifacts, and byte-identical replay.
- LDFI campaigns: lineage-driven fault injection that ranks fault
  hypotheses, verifies them by replay, and minimizes counterexamples with
  certificates.
- Effect origins: journal entries trace back to the call sites that
  produced them, on every execution path.
- Runner watchdog: `--deadline-ms` converts hangs into a fast, diagnosable
  exit instead of a silent stall.
- Liveness outcomes: deadlocks and budget exhaustion surface as findings
  with witnesses, minimizable like any other violation.
- Determinism lint: static scanning for ambient APIs and unordered hash
  collections on the simulation path.
- OTel ingest: OpenTelemetry spans become journal envelopes.
- Polyglot guests: wasm32-wasip1 guests reach the full engine, with
  differential parity tests.
- CLI with machine-readable output, shell completions, scaffolds, coverage
  export (lcov/sarif/jacoco), and signed campaign certificates.
- Failure-spec scenarios: declarative fault programs (partitions, crash
  and restart, storage corruption, clock skew) compiled to deterministic
  fault schedules.

## Next

The current focus, in rough order.

- `ledger-fuzzer` crate: the search loop as its own component, with a
  persistent corpus of seeds, fault schedules, and inputs, plus
  coverage-guided exploration driven by journal-root diversity.
- Time realism: a deadline oracle and seeded per-actor clock skew and
  drift, so timing bugs are both injectable and observable.
- Resource realism: bounded queues, resource-exhaustion limits, and
  slow-storage faults.
- Source spans: minimized repros that point at the code locations that
  produced the conflicting values.
- Fairness oracle: liveness properties beyond budget exhaustion - a
  runnable task must be scheduled within N ticks.
- One-line porting: a `#[ledger::sim_test]` attribute and a tokio import
  swap, so an existing async test runs under the simulator with minimal
  change - and a verification flow that proves the port preserved
  behavior byte for byte.
- Durable execution: long-running workflows log their steps to the
  journal and resume from it.
- Campaign UX: a terminal UI for campaigns, an MCP server with
  campaign-authoring tools, and failure explanation on top of the
  journal.
- Trust surface: signed journals and attestations bound to tenant keys.

## Exploring

Directions we expect to pursue, design still open.

- Concolic input generation for wasm guests.
- Deterministic profiling: same run config, byte-identical profile.
- Upgrade-safety differential testing: run two builds against the same
  schedule and pin every divergence.
- Time-travel debugging: step through a recorded run.
- Foreign-process boundary: determinize network, time, and faults for
  systems that cannot be re-instrumented, via a per-language shim.
- Journal-native linearizability checking, and oracles compiled from
  executable specifications.
- Learning the system's state machine from journals, to guide fault
  injection and measure model coverage.
- Structured mutation of failure-spec scenarios, including
  LLM-drafted scenarios validated by the compiler.
- Duplicate-delivery faults for at-least-once systems (a deliberate,
  format-versioned change).
- Shared-memory schedule exploration: threads, atomics, and lock orders
  beside the message-passing model.
- Byte-stream network fidelity for protocol stacks that need TCP/IP
  semantics rather than message channels.
- Multi-node journal replication.
- Format interchange with external record/replay and trace formats.
- More example systems: an authentication service with a revocation
  race, embedded targets, and flash-storage simulation.
- Python and TypeScript SDKs.
- ldgrhub: a public registry where findings are browsed by protocol class
  and replayed live in your browser.

## Feedback

Missing something you need? Open an issue - real workloads steer this
list more than the plan does.
