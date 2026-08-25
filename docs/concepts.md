# Concepts

This page gives you the mental model for ldgr. It explains what the tool does and why it works.

## Deterministic simulation testing

Normal tests run your code once on real time, real randomness, real threads and real I/O. That hides bugs until production. The bug depends on timing or ordering that you cannot control.

Deterministic simulation testing replaces the real world with a simulated one. Your system runs against a controlled scheduler, virtual time and simulated effects. You pick a seed. The engine picks the interleaving. Every run is reproducible.

When you fix a bug, you can prove the fix. Same seed, same config, same inputs give the same journal, byte for byte.

## The causal journal

Every effect your system causes during simulation lands in a causal journal. Think of it as a DAG, not a flat log.

* Each effect becomes a journal entry with parents, a vector clock and a payload.
* The DAG is content-addressed. The hash of a run is the root of that DAG.
* The journal is the evidence. Replay is not re-running and hoping - it is walking the same decisions and checking that the journal matches.
* A counterexample is data, not a story: seed, schedule and journal together. You can store it as a file, attach it to an issue and replay it on another machine with one command.

## The effects boundary

Simulation code must not touch the host. Host state breaks replay because two machines or two runs will see different clocks, different random bytes, different filesystem contents.

So ldgr draws a boundary:

* Use virtual time, not the wall clock.
* Use seeded random streams, not OS randomness.
* Use the simulated network (SimNet), not real sockets.
* Use the simulated filesystem (SimFs), not real disk I/O.
* Use the cooperative scheduler, not OS threads.

Outside the boundary, normal host code is fine. The CLI, the worker and adapters run on the host. Inside the boundary, the engine enforces the rule and a lint fails the build if simulation code reaches for ambient APIs.

## Schedules and policies

A run is a sequence of scheduling decisions: which task runs next. A policy picks that task.

* The seed determines the initial state and the scheduler stream.
* Policies are user-visible names like `random`, `bandit`, `pct` and `replay`.
* A campaign runs the same workload many times with many derived seeds and schedules, looking for a violation.

A seed plus a decision list is enough to replay a run exactly. You can diff two runs entry by entry and see where they first diverge.

## Fault injection and LDFI

Many distributed bugs need a fault to show up - a crash, a partition, a slow disk. Injecting faults at random is costly. ldgr also uses lineage-driven fault injection.

* LDFI looks backward from the failure through the journal lineage.
* It asks which faults could have caused that lineage.
* It ranks hypotheses and tries the smallest ones first.

The result is fewer wasted runs. A random campaign may need many attempts. An LDFI campaign often finds the same bug with far fewer.

ldgr also supports declared failure scenarios. You write a scenario that says what class of faults you care about, the engine compiles it to concrete faults and injects them at the right causal positions.

## Counterexamples as data

When an oracle says a run failed, ldgr hands you a finding. A finding carries:

* The seed that found it.
* The decisions the scheduler made.
* The witnesses - the journal entries that show the violation.
* The minimal fault set, when LDFI is involved.

You can replay that finding, verify its journal root, minimize its schedule and emit a certificate that attests to the result. The bug becomes an artifact you can check in CI, not a flaky log you chase.
