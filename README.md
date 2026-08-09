# ldgr

`ldgr` is a small Rust prototype for Ledger's deterministic simulation idea.

It currently demonstrates part of the seed implementation:

- canonical CBOR-derived content addresses;
- causal journal entries with vector-clock summaries;
- seeded random and PCT-style scheduling;
- virtual time, simulated networking, and a small crashable file model;
- journal predicates, causal slicing, and `ddmin`;
- bounded LDFI fault candidates; and
- a mini-KV stale-read campaign.

Run the demo with `cargo run --example minikv`.

The demo runs a two-node key-value workload with a client write and read race.
Node A replicates the write to node B through the simulated network.
Some schedules let node B answer the read before replication arrives.
The oracle reports that stale read and the journal records its causal path.
The Explorer prints a reproducible journal root and bounded LDFI fault candidates.

This is a prototype, not the full Ledger platform. It does not yet implement most of the core features.
