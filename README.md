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

Run the demo with `cargo run -- sim` or inspect fault candidates with `cargo run -- ldfi`.

This is a prototype, not the full Ledger platform. It does not yet implement most of the core features.
