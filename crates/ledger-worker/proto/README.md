# ledger-worker wire codec

The single wire codec is `crate::r#gen` (`crates/ledger-worker/src/gen.rs`,
`crates/ledger-worker/src/gen/ledger.control.v2.rs`).

The former hand-rolled codec in `pb.rs` was deleted after the generated
bindings proved wire-identical in parity tests; prost skips unknown fields so
older readers tolerate newer writers. `build.rs` regenerates the bindings when
the `grpc` feature is enabled and fails closed when `protoc` is missing; the
checked-in copy in `src/gen/ledger.control.v2.rs` keeps offline builds working
via `include!`.

Wire note: `execution_identity` bytes fields carry the framed 34-byte
`EntryHash` form (`0x1e 0x20` prefix plus the 32-byte digest). Hex fields
(`run_config_hash_hex`, `journal_root_hex`) stay raw 64-char hex; only the
binary bytes fields frame.
