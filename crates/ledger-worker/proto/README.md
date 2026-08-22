# ledger-worker wire codec

The single wire codec is `crate::r#gen` (`crates/ledger-worker/src/gen.rs`,
`crates/ledger-worker/src/gen/ledger.control.v1.rs`).

The former hand-rolled codec in `pb.rs` was deleted after the generated
bindings proved wire-identical in parity tests; prost skips unknown fields so
older readers tolerate newer writers. `build.rs` regenerates the bindings when
the `grpc` feature is enabled and fails closed when `protoc` is missing; the
checked-in copy in `src/gen/ledger.control.v1.rs` keeps offline builds working
via `include!`.
