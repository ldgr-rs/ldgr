# ledger.control.v1 protobuf contract

Source of truth for the control plane ↔ worker gRPC contract, per
the contract lives with the format spec under `ledger-format`.

- Proto file: `ledger/control/v1/control.proto`
- Package: `ledger.control.v1`
- Services: `ControlPlane`, `WorkerControl`, `ArtifactService`, `Health`

Moved from the repo-root `proto/` directory; the old location is gone.

Rules:

- Append-only within major v1. Never reorder or reuse field numbers.
- Wire-incompatible change requires a major version bump.

Buf CI:

```sh
cd crates/ledger-format && buf lint
buf breaking --against '.git#branch=main,subdir=crates/ledger-format'
```

`buf lint` runs in CI (`control-plane-ci.yml`) on PRs that touch this
directory or the worker. `buf breaking` joins when the Go control-plane
repository lands; there is no second side to compare against yet.

Rust wire codec:

`crates/ledger-worker/src/pb.rs` is the hand-rolled Rust mirror of this
contract. It encodes and decodes the same bytes `prost` would produce, needs
no codegen, and skips unknown fields so older readers tolerate newer writers.
The default transport is newline-delimited JSON over UDS (`proto.rs`). The
`grpc` cargo feature adds tonic-generated stubs (`src/gen/`) and serves this
contract as real gRPC over UDS (`transport.rs`); `tests/cross_boundary.rs`
exercises both transports against the direct in-process simulation.
