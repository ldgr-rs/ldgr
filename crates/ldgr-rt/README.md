# ldgr-rt

Deterministic runtime facade and wire protocol for the ldgr engine.

The runtime architecture consists of two crates:

1. **`ldgr-rt`** (Apache-2.0): Client-facing SDK and wire protocol. External systems under test (SUT) import this crate.
2. **`rt-server`** (AGPL-3.0-or-later): Dedicated engine server daemon. It binds a private Unix domain socket and executes simulation effects against `ledger-sim` and `ledger-explorer`.

## Execution Modes

- **Default (`tokio`)**: Runs code on the ambient asynchronous runtime with OS entropy and system clocks.
- **`sim` (IPC)**: Connects to `rt-server` over a private Unix domain socket. Effects (clock, RNG, filesystem, network) execute deterministically on the engine.
- **`sim-link`**: Links directly to `ledger-sim` in-process for fast workspace iteration and testing.

## Protocol Boundary

The client and server communicate via length-prefixed binary frames:
- **Transport**: Unix domain socket in a private mode-0700 directory.
- **Peer Verification**: Linux `SO_PEERCRED` checks match the socket owner UID.
- **Handshake**: Authenticates with a 32-byte `ExecutionIdentity` digest.
- **Effect Stream**: Request and response frames for clock, RNG, network messages, and byte-accurate filesystem operations.
