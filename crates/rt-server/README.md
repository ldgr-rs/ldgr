# rt-server

AGPL-3.0-or-later composition root: the deterministic engine effect server.

`rt-server` binds a private Unix domain socket and serves simulation effects for external processes.

## Features

- **Byte-Faithful SimFs**: Reads and writes arbitrary byte payloads to simulated storage with provenance tracking.
- **SO_PEERCRED Verification**: Validates connecting peers against the socket owner UID on Linux.
- **Identity Handshake**: Verifies the client's `ExecutionIdentity` before serving effects.
- **IPC Protocol**: Speaks the binary length-prefixed wire protocol defined in `ldgr-rt`.
