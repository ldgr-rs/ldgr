# Security

## Reporting a vulnerability

No `security.txt` is published yet. To report a vulnerability, open a
restricted GitHub Security Advisory for `ldgr`:

1. Go to the repository Security tab.
2. Select "Report a vulnerability".
3. Fill in affected versions, impact, and reproduction steps.
4. Keep the report private until the maintainers confirm a fix window.

Do not file a public issue for a suspected vulnerability. The maintainers
will acknowledge within three business days and coordinate disclosure.

## Attack surface

ldgr is a testing tool. The following boundaries are the ones to watch.

### Untrusted input

The CLI parses untrusted inputs at explicit boundaries:

* `.ldgr` manifests and CBOR payloads
* Entry and journal framing
* Hash, hex, URL, and path fields in manifests and queue records
* Protobuf fields on control-plane paths

Every boundary validates before use. Lengths and counts are bounded, hashes
are verified, and paths are checked before they touch the filesystem.
Treat any red error from `ledger format --check` or `ledger repro` as a
signal that the artifact is malformed.

### IPC and network

* UDS endpoints live in a private directory with restrictive socket
  permissions and authenticate the peer where the platform supports peer
  credentials.
* gRPC and queue paths validate records before execution.
* Do not expose the worker UDS directory or gRPC endpoint to untrusted
  networks. Bind them to localhost or to a private interface.

### No secrets in logs or URLs

Never put tokens or credentials in log lines or URL query strings. The
worker reads artifact tokens from the environment. The CLI never logs
secret values.

## What ldgr does not promise

ldgr finds bugs in simulated runs. It does not sandbox the system under
test for production use for now. Do not point the simulator or the worker at
untrusted workloads on a production host. Run foreign or third-party guests
in an isolated environment you control.

ldgr also does not promise that a clean simulation run equals production
safety. A clean run means no bug was found for the seeds, schedules, and
faults you tried. Widen the campaign before you claim coverage.

## Sentinel

On Linux, the optional `sentinel` feature adds a belt-and-suspenders check
inside simulation. The belt traps ambient reads of the clock and system
entropy and records them as typed findings. It is a detector, not an
enforcer. The normal enforcement remains the effects boundary and
`ledger-lint`. The belt is opt-in, Linux-only, and gated behind explicit
cargo features and host setup. Prefer the boundary and the linter for
portability. Use the belt as an extra review signal.

## Updates

Track `SECURITY.md` at the repository root for future rotation of the
contact method and for any published advisories. Pin your dependency on a
tagged release and verify its signature when releases are signed.
