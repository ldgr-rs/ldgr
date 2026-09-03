// ledger-lint:allow - host daemon / non-sim passthrough, like TokioBackend
use ledger_format::EntryHash;
use ledger_sim::RunConfig;

/// True when `wire_fingerprint_hex` names the profile pinned by
/// `expected_hex8`: same lowercase prefix and at least as long. The daemon
/// pins eight hex chars while wire senders may carry the full digest.
pub fn profile_pin_matches(wire_fingerprint_hex: &str, expected_hex8: &str) -> bool {
    let wire = wire_fingerprint_hex.to_ascii_lowercase();
    let expected = expected_hex8.to_ascii_lowercase();
    wire.len() >= expected.len() && wire.starts_with(&expected)
}

/// Compute the deterministic blake3 hash of a RunConfig's canonical bytes.
///
/// # Errors
/// Returns the canonical-encoding error when the config carries a non-finite
/// float; the owned codec lives in `ledger_sim::config_canonical`.
pub fn run_config_hash(
    config: &RunConfig,
) -> Result<ledger_format::EntryHash, ledger_sim::ConfigCanonicalError> {
    ledger_sim::canonical_hash(config)
}

/// Canonical bytes for RunConfig hashing, version 1.
///
/// The owned codec in `ledger_sim::config_canonical` produces versioned
/// canonical CBOR: seed, policy, max_steps, swarm knobs, dropped events,
/// links, DNS (sorted), fault schedule, monitor, and `fs_journaling` (always
/// present, `null` when unset) so the bytes are identical across feature
/// builds. See that module for the field order and version rules.
///
/// # Errors
/// Returns the canonical-encoding error when the config carries a non-finite
/// float.
pub fn canonical_bytes(config: &RunConfig) -> Result<Vec<u8>, ledger_sim::ConfigCanonicalError> {
    ledger_sim::to_canonical_bytes(config)
}

/// Encode a hash as lowercase hex.
pub fn hash_to_hex(hash: &EntryHash) -> String {
    ledger_format::hash_to_hex(hash)
}

/// Decode a lowercase hex string into a hash.
///
/// # Errors
/// Returns the format crate's hex error for malformed input.
pub fn hex_to_hash(s: &str) -> Result<EntryHash, ledger_format::HexError> {
    ledger_format::hash_from_hex(s)
}
