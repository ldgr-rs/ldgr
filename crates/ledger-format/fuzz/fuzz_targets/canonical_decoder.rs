//! Fuzz the canonical CBOR decoder and the manifest reader.
//!
//! The zero-trust contract: any byte input must either decode or return an
//! error. A panic in the decoder is a libFuzzer crash and fails the run,
//! which is the desired signal. These are the only two calls made; there is
//! no setup that can panic first.

#![no_main]

use ledger_format::RunManifest;
use ledger_format::cbor::CborValue;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = CborValue::from_canonical_bytes(data);
    let _ = RunManifest::from_canonical_bytes(data);
});
