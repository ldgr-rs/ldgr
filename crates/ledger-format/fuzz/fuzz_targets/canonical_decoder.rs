//! Fuzz the canonical decoder and manifest reader: any input decodes or
//! errors, never panics. A panic is a libFuzzer crash.

#![no_main]

use ledger_format::RunManifest;
use ledger_format::cbor::CborValue;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = CborValue::from_canonical_bytes(data);
    let _ = RunManifest::from_canonical_bytes(data);
});
