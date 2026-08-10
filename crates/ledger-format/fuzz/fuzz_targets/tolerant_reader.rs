//! Fuzz the tolerant (superset-accepting) CBOR reader.
//!
//! The tolerant reader accepts indefinite-length forms, non-shortest widths,
//! duplicate keys, `NaN`, and `-0.0`. Its contract is the same as the
//! canonical decoder: any byte input returns a value or an error, never a
//! panic. A panic here is a libFuzzer crash and fails the run.

#![no_main]

use ledger_format::cbor::TolerantReader;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = TolerantReader::new().parse(data);
});
