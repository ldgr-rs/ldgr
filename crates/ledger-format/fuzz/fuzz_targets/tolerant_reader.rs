//! Fuzz the tolerant reader: any input returns a value or an error,
//! never a panic. A panic is a libFuzzer crash.

#![no_main]

use ledger_format::cbor::TolerantReader;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = TolerantReader::new().parse(data);
});
