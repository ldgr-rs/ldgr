// ledger-lint:allow (host binary; rt-server parses process CLI arguments)
//! `rt-server`: the AGPL engine effect server binary.
//! Usage: `rt-server --socket PATH --seed HEX`.

use std::path::PathBuf;
use std::process::ExitCode;

use rt_server::run;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut socket: Option<PathBuf> = None;
    let mut seed = ledger_format::EntryHash([0u8; 32]);

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" => {
                i += 1;
                socket = args.get(i).map(PathBuf::from);
            }
            "--seed" => {
                i += 1;
                let Some(hex) = args.get(i) else {
                    eprintln!("rt-server: missing argument for --seed");
                    return ExitCode::from(2);
                };
                let Some(bytes) = decode_hex(hex) else {
                    eprintln!("rt-server: invalid 64-hex seed: {hex}");
                    return ExitCode::from(2);
                };
                seed = bytes;
            }
            _ => {}
        }
        i += 1;
    }

    let Some(socket) = socket else {
        eprintln!("usage: rt-server --socket PATH --seed HEX");
        return ExitCode::from(2);
    };

    match run(&socket, seed) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("rt-server: {error}");
            ExitCode::from(1)
        }
    }
}

/// Decode 64 hex chars into a 32-byte seed (`None` fails closed to zero seed).
fn decode_hex(hex: &str) -> Option<ledger_format::EntryHash> {
    ledger_format::hash_from_hex(hex).ok()
}
