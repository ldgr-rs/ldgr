// ledger-lint:allow (host SUT binary; rt-canary parses process CLI arguments)
//! `rt-canary`: a real external SUT driving the ldgr-rt effect shim.
//!
//! The canary runs a fixed business logic against the deterministic engine:
//! read the clock, draw random words, write a value to SimFs, read it back,
//! fsync, sleep, send a message to itself, and receive it. Every effect is
//! journaled by the engine; the canary prints the final journal root and
//! entry count to stdout.
//!
//! Usage: `rt-canary --socket PATH --identity HEX`

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ldgr_rt::proto::{Effect, EffectResult, Goodbye};
use ldgr_rt::{EngineSession, ShimError};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut socket: Option<PathBuf> = None;
    let mut identity = [0u8; 32];

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" => {
                i += 1;
                socket = args.get(i).map(PathBuf::from);
            }
            "--identity" => {
                i += 1;
                if let Some(hex) = args.get(i)
                    && let Some(bytes) = decode_hex(hex)
                {
                    identity = bytes;
                }
            }
            _ => {}
        }
        i += 1;
    }

    let Some(socket) = socket else {
        eprintln!("usage: rt-canary --socket PATH --identity HEX");
        return ExitCode::from(2);
    };

    match run_canary(&socket, identity) {
        Ok(goodbye) => {
            println!("root {}", hex(&goodbye.root));
            println!("entries {}", goodbye.entries);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("rt-canary: {error}");
            ExitCode::from(1)
        }
    }
}

/// The canary's deterministic business logic.
fn run_canary(socket: &Path, identity: [u8; 32]) -> Result<Goodbye, ShimError> {
    let mut session = EngineSession::connect(socket, identity)?;

    // Clock: read the virtual clock.
    let clock = session.effect(Effect::Clock)?;
    let _ticks = match clock {
        EffectResult::Clock { ticks } => ticks,
        other => panic!("clock effect returned {other:?}"),
    };

    // Random: two words from stream 3.
    let random = session.effect(Effect::Random {
        stream: 3,
        count: 2,
    })?;
    match random {
        EffectResult::Random { words } => assert_eq!(words.len(), 16),
        other => panic!("random effect returned {other:?}"),
    }

    // Filesystem: write, read, sync.
    session.effect(Effect::FsWrite {
        path: "/kv/k".into(),
        offset: 0,
        bytes: 42u64.to_le_bytes().to_vec(),
    })?;
    let read = session.effect(Effect::FsRead {
        path: "/kv/k".into(),
        offset: 0,
        len: 8,
    })?;
    match read {
        EffectResult::FsRead { observed } => {
            assert_eq!(
                &observed[..8],
                &42u64.to_le_bytes(),
                "read back the written value"
            );
        }
        other => panic!("fs read returned {other:?}"),
    }
    session.effect(Effect::FsSync {
        path: "/kv/k".into(),
    })?;

    // Sleep and network.
    session.effect(Effect::Sleep { ticks: 10 })?;
    session.effect(Effect::Send {
        to: session.actor(),
        payload: b"hello".to_vec(),
    })?;
    let recv = session.effect(Effect::Recv)?;
    match recv {
        EffectResult::Recv { payload } => {
            assert_eq!(
                payload.as_deref(),
                Some(b"hello".as_slice()),
                "receive the sent message"
            );
        }
        other => panic!("recv returned {other:?}"),
    }

    session.finish()
}

fn decode_hex(hex: &str) -> Option<[u8; 32]> {
    ledger_format::hash_from_hex(hex).ok()
}

fn hex(bytes: &[u8; 32]) -> String {
    ledger_format::hash_to_hex(bytes)
}
