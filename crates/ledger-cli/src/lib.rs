//! Library backend for the ledger CLI.
//!
//! Host-side checks, project scaffolding, format verification, and the LDFI
//! campaign driver live here so integration tests can call them in process
//! without spawning the binary.

pub mod checks;
pub mod format_check;
pub mod ldfi_cmd;
pub mod scaffold;

use std::io;
use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_verbosity_flag::{Verbosity, VerbosityFilter};

use ledger_format::{EntryKind, Hash, Payload};
use ledger_sim::{Instruction, Policy, RunResult};

/// Re-exports the completion shell selector for test consumers.
pub use clap_complete::Shell;

/// Emits shell completions for the ledger command.
///
/// This helper lives in the library so integration tests can exercise the
/// generator without spawning the binary.
pub fn generate_completions(shell: clap_complete::Shell, out: &mut dyn io::Write) {
    let mut command = Cli::command();
    clap_complete::generate(shell, &mut command, "ledger", out);
}

/// The reference mini key-value workload used by the campaign subcommands.
#[derive(Debug, Clone, Copy)]
pub struct DefaultMiniKv;

impl ledger_explorer::search::Workload for DefaultMiniKv {
    fn programs(&self) -> Vec<Vec<Instruction>> {
        vec![
            vec![
                Instruction::Send { to: 1, payload: 42 },
                Instruction::Send {
                    to: 2,
                    payload: 100,
                },
                Instruction::Done,
            ],
            vec![
                Instruction::Receive,
                Instruction::Send { to: 2, payload: 42 },
                Instruction::Done,
            ],
            vec![
                Instruction::Receive,
                Instruction::Outcome,
                Instruction::Done,
            ],
        ]
    }

    fn history(&self, run: &RunResult) -> Vec<ledger_explorer::HistoryOperation> {
        run.journal
            .entries()
            .filter_map(|entry| match (&entry.data.kind, &entry.data.payload) {
                (EntryKind::Send, Payload::Pair { left: 1, right: 42 })
                    if entry.data.actor == 0 =>
                {
                    Some(ledger_explorer::HistoryOperation::Write {
                        key: "k".into(),
                        value: 42,
                        witness: entry.id,
                    })
                }
                (EntryKind::Outcome, Payload::Number(value)) if entry.data.actor == 2 => {
                    Some(ledger_explorer::HistoryOperation::Read {
                        key: "k".into(),
                        value: *value,
                        witness: entry.id,
                    })
                }
                _ => None,
            })
            .collect()
    }
}

/// Derives a 32-byte content seed from a compact u64 root.
pub fn seed_from_u64(value: u64) -> Hash {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&value.to_le_bytes());
    seed
}

/// Returns true when the requested verbosity shows detail beyond the default.
pub fn is_verbose(filter: VerbosityFilter) -> bool {
    matches!(
        filter,
        VerbosityFilter::Info | VerbosityFilter::Debug | VerbosityFilter::Trace
    )
}

/// Ledger - Deterministic Simulation Testing and Causal Journal Platform.
#[derive(Debug, Parser)]
#[command(name = "ledger", version, about, long_about = None)]
pub struct Cli {
    /// Emit machine-readable JSON records.
    #[arg(short = 'j', long, global = true, conflicts_with = "ndjson")]
    pub json: bool,

    /// Emit one JSON object per line for structured outputs.
    #[arg(long, global = true)]
    pub ndjson: bool,

    /// Verbosity: repeat `-v` for more detail, `-q` to quiet.
    #[command(flatten)]
    pub verbose: Verbosity,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run a deterministic simulation campaign.
    Sim {
        /// Root seed for the campaign.
        #[arg(long, default_value_t = 0)]
        seed: u64,
        /// Scheduling policy.
        #[arg(long, value_enum, default_value_t = PolicyArg::Bandit)]
        policy: PolicyArg,
        /// Exploration constant for the bandit policy.
        #[arg(long, default_value_t = 1.414)]
        exploration_constant: f64,
        /// Priority-change budget for the pct policy.
        #[arg(long, default_value_t = 8)]
        priority_changes: usize,
        /// Maximum instructions per run.
        #[arg(long, default_value_t = 256)]
        max_steps: usize,
        /// Number of campaign attempts.
        #[arg(long, default_value_t = 100)]
        runs: usize,
    },
    /// Replay a seed and verify the journal root.
    Repro {
        /// Root seed for the replay.
        #[arg(long, default_value_t = 0)]
        seed: u64,
        /// Scheduling policy.
        #[arg(long, value_enum, default_value_t = PolicyArg::Random)]
        policy: PolicyArg,
        /// Exploration constant for the bandit policy.
        #[arg(long, default_value_t = 1.414)]
        exploration_constant: f64,
        /// Priority-change budget for the pct policy.
        #[arg(long, default_value_t = 8)]
        priority_changes: usize,
        /// Maximum instructions per run.
        #[arg(long, default_value_t = 256)]
        max_steps: usize,
    },
    /// Minimize a failing run using schedule-delta debugging.
    Minimize {
        /// Root seed for the campaign.
        #[arg(long, default_value_t = 0)]
        seed: u64,
        /// Scheduling policy.
        #[arg(long, value_enum, default_value_t = PolicyArg::Random)]
        policy: PolicyArg,
        /// Exploration constant for the bandit policy.
        #[arg(long, default_value_t = 1.414)]
        exploration_constant: f64,
        /// Priority-change budget for the pct policy.
        #[arg(long, default_value_t = 8)]
        priority_changes: usize,
        /// Maximum instructions per run.
        #[arg(long, default_value_t = 256)]
        max_steps: usize,
        /// Number of campaign attempts.
        #[arg(long, default_value_t = 256)]
        runs: usize,
    },
    /// Compare two seeds or runs for first divergence.
    Diff {
        /// Root seed for the first run.
        #[arg(long, default_value_t = 1)]
        seed_a: u64,
        /// Root seed for the second run.
        #[arg(long, default_value_t = 2)]
        seed_b: u64,
        /// Maximum instructions per run.
        #[arg(long, default_value_t = 256)]
        max_steps: usize,
    },
    /// Verify environment determinism and toolchain health.
    Doctor,
    /// Initialize a new .ldgr project template.
    Init {
        /// Target directory (default: current directory).
        #[arg(value_name = "DIR")]
        dir: Option<String>,
        /// Overwrite existing files.
        #[arg(long)]
        force: bool,
    },
    /// Inspect a .ldgr or CBOR file.
    Format {
        /// The .ldgr or CBOR file to verify.
        file: PathBuf,
        /// Verify canonical RFC 8949 Core Deterministic CBOR encoding.
        #[arg(long)]
        check: bool,
    },
    /// Run an LDFI campaign and execute the top fault hypothesis.
    Ldfi {
        /// Root seed for the campaign.
        #[arg(long, default_value_t = 0)]
        seed: u64,
        /// Maximum instructions per run.
        #[arg(long, default_value_t = 256)]
        max_steps: usize,
        /// Number of campaign attempts.
        #[arg(long, default_value_t = 64)]
        attempts: usize,
    },
    /// Print shell completion scripts to stdout.
    Completions {
        /// Target shell.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PolicyArg {
    Random,
    Pct,
    Bandit,
    Replay,
}

impl PolicyArg {
    pub fn to_policy(self, exploration_constant: f64, priority_changes: usize) -> Policy {
        match self {
            Self::Random => Policy::Random,
            Self::Pct => Policy::Pct { priority_changes },
            Self::Bandit => Policy::Bandit {
                exploration_constant,
                pct_mix: 0.1,
            },
            Self::Replay => Policy::Replay,
        }
    }
}
