//! Library backend for the ledger CLI.
//!
//! Host-side checks, project scaffolding, format verification, and the LDFI
//! campaign driver live here so integration tests can call them in process
//! without spawning the binary.

pub mod cert_cmd;
pub mod checks;
pub mod coverage_cmd;
pub mod faults_cmd;
pub mod format_check;
pub mod ldfi_cmd;
#[cfg(unix)]
pub mod rt_server;
pub mod scaffold;
pub mod scaffold_consensus;

use std::io;
use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_verbosity_flag::{Verbosity, VerbosityFilter};

use ledger_format::{ActorId, EntryHash, EntryKind, EntryPayload, SendFrame};
use ledger_sim::{Instruction, Policy, Probability, RunResult};

/// Default pct_mix 0.1 without unwrap or expect; 0.1 is known valid.
pub(crate) fn default_pct_mix() -> Probability {
    match Probability::new(0.1) {
        Ok(prob) => prob,
        Err(_) => Probability::ZERO,
    }
}

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
                (
                    EntryKind::Send,
                    EntryPayload::Send(SendFrame {
                        to: ActorId(1),
                        original_content,
                        ..
                    }),
                ) if entry.data.actor == ActorId(0)
                    && original_content.as_slice() == 42u64.to_le_bytes() =>
                {
                    Some(ledger_explorer::HistoryOperation::Write {
                        key: "k".into(),
                        value: 42,
                        witness: entry.id,
                    })
                }
                (
                    EntryKind::Outcome,
                    EntryPayload::Outcome(ledger_format::OutcomePayload {
                        value: ledger_format::CanonicalValue::Unsigned(value),
                        ..
                    }),
                ) if entry.data.actor == ActorId(2) => {
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
pub fn seed_from_u64(value: u64) -> EntryHash {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&value.to_le_bytes());
    EntryHash(seed)
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

    /// Wall-clock deadline for the whole command in milliseconds. On expiry
    /// the runner prints a diagnostic and exits with code 2, guarding
    /// against silent hangs in runs and campaigns.
    #[arg(long, global = true, value_name = "MS")]
    pub deadline_ms: Option<u64>,

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
        /// Path to JSON decisions artifact (Vec<usize>) from a real run.
        ///
        /// When present, strict replay uses the artifact instead of the
        /// internally generated trace. Mutating the artifact exercises the
        /// typed strict violations (Exhausted, OutOfRange, Trailing).
        #[arg(long, value_name = "FILE")]
        decisions: Option<PathBuf>,
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
        /// Scaffold an ldgr-rt based SUT crate.
        #[arg(long)]
        sut: bool,
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
        /// Fault-solver engine for hypothesis ranking.
        ///
        /// `auto` routes by measured hard-clause crossover; `builtin` forces
        /// the pure-Rust hitting-set engine; `cadical` forces the MaxSAT
        /// engine (branch-and-bound fallback without the `solver-cadical`
        /// build feature).
        #[arg(long, value_enum, default_value_t = MaxSatEngineArg::Auto)]
        maxsat_engine: MaxSatEngineArg,
    },
    /// Print shell completion scripts to stdout.
    Completions {
        /// Target shell.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Ingest OTel NDJSON spans into a content-addressed journal.
    Ingest {
        /// Path to newline-delimited JSON OTel spans.
        #[arg(long)]
        input: PathBuf,
        /// Fidelity mode.
        #[arg(long, value_enum, default_value_t = FidelityArg::LineageOnly)]
        fidelity: FidelityArg,
    },
    /// Campaign certificate operations.
    Cert {
        #[command(subcommand)]
        cmd: CertCommand,
    },
    /// Failure-spec scenario operations.
    Faults {
        #[command(subcommand)]
        cmd: FaultsCommand,
    },
    /// Export exploration coverage (distinct roots / scenario space).
    Coverage {
        /// Path to NDJSON of {root_hex, run_index, finding} lines.
        #[arg(long)]
        input: PathBuf,
        /// Export format: lcov, sarif, or jacoco.
        #[arg(long, default_value = "lcov")]
        format: String,
    },
    /// Scaffold a consensus-family example crate (mini-Raft, Mini-KV, 2PC).
    Scaffold {
        /// Template: consensus|kv|2pc
        #[arg(long, default_value = "consensus")]
        template: String,
        /// Target directory for the scaffolded crate.
        #[arg(value_name = "DIR")]
        dir: PathBuf,
        /// Overwrite existing files.
        #[arg(long)]
        force: bool,
    },
    /// Hidden: run the ldgr-rt IPC engine server over a Unix socket.
    #[cfg(unix)]
    #[command(hide = true)]
    RtServer {
        /// Path to Unix socket for the SUT facade transport.
        #[arg(long)]
        socket: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum CertCommand {
    /// Verify a campaign certificate JSON file.
    Verify {
        /// Path to the certificate JSON file.
        path: PathBuf,
        /// Directory of the persisted journal for journal-anchored validation.
        #[arg(long)]
        journal: Option<PathBuf>,
        /// Selected operation: statement, journal, or inclusion-minimal.
        /// Journal and inclusion-minimal require --journal.
        #[arg(long, value_enum, default_value_t = CertVerifyOp::Statement)]
        op: CertVerifyOp,
    },
}

/// The three distinct certificate operations the CLI names explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum CertVerifyOp {
    /// Bounded statement validation without a journal.
    Statement,
    /// Journal-anchored observation and cut validation.
    Journal,
    /// Bounded inclusion-minimal fault-cut validation.
    InclusionMinimal,
}

#[derive(Debug, Subcommand)]
pub enum FaultsCommand {
    /// Compile a failure-spec scenario and list its faults.
    Compile {
        /// Path to the scenario DSL file.
        #[arg(long)]
        file: PathBuf,
    },
    /// Apply a failure-spec scenario to a seeded simulation run.
    Apply {
        /// Path to the scenario DSL file.
        #[arg(long)]
        file: PathBuf,
        /// 64-hex-character root seed for the run.
        #[arg(long)]
        seed_hex: String,
        /// Workload to run under the injected faults.
        #[arg(long, default_value = "kv")]
        workload: String,
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
                pct_mix: default_pct_mix(),
            },
            Self::Replay => Policy::Replay,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FidelityArg {
    #[value(name = "lineage-only")]
    LineageOnly,
    #[value(name = "bit-exact")]
    BitExact,
}

/// CLI selector for the LDFI fault-solver engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MaxSatEngineArg {
    Auto,
    Builtin,
    Cadical,
}

impl MaxSatEngineArg {
    pub fn to_solver_engine(self) -> ledger_explorer::SolverEngine {
        match self {
            Self::Auto => ledger_explorer::SolverEngine::Auto,
            Self::Builtin => ledger_explorer::SolverEngine::Builtin,
            Self::Cadical => ledger_explorer::SolverEngine::Cadical,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Builtin => "builtin",
            Self::Cadical => "cadical",
        }
    }
}

impl FidelityArg {
    pub fn to_fidelity(self) -> ledger_adapters::Fidelity {
        match self {
            Self::LineageOnly => ledger_adapters::Fidelity::LineageOnly,
            Self::BitExact => ledger_adapters::Fidelity::BitExact,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::LineageOnly => "lineage-only",
            Self::BitExact => "bit-exact",
        }
    }
}

impl std::fmt::Display for FidelityArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
