// ledger-lint:allow (host application; fault scenarios load DSL files from disk)
//! `ledger faults` command: compile and apply failure-spec scenarios.
//!
//! `compile` parses and compiles a DSL file via `ledger-faultspec` and lists
//! each fault with its kind, target, and cost. The cost is a deterministic
//! magnitude estimate derived from the block parameters (percent for drops,
//! ticks for delays and clock skew, byte span for corruption, 1 otherwise);
//! exact per-event costs need a live journal and stay the LDFI solver's job.
//!
//! `apply` bridges the compiled scenario onto a seeded [`RunConfig`] through
//! the explorer's `faultspec_bridge`, runs the reference mini-KV workload,
//! and prints the journal root plus the applied-fault count.

use std::path::Path;

use ledger_explorer::faultspec_bridge::apply_dsl_to_config;
use ledger_explorer::search::Workload;
use ledger_faultspec::{
    CompiledScenario, FaultInjection as CompiledFault, ScenarioError, compile, parse_scenario,
};
use ledger_format::{EntryHash, EntryKind};
use ledger_sim::{RunConfig, RuntimeError, Simulation};

/// Errors from the `faults` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum FaultsError {
    /// The scenario file could not be read.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Parsing or compilation failed; includes storm detection.
    #[error("{0}")]
    Scenario(#[from] ScenarioError),
    /// The seed hex is not exactly 64 hex characters.
    #[error("invalid --seed-hex {0}: must be exactly 64 hex characters")]
    InvalidSeedHex(String),
    /// The requested workload has no implementation here.
    #[error("unknown workload {0}: supported workloads: kv")]
    UnknownWorkload(String),
    /// The simulation run failed.
    #[error("simulation error: {0}")]
    Sim(#[from] RuntimeError),
}

/// Stable lowercase name for an entry kind used in fault listings.
fn kind_name(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Send => "send",
        EntryKind::FsWrite => "fs-write",
        EntryKind::Recv => "recv",
        EntryKind::FsRead => "fs-read",
        EntryKind::Outcome => "outcome",
        _ => "other",
    }
}

/// Human-readable target label for one compiled block.
fn target_label(fault: &CompiledFault) -> String {
    match fault {
        CompiledFault::Drop { src, dst, .. }
        | CompiledFault::Partition { src, dst }
        | CompiledFault::Delay { src, dst, .. } => format!("{src}->{dst}"),
        CompiledFault::Crash { actor, .. } | CompiledFault::ClockSkew { actor, .. } => {
            actor.clone()
        }
        CompiledFault::Corrupt { segment, range } => {
            format!("{segment}:{:x}-{:x}", range.0, range.1)
        }
        CompiledFault::TornWrite { flag } => flag.clone(),
    }
}

/// Deterministic magnitude estimate for one compiled block.
fn fault_cost(fault: &CompiledFault) -> u64 {
    match fault {
        CompiledFault::Drop { percent, .. } => u64::from(*percent),
        CompiledFault::Corrupt { range, .. } => range.1 - range.0,
        CompiledFault::ClockSkew { skew_ticks, .. } => skew_ticks.unsigned_abs(),
        CompiledFault::Delay { ticks, .. } => *ticks,
        CompiledFault::Partition { .. }
        | CompiledFault::Crash { .. }
        | CompiledFault::TornWrite { .. } => 1,
    }
}

/// Parses and compiles a DSL file without touching simulation state.
fn load_compiled(path: &Path) -> Result<CompiledScenario, FaultsError> {
    let dsl = std::fs::read_to_string(path)?;
    let scenario = parse_scenario(&dsl)?;
    Ok(compile(&scenario)?)
}

/// One row of the compile listing: index, kind, target, and cost.
struct FaultRow {
    index: usize,
    kind: &'static str,
    target: String,
    cost: u64,
}

/// Zips entry kinds with schedule injections into listing rows.
///
/// The compiler emits one fault entry and one injection per block, so the
/// zip never truncates; it only guards against future shape drift.
fn fault_rows(compiled: &CompiledScenario) -> Vec<FaultRow> {
    compiled
        .faults
        .iter()
        .zip(compiled.schedule.iter())
        .enumerate()
        .map(|(index, (kind, injection))| FaultRow {
            index,
            kind: kind_name(kind.0),
            target: target_label(injection),
            cost: fault_cost(injection),
        })
        .collect()
}

/// Compiles the scenario at `path` and renders the fault listing.
///
/// Returns human-readable text, or a JSON object when `json` is set.
///
/// # Errors
/// Returns [`FaultsError`] when the file cannot be read or the DSL fails to
/// parse or compile, including [`ScenarioError::StormDetected`] rejections.
pub fn compile_scenario(path: &Path, json: bool) -> Result<String, FaultsError> {
    let compiled = load_compiled(path)?;
    let rows = fault_rows(&compiled);

    if json {
        let value = serde_json::json!({
            "scenario": compiled.name,
            "fault_count": rows.len(),
            "faults": rows.iter().map(|row| serde_json::json!({
                "index": row.index,
                "kind": row.kind,
                "target": row.target,
                "cost": row.cost
            })).collect::<Vec<_>>()
        });
        Ok(value.to_string())
    } else {
        let mut out = format!("scenario '{}': {} fault(s)\n", compiled.name, rows.len());
        for row in &rows {
            out.push_str(&format!(
                "  [{}] kind={} target={} cost={}\n",
                row.index, row.kind, row.target, row.cost
            ));
        }
        // Trim the trailing newline for consistent single-string output.
        if out.ends_with('\n') {
            out.pop();
        }
        Ok(out)
    }
}

/// Parses a 64-character hex string into a 32-byte seed.
fn parse_seed_hex(seed_hex: &str) -> Result<EntryHash, FaultsError> {
    let bytes = seed_hex.as_bytes();
    if bytes.len() != 64 || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return Err(FaultsError::InvalidSeedHex(seed_hex.to_string()));
    }
    let mut seed = [0u8; 32];
    for (byte, pair) in seed.iter_mut().zip(bytes.chunks_exact(2)) {
        // Digits passed validation above; 0 keeps the conversion total.
        let hi = (pair[0] as char).to_digit(16).unwrap_or(0) as u8;
        let lo = (pair[1] as char).to_digit(16).unwrap_or(0) as u8;
        *byte = (hi << 4) | lo;
    }
    Ok(EntryHash(seed))
}

/// Compiles the scenario, applies it to a seeded run config, runs the
/// selected workload, and renders the result.
///
/// When `json` is true, output is `{"journal_root_hex":"...","applied_faults":N}`.
/// Otherwise a human-readable summary is returned.
///
/// # Errors
/// Returns [`FaultsError`] on read, parse, compile (including storm
/// detection), seed-hex, workload, or simulation failures.
pub fn apply_scenario(
    path: &Path,
    seed_hex: &str,
    workload_name: &str,
    json: bool,
) -> Result<String, FaultsError> {
    if workload_name != "kv" {
        return Err(FaultsError::UnknownWorkload(workload_name.to_string()));
    }
    let dsl = std::fs::read_to_string(path)?;
    let seed = parse_seed_hex(seed_hex)?;

    let mut config = RunConfig::builder().seed(seed).build();
    apply_dsl_to_config(&dsl, &mut config)?;

    let workload = crate::DefaultMiniKv;
    let run = Simulation::new(config, workload.programs()).run()?;

    let root_hex = ledger_format::hash_to_hex(&run.journal.root_hash());
    let applied = run.applied_faults.len();
    if json {
        let value = serde_json::json!({
            "journal_root_hex": root_hex,
            "applied_faults": applied
        });
        Ok(value.to_string())
    } else {
        Ok(format!(
            "journal root: {root_hex}\napplied faults: {applied}"
        ))
    }
}
