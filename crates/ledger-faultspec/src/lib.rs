#![deny(unsafe_code)]

//! Failure-spec DSL, compiler, and canonical scenario library.
//!
//! This crate is a pure spec seam (Apache-2.0) that parses a human-readable
//! failure DSL and compiles it into neutral fault types. The porting seam to
//! the simulation engine goes through `ledger-format` types only: each
//! scenario compiles to ordered `(EntryKind, FaultSpec)` entries plus a
//! string-targeted `FaultInjection` schedule, both accessible from
//! [`CompiledScenario`]. The `ledger-explorer` crate (AGPL) owns the bridge
//! `faultspec_bridge` that converts this neutral output into hash-targeted
//! engine faults and wires it into `RunConfig.fault_schedule()` via
//! deterministic BLAKE3 hashing. Same DSL yields same engine faults without a
//! live journal. The two fault types stay explicitly named at that seam: this
//! crate's string-targeted `FaultInjection` and the engine's hash-targeted
//! `ledger_sim::SimFault`. No AGPL type is imported by this crate.

mod compiler;
mod library;
mod parser;

pub use compiler::{
    ActorRegistry, CompiledScenario, FaultInjection, MAX_REGISTRY_ACTOR_ID, actor_id, compile,
    opaque_actor_id, scenario_registry,
};
pub use library::{ScenarioId, canonical_library, canonical_library_with_ids, dsl_for};
pub use parser::{Block, MAX_NAME_LEN, Scenario, ScenarioError, parse_scenario};
