#![deny(unsafe_code)]

//! Failure-spec DSL, compiler, and canonical scenario library.
//! Pure spec seam (Apache-2.0): DSL compiles to neutral fault types over
//! `ledger-format` only. The `ledger-explorer` bridge converts them to
//! engine faults. No AGPL import.

mod compiler;
mod library;
mod parser;

pub use compiler::{
    ActorRegistry, CompiledScenario, FaultInjection, MAX_REGISTRY_ACTOR_ID, actor_id, compile,
    opaque_actor_id, scenario_registry,
};
pub use library::{ScenarioId, canonical_library, canonical_library_with_ids, dsl_for};
pub use parser::{Block, MAX_NAME_LEN, Scenario, ScenarioError, parse_scenario};
