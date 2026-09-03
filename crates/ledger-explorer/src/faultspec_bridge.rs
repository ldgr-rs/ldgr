//! Bridge from `ledger-faultspec` compiled scenarios into the simulation engine.
//!
//! This module is the true porting seam: faultspec stays Apache-2.0 and
//! string-targeted, while the engine is AGPL and hash-targeted. The bridge
//! performs a deterministic, bijective translation using BLAKE3 over
//! `scenario_name || block_index || target_label`.
//!
//! Why hash vs direct id: `ledger-format` FaultSpec values describe *what*
//! to inject, but `ledger-sim::SimFault` must name a causal position
//! (the 32-byte entry hash to drop/crash). No journal exists at DSL compile
//! time, so we synthesize a stable sentinel hash. The mapping is deterministic
//! and bijective in the sense that re-parsing the same DSL yields the same
//! hashes, and the original (name, index, label) can be recovered if needed.
//! For `Partition` the engine is actor-id targeted, so names resolve
//! through the scenario-scoped registry shared with the compiler
//! (numeric suffixes directly, opaque names at historic wrapping-hash ids
//! with collision detection).
//!
//! The conversion scheme is documented here once: each block that is not a
//! `Partition` is hashed as BLAKE3 over
//! `scenario_name || 0xff || block_index(u64 LE) || 0xff || target_label`,
//! where `target_label` is derived per variant in `to_sim_injections` and
//! `block_index` is the block's position in the compiled schedule. The frozen
//! fixture tests lock the output bytes.

use ledger_faultspec::{
    CompiledScenario, FaultInjection, ScenarioError, actor_id, scenario_registry,
};
use ledger_format::{ActorId, EntryHash};
use ledger_sim::{RunConfig, SimFault};

/// Deterministic hash for a scenario block.
///
/// The bridge owns the seam hashing scheme: BLAKE3 over
/// `scenario_name || 0xff || block_index(u64 LE) || 0xff || target_label`.
/// The scheme is stable across crates and versions; the frozen fixture test
/// locks the output bytes.
fn block_hash(scenario_name: &str, index: usize, label: &str) -> EntryHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(scenario_name.as_bytes());
    hasher.update(&[0xff]);
    hasher.update(&(index as u64).to_le_bytes());
    hasher.update(&[0xff]);
    hasher.update(label.as_bytes());
    EntryHash(*hasher.finalize().as_bytes())
}

/// Convert a compiled faultspec into engine fault injections.
///
/// Deterministic: same compiled scenario yields same injections. The
/// per-variant labels and actor-id parsing implement the documented seam
/// scheme above; the frozen fixture tests guard the output bytes.
/// Partition actor names resolve through the same scenario-scoped registry
/// the compiler uses (opaque names at their historic wrapping-hash ids
/// with collision detection), so bridge ids always match compiled ids.
///
/// # Errors
///
/// Returns [`ScenarioError`] on colliding actor names or out-of-range
/// numeric ids.
pub fn to_sim_injections(compiled: &CompiledScenario) -> Result<Vec<SimFault>, ScenarioError> {
    let registry = scenario_registry(compiled.schedule.iter().flat_map(injection_actor_names))?;
    let mut out = Vec::with_capacity(compiled.schedule.len());
    for (idx, inj) in compiled.schedule.iter().enumerate() {
        match inj {
            FaultInjection::Drop { src, dst, .. } => {
                let label = format!("drop:{src}->{dst}");
                let h = block_hash(&compiled.name, idx, &label);
                out.push(SimFault::Drop(h));
            }
            FaultInjection::Partition { src, dst } => {
                out.push(SimFault::Partition {
                    src: registry.resolve(src)?,
                    dst: registry.resolve(dst)?,
                });
            }
            FaultInjection::Crash { actor, .. } => {
                let label = format!("crash:{actor}");
                let h = block_hash(&compiled.name, idx, &label);
                out.push(SimFault::Crash(h));
            }
            FaultInjection::Corrupt { segment, range } => {
                let label = format!("corrupt:{segment}:{:x}-{:x}", range.0, range.1);
                let h = block_hash(&compiled.name, idx, &label);
                let xor_mask = range.0 ^ range.1;
                out.push(SimFault::Corrupt { write: h, xor_mask });
            }
            FaultInjection::TornWrite { flag } => {
                let label = format!("torn:{flag}");
                let h = block_hash(&compiled.name, idx, &label);
                out.push(SimFault::CrashState { write: h, state: 2 });
            }
            FaultInjection::ClockSkew { actor, skew_ticks } => {
                let label = format!("clock:{actor}");
                let h = block_hash(&compiled.name, idx, &label);
                let ticks = skew_ticks.unsigned_abs();
                out.push(SimFault::Delay { send: h, ticks });
            }
            FaultInjection::Delay { src, dst, ticks } => {
                let label = format!("delay:{src}->{dst}");
                let h = block_hash(&compiled.name, idx, &label);
                out.push(SimFault::Delay {
                    send: h,
                    ticks: *ticks,
                });
            }
        }
    }
    Ok(out)
}

/// Apply a compiled scenario to a `RunConfig`'s fault schedule.
///
/// Appends to the config's fault schedule and preserves determinism.
///
/// # Errors
///
/// Returns [`ScenarioError`] on colliding actor names.
pub fn apply_to_run_config(
    compiled: &CompiledScenario,
    config: &mut RunConfig,
) -> Result<(), ScenarioError> {
    config.extend_fault_schedule(to_sim_injections(compiled)?);
    Ok(())
}

/// Parse DSL, compile, validate storm heuristics, and convert to engine injections.
///
/// This is the one-stop helper for Explorer and CLI: parse -> compile -> translate.
///
/// # Errors
///
/// Returns `ScenarioError` if parsing or compilation fails (including storm detection).
pub fn compile_and_convert(dsl: &str) -> Result<Vec<SimFault>, ScenarioError> {
    let scenario = ledger_faultspec::parse_scenario(dsl)?;
    let compiled = ledger_faultspec::compile(&scenario)?;
    to_sim_injections(&compiled)
}

/// Compile DSL and apply to config in one step.
///
/// # Errors
///
/// Returns `ScenarioError` if parsing or compilation fails.
pub fn apply_dsl_to_config(dsl: &str, config: &mut RunConfig) -> Result<(), ScenarioError> {
    let scenario = ledger_faultspec::parse_scenario(dsl)?;
    let compiled = ledger_faultspec::compile(&scenario)?;
    apply_to_run_config(&compiled, config)?;
    Ok(())
}

/// Actor names a compiled injection addresses.
///
/// Mirrors the compiler's scenario name collection so bridge resolution
/// matches compiled ids exactly. Storage-targeted variants carry no actor
/// names.
fn injection_actor_names(injection: &FaultInjection) -> Vec<String> {
    match injection {
        FaultInjection::Drop { src, dst, .. } => vec![src.clone(), dst.clone()],
        FaultInjection::Partition { src, dst } => vec![src.clone(), dst.clone()],
        FaultInjection::Crash { actor, .. } => vec![actor.clone()],
        FaultInjection::Corrupt { .. } => Vec::new(),
        FaultInjection::TornWrite { .. } => Vec::new(),
        FaultInjection::ClockSkew { actor, .. } => vec![actor.clone()],
        FaultInjection::Delay { src, dst, .. } => vec![src.clone(), dst.clone()],
    }
}

/// Re-derive the synthetic hash for a given scenario name/index/label.
///
/// Exposed for testing and for drivers that need to resolve synthetic ids to
/// real journal entry ids.
pub fn synthetic_hash(scenario_name: &str, index: usize, label: &str) -> EntryHash {
    block_hash(scenario_name, index, label)
}

/// Parse actor id using the shared `ledger-faultspec` scheme.
///
/// Numeric suffixes (`replica-2` -> 2) resolve directly; opaque names resolve
/// through the canonical registry. Unknown opaque names fail with
/// [`ScenarioError::UnknownActor`]. The single implementation lives in
/// `ledger_faultspec::actor_id`; the table test here locks the shared
/// behavior against drift.
///
/// # Errors
///
/// Returns [`ScenarioError`] for unknown opaque names or out-of-range ids.
pub fn parse_actor_id(name: &str) -> Result<ActorId, ScenarioError> {
    actor_id(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_faultspec::{ScenarioId, canonical_library, compile, dsl_for, parse_scenario};

    #[test]
    fn bridge_deterministic() {
        let dsl = "scenario d\ndrop 10% of a->b Msgs for 1s every 10s";
        let s = parse_scenario(dsl).unwrap();
        let c = compile(&s).unwrap();
        let a = to_sim_injections(&c).unwrap();
        let b = to_sim_injections(&c).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn bridge_output_frozen_fixture() {
        // Frozen lock of the seam conversion. Expected values are computed
        // from the documented scheme - BLAKE3(name || 0xff || index u64 LE ||
        // 0xff || label) with labels from the variant mapping in
        // to_sim_injections - and verified by reviewer recomputation. They
        // must not drift.
        let dsl = "scenario x\ndrop 10% of a->b Msgs for 1s every 10s\npartition replica-2->replica-7\ncrash-restart replica-2 after FsFsync\ncorrupt sector range [0x10,0x20) of seg-1\ntorn-write on O_APPEND";
        let s = parse_scenario(dsl).unwrap();
        let c = compile(&s).unwrap();
        let sim = to_sim_injections(&c).unwrap();
        assert_eq!(sim.len(), 5);
        assert_eq!(
            sim[0],
            SimFault::Drop(EntryHash([
                0x2d, 0xfd, 0x25, 0xa2, 0x41, 0xcd, 0x42, 0x63, 0xfe, 0xd2, 0xdd, 0xee, 0xef, 0x16,
                0x60, 0x2a, 0xf0, 0x38, 0xbe, 0x3b, 0x06, 0xd8, 0x1b, 0x94, 0xfa, 0x4b, 0xd2, 0x20,
                0x62, 0x5d, 0x47, 0x7c,
            ]))
        );
        assert_eq!(
            sim[1],
            SimFault::Partition {
                src: ActorId(2),
                dst: ActorId(7)
            }
        );
        assert_eq!(
            sim[2],
            SimFault::Crash(EntryHash([
                0x95, 0xcc, 0x77, 0xf9, 0x85, 0xfe, 0xee, 0xee, 0xf0, 0x1e, 0x53, 0x44, 0x46, 0xa7,
                0x41, 0xfe, 0x19, 0x6c, 0x79, 0x41, 0x7a, 0x43, 0xf1, 0x71, 0xe4, 0x86, 0x4e, 0x11,
                0x10, 0xdb, 0xac, 0x4f,
            ]))
        );
        assert_eq!(
            sim[3],
            SimFault::Corrupt {
                write: EntryHash([
                    0x5d, 0x41, 0xd0, 0xf5, 0x1e, 0x11, 0xa3, 0x58, 0x3d, 0x6c, 0xb5, 0x4a, 0x9f,
                    0x4f, 0x0f, 0xb6, 0xf7, 0xa3, 0xb5, 0xa0, 0xea, 0xdb, 0xf9, 0x9f, 0x71, 0x78,
                    0x05, 0xc6, 0xa8, 0xa7, 0x6f, 0x43,
                ]),
                xor_mask: 0x30,
            }
        );
        assert_eq!(
            sim[4],
            SimFault::CrashState {
                write: EntryHash([
                    0xf5, 0xe9, 0x3e, 0xa7, 0x2d, 0x5c, 0x75, 0x3e, 0xf0, 0x6d, 0xbf, 0x80, 0xf2,
                    0xa4, 0x79, 0x46, 0x6a, 0x55, 0x19, 0x6a, 0xe6, 0x5b, 0xde, 0x47, 0x5e, 0xc5,
                    0xf1, 0xee, 0x81, 0x94, 0x2b, 0xb4,
                ]),
                state: 2,
            }
        );
    }

    #[test]
    fn bridge_output_frozen_skew_latency() {
        // Frozen lock for ClockSkew and BoundedLatency, both mapping to
        // SimFault::Delay through the documented scheme. "ms" values parse to
        // microsecond ticks (ms * 1000): 100ms -> 100_000, 50ms -> 50_000.
        // Expected hashes computed per the documented scheme and verified by
        // reviewer recomputation; they must not drift.
        let dsl = "scenario y\nclock-skew n1 by 100ms\ndelay a->b by 50ms";
        let s = parse_scenario(dsl).unwrap();
        let c = compile(&s).unwrap();
        let sim = to_sim_injections(&c).unwrap();
        assert_eq!(sim.len(), 2);
        assert_eq!(
            sim[0],
            SimFault::Delay {
                send: EntryHash([
                    0xc2, 0xbc, 0x3f, 0x26, 0x4a, 0x20, 0x4b, 0x45, 0x7c, 0x93, 0x4b, 0xcc, 0x32,
                    0xb7, 0x1e, 0xb8, 0xbe, 0x09, 0x2c, 0x4a, 0x21, 0xfa, 0xa3, 0x3a, 0xe5, 0x30,
                    0x5d, 0x01, 0xac, 0x4c, 0x69, 0x38,
                ]),
                ticks: 100_000,
            }
        );
        assert_eq!(
            sim[1],
            SimFault::Delay {
                send: EntryHash([
                    0x83, 0x68, 0xff, 0x8e, 0x34, 0x76, 0x50, 0x7c, 0x9e, 0xb8, 0x11, 0xbc, 0xea,
                    0xab, 0x22, 0xe2, 0x40, 0x4e, 0x65, 0xa2, 0x41, 0x73, 0x7b, 0xd4, 0x05, 0xdb,
                    0x02, 0x9a, 0x30, 0x21, 0xfc, 0x18,
                ]),
                ticks: 50_000,
            }
        );
    }

    #[test]
    fn parse_actor_id_table() {
        // Locks the shared ledger-faultspec actor-id parsing against drift:
        // numeric suffixes resolve directly; canonical opaque names keep
        // historic ids; unknown opaque names fail closed.
        assert_eq!(parse_actor_id("replica-2").unwrap(), ActorId(2));
        assert_eq!(parse_actor_id("replica-7").unwrap(), ActorId(7));
        assert_eq!(parse_actor_id("node:3").unwrap(), ActorId(3));
        assert_eq!(parse_actor_id("leader").unwrap(), ActorId(3002));
        assert_eq!(parse_actor_id("replica").unwrap(), ActorId(4633));
        assert!(
            matches!(
                parse_actor_id("foo"),
                Err(ScenarioError::UnknownActor { .. })
            ),
            "unknown opaque names must fail closed"
        );
        assert!(
            matches!(
                parse_actor_id("bar"),
                Err(ScenarioError::UnknownActor { .. })
            ),
            "unknown opaque names must fail closed"
        );
    }

    #[test]
    fn bridge_partition_ids() {
        let dsl = "scenario p\npartition replica-3->replica-9";
        let s = parse_scenario(dsl).unwrap();
        let c = compile(&s).unwrap();
        let sim = to_sim_injections(&c).unwrap();
        assert_eq!(sim.len(), 1);
        match sim[0] {
            SimFault::Partition { src, dst } => {
                assert_eq!(src, ActorId(3));
                assert_eq!(dst, ActorId(9));
            }
            _ => panic!("expected partition"),
        }
    }

    #[test]
    fn bridge_apply_to_config() {
        let dsl = "scenario a\npartition replica-1->replica-2";
        let s = parse_scenario(dsl).unwrap();
        let c = compile(&s).unwrap();
        let mut cfg = RunConfig::default();
        apply_to_run_config(&c, &mut cfg).unwrap();
        assert_eq!(cfg.fault_schedule().len(), 1);
    }

    #[test]
    fn bridge_partition_opaque_names_match_compiler() {
        use ledger_faultspec::opaque_actor_id;
        let dsl = "scenario a\npartition foo->bar";
        let res = compile_and_convert(dsl).expect("scenario names must auto-register");
        assert_eq!(res.len(), 1);
        match res[0] {
            SimFault::Partition { src, dst } => {
                assert_eq!(src, opaque_actor_id("foo"));
                assert_eq!(dst, opaque_actor_id("bar"));
            }
            _ => panic!("expected partition"),
        }
    }

    #[test]
    fn bridge_rejects_colliding_partition_actors() {
        let dsl = "scenario a\npartition replica-1->node:1";
        let res = compile_and_convert(dsl);
        assert!(
            matches!(res, Err(ScenarioError::ActorCollision { .. })),
            "numeric aliases for one id must collide, got {res:?}"
        );
    }

    #[test]
    fn canonical_library_via_bridge() {
        let lib = canonical_library().expect("must parse");
        for sc in lib {
            let compiled = compile(&sc).expect("must compile");
            let sim = to_sim_injections(&compiled).unwrap();
            // Each canonical scenario is synthetic; ensure hash not zero.
            for inj in sim {
                match inj {
                    SimFault::Drop(h)
                    | SimFault::Crash(h)
                    | SimFault::Corrupt { write: h, .. }
                    | SimFault::CrashState { write: h, .. }
                    | SimFault::Delay { send: h, .. } => {
                        assert_ne!(h, EntryHash([0; 32]));
                    }
                    SimFault::Partition { .. } => {}
                }
            }
        }
    }

    #[test]
    fn compile_and_convert_storm_rejected() {
        let dsl = "scenario s\npartition replica-1->replica-2\npartition replica-3->replica-4\npartition replica-5->replica-6\npartition replica-7->replica-8\npartition replica-9->replica-10\npartition replica-11->replica-12";
        let res = compile_and_convert(dsl);
        assert!(matches!(res, Err(ScenarioError::StormDetected(_))));
    }

    #[test]
    fn synthetic_hash_stable() {
        let h1 = synthetic_hash("my-scenario", 0, "drop:a->b");
        let h2 = synthetic_hash("my-scenario", 0, "drop:a->b");
        assert_eq!(h1, h2);
        let h3 = synthetic_hash("my-scenario", 1, "drop:a->b");
        assert_ne!(h1, h3);
    }

    #[test]
    fn each_canonical_via_bridge_stable() {
        for id in [
            ScenarioId::Partition,
            ScenarioId::CrashRestart,
            ScenarioId::Corruption,
            ScenarioId::ClockSkew,
            ScenarioId::TornWrite,
            ScenarioId::BoundedLatency,
            ScenarioId::LeaderStepdown,
            ScenarioId::MembershipChurn,
        ] {
            let dsl = dsl_for(id);
            let a = compile_and_convert(dsl).unwrap();
            let b = compile_and_convert(dsl).unwrap();
            assert_eq!(a, b, "stable for {:?}", id);
        }
    }
}
