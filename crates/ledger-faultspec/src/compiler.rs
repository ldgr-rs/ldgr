//! Compiler from Scenario to ordered fault entries and schedule.

use std::collections::{HashMap, HashSet};

use ledger_format::{ActorId, EntryKind, FaultSpec};

use crate::parser::{Block, Scenario, ScenarioError};

/// A scheduled fault injection derived from a scenario block.
///
/// String-targeted (spec-shaped). This is the neutral representation owned by
/// the Apache-licensed spec crate. The `ledger-explorer` bridge (AGPL) converts
/// it into hash-targeted engine faults via deterministic BLAKE3 hashing at the
/// porting seam. Keeping the spec string-targeted preserves readability and
/// avoids coupling the DSL to entry IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaultInjection {
    Drop {
        src: String,
        dst: String,
        percent: u8,
        duration_ticks: u64,
        period_ticks: u64,
    },
    Partition {
        src: String,
        dst: String,
    },
    Crash {
        actor: String,
        after: String,
    },
    Corrupt {
        segment: String,
        range: (u64, u64),
    },
    TornWrite {
        flag: String,
    },
    ClockSkew {
        actor: String,
        skew_ticks: i64,
    },
    Delay {
        src: String,
        dst: String,
        ticks: u64,
    },
}

/// Compiled scenario with validated faults and schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledScenario {
    pub name: String,
    pub faults: Vec<(EntryKind, FaultSpec)>,
    pub schedule: Vec<FaultInjection>,
}

/// Compile a scenario, validating and producing ordered fault entries.
///
/// Validation includes percent bounds, range ordering, duplicate-target
/// detection, and storm heuristics (>5 total faults or >3 faults on same actor).
pub fn compile(scenario: &Scenario) -> Result<CompiledScenario, ScenarioError> {
    // Storm heuristic: too many total faults.
    if scenario.blocks.len() > 5 {
        return Err(ScenarioError::StormDetected(format!(
            "too many faults {} > 5",
            scenario.blocks.len()
        )));
    }

    // Storm heuristic: per-actor concentration.
    let mut actor_counts: HashMap<String, usize> = HashMap::new();
    for block in &scenario.blocks {
        for actor in actors_for_block(block) {
            let counter = actor_counts.entry(actor.clone()).or_insert(0);
            *counter += 1;
            if *counter > 3 {
                return Err(ScenarioError::StormDetected(format!(
                    "actor {actor} appears in >3 faults"
                )));
            }
        }
    }

    let mut faults = Vec::new();
    let mut schedule = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    // Scenario-scoped actor registry: every actor name the scenario
    // mentions resolves deterministically. Numeric suffixes resolve
    // directly; opaque names fall back to the historic wrapping hash with
    // collision detection, so ad-hoc topologies (a->b) keep working while
    // silent id merges fail closed.
    let registry = scenario_registry(scenario.blocks.iter().flat_map(actor_names_for_block))?;
    // Actor id owners across Partition blocks: distinct opaque names must not
    // share one id. Numeric aliases for the same id under different spellings
    // (replica-1 vs node:1) are collisions too.
    let mut id_owners: HashMap<ActorId, String> = HashMap::new();

    for block in &scenario.blocks {
        let key = target_key(block);
        if !seen.insert(key.clone()) {
            return Err(ScenarioError::DuplicateTarget(key));
        }
        let (fault_entries, injection) = compile_block(block, &registry)?;
        check_partition_collision(&injection, &registry, &mut id_owners)?;
        faults.extend(fault_entries);
        schedule.push(injection);
    }

    Ok(CompiledScenario {
        name: scenario.name.clone(),
        faults,
        schedule,
    })
}

fn actors_for_block(block: &Block) -> Vec<String> {
    match block {
        Block::Drop { src, dst, .. } => vec![src.clone(), dst.clone()],
        Block::CrashRestart { actor, .. } => vec![actor.clone()],
        Block::Corrupt { segment, .. } => vec![segment.clone()],
        Block::TornWrite { flag } => vec![flag.clone()],
        Block::Partition { src, dst } => vec![src.clone(), dst.clone()],
        Block::ClockSkew { actor, .. } => vec![actor.clone()],
        Block::BoundedLatency { src, dst, .. } => vec![src.clone(), dst.clone()],
    }
}

/// Actor names a block addresses as simulated actors.
///
/// `Corrupt` segments and `TornWrite` flags name storage objects, not
/// actors, so they stay out of the actor registry (they still count toward
/// the per-actor storm heuristic via [`actors_for_block`]).
fn actor_names_for_block(block: &Block) -> Vec<String> {
    match block {
        Block::Drop { src, dst, .. } => vec![src.clone(), dst.clone()],
        Block::CrashRestart { actor, .. } => vec![actor.clone()],
        Block::Corrupt { .. } => Vec::new(),
        Block::TornWrite { .. } => Vec::new(),
        Block::Partition { src, dst } => vec![src.clone(), dst.clone()],
        Block::ClockSkew { actor, .. } => vec![actor.clone()],
        Block::BoundedLatency { src, dst, .. } => vec![src.clone(), dst.clone()],
    }
}

/// Historic deterministic id for opaque actor names.
///
/// Restored wrapping multiply (`h % 10000 + 1`, never 0) so ad-hoc
/// topologies keep byte-stable mappings across refactors. Collisions
/// between distinct names are detected at registration, not silently
/// merged.
pub fn opaque_actor_id(name: &str) -> ActorId {
    let mut h: u32 = 0;
    for b in name.bytes() {
        h = h.wrapping_mul(31).wrapping_add(u32::from(b));
    }
    if h == 0 {
        ActorId(1)
    } else {
        ActorId(h % 10000 + 1)
    }
}

/// Build the scenario-scoped registry for `compile`.
///
/// Starts from [`ActorRegistry::with_known`] and auto-registers every
/// opaque name the scenario mentions at its [`opaque_actor_id`]. Numeric
/// suffixes need no registration. Distinct names that map to one id fail
/// with [`ScenarioError::ActorCollision`].
pub fn scenario_registry(
    names: impl IntoIterator<Item = String>,
) -> Result<ActorRegistry, ScenarioError> {
    let mut registry = ActorRegistry::with_known();
    for name in names {
        if name.is_empty() || name.len() > crate::parser::MAX_NAME_LEN {
            return Err(ScenarioError::InvalidSyntax(format!(
                "actor name {name:?} must be 1..={} bytes",
                crate::parser::MAX_NAME_LEN
            )));
        }
        if numeric_suffix(&name).is_some() {
            continue;
        }
        if registry.by_name.contains_key(&name) {
            continue;
        }
        let id = opaque_actor_id(&name);
        registry.register(&name, id)?;
    }
    Ok(registry)
}

/// Trailing numeric suffix after `-` or `:` (`replica-2` -> 2).
fn numeric_suffix(name: &str) -> Option<u32> {
    if let Some(pos) = name.rfind('-')
        && let Ok(n) = name[pos + 1..].parse::<u32>()
    {
        return Some(n);
    }
    if let Some(pos) = name.rfind(':')
        && let Ok(n) = name[pos + 1..].parse::<u32>()
    {
        return Some(n);
    }
    None
}

fn compile_block(
    block: &Block,
    registry: &ActorRegistry,
) -> Result<(Vec<(EntryKind, FaultSpec)>, FaultInjection), ScenarioError> {
    match block {
        Block::Drop {
            percent,
            src,
            dst,
            duration_ticks,
            period_ticks,
        } => {
            if *percent > 100 {
                return Err(ScenarioError::InvalidPercent(*percent));
            }
            let faults = vec![(EntryKind::Send, FaultSpec::Drop)];
            let inj = FaultInjection::Drop {
                src: src.clone(),
                dst: dst.clone(),
                percent: *percent,
                duration_ticks: *duration_ticks,
                period_ticks: *period_ticks,
            };
            Ok((faults, inj))
        }
        Block::CrashRestart { actor, after } => {
            if actor.is_empty() || after.is_empty() {
                return Err(ScenarioError::InvalidSyntax(format!(
                    "crash-restart {actor} after {after}"
                )));
            }
            let faults = vec![(EntryKind::FsWrite, FaultSpec::Crash)];
            let inj = FaultInjection::Crash {
                actor: actor.clone(),
                after: after.clone(),
            };
            Ok((faults, inj))
        }
        Block::Corrupt { range, segment } => {
            if range.0 >= range.1 {
                return Err(ScenarioError::InvalidRange {
                    start: range.0,
                    end: range.1,
                });
            }
            let faults = vec![(EntryKind::FsWrite, FaultSpec::Corrupt)];
            let inj = FaultInjection::Corrupt {
                segment: segment.clone(),
                range: *range,
            };
            Ok((faults, inj))
        }
        Block::TornWrite { flag } => {
            if flag.is_empty() {
                return Err(ScenarioError::InvalidSyntax(
                    "torn-write flag empty".to_string(),
                ));
            }
            let faults = vec![(EntryKind::FsWrite, FaultSpec::CrashState(2))];
            let inj = FaultInjection::TornWrite { flag: flag.clone() };
            Ok((faults, inj))
        }
        Block::Partition { src, dst } => {
            let src_id = registry.resolve(src)?;
            let dst_id = registry.resolve(dst)?;
            if src_id == dst_id && src != dst {
                return Err(ScenarioError::ActorCollision {
                    first: src.clone(),
                    second: dst.clone(),
                    id: src_id,
                });
            }
            let faults = vec![(
                EntryKind::Send,
                FaultSpec::Partition {
                    src: src_id,
                    dst: dst_id,
                },
            )];
            let inj = FaultInjection::Partition {
                src: src.clone(),
                dst: dst.clone(),
            };
            Ok((faults, inj))
        }
        Block::ClockSkew { actor, skew_ticks } => {
            // A negative skew (clock set back) cannot map to the positive
            // `Delay` fault with equal magnitude: that would silently invert
            // the direction. The fault surface only supports positive ticks,
            // so negative skew is a typed compile error.
            if *skew_ticks < 0 {
                return Err(ScenarioError::InvalidSyntax(format!(
                    "clock-skew {actor}: negative skew {skew_ticks} cannot map to a Delay fault"
                )));
            }
            let ticks = u64::try_from(*skew_ticks).map_err(|_| {
                ScenarioError::InvalidSyntax(format!(
                    "clock-skew {actor}: skew {skew_ticks} is not representable"
                ))
            })?;
            let faults = vec![(EntryKind::TimerFire, FaultSpec::Delay { ticks })];
            let inj = FaultInjection::ClockSkew {
                actor: actor.clone(),
                skew_ticks: *skew_ticks,
            };
            Ok((faults, inj))
        }
        Block::BoundedLatency {
            src,
            dst,
            delay_ticks,
        } => {
            let faults = vec![(
                EntryKind::Send,
                FaultSpec::Delay {
                    ticks: *delay_ticks,
                },
            )];
            let inj = FaultInjection::Delay {
                src: src.clone(),
                dst: dst.clone(),
                ticks: *delay_ticks,
            };
            Ok((faults, inj))
        }
    }
}

/// Record Partition actor ids and reject cross-block id reuse across
/// distinct names.
fn check_partition_collision(
    injection: &FaultInjection,
    registry: &ActorRegistry,
    owners: &mut HashMap<ActorId, String>,
) -> Result<(), ScenarioError> {
    let FaultInjection::Partition { src, dst } = injection else {
        return Ok(());
    };
    for name in [src, dst] {
        // Names resolve through the scenario registry built at compile;
        // numeric and auto-registered opaque names both resolve here.
        let id = registry.resolve(name)?;
        if let Some(owner) = owners.get(&id) {
            if owner != name {
                return Err(ScenarioError::ActorCollision {
                    first: owner.clone(),
                    second: name.clone(),
                    id,
                });
            }
        } else {
            owners.insert(id, name.clone());
        }
    }
    Ok(())
}

fn target_key(block: &Block) -> String {
    match block {
        Block::Drop { src, dst, .. } => format!("drop:{src}->{dst}"),
        Block::CrashRestart { actor, .. } => format!("crash:{actor}"),
        Block::Corrupt { segment, .. } => format!("corrupt:{segment}"),
        Block::TornWrite { flag } => format!("torn:{flag}"),
        Block::Partition { src, dst } => format!("partition:{src}->{dst}"),
        Block::ClockSkew { actor, .. } => format!("clock:{actor}"),
        Block::BoundedLatency { src, dst, .. } => format!("latency:{src}->{dst}"),
    }
}

/// Maximum actor id accepted by the registry.
///
/// Matches the IPC wire cap so compiled partitions stay routable; larger
/// numeric suffixes are rejected with [`ScenarioError::InvalidActorId`].
/// Zero is the default first actor and stays valid.
pub const MAX_REGISTRY_ACTOR_ID: u32 = 1 << 20;

/// Deterministic actor registry for opaque names.
///
/// Numeric suffixes (`replica-2`, `node:3`, `replica-0`) resolve directly
/// without registration. Opaque names resolve through the scenario-scoped
/// registry built by [`scenario_registry`], which auto-registers every
/// name the scenario mentions at its [`opaque_actor_id`]; direct
/// [`ActorRegistry::resolve`] on an unregistered opaque name fails with
/// [`ScenarioError::UnknownActor`]. Registration rejects id reuse across
/// distinct names with [`ScenarioError::ActorCollision`].
#[derive(Debug, Clone, Default)]
pub struct ActorRegistry {
    by_name: std::collections::BTreeMap<String, ActorId>,
    by_id: std::collections::BTreeMap<ActorId, String>,
}

impl ActorRegistry {
    /// Empty registry with no opaque names.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registry preloaded with the canonical opaque names at their historic
    /// ids (`leader` -> 3002, `replica` -> 4633) so existing canonical
    /// scenarios keep identical mappings.
    pub fn with_known() -> Self {
        let mut registry = Self::new();
        // Historic wrapping-hash values, preserved so canonical fixtures do
        // not drift. Registration cannot collide here by construction.
        let _ = registry.register("leader", ActorId(3002));
        let _ = registry.register("replica", ActorId(4633));
        registry
    }

    /// Register `name` at `id`.
    ///
    /// Rejects empty or overlong names and over-cap ids, and id reuse
    /// across distinct names. Zero is a valid actor (the default first
    /// actor; sim and the IPC wire both accept it).
    pub fn register(&mut self, name: &str, id: ActorId) -> Result<(), ScenarioError> {
        if name.is_empty() || name.len() > crate::parser::MAX_NAME_LEN {
            return Err(ScenarioError::InvalidSyntax(format!(
                "actor name {name:?} must be 1..={} bytes",
                crate::parser::MAX_NAME_LEN
            )));
        }
        if id.0 > MAX_REGISTRY_ACTOR_ID {
            return Err(ScenarioError::InvalidActorId {
                name: name.to_string(),
                id,
                max: MAX_REGISTRY_ACTOR_ID,
            });
        }
        if let Some(known) = self.by_name.get(name) {
            if *known == id {
                return Ok(());
            }
            return Err(ScenarioError::ActorCollision {
                first: name.to_string(),
                second: name.to_string(),
                id,
            });
        }
        if let Some(owner) = self.by_id.get(&id) {
            return Err(ScenarioError::ActorCollision {
                first: owner.clone(),
                second: name.to_string(),
                id,
            });
        }
        self.by_name.insert(name.to_string(), id);
        self.by_id.insert(id, name.to_string());
        Ok(())
    }

    /// Resolve `name` to an actor id.
    ///
    /// A trailing numeric suffix after `-` or `:` resolves directly
    /// (`replica-2` -> 2, `node:3` -> 3, `replica-0` -> 0) within
    /// `0..=MAX`. Opaque names resolve through registration (see
    /// [`scenario_registry` for scenario-scoped auto-registration);
    /// unknown opaque names fail with [`ScenarioError::UnknownActor`].
    pub fn resolve(&self, name: &str) -> Result<ActorId, ScenarioError> {
        if name.is_empty() || name.len() > crate::parser::MAX_NAME_LEN {
            return Err(ScenarioError::InvalidSyntax(format!(
                "actor name {name:?} must be 1..={} bytes",
                crate::parser::MAX_NAME_LEN
            )));
        }
        if let Some(n) = numeric_suffix(name) {
            return check_numeric_id(name, n);
        }
        self.by_name
            .get(name)
            .copied()
            .ok_or_else(|| ScenarioError::UnknownActor {
                name: name.to_string(),
            })
    }
}

fn check_numeric_id(name: &str, id: u32) -> Result<ActorId, ScenarioError> {
    if id > MAX_REGISTRY_ACTOR_ID {
        return Err(ScenarioError::InvalidActorId {
            name: name.to_string(),
            id: ActorId(id),
            max: MAX_REGISTRY_ACTOR_ID,
        });
    }
    Ok(ActorId(id))
}

/// Deterministic actor-id parse shared with the explorer bridge.
///
/// Numeric suffixes resolve directly; opaque names resolve through the
/// canonical registry (`leader`, `replica` plus numeric forms). Unknown
/// opaque names fail with [`ScenarioError::UnknownActor`]; use
/// [`scenario_registry`] to resolve every name a scenario mentions
/// (auto-registers opaque names at [`opaque_actor_id`] with collision
/// detection). The bridge in `ledger-explorer` must propagate the
/// `Result`.
pub fn actor_id(name: &str) -> Result<ActorId, ScenarioError> {
    ActorRegistry::with_known().resolve(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_scenario;

    #[test]
    fn compile_drop_happy() {
        let s = parse_scenario("drop 30% of leader->replica Msgs for 5s every 60s").unwrap();
        let c = compile(&s).unwrap();
        assert_eq!(c.faults.len(), 1);
        assert_eq!(c.schedule.len(), 1);
        assert!(matches!(
            c.schedule[0],
            FaultInjection::Drop { percent: 30, .. }
        ));
    }

    #[test]
    fn compile_invalid_percent() {
        let scenario = Scenario {
            name: "x".to_string(),
            blocks: vec![Block::Drop {
                percent: 150,
                src: "a".to_string(),
                dst: "b".to_string(),
                duration_ticks: 0,
                period_ticks: 0,
            }],
        };
        assert!(matches!(
            compile(&scenario),
            Err(ScenarioError::InvalidPercent(150))
        ));
    }

    #[test]
    fn compile_invalid_range() {
        let scenario = Scenario {
            name: "x".to_string(),
            blocks: vec![Block::Corrupt {
                range: (0x1000, 0x800),
                segment: "seg".to_string(),
            }],
        };
        assert!(matches!(
            compile(&scenario),
            Err(ScenarioError::InvalidRange { .. })
        ));
    }

    #[test]
    fn compile_duplicate_storm() {
        let s =
            parse_scenario("scenario dup\npartition leader->replica\npartition leader->replica")
                .unwrap();
        assert!(matches!(
            compile(&s),
            Err(ScenarioError::DuplicateTarget(_))
        ));
    }

    #[test]
    fn compile_storm_too_many_total() {
        // 6 distinct faults exceeds total threshold 5
        let dsl = "scenario storm\npartition a->b\npartition a->c\npartition a->d\npartition b->c\npartition b->d\npartition c->d";
        let s = parse_scenario(dsl).unwrap();
        assert!(matches!(compile(&s), Err(ScenarioError::StormDetected(_))));
    }

    #[test]
    fn compile_storm_same_actor() {
        // 4 faults targeting same actor replica-1 via different link directions
        let dsl = "scenario storm2\ndrop 10% of replica-1->a Msgs for 1s every 10s\ndrop 10% of replica-1->b Msgs for 1s every 10s\npartition replica-1->c\npartition replica-1->d";
        let s = parse_scenario(dsl).unwrap();
        assert!(matches!(compile(&s), Err(ScenarioError::StormDetected(_))));
    }

    #[test]
    fn compile_determinism() {
        let input = "scenario d\ndrop 10% of a->b Msgs for 1s every 10s\ncrash-restart replica-2 after FsFsync";
        let s1 = parse_scenario(input).unwrap();
        let s2 = parse_scenario(input).unwrap();
        let c1 = compile(&s1).unwrap();
        let c2 = compile(&s2).unwrap();
        assert_eq!(c1, c2);
    }

    #[test]
    fn compile_all_block_types() {
        let cases = [
            "drop 10% of a->b Msgs for 1s every 10s",
            "crash-restart replica-2 after FsFsync",
            "corrupt sector range [0x0,0x100) of seg-1",
            "torn-write on O_APPEND",
            "partition replica-1->replica-2",
            "clock-skew n1 by 100ms",
            "delay a->b by 50ms",
        ];
        for c in cases {
            let s = parse_scenario(c).unwrap();
            let compiled = compile(&s).unwrap();
            assert_eq!(compiled.schedule.len(), 1);
            assert!(!compiled.faults.is_empty());
        }
    }

    /// A negative skew (clock set back) must not silently map to a positive
    /// `Delay` of equal magnitude; the compile surface rejects it typed.
    #[test]
    fn compile_rejects_negative_clock_skew() {
        let s = parse_scenario("clock-skew a by -5s").unwrap();
        let error = compile(&s).unwrap_err();
        assert!(
            matches!(error, ScenarioError::InvalidSyntax(ref msg) if msg.contains("negative skew")),
            "{error}"
        );
        // A programmatically constructed i64::MIN block is rejected too: the
        // fault surface cannot represent it.
        let scenario = Scenario {
            name: "x".to_string(),
            blocks: vec![Block::ClockSkew {
                actor: "a".to_string(),
                skew_ticks: i64::MIN,
            }],
        };
        assert!(matches!(
            compile(&scenario),
            Err(ScenarioError::InvalidSyntax(_))
        ));
    }

    #[test]
    fn compile_clock_skew_at_i64_max_boundary() {
        let s = parse_scenario("clock-skew a by 9223372036854775807us").unwrap();
        let c = compile(&s).unwrap();
        match c.faults[0].1 {
            FaultSpec::Delay { ticks } => assert_eq!(ticks, i64::MAX as u64),
            _ => panic!("expected a Delay fault"),
        }
        match &c.schedule[0] {
            FaultInjection::ClockSkew { skew_ticks, .. } => {
                assert_eq!(*skew_ticks, i64::MAX);
            }
            _ => panic!("expected ClockSkew injection"),
        }
    }

    #[test]
    fn neutral_surface_deterministic() {
        let input =
            "scenario d\ndrop 10% of a->b Msgs for 1s every 10s\npartition replica-1->replica-2";
        let s1 = parse_scenario(input).unwrap();
        let s2 = parse_scenario(input).unwrap();
        let c1 = compile(&s1).unwrap();
        let c2 = compile(&s2).unwrap();
        // The neutral surface (faults, schedule) is the deterministic input
        // to the explorer bridge.
        assert_eq!(c1.faults, c2.faults);
        assert_eq!(c1.schedule, c2.schedule);
        // One entry fault per scheduled injection, in block order.
        assert_eq!(c1.faults.len(), c1.schedule.len());
    }

    #[test]
    fn partition_actor_id() {
        let s = parse_scenario("scenario p\npartition replica-2->replica-7").unwrap();
        let c = compile(&s).unwrap();
        assert_eq!(c.faults.len(), 1);
        match c.faults[0].1 {
            FaultSpec::Partition { src, dst } => {
                assert_eq!(src, ActorId(2));
                assert_eq!(dst, ActorId(7));
            }
            _ => panic!("expected partition"),
        }
        // Canonical opaque names keep their historic ids.
        let s = parse_scenario("scenario p\npartition leader->replica").unwrap();
        let c = compile(&s).unwrap();
        match c.faults[0].1 {
            FaultSpec::Partition { src, dst } => {
                assert_eq!(src, ActorId(3002));
                assert_eq!(dst, ActorId(4633));
            }
            _ => panic!("expected partition"),
        }
        // Opaque names in the scenario auto-register at their historic
        // wrapping-hash ids with collision detection.
        let s = parse_scenario("scenario p\npartition foo->bar").unwrap();
        let c = compile(&s).expect("scenario names must auto-register");
        match c.faults[0].1 {
            FaultSpec::Partition { src, dst } => {
                assert_eq!(src, opaque_actor_id("foo"));
                assert_eq!(dst, opaque_actor_id("bar"));
            }
            _ => panic!("expected partition"),
        }
    }

    #[test]
    fn registry_rejects_collisions_and_bad_ids() {
        // Distinct names sharing one id collide, even across blocks.
        let s = parse_scenario(
            "scenario c\npartition replica-1->replica-2\npartition node:1->replica-3",
        )
        .unwrap();
        assert!(
            matches!(compile(&s), Err(ScenarioError::ActorCollision { .. })),
            "numeric aliases for one id must collide"
        );
        // Self-partition under two spellings of one id collides per block.
        let s = parse_scenario("scenario c\npartition replica-1->node:1").unwrap();
        assert!(
            matches!(compile(&s), Err(ScenarioError::ActorCollision { .. })),
            "same id under distinct names must collide"
        );
        // Zero is the default first actor; over-cap suffixes are rejected.
        assert_eq!(
            actor_id("replica-0").expect("replica-0 must resolve"),
            ActorId(0)
        );
        assert!(matches!(
            actor_id("replica-2097152"),
            Err(ScenarioError::InvalidActorId { .. })
        ));
        // Direct registry collision on register.
        let mut registry = ActorRegistry::new();
        registry
            .register("alpha", ActorId(11))
            .expect("first register");
        let error = registry
            .register("beta", ActorId(11))
            .expect_err("id reuse must collide");
        assert!(
            matches!(
                error,
                ScenarioError::ActorCollision {
                    id: ActorId(11),
                    ..
                }
            ),
            "{error}"
        );
        // Unknown opaque resolves fail; known resolve succeeds.
        assert!(matches!(
            ActorRegistry::new().resolve("ghost"),
            Err(ScenarioError::UnknownActor { .. })
        ));
        assert_eq!(
            ActorRegistry::with_known()
                .resolve("leader")
                .expect("known"),
            ActorId(3002)
        );
    }

    /// Every public facade type stays on ledger-format types only.
    ///
    /// The crate builds without `ledger-sim`; any AGPL import would fail the
    /// build because the dependency is absent. This test exercises the full
    /// public surface (parse, compile, entry faults, schedule) with neutral
    /// types to lock the Apache-only seam.
    #[test]
    fn public_surface_stays_neutral() {
        let cases = [
            "drop 10% of a->b Msgs for 1s every 10s",
            "crash-restart replica-2 after FsFsync",
            "corrupt sector range [0x0,0x100) of seg-1",
            "torn-write on O_APPEND",
            "partition replica-1->replica-2",
            "clock-skew n1 by 100ms",
            "delay a->b by 50ms",
        ];
        for dsl in cases {
            let scenario = parse_scenario(dsl).unwrap();
            let compiled = compile(&scenario).unwrap();
            assert_eq!(compiled.faults.len(), compiled.schedule.len());
            for (kind, spec) in &compiled.faults {
                // EntryKind and FaultSpec are ledger-format types; FaultInjection
                // is this crate's string-targeted neutral type.
                let _: &EntryKind = kind;
                let _: &FaultSpec = spec;
            }
            for injection in &compiled.schedule {
                let _: &FaultInjection = injection;
            }
        }
    }
}
