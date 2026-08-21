//! Compiler from Scenario to ordered fault entries and schedule.

use std::collections::{HashMap, HashSet};

use ledger_format::{EntryKind, FaultSpec};

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

    for block in &scenario.blocks {
        let key = target_key(block);
        if !seen.insert(key.clone()) {
            return Err(ScenarioError::DuplicateTarget(key));
        }
        let (fault_entries, injection) = compile_block(block)?;
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

fn compile_block(
    block: &Block,
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
            let faults = vec![(
                EntryKind::Send,
                FaultSpec::Partition {
                    src: actor_id(src),
                    dst: actor_id(dst),
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

/// Deterministic actor-id parse shared with the explorer bridge.
///
/// A trailing numeric suffix after `-` or `:` parses directly
/// (`"replica-2"` -> 2, `"node:3"` -> 3). Opaque names fall back to a
/// deterministic wrapping hash in 1..=10000; 0 is reserved for the scheduler
/// actor. The bridge in `ledger-explorer` imports this single implementation
/// for `SimFault::Partition` targeting.
pub fn actor_id(name: &str) -> u32 {
    if let Some(pos) = name.rfind('-')
        && let Ok(n) = name[pos + 1..].parse::<u32>()
    {
        return n;
    }
    if let Some(pos) = name.rfind(':')
        && let Ok(n) = name[pos + 1..].parse::<u32>()
    {
        return n;
    }
    // Fallback deterministic hash: simple wrapping multiply.
    let mut h: u32 = 0;
    for b in name.bytes() {
        h = h.wrapping_mul(31).wrapping_add(u32::from(b));
    }
    // Avoid 0 which is reserved for scheduler actor.
    if h == 0 { 1 } else { h % 10000 + 1 }
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
            "partition a->b",
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
        let input = "scenario d\ndrop 10% of a->b Msgs for 1s every 10s\npartition a->b";
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
                assert_eq!(src, 2);
                assert_eq!(dst, 7);
            }
            _ => panic!("expected partition"),
        }
        // Opaque names use the deterministic fallback id, never 0.
        let s = parse_scenario("scenario p\npartition foo->bar").unwrap();
        let c = compile(&s).unwrap();
        match c.faults[0].1 {
            FaultSpec::Partition { src, dst } => {
                assert_ne!(src, 0);
                assert_ne!(dst, 0);
                assert_ne!(src, dst);
            }
            _ => panic!("expected partition"),
        }
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
            "partition a->b",
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
