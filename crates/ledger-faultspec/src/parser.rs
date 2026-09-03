//! Line-oriented parser for the failure-spec DSL.

use std::num::ParseIntError;
use thiserror::Error;

/// Maximum bytes for an actor, segment, or flag name.
pub const MAX_NAME_LEN: usize = 64;

/// A block in a failure scenario.
#[rustfmt::skip]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    Drop { percent: u8, src: String, dst: String, duration_ticks: u64, period_ticks: u64 },
    CrashRestart { actor: String, after: String },
    Corrupt { range: (u64, u64), segment: String },
    TornWrite { flag: String },
    Partition { src: String, dst: String },
    ClockSkew { actor: String, skew_ticks: i64 },
    BoundedLatency { src: String, dst: String, delay_ticks: u64 },
    Duplicate { src: String, dst: String },
}

/// A parsed scenario with a name and ordered blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scenario {
    pub name: String,
    pub blocks: Vec<Block>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScenarioError {
    #[error("empty scenario")]
    EmptyInput,
    #[error("invalid syntax: {0}")]
    InvalidSyntax(String),
    #[error("invalid percent {0}: must be 0..=100")]
    InvalidPercent(u8),
    #[error("invalid range start {start} end {end}: start must be < end")]
    InvalidRange { start: u64, end: u64 },
    #[error("duplicate target {0}: would cause voided-fault storm")]
    DuplicateTarget(String),
    #[error("invalid duration {0}")]
    InvalidDuration(String),
    #[error("invalid number '{token}': {source}")]
    InvalidNumber {
        token: String,
        #[source]
        source: ParseIntError,
    },
    #[error("invalid hex '{token}': {source}")]
    InvalidHex {
        token: String,
        #[source]
        source: ParseIntError,
    },
    #[error("storm detected: {0}")]
    StormDetected(String),
    #[error("unknown actor {name:?}: not registered and no numeric suffix")]
    UnknownActor { name: String },
    #[error("actor collision: {first:?} and {second:?} both map to id {id:?}")]
    ActorCollision {
        first: String,
        second: String,
        id: ledger_format::ActorId,
    },
    #[error("invalid actor id {id:?} for {name:?}: must be 1..={max}")]
    InvalidActorId {
        name: String,
        id: ledger_format::ActorId,
        max: u32,
    },
}

pub fn parse_scenario(input: &str) -> Result<Scenario, ScenarioError> {
    let mut lines = Vec::new();
    for raw in input.lines() {
        let t = raw.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        lines.push(t);
    }
    if lines.is_empty() {
        return Err(ScenarioError::EmptyInput);
    }
    let (name, start) = if lines[0].to_ascii_lowercase().starts_with("scenario ") {
        let n = lines[0][9..].trim();
        if n.is_empty() {
            (String::from("default"), 1)
        } else {
            check_name_len(n)?;
            (n.to_string(), 1)
        }
    } else {
        (String::from("default"), 0)
    };
    let mut blocks = Vec::new();
    for line in &lines[start..] {
        blocks.push(parse_block(line)?);
    }
    if name == "default" && blocks.is_empty() {
        return Err(ScenarioError::EmptyInput);
    }
    Ok(Scenario { name, blocks })
}

fn parse_block(line: &str) -> Result<Block, ScenarioError> {
    let l = line.to_ascii_lowercase();
    if l.starts_with("drop ") {
        parse_drop(line)
    } else if l.starts_with("crash-restart ") {
        parse_crash_restart(line)
    } else if l.starts_with("corrupt ") {
        parse_corrupt(line)
    } else if l == "torn-write" || l.starts_with("torn-write ") {
        parse_torn_write(line)
    } else if l.starts_with("partition ") {
        parse_partition(line)
    } else if l.starts_with("duplicate ") {
        parse_duplicate(line)
    } else if l.starts_with("clock-skew ") {
        parse_clock_skew(line)
    } else if l.starts_with("delay ") || l.starts_with("bounded-latency ") {
        parse_bounded_latency(line)
    } else {
        Err(ScenarioError::InvalidSyntax(line.to_string()))
    }
}

fn parse_drop(line: &str) -> Result<Block, ScenarioError> {
    let p = extract_percent(line)?;
    let (s, d) = extract_link(line)?;
    if p > 100 {
        return Err(ScenarioError::InvalidPercent(p));
    }
    Ok(Block::Drop {
        percent: p,
        src: s,
        dst: d,
        duration_ticks: extract_duration_after(line, "for")?.unwrap_or(0),
        period_ticks: extract_duration_after(line, "every")?.unwrap_or(0),
    })
}

fn parse_crash_restart(line: &str) -> Result<Block, ScenarioError> {
    let r = line["crash-restart".len()..].trim();
    if r.is_empty() {
        return Err(ScenarioError::InvalidSyntax(line.to_string()));
    }
    if let Some(pos) = r.to_ascii_lowercase().find(" after ") {
        let a = r[..pos].trim().to_string();
        let af = r[pos + 7..].trim().to_string();
        if a.is_empty() || af.is_empty() {
            return Err(ScenarioError::InvalidSyntax(line.to_string()));
        }
        check_name_len(&a)?;
        check_name_len(&af)?;
        Ok(Block::CrashRestart {
            actor: a,
            after: af,
        })
    } else {
        check_name_len(r)?;
        Ok(Block::CrashRestart {
            actor: r.to_string(),
            after: String::from("FsFsync"),
        })
    }
}

fn parse_corrupt(line: &str) -> Result<Block, ScenarioError> {
    let lb = line
        .find('[')
        .ok_or_else(|| ScenarioError::InvalidSyntax(line.to_string()))?;
    let co = line[lb..]
        .find(',')
        .ok_or_else(|| ScenarioError::InvalidSyntax(line.to_string()))?
        + lb;
    let rb = line[co..]
        .find(')')
        .ok_or_else(|| ScenarioError::InvalidSyntax(line.to_string()))?
        + co;
    let st = parse_hex_u64(line[lb + 1..co].trim())?;
    let en = parse_hex_u64(line[co + 1..rb].trim())?;
    if st >= en {
        return Err(ScenarioError::InvalidRange { start: st, end: en });
    }
    let seg = line
        .to_ascii_lowercase()
        .rfind(" of ")
        .map(|p| line[p + 4..].trim().to_string())
        .ok_or_else(|| ScenarioError::InvalidSyntax(line.to_string()))?;
    if seg.is_empty() {
        return Err(ScenarioError::InvalidSyntax(line.to_string()));
    }
    check_name_len(&seg)?;
    Ok(Block::Corrupt {
        range: (st, en),
        segment: seg,
    })
}

fn parse_torn_write(line: &str) -> Result<Block, ScenarioError> {
    let l = line.to_ascii_lowercase();
    let flag = if let Some(pos) = l.find(" on ") {
        line[pos + 4..].trim().to_string()
    } else {
        let rest = line["torn-write".len()..].trim();
        if rest.is_empty() {
            return Err(ScenarioError::InvalidSyntax(line.to_string()));
        }
        rest.to_string()
    };
    if flag.is_empty() {
        return Err(ScenarioError::InvalidSyntax(line.to_string()));
    }
    check_name_len(&flag)?;
    Ok(Block::TornWrite { flag })
}

fn parse_partition(line: &str) -> Result<Block, ScenarioError> {
    let (s, d) = extract_link(line["partition".len()..].trim())?;
    Ok(Block::Partition { src: s, dst: d })
}

fn parse_duplicate(line: &str) -> Result<Block, ScenarioError> {
    let (s, d) = extract_link(line["duplicate".len()..].trim())?;
    Ok(Block::Duplicate { src: s, dst: d })
}

fn parse_clock_skew(line: &str) -> Result<Block, ScenarioError> {
    let rest = line["clock-skew".len()..].trim();
    let (actor, dur_s) = if let Some(pos) = rest.to_ascii_lowercase().find(" by ") {
        (
            rest[..pos].trim().to_string(),
            rest[pos + 4..].trim().to_string(),
        )
    } else {
        let mut p = rest.split_whitespace();
        (
            p.next().unwrap_or("").to_string(),
            p.next().unwrap_or("").to_string(),
        )
    };
    if actor.is_empty() || dur_s.is_empty() {
        return Err(ScenarioError::InvalidSyntax(line.to_string()));
    }
    check_name_len(&actor)?;
    let neg = dur_s.starts_with('-');
    let raw = if neg { &dur_s[1..] } else { dur_s.as_str() };
    let ticks = parse_duration_ticks(raw)?;
    let skew_ticks = i64::try_from(ticks).map_err(|_| {
        ScenarioError::InvalidDuration(format!("clock-skew {dur_s}: exceeds i64 range"))
    })?;
    // The checked conversion above bounds `skew_ticks` to `0..=i64::MAX`, so
    // the negation below can never overflow.
    Ok(Block::ClockSkew {
        actor,
        skew_ticks: if neg { -skew_ticks } else { skew_ticks },
    })
}

fn parse_bounded_latency(line: &str) -> Result<Block, ScenarioError> {
    let l = line.to_ascii_lowercase();
    let rest = if l.starts_with("delay ") {
        line["delay".len()..].trim()
    } else {
        line["bounded-latency".len()..].trim()
    };
    let (s, d) = extract_link(rest)?;
    let delay = if let Some(pos) = rest.to_ascii_lowercase().find(" by ") {
        parse_duration_ticks(rest[pos + 4..].trim())?
    } else {
        let last = rest.split_whitespace().last().unwrap_or("");
        if last.contains("ms") || last.contains('s') {
            // A duration-looking token must parse. A malformed one is a typed
            // parse error, never a silent zero delay.
            parse_duration_ticks(last)?
        } else {
            0
        }
    };
    Ok(Block::BoundedLatency {
        src: s,
        dst: d,
        delay_ticks: delay,
    })
}

fn extract_percent(line: &str) -> Result<u8, ScenarioError> {
    for tok in line.split_whitespace() {
        if let Some(stripped) = tok.strip_suffix('%') {
            let v: u8 = stripped
                .parse()
                .map_err(|source| ScenarioError::InvalidNumber {
                    token: stripped.to_string(),
                    source,
                })?;
            return Ok(v);
        }
        if let Some(p) = tok.find('%')
            && let Ok(v) = tok[..p].parse::<u8>()
        {
            return Ok(v);
        }
    }
    Err(ScenarioError::InvalidSyntax(line.to_string()))
}

fn extract_link(line: &str) -> Result<(String, String), ScenarioError> {
    for tok in line.split_whitespace() {
        if let Some(pos) = tok.find("->") {
            let s = tok[..pos].trim().to_string();
            let d = tok[pos + 2..].trim().trim_end_matches(',').to_string();
            if !s.is_empty() && !d.is_empty() {
                check_name_len(&s)?;
                check_name_len(&d)?;
                return Ok((s, d));
            }
        }
    }
    Err(ScenarioError::InvalidSyntax(line.to_string()))
}

/// Find the duration token after `kw`, if any. Absent is `Ok(None)`.
fn extract_duration_after(line: &str, kw: &str) -> Result<Option<u64>, ScenarioError> {
    let Some(pos) = line.to_ascii_lowercase().find(&format!(" {kw} ")) else {
        return Ok(None);
    };
    let Some(token) = line[pos + kw.len() + 2..].split_whitespace().next() else {
        return Ok(None);
    };
    parse_duration_ticks(token).map(Some)
}

fn parse_duration_ticks(s: &str) -> Result<u64, ScenarioError> {
    let t = s.trim().trim_end_matches(',').trim_end_matches('.');
    let invalid = |source: ParseIntError| ScenarioError::InvalidNumber {
        token: s.to_string(),
        source,
    };
    if t.is_empty() {
        return Err(ScenarioError::InvalidDuration(s.to_string()));
    }
    if let Some(stripped) = t.strip_suffix("ms") {
        let value = stripped.parse::<u64>().map_err(invalid)?;
        return value
            .checked_mul(1000)
            .ok_or_else(|| ScenarioError::InvalidDuration(s.to_string()));
    }
    if let Some(stripped) = t.strip_suffix("us") {
        return stripped.parse::<u64>().map_err(invalid);
    }
    if let Some(stripped) = t.strip_suffix('s') {
        let value = stripped.parse::<u64>().map_err(invalid)?;
        return value
            .checked_mul(1_000_000)
            .ok_or_else(|| ScenarioError::InvalidDuration(s.to_string()));
    }
    t.parse::<u64>().map_err(invalid)
}

fn parse_hex_u64(s: &str) -> Result<u64, ScenarioError> {
    let t = s.trim();
    let hex = if t.starts_with("0x") || t.starts_with("0X") {
        &t[2..]
    } else {
        t
    };
    u64::from_str_radix(hex, 16).map_err(|source| ScenarioError::InvalidHex {
        token: s.to_string(),
        source,
    })
}

/// Reject names over [`MAX_NAME_LEN`] bytes.
fn check_name_len(name: &str) -> Result<(), ScenarioError> {
    if name.len() > MAX_NAME_LEN {
        return Err(ScenarioError::InvalidSyntax(format!(
            "name {name:?} exceeds {MAX_NAME_LEN} bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_drop_example() {
        let s =
            parse_scenario("scenario drop-test\ndrop 30% of leader->replica Msgs for 5s every 60s")
                .unwrap();
        assert_eq!(s.name, "drop-test");
        assert_eq!(s.blocks.len(), 1);
        match &s.blocks[0] {
            Block::Drop {
                percent,
                src,
                dst,
                duration_ticks,
                period_ticks,
            } => {
                assert_eq!(*percent, 30);
                assert_eq!(src, "leader");
                assert_eq!(dst, "replica");
                assert_eq!(*duration_ticks, 5_000_000);
                assert_eq!(*period_ticks, 60_000_000);
            }
            _ => panic!("wrong"),
        }
    }
    #[test]
    fn parse_crash_restart() {
        let s = parse_scenario("crash-restart replica-2 after FsFsync").unwrap();
        match &s.blocks[0] {
            Block::CrashRestart { actor, after } => {
                assert_eq!(actor, "replica-2");
                assert_eq!(after, "FsFsync");
            }
            _ => panic!("wrong"),
        }
    }
    #[test]
    fn parse_corrupt() {
        let s = parse_scenario("corrupt sector range [0x800,0x1000) of log-seg-7").unwrap();
        match &s.blocks[0] {
            Block::Corrupt { range, segment } => {
                assert_eq!(*range, (0x800, 0x1000));
                assert_eq!(segment, "log-seg-7");
            }
            _ => panic!("wrong"),
        }
    }
    #[test]
    fn parse_torn_write() {
        let s = parse_scenario("torn-write on O_APPEND").unwrap();
        match &s.blocks[0] {
            Block::TornWrite { flag } => assert_eq!(flag, "O_APPEND"),
            _ => panic!("wrong"),
        }
    }
    #[test]
    fn parse_partition_example() {
        let s = parse_scenario("partition leader->replica").unwrap();
        match &s.blocks[0] {
            Block::Partition { src, dst } => {
                assert_eq!(src, "leader");
                assert_eq!(dst, "replica");
            }
            _ => panic!("wrong"),
        }
    }
    #[test]
    fn parse_duplicate_example() {
        let s = parse_scenario("duplicate leader->replica").unwrap();
        match &s.blocks[0] {
            Block::Duplicate { src, dst } => {
                assert_eq!(src, "leader");
                assert_eq!(dst, "replica");
            }
            _ => panic!("wrong"),
        }
    }
    #[test]
    fn parse_duplicate_missing_link_is_rejected() {
        assert!(matches!(
            parse_scenario("duplicate leader"),
            Err(ScenarioError::InvalidSyntax(_))
        ));
    }
    #[test]
    fn parse_errors() {
        assert!(parse_scenario("").is_err());
        assert!(parse_scenario("   ").is_err());
        let r = parse_scenario("corrupt sector range [0x1000,0x800) of seg");
        match r {
            Err(ScenarioError::InvalidRange { start, end }) => {
                assert_eq!(start, 0x1000);
                assert_eq!(end, 0x800);
            }
            _ => panic!("expected InvalidRange"),
        }
    }
    #[test]
    fn determinism() {
        let input = "scenario d\ndrop 10% of a->b Msgs for 1s every 10s";
        assert_eq!(
            parse_scenario(input).unwrap(),
            parse_scenario(input).unwrap()
        );
    }

    #[test]
    fn overlong_actor_names_are_rejected() {
        let long = "a".repeat(crate::parser::MAX_NAME_LEN + 1);
        let dsl = format!("partition {long}->replica-1");
        assert!(
            matches!(parse_scenario(&dsl), Err(ScenarioError::InvalidSyntax(_))),
            "overlong actor names must be bounded"
        );
    }

    #[test]
    fn clock_skew_exceeding_i64_is_rejected_not_wrapped() {
        // 2^63 microseconds is one beyond i64::MAX; the unchecked `as i64`
        // would wrap it negative. The parse must fail with a typed error.
        let error = parse_scenario("clock-skew a by 9223372036854775808us").unwrap_err();
        assert!(
            matches!(error, ScenarioError::InvalidDuration(_)),
            "{error}"
        );
        // The i64::MAX boundary itself parses.
        let s = parse_scenario("clock-skew a by 9223372036854775807us").unwrap();
        match &s.blocks[0] {
            Block::ClockSkew { skew_ticks, .. } => assert_eq!(*skew_ticks, i64::MAX),
            _ => panic!("wrong"),
        }
    }

    #[test]
    fn negative_clock_skew_parses_signed_without_overflow() {
        let s = parse_scenario("clock-skew a by -5s").unwrap();
        match &s.blocks[0] {
            Block::ClockSkew { skew_ticks, .. } => assert_eq!(*skew_ticks, -5_000_000),
            _ => panic!("wrong"),
        }
        // A minus with nothing after it is malformed, not zero.
        assert!(parse_scenario("clock-skew a by -").is_err());
    }

    #[test]
    fn duration_unit_multiply_overflow_is_rejected() {
        // u64::MAX milliseconds overflows the ticks multiplier; the result
        // must be a typed error, never a wrapped value.
        for dsl in [
            "delay a->b by 18446744073709551615ms",
            "delay a->b by 18446744073709551615s",
        ] {
            let error = parse_scenario(dsl).unwrap_err();
            assert!(
                matches!(error, ScenarioError::InvalidDuration(_)),
                "{dsl}: {error}"
            );
        }
        // Microseconds carry no multiplier, so the full u64 range is valid.
        let s = parse_scenario("delay a->b by 18446744073709551615us").unwrap();
        match &s.blocks[0] {
            Block::BoundedLatency { delay_ticks, .. } => assert_eq!(*delay_ticks, u64::MAX),
            _ => panic!("wrong"),
        }
    }

    #[test]
    fn malformed_bounded_latency_is_rejected_not_zeroed() {
        // A duration-looking trailing token must parse; a malformed one used
        // to become a silent zero delay.
        let error = parse_scenario("delay a->b bogusms").unwrap_err();
        assert!(
            matches!(error, ScenarioError::InvalidNumber { .. }),
            "{error}"
        );
        let error = parse_scenario("delay a->b 12xs").unwrap_err();
        assert!(
            matches!(error, ScenarioError::InvalidNumber { .. }),
            "{error}"
        );
        let error = parse_scenario("bounded-latency a->b 7s bogusx").unwrap_err();
        assert!(
            matches!(error, ScenarioError::InvalidNumber { .. }),
            "{error}"
        );
        // A bare number without a duration suffix means "no duration".
        let s = parse_scenario("delay a->b 100").unwrap();
        match &s.blocks[0] {
            Block::BoundedLatency { delay_ticks, .. } => assert_eq!(*delay_ticks, 0),
            _ => panic!("wrong"),
        }
        // The by-form parses with checked multiplication.
        let s = parse_scenario("delay a->b by 100ms").unwrap();
        match &s.blocks[0] {
            Block::BoundedLatency { delay_ticks, .. } => assert_eq!(*delay_ticks, 100_000),
            _ => panic!("wrong"),
        }
    }

    /// A present malformed drop duration used to become a silent zero under
    /// `unwrap_or(0)`; it must be a typed parse error. A missing keyword
    /// still defaults to zero, which is the legitimate indefinite case.
    #[test]
    fn malformed_present_drop_duration_is_rejected_not_zeroed() {
        let error = parse_scenario("drop 30% of a->b Msgs for bogusms").unwrap_err();
        assert!(
            matches!(error, ScenarioError::InvalidNumber { .. }),
            "malformed for-token must be a typed error, got {error}"
        );
        let error = parse_scenario("drop 30% of a->b Msgs for 5s every bogusx").unwrap_err();
        assert!(
            matches!(error, ScenarioError::InvalidNumber { .. }),
            "malformed every-token must be a typed error, got {error}"
        );
        let error = parse_scenario("drop 30% of a->b Msgs for 18446744073709551615ms").unwrap_err();
        assert!(
            matches!(error, ScenarioError::InvalidDuration(_)),
            "overflowing duration must be a typed error, got {error}"
        );

        // No keyword at all: absence defaults to zero (indefinite drop).
        let s = parse_scenario("drop 30% of a->b Msgs").unwrap();
        match &s.blocks[0] {
            Block::Drop {
                duration_ticks,
                period_ticks,
                ..
            } => {
                assert_eq!(*duration_ticks, 0);
                assert_eq!(*period_ticks, 0);
            }
            _ => panic!("wrong"),
        }
        // A dangling keyword with no token stays absent.
        let s = parse_scenario("drop 30% of a->b Msgs for").unwrap();
        match &s.blocks[0] {
            Block::Drop { duration_ticks, .. } => assert_eq!(*duration_ticks, 0),
            _ => panic!("wrong"),
        }
        // Valid durations still parse with the unit multiplier.
        let s = parse_scenario("drop 30% of a->b Msgs for 5s every 60s").unwrap();
        match &s.blocks[0] {
            Block::Drop {
                duration_ticks,
                period_ticks,
                ..
            } => {
                assert_eq!(*duration_ticks, 5_000_000);
                assert_eq!(*period_ticks, 60_000_000);
            }
            _ => panic!("wrong"),
        }
    }
}
