//! Canonical scenario library with known outcomes.

use crate::parser::{Scenario, ScenarioError, parse_scenario};

/// Identifier for a canonical scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScenarioId {
    Partition,
    CrashRestart,
    Corruption,
    ClockSkew,
    TornWrite,
    BoundedLatency,
    LeaderStepdown,
    MembershipChurn,
}

impl ScenarioId {
    /// Canonical name for the scenario.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Partition => "partition",
            Self::CrashRestart => "crash-restart",
            Self::Corruption => "corruption",
            Self::ClockSkew => "clock-skew",
            Self::TornWrite => "torn-write",
            Self::BoundedLatency => "bounded-latency",
            Self::LeaderStepdown => "leader-stepdown",
            Self::MembershipChurn => "membership-churn",
        }
    }
}

/// DSL string for a canonical id.
pub fn dsl_for(id: ScenarioId) -> &'static str {
    match id {
        ScenarioId::Partition => "scenario partition\npartition leader->replica",
        ScenarioId::CrashRestart => "scenario crash-restart\ncrash-restart replica-2 after FsFsync",
        ScenarioId::Corruption => {
            "scenario corruption\ncorrupt sector range [0x800,0x1000) of log-seg-7"
        }
        ScenarioId::ClockSkew => "scenario clock-skew\nclock-skew replica-2 by 500ms",
        ScenarioId::TornWrite => "scenario torn-write\ntorn-write on O_APPEND",
        ScenarioId::BoundedLatency => "scenario bounded-latency\ndelay leader->replica by 100ms",
        ScenarioId::LeaderStepdown => {
            "scenario leader-stepdown\ncrash-restart leader after FsFsync"
        }
        ScenarioId::MembershipChurn => {
            "scenario membership-churn\ncrash-restart replica-3 after FsFsync"
        }
    }
}

/// Canonical library of at least 8 scenarios.
pub fn canonical_library() -> Result<Vec<Scenario>, ScenarioError> {
    canonical_library_with_ids().map(|lib| lib.into_iter().map(|(_, scenario)| scenario).collect())
}

/// Return canonical library with ids paired.
pub fn canonical_library_with_ids() -> Result<Vec<(ScenarioId, Scenario)>, ScenarioError> {
    let ids = [
        ScenarioId::Partition,
        ScenarioId::CrashRestart,
        ScenarioId::Corruption,
        ScenarioId::ClockSkew,
        ScenarioId::TornWrite,
        ScenarioId::BoundedLatency,
        ScenarioId::LeaderStepdown,
        ScenarioId::MembershipChurn,
    ];
    ids.iter()
        .map(|id| Ok((*id, parse_scenario(dsl_for(*id))?)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::compile;

    #[test]
    fn library_has_eight() {
        let lib = canonical_library().expect("canonical library must parse");
        assert!(lib.len() >= 8);
    }

    #[test]
    fn library_names_match_ids() {
        let lib = canonical_library_with_ids().expect("canonical library must parse");
        for (id, sc) in lib {
            assert_eq!(sc.name, id.as_str());
        }
    }

    #[test]
    fn library_compiles_without_voided_storms() {
        for sc in canonical_library().expect("canonical library must parse") {
            let res = compile(&sc);
            assert!(
                res.is_ok(),
                "scenario {} failed to compile: {:?}",
                sc.name,
                res.err()
            );
            let compiled = res.expect("already ok");
            assert!(!compiled.faults.is_empty());
            assert!(!compiled.schedule.is_empty());
            // The neutral surface stays paired and deterministic: one entry
            // fault per scheduled injection, stable across recompiles. The
            // explorer bridge derives engine injections from this surface.
            assert_eq!(compiled.faults.len(), compiled.schedule.len());
            let again = compile(&sc).expect("must compile again");
            assert_eq!(again.faults, compiled.faults);
            assert_eq!(again.schedule, compiled.schedule);
        }
    }

    #[test]
    fn each_dsl_parses_and_roundtrips_via_compile() {
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
            let first = parse_scenario(dsl).expect("must parse");
            let second = parse_scenario(dsl).expect("must parse");
            assert_eq!(first, second, "determinism for {:?}", id);
            let c = compile(&first).expect("must compile");
            let c2 = compile(&second).expect("must compile");
            assert_eq!(c, c2);
        }
    }
}
