//! Scenario-scoped actor-registry integration tests.
//!
//! Numeric suffixes resolve directly. Canonical opaque names keep historic
//! ids. Other opaque names a scenario mentions auto-register at their
//! historic wrapping-hash ids with collision detection; direct resolution
//! outside a scenario fails closed typed.

use ledger_faultspec::{
    ActorRegistry, MAX_NAME_LEN, MAX_REGISTRY_ACTOR_ID, ScenarioError, actor_id, compile,
    opaque_actor_id, parse_scenario,
};
use ledger_format::ActorId;

#[test]
fn numeric_suffixes_resolve_directly() {
    assert_eq!(actor_id("replica-2").expect("numeric"), ActorId(2));
    assert_eq!(actor_id("node:3").expect("numeric"), ActorId(3));
}

#[test]
fn canonical_opaque_names_keep_historic_ids() {
    assert_eq!(actor_id("leader").expect("known"), ActorId(3002));
    assert_eq!(actor_id("replica").expect("known"), ActorId(4633));
}

#[test]
fn unknown_opaque_names_fail_closed_outside_scenarios() {
    assert!(matches!(
        actor_id("foo"),
        Err(ScenarioError::UnknownActor { .. })
    ));
    // Inside a scenario the same names auto-register deterministically.
    let scenario = parse_scenario("scenario p\npartition foo->bar").expect("parses");
    let compiled = compile(&scenario).expect("scenario names auto-register");
    assert_eq!(compiled.schedule.len(), 1);
    assert_eq!(opaque_actor_id("foo"), opaque_actor_id("foo"));
    assert_ne!(opaque_actor_id("foo"), opaque_actor_id("bar"));
}

#[test]
fn collisions_are_detected() {
    let scenario =
        parse_scenario("scenario c\npartition replica-1->replica-2\npartition node:1->replica-3")
            .expect("parses");
    assert!(matches!(
        compile(&scenario),
        Err(ScenarioError::ActorCollision { .. })
    ));
    let mut registry = ActorRegistry::new();
    registry.register("alpha", ActorId(11)).expect("first");
    assert!(matches!(
        registry.register("beta", ActorId(11)),
        Err(ScenarioError::ActorCollision { .. })
    ));
}

#[test]
fn ids_are_bounded_and_names_capped() {
    // Zero is the default first actor; sim and the IPC wire accept it.
    assert_eq!(actor_id("replica-0").expect("zero actor"), ActorId(0));
    assert!(matches!(
        actor_id("replica-2097152"),
        Err(ScenarioError::InvalidActorId { .. })
    ));
    assert_eq!(MAX_REGISTRY_ACTOR_ID, 1 << 20);
    let long = "a".repeat(MAX_NAME_LEN + 1);
    assert!(matches!(
        ActorRegistry::new().resolve(&long),
        Err(ScenarioError::InvalidSyntax(_))
    ));
}
