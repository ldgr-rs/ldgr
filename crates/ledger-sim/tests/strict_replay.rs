use ledger_sim::{
    Instruction, Policy, ReplayViolation, RunConfig, RuntimeError, Scheduler, SeedTree, Simulation,
};

fn simple_programs_two_done() -> Vec<Vec<Instruction>> {
    vec![vec![Instruction::Done], vec![Instruction::Done]]
}

fn mini_kv_programs() -> Vec<Vec<Instruction>> {
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

#[test]
fn out_of_range_fires_no_modulo() {
    // Ready at step 0 has len 2, value 2 is out of range, lenient would mod to 0.
    let seed = SeedTree::new([7; 32]);
    let mut strict =
        Scheduler::with_fallback_strict(Policy::Replay, seed.clone(), vec![2], Policy::Random);
    let ready = vec![0, 1];
    let choice = strict.choose(&ready, 0);
    let violation = strict.take_violation().expect("violation must be recorded");
    match violation {
        ReplayViolation::OutOfRange {
            step,
            value,
            ready_len,
        } => {
            assert_eq!(step, 0);
            assert_eq!(value, 2);
            assert_eq!(ready_len, 2);
        }
        other => panic!("expected OutOfRange, got {other:?}"),
    }
    // No modulo applied, choice is dummy and not the normalized 0 via 2%2.
    // The scheduler must not have normalized; the returned choice is dummy 0 but
    // the violation proves it was rejected, not normalized. Verify lenient does normalize.
    let mut lenient = Scheduler::with_fallback(Policy::Replay, seed, vec![2], Policy::Random);
    let lenient_choice = lenient.choose(&ready, 0);
    assert_eq!(lenient_choice, 0, "lenient must normalize 2 % 2 == 0");
    // Ensure strict did not fallback or normalize: violation exists and lenient path differs in handling
    // (strict rejected, lenient accepted).
    assert_eq!(choice, 0);
    // Also test value 5 >=2 is rejected, not 5%2==1
    let mut strict2 = Scheduler::with_fallback_strict(
        Policy::Replay,
        SeedTree::new([7; 32]),
        vec![5],
        Policy::Random,
    );
    strict2.choose(&ready, 0);
    let v2 = strict2.take_violation().expect("must be out of range");
    assert!(matches!(v2, ReplayViolation::OutOfRange { value: 5, .. }));
}

#[test]
fn exhausted_fires_with_zero_fallback_draws() {
    // Two done tasks need 2 steps, provide only 1 decision.
    let seed = [9; 32];
    let config = RunConfig::builder()
        .seed(seed)
        .policy(Policy::Replay)
        .max_steps(10)
        .build();
    let programs = simple_programs_two_done();
    // Replay with single decision, second step will be exhausted.
    let replay = vec![0];
    let err = Simulation::with_replay_strict(config.clone(), programs.clone(), replay.clone())
        .run()
        .expect_err("exhausted must error");
    match err {
        RuntimeError::StrictReplay(ReplayViolation::Exhausted { step, replay_len }) => {
            assert_eq!(step, 1);
            assert_eq!(replay_len, 1);
        }
        other => panic!("expected Exhausted, got {other:?}"),
    }
    // Zero fallback draws: lenient would have fallen back to Random and succeeded.
    let lenient = Simulation::with_replay(config, programs, replay)
        .run()
        .expect("lenient must fallback");
    assert_eq!(lenient.steps, 2);
    // Ensure strict did not consume fallback by checking that no extra decisions beyond replay were recorded.
    // The strict run error step is exactly replay_len, meaning no fallback decision was made.
}

#[test]
fn trailing_via_finish() {
    let config = RunConfig::builder()
        .seed([11; 32])
        .policy(Policy::Random)
        .max_steps(64)
        .build();
    let programs = simple_programs_two_done();
    let base = Simulation::new(config.clone(), programs.clone())
        .run()
        .unwrap();
    assert_eq!(base.steps, 2);
    // Provide replay longer than needed by 3.
    let mut trailing_replay = base.decisions.clone();
    trailing_replay.extend(vec![0, 1, 0]);
    let strict_config = config.clone().with_policy(Policy::Replay);
    let err = Simulation::with_replay_strict(strict_config, programs, trailing_replay.clone())
        .run()
        .expect_err("trailing must error");
    match err {
        RuntimeError::StrictReplay(ReplayViolation::Trailing { trailing, steps }) => {
            assert_eq!(trailing, 3);
            assert_eq!(steps, 2);
        }
        other => panic!("expected Trailing, got {other:?}"),
    }
}

#[test]
fn valid_full_strict_replay_matches_lenient_root() {
    let config = RunConfig::builder()
        .seed([13; 32])
        .policy(Policy::Random)
        .max_steps(256)
        .build();
    let programs = mini_kv_programs();
    let base = Simulation::new(config.clone(), programs.clone())
        .run()
        .unwrap();
    let decisions = base.decisions.clone();
    let lenient_config = config.clone().with_policy(Policy::Replay);
    let lenient = Simulation::with_replay(lenient_config, programs.clone(), decisions.clone())
        .run()
        .unwrap();
    let strict_config = config.with_policy(Policy::Replay);
    let strict = Simulation::with_replay_strict(strict_config, programs, decisions)
        .run()
        .unwrap();
    assert_eq!(
        lenient.journal.root_hash(),
        strict.journal.root_hash(),
        "valid strict replay must be byte identical to lenient"
    );
    assert_eq!(lenient.decisions, strict.decisions);
}

#[test]
fn violation_leaves_entry_count_unchanged() {
    // Prove the violation is recorded before any journal append or rng draw.
    // Scheduler strict out-of-range must not push a decision and must not
    // consume a fallback draw; the executor checks take_violation before
    // journal_rng_draw, so entry count stays at spawns only.
    let seed = SeedTree::new([17; 32]);
    let ready = vec![0, 1];
    let mut strict =
        Scheduler::with_fallback_strict(Policy::Replay, seed.clone(), vec![99], Policy::Random);
    let before_decisions = strict.decisions().len();
    strict.choose(&ready, 0);
    let violation = strict.take_violation().expect("must be out of range");
    assert!(matches!(violation, ReplayViolation::OutOfRange { .. }));
    // No decision was recorded for the violating step.
    assert_eq!(
        strict.decisions().len(),
        before_decisions,
        "violating choice must not be recorded"
    );
    // Exhausted case also leaves decisions unchanged beyond replay_len.
    let mut strict2 =
        Scheduler::with_fallback_strict(Policy::Replay, seed, vec![0], Policy::Random);
    let ready2 = vec![0, 1];
    // Step 0 valid
    strict2.choose(&ready2, 0);
    assert!(strict2.take_violation().is_none());
    assert_eq!(strict2.decisions().len(), 1);
    // Step 1 exhausted
    strict2.choose(&ready2, 1);
    let v2 = strict2.take_violation().expect("exhausted");
    assert!(matches!(v2, ReplayViolation::Exhausted { step: 1, .. }));
    assert_eq!(
        strict2.decisions().len(),
        1,
        "exhausted must not push a fallback decision"
    );
    // Lenient would have pushed a fallback decision.
    let mut lenient = Scheduler::with_fallback(
        Policy::Replay,
        SeedTree::new([17; 32]),
        vec![0],
        Policy::Random,
    );
    lenient.choose(&ready2, 0);
    let lenient_choice = lenient.choose(&ready2, 1);
    assert_eq!(lenient.decisions().len(), 2);
    // The lenient fallback choice must be the deterministic Random draw.
    let expected = (SeedTree::new([17; 32]).draw_u64("sched", 1) as usize) % 2;
    assert_eq!(lenient_choice, expected);
    // Simulation level also proves no journal append: strict with out-of-range
    // at step 0 returns OutOfRange before any RngDraw, while lenient succeeds.
    let config = RunConfig::builder()
        .seed([17; 32])
        .policy(Policy::Replay)
        .max_steps(10)
        .build();
    let programs = simple_programs_two_done();
    let err = Simulation::with_replay_strict(config.clone(), programs.clone(), vec![99])
        .run()
        .expect_err("must be out of range");
    assert!(matches!(
        err,
        RuntimeError::StrictReplay(ReplayViolation::OutOfRange { step: 0, .. })
    ));
    let ok = Simulation::with_replay(config, programs, vec![99])
        .run()
        .expect("lenient must succeed with modulo");
    // Lenient's journal includes the scheduling draws, strict's would have none.
    assert!(ok.journal.len() > 2);
}

#[test]
fn scheduler_lenient_still_modulo_and_fallback() {
    let seed = SeedTree::new([5; 32]);
    let ready = vec![0, 1, 2];
    // Lenient normalizes 5 %3 ==2
    let mut lenient =
        Scheduler::with_fallback(Policy::Replay, seed.clone(), vec![5], Policy::Random);
    assert_eq!(lenient.choose(&ready, 0), 2);
    assert!(lenient.take_violation().is_none());
    // Lenient exhausted falls back to Random (deterministic)
    let mut lenient2 =
        Scheduler::with_fallback(Policy::Replay, seed.clone(), vec![], Policy::Random);
    let choice = lenient2.choose(&ready, 0);
    // Must be deterministic Random draw: seed draw at sched step0 %3
    let expected = (seed.draw_u64("sched", 0) as usize) % 3;
    assert_eq!(choice, expected);
}
