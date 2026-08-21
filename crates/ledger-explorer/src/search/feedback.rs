use super::{
    CampaignPersist, CampaignReport, Finding, Workload, fault_injection_target, replay_with_faults,
};
use crate::ldfi::{hypothesis_to_schedule, solve_with};
use crate::maxsat::encode_hazard;
use crate::oracle::Oracle;
use crate::solver::{SolverConfig, select_solver};
use ledger_format::Hash;
use ledger_sim::{RunConfig, SimFault, Simulation, canonical_hash};
use std::collections::{BTreeMap, BTreeSet, HashSet};

fn injection_kind(injection: &SimFault) -> &'static str {
    match injection {
        SimFault::Drop(_) => "Drop",
        SimFault::Delay { .. } => "Delay",
        SimFault::Partition { .. } => "Partition",
        SimFault::Crash(_) => "Crash",
        SimFault::Corrupt { .. } => "Corrupt",
        SimFault::CrashState { .. } => "CrashState",
    }
}

/// Escalate a fault to the next severity level.
///
/// Ladder (deterministic):
/// - `Drop(id)` -> `Crash(id)` (stronger loss)
/// - `Delay{send, ticks}` -> `Delay{send, ticks*2}` capped at 32
/// - `Corrupt{write, xor_mask}` -> wider mask `1 -> 0xFF -> 0xFFFF -> 0xFFFFFFFF -> 0xFFFFFFFFFFFFFFFF`
/// - `CrashState{write, state}` -> `state+1` capped at 3
/// - `Crash` and `Partition` have no escalation
pub fn escalate(injection: &SimFault) -> Option<SimFault> {
    match injection {
        SimFault::Drop(id) => Some(SimFault::Crash(*id)),
        SimFault::Delay { send, ticks } => {
            let next = ticks.saturating_mul(2).max(1);
            let capped = next.min(32);
            if capped == *ticks {
                None
            } else {
                Some(SimFault::Delay {
                    send: *send,
                    ticks: capped,
                })
            }
        }
        SimFault::Corrupt { write, xor_mask } => {
            let next_mask = match xor_mask {
                1 => 0xFF,
                0xFF => 0xFFFF,
                0xFFFF => 0xFFFF_FFFF,
                0xFFFF_FFFF => 0xFFFF_FFFF_FFFF_FFFF_u64,
                _ => xor_mask.wrapping_mul(2).wrapping_add(1),
            };
            if next_mask == *xor_mask {
                None
            } else {
                Some(SimFault::Corrupt {
                    write: *write,
                    xor_mask: next_mask,
                })
            }
        }
        SimFault::CrashState { write, state } => {
            let next = state.saturating_add(1).min(3);
            if next == *state {
                None
            } else {
                Some(SimFault::CrashState {
                    write: *write,
                    state: next,
                })
            }
        }
        SimFault::Crash(_) | SimFault::Partition { .. } => None,
    }
}

/// Run the feedback reproduction campaign without cross-campaign state.
///
/// See [`run_feedback_campaign_with_state`] for the stateful variant.
pub fn run_feedback_campaign<W: Workload, O: Oracle>(
    workload: &W,
    oracle: &O,
    base: RunConfig,
    attempts: usize,
) -> Result<CampaignReport, String> {
    run_feedback_campaign_with_state(workload, oracle, base, attempts, None)
}

/// Run the feedback reproduction campaign closing the voided-fault loop.
///
/// Phase 0 finds the first violation with up to `attempts/2` budget.
/// Phase 1 replays the LDFI schedule and feeds voided faults back:
///
/// - voided injections are dropped and their target hashes are suppressed
/// - applied but non-reproducing faults are escalated via [`escalate`]
/// - the original finding's journal is re-solved, filtering hypotheses whose
///   cut intersects the suppressed set, and the schedule is rebuilt
///
///   Every executed run counts toward `runs_executed`. Variants are
///   deterministic via sorted iteration.
pub fn run_feedback_campaign_with_state<W: Workload, O: Oracle>(
    workload: &W,
    oracle: &O,
    base: RunConfig,
    attempts: usize,
    mut state: Option<&mut CampaignPersist>,
) -> Result<CampaignReport, String> {
    if attempts == 0 {
        return Ok(CampaignReport {
            runs_executed: 0,
            distinct_roots: 0,
            findings: Vec::new(),
            variants: Vec::new(),
            monitors: Vec::new(),
            memo_hits: 0,
        });
    }
    let budget = attempts / 2;
    let mut distinct_roots: HashSet<Hash> = HashSet::new();
    let mut findings: Vec<Finding> = Vec::new();
    let mut variants: Vec<String> = Vec::new();
    let mut search_runs: usize = 0;
    let mut base_finding: Option<Finding> = None;

    // Phase 0: budget search.
    let search_budget = if budget == 0 { 1 } else { budget };
    for attempt in 0..search_budget {
        if search_runs >= budget && budget > 0 {
            break;
        }
        let mut config = base.clone();
        config.seed_mut()[0..8].copy_from_slice(&(attempt as u64).to_le_bytes());
        let run = Simulation::new(config.clone(), workload.programs())
            .run()
            .map_err(|error| format!("simulation failed: {error:?}"))?;
        distinct_roots.insert(run.journal.root_hash());
        variants.push(format!("attempt={attempt} policy=feedback-search"));
        search_runs += 1;
        let verdict = oracle.check(&run);
        if verdict.violated {
            let finding = Finding {
                seed: config.seed(),
                run,
                verdict,
            };
            findings.push(finding.clone());
            base_finding = Some(finding);
            break;
        }
        if search_runs >= attempts {
            break;
        }
    }
    // If budget was 0 and we already did one attempt above, adjust search_runs.
    // For attempts ==1, budget==0, we did 1 search attempt; remaining will be 0.
    let Some(finding) = base_finding else {
        return Ok(CampaignReport {
            runs_executed: search_runs,
            distinct_roots: distinct_roots.len(),
            findings,
            variants,
            monitors: Vec::new(),
            memo_hits: 0,
        });
    };
    let remaining = attempts.saturating_sub(search_runs);
    if remaining == 0 {
        return Ok(CampaignReport {
            runs_executed: search_runs,
            distinct_roots: distinct_roots.len(),
            findings,
            variants,
            monitors: Vec::new(),
            memo_hits: 0,
        });
    }

    // Phase 1: feedback loop.
    // Initial schedule from LDFI on the original finding. Shared state
    // pre-warms this solver from prior rounds and stores this round's caches.
    // The canonical run-config hash joins the solver keys, so artifacts
    // persisted under another run config never pre-warm this campaign.
    let run_config_hash =
        canonical_hash(&base).map_err(|error| format!("canonical run-config hash: {error}"))?;
    let cfg = SolverConfig {
        max_horizon: Some(64),
        run_config_hash: Some(run_config_hash),
        ..SolverConfig::default()
    };
    let encoded = encode_hazard(&finding.run.journal, &finding.verdict, &cfg)
        .map_err(|error| format!("ldfi encode: {error}"))?;
    let mut ldfi_solver = select_solver(&cfg, &encoded);
    if let Some(shared) = state.as_deref_mut() {
        shared.resume_into(ldfi_solver.as_mut())?;
    }
    let hypotheses = solve_with(ldfi_solver.as_mut(), &finding.run.journal, &finding.verdict)
        .map_err(|error| format!("ldfi solve: {error}"))?;
    if let Some(shared) = state.as_deref_mut() {
        shared.persist_from(ldfi_solver.as_ref())?;
    }
    let mut schedule: Vec<SimFault> = hypotheses
        .first()
        .map(|hyp| hypothesis_to_schedule(hyp, &finding.run.journal))
        .unwrap_or_default();
    // Deterministic initial sort.
    schedule.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    // Deduplicate deterministically.
    {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut deduped = Vec::new();
        for inj in schedule {
            let key = format!("{inj:?}");
            if seen.insert(key) {
                deduped.push(inj);
            }
        }
        schedule = deduped;
    }

    let mut suppressed: BTreeSet<Hash> = BTreeSet::new();
    let mut voided_sigs: BTreeSet<String> = BTreeSet::new();
    let mut escalated_map: BTreeMap<Hash, SimFault> = BTreeMap::new();
    let mut feedback_executed: usize = 0;

    for round in 0..remaining {
        let report = replay_with_faults(
            workload,
            &finding.run.journal,
            finding.seed,
            finding.run.decisions.clone(),
            schedule.clone(),
        )?;

        let applied = report.applied.clone();
        let voided = report.voided.clone();

        for inj in &voided {
            if let Some(hash) = fault_injection_target(inj) {
                suppressed.insert(hash);
            } else {
                voided_sigs.insert(format!("{inj:?}"));
            }
        }

        let verdict = oracle.check(&report.run);
        let violated = verdict.violated;

        // Escalation for applied but non-reproducing.
        let mut escalated_descs: Vec<String> = Vec::new();
        let mut next_escalated_map = escalated_map.clone();
        if !violated {
            for inj in &applied {
                if let Some(esc) = escalate(inj) {
                    let desc = format!("{}->{}", injection_kind(inj), injection_kind(&esc));
                    escalated_descs.push(desc);
                    if let Some(target) = fault_injection_target(&esc) {
                        next_escalated_map.insert(target, esc);
                    } else if let Some(orig) = fault_injection_target(inj) {
                        next_escalated_map.insert(orig, esc);
                    }
                }
            }
            escalated_descs.sort();
            escalated_descs.dedup();
        }
        let escalated_str = if escalated_descs.is_empty() {
            "none".to_string()
        } else {
            escalated_descs.join(",")
        };
        // Variant describes round and counts; includes suppressed for test visibility.
        variants.push(format!(
            "round={round} applied={} voided={} escalated={escalated_str} suppressed={}",
            applied.len(),
            voided.len(),
            suppressed.len()
        ));
        distinct_roots.insert(report.run.journal.root_hash());
        feedback_executed += 1;

        if violated {
            findings.push(Finding {
                seed: finding.seed,
                run: report.run.clone(),
                verdict,
            });
            break;
        }

        // Re-solve LDFI on original journal, filter hypotheses intersecting suppressed.
        let mut round_solver = select_solver(&cfg, &encoded);
        if let Some(shared) = state.as_deref_mut() {
            shared.resume_into(round_solver.as_mut())?;
        }
        let hyps = solve_with(
            round_solver.as_mut(),
            &finding.run.journal,
            &finding.verdict,
        )
        .map_err(|error| format!("ldfi solve: {error}"))?;
        if let Some(shared) = state.as_deref_mut() {
            shared.persist_from(round_solver.as_ref())?;
        }
        let filtered: Vec<_> = hyps
            .into_iter()
            .filter(|hyp| !hyp.events.iter().any(|event| suppressed.contains(event)))
            .collect();
        let mut next_base_schedule = filtered
            .first()
            .map(|hyp| hypothesis_to_schedule(hyp, &finding.run.journal))
            .unwrap_or_default();

        // Drop suppressed / voided from rebuilt schedule.
        next_base_schedule.retain(|inj| {
            if let Some(hash) = fault_injection_target(inj) {
                !suppressed.contains(&hash)
            } else {
                !voided_sigs.contains(&format!("{inj:?}"))
            }
        });

        // Apply escalations: replace or add.
        let mut next_schedule_vec: Vec<SimFault> = Vec::new();
        let mut seen_targets: BTreeSet<Hash> = BTreeSet::new();
        for inj in next_base_schedule {
            if let Some(hash) = fault_injection_target(&inj) {
                if let Some(esc) = next_escalated_map.get(&hash)
                    && seen_targets.insert(hash)
                {
                    next_schedule_vec.push(esc.clone());
                    continue;
                }
                if seen_targets.contains(&hash) {
                    continue;
                }
                seen_targets.insert(hash);
            }
            next_schedule_vec.push(inj);
        }
        for (hash, esc) in &next_escalated_map {
            let present = next_schedule_vec
                .iter()
                .any(|inj| fault_injection_target(inj) == Some(*hash));
            if !present && !suppressed.contains(hash) {
                next_schedule_vec.push(esc.clone());
            }
        }

        // Deterministic sort and dedup.
        next_schedule_vec.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
        let mut deduped_next: Vec<SimFault> = Vec::new();
        let mut seen_keys: BTreeSet<String> = BTreeSet::new();
        for inj in next_schedule_vec {
            let key = format!("{inj:?}");
            if seen_keys.insert(key) {
                deduped_next.push(inj);
            }
        }
        schedule = deduped_next;
        escalated_map = next_escalated_map;
    }

    Ok(CampaignReport {
        runs_executed: search_runs + feedback_executed,
        distinct_roots: distinct_roots.len(),
        findings,
        variants,
        monitors: Vec::new(),
        memo_hits: 0,
    })
}
