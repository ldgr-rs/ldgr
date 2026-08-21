use super::{Finding, Workload};
use crate::oracle::Oracle;
use crate::pbt::{EnergyDistribution, INPUT_SAMPLE_RANGE, PbtBridge};
use ledger_format::Hash;
use ledger_sim::{RunConfig, SeedTree, Simulation};

pub(super) const INPUT_AXIS_SAMPLE: usize = 16;

/// Draw a fresh PBT input sequence for one campaign attempt.
///
/// The attempt seed is derived per attempt, so each attempt samples an
/// independent, reproducible `gen/<generator>` input sequence. When `dist`
/// is `None` or `Uniform`, the uniform modulo path is used; `Power`
/// distributions are sampled via `PbtBridge::sample_energy`, whose exponent
/// validation error propagates to the caller.
pub(super) fn draw_inputs(
    generator: &str,
    attempt_seed: Hash,
    dist: Option<&EnergyDistribution>,
) -> Result<Vec<u64>, String> {
    let mut bridge = PbtBridge::new(generator, attempt_seed);
    let mut inputs = Vec::with_capacity(INPUT_AXIS_SAMPLE);
    for _ in 0..INPUT_AXIS_SAMPLE {
        let value = match dist {
            None | Some(EnergyDistribution::Uniform) => bridge.sample_range(0, INPUT_SAMPLE_RANGE),
            Some(ed @ EnergyDistribution::Power { .. }) => bridge
                .sample_energy(INPUT_SAMPLE_RANGE, ed)
                .map_err(|error| format!("input energy distribution: {error}"))?,
        };
        inputs.push(value);
    }
    Ok(inputs)
}

/// Search the input axis: fix the schedule seed and vary the generated input.
///
/// Each attempt samples a fresh input sequence from the generator's
/// `gen/<name>` stream and rebuilds the workload with those values. The
/// schedule seed stays fixed, so a finding pins `(input, schedule)` jointly.
///
/// The workload must parameterize its inputs by overriding
/// [`Workload::with_inputs`]. Workloads that keep the default identity
/// implementation run identically on every attempt; the search then either
/// finds a violation on the first attempt or never.
pub fn search_input<W, O>(
    workload_template: &W,
    oracle: &O,
    base: RunConfig,
    generator: &str,
    attempts: usize,
) -> Result<Option<Finding>, String>
where
    W: Workload,
    O: Oracle,
{
    search_input_energy(workload_template, oracle, base, generator, None, attempts)
}

/// [`search_input`] with an energy distribution over the sampled inputs.
///
/// When `energy` is `None` or [`EnergyDistribution::Uniform`], inputs use the
/// uniform modulo path; a `Power` distribution biases samples toward one end
/// of the domain (see [`PbtBridge::sample_energy`]) and its exponent
/// validation error propagates to the caller.
pub fn search_input_energy<W, O>(
    workload_template: &W,
    oracle: &O,
    base: RunConfig,
    generator: &str,
    energy: Option<&EnergyDistribution>,
    attempts: usize,
) -> Result<Option<Finding>, String>
where
    W: Workload,
    O: Oracle,
{
    for attempt in 0..attempts {
        let attempt_seed = SeedTree::new(base.seed()).derive(&format!("input-axis/{attempt}"));
        let inputs = draw_inputs(generator, attempt_seed, energy)?;
        let workload = workload_template.with_inputs(&inputs);
        let run = Simulation::new(base.clone(), workload.programs())
            .run()
            .map_err(|error| format!("simulation failed: {error:?}"))?;
        let verdict = oracle.check(&run);
        if verdict.violated {
            return Ok(Some(Finding {
                seed: attempt_seed,
                run,
                verdict,
            }));
        }
    }
    Ok(None)
}
