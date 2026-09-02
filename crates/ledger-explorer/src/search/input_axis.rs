use super::{Finding, SearchError, Workload};
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
/// distributions are sampled via `PbtBridge::sample_energy`, whose typed
/// validation error propagates to the caller.
pub(super) fn draw_inputs(
    generator: &str,
    attempt_seed: Hash,
    dist: Option<&EnergyDistribution>,
) -> Result<Vec<u64>, SearchError> {
    let mut bridge = PbtBridge::new(generator, attempt_seed);
    let mut inputs = Vec::with_capacity(INPUT_AXIS_SAMPLE);
    for _ in 0..INPUT_AXIS_SAMPLE {
        let value = match dist {
            None | Some(EnergyDistribution::Uniform) => bridge.sample_range(0, INPUT_SAMPLE_RANGE),
            Some(ed @ EnergyDistribution::Power { .. }) => {
                bridge.sample_energy(INPUT_SAMPLE_RANGE, ed)?
            }
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
) -> Result<Option<Finding>, SearchError>
where
    W: Workload + ?Sized,
    O: Oracle + ?Sized,
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
) -> Result<Option<Finding>, SearchError>
where
    W: Workload + ?Sized,
    O: Oracle + ?Sized,
{
    for attempt in 0..attempts {
        let attempt_seed = SeedTree::new(base.seed()).derive(&format!("input-axis/{attempt}"));
        let inputs = draw_inputs(generator, attempt_seed, energy)?;
        let workload = workload_template.with_inputs(&inputs);
        let run = Simulation::new(base.clone(), workload.programs()).run()?;
        let verdict = super::effective_verdict(&run, oracle.check(&run));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::SearchError;

    #[test]
    fn draw_is_deterministic_per_attempt_seed() {
        let seed: Hash = [7; 32];
        let first = draw_inputs("gen-a", seed, None).unwrap();
        let second = draw_inputs("gen-a", seed, None).unwrap();
        assert_eq!(
            first, second,
            "the same attempt seed must redraw identically"
        );
        assert_eq!(first.len(), INPUT_AXIS_SAMPLE);
    }

    #[test]
    fn generator_streams_are_independent() {
        let seed: Hash = [7; 32];
        let a = draw_inputs("gen-a", seed, None).unwrap();
        let b = draw_inputs("gen-b", seed, None).unwrap();
        assert_ne!(a, b, "distinct generators must draw distinct streams");
    }

    #[test]
    fn power_energy_validates_the_exponent() {
        let seed: Hash = [7; 32];
        let error = draw_inputs(
            "gen-a",
            seed,
            Some(&EnergyDistribution::Power { exponent: 0.0 }),
        )
        .unwrap_err();
        assert!(matches!(error, SearchError::Pbt(_)));
    }

    #[test]
    fn draws_stay_inside_the_declared_domain() {
        let seed: Hash = [9; 32];
        let inputs = draw_inputs("gen-bounds", seed, None).unwrap();
        assert!(inputs.iter().all(|value| *value < 100));
    }
}
