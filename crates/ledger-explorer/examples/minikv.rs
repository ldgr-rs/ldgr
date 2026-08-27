//! Mini-KV race exploration and LDFI mitigation example.

use ledger_explorer::ldfi::solve_with;
use ledger_explorer::minimizer::minimize_schedule;
use ledger_explorer::oracle::{HistoryOracle, KeyValueSpec, Oracle};
use ledger_explorer::search::{replay_prefix, search};
use ledger_explorer::solver::HittingSetSolver;
use ledger_explorer::workloads::MiniKvWorkload;
use ledger_sim::{Policy, RunConfig};

fn main() {
    println!("=== Ledger Engine: Mini-KV Race Exploration ===");
    let config = RunConfig::builder()
        .seed([0; 32])
        .policy(Policy::Random)
        .max_steps(256)
        .build();
    let workload = MiniKvWorkload;
    let oracle = HistoryOracle::new(&workload, KeyValueSpec::default());

    println!("1. Searching for race conditions...");
    if let Some(finding) = search(&workload, &oracle, config, 256).unwrap() {
        println!(
            "  [FAIL] Discovered race violation: {}",
            finding.verdict.reason
        );
        println!("  Journal steps: {}", finding.run.steps);

        println!("\n2. Computing LDFI Minimal Hitting Sets...");
        let hypotheses = solve_with(
            &mut HittingSetSolver::new(),
            &finding.run.journal,
            &finding.verdict,
        )
        .expect("solve");
        for (i, hyp) in hypotheses.iter().enumerate() {
            println!(
                "  Cut #{}: {} fault(s), cost={}",
                i + 1,
                hyp.events.len(),
                hyp.total_cost
            );
            println!("    Explanation: {}", hyp.explanation);
        }

        println!("\n3. Minimizing schedule decisions...");
        let report = minimize_schedule(&finding.run.decisions, |d| {
            let r = replay_prefix(&workload, finding.seed, d.to_vec());
            r.as_ref()
                .map(|run| oracle.check(run).violated)
                .unwrap_or(false)
        });
        println!(
            "  Minimizer: {} -> {} decisions ({:.1}% reduction)",
            report.original_count, report.minimized_count, report.reduction_percent
        );
    }
}
