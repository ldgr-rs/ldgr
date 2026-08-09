use ldgr::config::{Policy, RunConfig};
use ldgr::explorer::search;
use ldgr::ldfi::suggest_cut;
use ldgr::oracle::LinearizabilityOracle;
use ldgr::workloads::minikv::MiniKv;

fn main() {
    let command = std::env::args().nth(1).unwrap_or_else(|| "sim".to_owned());
    let config = RunConfig {
        seed: [0; 32],
        policy: Policy::Random,
        max_steps: 256,
    };
    let workload = MiniKv;
    let oracle = LinearizabilityOracle;
    match command.as_str() {
        "sim" | "repro" => match search(&workload, &oracle, config, 256) {
            Ok(Some(finding)) => {
                println!("violation: {}", finding.verdict.reason);
                println!("seed: {:02x?}", finding.seed);
                println!("journal root: {:02x?}", finding.run.journal.root_hash());
                println!("steps: {}", finding.run.steps);
            }
            Ok(None) => println!("no violation found"),
            Err(error) => eprintln!("simulation failed: {error}"),
        },
        "ldfi" => match search(&workload, &oracle, config, 256) {
            Ok(Some(finding)) => {
                println!("violation: {}", finding.verdict.reason);
                for cut in suggest_cut(&finding.run.journal, &finding.verdict) {
                    println!(
                        "fault candidate {:02x?}, cost {}",
                        &cut.event[..4],
                        cut.cost
                    );
                }
            }
            Ok(None) => println!("no violation found"),
            Err(error) => eprintln!("simulation failed: {error}"),
        },
        other => eprintln!("unknown command {other}; use sim, repro, or ldfi"),
    }
}
