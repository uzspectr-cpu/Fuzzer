mod config;
mod corpus;
mod generator;
mod executor;
mod snapshot;
mod oracle;
mod shrink;
mod report;

use anyhow::Result;
use clap::Parser;
use config::Config;

fn main() -> Result<()> {
    let cfg = Config::parse();
    env_logger_init(&cfg);

    println!("[pcif] Page-Cache Integrity Fuzzer");
    println!("[pcif] seed={} iters={} workers={}",
        cfg.seed, cfg.iterations, cfg.workers);

    let mut global = corpus::Corpus::new(&cfg)?;
    let mut found: Vec<report::Finding> = Vec::new();

    for iter in 0..cfg.iterations {
        let program = generator::generate(&cfg, iter);
        if cfg.verbose {
            eprintln!("[pcif] iter={} prog={:?}", iter, program);
        }

        match executor::run(&cfg, &program) {
            Ok(trace) => {
                if let Some(finding) = oracle::check(&cfg, &program, &trace) {
                    eprintln!("[pcif] FINDING iter={} kind={:?}", iter, finding.kind);
                    let minimized = shrink::minimize(&cfg, program.clone(), finding.clone());
                    found.push(minimized.clone());
                    report::write_finding(&cfg, &minimized)?;
                    global.add(minimized.program.clone());
                } else {
                    global.add(program);
                }
            }
            Err(e) => {
                if cfg.verbose {
                    eprintln!("[pcif] exec err iter={}: {}", iter, e);
                }
            }
        }

        if iter % 1000 == 0 && iter > 0 {
            eprintln!("[pcif] iter={} corpus={} findings={}",
                iter, global.len(), found.len());
        }
    }

    report::write_summary(&cfg, &found)?;
    Ok(())
}

fn env_logger_init(_cfg: &Config) {}
