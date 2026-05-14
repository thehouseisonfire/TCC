use anyhow::Result;
use clap::Parser;
use repo_run_benchmarks::{Cli, run};

fn main() {
    if let Err(err) = main_impl() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn main_impl() -> Result<()> {
    let cli = Cli::parse();
    run(&cli)
}
