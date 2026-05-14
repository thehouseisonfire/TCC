use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use repo_xtask::benchmark_host_smoke::run_smoke;

#[derive(Debug, Parser)]
#[command(about = "Apply and verify the benchmark-host smoke path for a fresh host.")]
struct Args {
    /// Path to the Ansible inventory.
    #[arg(long)]
    inventory: PathBuf,

    /// Optional Ansible host limit.
    #[arg(long)]
    limit: Option<String>,

    /// Skip convergence and run only the verification playbook.
    #[arg(long)]
    verify_only: bool,
}

fn run() -> Result<()> {
    let args = Args::parse();
    run_smoke(&args.inventory, args.limit.as_deref(), args.verify_only)
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
