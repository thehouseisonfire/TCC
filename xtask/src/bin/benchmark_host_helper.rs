use anyhow::Result;
use clap::Parser;
use repo_xtask::benchmark_host_helper::{benchmark_host_paths, render_human};

#[derive(Debug, Parser)]
#[command(about = "Report the canonical benchmark-host layout for this repository.")]
struct Args {
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

fn run() -> Result<()> {
    let args = Args::parse();
    let payload = benchmark_host_paths();

    if args.json {
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!("{}", render_human(&payload));
    }

    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use assert_cmd::Command;
    use serde_json::Value;

    #[test]
    fn benchmark_host_helper_json_cli_reports_expected_layout() -> anyhow::Result<()> {
        let output = Command::cargo_bin("benchmark-host-helper")?
            .arg("--json")
            .output()?;

        assert!(output.status.success());
        let payload: Value = serde_json::from_slice(&output.stdout)?;
        let relative_layout = &payload["relative_layout"];

        assert_eq!(relative_layout["terraform_root"], "infra/terraform");
        assert_eq!(relative_layout["ansible_root"], "infra/ansible");
        assert_eq!(relative_layout["infra_readme_path"], "infra/README.md");
        assert_eq!(relative_layout["todo_path"], "TODO2.md");
        assert_eq!(
            payload["recommended_stack"],
            serde_json::json!(["terraform", "ansible", "apt-snapshots"])
        );
        assert_eq!(payload["packer_stage"], "deferred");

        Ok(())
    }
}
