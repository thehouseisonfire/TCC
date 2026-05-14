use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser};
use repo_xtask::render_benchmark_inventory::{
    InventorySource, load_inventory, render_inventory_yaml,
};

#[derive(Debug, Parser)]
#[command(about = "Render the benchmark-host Ansible inventory from Terraform outputs.")]
struct Cli {
    #[command(flatten)]
    source: Source,
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
struct Source {
    /// Read inventory data from `terraform output -json` in infra/terraform.
    #[arg(long)]
    from_terraform: bool,

    /// Read inventory data from a saved `terraform output -json` file.
    #[arg(long, value_name = "PATH")]
    terraform_json: Option<PathBuf>,
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let source = if cli.source.from_terraform {
        InventorySource::Terraform
    } else {
        InventorySource::JsonFile(
            cli.source
                .terraform_json
                .expect("clap requires one inventory source"),
        )
    };

    let inventory_host = load_inventory(&source)?;
    print!("{}", render_inventory_yaml(&inventory_host)?);
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

    #[test]
    fn render_inventory_cli_reads_saved_terraform_output() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let terraform_output = temp.path().join("terraform-output.json");
        std::fs::write(
            &terraform_output,
            r#"
{
  "ansible_inventory": {
    "sensitive": false,
    "type": [
      "object",
      {
        "ansible_host": "string",
        "ansible_user": "string",
        "host_alias": "string"
      }
    ],
    "value": {
      "host_alias": "tcc2-bench-host",
      "ansible_host": "203.0.113.20",
      "ansible_user": "benchmark"
    }
  }
}
"#
            .trim_start(),
        )?;

        let output = Command::cargo_bin("render-benchmark-inventory")?
            .arg("--terraform-json")
            .arg(&terraform_output)
            .output()?;

        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout)?;
        assert!(stdout.contains("\"tcc2-bench-host\":"));
        assert!(stdout.contains("ansible_host: \"203.0.113.20\""));
        assert!(stdout.contains("ansible_user: \"benchmark\""));

        Ok(())
    }
}
