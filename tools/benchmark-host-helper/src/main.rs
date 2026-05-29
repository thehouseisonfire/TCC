use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Parser;
use serde::Serialize;

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct RelativeLayout {
    ansible_root: &'static str,
    infra_readme_path: &'static str,
    infra_root: &'static str,
    terraform_root: &'static str,
    todo_path: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct TargetInfo {
    os: &'static str,
    provider: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct BenchmarkHostPaths {
    packer_stage: &'static str,
    recommended_stack: [&'static str; 3],
    relative_layout: RelativeLayout,
    repo_root: String,
    target: TargetInfo,
}

#[derive(Debug, Parser)]
#[command(about = "Report the canonical benchmark-host layout for this repository.")]
struct Args {
    #[arg(long)]
    json: bool,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("tools/benchmark-host-helper should live at <repo>/tools/benchmark-host-helper")
        .to_path_buf()
}

fn benchmark_host_paths() -> BenchmarkHostPaths {
    BenchmarkHostPaths {
        packer_stage: "deferred",
        recommended_stack: ["terraform", "ansible", "apt-snapshots"],
        relative_layout: RelativeLayout {
            ansible_root: "infra/ansible",
            infra_readme_path: "infra/README.md",
            infra_root: "infra",
            terraform_root: "infra/terraform",
            todo_path: "TODO2.md",
        },
        repo_root: repo_root().display().to_string(),
        target: TargetInfo {
            os: "ubuntu-24.04",
            provider: "hetzner",
        },
    }
}

fn render_human(payload: &BenchmarkHostPaths) -> String {
    let layout = &payload.relative_layout;
    let target = &payload.target;

    [
        format!("repo_root: {}", payload.repo_root),
        format!("infra_root: {}", layout.infra_root),
        format!("terraform_root: {}", layout.terraform_root),
        format!("ansible_root: {}", layout.ansible_root),
        format!("infra_readme_path: {}", layout.infra_readme_path),
        format!("todo_path: {}", layout.todo_path),
        format!(
            "recommended_stack: {}",
            payload.recommended_stack.join(", ")
        ),
        format!("packer_stage: {}", payload.packer_stage),
        format!("target_provider: {}", target.provider),
        format!("target_os: {}", target.os),
    ]
    .join("\n")
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
    use super::{benchmark_host_paths, repo_root};

    #[test]
    fn benchmark_host_helper_returns_canonical_paths() {
        let payload = benchmark_host_paths();

        assert_eq!(payload.repo_root, repo_root().display().to_string());
        assert_eq!(payload.relative_layout.infra_root, "infra");
        assert_eq!(payload.relative_layout.terraform_root, "infra/terraform");
        assert_eq!(payload.relative_layout.ansible_root, "infra/ansible");
        assert_eq!(payload.relative_layout.infra_readme_path, "infra/README.md");
        assert_eq!(payload.relative_layout.todo_path, "TODO2.md");
        assert_eq!(
            payload.recommended_stack,
            ["terraform", "ansible", "apt-snapshots"]
        );
        assert_eq!(payload.packer_stage, "deferred");
        assert_eq!(payload.target.provider, "hetzner");
        assert_eq!(payload.target.os, "ubuntu-24.04");
    }
}
