use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::repo_root;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AnsibleCommand {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub playbook: String,
}

impl AnsibleCommand {
    pub fn command_line(&self) -> Vec<String> {
        std::iter::once(self.program.clone())
            .chain(self.args.iter().cloned())
            .collect()
    }
}

pub fn ansible_dir() -> PathBuf {
    repo_root().join("infra/ansible")
}

pub fn ansible_playbook_command(
    inventory: &Path,
    playbook: &str,
    limit: Option<&str>,
) -> AnsibleCommand {
    let mut args = vec![
        "run".to_owned(),
        "--locked".to_owned(),
        "--group".to_owned(),
        "dev".to_owned(),
        "ansible-playbook".to_owned(),
        "-i".to_owned(),
        inventory.display().to_string(),
        playbook.to_owned(),
    ];

    if let Some(limit) = limit {
        args.push("--limit".to_owned());
        args.push(limit.to_owned());
    }

    AnsibleCommand {
        program: "uv".to_owned(),
        args,
        cwd: ansible_dir(),
        playbook: playbook.to_owned(),
    }
}

pub fn smoke_command_plan(
    inventory: &Path,
    limit: Option<&str>,
    verify_only: bool,
) -> Result<Vec<AnsibleCommand>> {
    let inventory_path = inventory
        .canonicalize()
        .with_context(|| format!("failed to resolve inventory path {}", inventory.display()))?;

    let mut commands = Vec::new();
    if !verify_only {
        commands.push(ansible_playbook_command(
            &inventory_path,
            "playbook.yml",
            limit,
        ));
    }
    commands.push(ansible_playbook_command(
        &inventory_path,
        "verify.yml",
        limit,
    ));
    Ok(commands)
}

fn run_ansible_command(command: &AnsibleCommand) -> Result<()> {
    let status = Command::new(&command.program)
        .args(&command.args)
        .current_dir(&command.cwd)
        .status()
        .with_context(|| {
            format!(
                "failed to run ansible-playbook from {}",
                command.cwd.display()
            )
        })?;

    if !status.success() {
        bail!("ansible-playbook {} exited with {status}", command.playbook);
    }

    Ok(())
}

pub fn run_smoke(inventory: &Path, limit: Option<&str>, verify_only: bool) -> Result<()> {
    for command in smoke_command_plan(inventory, limit, verify_only)? {
        run_ansible_command(&command)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ansible_dir, smoke_command_plan};

    #[test]
    fn benchmark_host_smoke_runs_converge_then_verify() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let inventory = temp.path().join("inventory.yml");
        std::fs::write(&inventory, "---\nall:\n  hosts: {}\n")?;
        let inventory = inventory.canonicalize()?;

        let calls = smoke_command_plan(&inventory, None, false)?;

        assert_eq!(
            calls
                .iter()
                .map(|call| call.command_line())
                .collect::<Vec<_>>(),
            vec![
                vec![
                    "uv".to_owned(),
                    "run".to_owned(),
                    "--locked".to_owned(),
                    "--group".to_owned(),
                    "dev".to_owned(),
                    "ansible-playbook".to_owned(),
                    "-i".to_owned(),
                    inventory.display().to_string(),
                    "playbook.yml".to_owned(),
                ],
                vec![
                    "uv".to_owned(),
                    "run".to_owned(),
                    "--locked".to_owned(),
                    "--group".to_owned(),
                    "dev".to_owned(),
                    "ansible-playbook".to_owned(),
                    "-i".to_owned(),
                    inventory.display().to_string(),
                    "verify.yml".to_owned(),
                ],
            ]
        );
        assert!(calls.iter().all(|call| call.cwd == ansible_dir()));

        Ok(())
    }

    #[test]
    fn benchmark_host_smoke_verify_only_skips_converge() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let inventory = temp.path().join("inventory.yml");
        std::fs::write(&inventory, "---\nall:\n  hosts: {}\n")?;
        let inventory = inventory.canonicalize()?;

        let calls = smoke_command_plan(&inventory, None, true)?;

        assert_eq!(
            calls
                .iter()
                .map(|call| call.command_line())
                .collect::<Vec<_>>(),
            vec![vec![
                "uv".to_owned(),
                "run".to_owned(),
                "--locked".to_owned(),
                "--group".to_owned(),
                "dev".to_owned(),
                "ansible-playbook".to_owned(),
                "-i".to_owned(),
                inventory.display().to_string(),
                "verify.yml".to_owned(),
            ]]
        );

        Ok(())
    }

    #[test]
    fn benchmark_host_smoke_forwards_limit_to_both_playbooks() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let inventory = temp.path().join("inventory.yml");
        std::fs::write(&inventory, "---\nall:\n  hosts: {}\n")?;
        let inventory = inventory.canonicalize()?;

        let calls = smoke_command_plan(&inventory, Some("tcc2-bench-host"), false)?;

        assert_eq!(
            calls
                .iter()
                .map(|call| call.command_line())
                .collect::<Vec<_>>(),
            vec![
                vec![
                    "uv".to_owned(),
                    "run".to_owned(),
                    "--locked".to_owned(),
                    "--group".to_owned(),
                    "dev".to_owned(),
                    "ansible-playbook".to_owned(),
                    "-i".to_owned(),
                    inventory.display().to_string(),
                    "playbook.yml".to_owned(),
                    "--limit".to_owned(),
                    "tcc2-bench-host".to_owned(),
                ],
                vec![
                    "uv".to_owned(),
                    "run".to_owned(),
                    "--locked".to_owned(),
                    "--group".to_owned(),
                    "dev".to_owned(),
                    "ansible-playbook".to_owned(),
                    "-i".to_owned(),
                    inventory.display().to_string(),
                    "verify.yml".to_owned(),
                    "--limit".to_owned(),
                    "tcc2-bench-host".to_owned(),
                ],
            ]
        );

        Ok(())
    }
}
