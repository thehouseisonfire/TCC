use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::Parser;

#[derive(Debug, Clone, Parser, Eq, PartialEq)]
#[command(about = "Build benchmark prerequisites and run the MQTT benchmark scenarios.")]
pub struct Cli {
    #[arg(long)]
    pub skip_build: bool,

    #[arg(long)]
    pub skip_tokens: bool,

    #[arg(long)]
    pub scenarios: Option<String>,

    #[arg(long)]
    pub clients: Option<String>,

    #[arg(long)]
    pub messages: Option<String>,

    #[arg(long)]
    pub qos: Option<String>,

    #[arg(long)]
    pub tls: bool,

    #[arg(long)]
    pub tls_insecure: bool,

    #[arg(long)]
    pub tls_ca_file: Option<String>,

    #[arg(long)]
    pub token_issuer_no_default_roles: bool,

    #[arg(long)]
    pub token_issuer_no_default_grants: bool,

    #[arg(long)]
    pub biscuit_base64url: bool,

    #[arg(long)]
    pub token_refresh_codes: Option<String>,

    #[arg(long)]
    pub client_topology: Option<String>,

    #[arg(long)]
    pub client_memory: Option<String>,

    #[arg(long)]
    pub client_cpus: Option<String>,

    #[arg(long)]
    pub compose_bin: Option<String>,

    #[arg(long)]
    pub no_cleanup: bool,

    #[arg(long, default_value = "INFO")]
    pub log_level: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct CommandSpec {
    program: String,
    args: Vec<String>,
    cwd: PathBuf,
    env: BTreeMap<String, String>,
}

impl CommandSpec {
    fn status(&self) -> Result<()> {
        let mut command = Command::new(&self.program);
        command.args(&self.args).current_dir(&self.cwd);
        if !self.env.is_empty() {
            command.envs(&self.env);
        }

        let status = command.status().with_context(|| {
            format!(
                "failed to start command in {}: {} {}",
                self.cwd.display(),
                self.program,
                self.args.join(" ")
            )
        })?;

        if !status.success() {
            bail!(
                "command exited with {}: {} {}",
                status,
                self.program,
                self.args.join(" ")
            );
        }

        Ok(())
    }

    fn quiet_status(&self) {
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .current_dir(&self.cwd)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if !self.env.is_empty() {
            command.envs(&self.env);
        }
        let _ = command.status();
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct RuntimePlan {
    cleanup: CommandSpec,
    build: Option<CommandSpec>,
    generate_tokens: Option<CommandSpec>,
    run_scenarios: CommandSpec,
}

struct CleanupGuard {
    cleanup: Option<CommandSpec>,
}

impl CleanupGuard {
    fn new(cleanup: CommandSpec, enabled: bool) -> Self {
        Self {
            cleanup: enabled.then_some(cleanup),
        }
    }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if let Some(cleanup) = &self.cleanup {
            eprintln!("Cleaning up Docker services...");
            cleanup.quiet_status();
        }
    }
}

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("tools/run-benchmarks should live at <repo>/tools/run-benchmarks")
        .to_path_buf()
}

pub fn benchmark_workdir() -> PathBuf {
    repo_root().join("mqtt-auth-biscuit")
}

pub fn compose_files(tls: bool) -> Vec<&'static str> {
    let mut files = vec!["docker/docker-compose.yml"];
    if tls {
        files.push("docker/docker-compose.tls.yml");
    }
    files
}

pub fn compose_args(files: &[&str]) -> Vec<String> {
    let mut args = Vec::with_capacity(files.len() * 2);
    for file in files {
        args.push("-f".to_owned());
        args.push((*file).to_owned());
    }
    args
}

pub fn scenario_args(cli: &Cli) -> Vec<String> {
    let mut args = Vec::new();

    if let Some(scenarios) = &cli.scenarios {
        args.push("--scenarios-arg".to_owned());
        args.push(scenarios.clone());
    }
    if let Some(clients) = &cli.clients {
        args.push("--clients".to_owned());
        args.push(clients.clone());
    }
    if let Some(messages) = &cli.messages {
        args.push("--messages".to_owned());
        args.push(messages.clone());
    }
    if let Some(qos) = &cli.qos {
        args.push("--qos".to_owned());
        args.push(qos.clone());
    }
    if cli.tls {
        args.push("--tls".to_owned());
    }
    if cli.tls_insecure {
        args.push("--tls-insecure".to_owned());
    }
    if let Some(tls_ca_file) = &cli.tls_ca_file {
        args.push("--tls-ca-file".to_owned());
        args.push(tls_ca_file.clone());
    }
    if cli.token_issuer_no_default_roles {
        args.push("--token-issuer-no-default-roles".to_owned());
    }
    if cli.token_issuer_no_default_grants {
        args.push("--token-issuer-no-default-grants".to_owned());
    }
    if cli.biscuit_base64url {
        args.push("--biscuit-base64url".to_owned());
    }
    if let Some(token_refresh_codes) = &cli.token_refresh_codes {
        args.push("--token-refresh-codes".to_owned());
        args.push(token_refresh_codes.clone());
    }
    if let Some(client_topology) = &cli.client_topology {
        args.push("--client-topology".to_owned());
        args.push(client_topology.clone());
    }
    if let Some(client_memory) = &cli.client_memory {
        args.push("--client-memory".to_owned());
        args.push(client_memory.clone());
    }
    if let Some(client_cpus) = &cli.client_cpus {
        args.push("--client-cpus".to_owned());
        args.push(client_cpus.clone());
    }

    args
}

pub fn detect_compose_command(override_cmd: Option<&str>) -> Result<Vec<String>> {
    if let Some(override_cmd) = override_cmd {
        let parsed = shlex::split(override_cmd)
            .ok_or_else(|| anyhow::anyhow!("failed to parse --compose-bin: {override_cmd}"))?;
        if parsed.is_empty() {
            bail!("--compose-bin must not be empty");
        }
        return Ok(parsed);
    }

    if command_exists("docker") && docker_compose_supported() {
        return Ok(vec!["docker".to_owned(), "compose".to_owned()]);
    }
    if command_exists("docker-compose") {
        return Ok(vec!["docker-compose".to_owned()]);
    }

    bail!("Docker Compose not found. Install docker compose or docker-compose.")
}

fn command_exists(program: &str) -> bool {
    let paths = match std::env::var_os("PATH") {
        Some(paths) => paths,
        None => return false,
    };

    std::env::split_paths(&paths).any(|path| executable_path(&path, program).is_file())
}

fn executable_path(dir: &Path, program: &str) -> PathBuf {
    if cfg!(windows) && !program.contains('.') {
        dir.join(format!("{program}.exe"))
    } else {
        dir.join(program)
    }
}

fn docker_compose_supported() -> bool {
    Command::new("docker")
        .args(["compose", "version"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn unix_time_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH")?
        .as_secs())
}

fn run_scenarios_env(compose_cmd: &[String]) -> BTreeMap<String, String> {
    BTreeMap::from([("DOCKER_COMPOSE_BIN".to_owned(), compose_cmd.join(" "))])
}

fn plan_command(
    program: impl Into<String>,
    args: impl IntoIterator<Item = impl Into<String>>,
    cwd: &Path,
    env: BTreeMap<String, String>,
) -> CommandSpec {
    CommandSpec {
        program: program.into(),
        args: args.into_iter().map(Into::into).collect(),
        cwd: cwd.to_path_buf(),
        env,
    }
}

fn build_runtime_plan(cli: &Cli, now: u64, compose_cmd: &[String]) -> RuntimePlan {
    let workdir = benchmark_workdir();
    let compose_files = compose_files(cli.tls);
    let cleanup = plan_command(
        &compose_cmd[0],
        compose_cmd[1..]
            .iter()
            .map(String::as_str)
            .chain(compose_args(&compose_files).iter().map(String::as_str))
            .chain(["down"]),
        &workdir,
        BTreeMap::new(),
    );

    let build = (!cli.skip_build).then(|| {
        plan_command(
            "cargo",
            [
                "build",
                "--locked",
                "--release",
                "-p",
                "mosquitto-auth-biscuit",
            ],
            &workdir,
            BTreeMap::new(),
        )
    });

    let generate_tokens = (!cli.skip_tokens).then(|| {
        plan_command(
            "cargo",
            ["run", "--locked", "-p", "gen-tokens", "--bin", "gen-tokens"],
            &workdir,
            BTreeMap::from([("GEN_TOKENS_FIXED_NOW".to_owned(), now.to_string())]),
        )
    });

    let run_scenarios = plan_command(
        "uv",
        [
            "run",
            "--locked",
            "python",
            "-m",
            "benchmarks.run_scenarios",
        ]
        .into_iter()
        .map(str::to_owned)
        .chain(scenario_args(cli))
        .collect::<Vec<_>>(),
        &workdir,
        run_scenarios_env(compose_cmd),
    );

    RuntimePlan {
        cleanup,
        build,
        generate_tokens,
        run_scenarios,
    }
}

fn ensure_workdir() -> Result<PathBuf> {
    let workdir = benchmark_workdir();
    if !workdir.is_dir() {
        bail!(
            "Expected mqtt-auth-biscuit directory at {}",
            workdir.display()
        );
    }
    Ok(workdir)
}

fn ensure_required_command(command: &str) -> Result<()> {
    if command_exists(command) {
        return Ok(());
    }
    bail!("Missing required command: {command}");
}

pub fn run(cli: &Cli) -> Result<()> {
    let _ = &cli.log_level;
    let _ = ensure_workdir()?;
    ensure_required_command("cargo")?;
    ensure_required_command("uv")?;

    let compose_cmd = detect_compose_command(cli.compose_bin.as_deref())?;
    eprintln!("Using docker compose: {}", compose_cmd.join(" "));

    let plan = build_runtime_plan(cli, unix_time_secs()?, &compose_cmd);
    let _cleanup = CleanupGuard::new(plan.cleanup.clone(), !cli.no_cleanup);

    if let Some(build) = &plan.build {
        eprintln!("Building plugin...");
        build.status()?;
    } else {
        eprintln!("Skipping build (per --skip-build)");
    }

    if let Some(generate_tokens) = &plan.generate_tokens {
        eprintln!("Generating tokens...");
        generate_tokens.status()?;
    } else {
        eprintln!("Skipping token generation (per --skip-tokens)");
    }

    eprintln!("Running scenarios...");
    plan.run_scenarios.status()
}

#[cfg(test)]
mod tests {
    use super::{
        Cli, benchmark_workdir, build_runtime_plan, compose_args, compose_files,
        detect_compose_command, repo_root, scenario_args,
    };

    #[test]
    fn repo_paths_point_at_expected_locations() {
        assert!(repo_root().join("Cargo.toml").is_file());
        assert_eq!(benchmark_workdir(), repo_root().join("mqtt-auth-biscuit"));
    }

    #[test]
    fn compose_helpers_build_expected_file_args() {
        assert_eq!(compose_files(false), vec!["docker/docker-compose.yml"]);
        assert_eq!(
            compose_files(true),
            vec!["docker/docker-compose.yml", "docker/docker-compose.tls.yml"]
        );
        assert_eq!(
            compose_args(&compose_files(true)),
            vec![
                "-f".to_owned(),
                "docker/docker-compose.yml".to_owned(),
                "-f".to_owned(),
                "docker/docker-compose.tls.yml".to_owned()
            ]
        );
    }

    #[test]
    fn compose_override_is_shell_split() -> anyhow::Result<()> {
        assert_eq!(
            detect_compose_command(Some("docker compose"))?,
            vec!["docker".to_owned(), "compose".to_owned()]
        );
        assert_eq!(
            detect_compose_command(Some("podman-compose --env-file env.txt"))?,
            vec![
                "podman-compose".to_owned(),
                "--env-file".to_owned(),
                "env.txt".to_owned()
            ]
        );
        Ok(())
    }

    #[test]
    fn scenario_args_forward_supported_flags() {
        let cli = Cli {
            skip_build: false,
            skip_tokens: false,
            scenarios: Some("TOKEN-BASELINE-JWT".to_owned()),
            clients: Some("10".to_owned()),
            messages: Some("25".to_owned()),
            qos: Some("1".to_owned()),
            tls: true,
            tls_insecure: true,
            tls_ca_file: Some("ca.pem".to_owned()),
            token_issuer_no_default_roles: true,
            token_issuer_no_default_grants: true,
            biscuit_base64url: true,
            token_refresh_codes: Some("204,500".to_owned()),
            client_topology: Some("container-per-client".to_owned()),
            client_memory: Some("96m".to_owned()),
            client_cpus: Some("0.5".to_owned()),
            compose_bin: None,
            no_cleanup: false,
            log_level: "INFO".to_owned(),
        };

        assert_eq!(
            scenario_args(&cli),
            vec![
                "--scenarios-arg".to_owned(),
                "TOKEN-BASELINE-JWT".to_owned(),
                "--clients".to_owned(),
                "10".to_owned(),
                "--messages".to_owned(),
                "25".to_owned(),
                "--qos".to_owned(),
                "1".to_owned(),
                "--tls".to_owned(),
                "--tls-insecure".to_owned(),
                "--tls-ca-file".to_owned(),
                "ca.pem".to_owned(),
                "--token-issuer-no-default-roles".to_owned(),
                "--token-issuer-no-default-grants".to_owned(),
                "--biscuit-base64url".to_owned(),
                "--token-refresh-codes".to_owned(),
                "204,500".to_owned(),
                "--client-topology".to_owned(),
                "container-per-client".to_owned(),
                "--client-memory".to_owned(),
                "96m".to_owned(),
                "--client-cpus".to_owned(),
                "0.5".to_owned(),
            ]
        );
    }

    #[test]
    fn runtime_plan_matches_previous_python_flow() {
        let cli = Cli {
            skip_build: true,
            skip_tokens: false,
            scenarios: Some("TOKEN-BASELINE-JWT".to_owned()),
            clients: None,
            messages: None,
            qos: None,
            tls: true,
            tls_insecure: false,
            tls_ca_file: None,
            token_issuer_no_default_roles: false,
            token_issuer_no_default_grants: false,
            biscuit_base64url: false,
            token_refresh_codes: None,
            client_topology: None,
            client_memory: None,
            client_cpus: None,
            compose_bin: None,
            no_cleanup: false,
            log_level: "INFO".to_owned(),
        };

        let compose_cmd = vec!["docker".to_owned(), "compose".to_owned()];
        let plan = build_runtime_plan(&cli, 1_717_171_717, &compose_cmd);

        assert!(plan.build.is_none());
        assert_eq!(
            plan.cleanup.args,
            vec![
                "compose".to_owned(),
                "-f".to_owned(),
                "docker/docker-compose.yml".to_owned(),
                "-f".to_owned(),
                "docker/docker-compose.tls.yml".to_owned(),
                "down".to_owned()
            ]
        );

        let generate_tokens = plan.generate_tokens.expect("token generation step");
        assert_eq!(
            generate_tokens.args,
            vec![
                "run".to_owned(),
                "--locked".to_owned(),
                "-p".to_owned(),
                "gen-tokens".to_owned(),
                "--bin".to_owned(),
                "gen-tokens".to_owned()
            ]
        );
        assert_eq!(
            generate_tokens.env.get("GEN_TOKENS_FIXED_NOW"),
            Some(&"1717171717".to_owned())
        );

        assert_eq!(
            plan.run_scenarios.args,
            vec![
                "run".to_owned(),
                "--locked".to_owned(),
                "python".to_owned(),
                "-m".to_owned(),
                "benchmarks.run_scenarios".to_owned(),
                "--scenarios-arg".to_owned(),
                "TOKEN-BASELINE-JWT".to_owned(),
                "--tls".to_owned()
            ]
        );
        assert_eq!(
            plan.run_scenarios.env.get("DOCKER_COMPOSE_BIN"),
            Some(&"docker compose".to_owned())
        );
    }
}
