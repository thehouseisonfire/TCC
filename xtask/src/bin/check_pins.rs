use std::path::Path;

use anyhow::{Context, Result, bail};
use regex::Regex;
use repo_xtask::repo_root;
use toml::Value;

fn read_to_string(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))
}

fn parse_toml(path: &Path) -> Result<Value> {
    let text = read_to_string(path)?;
    text.parse::<Value>()
        .with_context(|| format!("failed to parse TOML from {}", path.display()))
}

fn table<'a>(value: &'a Value, key: &str) -> Result<&'a toml::map::Map<String, Value>> {
    value
        .get(key)
        .and_then(Value::as_table)
        .ok_or_else(|| anyhow::anyhow!("missing TOML table: {key}"))
}

fn check_pyproject(root: &Path) -> Result<()> {
    let path = root.join("pyproject.toml");
    let data = parse_toml(&path)?;
    let project = table(&data, "project")?;

    if project.get("requires-python").and_then(Value::as_str) != Some("==3.14.2") {
        bail!("pyproject.toml must pin requires-python to ==3.14.2");
    }

    if let Some(dependencies) = project.get("dependencies").and_then(Value::as_array) {
        for dep in dependencies {
            let dep = dep
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("pyproject.toml dependency must be a string"))?;
            if !dep.contains("==") {
                bail!("pyproject.toml has unpinned dependency: {dep}");
            }
        }
    }

    if let Some(dev_dependencies) = data
        .get("dependency-groups")
        .and_then(Value::as_table)
        .and_then(|groups| groups.get("dev"))
        .and_then(Value::as_array)
    {
        for dep in dev_dependencies {
            let dep = dep
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("pyproject.toml dev dependency must be a string"))?;
            if !dep.contains("==") {
                bail!("pyproject.toml has unpinned dev dependency: {dep}");
            }
        }
    }

    Ok(())
}

fn check_requirements(root: &Path) -> Result<()> {
    let pattern = Regex::new(r"^[A-Za-z0-9_.\-\[\]]+==[^ ;]+(?: ; .+)?$")?;
    let path = root.join("requirements.txt");

    for raw_line in read_to_string(&path)?.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !pattern.is_match(line) {
            bail!("requirements.txt has an unpinned entry: {line}");
        }
    }

    Ok(())
}

fn cargo_dependency_version(spec: &Value) -> Option<&str> {
    match spec {
        Value::String(version) => Some(version.as_str()),
        Value::Table(table) => table.get("version").and_then(Value::as_str),
        _ => None,
    }
}

fn check_cargo(root: &Path) -> Result<()> {
    let cargo_files = [
        root.join("mqtt-auth-biscuit/crates/authz-server/Cargo.toml"),
        root.join("mqtt-auth-biscuit/crates/benchmarks/Cargo.toml"),
        root.join("mqtt-auth-biscuit/crates/mosquitto-plugin/Cargo.toml"),
        root.join("mqtt-auth-biscuit/crates/token-issuer/Cargo.toml"),
    ];

    for path in cargo_files {
        let data = parse_toml(&path)?;
        let package = table(&data, "package")?;
        if package.get("rust-version").and_then(Value::as_str) != Some("1.93.1") {
            bail!("{} must pin rust-version to 1.93.1", path.display());
        }

        if let Some(dependencies) = data.get("dependencies").and_then(Value::as_table) {
            for (name, spec) in dependencies {
                let version = cargo_dependency_version(spec);
                if !version.is_some_and(|version| version.starts_with('=')) {
                    bail!(
                        "{} has unpinned dependency {name}: {:?}",
                        path.display(),
                        version
                    );
                }
            }
        }
    }

    Ok(())
}

fn check_docker_refs(root: &Path) -> Result<()> {
    let docker_files = [
        root.join("mqtt-auth-biscuit/docker/Dockerfile.mosquitto.custom"),
        root.join("mqtt-auth-biscuit/docker/Dockerfile.mosquitto"),
        root.join("mqtt-auth-biscuit/docker/Dockerfile.tcpdump"),
        root.join("mqtt-auth-biscuit/docker/Dockerfile.netem"),
        root.join("mqtt-auth-biscuit/docker/Dockerfile.token-issuer"),
        root.join("mqtt-auth-biscuit/docker/Dockerfile.authz"),
        root.join("mqtt-auth-biscuit/docker/docker-compose.yml"),
    ];

    for path in docker_files {
        for raw_line in read_to_string(&path)?.lines() {
            let line = raw_line.trim();
            if line.starts_with("FROM ") && !line.contains("@sha256:") {
                bail!("{} has unpinned base image: {line}", path.display());
            }
            if line.starts_with("image:")
                && !line.contains("mosquitto:2.1.3-custom")
                && !line.contains("@sha256:")
            {
                bail!("{} has unpinned runtime image: {line}", path.display());
            }
            if let Some((_, pkg_text)) = line.split_once("apk add --no-cache") {
                for pkg in pkg_text
                    .split_whitespace()
                    .filter(|pkg| !pkg.starts_with('-'))
                {
                    if !pkg.contains('=') {
                        bail!("{} has unpinned apk package: {pkg}", path.display());
                    }
                }
            }
        }
    }

    Ok(())
}

fn check_workflows(root: &Path) -> Result<()> {
    let sha_ref = Regex::new(r"^uses:\s+[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")?;
    let exact_version = Regex::new(r"^\d+\.\d+\.\d+$")?;
    let workflows_dir = root.join(".github/workflows");

    if !workflows_dir.is_dir() {
        return Ok(());
    }

    for entry in std::fs::read_dir(&workflows_dir)
        .with_context(|| format!("failed to read {}", workflows_dir.display()))?
    {
        let path = entry?.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("yml") {
            continue;
        }

        let text = read_to_string(&path)?;
        if text.contains("ubuntu-latest") {
            bail!("{} still uses ubuntu-latest", path.display());
        }

        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.starts_with("uses:") && !sha_ref.is_match(line) {
                bail!("{} has unpinned action ref: {line}", path.display());
            }
            if let Some((_, version)) = line.split_once("python-version:") {
                let version = version.trim().trim_matches(['\'', '"']);
                if !exact_version.is_match(version) {
                    bail!("{} has non-exact python-version: {line}", path.display());
                }
            }
            if let Some((_, toolchain)) = line.split_once("toolchain:") {
                let toolchain = toolchain.trim().trim_matches(['\'', '"']);
                if matches!(toolchain, "stable" | "nightly") {
                    bail!("{} has floating toolchain: {line}", path.display());
                }
            }
        }
    }

    Ok(())
}

fn check_terraform(root: &Path) -> Result<()> {
    let versions_path = root.join("infra/terraform/versions.tf");
    if !versions_path.is_file() {
        bail!("infra/terraform/versions.tf is missing");
    }

    let versions_text = read_to_string(&versions_path)?;
    if !versions_text.contains(r#"required_version = "= 1.13.5""#) {
        bail!("infra/terraform/versions.tf must pin Terraform to = 1.13.5");
    }
    if !versions_text.contains(r#"source  = "hetznercloud/hcloud""#) {
        bail!("infra/terraform/versions.tf must use the hetznercloud/hcloud provider");
    }
    if !versions_text.contains(r#"version = "= 1.60.1""#) {
        bail!("infra/terraform/versions.tf must pin hcloud to = 1.60.1");
    }

    let lock_path = root.join("infra/terraform/.terraform.lock.hcl");
    if !lock_path.is_file() {
        bail!("infra/terraform/.terraform.lock.hcl is missing");
    }

    let tfvars_example = root.join("infra/terraform/terraform.tfvars.example");
    if !tfvars_example.is_file() {
        bail!("infra/terraform/terraform.tfvars.example is missing");
    }

    let tfvars_text = read_to_string(&tfvars_example)?;
    let secret_patterns = [
        Regex::new(r"HCLOUD_TOKEN")?,
        Regex::new(r"(?im)^\s*(?:token|api_token|secret|password|private_key)\s*=")?,
        Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")?,
    ];

    if secret_patterns
        .iter()
        .any(|pattern| pattern.is_match(&tfvars_text))
    {
        bail!("infra/terraform/terraform.tfvars.example must not contain secrets");
    }

    Ok(())
}

fn run() -> Result<()> {
    let root = repo_root();
    check_pyproject(&root)?;
    check_requirements(&root)?;
    check_cargo(&root)?;
    check_docker_refs(&root)?;
    check_workflows(&root)?;
    check_terraform(&root)?;
    println!("Pinned dependency audit passed.");
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
