#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def check_pyproject() -> None:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    project = data["project"]
    if project.get("requires-python") != "==3.14.2":
        fail("pyproject.toml must pin requires-python to ==3.14.2")
    for dep in project.get("dependencies", []):
        if "==" not in dep:
            fail(f"pyproject.toml has unpinned dependency: {dep}")
    for dep in data.get("dependency-groups", {}).get("dev", []):
        if "==" not in dep:
            fail(f"pyproject.toml has unpinned dev dependency: {dep}")


def check_requirements() -> None:
    pattern = re.compile(r"^[A-Za-z0-9_.\-\[\]]+==[^ ;]+(?: ; .+)?$")
    for line in (ROOT / "requirements.txt").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not pattern.match(line):
            fail(f"requirements.txt has an unpinned entry: {line}")


def check_cargo() -> None:
    cargo_files = [
        ROOT / "mqtt-auth-biscuit" / "crates" / "authz-server" / "Cargo.toml",
        ROOT / "mqtt-auth-biscuit" / "crates" / "benchmarks" / "Cargo.toml",
        ROOT / "mqtt-auth-biscuit" / "crates" / "mosquitto-plugin" / "Cargo.toml",
        ROOT / "mqtt-auth-biscuit" / "crates" / "token-issuer" / "Cargo.toml",
    ]
    for path in cargo_files:
        data = tomllib.loads(path.read_text())
        package = data["package"]
        if package.get("rust-version") != "1.93.1":
            fail(f"{path} must pin rust-version to 1.93.1")
        for name, spec in data.get("dependencies", {}).items():
            version = spec if isinstance(spec, str) else spec.get("version")
            if version is None or not version.startswith("="):
                fail(f"{path} has unpinned dependency {name}: {version!r}")


def check_docker_refs() -> None:
    docker_files = [
        ROOT / "mqtt-auth-biscuit" / "docker" / "Dockerfile.mosquitto.custom",
        ROOT / "mqtt-auth-biscuit" / "docker" / "Dockerfile.mosquitto",
        ROOT / "mqtt-auth-biscuit" / "docker" / "Dockerfile.tcpdump",
        ROOT / "mqtt-auth-biscuit" / "docker" / "Dockerfile.netem",
        ROOT / "mqtt-auth-biscuit" / "docker" / "Dockerfile.token-issuer",
        ROOT / "mqtt-auth-biscuit" / "docker" / "Dockerfile.authz",
        ROOT / "mqtt-auth-biscuit" / "docker" / "docker-compose.yml",
    ]
    for path in docker_files:
        for raw_line in path.read_text().splitlines():
            line = raw_line.strip()
            if line.startswith("FROM ") and "@sha256:" not in line:
                fail(f"{path} has unpinned base image: {line}")
            if (
                line.startswith("image:")
                and "mosquitto:2.1.3-custom" not in line
                and "@sha256:" not in line
            ):
                fail(f"{path} has unpinned runtime image: {line}")
            if "apk add --no-cache" in line:
                pkg_text = line.split("apk add --no-cache", 1)[1].strip()
                pkgs = [pkg for pkg in pkg_text.split() if not pkg.startswith("-")]
                for pkg in pkgs:
                    if "=" not in pkg:
                        fail(f"{path} has unpinned apk package: {pkg}")


def check_workflows() -> None:
    sha_ref = re.compile(r"uses:\s+[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")
    for path in (ROOT / ".github" / "workflows").glob("*.yml"):
        text = path.read_text()
        if "ubuntu-latest" in text:
            fail(f"{path} still uses ubuntu-latest")
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if line.startswith("uses:") and not sha_ref.match(line):
                fail(f"{path} has unpinned action ref: {line}")
            if line.startswith("python-version:"):
                version = line.split(":", 1)[1].strip().strip("'\"")
                if not re.fullmatch(r"\d+\.\d+\.\d+", version):
                    fail(f"{path} has non-exact python-version: {line}")
            if line.startswith("toolchain:"):
                toolchain = line.split(":", 1)[1].strip().strip("'\"")
                if toolchain in {"stable", "nightly"}:
                    fail(f"{path} has floating toolchain: {line}")


def check_terraform() -> None:
    versions_path = ROOT / "infra" / "terraform" / "versions.tf"
    if not versions_path.is_file():
        fail("infra/terraform/versions.tf is missing")

    versions_text = versions_path.read_text()
    if 'required_version = "= 1.13.5"' not in versions_text:
        fail("infra/terraform/versions.tf must pin Terraform to = 1.13.5")
    if 'source  = "hetznercloud/hcloud"' not in versions_text:
        fail("infra/terraform/versions.tf must use the hetznercloud/hcloud provider")
    if 'version = "= 1.60.1"' not in versions_text:
        fail("infra/terraform/versions.tf must pin hcloud to = 1.60.1")

    lock_path = ROOT / "infra" / "terraform" / ".terraform.lock.hcl"
    if not lock_path.is_file():
        fail("infra/terraform/.terraform.lock.hcl is missing")

    tfvars_example = ROOT / "infra" / "terraform" / "terraform.tfvars.example"
    if not tfvars_example.is_file():
        fail("infra/terraform/terraform.tfvars.example is missing")

    tfvars_text = tfvars_example.read_text()
    secret_patterns = [
        re.compile(r"HCLOUD_TOKEN"),
        re.compile(r"(?im)^\s*(?:token|api_token|secret|password|private_key)\s*="),
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ]
    for pattern in secret_patterns:
        if pattern.search(tfvars_text):
            fail("infra/terraform/terraform.tfvars.example must not contain secrets")


def main() -> None:
    check_pyproject()
    check_requirements()
    check_cargo()
    check_docker_refs()
    check_workflows()
    check_terraform()
    print("Pinned dependency audit passed.")


if __name__ == "__main__":
    main()
