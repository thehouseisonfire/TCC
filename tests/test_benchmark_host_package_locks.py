from __future__ import annotations

import re
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_snapshot_id_and_package_locks_are_repo_pinned() -> None:
    benchmark_host_vars = yaml.safe_load(
        (ROOT / "infra" / "ansible" / "group_vars" / "all" / "benchmark_host.yml").read_text(
            encoding="utf-8"
        )
    )
    package_locks = yaml.safe_load(
        (ROOT / "infra" / "ansible" / "group_vars" / "all" / "package_locks.yml").read_text(
            encoding="utf-8"
        )
    )

    assert re.fullmatch(r"\d{8}T\d{6}Z", benchmark_host_vars["benchmark_host_snapshot_id"])
    assert benchmark_host_vars["benchmark_host_operator_user"] == "benchmark"

    assert package_locks["benchmark_host_base_package_versions"] == {
        "ca-certificates": "20240203",
        "curl": "8.5.0-2ubuntu10.3",
        "git": "1:2.43.0-1ubuntu7.1",
        "jq": "1.7.1-3build1",
    }
    assert package_locks["benchmark_host_docker_package_versions"] == {
        "docker.io": "24.0.7-0ubuntu4.1",
        "docker-compose-v2": "2.24.6+ds1-0ubuntu2",
    }


def test_benchmark_toolchain_pins_match_repo_contract() -> None:
    benchmark_toolchain = yaml.safe_load(
        (ROOT / "infra" / "ansible" / "group_vars" / "all" / "benchmark_toolchain.yml").read_text(
            encoding="utf-8"
        )
    )
    rust_toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))
    python_version = (ROOT / ".python-version").read_text(encoding="utf-8").strip()
    benchmark_docs = (ROOT / "mqtt-auth-biscuit" / "README.md").read_text(encoding="utf-8")

    assert benchmark_toolchain["benchmark_host_python_version"] == python_version
    assert (
        benchmark_toolchain["benchmark_host_rust_toolchain"]
        == rust_toolchain["toolchain"]["channel"]
    )
    assert (
        benchmark_toolchain["benchmark_host_rust_components"]
        == rust_toolchain["toolchain"]["components"]
    )
    assert benchmark_toolchain["benchmark_host_uv_version"] == "0.9.17"
    assert "Python 3.14.2 + `uv 0.9.17`" in benchmark_docs
