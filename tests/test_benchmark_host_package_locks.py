from __future__ import annotations

import re
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
