from __future__ import annotations

import json
import subprocess
import sys
from importlib import import_module
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

benchmark_host_paths = import_module("scripts.benchmark_host_helper").benchmark_host_paths


def test_benchmark_host_helper_returns_canonical_paths() -> None:
    payload = benchmark_host_paths()

    assert payload["repo_root"] == str(ROOT)
    assert payload["relative_layout"] == {
        "infra_root": "infra",
        "terraform_root": "infra/terraform",
        "ansible_root": "infra/ansible",
        "infra_readme_path": "infra/README.md",
        "todo_path": "TODO2.md",
    }
    assert payload["recommended_stack"] == ["terraform", "ansible", "apt-snapshots"]
    assert payload["packer_stage"] == "deferred"
    assert payload["target"] == {
        "provider": "hetzner",
        "os": "ubuntu-24.04",
    }


def test_benchmark_host_helper_json_cli_reports_expected_layout() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/benchmark_host_helper.py", "--json"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(result.stdout)
    relative_layout = payload["relative_layout"]

    assert relative_layout["terraform_root"] == "infra/terraform"
    assert relative_layout["ansible_root"] == "infra/ansible"
    assert relative_layout["infra_readme_path"] == "infra/README.md"
    assert relative_layout["todo_path"] == "TODO2.md"
    assert payload["recommended_stack"] == ["terraform", "ansible", "apt-snapshots"]
    assert payload["packer_stage"] == "deferred"
