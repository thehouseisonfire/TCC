from __future__ import annotations

import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ANSIBLE_DIR = ROOT / "infra" / "ansible"


def test_benchmark_playbook_includes_benchmark_prereqs_role() -> None:
    payload = yaml.safe_load((ANSIBLE_DIR / "playbook.yml").read_text(encoding="utf-8"))
    assert payload[0]["roles"] == ["apt_snapshot", "base", "docker", "benchmark_prereqs"]


def test_benchmark_verify_playbook_covers_baseline_and_benchmark_roles() -> None:
    payload = yaml.safe_load((ANSIBLE_DIR / "verify.yml").read_text(encoding="utf-8"))
    assert payload[0]["roles"] == ["baseline_verify", "benchmark_verify"]


def test_benchmark_ansible_playbooks_pass_syntax_check() -> None:
    for playbook_name in ("playbook.yml", "verify.yml"):
        subprocess.run(
            [
                "uv",
                "run",
                "--locked",
                "--group",
                "dev",
                "ansible-playbook",
                "-i",
                "inventory.example.yml",
                playbook_name,
                "--syntax-check",
            ],
            cwd=ANSIBLE_DIR,
            check=True,
            capture_output=True,
            text=True,
        )
