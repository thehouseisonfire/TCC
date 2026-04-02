from __future__ import annotations

import subprocess
import sys
from importlib import import_module
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

benchmark_host_smoke = import_module("scripts.benchmark_host_smoke")


def test_benchmark_host_smoke_runs_converge_then_verify(monkeypatch, tmp_path: Path) -> None:
    inventory = tmp_path / "inventory.yml"
    inventory.write_text("---\nall:\n  hosts: {}\n", encoding="utf-8")
    calls: list[dict[str, object]] = []

    def _fake_run(cmd, cwd, check):  # noqa: ANN001
        calls.append({"cmd": cmd, "cwd": cwd, "check": check})
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(benchmark_host_smoke.subprocess, "run", _fake_run)

    benchmark_host_smoke.run_smoke(inventory)

    assert [call["cmd"] for call in calls] == [
        [
            "uv",
            "run",
            "--locked",
            "--group",
            "dev",
            "ansible-playbook",
            "-i",
            str(inventory.resolve()),
            "playbook.yml",
        ],
        [
            "uv",
            "run",
            "--locked",
            "--group",
            "dev",
            "ansible-playbook",
            "-i",
            str(inventory.resolve()),
            "verify.yml",
        ],
    ]
    assert all(call["cwd"] == benchmark_host_smoke.ANSIBLE_DIR for call in calls)
    assert all(call["check"] is True for call in calls)


def test_benchmark_host_smoke_verify_only_skips_converge(monkeypatch, tmp_path: Path) -> None:
    inventory = tmp_path / "inventory.yml"
    inventory.write_text("---\nall:\n  hosts: {}\n", encoding="utf-8")
    calls: list[list[str]] = []

    def _fake_run(cmd, cwd, check):  # noqa: ANN001
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(benchmark_host_smoke.subprocess, "run", _fake_run)

    benchmark_host_smoke.run_smoke(inventory, verify_only=True)

    assert calls == [
        [
            "uv",
            "run",
            "--locked",
            "--group",
            "dev",
            "ansible-playbook",
            "-i",
            str(inventory.resolve()),
            "verify.yml",
        ]
    ]


def test_benchmark_host_smoke_forwards_limit_to_both_playbooks(
    monkeypatch,
    tmp_path: Path,
) -> None:
    inventory = tmp_path / "inventory.yml"
    inventory.write_text("---\nall:\n  hosts: {}\n", encoding="utf-8")
    calls: list[list[str]] = []

    def _fake_run(cmd, cwd, check):  # noqa: ANN001
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(benchmark_host_smoke.subprocess, "run", _fake_run)

    benchmark_host_smoke.run_smoke(inventory, limit="tcc2-bench-host")

    assert calls == [
        [
            "uv",
            "run",
            "--locked",
            "--group",
            "dev",
            "ansible-playbook",
            "-i",
            str(inventory.resolve()),
            "playbook.yml",
            "--limit",
            "tcc2-bench-host",
        ],
        [
            "uv",
            "run",
            "--locked",
            "--group",
            "dev",
            "ansible-playbook",
            "-i",
            str(inventory.resolve()),
            "verify.yml",
            "--limit",
            "tcc2-bench-host",
        ],
    ]
