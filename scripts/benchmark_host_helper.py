#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import TypedDict


class RelativeLayout(TypedDict):
    infra_root: str
    terraform_root: str
    ansible_root: str
    infra_readme_path: str
    todo_path: str


class TargetInfo(TypedDict):
    provider: str
    os: str


class BenchmarkHostPaths(TypedDict):
    repo_root: str
    relative_layout: RelativeLayout
    recommended_stack: list[str]
    packer_stage: str
    target: TargetInfo


def benchmark_host_paths() -> BenchmarkHostPaths:
    repo_root = Path(__file__).resolve().parent.parent
    relative_layout: RelativeLayout = {
        "infra_root": "infra",
        "terraform_root": "infra/terraform",
        "ansible_root": "infra/ansible",
        "infra_readme_path": "infra/README.md",
        "todo_path": "TODO2.md",
    }
    return {
        "repo_root": str(repo_root),
        "relative_layout": relative_layout,
        "recommended_stack": ["terraform", "ansible", "apt-snapshots"],
        "packer_stage": "deferred",
        "target": {
            "provider": "hetzner",
            "os": "ubuntu-24.04",
        },
    }


def _render_human(payload: BenchmarkHostPaths) -> str:
    relative_layout = payload["relative_layout"]
    target = payload["target"]
    lines = [
        f"repo_root: {payload['repo_root']}",
        f"infra_root: {relative_layout['infra_root']}",
        f"terraform_root: {relative_layout['terraform_root']}",
        f"ansible_root: {relative_layout['ansible_root']}",
        f"infra_readme_path: {relative_layout['infra_readme_path']}",
        f"todo_path: {relative_layout['todo_path']}",
        "recommended_stack: " + ", ".join(payload["recommended_stack"]),
        f"packer_stage: {payload['packer_stage']}",
        f"target_provider: {target['provider']}",
        f"target_os: {target['os']}",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Report the canonical benchmark-host layout for this repository."
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = parser.parse_args()

    payload = benchmark_host_paths()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(_render_human(payload))


if __name__ == "__main__":
    main()
