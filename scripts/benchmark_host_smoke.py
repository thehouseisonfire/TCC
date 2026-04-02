#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ANSIBLE_DIR = ROOT / "infra" / "ansible"


def _ansible_playbook_command(
    inventory: Path,
    playbook: str,
    *,
    limit: str | None = None,
) -> list[str]:
    command = ["uv", "run", "--locked", "--group", "dev", "ansible-playbook"]
    command.extend(["-i", str(inventory), playbook])
    if limit:
        command.extend(["--limit", limit])
    return command


def run_smoke(
    inventory: Path,
    *,
    limit: str | None = None,
    verify_only: bool = False,
) -> None:
    inventory_path = inventory.resolve()
    if not verify_only:
        subprocess.run(
            _ansible_playbook_command(inventory_path, "playbook.yml", limit=limit),
            cwd=ANSIBLE_DIR,
            check=True,
        )
    subprocess.run(
        _ansible_playbook_command(inventory_path, "verify.yml", limit=limit),
        cwd=ANSIBLE_DIR,
        check=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Apply and verify the benchmark-host smoke path for a fresh host."
    )
    parser.add_argument(
        "--inventory",
        type=Path,
        required=True,
        help="Path to the Ansible inventory.",
    )
    parser.add_argument("--limit", help="Optional Ansible host limit.")
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Skip convergence and run only the verification playbook.",
    )
    args = parser.parse_args()

    run_smoke(args.inventory, limit=args.limit, verify_only=args.verify_only)


if __name__ == "__main__":
    main()
