#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, TypedDict

ROOT = Path(__file__).resolve().parent.parent
TERRAFORM_DIR = ROOT / "infra" / "terraform"


class InventoryHost(TypedDict):
    host_alias: str
    ansible_host: str
    ansible_user: str


def _extract_inventory_host(payload: dict[str, Any]) -> InventoryHost:
    if "ansible_inventory" in payload:
        candidate = payload["ansible_inventory"]
        if isinstance(candidate, dict) and "value" in candidate:
            candidate = candidate["value"]
    else:
        candidate = payload

    if not isinstance(candidate, dict):
        raise SystemExit("Terraform output did not contain an ansible_inventory object.")

    required_keys = ("host_alias", "ansible_host", "ansible_user")
    missing = [key for key in required_keys if not isinstance(candidate.get(key), str)]
    if missing:
        raise SystemExit(
            "Terraform ansible_inventory is missing required string fields: "
            + ", ".join(sorted(missing))
        )

    inventory_host: InventoryHost = {key: candidate[key].strip() for key in required_keys}
    if any(not value for value in inventory_host.values()):
        raise SystemExit("Terraform ansible_inventory fields must not be empty.")
    return inventory_host


def _load_terraform_output_json(json_path: Path) -> dict[str, Any]:
    return json.loads(json_path.read_text(encoding="utf-8"))


def load_inventory_from_terraform() -> InventoryHost:
    result = subprocess.run(
        ["terraform", f"-chdir={TERRAFORM_DIR}", "output", "-json"],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(result.stdout)
    return _extract_inventory_host(payload)


def load_inventory_from_json_file(json_path: Path) -> InventoryHost:
    payload = _load_terraform_output_json(json_path)
    return _extract_inventory_host(payload)


def render_inventory_yaml(inventory_host: InventoryHost) -> str:
    host_alias = json.dumps(inventory_host["host_alias"])
    ansible_host = json.dumps(inventory_host["ansible_host"])
    ansible_user = json.dumps(inventory_host["ansible_user"])
    return "\n".join(
        [
            "---",
            "all:",
            "  hosts:",
            f"    {host_alias}:",
            f"      ansible_host: {ansible_host}",
            f"      ansible_user: {ansible_user}",
            "",
        ]
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Render the benchmark-host Ansible inventory from Terraform outputs."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--from-terraform",
        action="store_true",
        help="Read inventory data from terraform output -json in infra/terraform.",
    )
    source.add_argument(
        "--terraform-json",
        type=Path,
        help="Read inventory data from a saved terraform output -json file.",
    )
    args = parser.parse_args()

    if args.from_terraform:
        inventory_host = load_inventory_from_terraform()
    else:
        inventory_host = load_inventory_from_json_file(args.terraform_json)

    sys.stdout.write(render_inventory_yaml(inventory_host))


if __name__ == "__main__":
    main()
