from __future__ import annotations

import subprocess
import sys
from importlib import import_module
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

render_benchmark_inventory = import_module("scripts.render_benchmark_inventory")


def test_render_inventory_yaml_uses_structured_inventory_fields() -> None:
    rendered = render_benchmark_inventory.render_inventory_yaml(
        {
            "host_alias": "tcc2-bench-host",
            "ansible_host": "198.51.100.10",
            "ansible_user": "benchmark",
        }
    )

    assert '"tcc2-bench-host":' in rendered
    assert 'ansible_host: "198.51.100.10"' in rendered
    assert 'ansible_user: "benchmark"' in rendered


def test_render_inventory_cli_reads_saved_terraform_output(tmp_path: Path) -> None:
    terraform_output = tmp_path / "terraform-output.json"
    terraform_output.write_text(
        """
{
  "ansible_inventory": {
    "sensitive": false,
    "type": [
      "object",
      {
        "ansible_host": "string",
        "ansible_user": "string",
        "host_alias": "string"
      }
    ],
    "value": {
      "host_alias": "tcc2-bench-host",
      "ansible_host": "203.0.113.20",
      "ansible_user": "benchmark"
    }
  }
}
""".strip() + "\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/render_benchmark_inventory.py",
            "--terraform-json",
            str(terraform_output),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert '"tcc2-bench-host":' in result.stdout
    assert 'ansible_host: "203.0.113.20"' in result.stdout
    assert 'ansible_user: "benchmark"' in result.stdout
