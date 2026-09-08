import subprocess
import sys
from pathlib import Path

from benchmarks.rust_helpers import resolve_rust_helper as _resolve_rust_helper

REPO_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    completed = subprocess.run(
        _resolve_rust_helper("mqtt-auth-client") + sys.argv[1:],
        cwd=REPO_ROOT,
        check=False,
        text=True,
    )
    raise SystemExit(completed.returncode)


if __name__ == "__main__":
    main()
