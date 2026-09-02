from pathlib import Path

from benchmarks import run_scenarios as rs

REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_documented_scenario_inventory_matches_registry() -> None:
    tokens = rs._read_tokens(str(PROJECT_ROOT / "benchmarks/tokens.json"))
    base = rs._build_available_scenarios(
        tokens,
        token_issuer_no_default_roles=False,
        token_issuer_no_default_grants=False,
    )
    expanded = rs._expand_tls_matrix(base)

    assert len(base) == 222
    assert len(expanded) == 444

    for relative_path in ["RUN.md", "SEMANTIC-VERIFIED.md", "TESTING.md"]:
        content = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
        assert "444" in content, relative_path
        assert "222" in content, relative_path

    assert "3,222" in (REPO_ROOT / "RUN.md").read_text(encoding="utf-8")
    assert "1,530" in (REPO_ROOT / "RUN.md").read_text(encoding="utf-8")
