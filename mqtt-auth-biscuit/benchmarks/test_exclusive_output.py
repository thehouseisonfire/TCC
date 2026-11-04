from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from typer.testing import CliRunner

from benchmarks import aggregate_results, run_scenarios


def test_claim_is_atomic_and_separate_destinations_work(tmp_path: Path) -> None:
    target = tmp_path / "parent" / "slot"

    def claim() -> bool:
        try:
            run_scenarios._claim_exclusive_output(str(target))
            return True
        except FileExistsError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _: claim(), range(2))) == [False, True]
    run_scenarios._claim_exclusive_output(str(tmp_path / "parent" / "other"))
    with pytest.raises(FileExistsError):
        run_scenarios._claim_exclusive_output(str(target))


def test_result_create_new_and_ordinary_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "scenario.json"
    path.write_text("original")
    with pytest.raises(FileExistsError):
        run_scenarios._write_result(str(tmp_path), "scenario", {}, exclusive=True)
    assert path.read_text() == "original"
    run_scenarios._write_result(str(tmp_path), "scenario", {})
    assert path.read_text() == "{}"


@pytest.mark.parametrize("existing", ["summary.json", "summary.csv"])
def test_aggregator_refuses_existing_summary(tmp_path: Path, existing: str) -> None:
    path = tmp_path / existing
    path.write_text("original")
    with pytest.raises(FileExistsError):
        aggregate_results.main(input=str(tmp_path), exclusive_out=True, log_level="INFO")
    assert path.read_text() == "original"


def test_existing_destination_fails_before_workload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(run_scenarios, "_load_image_freeze_manifest", lambda: None)
    monkeypatch.setattr(run_scenarios, "_no_build_images", lambda: False)
    monkeypatch.setattr(
        run_scenarios,
        "_dynamic_security_scenario_config",
        lambda **_: pytest.fail("workload started"),
    )
    result = CliRunner().invoke(
        run_scenarios.app,
        [
            "--scenarios-arg",
            "HYBRID-FALLBACK-AUTHZ-DOWN-JWT",
            "--out",
            str(tmp_path),
            "--exclusive-out",
            "--no-tcpdump",
        ],
    )
    assert result.exit_code == 73


def test_help_does_not_claim(tmp_path: Path) -> None:
    target = tmp_path / "slot"
    result = CliRunner().invoke(
        run_scenarios.app, ["--help", "--out", str(target), "--exclusive-out"]
    )
    assert result.exit_code == 0
    assert not target.exists()


def test_new_destination_proceeds_to_normal_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "slot"
    monkeypatch.setattr(run_scenarios, "_load_image_freeze_manifest", lambda: None)
    monkeypatch.setattr(run_scenarios, "_no_build_images", lambda: False)

    def stop_at_setup(*args: object, **kwargs: object) -> None:
        assert target.is_dir()
        raise RuntimeError("setup reached")

    monkeypatch.setattr(run_scenarios, "_dynamic_security_scenario_config", stop_at_setup)
    result = CliRunner().invoke(
        run_scenarios.app,
        [
            "--scenarios-arg",
            "HYBRID-FALLBACK-AUTHZ-DOWN-JWT",
            "--out",
            str(target),
            "--exclusive-out",
            "--no-tcpdump",
        ],
    )
    assert isinstance(result.exception, RuntimeError)
    assert str(result.exception) == "setup reached"
