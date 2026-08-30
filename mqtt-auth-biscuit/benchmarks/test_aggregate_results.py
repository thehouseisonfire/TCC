import csv
import json
from pathlib import Path

from benchmarks import aggregate_results


def test_summary_rejects_legacy_result_schema(tmp_path: Path) -> None:
    (tmp_path / "legacy.json").write_text(json.dumps({"scenario": "OLD", "runs": []}))

    try:
        aggregate_results._build_summary(tmp_path)
    except ValueError as exc:
        assert "unsupported benchmark result schema" in str(exc)
    else:
        raise AssertionError("legacy results must not be silently aggregated as schema v2")


def test_resource_aggregation_uses_workload_interval_semantics() -> None:
    aggregated = aggregate_results._aggregate_resources(
        [
            {
                "resources": {
                    "available": True,
                    "cpu_usage_seconds": 1.5,
                    "memory_working_set_bytes": {"max": 200, "mean": 150, "samples": 4},
                }
            },
            {"resources": {"available": False}},
        ]
    )

    assert aggregated["cpu_usage_seconds"]["avg"] == 1.5
    assert aggregated["memory_peak_bytes"]["avg"] == 200.0
    assert aggregated["memory_mean_bytes"]["avg"] == 150.0
    assert aggregated["memory_sample_count"]["avg"] == 4.0
    assert aggregated["unavailable_runs"] == 1


def test_csv_preserves_role_specific_credential_profiles(tmp_path: Path) -> None:
    output = tmp_path / "summary.csv"
    summary = {
        "scenarios": [
            {
                "scenario": "FANOUT",
                "credential_attestations": {
                    "clients": {
                        "profile": "subscriber-profile",
                        "semantic": {"complexity_level": "med"},
                    },
                    "fanout_publisher": {
                        "profile": "publisher-profile",
                        "semantic": {"complexity_level": "high"},
                    },
                },
            }
        ]
    }

    aggregate_results._write_csv(summary, output)

    with output.open(encoding="utf-8", newline="") as handle:
        row = next(csv.DictReader(handle))
    assert row["client_credential_profile"] == "subscriber-profile"
    assert row["client_credential_complexity_level"] == "med"
    assert row["fanout_publisher_credential_profile"] == "publisher-profile"
    assert row["fanout_publisher_credential_complexity_level"] == "high"
