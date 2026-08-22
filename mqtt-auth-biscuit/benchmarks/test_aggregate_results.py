import csv
from pathlib import Path

from benchmarks import aggregate_results


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
