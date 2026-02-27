import pytest

from benchmarks import run_scenarios as rs


def _tokens() -> dict[str, str]:
    return {
        "jwt": "jwt-token",
        "biscuit": "biscuit-token",
    }


def _expected_ids() -> set[str]:
    subscribers = [10, 50, 100]
    out: set[str] = set()
    for count in subscribers:
        out.add(f"DYNSEC-ACLREAD-FANOUT-CHURN-JWT-{count}")
        out.add(f"DYNSEC-ACLREAD-FANOUT-CHURN-BIS-{count}")
        out.add(f"SQLITE-ACLREAD-FANOUT-CHURN-JWT-{count}")
        out.add(f"SQLITE-ACLREAD-FANOUT-CHURN-BIS-{count}")
    return out


def test_issue30_scenario_ids_are_preserved() -> None:
    scenarios = rs._issue30_acl_read_fanout_scenarios(_tokens())
    assert set(scenarios.keys()) == _expected_ids()


def test_issue30_scenarios_use_fanout_and_subscriber_scaling() -> None:
    scenarios = rs._issue30_acl_read_fanout_scenarios(_tokens())

    for scenario_id, scenario in scenarios.items():
        assert scenario["mode"] == "fanout"
        assert scenario["fanout_topic"] == "fanout/broadcast"
        assert scenario["fanout_churn_after_messages"] == 5
        assert scenario["fanout_churn_settle_ms"] == 1200
        assert scenario["subscriber_count"] in {10, 50, 100}

        if scenario_id.startswith("DYNSEC-"):
            assert scenario["mosquitto_conf"] == "./mosquitto_dynsec_acl_read.conf"
            assert (
                scenario["dynsec_config"]
                == "docker/dynamic-security-fanout-read-allow-unpinned.json"
            )
            assert scenario["fanout_churn_kind"] == "dynsec_swap"
            assert (
                scenario["fanout_churn_dynsec_source"]
                == "docker/dynamic-security-fanout-read-deny-unpinned.json"
            )
        elif scenario_id.startswith("SQLITE-"):
            assert scenario["mosquitto_conf"] == "./mosquitto_sqlite_acl_read.conf"
            assert scenario["fanout_churn_kind"] == "sqlite_revoke_read"
            assert scenario["sqlite_seed_fanout"] is True
            assert scenario["sqlite_seed_db"] == "docker/sqlite/policy.db"
            assert scenario["sqlite_seed_topic"] == "fanout/broadcast"
            assert scenario["fanout_churn_sqlite_db"] == "docker/sqlite/policy.db"
            assert scenario["fanout_churn_sqlite_topic"] == "fanout/broadcast"
            assert scenario["fanout_churn_sqlite_subscribers"] == scenario["subscriber_count"]
        else:
            raise AssertionError(f"unexpected scenario id: {scenario_id}")


def test_issue30_dynsec_scenarios_pass_fanout_alignment_validator() -> None:
    scenarios = rs._issue30_acl_read_fanout_scenarios(_tokens())
    for scenario_id, scenario in scenarios.items():
        if scenario_id.startswith("DYNSEC-"):
            rs._validate_dynsec_fanout_alignment(scenario_id, scenario)


def test_dynsec_fanout_alignment_rejects_pinned_single_identity() -> None:
    scenario = {
        "id": "TEST-DYNSEC-PINNED",
        "mode": "fanout",
        "subscriber_count": 10,
        "username": "dynsec_client_1",
        "dynsec_config": "docker/dynamic-security.json",
        "fanout_churn_kind": "dynsec_swap",
        "fanout_churn_dynsec_source": "docker/dynamic-security-fanout-read-deny.json",
    }
    with pytest.raises(ValueError, match="pins username"):
        rs._validate_dynsec_fanout_alignment(scenario["id"], scenario)
