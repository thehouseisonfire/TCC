from benchmarks import run_scenarios as rs


def _tokens() -> dict[str, str]:
    return {
        "jwt": "jwt-token",
        "biscuit": "biscuit-token",
    }


def test_sqlite_rbac_churn_issue22_scenario_ids_are_present() -> None:
    scenarios = rs._sqlite_rbac_churn_scenarios_issue22(_tokens())
    assert set(scenarios.keys()) == {"SQLITE-RBAC-CHURN-JWT", "SQLITE-RBAC-CHURN-BIS"}


def test_sqlite_rbac_churn_issue22_uses_periodic_sqlite_toggle_churn() -> None:
    scenarios = rs._sqlite_rbac_churn_scenarios_issue22(_tokens())
    for scenario in scenarios.values():
        assert scenario["mosquitto_conf"] == "./mosquitto_sqlite_acl_read.conf"
        assert scenario["mode"] == "fanout"
        assert scenario["fanout_topic"] == "fanout/broadcast"
        assert scenario["sqlite_seed_fanout"] is True
        assert scenario["sqlite_seed_profile"] == "fanout_basic"
        assert scenario["fanout_churn_kind"] == "sqlite_toggle_read"
        assert scenario["fanout_churn_after_messages"] == 4
        assert scenario["fanout_churn_interval_messages"] == 4
        assert scenario["fanout_churn_max_events"] == 4
        assert scenario["fanout_churn_sqlite_db"] == "docker/sqlite/policy.db"
