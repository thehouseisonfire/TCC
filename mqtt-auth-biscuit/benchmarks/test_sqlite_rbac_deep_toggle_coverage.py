from benchmarks import run_scenarios as rs


def _tokens() -> dict[str, str]:
    return {
        "jwt": "jwt-token",
        "biscuit": "biscuit-token",
    }


def test_sqlite_rbac_deep_toggle_scenario_ids_are_present() -> None:
    scenarios = rs._sqlite_rbac_deep_toggle_scenarios(_tokens())
    assert set(scenarios.keys()) == {
        "SQLITE-RBAC-DEEP-CONFLICT-JWT",
        "SQLITE-RBAC-DEEP-CONFLICT-BISCUIT",
        "SQLITE-RBAC-DEEP-CONTROL-JWT",
        "SQLITE-RBAC-DEEP-CONTROL-BISCUIT",
    }


def test_sqlite_rbac_deep_toggle_conflict_scenarios_use_private_deny_toggle() -> None:
    scenarios = rs._sqlite_rbac_deep_toggle_scenarios(_tokens())
    for scenario_id in ["SQLITE-RBAC-DEEP-CONFLICT-JWT", "SQLITE-RBAC-DEEP-CONFLICT-BISCUIT"]:
        scenario = scenarios[scenario_id]
        assert scenario["traffic_pattern"] == "fanout"
        assert scenario["fanout_topic"] == "sensors/private/broadcast"
        assert scenario["sqlite_seed_fanout"] is True
        assert scenario["sqlite_seed_profile"] == "rbac_deep"
        assert scenario["fanout_churn_kind"] == "sqlite_toggle_private_deny"
        assert scenario["fanout_churn_after_messages"] == 4
        assert scenario["fanout_churn_interval_messages"] == 4
        assert scenario["fanout_churn_max_events"] == 4


def test_sqlite_rbac_deep_toggle_control_scenarios_enable_control_mode() -> None:
    scenarios = rs._sqlite_rbac_deep_toggle_scenarios(_tokens())
    for scenario_id in ["SQLITE-RBAC-DEEP-CONTROL-JWT", "SQLITE-RBAC-DEEP-CONTROL-BISCUIT"]:
        scenario = scenarios[scenario_id]
        assert scenario["control_mode"] is True
        assert scenario["control_topic"] == "$CONTROL/dynamic-security/v1"
        assert scenario["control_repeat"] == 5
        assert scenario["sqlite_seed_profile"] == "rbac_deep_control_allow"


def test_sqlite_control_scenarios_keep_publish_path_without_dynsec_response() -> None:
    scenarios = rs._apply_result_contracts(rs._sqlite_rbac_deep_toggle_scenarios(_tokens()))
    for scenario_id in ["SQLITE-RBAC-DEEP-CONTROL-JWT", "SQLITE-RBAC-DEEP-CONTROL-BISCUIT"]:
        scenario = scenarios[scenario_id]
        # The control operation itself is preserved: the allow path is still measured.
        assert scenario["control_mode"] is True
        assert scenario["control_topic"] == "$CONTROL/dynamic-security/v1"
        assert scenario["control_payload"] == {"commands": [{"command": "listClients"}]}
        assert scenario["control_repeat"] == 5
        # SQLite mode has no DynSec responder, so no correlated response is expected.
        assert "control_response_topic" not in scenario


def test_dynsec_control_scenarios_keep_correlated_response_topic() -> None:
    scenarios: dict[str, rs.ScenarioConfig] = {
        "dynsec-conf": {
            "control_topic": "$CONTROL/dynamic-security/v1",
            "mosquitto_conf": "./mosquitto_dynsec.conf",
        },
        "dynsec-profile": {
            "control_topic": "$CONTROL/dynamic-security/v1",
            "mosquitto_conf": "./mosquitto_sqlite_acl_read.conf",
            "dynamic_security_generated_profile": "control_admin_base",
        },
    }
    rs._apply_result_contracts(scenarios)
    for scenario in scenarios.values():
        assert scenario["control_response_topic"] == "$CONTROL/dynamic-security/v1/response"
