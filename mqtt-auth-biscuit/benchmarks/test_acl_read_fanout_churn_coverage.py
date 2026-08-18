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
        out.add(f"DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-JWT-{count}")
        out.add(f"DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-BISCUIT-{count}")
        out.add(f"DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-REVOKE-JWT-{count}")
        out.add(f"DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-REVOKE-BISCUIT-{count}")
        out.add(f"DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-DISABLE-JWT-{count}")
        out.add(f"DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-DISABLE-BISCUIT-{count}")
        out.add(f"SQLITE-ACL-READ-FANOUT-CHURN-JWT-{count}")
        out.add(f"SQLITE-ACL-READ-FANOUT-CHURN-BISCUIT-{count}")
    return out


def test_acl_read_fanout_churn_scenario_ids_are_preserved() -> None:
    scenarios = rs._acl_read_fanout_churn_scenarios(_tokens())
    assert set(scenarios.keys()) == _expected_ids()


def test_acl_read_fanout_churn_scenarios_use_fanout_and_subscriber_scaling() -> None:
    scenarios = rs._acl_read_fanout_churn_scenarios(_tokens())

    for scenario_id, scenario in scenarios.items():
        assert scenario["traffic_pattern"] == "fanout"
        assert scenario["fanout_topic"] == "fanout/broadcast"
        assert scenario["fanout_churn_after_messages"] == 5
        assert scenario["fanout_churn_settle_ms"] == 1200
        assert scenario["subscriber_count"] in {10, 50, 100}

        if scenario_id.startswith("DYNAMIC-SECURITY-"):
            assert scenario["mosquitto_conf"] == "./mosquitto_dynsec_acl_read.conf"
            if "CONTROL-" in scenario_id:
                assert scenario["dynamic_security_generated_profile"] == "fanout_control_allow"
                assert scenario["fanout_churn_kind"] == "dynamic_security_control"
                assert scenario["fanout_churn_control_topic"] == "$CONTROL/dynamic-security/v1"
                commands = scenario["fanout_churn_control_payload"]["commands"]
                assert isinstance(commands, list)
                assert len(commands) == 1
                command = commands[0]
                assert isinstance(command, dict)
                if "REVOKE" in scenario_id:
                    assert command["command"] == "removeRoleACL"
                    assert command["rolename"] == "fanout_reader"
                    assert command["acltype"] == "publishClientReceive"
                    assert command["topic"] == "fanout/broadcast"
                else:
                    assert command == {
                        "command": "disableClient",
                        "username": "dynsec_client_1",
                    }
                    assert scenario["allowed_error_prefixes"] == [
                        rs.EXPECTED_DISABLE_RECEIVE_ERROR_PREFIX
                    ]
            else:
                assert (
                    scenario["dynamic_security_config"]
                    == "docker/dynamic-security-fanout-read-allow-unpinned.json"
                )
                assert scenario["fanout_churn_kind"] == "dynamic_security_swap"
                assert (
                    scenario["fanout_churn_dynamic_security_source"]
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


def test_acl_read_fanout_churn_dynsec_scenarios_pass_fanout_alignment_validator() -> None:
    scenarios = rs._acl_read_fanout_churn_scenarios(_tokens())
    for scenario_id, scenario in scenarios.items():
        if scenario_id.startswith("DYNAMIC-SECURITY-"):
            rs._validate_dynamic_security_fanout_alignment(scenario_id, scenario)


def test_dynsec_fanout_alignment_rejects_pinned_single_identity() -> None:
    scenario: rs.ScenarioConfig = {
        "id": "TEST-DYNAMIC-SECURITY-PINNED",
        "traffic_pattern": "fanout",
        "subscriber_count": 10,
        "username": "dynsec_client_1",
        "dynamic_security_config": "docker/dynamic-security.json",
        "fanout_churn_kind": "dynamic_security_swap",
        "fanout_churn_dynamic_security_source": (
            "docker/dynamic-security-fanout-read-deny-unpinned.json"
        ),
    }
    with pytest.raises(ValueError, match="pins username"):
        rs._validate_dynamic_security_fanout_alignment(scenario["id"], scenario)
