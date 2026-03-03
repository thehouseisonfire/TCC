from benchmarks import run_scenarios as rs

TOKENS = {
    "jwt": "jwt-token",
    "biscuit": "biscuit-token",
    "jwt_fanout_allow": "jwt-fanout-allow",
    "jwt_fanout_read_deny": "jwt-fanout-deny",
    "biscuit_fanout_allow": "bis-fanout-allow",
    "biscuit_fanout_read_deny": "bis-fanout-deny",
}


def _expected_ids() -> set[str]:
    expected: set[str] = set()

    for token in ("JWT", "BIS"):
        for subscribers in (10, 50, 100):
            expected.add(f"TOKEN-ACLREAD-FANOUT-ALLOW-{token}-{subscribers}")
        expected.add(f"TOKEN-ACLREAD-FANOUT-DENY-{token}-10")

    for source in ("HTTP", "HYBRID"):
        for tier in ("SIMPLE", "MED", "COMPLEX"):
            for token in ("JWT", "BIS"):
                expected.add(f"{source}-ACLREAD-FANOUT-{tier}-ALLOW-{token}-10")
                expected.add(f"{source}-ACLREAD-FANOUT-{tier}-DENY-{token}-10")
                if tier == "MED":
                    expected.add(f"{source}-ACLREAD-FANOUT-{tier}-ALLOW-{token}-50")
                    expected.add(f"{source}-ACLREAD-FANOUT-{tier}-ALLOW-{token}-100")

    return expected


def test_issue37_scenario_ids_are_preserved() -> None:
    scenarios = rs._issue37_acl_read_profile_scenarios(TOKENS)
    assert set(scenarios.keys()) == _expected_ids()


def test_issue37_scenarios_are_strict_fanout_with_profile_metadata() -> None:
    scenarios = rs._issue37_acl_read_profile_scenarios(TOKENS)

    for scenario_id, scenario in scenarios.items():
        assert scenario["mode"] == "fanout"
        assert scenario["fanout_topic"] == "fanout/broadcast"
        assert scenario["topic"] == "fanout/broadcast"
        assert scenario["acl_read_full_authz"] is True
        assert scenario["acl_read_mode"] == "strict"
        assert scenario["policy_source"] in {"token", "http", "hybrid"}

        if scenario_id.startswith("TOKEN-"):
            assert scenario["mosquitto_conf"] == "./mosquitto_integration_acl_read_full.conf"
            assert scenario["authz"] is None
            assert scenario["policy_profile"] == "default"
        elif scenario_id.startswith("HTTP-"):
            assert scenario["mosquitto_conf"] == "./mosquitto_http_acl_read.conf"
            assert scenario["policy_source"] == "http"
            assert scenario["authz"] is not None
        elif scenario_id.startswith("HYBRID-"):
            assert scenario["mosquitto_conf"] == "./mosquitto_hybrid_acl_read.conf"
            assert scenario["policy_source"] == "hybrid"
            assert scenario["authz"] is not None
        else:
            raise AssertionError(f"Unexpected scenario id: {scenario_id}")


def test_issue37_http_hybrid_profile_slices_follow_balanced_scaling() -> None:
    scenarios = rs._issue37_acl_read_profile_scenarios(TOKENS)

    for source in ("HTTP", "HYBRID"):
        for tier in ("SIMPLE", "MED", "COMPLEX"):
            for token in ("JWT", "BIS"):
                allow_subscribers = sorted(
                    scenario["subscriber_count"]
                    for sid, scenario in scenarios.items()
                    if sid.startswith(f"{source}-ACLREAD-FANOUT-{tier}-ALLOW-{token}")
                )
                deny_subscribers = sorted(
                    scenario["subscriber_count"]
                    for sid, scenario in scenarios.items()
                    if sid.startswith(f"{source}-ACLREAD-FANOUT-{tier}-DENY-{token}")
                )

                if tier == "MED":
                    assert allow_subscribers == [10, 50, 100]
                else:
                    assert allow_subscribers == [10]
                assert deny_subscribers == [10]


def test_issue37_deny_variants_include_explicit_read_deny_rule() -> None:
    scenarios = rs._issue37_acl_read_profile_scenarios(TOKENS)
    for scenario_id, scenario in scenarios.items():
        if "-DENY-" not in scenario_id:
            continue
        if scenario["authz"] is None:
            continue
        rules = scenario["authz"].get("rules", [])
        assert any(
            rule.get("effect") == "deny"
            and "read" in rule.get("ops", [])
            and "fanout/broadcast" in rule.get("topics", [])
            for rule in rules
        )
