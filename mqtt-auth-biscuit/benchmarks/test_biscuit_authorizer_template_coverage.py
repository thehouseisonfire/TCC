from benchmarks import run_scenarios as rs


def _tokens() -> dict[str, str]:
    return {
        "biscuit_authorizer_template": "shared-token",
    }


def test_biscuit_authorizer_template_scenario_ids_are_preserved() -> None:
    scenarios = rs._biscuit_authorizer_template_scenarios(_tokens())
    assert set(scenarios.keys()) == {
        "POLICY-AUTHZ-TEMPLATE-SIMPLE",
        "POLICY-AUTHZ-TEMPLATE-RBAC",
        "POLICY-AUTHZ-TEMPLATE-CONTEXTUAL",
    }


def test_biscuit_authorizer_template_scenarios_share_constant_token_fixture() -> None:
    scenarios = rs._biscuit_authorizer_template_scenarios(_tokens())
    assert all(scenario["password"] == "shared-token" for scenario in scenarios.values())


def test_biscuit_authorizer_template_scenario_metadata_is_explicit() -> None:
    scenarios = rs._biscuit_authorizer_template_scenarios(_tokens())

    expected = {
        "POLICY-AUTHZ-TEMPLATE-SIMPLE": ("simple", "simple"),
        "POLICY-AUTHZ-TEMPLATE-RBAC": ("med", "rbac"),
        "POLICY-AUTHZ-TEMPLATE-CONTEXTUAL": ("complex", "contextual"),
    }

    for scenario_id, (tier, profile) in expected.items():
        scenario = scenarios[scenario_id]
        assert scenario["policy_complexity_kind"] == "authorizer_template"
        assert scenario["policy_complexity_tier"] == tier
        assert scenario["policy_profile"] == profile
        assert scenario["topic"] == "sensors/{client_id}/temp"
        assert scenario["username"] == "biscuit"


def test_biscuit_authorizer_template_scenarios_require_template_token() -> None:
    assert rs._biscuit_authorizer_template_scenarios({}) == {}
