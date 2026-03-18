from benchmarks import run_scenarios as rs


def _tokens() -> dict[str, str]:
    return {
        "biscuit_authorizer_template": "shared-token",
    }


def test_biscuit_authorizer_template_scenario_ids_are_preserved() -> None:
    scenarios = rs._biscuit_authorizer_template_scenarios(_tokens())
    assert set(scenarios.keys()) == {
        "TOKEN-AUTHORIZER-PROFILE-SIMPLE-BISCUIT",
        "TOKEN-AUTHORIZER-PROFILE-RBAC-BISCUIT",
        "TOKEN-AUTHORIZER-PROFILE-CONTEXTUAL-BISCUIT",
    }


def test_biscuit_authorizer_template_scenarios_share_constant_token_fixture() -> None:
    scenarios = rs._biscuit_authorizer_template_scenarios(_tokens())
    assert all(scenario["password"] == "shared-token" for scenario in scenarios.values())


def test_biscuit_authorizer_template_scenario_metadata_is_explicit() -> None:
    scenarios = rs._biscuit_authorizer_template_scenarios(_tokens())

    expected = {
        "TOKEN-AUTHORIZER-PROFILE-SIMPLE-BISCUIT": ("simple", "simple"),
        "TOKEN-AUTHORIZER-PROFILE-RBAC-BISCUIT": ("med", "rbac"),
        "TOKEN-AUTHORIZER-PROFILE-CONTEXTUAL-BISCUIT": ("complex", "contextual"),
    }

    for scenario_id, (tier, profile) in expected.items():
        scenario = scenarios[scenario_id]
        assert scenario["complexity_axis"] == "authorizer_template"
        assert scenario["complexity_level"] == tier
        assert scenario["authorizer_profile"] == profile
        assert scenario["topic"] == "sensors/{client_id}/temp"
        assert scenario["username"] == "biscuit"


def test_biscuit_authorizer_template_scenarios_require_template_token() -> None:
    assert rs._biscuit_authorizer_template_scenarios({}) == {}
