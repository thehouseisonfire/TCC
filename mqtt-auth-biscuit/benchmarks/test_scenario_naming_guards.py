from __future__ import annotations

import re
from pathlib import Path

from benchmarks import run_scenarios


def _placeholder_tokens() -> dict[str, str]:
    source = Path(run_scenarios.__file__).read_text()
    keys = set(re.findall(r'tokens\["([^"]+)"\]', source))
    keys.update(re.findall(r'tokens\.get\("([^"]+)"', source))
    return {key: f"{key}-fixture" for key in keys}


def _scenario_registry() -> dict[str, run_scenarios.ScenarioConfig]:
    return run_scenarios._build_available_scenarios(
        _placeholder_tokens(),
        token_issuer_no_default_roles=False,
        token_issuer_no_default_grants=False,
    )


def test_scenario_ids_use_canonical_naming() -> None:
    legacy_fragments = (
        "ACLREAD",
        "DYNSEC-",
        "-BIS-",
        "BASE-01",
        "JWT-01",
        "HTTP-POLICY-",
        "POLICY-COMPLEX-",
        "POLICY-AUTHZ-TEMPLATE-",
        "ANON-BASE",
    )

    for scenario_id in _scenario_registry():
        assert all(fragment not in scenario_id for fragment in legacy_fragments), scenario_id


def test_scenario_configs_do_not_expose_legacy_metadata_keys() -> None:
    legacy_keys = {
        "authz",
        "mode",
        "policy_profile",
        "policy_complexity_kind",
        "policy_complexity_tier",
        "dynsec_config",
        "dynsec_churn",
        "fanout_churn_dynsec_source",
        "acl_read_full_authz",
        "acl_read_mode",
    }

    for scenario_id, scenario in _scenario_registry().items():
        assert not (legacy_keys & set(scenario)), scenario_id
