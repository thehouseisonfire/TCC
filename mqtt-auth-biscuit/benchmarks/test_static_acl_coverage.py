from benchmarks import run_scenarios as rs


def _tokens() -> dict[str, str]:
    return {
        "jwt_static_writer": "jwt-writer-token",
        "jwt_static_reader": "jwt-reader-token",
        "biscuit_static_writer": "biscuit-writer-token",
        "biscuit_static_reader": "biscuit-reader-token",
    }


def test_static_acl_scenario_ids_are_preserved():
    scenarios = rs._static_acl_scenarios(_tokens())
    assert set(scenarios.keys()) == {
        "STATIC-ACL-PUBLISH-JWT",
        "STATIC-ACL-PUBLISH-BISCUIT",
        "STATIC-ACL-FANOUT-JWT",
        "STATIC-ACL-FANOUT-BISCUIT",
    }


def test_static_acl_publish_scenarios_use_writer_role_only_tokens():
    scenarios = rs._static_acl_scenarios(_tokens())
    jwt_publish = scenarios["STATIC-ACL-PUBLISH-JWT"]
    bis_publish = scenarios["STATIC-ACL-PUBLISH-BISCUIT"]

    assert jwt_publish["password"] == "jwt-writer-token"
    assert bis_publish["password"] == "biscuit-writer-token"
    assert jwt_publish.get("mode") is None
    assert bis_publish.get("mode") is None


def test_static_acl_fanout_scenarios_split_subscriber_and_publisher_roles():
    scenarios = rs._static_acl_scenarios(_tokens())
    jwt_fanout = scenarios["STATIC-ACL-FANOUT-JWT"]
    bis_fanout = scenarios["STATIC-ACL-FANOUT-BISCUIT"]

    assert jwt_fanout["traffic_pattern"] == "fanout"
    assert bis_fanout["traffic_pattern"] == "fanout"
    assert jwt_fanout["password"] == "jwt-reader-token"
    assert jwt_fanout["fanout_publisher_password"] == "jwt-writer-token"
    assert bis_fanout["password"] == "biscuit-reader-token"
    assert bis_fanout["fanout_publisher_password"] == "biscuit-writer-token"
