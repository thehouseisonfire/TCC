from __future__ import annotations

# NOTE: These tests exercise internal helpers (`rs._generate_control_churn_payload`)
# rather than the public scenario runner API. If those helpers are renamed or made
# module-private in a different way, these tests will break at import/call time
# rather than at a type-checked boundary. Keep that coupling in mind when refactoring
# run_scenarios.py.
from typing import Any

from benchmarks import run_scenarios as rs


def _command_names(payload: dict[str, Any]) -> list[str]:
    commands = payload.get("commands")
    assert isinstance(commands, list)
    out: list[str] = []
    for command in commands:
        assert isinstance(command, dict)
        name = command.get("command")
        assert isinstance(name, str)
        out.append(name)
    return out


def _commands(payload: dict[str, Any]) -> list[dict[str, Any]]:
    commands = payload.get("commands")
    assert isinstance(commands, list)
    out: list[dict[str, Any]] = []
    for command in commands:
        assert isinstance(command, dict)
        out.append(command)
    return out


def test_control_churn_create_role_payload_uses_role_lifecycle_commands() -> None:
    payload = rs._generate_control_churn_payload("CONTROL-CHURN-CREATE-ROLE-JWT", "client_1")
    assert payload is not None
    assert _command_names(payload) == ["createRole", "deleteRole"]


def test_control_churn_group_client_payload_uses_group_membership_commands() -> None:
    payload = rs._generate_control_churn_payload("CONTROL-CHURN-GROUP-CLIENT-BISCUIT", "client_1")
    assert payload is not None
    assert _command_names(payload) == [
        "createGroup",
        "addGroupClient",
        "removeGroupClient",
        "deleteGroup",
    ]


def test_control_churn_acl_modify_payload_remains_supported() -> None:
    payload = rs._generate_control_churn_payload("CONTROL-CHURN-ACL-MODIFY-JWT", "client_1")
    assert payload is not None
    assert _command_names(payload) == [
        "createRole",
        "addRoleACL",
        "removeRoleACL",
        "deleteRole",
    ]


def test_control_churn_large_state_group_client_targets_seeded_large_state_user() -> None:
    payload = rs._generate_control_churn_payload(
        "CONTROL-CHURN-LARGE-STATE-GROUP-CLIENT-JWT",
        "admin",
    )
    assert payload is not None
    commands = _commands(payload)
    assert _command_names(payload) == [
        "createGroup",
        "addGroupClient",
        "removeGroupClient",
        "deleteGroup",
    ]
    assert commands[0]["groupname"] == "dynamic_group_large_state_control"
    assert commands[1]["username"] == "bulk_user_1"
    assert commands[2]["username"] == "bulk_user_1"


def test_control_churn_noop_group_client_payload_is_single_idempotent_add() -> None:
    payload = rs._generate_control_churn_payload(
        "CONTROL-CHURN-NOOP-GROUP-CLIENT-BISCUIT",
        "dynsec_client_1",
    )
    assert payload is not None
    commands = _commands(payload)
    assert _command_names(payload) == ["addGroupClient"]
    assert commands[0]["groupname"] == "fanout_existing_readers"
    assert commands[0]["username"] == "dynsec_client_1"


def test_control_churn_repeat_same_entity_payload_uses_shared_role_name() -> None:
    payload = rs._generate_control_churn_payload(
        "CONTROL-CHURN-REPEAT-SAME-ENTITY-JWT",
        "client_9",
    )
    assert payload is not None
    commands = _commands(payload)
    assert _command_names(payload) == ["createRole", "deleteRole"]
    assert commands[0]["rolename"] == "dynamic_role_shared_control_entity"
    assert commands[1]["rolename"] == "dynamic_role_shared_control_entity"


def test_control_churn_repeat_distinct_payload_keeps_client_placeholder_for_runtime_expansion() -> (
    None
):
    payload = rs._generate_control_churn_payload(
        "CONTROL-CHURN-REPEAT-DISTINCT-ENTITY-JWT",
        "admin",
    )
    assert payload is not None
    commands = _commands(payload)
    assert _command_names(payload) == ["createRole", "deleteRole"]
    assert commands[0]["rolename"] == "dynamic_role_{client_id}"
    assert commands[0]["acls"][0]["topic"] == "test/{client_id}/#"
    assert commands[1]["rolename"] == "dynamic_role_{client_id}"


def test_control_churn_concurrent_controllers_payload_reuses_distinct_runtime_placeholders() -> (
    None
):
    payload = rs._generate_control_churn_payload(
        "CONTROL-CHURN-CONCURRENT-CONTROLLERS-BISCUIT",
        "admin",
    )
    assert payload is not None
    commands = _commands(payload)
    assert _command_names(payload) == ["createRole", "deleteRole"]
    assert commands[0]["rolename"] == "dynamic_role_{client_id}"
