from __future__ import annotations

# NOTE: These tests exercise internal helpers (`rs._generate_control_churn_payload`)
# rather than the public scenario runner API. If those helpers are renamed or made
# module-private in a different way, these tests will break at import/call time
# rather than at a type-checked boundary. Keep that coupling in mind when refactoring
# run_scenarios.py.
from benchmarks import run_scenarios as rs


def _command_names(payload: dict[str, object]) -> list[str]:
    commands = payload.get("commands")
    assert isinstance(commands, list)
    out: list[str] = []
    for command in commands:
        assert isinstance(command, dict)
        name = command.get("command")
        assert isinstance(name, str)
        out.append(name)
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
