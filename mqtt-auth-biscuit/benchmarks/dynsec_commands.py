"""Dynamic Security command payload generators for Mosquitto $CONTROL topic."""

from __future__ import annotations

import json
import uuid
from typing import Any, TypedDict


class DynsecACL(TypedDict, total=False):
    """Dynamic Security ACL entry."""

    acltype: str
    topic: str
    priority: int
    allow: bool


class DynsecCommand(TypedDict, total=False):
    """Dynamic Security command structure."""

    command: str
    rolename: str | None
    groupname: str | None
    username: str | None
    clientid: str | None
    textname: str | None
    textdescription: str | None
    acls: list[DynsecACL] | None
    roles: list[dict[str, Any]] | None
    priority: int | None
    correlationData: str | None
    # addRoleACL / removeRoleACL specific fields
    acltype: str | None
    topic: str | None
    allow: bool | None


def generate_create_role_command(
    rolename: str,
    acls: list[DynsecACL] | None = None,
    textname: str | None = None,
    textdescription: str | None = None,
    correlation_data: str | None = None,
) -> DynsecCommand:
    """Generate a createRole command.

    Args:
        rolename: Name of the role to create
        acls: Optional list of ACLs to attach to the role
        textname: Optional human-readable name
        textdescription: Optional description
        correlation_data: Optional correlation ID for tracking

    Returns:
        createRole command dict
    """
    cmd: DynsecCommand = {"command": "createRole", "rolename": rolename}
    if textname:
        cmd["textname"] = textname
    if textdescription:
        cmd["textdescription"] = textdescription
    if acls:
        cmd["acls"] = acls
    if correlation_data:
        cmd["correlationData"] = correlation_data
    return cmd


def generate_delete_role_command(
    rolename: str,
    correlation_data: str | None = None,
) -> DynsecCommand:
    """Generate a deleteRole command.

    Args:
        rolename: Name of the role to delete
        correlation_data: Optional correlation ID for tracking

    Returns:
        deleteRole command dict
    """
    cmd: DynsecCommand = {"command": "deleteRole", "rolename": rolename}
    if correlation_data:
        cmd["correlationData"] = correlation_data
    return cmd


def generate_create_group_command(
    groupname: str,
    roles: list[dict[str, Any]] | None = None,
    correlation_data: str | None = None,
) -> DynsecCommand:
    """Generate a createGroup command.

    Args:
        groupname: Name of the group to create
        roles: Optional list of role assignments {"rolename": str, "priority": int}
        correlation_data: Optional correlation ID for tracking

    Returns:
        createGroup command dict
    """
    cmd: DynsecCommand = {"command": "createGroup", "groupname": groupname}
    if roles:
        cmd["roles"] = roles
    if correlation_data:
        cmd["correlationData"] = correlation_data
    return cmd


def generate_delete_group_command(
    groupname: str,
    correlation_data: str | None = None,
) -> DynsecCommand:
    """Generate a deleteGroup command.

    Args:
        groupname: Name of the group to delete
        correlation_data: Optional correlation ID for tracking

    Returns:
        deleteGroup command dict
    """
    cmd: DynsecCommand = {"command": "deleteGroup", "groupname": groupname}
    if correlation_data:
        cmd["correlationData"] = correlation_data
    return cmd


def generate_add_group_client_command(
    groupname: str,
    username: str,
    priority: int = 0,
    correlation_data: str | None = None,
) -> DynsecCommand:
    """Generate an addGroupClient command.

    Args:
        groupname: Name of the group
        username: Username to add to the group
        priority: Priority of this group for the client (default 0)
        correlation_data: Optional correlation ID for tracking

    Returns:
        addGroupClient command dict
    """
    cmd: DynsecCommand = {
        "command": "addGroupClient",
        "groupname": groupname,
        "username": username,
        "priority": priority,
    }
    if correlation_data:
        cmd["correlationData"] = correlation_data
    return cmd


def generate_remove_group_client_command(
    groupname: str,
    username: str,
    correlation_data: str | None = None,
) -> DynsecCommand:
    """Generate a removeGroupClient command.

    Args:
        groupname: Name of the group
        username: Username to remove from the group
        correlation_data: Optional correlation ID for tracking

    Returns:
        removeGroupClient command dict
    """
    cmd: DynsecCommand = {
        "command": "removeGroupClient",
        "groupname": groupname,
        "username": username,
    }
    if correlation_data:
        cmd["correlationData"] = correlation_data
    return cmd


def generate_add_client_role_command(
    username: str,
    rolename: str,
    priority: int = 0,
    correlation_data: str | None = None,
) -> DynsecCommand:
    """Generate an addClientRole command.

    Args:
        username: Username of the client
        rolename: Name of the role to add
        priority: Priority of this role for the client (default 0)
        correlation_data: Optional correlation ID for tracking

    Returns:
        addClientRole command dict
    """
    cmd: DynsecCommand = {
        "command": "addClientRole",
        "username": username,
        "rolename": rolename,
        "priority": priority,
    }
    if correlation_data:
        cmd["correlationData"] = correlation_data
    return cmd


def generate_remove_client_role_command(
    username: str,
    rolename: str,
    correlation_data: str | None = None,
) -> DynsecCommand:
    """Generate a removeClientRole command.

    Args:
        username: Username of the client
        rolename: Name of the role to remove
        correlation_data: Optional correlation ID for tracking

    Returns:
        removeClientRole command dict
    """
    cmd: DynsecCommand = {
        "command": "removeClientRole",
        "username": username,
        "rolename": rolename,
    }
    if correlation_data:
        cmd["correlationData"] = correlation_data
    return cmd


def generate_add_role_acl_command(
    rolename: str,
    acltype: str,
    topic: str,
    priority: int = 0,
    allow: bool = True,
    correlation_data: str | None = None,
) -> DynsecCommand:
    """Generate an addRoleACL command.

    Args:
        rolename: Name of the role to modify
        acltype: ACL type (e.g., "publishClientSend", "subscribeLiteral")
        topic: Topic pattern
        priority: Priority of this ACL (default 0)
        allow: Whether to allow or deny (default True)
        correlation_data: Optional correlation ID for tracking

    Returns:
        addRoleACL command dict
    """
    cmd: DynsecCommand = {
        "command": "addRoleACL",
        "rolename": rolename,
        "acltype": acltype,
        "topic": topic,
        "priority": priority,
        "allow": allow,
    }
    if correlation_data:
        cmd["correlationData"] = correlation_data
    return cmd


def generate_remove_role_acl_command(
    rolename: str,
    acltype: str,
    topic: str,
    correlation_data: str | None = None,
) -> DynsecCommand:
    """Generate a removeRoleACL command.

    Args:
        rolename: Name of the role to modify
        acltype: ACL type (e.g., "publishClientSend", "subscribeLiteral")
        topic: Topic pattern
        correlation_data: Optional correlation ID for tracking

    Returns:
        removeRoleACL command dict
    """
    cmd: DynsecCommand = {
        "command": "removeRoleACL",
        "rolename": rolename,
        "acltype": acltype,
        "topic": topic,
    }
    if correlation_data:
        cmd["correlationData"] = correlation_data
    return cmd


def generate_disable_client_command(
    username: str,
    correlation_data: str | None = None,
) -> DynsecCommand:
    """Generate a disableClient command."""
    cmd: DynsecCommand = {
        "command": "disableClient",
        "username": username,
    }
    if correlation_data:
        cmd["correlationData"] = correlation_data
    return cmd


def generate_command_payload(
    commands: list[DynsecCommand],
    correlation_data: str | None = None,
) -> dict[str, Any]:
    """Generate the full Dynamic Security command payload.

    Args:
        commands: List of Dynamic Security commands
        correlation_data: Optional global correlation ID

    Returns:
        JSON payload with commands array
    """
    payload: dict[str, Any] = {"commands": commands}
    if correlation_data:
        payload["correlationData"] = correlation_data
    return payload


def generate_churn_sequence(
    sequence_type: str,
    base_id: str | None = None,
    client_id: str | None = None,
) -> list[DynsecCommand]:
    """Generate a standard churn command sequence.

    Args:
        sequence_type: Type of churn sequence ("role", "group_client", "acl",
            "noop_group_client", "disable_client")
        base_id: Optional base ID for naming (generates UUID if not provided)
        client_id: Optional client ID for group/acl operations

    Returns:
        List of commands to execute in sequence
    """
    base = base_id or uuid.uuid4().hex[:8]
    cid = client_id or f"client_{base}"

    if sequence_type == "role":
        rolename = f"dynamic_role_{base}"
        return [
            generate_create_role_command(
                rolename=rolename,
                acls=[
                    {
                        "acltype": "publishClientSend",
                        "topic": f"test/{cid}/#",
                        "priority": 0,
                        "allow": True,
                    },
                    {
                        "acltype": "subscribeLiteral",
                        "topic": f"test/{cid}/#",
                        "priority": 0,
                        "allow": True,
                    },
                ],
                textname=f"Dynamic Role {base}",
                textdescription="Temporarily created role for churn testing",
            ),
            generate_delete_role_command(rolename=rolename),
        ]

    elif sequence_type == "group_client":
        groupname = f"dynamic_group_{base}"
        return [
            generate_create_group_command(
                groupname=groupname,
                roles=[{"rolename": "sensor_reader", "priority": 0}],
            ),
            generate_add_group_client_command(
                groupname=groupname,
                username=cid,
                priority=0,
            ),
            generate_remove_group_client_command(groupname=groupname, username=cid),
            generate_delete_group_command(groupname=groupname),
        ]

    elif sequence_type == "acl":
        rolename = f"dynamic_role_{base}"
        topic = f"test/{cid}/#"
        return [
            generate_create_role_command(rolename=rolename),
            generate_add_role_acl_command(
                rolename=rolename,
                acltype="publishClientSend",
                topic=topic,
                priority=0,
                allow=True,
            ),
            generate_remove_role_acl_command(
                rolename=rolename,
                acltype="publishClientSend",
                topic=topic,
            ),
            generate_delete_role_command(rolename=rolename),
        ]
    elif sequence_type == "noop_group_client":
        return [
            generate_add_group_client_command(
                groupname="fanout_existing_readers",
                username=cid,
                priority=0,
            )
        ]
    elif sequence_type == "disable_client":
        return [generate_disable_client_command(username=cid)]

    else:
        raise ValueError(f"Unknown sequence_type: {sequence_type}")


def payload_to_json(payload: dict[str, Any]) -> str:
    """Convert payload dict to JSON string.

    Args:
        payload: Command payload dict

    Returns:
        JSON string
    """
    return json.dumps(payload, separators=(",", ":"))


# Common ACL types for reference
ACL_TYPE_PUBLISH_CLIENT_SEND = "publishClientSend"
ACL_TYPE_PUBLISH_CLIENT_RECV = "publishClientReceive"
ACL_TYPE_SUBSCRIBE_LITERAL = "subscribeLiteral"
ACL_TYPE_SUBSCRIBE_PATTERN = "subscribePattern"
ACL_TYPE_UNSUBSCRIBE_LITERAL = "unsubscribeLiteral"
ACL_TYPE_UNSUBSCRIBE_PATTERN = "unsubscribePattern"
