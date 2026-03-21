use super::model::{AclConfig, RoleRef};
use super::mutation::{PersistMutation, RoleAclMutation};
use super::{DynSecError, DynSecResult};
use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PersistBatchOutcome {
    changed: bool,
    blocked: bool,
}

impl PersistBatchOutcome {
    pub(super) const fn new(changed: bool, blocked: bool) -> Self {
        Self { changed, blocked }
    }

    pub(super) const fn changed(self) -> bool {
        self.changed
    }

    pub(super) const fn blocked(self) -> bool {
        self.blocked
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PersistApplyOutcome {
    Changed,
    AlreadySatisfied,
    Blocked,
}

impl PersistApplyOutcome {
    const fn from_changed(changed: bool) -> Self {
        if changed {
            Self::Changed
        } else {
            Self::AlreadySatisfied
        }
    }

    const fn changed(self) -> bool {
        matches!(self, Self::Changed)
    }

    const fn blocked(self) -> bool {
        matches!(self, Self::Blocked)
    }
}

pub(super) fn apply_persist_mutations(
    root: &mut Value,
    mutations: &[PersistMutation],
) -> DynSecResult<PersistBatchOutcome> {
    let mut changed = false;
    let mut blocked = false;

    for mutation in mutations {
        let outcome = apply_persist_mutation(root, mutation)?;
        changed |= outcome.changed();
        blocked |= outcome.blocked();
    }

    Ok(PersistBatchOutcome::new(changed, blocked))
}

fn apply_persist_mutation(
    root: &mut Value,
    mutation: &PersistMutation,
) -> DynSecResult<PersistApplyOutcome> {
    match mutation {
        PersistMutation::SetClientDisabled { username, disabled } => {
            apply_set_client_disabled(root, username, *disabled)
        }
        PersistMutation::CreateRole { rolename, acls } => apply_create_role(root, rolename, acls),
        PersistMutation::DeleteRole { rolename } => apply_delete_role(root, rolename),
        PersistMutation::CreateGroup { groupname, roles } => {
            apply_create_group(root, groupname, roles)
        }
        PersistMutation::DeleteGroup { groupname } => apply_delete_group(root, groupname),
        PersistMutation::AddGroupClient {
            groupname,
            username,
            priority,
        } => apply_add_group_client(root, groupname, username, *priority),
        PersistMutation::RemoveGroupClient {
            groupname,
            username,
        } => apply_remove_group_client(root, groupname, username),
        PersistMutation::RoleAcl(RoleAclMutation::Add {
            rolename,
            acltype,
            topic,
            priority,
            allow,
        }) => apply_add_role_acl(root, rolename, acltype, topic, *priority, *allow),
        PersistMutation::RoleAcl(RoleAclMutation::Remove {
            rolename,
            acltype,
            topic,
        }) => apply_remove_role_acl(root, rolename, acltype, topic),
    }
}

fn apply_set_client_disabled(
    root: &mut Value,
    username: &str,
    disabled: bool,
) -> DynSecResult<PersistApplyOutcome> {
    let clients = ensure_array(root, "clients")?;
    let mut changed = false;
    let mut found = false;
    for client in &mut *clients {
        let Some(current_username) = client.get("username").and_then(Value::as_str) else {
            continue;
        };
        if current_username == username {
            found = true;
            let current_disabled = client
                .get("disabled")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if current_disabled != disabled {
                client["disabled"] = Value::Bool(disabled);
                changed = true;
            }
        }
    }
    if !found && disabled {
        changed |= persist_disabled_placeholder_client(clients, username);
    }
    Ok(PersistApplyOutcome::from_changed(changed))
}

fn apply_create_role(
    root: &mut Value,
    rolename: &str,
    acls: &[AclConfig],
) -> DynSecResult<PersistApplyOutcome> {
    let roles = ensure_array(root, "roles")?;
    if let Some(role) = roles
        .iter_mut()
        .find(|role| role.get("rolename").and_then(Value::as_str) == Some(rolename))
    {
        let mut changed = false;
        for acl in acls {
            changed |= upsert_acl_ref(role, acl)?.changed();
        }
        return Ok(PersistApplyOutcome::from_changed(changed));
    }

    let mut role = json!({ "rolename": rolename });
    if !acls.is_empty() {
        role["acls"] = Value::Array(acls.iter().map(acl_to_value).collect());
    }
    roles.push(role);
    Ok(PersistApplyOutcome::Changed)
}

fn apply_delete_role(root: &mut Value, rolename: &str) -> DynSecResult<PersistApplyOutcome> {
    let mut changed = false;
    if let Some(roles) = get_array_field(root, "roles")? {
        let before_len = roles.len();
        roles.retain(|role| role.get("rolename").and_then(Value::as_str) != Some(rolename));
        changed |= roles.len() != before_len;
    }
    if let Some(groups) = get_array_field(root, "groups")? {
        for group in groups {
            changed |= remove_named_ref(group, "roles", "rolename", rolename)?.changed();
        }
    }
    if let Some(clients) = get_array_field(root, "clients")? {
        for client in clients {
            changed |= remove_named_ref(client, "roles", "rolename", rolename)?.changed();
        }
    }
    Ok(PersistApplyOutcome::from_changed(changed))
}

fn apply_create_group(
    root: &mut Value,
    groupname: &str,
    roles: &[RoleRef],
) -> DynSecResult<PersistApplyOutcome> {
    let groups = ensure_array(root, "groups")?;
    if let Some(group) = groups
        .iter_mut()
        .find(|group| group.get("groupname").and_then(Value::as_str) == Some(groupname))
    {
        let mut changed = false;
        for role in roles {
            changed |= upsert_named_priority_ref(
                group,
                "roles",
                "rolename",
                &role.rolename,
                role.priority.unwrap_or(-1),
            )?
            .changed();
        }
        return Ok(PersistApplyOutcome::from_changed(changed));
    }

    let mut group = json!({ "groupname": groupname });
    if !roles.is_empty() {
        group["roles"] = Value::Array(roles.iter().map(role_ref_to_value).collect());
    }
    groups.push(group);
    Ok(PersistApplyOutcome::Changed)
}

fn apply_delete_group(root: &mut Value, groupname: &str) -> DynSecResult<PersistApplyOutcome> {
    let mut changed = false;
    if let Some(groups) = get_array_field(root, "groups")? {
        let before_len = groups.len();
        groups.retain(|group| group.get("groupname").and_then(Value::as_str) != Some(groupname));
        changed |= groups.len() != before_len;
    }
    if let Some(clients) = get_array_field(root, "clients")? {
        let mut index = 0;
        while index < clients.len() {
            changed |=
                remove_named_ref(&mut clients[index], "groups", "groupname", groupname)?.changed();
            if is_prunable_persisted_placeholder_client(&clients[index])? {
                clients.remove(index);
                changed = true;
                continue;
            }
            index += 1;
        }
    }
    if root.get("anonymousGroup").and_then(Value::as_str) == Some(groupname) {
        let object = root.as_object_mut().ok_or(DynSecError::RootNotObject)?;
        changed |= object.remove("anonymousGroup").is_some();
    }
    Ok(PersistApplyOutcome::from_changed(changed))
}

fn apply_add_group_client(
    root: &mut Value,
    groupname: &str,
    username: &str,
    priority: i32,
) -> DynSecResult<PersistApplyOutcome> {
    let mut changed = false;

    {
        let Some(groups) = get_array_field(root, "groups")? else {
            return Ok(PersistApplyOutcome::Blocked);
        };
        let Some(group) = groups
            .iter_mut()
            .find(|group| group.get("groupname").and_then(Value::as_str) == Some(groupname))
        else {
            return Ok(PersistApplyOutcome::Blocked);
        };

        changed |=
            upsert_named_priority_ref(group, "clients", "username", username, priority)?.changed();
    }

    let Some(clients) = get_array_field(root, "clients")? else {
        return Ok(PersistApplyOutcome::from_changed(changed));
    };
    if let Some(client) = clients
        .iter_mut()
        .find(|client| client.get("username").and_then(Value::as_str) == Some(username))
    {
        changed |= upsert_named_priority_ref(client, "groups", "groupname", groupname, priority)?
            .changed();
    }

    Ok(PersistApplyOutcome::from_changed(changed))
}

fn apply_remove_group_client(
    root: &mut Value,
    groupname: &str,
    username: &str,
) -> DynSecResult<PersistApplyOutcome> {
    let mut changed = false;
    if let Some(groups) = get_array_field(root, "groups")? {
        for group in groups {
            let Some(current_groupname) = group.get("groupname").and_then(Value::as_str) else {
                continue;
            };
            if current_groupname == groupname {
                changed |= remove_named_ref(group, "clients", "username", username)?.changed();
            }
        }
    }
    if let Some(clients) = get_array_field(root, "clients")? {
        for client in &mut *clients {
            let Some(current_username) = client.get("username").and_then(Value::as_str) else {
                continue;
            };
            if current_username == username {
                changed |= remove_named_ref(client, "groups", "groupname", groupname)?.changed();
            }
        }
        changed |= prune_persisted_placeholder_client(clients, username)?.changed();
    }
    Ok(PersistApplyOutcome::from_changed(changed))
}

fn apply_add_role_acl(
    root: &mut Value,
    rolename: &str,
    acltype: &str,
    topic: &str,
    priority: i32,
    allow: bool,
) -> DynSecResult<PersistApplyOutcome> {
    let Some(roles) = get_array_field(root, "roles")? else {
        return Ok(PersistApplyOutcome::Blocked);
    };

    for role in roles {
        let Some(current_rolename) = role.get("rolename").and_then(Value::as_str) else {
            continue;
        };
        if current_rolename != rolename {
            continue;
        }
        let acls = ensure_nested_array(role, "acls")?;
        for acl in acls.iter_mut() {
            let acl_acltype = acl.get("acltype").and_then(Value::as_str);
            let acl_topic = acl.get("topic").and_then(Value::as_str);
            if acl_acltype == Some(acltype) && acl_topic == Some(topic) {
                let current_priority = acl.get("priority").and_then(Value::as_i64).unwrap_or(0);
                let current_allow = acl.get("allow").and_then(Value::as_bool).unwrap_or(false);
                if current_priority == i64::from(priority) && current_allow == allow {
                    return Ok(PersistApplyOutcome::AlreadySatisfied);
                }
                acl["priority"] = Value::Number(priority.into());
                acl["allow"] = Value::Bool(allow);
                return Ok(PersistApplyOutcome::Changed);
            }
        }
        acls.push(json!({
            "acltype": acltype,
            "topic": topic,
            "priority": priority,
            "allow": allow,
        }));
        return Ok(PersistApplyOutcome::Changed);
    }
    Ok(PersistApplyOutcome::Blocked)
}

fn apply_remove_role_acl(
    root: &mut Value,
    rolename: &str,
    acltype: &str,
    topic: &str,
) -> DynSecResult<PersistApplyOutcome> {
    let Some(roles) = get_array_field(root, "roles")? else {
        return Ok(PersistApplyOutcome::AlreadySatisfied);
    };

    let mut changed = false;
    for role in roles {
        let Some(current_rolename) = role.get("rolename").and_then(Value::as_str) else {
            continue;
        };
        if current_rolename != rolename {
            continue;
        }
        if let Some(acls) = get_nested_array_field(role, "acls")? {
            let before_len = acls.len();
            acls.retain(|acl| {
                let acl_acltype = acl.get("acltype").and_then(Value::as_str);
                let acl_topic = acl.get("topic").and_then(Value::as_str);
                !(acl_acltype == Some(acltype) && acl_topic == Some(topic))
            });
            changed |= acls.len() != before_len;
        }
    }
    Ok(PersistApplyOutcome::from_changed(changed))
}

fn ensure_array<'a>(root: &'a mut Value, key: &str) -> DynSecResult<&'a mut Vec<Value>> {
    if root.get(key).is_none() {
        root[key] = Value::Array(Vec::new());
    }
    let Some(value) = root.get_mut(key) else {
        return Err(DynSecError::MissingField {
            field: key.to_string(),
        });
    };
    expect_array(value, key)
}

fn get_array_field<'a>(root: &'a mut Value, key: &str) -> DynSecResult<Option<&'a mut Vec<Value>>> {
    let Some(value) = root.get_mut(key) else {
        return Ok(None);
    };
    expect_array(value, key).map(Some)
}

fn ensure_nested_array<'a>(parent: &'a mut Value, field: &str) -> DynSecResult<&'a mut Vec<Value>> {
    if parent.get(field).is_none() {
        parent[field] = Value::Array(Vec::new());
    }
    let Some(value) = parent.get_mut(field) else {
        return Err(DynSecError::MissingField {
            field: field.to_string(),
        });
    };
    expect_array(value, field)
}

fn get_nested_array_field<'a>(
    parent: &'a mut Value,
    field: &str,
) -> DynSecResult<Option<&'a mut Vec<Value>>> {
    let Some(value) = parent.get_mut(field) else {
        return Ok(None);
    };
    expect_array(value, field).map(Some)
}

fn expect_array<'a>(value: &'a mut Value, field: &str) -> DynSecResult<&'a mut Vec<Value>> {
    value
        .as_array_mut()
        .ok_or_else(|| DynSecError::ExpectedArray {
            field: field.to_string(),
        })
}

fn remove_named_ref(
    parent: &mut Value,
    field: &str,
    name_field: &str,
    target: &str,
) -> DynSecResult<PersistApplyOutcome> {
    let Some(list) = get_nested_array_field(parent, field)? else {
        return Ok(PersistApplyOutcome::AlreadySatisfied);
    };
    let before_len = list.len();
    list.retain(|entry| entry.get(name_field).and_then(Value::as_str) != Some(target));
    Ok(PersistApplyOutcome::from_changed(list.len() != before_len))
}

fn prune_persisted_placeholder_client(
    clients: &mut Vec<Value>,
    username: &str,
) -> DynSecResult<PersistApplyOutcome> {
    let Some(index) = clients
        .iter()
        .position(|client| client.get("username").and_then(Value::as_str) == Some(username))
    else {
        return Ok(PersistApplyOutcome::AlreadySatisfied);
    };

    if !is_prunable_persisted_placeholder_client(&clients[index])? {
        return Ok(PersistApplyOutcome::AlreadySatisfied);
    }

    clients.remove(index);
    Ok(PersistApplyOutcome::Changed)
}

fn persist_disabled_placeholder_client(clients: &mut Vec<Value>, username: &str) -> bool {
    clients.push(json!({
        "username": username,
        "disabled": true,
    }));
    true
}

fn is_prunable_persisted_placeholder_client(client: &Value) -> DynSecResult<bool> {
    if client.get("username").and_then(Value::as_str).is_none() {
        return Ok(false);
    }

    let has_client_id = client
        .get("clientid")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty());
    let roles_empty = nested_array_missing_or_empty(client, "roles")?;
    let groups_empty = nested_array_missing_or_empty(client, "groups")?;
    let disabled = client
        .get("disabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    Ok(!has_client_id && roles_empty && groups_empty && !disabled)
}

pub(super) fn nested_array_missing_or_empty(parent: &Value, field: &str) -> DynSecResult<bool> {
    let Some(value) = parent.get(field) else {
        return Ok(true);
    };
    let Some(array) = value.as_array() else {
        return Err(DynSecError::ExpectedArray {
            field: field.to_string(),
        });
    };
    Ok(array.is_empty())
}

fn upsert_named_priority_ref(
    parent: &mut Value,
    field: &str,
    name_field: &str,
    target: &str,
    priority: i32,
) -> DynSecResult<PersistApplyOutcome> {
    let list = ensure_nested_array(parent, field)?;

    for entry in list.iter_mut() {
        let Some(current_target) = entry.get(name_field).and_then(Value::as_str) else {
            continue;
        };
        if current_target != target {
            continue;
        }

        let current_priority = entry.get("priority").and_then(Value::as_i64).unwrap_or(-1);
        if current_priority != i64::from(priority) {
            entry["priority"] = Value::Number(priority.into());
            return Ok(PersistApplyOutcome::Changed);
        }
        return Ok(PersistApplyOutcome::AlreadySatisfied);
    }

    list.push(json!({
        name_field: target,
        "priority": priority,
    }));
    Ok(PersistApplyOutcome::Changed)
}

fn upsert_acl_ref(parent: &mut Value, acl: &AclConfig) -> DynSecResult<PersistApplyOutcome> {
    let acls = ensure_nested_array(parent, "acls")?;

    for entry in acls.iter_mut() {
        let current_acltype = entry.get("acltype").and_then(Value::as_str);
        let current_topic = entry.get("topic").and_then(Value::as_str);
        if current_acltype != Some(acl.acltype.as_str())
            || current_topic != Some(acl.topic.as_str())
        {
            continue;
        }

        let current_priority = entry.get("priority").and_then(Value::as_i64);
        let current_allow = entry.get("allow").and_then(Value::as_bool);
        let next_priority = acl.priority.map(i64::from);
        let next_allow = acl.allow;
        if current_priority == next_priority && current_allow == next_allow {
            return Ok(PersistApplyOutcome::AlreadySatisfied);
        }

        if let Some(priority) = acl.priority {
            entry["priority"] = Value::Number(priority.into());
        } else {
            let _ = entry.as_object_mut().map(|obj| obj.remove("priority"));
        }
        if let Some(allow) = acl.allow {
            entry["allow"] = Value::Bool(allow);
        } else {
            let _ = entry.as_object_mut().map(|obj| obj.remove("allow"));
        }
        return Ok(PersistApplyOutcome::Changed);
    }

    acls.push(acl_to_value(acl));
    Ok(PersistApplyOutcome::Changed)
}

fn role_ref_to_value(role: &RoleRef) -> Value {
    let mut out = json!({ "rolename": role.rolename });
    if let Some(priority) = role.priority {
        out["priority"] = Value::Number(priority.into());
    }
    out
}

fn acl_to_value(acl: &AclConfig) -> Value {
    let mut out = json!({
        "acltype": acl.acltype,
        "topic": acl.topic,
    });
    if let Some(priority) = acl.priority {
        out["priority"] = Value::Number(priority.into());
    }
    if let Some(allow) = acl.allow {
        out["allow"] = Value::Bool(allow);
    }
    out
}
