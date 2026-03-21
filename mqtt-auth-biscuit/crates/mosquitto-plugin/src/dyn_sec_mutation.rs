use super::dyn_sec_model::{
    AccessKind, AclConfig, AclEntry, AclType, DynSecClient, DynSecGroup, DynSecRole, DynSecState,
    RoleAclKey, RoleRef, RuntimeRoleAclOverride, group_member_usernames, role_member_usernames,
};
use super::{
    delete_group_from_state, merge_persist_group_roles, merge_persist_role_acls,
    prune_placeholder_client, state_allows_username_access,
};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ControlPayload {
    #[serde(default)]
    pub commands: Vec<ControlCommand>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ControlCommand {
    pub command: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub groupname: Option<String>,
    #[serde(default)]
    pub rolename: Option<String>,
    #[serde(default)]
    pub roles: Option<Vec<RoleRef>>,
    #[serde(default)]
    pub acls: Option<Vec<AclConfig>>,
    #[serde(default)]
    pub acltype: Option<String>,
    #[serde(default)]
    pub topic: Option<String>,
    #[serde(default)]
    pub priority: Option<i32>,
    #[serde(default)]
    pub allow: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlCommandKind {
    DisableClient,
    EnableClient,
    CreateRole,
    DeleteRole,
    CreateGroup,
    DeleteGroup,
    AddGroupClient,
    RemoveGroupClient,
    AddRoleAcl,
    RemoveRoleAcl,
}

impl ControlCommandKind {
    pub(crate) fn parse(command: &str) -> Option<Self> {
        match command.trim() {
            "disableClient" => Some(Self::DisableClient),
            "enableClient" => Some(Self::EnableClient),
            "createRole" => Some(Self::CreateRole),
            "deleteRole" => Some(Self::DeleteRole),
            "createGroup" => Some(Self::CreateGroup),
            "deleteGroup" => Some(Self::DeleteGroup),
            "addGroupClient" => Some(Self::AddGroupClient),
            "removeGroupClient" => Some(Self::RemoveGroupClient),
            "addRoleACL" => Some(Self::AddRoleAcl),
            "removeRoleACL" => Some(Self::RemoveRoleAcl),
            _ => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::DisableClient => "disableClient",
            Self::EnableClient => "enableClient",
            Self::CreateRole => "createRole",
            Self::DeleteRole => "deleteRole",
            Self::CreateGroup => "createGroup",
            Self::DeleteGroup => "deleteGroup",
            Self::AddGroupClient => "addGroupClient",
            Self::RemoveGroupClient => "removeGroupClient",
            Self::AddRoleAcl => "addRoleACL",
            Self::RemoveRoleAcl => "removeRoleACL",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ControlEnforcementTargets {
    pub kick_client_ids: Vec<String>,
    pub kick_usernames: Vec<String>,
    pub notify_events: Vec<ControlNotifyEvent>,
    pub persist_warning: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ControlMutationDraft {
    // Notify events are computed as a net revocation diff across the whole payload.
    pub initial_state: DynSecState,
    pub state: DynSecState,
    pub initial_runtime_disabled_usernames: HashSet<String>,
    pub runtime_disabled_usernames: HashSet<String>,
    pub runtime_role_acl_overrides: HashMap<RoleAclKey, RuntimeRoleAclOverride>,
    pub kick_client_ids: HashSet<String>,
    pub kick_usernames: HashSet<String>,
    pub pending_notify_candidates: Vec<PendingNotifyCandidate>,
    pub notify_events: Vec<ControlNotifyEvent>,
    pub persist_mutations: Vec<PersistMutation>,
    pub changed: bool,
}

impl ControlMutationDraft {
    pub(crate) fn new(
        state: DynSecState,
        runtime_disabled_usernames: HashSet<String>,
        runtime_role_acl_overrides: HashMap<RoleAclKey, RuntimeRoleAclOverride>,
    ) -> Self {
        Self {
            initial_state: state.clone(),
            state,
            initial_runtime_disabled_usernames: runtime_disabled_usernames.clone(),
            runtime_disabled_usernames,
            runtime_role_acl_overrides,
            kick_client_ids: HashSet::new(),
            kick_usernames: HashSet::new(),
            pending_notify_candidates: Vec::new(),
            notify_events: Vec::new(),
            persist_mutations: Vec::new(),
            changed: false,
        }
    }

    pub(crate) fn apply_command(&mut self, cmd: &ControlCommand) {
        let Some(command) = ControlCommandKind::parse(&cmd.command) else {
            return;
        };

        match command {
            ControlCommandKind::DisableClient | ControlCommandKind::EnableClient => {
                self.apply_client_disable_command(command, cmd);
            }
            ControlCommandKind::CreateRole => self.apply_create_role_command(cmd),
            ControlCommandKind::DeleteRole => self.apply_delete_role_command(cmd),
            ControlCommandKind::CreateGroup => self.apply_create_group_command(cmd),
            ControlCommandKind::DeleteGroup => self.apply_delete_group_command(cmd),
            ControlCommandKind::AddGroupClient | ControlCommandKind::RemoveGroupClient => {
                self.apply_group_client_command(command, cmd);
            }
            ControlCommandKind::AddRoleAcl | ControlCommandKind::RemoveRoleAcl => {
                self.apply_role_acl_command(command, cmd);
            }
        }
    }

    fn apply_create_role_command(&mut self, cmd: &ControlCommand) {
        let Some(rolename) = cmd
            .rolename
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return;
        };

        if self.state.roles.contains_key(rolename) {
            return;
        }

        self.state.roles.insert(
            rolename.to_string(),
            DynSecRole::from_control_acls(cmd.acls.clone()),
        );
        self.persist_mutations.push(PersistMutation::CreateRole {
            rolename: rolename.to_string(),
            acls: cmd.acls.clone().unwrap_or_default(),
        });
        self.changed = true;
    }

    fn apply_delete_role_command(&mut self, cmd: &ControlCommand) {
        let Some(rolename) = cmd
            .rolename
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return;
        };

        if self.state.roles.remove(rolename).is_none() {
            return;
        }
        for client in self.state.clients.values_mut() {
            client.remove_role(rolename);
        }
        for group in self.state.groups.values_mut() {
            group.remove_role(rolename);
        }
        let before_len = self.runtime_role_acl_overrides.len();
        self.runtime_role_acl_overrides
            .retain(|key, _| key.rolename != rolename);
        self.changed |= self.runtime_role_acl_overrides.len() != before_len;
        self.persist_mutations.push(PersistMutation::DeleteRole {
            rolename: rolename.to_string(),
        });
        self.queue_role_publish_receive_revocation_candidates(
            ControlCommandKind::DeleteRole,
            rolename,
            None,
        );
        self.changed = true;
    }

    fn apply_create_group_command(&mut self, cmd: &ControlCommand) {
        let Some(groupname) = cmd
            .groupname
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return;
        };

        if self.state.groups.contains_key(groupname) {
            return;
        }

        self.state.groups.insert(
            groupname.to_string(),
            DynSecGroup::from_control_roles(cmd.roles.clone()),
        );
        self.persist_mutations.push(PersistMutation::CreateGroup {
            groupname: groupname.to_string(),
            roles: cmd.roles.clone().unwrap_or_default(),
        });
        self.changed = true;
    }

    fn apply_delete_group_command(&mut self, cmd: &ControlCommand) {
        let Some(groupname) = cmd
            .groupname
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return;
        };

        if !delete_group_from_state(&mut self.state, groupname) {
            return;
        }
        self.persist_mutations.push(PersistMutation::DeleteGroup {
            groupname: groupname.to_string(),
        });
        self.queue_group_publish_receive_revocation_candidates(
            ControlCommandKind::DeleteGroup,
            groupname,
            None,
        );
        self.changed = true;
    }

    fn apply_client_disable_command(&mut self, command: ControlCommandKind, cmd: &ControlCommand) {
        let Some(username) = cmd
            .username
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return;
        };

        if command == ControlCommandKind::EnableClient {
            self.persist_mutations
                .push(PersistMutation::SetClientDisabled {
                    username: username.to_string(),
                    disabled: false,
                });
        }

        let Some(client) = self.state.clients.get_mut(username) else {
            if command == ControlCommandKind::EnableClient {
                self.changed |= self.runtime_disabled_usernames.remove(username);
            }
            return;
        };

        if command == ControlCommandKind::DisableClient {
            if client.disabled {
                return;
            }
            client.disabled = true;
            self.changed = true;
            self.persist_mutations
                .push(PersistMutation::SetClientDisabled {
                    username: username.to_string(),
                    disabled: true,
                });
            self.changed |= self.runtime_disabled_usernames.insert(username.to_string());
            self.kick_usernames.insert(username.to_string());
            if let Some(client_id) = client.client_id.as_ref() {
                self.kick_client_ids.insert(client_id.clone());
            }
            return;
        }

        let was_disabled = client.disabled;
        client.disabled = false;
        self.changed |= was_disabled;
        self.changed |= self.runtime_disabled_usernames.remove(username);
        self.kick_usernames.remove(username);
        if was_disabled && let Some(client_id) = client.client_id.as_ref() {
            self.kick_client_ids.remove(client_id);
        }
    }

    fn apply_group_client_command(&mut self, command: ControlCommandKind, cmd: &ControlCommand) {
        let Some(groupname) = cmd
            .groupname
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return;
        };
        let Some(username) = cmd
            .username
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return;
        };

        let mut changed = false;
        if command == ControlCommandKind::AddGroupClient {
            let priority = cmd.priority.unwrap_or(0);
            let Some(group) = self.state.groups.get_mut(groupname) else {
                return;
            };
            changed |= group.add_client(username, priority);
            let client = self
                .state
                .clients
                .entry(username.to_string())
                .or_insert_with(|| DynSecClient::placeholder(username));
            changed |= client.add_group(groupname, priority);
            if changed {
                self.persist_mutations
                    .push(PersistMutation::AddGroupClient {
                        groupname: groupname.to_string(),
                        username: username.to_string(),
                        priority,
                    });
            }
        } else {
            if let Some(group) = self.state.groups.get_mut(groupname) {
                changed |= group.remove_client(username);
            }
            if let Some(client) = self.state.clients.get_mut(username) {
                changed |= client.remove_group(groupname);
            }
            changed |= self.prune_placeholder_client(username);
            if changed {
                self.persist_mutations
                    .push(PersistMutation::RemoveGroupClient {
                        groupname: groupname.to_string(),
                        username: username.to_string(),
                    });
                self.queue_group_publish_receive_revocation_candidates(
                    command,
                    groupname,
                    Some(username),
                );
            }
        }
        self.changed |= changed;
    }

    pub fn prune_placeholder_client(&mut self, username: &str) -> bool {
        prune_placeholder_client(&mut self.state, username)
    }

    pub fn queue_role_publish_receive_revocation_candidates(
        &mut self,
        command: ControlCommandKind,
        rolename: &str,
        usernames: Option<Vec<String>>,
    ) {
        let Some(role) = self.initial_state.roles.get(rolename) else {
            return;
        };
        let usernames =
            usernames.unwrap_or_else(|| role_member_usernames(&self.initial_state, rolename));
        if usernames.is_empty() {
            return;
        }

        let topics: Vec<String> = role
            .acls
            .publish_c_recv
            .iter()
            .filter(|acl| acl.allow && !acl.topic.starts_with("$CONTROL/"))
            .map(|acl| acl.topic.clone())
            .collect();
        for topic in topics {
            self.queue_publish_receive_revocation_candidate(command, rolename, &topic, &usernames);
        }
    }

    pub fn queue_group_publish_receive_revocation_candidates(
        &mut self,
        command: ControlCommandKind,
        groupname: &str,
        username: Option<&str>,
    ) {
        let Some(group) = self.initial_state.groups.get(groupname) else {
            return;
        };
        let usernames = username.map_or_else(
            || group_member_usernames(&self.initial_state, groupname),
            |value| vec![value.to_string()],
        );
        if usernames.is_empty() {
            return;
        }

        let role_names: Vec<String> = group
            .roles
            .iter()
            .map(|role_ref| role_ref.name.clone())
            .collect();
        for role_name in role_names {
            self.queue_role_publish_receive_revocation_candidates(
                command,
                &role_name,
                Some(usernames.clone()),
            );
        }
    }

    pub fn queue_publish_receive_revocation_candidate(
        &mut self,
        command: ControlCommandKind,
        rolename: &str,
        topic: &str,
        candidate_usernames: &[String],
    ) {
        let usernames =
            self.usernames_with_initial_publish_receive_access(candidate_usernames, topic);
        if usernames.is_empty() {
            return;
        }

        self.pending_notify_candidates.push(PendingNotifyCandidate {
            command: command.as_str().to_string(),
            rolename: rolename.to_string(),
            topic: topic.to_string(),
            usernames,
        });
    }

    pub fn usernames_with_initial_publish_receive_access(
        &self,
        candidate_usernames: &[String],
        topic: &str,
    ) -> Vec<String> {
        let mut usernames = Vec::new();
        for username in candidate_usernames {
            let had_access = state_allows_username_access(
                &self.initial_state,
                &self.initial_runtime_disabled_usernames,
                username,
                topic,
                AccessKind::PublishReceive,
            );
            if had_access {
                usernames.push(username.clone());
            }
        }
        usernames.sort();
        usernames.dedup();
        usernames
    }

    pub fn finalize_notify_events(&mut self) {
        // Emit read-policy notifications only for access lost in the final payload state.
        let mut aggregated_usernames: HashMap<NotifyEventKey, Vec<String>> = HashMap::new();
        for candidate in &self.pending_notify_candidates {
            let mut usernames: Vec<String> = candidate
                .usernames
                .iter()
                .filter(|username| {
                    !state_allows_username_access(
                        &self.state,
                        &self.runtime_disabled_usernames,
                        username,
                        &candidate.topic,
                        AccessKind::PublishReceive,
                    )
                })
                .cloned()
                .collect();
            if usernames.is_empty() {
                continue;
            }
            usernames.sort();
            usernames.dedup();
            aggregated_usernames
                .entry(NotifyEventKey::from_candidate(candidate))
                .or_default()
                .extend(usernames);
        }
        let mut notify_events: Vec<ControlNotifyEvent> = aggregated_usernames
            .into_iter()
            .map(|(key, mut usernames)| {
                usernames.sort();
                usernames.dedup();
                ControlNotifyEvent {
                    command: key.command,
                    rolename: Some(key.rolename),
                    acltype: Some("publishClientReceive".to_string()),
                    topic: Some(key.topic),
                    usernames,
                }
            })
            .collect();
        notify_events.sort_by(|a, b| {
            a.command
                .cmp(&b.command)
                .then_with(|| a.rolename.cmp(&b.rolename))
                .then_with(|| a.topic.cmp(&b.topic))
        });
        self.notify_events = notify_events;
        self.pending_notify_candidates.clear();
    }

    fn apply_role_acl_command(&mut self, command: ControlCommandKind, cmd: &ControlCommand) {
        let Some(rolename) = cmd
            .rolename
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return;
        };
        let Some(acltype) = cmd
            .acltype
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return;
        };
        let Some(topic) = cmd
            .topic
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return;
        };
        let Some(parsed_acl_type) = AclType::from_control_str(acltype) else {
            return;
        };

        let Some(role) = self.state.roles.get_mut(rolename) else {
            return;
        };

        if command == ControlCommandKind::RemoveRoleAcl {
            let removed_acl = role.acls.remove_acl_entry(parsed_acl_type, topic);
            if let Some(removed_acl) = removed_acl {
                self.changed = true;
                self.persist_mutations
                    .push(PersistMutation::RoleAcl(RoleAclMutation::Remove {
                        rolename: rolename.to_string(),
                        acltype: acltype.to_string(),
                        topic: topic.to_string(),
                    }));
                self.runtime_role_acl_overrides.insert(
                    RoleAclKey::new(rolename, parsed_acl_type, topic),
                    RuntimeRoleAclOverride::Remove,
                );
                if removed_acl.allow
                    && removed_acl.acl_type == AclType::PublishClientReceive
                    && !removed_acl.topic.starts_with("$CONTROL/")
                {
                    let usernames = role_member_usernames(&self.initial_state, rolename);
                    self.queue_publish_receive_revocation_candidate(
                        command, rolename, topic, &usernames,
                    );
                }
            }
            return;
        }

        let allow = cmd.allow.unwrap_or(false);
        let priority = cmd.priority.unwrap_or(0);
        let changed = role.acls.upsert_acl_entry(AclEntry {
            acl_type: parsed_acl_type,
            topic: topic.to_string(),
            allow,
            priority,
        });
        if !changed {
            return;
        }

        self.changed = true;
        self.persist_mutations
            .push(PersistMutation::RoleAcl(RoleAclMutation::Add {
                rolename: rolename.to_string(),
                acltype: acltype.to_string(),
                topic: topic.to_string(),
                priority,
                allow,
            }));
        self.runtime_role_acl_overrides.insert(
            RoleAclKey::new(rolename, parsed_acl_type, topic),
            RuntimeRoleAclOverride::Add { priority, allow },
        );
        if !allow
            && parsed_acl_type == AclType::PublishClientReceive
            && !topic.starts_with("$CONTROL/")
        {
            let usernames = role_member_usernames(&self.initial_state, rolename);
            self.queue_publish_receive_revocation_candidate(command, rolename, topic, &usernames);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ControlNotifyEvent {
    pub command: String,
    pub rolename: Option<String>,
    pub acltype: Option<String>,
    pub topic: Option<String>,
    pub usernames: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingNotifyCandidate {
    pub command: String,
    pub rolename: String,
    pub topic: String,
    pub usernames: Vec<String>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct NotifyEventKey {
    pub command: String,
    pub rolename: String,
    pub topic: String,
}

impl NotifyEventKey {
    fn from_candidate(candidate: &PendingNotifyCandidate) -> Self {
        Self {
            command: candidate.command.clone(),
            rolename: candidate.rolename.clone(),
            topic: candidate.topic.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum RoleAclMutation {
    Add {
        rolename: String,
        acltype: String,
        topic: String,
        priority: i32,
        allow: bool,
    },
    Remove {
        rolename: String,
        acltype: String,
        topic: String,
    },
}

#[derive(Debug, Clone)]
pub(crate) enum PersistMutation {
    SetClientDisabled {
        username: String,
        disabled: bool,
    },
    CreateRole {
        rolename: String,
        acls: Vec<AclConfig>,
    },
    DeleteRole {
        rolename: String,
    },
    CreateGroup {
        groupname: String,
        roles: Vec<RoleRef>,
    },
    DeleteGroup {
        groupname: String,
    },
    AddGroupClient {
        groupname: String,
        username: String,
        priority: i32,
    },
    RemoveGroupClient {
        groupname: String,
        username: String,
    },
    RoleAcl(RoleAclMutation),
}

impl PersistMutation {
    /// Returns whether this mutation should be replayed against freshly-loaded state
    /// during a config reload while the pending queue is non-empty.
    ///
    /// **Limitation**: `RoleAcl` variants return `false` — they are *not* replayed on
    /// reload. Instead, the `runtime_role_acl_overrides` map covers them at check-time.
    /// The two mechanisms can diverge: if a pending `addRoleACL` has not been flushed
    /// and a subsequent `deleteRole` removes the runtime override, the ACL change is
    /// lost from both the file and the override map. This is acceptable because the
    /// `deleteRole` semantics intentionally discard all ACLs for that role, and the
    /// pending persist queue's `RetryIntentReducer` will also drop orphaned ACL intents
    /// when it sees the role deletion.
    pub(crate) const fn is_replayed_on_reload(&self) -> bool {
        matches!(
            self,
            Self::SetClientDisabled { .. }
                | Self::CreateRole { .. }
                | Self::DeleteRole { .. }
                | Self::CreateGroup { .. }
                | Self::DeleteGroup { .. }
                | Self::AddGroupClient { .. }
                | Self::RemoveGroupClient { .. }
        )
    }
}

#[derive(Debug, Clone)]
pub(crate) enum PendingRoleLifecycle {
    Create { acls: Vec<AclConfig> },
    Delete,
    DeleteThenCreate { acls: Vec<AclConfig> },
}

#[derive(Debug, Clone)]
pub(crate) enum PendingGroupLifecycle {
    Create { roles: Vec<RoleRef> },
    Delete,
    DeleteThenCreate { roles: Vec<RoleRef> },
}

impl PendingRoleLifecycle {
    fn create_acls(&self) -> Option<&[AclConfig]> {
        match self {
            Self::Create { acls } | Self::DeleteThenCreate { acls } => Some(acls),
            Self::Delete => None,
        }
    }

    fn requires_delete_persist(&self) -> bool {
        matches!(self, Self::Delete | Self::DeleteThenCreate { .. })
    }

    fn is_delete_only(&self) -> bool {
        matches!(self, Self::Delete)
    }
}

impl PendingGroupLifecycle {
    fn create_roles(&self) -> Option<&[RoleRef]> {
        match self {
            Self::Create { roles } | Self::DeleteThenCreate { roles } => Some(roles),
            Self::Delete => None,
        }
    }

    fn requires_delete_persist(&self) -> bool {
        matches!(self, Self::Delete | Self::DeleteThenCreate { .. })
    }

    fn is_delete_only(&self) -> bool {
        matches!(self, Self::Delete)
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum PendingGroupClientMutation {
    Add { priority: i32 },
    Remove,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum PendingRoleAclMutation {
    Add { priority: i32, allow: bool },
    Remove,
}

#[derive(Debug, Default)]
pub(crate) struct RetryIntentReducer {
    pub client_disabled: BTreeMap<String, bool>,
    pub roles: BTreeMap<String, PendingRoleLifecycle>,
    pub groups: BTreeMap<String, PendingGroupLifecycle>,
    pub group_clients: BTreeMap<(String, String), PendingGroupClientMutation>,
    pub role_acls: BTreeMap<(String, String, String), PendingRoleAclMutation>,
}

impl RetryIntentReducer {
    pub(crate) fn apply(&mut self, mutation: &PersistMutation) {
        match mutation {
            PersistMutation::SetClientDisabled { username, disabled } => {
                self.client_disabled.insert(username.clone(), *disabled);
            }
            PersistMutation::CreateRole { rolename, acls } => {
                self.apply_role_create(rolename, acls);
            }
            PersistMutation::DeleteRole { rolename } => self.apply_role_delete(rolename),
            PersistMutation::CreateGroup {
                groupname,
                roles: role_refs,
            } => self.apply_group_create(groupname, role_refs),
            PersistMutation::DeleteGroup { groupname } => self.apply_group_delete(groupname),
            PersistMutation::AddGroupClient {
                groupname,
                username,
                priority,
            } => self.apply_group_client_intent(
                groupname,
                username,
                PendingGroupClientMutation::Add {
                    priority: *priority,
                },
            ),
            PersistMutation::RemoveGroupClient {
                groupname,
                username,
            } => self.apply_group_client_intent(
                groupname,
                username,
                PendingGroupClientMutation::Remove,
            ),
            PersistMutation::RoleAcl(RoleAclMutation::Add {
                rolename,
                acltype,
                topic,
                priority,
                allow,
            }) => self.apply_role_acl_intent(
                rolename,
                acltype,
                topic,
                PendingRoleAclMutation::Add {
                    priority: *priority,
                    allow: *allow,
                },
            ),
            PersistMutation::RoleAcl(RoleAclMutation::Remove {
                rolename,
                acltype,
                topic,
            }) => {
                self.apply_role_acl_intent(
                    rolename,
                    acltype,
                    topic,
                    PendingRoleAclMutation::Remove,
                );
            }
        }
    }

    fn apply_role_create(&mut self, rolename: &str, acls: &[AclConfig]) {
        let merged_acls = match self.roles.remove(rolename) {
            Some(PendingRoleLifecycle::Create { acls: existing }) => PendingRoleLifecycle::Create {
                acls: merge_persist_role_acls(&existing, acls),
            },
            Some(PendingRoleLifecycle::Delete) => PendingRoleLifecycle::DeleteThenCreate {
                acls: acls.to_vec(),
            },
            Some(PendingRoleLifecycle::DeleteThenCreate { acls: existing }) => {
                PendingRoleLifecycle::DeleteThenCreate {
                    acls: merge_persist_role_acls(&existing, acls),
                }
            }
            None => PendingRoleLifecycle::Create {
                acls: acls.to_vec(),
            },
        };
        self.roles.insert(rolename.to_string(), merged_acls);
    }

    fn apply_role_delete(&mut self, rolename: &str) {
        self.roles
            .insert(rolename.to_string(), PendingRoleLifecycle::Delete);
        self.role_acls
            .retain(|(current_role, _, _), _| current_role != rolename);
    }

    fn apply_group_create(&mut self, groupname: &str, roles: &[RoleRef]) {
        let merged_roles = match self.groups.remove(groupname) {
            Some(PendingGroupLifecycle::Create {
                roles: existing_roles,
            }) => PendingGroupLifecycle::Create {
                roles: merge_persist_group_roles(&existing_roles, roles),
            },
            Some(PendingGroupLifecycle::Delete) => PendingGroupLifecycle::DeleteThenCreate {
                roles: roles.to_vec(),
            },
            Some(PendingGroupLifecycle::DeleteThenCreate {
                roles: existing_roles,
            }) => PendingGroupLifecycle::DeleteThenCreate {
                roles: merge_persist_group_roles(&existing_roles, roles),
            },
            None => PendingGroupLifecycle::Create {
                roles: roles.to_vec(),
            },
        };
        self.groups.insert(groupname.to_string(), merged_roles);
    }

    fn apply_group_delete(&mut self, groupname: &str) {
        self.groups
            .insert(groupname.to_string(), PendingGroupLifecycle::Delete);
        self.group_clients
            .retain(|(current_group, _), _| current_group != groupname);
    }

    fn apply_group_client_intent(
        &mut self,
        groupname: &str,
        username: &str,
        mutation: PendingGroupClientMutation,
    ) {
        self.group_clients
            .insert((groupname.to_string(), username.to_string()), mutation);
    }

    fn apply_role_acl_intent(
        &mut self,
        rolename: &str,
        acltype: &str,
        topic: &str,
        mutation: PendingRoleAclMutation,
    ) {
        self.role_acls.insert(
            (rolename.to_string(), acltype.to_string(), topic.to_string()),
            mutation,
        );
    }

    pub(crate) fn into_persist_mutations(self) -> Vec<PersistMutation> {
        let RetryIntentReducer {
            client_disabled,
            roles,
            groups,
            group_clients,
            role_acls,
        } = self;

        let mut collapsed = Vec::new();

        // Order matters: persist cleanup deletes before recreate, then emit
        // dependent membership / ACL intents so disk state converges to the
        // already-applied runtime state.
        Self::emit_delete_cleanup_phase(&mut collapsed, &groups, &roles);
        Self::emit_create_phase(&mut collapsed, &roles, &groups);
        Self::emit_membership_add_phase(&mut collapsed, &groups, &group_clients);
        Self::emit_runtime_disable_phase(&mut collapsed, client_disabled);
        Self::emit_role_acl_add_phase(&mut collapsed, &roles, &role_acls);
        Self::emit_membership_remove_phase(&mut collapsed, &groups, &group_clients);
        Self::emit_role_acl_remove_phase(&mut collapsed, &roles, &role_acls);

        collapsed
    }

    fn emit_delete_cleanup_phase(
        collapsed: &mut Vec<PersistMutation>,
        groups: &BTreeMap<String, PendingGroupLifecycle>,
        roles: &BTreeMap<String, PendingRoleLifecycle>,
    ) {
        for (groupname, lifecycle) in groups {
            if lifecycle.requires_delete_persist() {
                collapsed.push(PersistMutation::DeleteGroup {
                    groupname: groupname.clone(),
                });
            }
        }

        for (rolename, lifecycle) in roles {
            if lifecycle.requires_delete_persist() {
                collapsed.push(PersistMutation::DeleteRole {
                    rolename: rolename.clone(),
                });
            }
        }
    }

    fn emit_create_phase(
        collapsed: &mut Vec<PersistMutation>,
        roles: &BTreeMap<String, PendingRoleLifecycle>,
        groups: &BTreeMap<String, PendingGroupLifecycle>,
    ) {
        for (rolename, lifecycle) in roles {
            if let Some(acls) = lifecycle.create_acls() {
                collapsed.push(PersistMutation::CreateRole {
                    rolename: rolename.clone(),
                    acls: acls.to_vec(),
                });
            }
        }

        for (groupname, lifecycle) in groups {
            if let Some(roles) = lifecycle.create_roles() {
                collapsed.push(PersistMutation::CreateGroup {
                    groupname: groupname.clone(),
                    roles: roles.to_vec(),
                });
            }
        }
    }

    fn emit_membership_add_phase(
        collapsed: &mut Vec<PersistMutation>,
        groups: &BTreeMap<String, PendingGroupLifecycle>,
        group_clients: &BTreeMap<(String, String), PendingGroupClientMutation>,
    ) {
        for ((groupname, username), mutation) in group_clients {
            if groups
                .get(groupname)
                .is_some_and(PendingGroupLifecycle::is_delete_only)
            {
                continue;
            }
            if let PendingGroupClientMutation::Add { priority } = mutation {
                collapsed.push(PersistMutation::AddGroupClient {
                    groupname: groupname.clone(),
                    username: username.clone(),
                    priority: *priority,
                });
            }
        }
    }

    fn emit_runtime_disable_phase(
        collapsed: &mut Vec<PersistMutation>,
        client_disabled: BTreeMap<String, bool>,
    ) {
        for (username, disabled) in client_disabled {
            collapsed.push(PersistMutation::SetClientDisabled { username, disabled });
        }
    }

    fn emit_role_acl_add_phase(
        collapsed: &mut Vec<PersistMutation>,
        roles: &BTreeMap<String, PendingRoleLifecycle>,
        role_acls: &BTreeMap<(String, String, String), PendingRoleAclMutation>,
    ) {
        for ((rolename, acltype, topic), mutation) in role_acls {
            if roles
                .get(rolename)
                .is_some_and(PendingRoleLifecycle::is_delete_only)
            {
                continue;
            }
            if let PendingRoleAclMutation::Add { priority, allow } = mutation {
                collapsed.push(PersistMutation::RoleAcl(RoleAclMutation::Add {
                    rolename: rolename.clone(),
                    acltype: acltype.clone(),
                    topic: topic.clone(),
                    priority: *priority,
                    allow: *allow,
                }));
            }
        }
    }

    fn emit_membership_remove_phase(
        collapsed: &mut Vec<PersistMutation>,
        groups: &BTreeMap<String, PendingGroupLifecycle>,
        group_clients: &BTreeMap<(String, String), PendingGroupClientMutation>,
    ) {
        for ((groupname, username), mutation) in group_clients {
            if groups
                .get(groupname)
                .is_some_and(PendingGroupLifecycle::is_delete_only)
            {
                continue;
            }
            if matches!(mutation, PendingGroupClientMutation::Remove) {
                collapsed.push(PersistMutation::RemoveGroupClient {
                    groupname: groupname.clone(),
                    username: username.clone(),
                });
            }
        }
    }

    fn emit_role_acl_remove_phase(
        collapsed: &mut Vec<PersistMutation>,
        roles: &BTreeMap<String, PendingRoleLifecycle>,
        role_acls: &BTreeMap<(String, String, String), PendingRoleAclMutation>,
    ) {
        for ((rolename, acltype, topic), mutation) in role_acls {
            if roles
                .get(rolename)
                .is_some_and(PendingRoleLifecycle::is_delete_only)
            {
                continue;
            }
            if matches!(mutation, PendingRoleAclMutation::Remove) {
                collapsed.push(PersistMutation::RoleAcl(RoleAclMutation::Remove {
                    rolename: rolename.clone(),
                    acltype: acltype.clone(),
                    topic: topic.clone(),
                }));
            }
        }
    }
}
