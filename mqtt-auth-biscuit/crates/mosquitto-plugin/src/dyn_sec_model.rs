use serde::Deserialize;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct RoleAclKey {
    pub rolename: String,
    pub acl_type: AclType,
    pub topic: String,
}

impl RoleAclKey {
    pub(crate) fn new(rolename: &str, acl_type: AclType, topic: &str) -> Self {
        Self {
            rolename: rolename.to_string(),
            acl_type,
            topic: topic.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum RuntimeRoleAclOverride {
    Remove,
    Add { priority: i32, allow: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccessKind {
    PublishSend,
    PublishReceive,
    Subscribe,
    Unsubscribe,
    Unknown,
}

impl AccessKind {
    pub(crate) const fn from_access(access: i32) -> Self {
        if (access & ACL_WRITE) != 0 {
            Self::PublishSend
        } else if (access & ACL_SUBSCRIBE) != 0 {
            Self::Subscribe
        } else if (access & ACL_UNSUBSCRIBE) != 0 {
            Self::Unsubscribe
        } else if (access & ACL_READ) != 0 {
            Self::PublishReceive
        } else {
            Self::Unknown
        }
    }
}

pub(crate) const ACL_READ: i32 = 0x01;
pub(crate) const ACL_WRITE: i32 = 0x02;
pub(crate) const ACL_SUBSCRIBE: i32 = 0x04;
pub(crate) const ACL_UNSUBSCRIBE: i32 = 0x08;

#[derive(Debug, Clone, Default)]
pub(crate) struct DynSecState {
    pub clients: HashMap<String, DynSecClient>,
    pub groups: HashMap<String, DynSecGroup>,
    pub roles: HashMap<String, DynSecRole>,
    pub default_access: DefaultAclAccess,
    pub anonymous_group: Option<String>,
}

impl DynSecState {
    pub(crate) fn from_config(cfg: DynSecConfig) -> Self {
        let mut roles = HashMap::new();
        if let Some(list) = cfg.roles {
            for role in list {
                roles.insert(role.rolename.clone(), DynSecRole::from_config(role));
            }
        }

        let mut groups = HashMap::new();
        if let Some(list) = cfg.groups {
            for group in list {
                groups.insert(group.groupname.clone(), DynSecGroup::from_config(group));
            }
        }

        let mut clients = HashMap::new();
        if let Some(list) = cfg.clients {
            for client in list {
                clients.insert(client.username.clone(), DynSecClient::from_config(client));
            }
        }

        for (group_name, group) in &groups {
            for client_ref in &group.clients {
                let entry = clients
                    .entry(client_ref.name.clone())
                    .or_insert_with(|| DynSecClient::placeholder(&client_ref.name));
                merge_name_priority_by_max(&mut entry.groups, group_name, client_ref.priority);
            }
        }

        Self {
            clients,
            groups,
            roles,
            default_access: DefaultAclAccess::from_config(cfg.default_acl_access),
            anonymous_group: cfg.anonymous_group,
        }
    }
}

pub(crate) fn role_member_usernames(state: &DynSecState, rolename: &str) -> Vec<String> {
    let mut usernames = HashSet::new();
    for (username, client) in &state.clients {
        let has_direct_role = client.roles.iter().any(|role| role.name == rolename);
        let has_group_role = client.groups.iter().any(|group_ref| {
            state
                .groups
                .get(&group_ref.name)
                .is_some_and(|group| group.roles.iter().any(|role| role.name == rolename))
        });
        if has_direct_role || has_group_role {
            usernames.insert(username.clone());
        }
    }
    let mut out: Vec<String> = usernames.into_iter().collect();
    out.sort();
    out
}

pub(crate) fn group_member_usernames(state: &DynSecState, groupname: &str) -> Vec<String> {
    let mut usernames = HashSet::new();
    if let Some(group) = state.groups.get(groupname) {
        for client_ref in &group.clients {
            usernames.insert(client_ref.name.clone());
        }
    }
    for (username, client) in &state.clients {
        if client
            .groups
            .iter()
            .any(|group_ref| group_ref.name == groupname)
        {
            usernames.insert(username.clone());
        }
    }
    let mut out: Vec<String> = usernames.into_iter().collect();
    out.sort();
    out
}

#[derive(Debug, Clone)]
pub(crate) struct DynSecClient {
    pub client_id: Option<String>,
    pub roles: Vec<NamePriority>,
    pub groups: Vec<NamePriority>,
    pub disabled: bool,
    pub synthetic: bool,
}

impl DynSecClient {
    pub(crate) fn from_config(cfg: ClientConfig) -> Self {
        let roles = NamePriority::from_role_refs(cfg.roles);
        let groups = NamePriority::from_group_refs(cfg.groups);
        Self {
            client_id: cfg.client_id,
            roles,
            groups,
            disabled: cfg.disabled.unwrap_or(false),
            synthetic: false,
        }
    }

    pub(crate) fn placeholder(_username: &str) -> Self {
        Self {
            client_id: None,
            roles: Vec::new(),
            groups: Vec::new(),
            disabled: false,
            synthetic: true,
        }
    }

    pub(crate) fn add_group(&mut self, group_name: &str, priority: i32) -> bool {
        upsert_name_priority(&mut self.groups, group_name, priority)
    }

    pub(crate) fn remove_group(&mut self, group_name: &str) -> bool {
        remove_name_priority(&mut self.groups, group_name)
    }

    pub(crate) fn remove_role(&mut self, rolename: &str) -> bool {
        remove_name_priority(&mut self.roles, rolename)
    }

    pub(crate) fn is_prunable_placeholder(&self) -> bool {
        self.synthetic
            && self.client_id.is_none()
            && self.roles.is_empty()
            && self.groups.is_empty()
            && !self.disabled
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DynSecGroup {
    pub roles: Vec<NamePriority>,
    pub clients: Vec<NamePriority>,
}

impl DynSecGroup {
    pub(crate) fn from_config(cfg: GroupConfig) -> Self {
        Self {
            roles: NamePriority::from_role_refs(cfg.roles),
            clients: NamePriority::from_client_refs(cfg.clients),
        }
    }

    pub(crate) fn from_control_roles(roles: Option<Vec<RoleRef>>) -> Self {
        Self {
            roles: NamePriority::from_role_refs(roles),
            clients: Vec::new(),
        }
    }

    pub fn add_client(&mut self, username: &str, priority: i32) -> bool {
        upsert_name_priority(&mut self.clients, username, priority)
    }

    pub fn remove_client(&mut self, username: &str) -> bool {
        remove_name_priority(&mut self.clients, username)
    }

    pub fn remove_role(&mut self, rolename: &str) -> bool {
        remove_name_priority(&mut self.roles, rolename)
    }

    pub fn merge_control_roles(&mut self, roles: &[RoleRef]) -> bool {
        let mut changed = false;
        for role in roles {
            changed |=
                upsert_name_priority(&mut self.roles, &role.rolename, role.priority.unwrap_or(-1));
        }
        changed
    }

    pub fn to_control_roles(&self) -> Vec<RoleRef> {
        self.roles
            .iter()
            .map(|role| RoleRef {
                rolename: role.name.clone(),
                priority: Some(role.priority),
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct DynSecRole {
    pub acls: DynSecAcls,
}

impl DynSecRole {
    pub fn from_config(cfg: RoleConfig) -> Self {
        let mut acls = DynSecAcls::default();
        if let Some(list) = cfg.acls {
            for acl in list {
                acls.add_acl(acl);
            }
        }
        acls.sort();
        Self { acls }
    }

    pub fn from_control_acls(acls: Option<Vec<AclConfig>>) -> Self {
        let mut dynsec_acls = DynSecAcls::default();
        if let Some(list) = acls {
            for acl in list {
                dynsec_acls.add_acl(acl);
            }
        }
        dynsec_acls.sort();
        Self { acls: dynsec_acls }
    }

    pub fn match_acl(&self, access: AccessKind, topic: &str) -> Option<bool> {
        match access {
            AccessKind::PublishSend => match_acl_publish(&self.acls.publish_c_send, topic),
            AccessKind::PublishReceive => match_acl_publish(&self.acls.publish_c_recv, topic),
            AccessKind::Subscribe => match_acl_literal(&self.acls.subscribe_literal, topic)
                .or_else(|| match_acl_sub(&self.acls.subscribe_pattern, topic)),
            AccessKind::Unsubscribe => match_acl_literal(&self.acls.unsubscribe_literal, topic)
                .or_else(|| match_acl_sub(&self.acls.unsubscribe_pattern, topic)),
            AccessKind::Unknown => None,
        }
    }

    pub fn merge_control_acls(&mut self, acls: &[AclConfig]) -> bool {
        let mut changed = false;
        for acl in acls {
            changed |= self
                .acls
                .upsert_acl_entry(AclEntry::from_config(acl.clone()));
        }
        changed
    }

    pub fn to_control_acls(&self) -> Vec<AclConfig> {
        self.acls.to_control_configs()
    }
}

#[derive(Debug, Clone, Default)]
pub struct DynSecAcls {
    pub publish_c_send: Vec<AclEntry>,
    pub publish_c_recv: Vec<AclEntry>,
    pub subscribe_literal: HashMap<String, AclEntry>,
    pub subscribe_pattern: Vec<AclEntry>,
    pub unsubscribe_literal: HashMap<String, AclEntry>,
    pub unsubscribe_pattern: Vec<AclEntry>,
}

impl DynSecAcls {
    pub fn add_acl(&mut self, cfg: AclConfig) {
        let acl = AclEntry::from_config(cfg);
        match acl.acl_type {
            AclType::PublishClientSend => self.publish_c_send.push(acl),
            AclType::PublishClientReceive => self.publish_c_recv.push(acl),
            AclType::SubscribeLiteral => insert_literal_acl(&mut self.subscribe_literal, acl),
            AclType::SubscribePattern => self.subscribe_pattern.push(acl),
            AclType::UnsubscribeLiteral => insert_literal_acl(&mut self.unsubscribe_literal, acl),
            AclType::UnsubscribePattern => self.unsubscribe_pattern.push(acl),
            AclType::SubscribeGeneric => {}
            AclType::UnsubscribeGeneric => {}
        }
    }

    pub fn sort(&mut self) {
        sort_acl_list(&mut self.publish_c_send);
        sort_acl_list(&mut self.publish_c_recv);
        sort_acl_list(&mut self.subscribe_pattern);
        sort_acl_list(&mut self.unsubscribe_pattern);
    }

    pub fn remove_acl_entry(&mut self, acl_type: AclType, topic: &str) -> Option<AclEntry> {
        match acl_type {
            AclType::PublishClientSend => remove_acl_from_vec(&mut self.publish_c_send, topic),
            AclType::PublishClientReceive => remove_acl_from_vec(&mut self.publish_c_recv, topic),
            AclType::SubscribeLiteral => self.subscribe_literal.remove(topic),
            AclType::SubscribePattern => remove_acl_from_vec(&mut self.subscribe_pattern, topic),
            AclType::UnsubscribeLiteral => self.unsubscribe_literal.remove(topic),
            AclType::UnsubscribePattern => {
                remove_acl_from_vec(&mut self.unsubscribe_pattern, topic)
            }
            AclType::SubscribeGeneric | AclType::UnsubscribeGeneric => None,
        }
    }

    pub fn upsert_acl_entry(&mut self, acl: AclEntry) -> bool {
        match acl.acl_type {
            AclType::PublishClientSend => upsert_acl_in_vec(&mut self.publish_c_send, acl),
            AclType::PublishClientReceive => upsert_acl_in_vec(&mut self.publish_c_recv, acl),
            AclType::SubscribeLiteral => {
                upsert_acl_in_literal_map(&mut self.subscribe_literal, acl)
            }
            AclType::SubscribePattern => upsert_acl_in_vec(&mut self.subscribe_pattern, acl),
            AclType::UnsubscribeLiteral => {
                upsert_acl_in_literal_map(&mut self.unsubscribe_literal, acl)
            }
            AclType::UnsubscribePattern => upsert_acl_in_vec(&mut self.unsubscribe_pattern, acl),
            AclType::SubscribeGeneric | AclType::UnsubscribeGeneric => false,
        }
    }

    pub fn to_control_configs(&self) -> Vec<AclConfig> {
        let mut out = Vec::new();
        out.extend(self.publish_c_send.iter().map(AclEntry::to_control_config));
        out.extend(self.publish_c_recv.iter().map(AclEntry::to_control_config));

        let mut subscribe_literal: Vec<_> = self.subscribe_literal.values().collect();
        subscribe_literal.sort_by(|left, right| left.topic.cmp(&right.topic));
        out.extend(
            subscribe_literal
                .into_iter()
                .map(AclEntry::to_control_config),
        );

        out.extend(
            self.subscribe_pattern
                .iter()
                .map(AclEntry::to_control_config),
        );

        let mut unsubscribe_literal: Vec<_> = self.unsubscribe_literal.values().collect();
        unsubscribe_literal.sort_by(|left, right| left.topic.cmp(&right.topic));
        out.extend(
            unsubscribe_literal
                .into_iter()
                .map(AclEntry::to_control_config),
        );

        out.extend(
            self.unsubscribe_pattern
                .iter()
                .map(AclEntry::to_control_config),
        );
        out
    }
}

#[derive(Debug, Clone)]
pub struct AclEntry {
    pub acl_type: AclType,
    pub topic: String,
    pub allow: bool,
    pub priority: i32,
}

impl AclEntry {
    pub fn from_config(cfg: AclConfig) -> Self {
        let acl_type = AclType::from_str(&cfg.acltype);
        Self {
            acl_type,
            topic: cfg.topic,
            allow: cfg.allow.unwrap_or(false),
            priority: cfg.priority.unwrap_or(0),
        }
    }

    pub fn to_control_config(&self) -> AclConfig {
        AclConfig {
            acltype: self.acl_type.as_str().to_string(),
            topic: self.topic.clone(),
            priority: Some(self.priority),
            allow: Some(self.allow),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AclType {
    PublishClientSend,
    PublishClientReceive,
    SubscribeLiteral,
    SubscribePattern,
    UnsubscribeLiteral,
    UnsubscribePattern,
    SubscribeGeneric,
    UnsubscribeGeneric,
}

impl AclType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PublishClientSend => "publishClientSend",
            Self::PublishClientReceive => "publishClientReceive",
            Self::SubscribeLiteral => "subscribeLiteral",
            Self::SubscribePattern => "subscribePattern",
            Self::UnsubscribeLiteral => "unsubscribeLiteral",
            Self::UnsubscribePattern => "unsubscribePattern",
            Self::SubscribeGeneric => "subscribe",
            Self::UnsubscribeGeneric => "unsubscribe",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value {
            "publishClientSend" => Self::PublishClientSend,
            "publishClientReceive" => Self::PublishClientReceive,
            "subscribeLiteral" => Self::SubscribeLiteral,
            "subscribePattern" => Self::SubscribePattern,
            "unsubscribeLiteral" => Self::UnsubscribeLiteral,
            "unsubscribePattern" => Self::UnsubscribePattern,
            "subscribe" => Self::SubscribeGeneric,
            "unsubscribe" => Self::UnsubscribeGeneric,
            _ => {
                eprintln!("dynsec: unknown acltype '{value}', defaulting to subscribe");
                Self::SubscribeGeneric
            }
        }
    }

    pub fn from_control_str(value: &str) -> Option<Self> {
        match value {
            "publishClientSend" => Some(Self::PublishClientSend),
            "publishClientReceive" => Some(Self::PublishClientReceive),
            "subscribeLiteral" => Some(Self::SubscribeLiteral),
            "subscribePattern" => Some(Self::SubscribePattern),
            "unsubscribeLiteral" => Some(Self::UnsubscribeLiteral),
            "unsubscribePattern" => Some(Self::UnsubscribePattern),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DefaultAclAccess {
    pub publish_client_send: bool,
    pub publish_client_receive: bool,
    pub subscribe: bool,
    pub unsubscribe: bool,
}

impl DefaultAclAccess {
    pub fn from_config(cfg: Option<DefaultAclAccessConfig>) -> Self {
        if let Some(cfg) = cfg {
            Self {
                publish_client_send: cfg.publish_client_send.unwrap_or(false),
                publish_client_receive: cfg.publish_client_receive.unwrap_or(false),
                subscribe: cfg.subscribe.unwrap_or(false),
                unsubscribe: cfg.unsubscribe.unwrap_or(false),
            }
        } else {
            eprintln!("dynsec: missing defaultACLAccess; defaulting to all deny");
            Self {
                publish_client_send: false,
                publish_client_receive: false,
                subscribe: false,
                unsubscribe: false,
            }
        }
    }

    pub const fn allow_for(&self, access: AccessKind) -> bool {
        match access {
            AccessKind::PublishSend => self.publish_client_send,
            AccessKind::PublishReceive => self.publish_client_receive,
            AccessKind::Subscribe => self.subscribe,
            AccessKind::Unsubscribe => self.unsubscribe,
            AccessKind::Unknown => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NamePriority {
    pub name: String,
    pub priority: i32,
}

impl NamePriority {
    pub fn new(name: &str, priority: i32) -> Self {
        Self {
            name: name.to_string(),
            priority,
        }
    }

    pub fn from_role_refs(list: Option<Vec<RoleRef>>) -> Vec<Self> {
        list.unwrap_or_default()
            .into_iter()
            .map(|entry| Self::new(&entry.rolename, entry.priority.unwrap_or(-1)))
            .collect()
    }

    pub fn from_group_refs(list: Option<Vec<GroupRef>>) -> Vec<Self> {
        list.unwrap_or_default()
            .into_iter()
            .map(|entry| Self::new(&entry.groupname, entry.priority.unwrap_or(-1)))
            .collect()
    }

    pub fn from_client_refs(list: Option<Vec<ClientRef>>) -> Vec<Self> {
        list.unwrap_or_default()
            .into_iter()
            .map(|entry| Self::new(&entry.username, entry.priority.unwrap_or(-1)))
            .collect()
    }
}

pub fn upsert_name_priority(list: &mut Vec<NamePriority>, name: &str, priority: i32) -> bool {
    if let Some(existing) = list.iter_mut().find(|entry| entry.name == name) {
        if priority != existing.priority {
            existing.priority = priority;
            return true;
        }
        return false;
    }
    list.push(NamePriority::new(name, priority));
    true
}

pub fn merge_name_priority_by_max(list: &mut Vec<NamePriority>, name: &str, priority: i32) -> bool {
    if let Some(existing) = list.iter_mut().find(|entry| entry.name == name) {
        if priority > existing.priority {
            existing.priority = priority;
            return true;
        }
        return false;
    }
    list.push(NamePriority::new(name, priority));
    true
}

pub fn remove_name_priority(list: &mut Vec<NamePriority>, name: &str) -> bool {
    let Some(idx) = list.iter().position(|entry| entry.name == name) else {
        return false;
    };
    list.remove(idx);
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct DynSecConfig {
    pub clients: Option<Vec<ClientConfig>>,
    pub groups: Option<Vec<GroupConfig>>,
    pub roles: Option<Vec<RoleConfig>>,
    #[serde(rename = "defaultACLAccess")]
    pub default_acl_access: Option<DefaultAclAccessConfig>,
    #[serde(rename = "anonymousGroup")]
    pub anonymous_group: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    pub username: String,
    #[serde(rename = "clientid")]
    pub client_id: Option<String>,
    pub roles: Option<Vec<RoleRef>>,
    pub groups: Option<Vec<GroupRef>>,
    pub disabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GroupConfig {
    pub groupname: String,
    pub roles: Option<Vec<RoleRef>>,
    pub clients: Option<Vec<ClientRef>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RoleConfig {
    pub rolename: String,
    pub acls: Option<Vec<AclConfig>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RoleRef {
    pub rolename: String,
    pub priority: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GroupRef {
    pub groupname: String,
    pub priority: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientRef {
    pub username: String,
    pub priority: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AclConfig {
    #[serde(rename = "acltype")]
    pub acltype: String,
    pub topic: String,
    pub priority: Option<i32>,
    pub allow: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DefaultAclAccessConfig {
    #[serde(rename = "publishClientSend")]
    pub publish_client_send: Option<bool>,
    #[serde(rename = "publishClientReceive")]
    pub publish_client_receive: Option<bool>,
    pub subscribe: Option<bool>,
    pub unsubscribe: Option<bool>,
}

pub fn match_acl_publish(acls: &[AclEntry], topic: &str) -> Option<bool> {
    for acl in acls {
        if topic_match_sub(&acl.topic, topic) {
            return Some(acl.allow);
        }
    }
    None
}

pub fn match_acl_literal(acls: &HashMap<String, AclEntry>, topic: &str) -> Option<bool> {
    acls.get(topic).map(|acl| acl.allow)
}

pub fn match_acl_sub(acls: &[AclEntry], topic: &str) -> Option<bool> {
    for acl in acls {
        if sub_match_sub(&acl.topic, topic) {
            return Some(acl.allow);
        }
    }
    None
}

pub fn insert_literal_acl(map: &mut HashMap<String, AclEntry>, acl: AclEntry) {
    let entry = map.entry(acl.topic.clone()).or_insert(acl.clone());
    if acl.priority > entry.priority {
        *entry = acl;
    }
}

pub fn upsert_acl_in_literal_map(map: &mut HashMap<String, AclEntry>, acl: AclEntry) -> bool {
    if let Some(existing) = map.get_mut(&acl.topic) {
        if existing.allow == acl.allow && existing.priority == acl.priority {
            return false;
        }
        *existing = acl;
        true
    } else {
        map.insert(acl.topic.clone(), acl);
        true
    }
}

pub fn upsert_acl_in_vec(list: &mut Vec<AclEntry>, acl: AclEntry) -> bool {
    if let Some(existing) = list.iter_mut().find(|entry| entry.topic == acl.topic) {
        if existing.allow == acl.allow && existing.priority == acl.priority {
            return false;
        }
        *existing = acl;
    } else {
        list.push(acl);
    }
    sort_acl_list(list);
    true
}

pub fn remove_acl_from_vec(list: &mut Vec<AclEntry>, topic: &str) -> Option<AclEntry> {
    let idx = list.iter().position(|entry| entry.topic == topic)?;
    Some(list.remove(idx))
}

pub fn sort_acl_list(list: &mut [AclEntry]) {
    list.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| a.topic.cmp(&b.topic))
    });
}

pub fn topic_match_sub(filter: &str, topic: &str) -> bool {
    sub_match_sub(filter, topic)
}

pub fn sub_match_sub(filter: &str, topic: &str) -> bool {
    if filter == "#" {
        return true;
    }

    let filter_parts: Vec<&str> = filter.split('/').collect();
    let topic_parts: Vec<&str> = topic.split('/').collect();
    let mut i = 0;

    while i < filter_parts.len() {
        let fp = filter_parts[i];
        if fp == "#" {
            return true;
        }
        if i >= topic_parts.len() {
            return false;
        }
        if fp != "+" && fp != topic_parts[i] {
            return false;
        }
        i += 1;
    }

    i == topic_parts.len()
}
