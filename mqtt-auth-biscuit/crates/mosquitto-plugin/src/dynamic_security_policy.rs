use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct DynamicSecurityPolicy {
    config_path: String,
    reload_interval: Duration,
    last_loaded: Mutex<Option<Instant>>,
    state: RwLock<DynSecState>,
}

impl DynamicSecurityPolicy {
    pub fn new(config_path: impl Into<String>, reload_interval: Duration) -> Result<Self, String> {
        let policy = Self {
            config_path: config_path.into(),
            reload_interval,
            last_loaded: Mutex::new(None),
            state: RwLock::new(DynSecState::default()),
        };
        policy.reload_if_needed(true)?;
        Ok(policy)
    }

    pub fn check(
        &self,
        username: Option<&str>,
        client_id: Option<&str>,
        topic: &str,
        access: i32,
    ) -> Result<bool, String> {
        self.reload_if_needed(false)?;
        let state = self
            .state
            .read()
            .map_err(|_| "dynsec state lock poisoned".to_string())?;

        let access_kind = AccessKind::from_access(access);
        let default_allow = state.default_access.allow_for(access_kind);

        let client = username.and_then(|name| state.clients.get(name));
        if let Some(client) = client {
            if client.disabled {
                return Ok(false);
            }
            if let (Some(expected), Some(actual)) = (client.client_id.as_deref(), client_id)
                && expected != actual {
                    return Ok(false);
                }
        }

        let mut roles = Vec::new();
        if let Some(client) = client {
            roles.extend(client.roles.iter().cloned());
            for group_ref in &client.groups {
                if let Some(group) = state.groups.get(&group_ref.name) {
                    roles.extend(group.roles.iter().cloned());
                }
            }
        } else if let Some(group_name) = state.anonymous_group.as_deref()
            && let Some(group) = state.groups.get(group_name) {
                roles.extend(group.roles.iter().cloned());
            }

        roles.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| a.name.cmp(&b.name))
        });

        for role_ref in roles {
            if let Some(role) = state.roles.get(&role_ref.name)
                && let Some(allow) = role.match_acl(access_kind, topic) {
                    return Ok(allow);
                }
        }

        Ok(default_allow)
    }

    fn reload_if_needed(&self, force: bool) -> Result<(), String> {
        let now = Instant::now();
        let mut last_loaded = self
            .last_loaded
            .lock()
            .map_err(|_| "dynsec reload lock poisoned".to_string())?;

        if !force
            && let Some(last) = *last_loaded
                && now.duration_since(last) < self.reload_interval {
                    return Ok(());
                }

        let raw = fs::read_to_string(&self.config_path)
            .map_err(|e| format!("dynsec config read failed: {e}"))?;
        let cfg: DynSecConfig =
            serde_json::from_str(&raw).map_err(|e| format!("dynsec config parse failed: {e}"))?;
        let state = DynSecState::from_config(cfg);

        let mut guard = self
            .state
            .write()
            .map_err(|_| "dynsec state lock poisoned".to_string())?;
        *guard = state;

        *last_loaded = Some(now);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessKind {
    PublishSend,
    PublishReceive,
    Subscribe,
    Unsubscribe,
    Unknown,
}

impl AccessKind {
    fn from_access(access: i32) -> Self {
        if (access & ACL_WRITE) != 0 {
            AccessKind::PublishSend
        } else if (access & ACL_SUBSCRIBE) != 0 {
            AccessKind::Subscribe
        } else if (access & ACL_UNSUBSCRIBE) != 0 {
            AccessKind::Unsubscribe
        } else if (access & ACL_READ) != 0 {
            AccessKind::PublishReceive
        } else {
            AccessKind::Unknown
        }
    }
}

const ACL_READ: i32 = 0x01;
const ACL_WRITE: i32 = 0x02;
const ACL_SUBSCRIBE: i32 = 0x04;
const ACL_UNSUBSCRIBE: i32 = 0x08;

#[derive(Debug, Clone, Default)]
struct DynSecState {
    clients: HashMap<String, DynSecClient>,
    groups: HashMap<String, DynSecGroup>,
    roles: HashMap<String, DynSecRole>,
    default_access: DefaultAclAccess,
    anonymous_group: Option<String>,
}

impl DynSecState {
    fn from_config(cfg: DynSecConfig) -> Self {
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

        for (group_name, group) in groups.iter() {
            for client_ref in &group.clients {
                let entry = clients
                    .entry(client_ref.name.clone())
                    .or_insert_with(|| DynSecClient::placeholder(&client_ref.name));
                entry.add_group(group_name, client_ref.priority);
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

#[derive(Debug, Clone)]
struct DynSecClient {
    username: String,
    client_id: Option<String>,
    roles: Vec<NamePriority>,
    groups: Vec<NamePriority>,
    disabled: bool,
}

impl DynSecClient {
    fn from_config(cfg: ClientConfig) -> Self {
        let roles = NamePriority::from_role_refs(cfg.roles);
        let groups = NamePriority::from_group_refs(cfg.groups);
        Self {
            username: cfg.username,
            client_id: cfg.client_id,
            roles,
            groups,
            disabled: cfg.disabled.unwrap_or(false),
        }
    }

    fn placeholder(username: &str) -> Self {
        Self {
            username: username.to_string(),
            client_id: None,
            roles: Vec::new(),
            groups: Vec::new(),
            disabled: false,
        }
    }

    fn add_group(&mut self, group_name: &str, priority: i32) {
        if let Some(existing) = self
            .groups
            .iter_mut()
            .find(|entry| entry.name == group_name)
        {
            if priority > existing.priority {
                existing.priority = priority;
            }
            return;
        }
        self.groups.push(NamePriority::new(group_name, priority));
    }
}

#[derive(Debug, Clone)]
struct DynSecGroup {
    groupname: String,
    roles: Vec<NamePriority>,
    clients: Vec<NamePriority>,
}

impl DynSecGroup {
    fn from_config(cfg: GroupConfig) -> Self {
        Self {
            groupname: cfg.groupname,
            roles: NamePriority::from_role_refs(cfg.roles),
            clients: NamePriority::from_client_refs(cfg.clients),
        }
    }
}

#[derive(Debug, Clone)]
struct DynSecRole {
    rolename: String,
    acls: DynSecAcls,
}

impl DynSecRole {
    fn from_config(cfg: RoleConfig) -> Self {
        let mut acls = DynSecAcls::default();
        if let Some(list) = cfg.acls {
            for acl in list {
                acls.add_acl(acl);
            }
        }
        acls.sort();
        Self {
            rolename: cfg.rolename,
            acls,
        }
    }

    fn match_acl(&self, access: AccessKind, topic: &str) -> Option<bool> {
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
}

#[derive(Debug, Clone, Default)]
struct DynSecAcls {
    publish_c_send: Vec<AclEntry>,
    publish_c_recv: Vec<AclEntry>,
    subscribe_literal: HashMap<String, AclEntry>,
    subscribe_pattern: Vec<AclEntry>,
    unsubscribe_literal: HashMap<String, AclEntry>,
    unsubscribe_pattern: Vec<AclEntry>,
}

impl DynSecAcls {
    fn add_acl(&mut self, cfg: AclConfig) {
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

    fn sort(&mut self) {
        sort_acl_list(&mut self.publish_c_send);
        sort_acl_list(&mut self.publish_c_recv);
        sort_acl_list(&mut self.subscribe_pattern);
        sort_acl_list(&mut self.unsubscribe_pattern);
    }
}

#[derive(Debug, Clone)]
struct AclEntry {
    acl_type: AclType,
    topic: String,
    allow: bool,
    priority: i32,
}

impl AclEntry {
    fn from_config(cfg: AclConfig) -> Self {
        let acl_type = AclType::from_str(&cfg.acltype);
        Self {
            acl_type,
            topic: cfg.topic,
            allow: cfg.allow.unwrap_or(false),
            priority: cfg.priority.unwrap_or(0),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AclType {
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
    fn from_str(value: &str) -> Self {
        match value {
            "publishClientSend" => AclType::PublishClientSend,
            "publishClientReceive" => AclType::PublishClientReceive,
            "subscribeLiteral" => AclType::SubscribeLiteral,
            "subscribePattern" => AclType::SubscribePattern,
            "unsubscribeLiteral" => AclType::UnsubscribeLiteral,
            "unsubscribePattern" => AclType::UnsubscribePattern,
            "subscribe" => AclType::SubscribeGeneric,
            "unsubscribe" => AclType::UnsubscribeGeneric,
            _ => {
                eprintln!("dynsec: unknown acltype '{value}', defaulting to subscribe");
                AclType::SubscribeGeneric
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
struct DefaultAclAccess {
    publish_client_send: bool,
    publish_client_receive: bool,
    subscribe: bool,
    unsubscribe: bool,
}

impl DefaultAclAccess {
    fn from_config(cfg: Option<DefaultAclAccessConfig>) -> Self {
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

    fn allow_for(&self, access: AccessKind) -> bool {
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
struct NamePriority {
    name: String,
    priority: i32,
}

impl NamePriority {
    fn new(name: &str, priority: i32) -> Self {
        Self {
            name: name.to_string(),
            priority,
        }
    }

    fn from_role_refs(list: Option<Vec<RoleRef>>) -> Vec<Self> {
        list.unwrap_or_default()
            .into_iter()
            .map(|entry| Self::new(&entry.rolename, entry.priority.unwrap_or(-1)))
            .collect()
    }

    fn from_group_refs(list: Option<Vec<GroupRef>>) -> Vec<Self> {
        list.unwrap_or_default()
            .into_iter()
            .map(|entry| Self::new(&entry.groupname, entry.priority.unwrap_or(-1)))
            .collect()
    }

    fn from_client_refs(list: Option<Vec<ClientRef>>) -> Vec<Self> {
        list.unwrap_or_default()
            .into_iter()
            .map(|entry| Self::new(&entry.username, entry.priority.unwrap_or(-1)))
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize)]
struct DynSecConfig {
    clients: Option<Vec<ClientConfig>>,
    groups: Option<Vec<GroupConfig>>,
    roles: Option<Vec<RoleConfig>>,
    #[serde(rename = "defaultACLAccess")]
    default_acl_access: Option<DefaultAclAccessConfig>,
    #[serde(rename = "anonymousGroup")]
    anonymous_group: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ClientConfig {
    username: String,
    #[serde(rename = "clientid")]
    client_id: Option<String>,
    roles: Option<Vec<RoleRef>>,
    groups: Option<Vec<GroupRef>>,
    disabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
struct GroupConfig {
    groupname: String,
    roles: Option<Vec<RoleRef>>,
    clients: Option<Vec<ClientRef>>,
}

#[derive(Debug, Clone, Deserialize)]
struct RoleConfig {
    rolename: String,
    acls: Option<Vec<AclConfig>>,
}

#[derive(Debug, Clone, Deserialize)]
struct RoleRef {
    rolename: String,
    priority: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
struct GroupRef {
    groupname: String,
    priority: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
struct ClientRef {
    username: String,
    priority: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
struct AclConfig {
    #[serde(rename = "acltype")]
    acltype: String,
    topic: String,
    priority: Option<i32>,
    allow: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
struct DefaultAclAccessConfig {
    #[serde(rename = "publishClientSend")]
    publish_client_send: Option<bool>,
    #[serde(rename = "publishClientReceive")]
    publish_client_receive: Option<bool>,
    subscribe: Option<bool>,
    unsubscribe: Option<bool>,
}

fn match_acl_publish(acls: &[AclEntry], topic: &str) -> Option<bool> {
    for acl in acls {
        if topic_match_sub(&acl.topic, topic) {
            return Some(acl.allow);
        }
    }
    None
}

fn match_acl_literal(acls: &HashMap<String, AclEntry>, topic: &str) -> Option<bool> {
    acls.get(topic).map(|acl| acl.allow)
}

fn match_acl_sub(acls: &[AclEntry], topic: &str) -> Option<bool> {
    for acl in acls {
        if sub_match_sub(&acl.topic, topic) {
            return Some(acl.allow);
        }
    }
    None
}

fn insert_literal_acl(map: &mut HashMap<String, AclEntry>, acl: AclEntry) {
    let entry = map.entry(acl.topic.clone()).or_insert(acl.clone());
    if acl.priority > entry.priority {
        *entry = acl;
    }
}

fn sort_acl_list(list: &mut [AclEntry]) {
    list.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| a.topic.cmp(&b.topic))
    });
}

fn topic_match_sub(filter: &str, topic: &str) -> bool {
    sub_match_sub(filter, topic)
}

fn sub_match_sub(filter: &str, topic: &str) -> bool {
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
