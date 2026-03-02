use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct DynamicSecurityPolicy {
    config_path: String,
    reload_interval: Duration,
    last_loaded: Mutex<Option<Instant>>,
    state: RwLock<DynSecState>,
    runtime_disabled_usernames: Mutex<HashSet<String>>,
}

impl DynamicSecurityPolicy {
    pub fn new(config_path: impl Into<String>, reload_interval: Duration) -> Result<Self, String> {
        let policy = Self {
            config_path: config_path.into(),
            reload_interval,
            last_loaded: Mutex::new(None),
            state: RwLock::new(DynSecState::default()),
            runtime_disabled_usernames: Mutex::new(HashSet::new()),
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
        if let Some(name) = username
            && self
                .runtime_disabled_usernames
                .lock()
                .map_err(|_| "dynsec runtime disable lock poisoned".to_string())?
                .contains(name)
        {
            return Ok(false);
        }
        if let Some(client) = client {
            if client.disabled {
                return Ok(false);
            }
            if let (Some(expected), Some(actual)) = (client.client_id.as_deref(), client_id)
                && expected != actual
            {
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
            && let Some(group) = state.groups.get(group_name)
        {
            roles.extend(group.roles.iter().cloned());
        }

        roles.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| a.name.cmp(&b.name))
        });

        for role_ref in roles {
            if let Some(role) = state.roles.get(&role_ref.name)
                && let Some(allow) = role.match_acl(access_kind, topic)
            {
                return Ok(allow);
            }
        }

        Ok(default_allow)
    }

    pub fn apply_control_payload(
        &self,
        payload: &[u8],
    ) -> Result<ControlEnforcementTargets, String> {
        if payload.is_empty() {
            return Ok(ControlEnforcementTargets::default());
        }

        let parsed: ControlPayload =
            serde_json::from_slice(payload).map_err(|e| format!("invalid control payload: {e}"))?;
        if parsed.commands.is_empty() {
            return Ok(ControlEnforcementTargets::default());
        }

        self.reload_if_needed(false)?;

        let mut kick_client_ids = HashSet::new();
        let mut disable_usernames = HashSet::new();
        let mut enable_usernames = HashSet::new();
        let mut requested_enable_usernames = HashSet::new();
        {
            let mut state = self
                .state
                .write()
                .map_err(|_| "dynsec state lock poisoned".to_string())?;
            for cmd in parsed.commands {
                let command = cmd.command.as_str();
                if command != "disableClient" && command != "enableClient" {
                    continue;
                }
                let Some(username) = cmd
                    .username
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                else {
                    continue;
                };

                if let Some(client) = state.clients.get_mut(username) {
                    if command == "disableClient" {
                        if client.disabled {
                            continue;
                        }
                        client.disabled = true;
                        disable_usernames.insert(username.to_string());
                        enable_usernames.remove(username);
                        if let Some(client_id) = client.client_id.as_ref() {
                            kick_client_ids.insert(client_id.clone());
                        }
                    } else {
                        requested_enable_usernames.insert(username.to_string());
                        if client.disabled {
                            enable_usernames.insert(username.to_string());
                            disable_usernames.remove(username);
                            if let Some(client_id) = client.client_id.as_ref() {
                                kick_client_ids.remove(client_id);
                            }
                        }
                        client.disabled = false;
                    }
                } else if command == "enableClient" {
                    requested_enable_usernames.insert(username.to_string());
                }
            }
        }

        {
            let mut runtime_disabled = self
                .runtime_disabled_usernames
                .lock()
                .map_err(|_| "dynsec runtime disable lock poisoned".to_string())?;
            for username in &disable_usernames {
                runtime_disabled.insert(username.clone());
            }
            for username in &requested_enable_usernames {
                runtime_disabled.remove(username);
            }
        }

        for username in &disable_usernames {
            if let Err(err) = self.persist_client_disabled(username, true) {
                eprintln!("dynsec: failed to persist disableClient for '{username}': {err}");
            }
        }
        for username in &requested_enable_usernames {
            if let Err(err) = self.persist_client_disabled(username, false) {
                eprintln!("dynsec: failed to persist enableClient for '{username}': {err}");
            }
        }

        let mut affected_client_ids: Vec<String> = kick_client_ids.into_iter().collect();
        let mut changed_usernames: Vec<String> = disable_usernames.into_iter().collect();
        affected_client_ids.sort();
        changed_usernames.sort();

        Ok(ControlEnforcementTargets {
            client_ids: affected_client_ids,
            usernames: changed_usernames,
        })
    }

    fn reload_if_needed(&self, force: bool) -> Result<(), String> {
        let now = Instant::now();
        let mut last_loaded = self
            .last_loaded
            .lock()
            .map_err(|_| "dynsec reload lock poisoned".to_string())?;

        if !force
            && let Some(last) = *last_loaded
            && now.duration_since(last) < self.reload_interval
        {
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

    fn persist_client_disabled(&self, username: &str, disabled: bool) -> Result<(), String> {
        let raw = fs::read_to_string(&self.config_path)
            .map_err(|e| format!("dynsec config read failed: {e}"))?;
        let mut root: Value =
            serde_json::from_str(&raw).map_err(|e| format!("dynsec config parse failed: {e}"))?;

        let mut changed = false;
        if let Some(clients) = root.get_mut("clients").and_then(Value::as_array_mut) {
            for client in clients {
                let Some(current_username) = client.get("username").and_then(Value::as_str) else {
                    continue;
                };
                if current_username == username {
                    client["disabled"] = Value::Bool(disabled);
                    changed = true;
                }
            }
        }

        if !changed {
            return Ok(());
        }

        let serialized = serde_json::to_string_pretty(&root)
            .map_err(|e| format!("dynsec config serialize failed: {e}"))?;
        fs::write(&self.config_path, format!("{serialized}\n"))
            .map_err(|e| format!("dynsec config write failed: {e}"))?;
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct ControlPayload {
    #[serde(default)]
    commands: Vec<ControlCommand>,
}

#[derive(Debug, Deserialize)]
struct ControlCommand {
    command: String,
    #[serde(default)]
    username: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ControlEnforcementTargets {
    pub client_ids: Vec<String>,
    pub usernames: Vec<String>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static DYNSEC_TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn write_test_dynsec_config() -> String {
        let unique = DYNSEC_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("dynsec-control-{unique}.json"));
        let config = r#"{
  "clients": [
    {
      "username": "test_user",
      "clientid": "test_client",
      "roles": [{"rolename": "ctrl", "priority": 0}],
      "disabled": false
    }
  ],
  "groups": [],
  "roles": [
    {
      "rolename": "ctrl",
      "acls": [
        {
          "acltype": "publishClientSend",
          "topic": "$CONTROL/dynamic-security/v1",
          "priority": 0,
          "allow": true
        }
      ]
    }
  ],
  "defaultACLAccess": {
    "publishClientSend": false,
    "publishClientReceive": false,
    "subscribe": false,
    "unsubscribe": false
  }
}"#;
        fs::write(&path, config).expect("test dynsec config must be writable");
        path.to_string_lossy().into_owned()
    }

    fn set_client_disabled(path: &str, username: &str, disabled: bool) {
        let raw = fs::read_to_string(path).expect("test dynsec config should be readable");
        let mut root: Value = serde_json::from_str(&raw).expect("test dynsec config should parse");
        if let Some(clients) = root.get_mut("clients").and_then(Value::as_array_mut) {
            for client in clients {
                let Some(current_username) = client.get("username").and_then(Value::as_str) else {
                    continue;
                };
                if current_username == username {
                    client["disabled"] = Value::Bool(disabled);
                }
            }
        }
        let serialized =
            serde_json::to_string_pretty(&root).expect("test dynsec config should serialize");
        fs::write(path, format!("{serialized}\n")).expect("test dynsec config should be writable");
    }

    fn write_test_dynsec_config_without_client_id() -> String {
        let unique = DYNSEC_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("dynsec-control-no-clientid-{unique}.json"));
        let config = r#"{
  "clients": [
    {
      "username": "test_user",
      "roles": [{"rolename": "ctrl", "priority": 0}],
      "disabled": false
    }
  ],
  "groups": [],
  "roles": [
    {
      "rolename": "ctrl",
      "acls": [
        {
          "acltype": "publishClientSend",
          "topic": "$CONTROL/dynamic-security/v1",
          "priority": 0,
          "allow": true
        }
      ]
    }
  ],
  "defaultACLAccess": {
    "publishClientSend": false,
    "publishClientReceive": false,
    "subscribe": false,
    "unsubscribe": false
  }
}"#;
        fs::write(&path, config).expect("test dynsec config must be writable");
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn apply_control_payload_disable_client_marks_user_disabled_and_returns_client_id() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");

        let payload = br#"{"commands":[{"command":"disableClient","username":"test_user"}]}"#;
        let targets = policy
            .apply_control_payload(payload)
            .expect("control payload should apply");
        assert_eq!(targets.client_ids, vec!["test_client".to_string()]);
        assert_eq!(targets.usernames, vec!["test_user".to_string()]);
        assert_eq!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed"),
            false
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_ignores_non_disable_commands() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");

        let payload = br#"{"commands":[{"command":"listRoles"}]}"#;
        let targets = policy
            .apply_control_payload(payload)
            .expect("control payload should apply");
        assert!(targets.client_ids.is_empty());
        assert!(targets.usernames.is_empty());
        assert_eq!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed"),
            true
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_rejects_invalid_json() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");

        let err = policy
            .apply_control_payload(br#"{"commands":[{"command":"disableClient"}"#)
            .expect_err("invalid payload should fail");
        assert!(err.contains("invalid control payload"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_returns_username_when_client_id_missing() {
        let path = write_test_dynsec_config_without_client_id();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");

        let payload = br#"{"commands":[{"command":"disableClient","username":"test_user"}]}"#;
        let targets = policy
            .apply_control_payload(payload)
            .expect("control payload should apply");
        assert!(targets.client_ids.is_empty());
        assert_eq!(targets.usernames, vec!["test_user".to_string()]);

        // Runtime disable overlay must continue denying even after config reloads.
        assert_eq!(
            policy
                .check(
                    Some("test_user"),
                    Some("another_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed"),
            false
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_enable_client_clears_runtime_disable_overlay() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");

        let disable_payload =
            br#"{"commands":[{"command":"disableClient","username":"test_user"}]}"#;
        let disable_targets = policy
            .apply_control_payload(disable_payload)
            .expect("disable payload should apply");
        assert_eq!(disable_targets.client_ids, vec!["test_client".to_string()]);
        assert_eq!(disable_targets.usernames, vec!["test_user".to_string()]);
        assert_eq!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed"),
            false
        );

        let enable_payload = br#"{"commands":[{"command":"enableClient","username":"test_user"}]}"#;
        let enable_targets = policy
            .apply_control_payload(enable_payload)
            .expect("enable payload should apply");
        assert!(enable_targets.client_ids.is_empty());
        assert!(enable_targets.usernames.is_empty());
        assert_eq!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed"),
            true
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_disable_then_enable_same_payload_has_no_kick_targets() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");

        let payload = br#"{
            "commands":[
                {"command":"disableClient","username":"test_user"},
                {"command":"enableClient","username":"test_user"}
            ]
        }"#;
        let targets = policy
            .apply_control_payload(payload)
            .expect("payload should apply");
        assert!(targets.client_ids.is_empty());
        assert!(targets.usernames.is_empty());
        assert_eq!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed"),
            true
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_enable_client_clears_overlay_even_if_state_already_enabled() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");

        let disable_payload =
            br#"{"commands":[{"command":"disableClient","username":"test_user"}]}"#;
        policy
            .apply_control_payload(disable_payload)
            .expect("disable payload should apply");

        // Simulate a state overlay mismatch by externally setting the file back to enabled.
        set_client_disabled(&path, "test_user", false);
        assert_eq!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed"),
            false
        );

        let enable_payload = br#"{"commands":[{"command":"enableClient","username":"test_user"}]}"#;
        let targets = policy
            .apply_control_payload(enable_payload)
            .expect("enable payload should apply");
        assert!(targets.client_ids.is_empty());
        assert!(targets.usernames.is_empty());
        assert_eq!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed"),
            true
        );
        let _ = fs::remove_file(path);
    }
}
