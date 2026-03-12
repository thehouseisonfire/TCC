use super::*;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;

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

fn restore_fanout_reader_publish_receive_acl(path: &str) {
    let raw = fs::read_to_string(path).expect("test dynsec config should be readable");
    let mut root: Value = serde_json::from_str(&raw).expect("test dynsec config should parse");
    if let Some(roles) = root.get_mut("roles").and_then(Value::as_array_mut) {
        for role in roles {
            let Some(current_rolename) = role.get("rolename").and_then(Value::as_str) else {
                continue;
            };
            if current_rolename != "fanout_reader" {
                continue;
            }

            if role.get("acls").is_none() {
                role["acls"] = Value::Array(Vec::new());
            }
            let Some(acls) = role.get_mut("acls").and_then(Value::as_array_mut) else {
                continue;
            };

            let mut already_present = false;
            for acl in acls.iter() {
                let acltype = acl.get("acltype").and_then(Value::as_str);
                let topic = acl.get("topic").and_then(Value::as_str);
                if acltype == Some("publishClientReceive") && topic == Some("fanout/broadcast") {
                    already_present = true;
                    break;
                }
            }
            if !already_present {
                acls.push(json!({
                    "acltype": "publishClientReceive",
                    "topic": "fanout/broadcast",
                    "priority": 0,
                    "allow": true
                }));
            }
        }
    }

    let serialized =
        serde_json::to_string_pretty(&root).expect("test dynsec config should serialize");
    fs::write(path, format!("{serialized}\n")).expect("test dynsec config should be writable");
}

fn remove_group_from_dynsec_file(path: &str, groupname: &str) {
    let raw = fs::read_to_string(path).expect("test dynsec config should be readable");
    let mut root: Value = serde_json::from_str(&raw).expect("test dynsec config should parse");
    if let Some(groups) = root.get_mut("groups").and_then(Value::as_array_mut) {
        groups.retain(|group| group.get("groupname").and_then(Value::as_str) != Some(groupname));
    }
    if let Some(clients) = root.get_mut("clients").and_then(Value::as_array_mut) {
        for client in clients {
            if let Some(group_refs) = client.get_mut("groups").and_then(Value::as_array_mut) {
                group_refs.retain(|group| {
                    group.get("groupname").and_then(Value::as_str) != Some(groupname)
                });
            }
        }
    }
    let serialized =
        serde_json::to_string_pretty(&root).expect("test dynsec config should serialize");
    fs::write(path, format!("{serialized}\n")).expect("test dynsec config should be writable");
}

fn remove_group_definition_from_dynsec_file(path: &str, groupname: &str) {
    let raw = fs::read_to_string(path).expect("test dynsec config should be readable");
    let mut root: Value = serde_json::from_str(&raw).expect("test dynsec config should parse");
    if let Some(groups) = root.get_mut("groups").and_then(Value::as_array_mut) {
        groups.retain(|group| group.get("groupname").and_then(Value::as_str) != Some(groupname));
    }
    let serialized =
        serde_json::to_string_pretty(&root).expect("test dynsec config should serialize");
    fs::write(path, format!("{serialized}\n")).expect("test dynsec config should be writable");
}

fn remove_role_from_dynsec_file(path: &str, rolename: &str) {
    let raw = fs::read_to_string(path).expect("test dynsec config should be readable");
    let mut root: Value = serde_json::from_str(&raw).expect("test dynsec config should parse");
    if let Some(roles) = root.get_mut("roles").and_then(Value::as_array_mut) {
        roles.retain(|role| role.get("rolename").and_then(Value::as_str) != Some(rolename));
    }
    if let Some(groups) = root.get_mut("groups").and_then(Value::as_array_mut) {
        for group in groups {
            if let Some(role_refs) = group.get_mut("roles").and_then(Value::as_array_mut) {
                role_refs
                    .retain(|role| role.get("rolename").and_then(Value::as_str) != Some(rolename));
            }
        }
    }
    if let Some(clients) = root.get_mut("clients").and_then(Value::as_array_mut) {
        for client in clients {
            if let Some(role_refs) = client.get_mut("roles").and_then(Value::as_array_mut) {
                role_refs
                    .retain(|role| role.get("rolename").and_then(Value::as_str) != Some(rolename));
            }
        }
    }
    let serialized =
        serde_json::to_string_pretty(&root).expect("test dynsec config should serialize");
    fs::write(path, format!("{serialized}\n")).expect("test dynsec config should be writable");
}

fn remove_role_definition_from_dynsec_file(path: &str, rolename: &str) {
    let raw = fs::read_to_string(path).expect("test dynsec config should be readable");
    let mut root: Value = serde_json::from_str(&raw).expect("test dynsec config should parse");
    if let Some(roles) = root.get_mut("roles").and_then(Value::as_array_mut) {
        roles.retain(|role| role.get("rolename").and_then(Value::as_str) != Some(rolename));
    }
    let serialized =
        serde_json::to_string_pretty(&root).expect("test dynsec config should serialize");
    fs::write(path, format!("{serialized}\n")).expect("test dynsec config should be writable");
}

fn write_invalid_json(path: &str) {
    fs::write(path, "{ invalid json").expect("test dynsec config should be writable");
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

fn write_test_dynsec_notify_config() -> String {
    let unique = DYNSEC_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("dynsec-control-notify-{unique}.json"));
    let config = r#"{
  "clients": [
    {
      "username": "test_user",
      "clientid": "test_client",
      "roles": [{"rolename": "fanout_reader", "priority": 0}],
      "disabled": false
    }
  ],
  "groups": [],
  "roles": [
    {
      "rolename": "fanout_reader",
      "acls": [
        {
          "acltype": "publishClientReceive",
          "topic": "fanout/broadcast",
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
    fs::write(&path, config).expect("test dynsec notify config must be writable");
    path.to_string_lossy().into_owned()
}

fn write_test_dynsec_client_side_group_notify_config() -> String {
    let unique = DYNSEC_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path =
        std::env::temp_dir().join(format!("dynsec-control-client-group-notify-{unique}.json"));
    let config = r#"{
  "clients": [
    {
      "username": "test_user",
      "clientid": "test_client",
      "groups": [{"groupname": "fanout", "priority": 0}],
      "disabled": false
    }
  ],
  "groups": [
    {
      "groupname": "fanout",
      "roles": [{"rolename": "fanout_reader", "priority": 0}]
    }
  ],
  "roles": [
    {
      "rolename": "fanout_reader",
      "acls": [
        {
          "acltype": "publishClientReceive",
          "topic": "fanout/broadcast",
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
    fs::write(&path, config).expect("test dynsec client-group notify config must be writable");
    path.to_string_lossy().into_owned()
}

fn write_test_dynsec_overlap_notify_config() -> String {
    let unique = DYNSEC_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("dynsec-control-overlap-notify-{unique}.json"));
    let config = r#"{
  "clients": [
    {
      "username": "test_user",
      "clientid": "test_client",
      "groups": [
        {"groupname": "fanout", "priority": 0},
        {"groupname": "backup", "priority": 10}
      ],
      "disabled": false
    }
  ],
  "groups": [
    {
      "groupname": "fanout",
      "roles": [{"rolename": "fanout_reader", "priority": 0}],
      "clients": [{"username": "test_user", "priority": 0}]
    },
    {
      "groupname": "backup",
      "roles": [{"rolename": "backup_reader", "priority": 0}],
      "clients": [{"username": "test_user", "priority": 10}]
    }
  ],
  "roles": [
    {
      "rolename": "fanout_reader",
      "acls": [
        {
          "acltype": "publishClientReceive",
          "topic": "fanout/broadcast",
          "priority": 0,
          "allow": true
        }
      ]
    },
    {
      "rolename": "backup_reader",
      "acls": [
        {
          "acltype": "publishClientReceive",
          "topic": "fanout/broadcast",
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
    fs::write(&path, config).expect("test dynsec overlap notify config must be writable");
    path.to_string_lossy().into_owned()
}

fn write_test_dynsec_anonymous_config() -> String {
    let unique = DYNSEC_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("dynsec-control-anon-{unique}.json"));
    let config = r#"{
  "clients": [],
  "groups": [
    {
      "groupname": "anonymous",
      "roles": [{"rolename": "anonymous_reader", "priority": 0}],
      "clients": []
    }
  ],
  "roles": [
    {
      "rolename": "anonymous_reader",
      "acls": [
        {
          "acltype": "publishClientReceive",
          "topic": "public/announce",
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
  },
  "anonymousGroup": "anonymous"
}"#;
    fs::write(&path, config).expect("test dynsec anonymous config must be writable");
    path.to_string_lossy().into_owned()
}

fn write_test_dynsec_conflicting_membership_priority_config() -> String {
    let unique = DYNSEC_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("dynsec-control-merge-priority-{unique}.json"));
    let config = r#"{
  "clients": [
    {
      "username": "test_user",
      "clientid": "test_client",
      "groups": [
        {"groupname": "high_deny", "priority": 10},
        {"groupname": "low_allow", "priority": 5}
      ],
      "disabled": false
    }
  ],
  "groups": [
    {
      "groupname": "high_deny",
      "roles": [{"rolename": "deny_reader", "priority": 0}],
      "clients": [{"username": "test_user", "priority": 1}]
    },
    {
      "groupname": "low_allow",
      "roles": [{"rolename": "allow_reader", "priority": 0}],
      "clients": []
    }
  ],
  "roles": [
    {
      "rolename": "deny_reader",
      "acls": [
        {
          "acltype": "publishClientReceive",
          "topic": "fanout/broadcast",
          "priority": 0,
          "allow": false
        }
      ]
    },
    {
      "rolename": "allow_reader",
      "acls": [
        {
          "acltype": "publishClientReceive",
          "topic": "fanout/broadcast",
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
    fs::write(&path, config).expect("test dynsec priority config must be writable");
    path.to_string_lossy().into_owned()
}

fn add_external_group_grant(path: &str, groupname: &str, rolename: &str, topic: &str) {
    let raw = fs::read_to_string(path).expect("test dynsec config should be readable");
    let mut root: Value = serde_json::from_str(&raw).expect("test dynsec config should parse");

    let roles = root["roles"]
        .as_array_mut()
        .expect("roles should be an array");
    roles.push(json!({
        "rolename": rolename,
        "acls": [
            {
                "acltype": "publishClientReceive",
                "topic": topic,
                "priority": 0,
                "allow": true
            }
        ]
    }));

    let groups = root["groups"]
        .as_array_mut()
        .expect("groups should be an array");
    groups.push(json!({
        "groupname": groupname,
        "roles": [{"rolename": rolename, "priority": 0}],
        "clients": [{"username": "test_user", "priority": 0}]
    }));

    let clients = root["clients"]
        .as_array_mut()
        .expect("clients should be an array");
    let client = clients
        .iter_mut()
        .find(|entry| entry["username"].as_str() == Some("test_user"))
        .expect("test_user client should exist");
    client["groups"] = Value::Array(vec![json!({
        "groupname": groupname,
        "priority": 0
    })]);

    let serialized =
        serde_json::to_string_pretty(&root).expect("test dynsec config should serialize");
    fs::write(path, format!("{serialized}\n")).expect("test dynsec config should be writable");
}

fn replace_dynsec_file_with_directory(path: &str) -> String {
    let original = fs::read_to_string(path).expect("test dynsec config should be readable");
    fs::remove_file(path).expect("test dynsec config should be removable");
    fs::create_dir(path).expect("test dynsec config path should become a directory");
    original
}

fn restore_dynsec_file(path: &str, original: &str) {
    let dynsec_path = Path::new(path);
    if dynsec_path.is_dir() {
        fs::remove_dir(dynsec_path).expect("test dynsec config directory should be removable");
    } else if dynsec_path.exists() {
        fs::remove_file(dynsec_path).expect("test dynsec config file should be removable");
    }
    fs::write(dynsec_path, original).expect("test dynsec config should be restorable");
}

#[cfg(unix)]
fn set_dynsec_file_mode(path: &str, mode: u32) -> u32 {
    let mut permissions = fs::metadata(path)
        .expect("test dynsec config metadata should be readable")
        .permissions();
    let original_mode = permissions.mode();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions).expect("test dynsec config permissions should set");
    original_mode
}

fn set_top_level_field_to_object(path: &str, field: &str) {
    let raw = fs::read_to_string(path).expect("test dynsec config should be readable");
    let mut root: Value = serde_json::from_str(&raw).expect("test dynsec config should parse");
    root[field] = json!({ "broken": true });
    let serialized =
        serde_json::to_string_pretty(&root).expect("test dynsec config should serialize");
    fs::write(path, format!("{serialized}\n")).expect("test dynsec config should be writable");
}

fn set_stub_group_grant(path: &str, groupname: &str, rolename: &str) {
    let raw = fs::read_to_string(path).expect("test dynsec config should be readable");
    let mut root: Value = serde_json::from_str(&raw).expect("test dynsec config should parse");

    let roles = root["roles"]
        .as_array_mut()
        .expect("roles should be an array");
    roles.push(json!({
        "rolename": rolename,
        "acls": []
    }));

    let groups = root["groups"]
        .as_array_mut()
        .expect("groups should be an array");
    groups.push(json!({
        "groupname": groupname,
        "roles": [],
        "clients": []
    }));

    let serialized =
        serde_json::to_string_pretty(&root).expect("test dynsec config should serialize");
    fs::write(path, format!("{serialized}\n")).expect("test dynsec config should be writable");
}

fn group_grant_payload() -> &'static [u8] {
    br#"{
  "commands": [
    {
      "command": "createRole",
      "rolename": "fanout_reader",
      "acls": [
        {
          "acltype": "subscribeLiteral",
          "topic": "fanout/broadcast",
          "priority": 1,
          "allow": true
        },
        {
          "acltype": "publishClientReceive",
          "topic": "fanout/broadcast",
          "priority": 1,
          "allow": true
        }
      ]
    },
    {
      "command": "createGroup",
      "groupname": "fanout",
      "roles": [
        {"rolename": "fanout_reader", "priority": 5}
      ]
    },
    {
      "command": "addGroupClient",
      "groupname": "fanout",
      "username": "test_user",
      "priority": 7
    }
  ]
}"#
}

fn anonymous_placeholder_group_payload() -> &'static [u8] {
    br#"{
  "commands": [
    {
      "command": "createRole",
      "rolename": "private_reader",
      "acls": [
        {
          "acltype": "publishClientReceive",
          "topic": "private/announce",
          "priority": 0,
          "allow": true
        }
      ]
    },
    {
      "command": "createGroup",
      "groupname": "private",
      "roles": [
        {"rolename": "private_reader", "priority": 0}
      ]
    },
    {
      "command": "addGroupClient",
      "groupname": "private",
      "username": "ghost",
      "priority": 0
    }
  ]
}"#
}

fn assert_persisted_disabled_placeholder_client(path: &str, username: &str) {
    let raw = fs::read_to_string(path).expect("dynsec config should be readable");
    let root: Value = serde_json::from_str(&raw).expect("dynsec config should parse");
    let clients = root["clients"]
        .as_array()
        .expect("clients should be an array");
    let client = clients
        .iter()
        .find(|client| client["username"].as_str() == Some(username))
        .expect("disabled placeholder client should be persisted");
    assert_eq!(client["disabled"].as_bool(), Some(true));
    assert!(client.get("clientid").is_none());
    assert!(nested_array_missing_or_empty(client, "roles").expect("roles should be valid"));
    assert!(nested_array_missing_or_empty(client, "groups").expect("groups should be valid"));
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
    assert_eq!(targets.kick_client_ids, vec!["test_client".to_string()]);
    assert_eq!(targets.kick_usernames, vec!["test_user".to_string()]);
    assert!(targets.notify_events.is_empty());
    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("policy check should succeed")
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
    assert!(targets.kick_client_ids.is_empty());
    assert!(targets.kick_usernames.is_empty());
    assert!(targets.notify_events.is_empty());
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("policy check should succeed")
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
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");

    let payload = br#"{"commands":[{"command":"disableClient","username":"test_user"}]}"#;
    let targets = policy
        .apply_control_payload(payload)
        .expect("control payload should apply");
    assert!(targets.kick_client_ids.is_empty());
    assert_eq!(targets.kick_usernames, vec!["test_user".to_string()]);
    assert!(targets.notify_events.is_empty());

    // Runtime disable overlay must continue denying even after config reloads.
    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("another_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("policy check should succeed")
    );
    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_enable_client_clears_runtime_disable_overlay() {
    let path = write_test_dynsec_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");

    let disable_payload = br#"{"commands":[{"command":"disableClient","username":"test_user"}]}"#;
    let disable_targets = policy
        .apply_control_payload(disable_payload)
        .expect("disable payload should apply");
    assert_eq!(
        disable_targets.kick_client_ids,
        vec!["test_client".to_string()]
    );
    assert_eq!(
        disable_targets.kick_usernames,
        vec!["test_user".to_string()]
    );
    assert!(disable_targets.notify_events.is_empty());
    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("policy check should succeed")
    );

    let enable_payload = br#"{"commands":[{"command":"enableClient","username":"test_user"}]}"#;
    let enable_targets = policy
        .apply_control_payload(enable_payload)
        .expect("enable payload should apply");
    assert!(enable_targets.kick_client_ids.is_empty());
    assert!(enable_targets.kick_usernames.is_empty());
    assert!(enable_targets.notify_events.is_empty());
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("policy check should succeed")
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
    assert!(targets.kick_client_ids.is_empty());
    assert!(targets.kick_usernames.is_empty());
    assert!(targets.notify_events.is_empty());
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("policy check should succeed")
    );
    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_enable_client_clears_overlay_even_if_state_already_enabled() {
    let path = write_test_dynsec_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");

    let disable_payload = br#"{"commands":[{"command":"disableClient","username":"test_user"}]}"#;
    policy
        .apply_control_payload(disable_payload)
        .expect("disable payload should apply");

    // Simulate a state overlay mismatch by externally setting the file back to enabled.
    set_client_disabled(&path, "test_user", false);
    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("policy check should succeed")
    );

    let enable_payload = br#"{"commands":[{"command":"enableClient","username":"test_user"}]}"#;
    let targets = policy
        .apply_control_payload(enable_payload)
        .expect("enable payload should apply");
    assert!(targets.kick_client_ids.is_empty());
    assert!(targets.kick_usernames.is_empty());
    assert!(targets.notify_events.is_empty());
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("policy check should succeed")
    );
    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_create_role_group_and_membership_grants_access_after_reload() {
    let path = write_test_dynsec_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");

    let targets = policy
        .apply_control_payload(group_grant_payload())
        .expect("create payload should apply");
    assert!(targets.kick_client_ids.is_empty());
    assert!(targets.kick_usernames.is_empty());
    assert!(targets.notify_events.is_empty());

    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_SUBSCRIBE
            )
            .expect("policy check should succeed")
    );
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        reloaded
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_SUBSCRIBE
            )
            .expect("policy check should succeed")
    );
    assert!(
        reloaded
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );
    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_remove_group_client_revokes_group_access_after_reload() {
    let path = write_test_dynsec_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");
    policy
        .apply_control_payload(group_grant_payload())
        .expect("create payload should apply");

    let payload =
            br#"{"commands":[{"command":"removeGroupClient","groupname":"fanout","username":"test_user"}]}"#;
    let targets = policy
        .apply_control_payload(payload)
        .expect("remove payload should apply");
    assert!(targets.kick_client_ids.is_empty());
    assert!(targets.kick_usernames.is_empty());
    assert_eq!(targets.notify_events.len(), 1);
    let event = &targets.notify_events[0];
    assert_eq!(event.command, "removeGroupClient");
    assert_eq!(event.rolename.as_deref(), Some("fanout_reader"));
    assert_eq!(event.acltype.as_deref(), Some("publishClientReceive"));
    assert_eq!(event.topic.as_deref(), Some("fanout/broadcast"));
    assert_eq!(event.usernames, vec!["test_user".to_string()]);
    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_SUBSCRIBE
            )
            .expect("policy check should succeed")
    );

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        !reloaded
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );
    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_remove_group_client_prunes_placeholder_and_restores_anonymous_fallback() {
    let path = write_test_dynsec_anonymous_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");
    policy
        .apply_control_payload(anonymous_placeholder_group_payload())
        .expect("create payload should apply");

    assert!(
        !policy
            .check(
                Some("ghost"),
                Some("ghost_client"),
                "public/announce",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    let payload =
            br#"{"commands":[{"command":"removeGroupClient","groupname":"private","username":"ghost"}]}"#;
    let targets = policy
        .apply_control_payload(payload)
        .expect("remove payload should apply");
    assert!(targets.kick_client_ids.is_empty());
    assert!(targets.kick_usernames.is_empty());
    assert_eq!(targets.notify_events.len(), 1);
    let event = &targets.notify_events[0];
    assert_eq!(event.command, "removeGroupClient");
    assert_eq!(event.rolename.as_deref(), Some("private_reader"));
    assert_eq!(event.acltype.as_deref(), Some("publishClientReceive"));
    assert_eq!(event.topic.as_deref(), Some("private/announce"));
    assert_eq!(event.usernames, vec!["ghost".to_string()]);

    let state = policy
        .state
        .read()
        .expect("dynsec state lock should succeed");
    assert!(!state.clients.contains_key("ghost"));
    drop(state);

    assert!(
        policy
            .check(
                Some("ghost"),
                Some("ghost_client"),
                "public/announce",
                ACL_READ
            )
            .expect("policy check should succeed")
    );
    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_delete_group_revokes_group_access_after_reload() {
    let path = write_test_dynsec_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");
    policy
        .apply_control_payload(group_grant_payload())
        .expect("create payload should apply");

    let payload = br#"{"commands":[{"command":"deleteGroup","groupname":"fanout"}]}"#;
    let targets = policy
        .apply_control_payload(payload)
        .expect("delete payload should apply");
    assert!(targets.kick_client_ids.is_empty());
    assert!(targets.kick_usernames.is_empty());
    assert_eq!(targets.notify_events.len(), 1);
    let event = &targets.notify_events[0];
    assert_eq!(event.command, "deleteGroup");
    assert_eq!(event.rolename.as_deref(), Some("fanout_reader"));
    assert_eq!(event.acltype.as_deref(), Some("publishClientReceive"));
    assert_eq!(event.topic.as_deref(), Some("fanout/broadcast"));
    assert_eq!(event.usernames, vec!["test_user".to_string()]);
    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    let raw = fs::read_to_string(&path).expect("dynsec config should be readable");
    let root: Value = serde_json::from_str(&raw).expect("dynsec config should parse");
    let groups = root["groups"]
        .as_array()
        .expect("groups should be an array");
    assert!(groups.is_empty());
    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_delete_group_prunes_placeholders_and_restores_anonymous_fallback() {
    let path = write_test_dynsec_anonymous_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");
    policy
        .apply_control_payload(anonymous_placeholder_group_payload())
        .expect("create payload should apply");

    let payload = br#"{"commands":[{"command":"deleteGroup","groupname":"private"}]}"#;
    let targets = policy
        .apply_control_payload(payload)
        .expect("delete payload should apply");
    assert!(targets.kick_client_ids.is_empty());
    assert!(targets.kick_usernames.is_empty());
    assert_eq!(targets.notify_events.len(), 1);
    let event = &targets.notify_events[0];
    assert_eq!(event.command, "deleteGroup");
    assert_eq!(event.rolename.as_deref(), Some("private_reader"));
    assert_eq!(event.acltype.as_deref(), Some("publishClientReceive"));
    assert_eq!(event.topic.as_deref(), Some("private/announce"));
    assert_eq!(event.usernames, vec!["ghost".to_string()]);

    let state = policy
        .state
        .read()
        .expect("dynsec state lock should succeed");
    assert!(!state.clients.contains_key("ghost"));
    drop(state);

    assert!(
        policy
            .check(
                Some("ghost"),
                Some("ghost_client"),
                "public/announce",
                ACL_READ
            )
            .expect("policy check should succeed")
    );
    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_delete_anonymous_group_clears_anonymous_binding() {
    let path = write_test_dynsec_anonymous_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");

    assert!(
        policy
            .check(None, None, "public/announce", ACL_READ)
            .expect("anonymous policy check should succeed")
    );

    let targets = policy
        .apply_control_payload(
            br#"{"commands":[{"command":"deleteGroup","groupname":"anonymous"}]}"#,
        )
        .expect("delete payload should apply");
    assert!(targets.kick_client_ids.is_empty());
    assert!(targets.kick_usernames.is_empty());

    let state = policy
        .state
        .read()
        .expect("dynsec state lock should succeed");
    assert!(!state.groups.contains_key("anonymous"));
    assert_eq!(state.anonymous_group, None);
    drop(state);

    assert!(
        !policy
            .check(None, None, "public/announce", ACL_READ)
            .expect("anonymous policy check should succeed")
    );

    let raw = fs::read_to_string(&path).expect("dynsec config should be readable");
    let root: Value = serde_json::from_str(&raw).expect("dynsec config should parse");
    assert!(root.get("anonymousGroup").is_none());

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        !reloaded
            .check(None, None, "public/announce", ACL_READ)
            .expect("anonymous policy check should succeed")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_delete_role_cleans_group_references_after_reload() {
    let path = write_test_dynsec_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");
    policy
        .apply_control_payload(group_grant_payload())
        .expect("create payload should apply");

    let payload = br#"{"commands":[{"command":"deleteRole","rolename":"fanout_reader"}]}"#;
    let targets = policy
        .apply_control_payload(payload)
        .expect("delete payload should apply");
    assert!(targets.kick_client_ids.is_empty());
    assert!(targets.kick_usernames.is_empty());
    assert_eq!(targets.notify_events.len(), 1);
    let event = &targets.notify_events[0];
    assert_eq!(event.command, "deleteRole");
    assert_eq!(event.rolename.as_deref(), Some("fanout_reader"));
    assert_eq!(event.acltype.as_deref(), Some("publishClientReceive"));
    assert_eq!(event.topic.as_deref(), Some("fanout/broadcast"));
    assert_eq!(event.usernames, vec!["test_user".to_string()]);
    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    let raw = fs::read_to_string(&path).expect("dynsec config should be readable");
    let root: Value = serde_json::from_str(&raw).expect("dynsec config should parse");
    let roles = root["roles"].as_array().expect("roles should be an array");
    assert_eq!(roles.len(), 1);
    let group_roles = root["groups"][0]["roles"]
        .as_array()
        .expect("group roles should be an array");
    assert!(group_roles.is_empty());
    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_add_group_client_updates_existing_priority_and_persists() {
    let path = write_test_dynsec_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");
    policy
        .apply_control_payload(group_grant_payload())
        .expect("create payload should apply");

    let payload =
            br#"{"commands":[{"command":"addGroupClient","groupname":"fanout","username":"test_user","priority":1}]}"#;
    let targets = policy
        .apply_control_payload(payload)
        .expect("priority update should apply");
    assert!(targets.kick_client_ids.is_empty());
    assert!(targets.kick_usernames.is_empty());
    assert!(targets.notify_events.is_empty());

    let state = policy
        .state
        .read()
        .expect("dynsec state lock should succeed");
    let client_group = state
        .clients
        .get("test_user")
        .and_then(|client| client.groups.iter().find(|group| group.name == "fanout"))
        .expect("client should keep fanout membership");
    assert_eq!(client_group.priority, 1);
    let group_client = state
        .groups
        .get("fanout")
        .and_then(|group| {
            group
                .clients
                .iter()
                .find(|client| client.name == "test_user")
        })
        .expect("group should keep test_user membership");
    assert_eq!(group_client.priority, 1);
    drop(state);

    let raw = fs::read_to_string(&path).expect("dynsec config should be readable");
    let root: Value = serde_json::from_str(&raw).expect("dynsec config should parse");
    let groups = root["groups"]
        .as_array()
        .expect("groups should be an array");
    let fanout_group = groups
        .iter()
        .find(|group| group["groupname"].as_str() == Some("fanout"))
        .expect("fanout group should exist");
    let clients = fanout_group["clients"]
        .as_array()
        .expect("group clients should be an array");
    let test_user = clients
        .iter()
        .find(|entry| entry["username"].as_str() == Some("test_user"))
        .expect("test_user client ref should exist");
    assert_eq!(test_user["priority"].as_i64(), Some(1));
    let test_user_groups = root["clients"][0]["groups"]
        .as_array()
        .expect("client groups should be an array");
    let fanout_membership = test_user_groups
        .iter()
        .find(|entry| entry["groupname"].as_str() == Some("fanout"))
        .expect("fanout group ref should exist");
    assert_eq!(fanout_membership["priority"].as_i64(), Some(1));

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    let reloaded_state = reloaded
        .state
        .read()
        .expect("dynsec state lock should succeed");
    let reloaded_group = reloaded_state
        .clients
        .get("test_user")
        .and_then(|client| client.groups.iter().find(|group| group.name == "fanout"))
        .expect("reloaded client should keep fanout membership");
    assert_eq!(reloaded_group.priority, 1);
    drop(reloaded_state);

    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_persist_failure_returns_warning_and_keeps_structural_mutations_live() {
    let path = write_test_dynsec_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let original = replace_dynsec_file_with_directory(&path);

    let targets = policy
        .apply_control_payload(group_grant_payload())
        .expect("persist failure should still apply runtime mutations");
    assert!(
        targets
            .persist_warning
            .as_deref()
            .is_some_and(|warning| warning.contains("dynsec config read failed"))
    );
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    restore_dynsec_file(&path, &original);
    policy
        .reload_if_needed(true)
        .expect("forced reload should preserve pending structural mutations");
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    restore_dynsec_file(&path, &original);
    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        !reloaded
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );
    let _ = fs::remove_file(path);
}

#[test]
fn check_fast_path_does_not_wait_on_control_apply_lock_when_reload_is_fresh() {
    let path = write_test_dynsec_config();
    let policy = Arc::new(
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load"),
    );
    let control_guard = policy
        .control_apply_lock
        .lock()
        .expect("control lock should succeed");
    let (tx, rx) = mpsc::channel();
    let thread_policy = Arc::clone(&policy);

    let handle = thread::spawn(move || {
        let result = thread_policy.check(
            Some("test_user"),
            Some("test_client"),
            "$CONTROL/dynamic-security/v1",
            ACL_WRITE,
        );
        tx.send(result).expect("channel send should succeed");
    });

    let result = rx
        .recv_timeout(Duration::from_millis(200))
        .expect("fresh check should not block on control lock");
    assert!(result.expect("policy check should succeed"));

    drop(control_guard);
    handle.join().expect("check thread should join");
    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_persist_failure_returns_warning_and_keeps_runtime_disable_overlay_live() {
    let path = write_test_dynsec_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let original = replace_dynsec_file_with_directory(&path);

    let targets = policy
        .apply_control_payload(
            br#"{"commands":[{"command":"disableClient","username":"test_user"}]}"#,
        )
        .expect("persist failure should still apply runtime disable");
    assert!(
        targets
            .persist_warning
            .as_deref()
            .is_some_and(|warning| warning.contains("dynsec config read failed"))
    );
    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("policy check should succeed")
    );

    restore_dynsec_file(&path, &original);
    policy
        .reload_if_needed(true)
        .expect("forced reload should preserve runtime disable overlay");
    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("policy check should succeed")
    );

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        reloaded
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("policy check should succeed")
    );
    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_persist_failure_returns_warning_and_keeps_runtime_enable_live() {
    let path = write_test_dynsec_config();
    set_client_disabled(&path, "test_user", true);
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let original = replace_dynsec_file_with_directory(&path);

    let targets = policy
        .apply_control_payload(
            br#"{"commands":[{"command":"enableClient","username":"test_user"}]}"#,
        )
        .expect("persist failure should still apply runtime enable");
    assert!(
        targets
            .persist_warning
            .as_deref()
            .is_some_and(|warning| warning.contains("dynsec config read failed"))
    );
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("policy check should succeed")
    );

    restore_dynsec_file(&path, &original);
    policy
        .reload_if_needed(true)
        .expect("forced reload should preserve runtime enable");
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("policy check should succeed")
    );

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        !reloaded
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("policy check should succeed")
    );
    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_persist_failure_returns_warning_and_keeps_role_acl_overrides_live() {
    let path = write_test_dynsec_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let original = replace_dynsec_file_with_directory(&path);

    let targets = policy
            .apply_control_payload(br#"{"commands":[{"command":"addRoleACL","rolename":"ctrl","acltype":"publishClientReceive","topic":"fanout/broadcast","priority":1,"allow":true}]}"#)
            .expect("persist failure should still apply role ACL overrides");
    assert!(
        targets
            .persist_warning
            .as_deref()
            .is_some_and(|warning| warning.contains("dynsec config read failed"))
    );
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    restore_dynsec_file(&path, &original);
    policy
        .reload_if_needed(true)
        .expect("forced reload should preserve runtime role ACL overrides");
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        !reloaded
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );
    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_schema_invalid_persist_keeps_pending_structural_mutations() {
    let path = write_test_dynsec_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let original = fs::read_to_string(&path).expect("test dynsec config should be readable");
    set_top_level_field_to_object(&path, "groups");

    let targets = policy
        .apply_control_payload(group_grant_payload())
        .expect("schema-invalid persist should still apply runtime mutations");
    assert!(
        targets
            .persist_warning
            .as_deref()
            .is_some_and(|warning| warning.contains("expected 'groups' to be an array"))
    );
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );
    assert!(
        !policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed")
            .is_empty()
    );

    restore_dynsec_file(&path, &original);
    policy
        .reload_if_needed(true)
        .expect("forced reload should preserve pending structural mutations");
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_schema_invalid_persist_keeps_pending_runtime_disable() {
    let path = write_test_dynsec_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let original = fs::read_to_string(&path).expect("test dynsec config should be readable");
    set_top_level_field_to_object(&path, "clients");

    let targets = policy
        .apply_control_payload(
            br#"{"commands":[{"command":"disableClient","username":"test_user"}]}"#,
        )
        .expect("schema-invalid persist should still apply runtime disable");
    assert!(
        targets
            .persist_warning
            .as_deref()
            .is_some_and(|warning| warning.contains("expected 'clients' to be an array"))
    );
    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("policy check should succeed")
    );
    assert!(
        !policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed")
            .is_empty()
    );

    restore_dynsec_file(&path, &original);
    policy
        .reload_if_needed(true)
        .expect("forced reload should preserve pending runtime disable");
    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("policy check should succeed")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_retries_pending_persist_mutations_on_later_success() {
    let path = write_test_dynsec_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let original = replace_dynsec_file_with_directory(&path);

    let first_targets = policy
        .apply_control_payload(group_grant_payload())
        .expect("persist failure should still apply runtime mutations");
    assert!(first_targets.persist_warning.is_some());
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    restore_dynsec_file(&path, &original);
    let retry_targets = policy
        .apply_control_payload(group_grant_payload())
        .expect("later control command should retry pending persistence");
    assert!(retry_targets.persist_warning.is_none());
    assert!(
        policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed")
            .is_empty()
    );

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        reloaded
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );
    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_keeps_pending_add_group_client_when_retry_is_blocked() {
    let path = write_test_dynsec_client_side_group_notify_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let original = replace_dynsec_file_with_directory(&path);

    let first_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"addGroupClient","groupname":"fanout","username":"ghost","priority":5}]}"#,
            )
            .expect("persist failure should still apply runtime mutations");
    assert!(first_targets.persist_warning.is_some());
    assert!(
        policy
            .check(
                Some("ghost"),
                Some("ghost_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    restore_dynsec_file(&path, &original);
    remove_group_from_dynsec_file(&path, "fanout");

    let retry_targets = policy
        .apply_control_payload(br#"{"commands":[{"command":"listRoles"}]}"#)
        .expect("retry should keep runtime changes live");
    assert!(
        retry_targets
            .persist_warning
            .as_deref()
            .is_some_and(|warning| warning.contains("blocked by divergent state"))
    );
    assert!(
        !policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed")
            .is_empty()
    );
    assert!(
        !policy
            .check(
                Some("ghost"),
                Some("ghost_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should follow fresh file state on replay failure")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_keeps_pending_role_acl_add_when_retry_is_blocked() {
    let path = write_test_dynsec_notify_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let original = replace_dynsec_file_with_directory(&path);

    let first_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"addRoleACL","rolename":"fanout_reader","acltype":"subscribeLiteral","topic":"fanout/broadcast","priority":0,"allow":true}]}"#,
            )
            .expect("persist failure should still apply runtime mutations");
    assert!(first_targets.persist_warning.is_some());
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_SUBSCRIBE
            )
            .expect("policy check should succeed")
    );

    restore_dynsec_file(&path, &original);
    remove_role_from_dynsec_file(&path, "fanout_reader");

    let retry_targets = policy
        .apply_control_payload(br#"{"commands":[{"command":"listRoles"}]}"#)
        .expect("retry should keep runtime changes live");
    assert!(
        retry_targets
            .persist_warning
            .as_deref()
            .is_some_and(|warning| warning.contains("blocked by divergent state"))
    );
    assert!(
        !policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed")
            .is_empty()
    );

    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_current_create_group_repairs_pending_add_group_client_retry() {
    let path = write_test_dynsec_client_side_group_notify_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let original = replace_dynsec_file_with_directory(&path);

    let first_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"addGroupClient","groupname":"fanout","username":"ghost","priority":5}]}"#,
            )
            .expect("persist failure should still apply runtime mutations");
    assert!(first_targets.persist_warning.is_some());

    restore_dynsec_file(&path, &original);
    remove_group_from_dynsec_file(&path, "fanout");

    let repair_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"createGroup","groupname":"fanout","roles":[{"rolename":"fanout_reader","priority":0}]}]}"#,
            )
            .expect("repair payload should apply");
    assert!(repair_targets.persist_warning.is_none());
    assert!(
        policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed")
            .is_empty()
    );

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        reloaded
            .check(
                Some("ghost"),
                Some("ghost_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed after durable repair")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_current_create_role_repairs_pending_role_acl_retry() {
    let path = write_test_dynsec_notify_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let original = replace_dynsec_file_with_directory(&path);

    let first_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"addRoleACL","rolename":"fanout_reader","acltype":"subscribeLiteral","topic":"fanout/broadcast","priority":0,"allow":true}]}"#,
            )
            .expect("persist failure should still apply runtime mutations");
    assert!(first_targets.persist_warning.is_some());

    restore_dynsec_file(&path, &original);
    remove_role_definition_from_dynsec_file(&path, "fanout_reader");

    let repair_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"createRole","rolename":"fanout_reader","acls":[{"acltype":"publishClientReceive","topic":"fanout/broadcast","priority":0,"allow":true}]}]}"#,
            )
            .expect("repair payload should apply");
    assert!(repair_targets.persist_warning.is_none());
    assert!(
        policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed")
            .is_empty()
    );

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        reloaded
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_SUBSCRIBE
            )
            .expect("policy check should succeed after durable repair")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn collapse_retry_intents_drops_superseded_group_client_add_before_delete_group() {
    let collapsed = collapse_retry_intents(&[
        PersistMutation::AddGroupClient {
            groupname: "fanout".to_string(),
            username: "ghost".to_string(),
            priority: 5,
        },
        PersistMutation::DeleteGroup {
            groupname: "fanout".to_string(),
        },
    ]);

    assert_eq!(collapsed.len(), 1);
    assert!(matches!(
        collapsed.as_slice(),
        [PersistMutation::DeleteGroup { groupname }] if groupname == "fanout"
    ));
}

#[test]
fn collapse_retry_intents_drops_superseded_role_acl_add_before_delete_role() {
    let collapsed = collapse_retry_intents(&[
        PersistMutation::RoleAcl(RoleAclMutation::Add {
            rolename: "fanout_reader".to_string(),
            acltype: "subscribeLiteral".to_string(),
            topic: "fanout/broadcast".to_string(),
            priority: 0,
            allow: true,
        }),
        PersistMutation::DeleteRole {
            rolename: "fanout_reader".to_string(),
        },
    ]);

    assert_eq!(collapsed.len(), 1);
    assert!(matches!(
        collapsed.as_slice(),
        [PersistMutation::DeleteRole { rolename }] if rolename == "fanout_reader"
    ));
}

#[test]
fn collapse_retry_intents_keeps_only_latest_group_client_intent() {
    let collapsed = collapse_retry_intents(&[
        PersistMutation::AddGroupClient {
            groupname: "fanout".to_string(),
            username: "ghost".to_string(),
            priority: 1,
        },
        PersistMutation::RemoveGroupClient {
            groupname: "fanout".to_string(),
            username: "ghost".to_string(),
        },
        PersistMutation::AddGroupClient {
            groupname: "fanout".to_string(),
            username: "ghost".to_string(),
            priority: 7,
        },
    ]);

    assert_eq!(collapsed.len(), 1);
    assert!(matches!(
        collapsed.as_slice(),
        [PersistMutation::AddGroupClient {
            groupname,
            username,
            priority
        }] if groupname == "fanout" && username == "ghost" && *priority == 7
    ));
}

#[test]
fn collapse_retry_intents_create_group_then_delete_then_recreate_keeps_delete_cleanup() {
    let collapsed = collapse_retry_intents(&[
        PersistMutation::CreateGroup {
            groupname: "fanout".to_string(),
            roles: vec![RoleRef {
                rolename: "reader".to_string(),
                priority: Some(0),
            }],
        },
        PersistMutation::DeleteGroup {
            groupname: "fanout".to_string(),
        },
        PersistMutation::CreateGroup {
            groupname: "fanout".to_string(),
            roles: vec![RoleRef {
                rolename: "writer".to_string(),
                priority: Some(5),
            }],
        },
    ]);

    assert!(matches!(
        collapsed.as_slice(),
        [
            PersistMutation::DeleteGroup { groupname: deleted_group },
            PersistMutation::CreateGroup { groupname, roles }
        ] if deleted_group == "fanout"
            && groupname == "fanout"
            && roles.len() == 1
            && roles[0].rolename == "writer"
            && roles[0].priority == Some(5)
    ));
}

#[test]
fn collapse_retry_intents_create_role_then_delete_then_recreate_keeps_delete_cleanup() {
    let collapsed = collapse_retry_intents(&[
        PersistMutation::CreateRole {
            rolename: "fanout_reader".to_string(),
            acls: vec![AclConfig {
                acltype: "subscribeLiteral".to_string(),
                topic: "fanout/old".to_string(),
                priority: Some(0),
                allow: Some(true),
            }],
        },
        PersistMutation::DeleteRole {
            rolename: "fanout_reader".to_string(),
        },
        PersistMutation::CreateRole {
            rolename: "fanout_reader".to_string(),
            acls: vec![AclConfig {
                acltype: "subscribeLiteral".to_string(),
                topic: "fanout/new".to_string(),
                priority: Some(2),
                allow: Some(true),
            }],
        },
    ]);

    assert!(matches!(
        collapsed.as_slice(),
        [
            PersistMutation::DeleteRole { rolename: deleted_role },
            PersistMutation::CreateRole { rolename, acls }
        ] if deleted_role == "fanout_reader"
            && rolename == "fanout_reader"
            && acls.len() == 1
            && acls[0].topic == "fanout/new"
            && acls[0].priority == Some(2)
    ));
}

#[test]
fn collapse_retry_intents_delete_group_then_create_group_keeps_recreated_membership() {
    let collapsed = collapse_retry_intents(&[
        PersistMutation::DeleteGroup {
            groupname: "fanout".to_string(),
        },
        PersistMutation::CreateGroup {
            groupname: "fanout".to_string(),
            roles: vec![RoleRef {
                rolename: "reader".to_string(),
                priority: Some(0),
            }],
        },
        PersistMutation::AddGroupClient {
            groupname: "fanout".to_string(),
            username: "ghost".to_string(),
            priority: 3,
        },
    ]);

    assert!(matches!(
        collapsed.as_slice(),
        [
            PersistMutation::DeleteGroup { groupname: deleted_group },
            PersistMutation::CreateGroup { groupname, .. },
            PersistMutation::AddGroupClient {
                groupname: add_group,
                username,
                priority
            }
        ] if deleted_group == "fanout"
            && groupname == "fanout"
            && add_group == "fanout"
            && username == "ghost"
            && *priority == 3
    ));
}

#[test]
fn collapse_retry_intents_delete_role_then_create_role_keeps_recreated_acl_add() {
    let collapsed = collapse_retry_intents(&[
        PersistMutation::DeleteRole {
            rolename: "fanout_reader".to_string(),
        },
        PersistMutation::CreateRole {
            rolename: "fanout_reader".to_string(),
            acls: vec![AclConfig {
                acltype: "publishClientReceive".to_string(),
                topic: "fanout/base".to_string(),
                priority: Some(0),
                allow: Some(true),
            }],
        },
        PersistMutation::RoleAcl(RoleAclMutation::Add {
            rolename: "fanout_reader".to_string(),
            acltype: "subscribeLiteral".to_string(),
            topic: "fanout/extra".to_string(),
            priority: 4,
            allow: true,
        }),
    ]);

    assert!(matches!(
        collapsed.as_slice(),
        [
            PersistMutation::DeleteRole { rolename: deleted_role },
            PersistMutation::CreateRole { rolename, .. },
            PersistMutation::RoleAcl(RoleAclMutation::Add {
                rolename: acl_role,
                acltype,
                topic,
                priority,
                allow
            })
        ] if deleted_role == "fanout_reader"
            && rolename == "fanout_reader"
            && acl_role == "fanout_reader"
            && acltype == "subscribeLiteral"
            && topic == "fanout/extra"
            && *priority == 4
            && *allow
    ));
}

#[test]
fn collapse_retry_intents_emits_delete_before_recreate_and_dependents() {
    let collapsed = collapse_retry_intents(&[
        PersistMutation::DeleteGroup {
            groupname: "fanout".to_string(),
        },
        PersistMutation::CreateGroup {
            groupname: "fanout".to_string(),
            roles: vec![RoleRef {
                rolename: "reader".to_string(),
                priority: Some(0),
            }],
        },
        PersistMutation::AddGroupClient {
            groupname: "fanout".to_string(),
            username: "ghost".to_string(),
            priority: 3,
        },
        PersistMutation::SetClientDisabled {
            username: "ghost".to_string(),
            disabled: true,
        },
        PersistMutation::RoleAcl(RoleAclMutation::Add {
            rolename: "reader".to_string(),
            acltype: "subscribeLiteral".to_string(),
            topic: "fanout/extra".to_string(),
            priority: 4,
            allow: true,
        }),
        PersistMutation::RemoveGroupClient {
            groupname: "fanout".to_string(),
            username: "other".to_string(),
        },
        PersistMutation::RoleAcl(RoleAclMutation::Remove {
            rolename: "reader".to_string(),
            acltype: "subscribeLiteral".to_string(),
            topic: "fanout/old".to_string(),
        }),
    ]);

    assert!(matches!(
        collapsed.as_slice(),
        [
            PersistMutation::DeleteGroup { groupname: deleted_group },
            PersistMutation::CreateGroup { groupname: created_group, .. },
            PersistMutation::AddGroupClient { groupname: added_group, username: added_user, priority: added_priority },
            PersistMutation::SetClientDisabled { username: disabled_user, disabled },
            PersistMutation::RoleAcl(RoleAclMutation::Add {
                rolename: added_role,
                acltype: added_acltype,
                topic: added_topic,
                priority: added_acl_priority,
                allow: added_allow
            }),
            PersistMutation::RemoveGroupClient { groupname: removed_group, username: removed_user },
            PersistMutation::RoleAcl(RoleAclMutation::Remove {
                rolename: removed_role,
                acltype: removed_acltype,
                topic: removed_topic
            })
        ] if deleted_group == "fanout"
            && created_group == "fanout"
            && added_group == "fanout"
            && added_user == "ghost"
            && *added_priority == 3
            && disabled_user == "ghost"
            && *disabled
            && added_role == "reader"
            && added_acltype == "subscribeLiteral"
            && added_topic == "fanout/extra"
            && *added_acl_priority == 4
            && *added_allow
            && removed_group == "fanout"
            && removed_user == "other"
            && removed_role == "reader"
            && removed_acltype == "subscribeLiteral"
            && removed_topic == "fanout/old"
    ));
}

#[test]
fn collapse_retry_intents_skips_dependents_only_for_delete_not_delete_then_create() {
    let delete_only = collapse_retry_intents(&[
        PersistMutation::DeleteGroup {
            groupname: "fanout".to_string(),
        },
        PersistMutation::AddGroupClient {
            groupname: "fanout".to_string(),
            username: "ghost".to_string(),
            priority: 3,
        },
    ]);
    assert!(matches!(
        delete_only.as_slice(),
        [PersistMutation::DeleteGroup { groupname }] if groupname == "fanout"
    ));

    let recreated = collapse_retry_intents(&[
        PersistMutation::DeleteGroup {
            groupname: "fanout".to_string(),
        },
        PersistMutation::CreateGroup {
            groupname: "fanout".to_string(),
            roles: vec![RoleRef {
                rolename: "reader".to_string(),
                priority: Some(0),
            }],
        },
        PersistMutation::AddGroupClient {
            groupname: "fanout".to_string(),
            username: "ghost".to_string(),
            priority: 3,
        },
    ]);
    assert!(matches!(
        recreated.as_slice(),
        [
            PersistMutation::DeleteGroup { groupname: deleted_group },
            PersistMutation::CreateGroup { groupname: created_group, .. },
            PersistMutation::AddGroupClient { groupname: added_group, username, priority }
        ] if deleted_group == "fanout"
            && created_group == "fanout"
            && added_group == "fanout"
            && username == "ghost"
            && *priority == 3
    ));
}

#[test]
fn collapse_retry_intents_create_group_then_delete_drops_intermediate_membership_intents() {
    let collapsed = collapse_retry_intents(&[
        PersistMutation::CreateGroup {
            groupname: "fanout".to_string(),
            roles: vec![RoleRef {
                rolename: "reader".to_string(),
                priority: Some(0),
            }],
        },
        PersistMutation::AddGroupClient {
            groupname: "fanout".to_string(),
            username: "ghost".to_string(),
            priority: 5,
        },
        PersistMutation::DeleteGroup {
            groupname: "fanout".to_string(),
        },
    ]);

    assert!(matches!(
        collapsed.as_slice(),
        [PersistMutation::DeleteGroup { groupname }] if groupname == "fanout"
    ));
}

#[test]
fn collapse_retry_intents_create_role_then_delete_drops_intermediate_acl_intents() {
    let collapsed = collapse_retry_intents(&[
        PersistMutation::CreateRole {
            rolename: "fanout_reader".to_string(),
            acls: vec![AclConfig {
                acltype: "publishClientReceive".to_string(),
                topic: "fanout/base".to_string(),
                priority: Some(0),
                allow: Some(true),
            }],
        },
        PersistMutation::RoleAcl(RoleAclMutation::Add {
            rolename: "fanout_reader".to_string(),
            acltype: "subscribeLiteral".to_string(),
            topic: "fanout/extra".to_string(),
            priority: 4,
            allow: true,
        }),
        PersistMutation::DeleteRole {
            rolename: "fanout_reader".to_string(),
        },
    ]);

    assert!(matches!(
        collapsed.as_slice(),
        [PersistMutation::DeleteRole { rolename }] if rolename == "fanout_reader"
    ));
}

#[test]
fn apply_control_payload_recreate_group_after_failed_delete_cleans_stale_memberships() {
    let path = write_test_dynsec_client_side_group_notify_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let original = replace_dynsec_file_with_directory(&path);

    let first_targets = policy
        .apply_control_payload(br#"{"commands":[{"command":"deleteGroup","groupname":"fanout"}]}"#)
        .expect("persist failure should still apply runtime mutations");
    assert!(first_targets.persist_warning.is_some());
    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("runtime state should reflect deleted group")
    );

    restore_dynsec_file(&path, &original);
    remove_group_definition_from_dynsec_file(&path, "fanout");

    let repair_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"createGroup","groupname":"fanout","roles":[{"rolename":"fanout_reader","priority":0}]}]}"#,
            )
            .expect("recreate payload should converge pending persistence");
    assert!(repair_targets.persist_warning.is_none());
    assert!(
        policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed")
            .is_empty()
    );

    let raw = fs::read_to_string(&path).expect("dynsec config should be readable");
    let root: Value = serde_json::from_str(&raw).expect("dynsec config should parse");
    let client = root["clients"]
        .as_array()
        .and_then(|clients| {
            clients
                .iter()
                .find(|entry| entry["username"].as_str() == Some("test_user"))
        })
        .expect("test_user client should exist");
    let groups = client["groups"]
        .as_array()
        .expect("client groups should be an array");
    assert!(
        groups
            .iter()
            .all(|group| group["groupname"].as_str() != Some("fanout"))
    );

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        !reloaded
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("reload should not regain stale membership access")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_recreate_role_after_failed_delete_cleans_stale_bindings() {
    let path = write_test_dynsec_notify_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let original = replace_dynsec_file_with_directory(&path);

    let first_targets = policy
        .apply_control_payload(
            br#"{"commands":[{"command":"deleteRole","rolename":"fanout_reader"}]}"#,
        )
        .expect("persist failure should still apply runtime mutations");
    assert!(first_targets.persist_warning.is_some());
    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("runtime state should reflect deleted role")
    );

    restore_dynsec_file(&path, &original);
    remove_role_definition_from_dynsec_file(&path, "fanout_reader");

    let repair_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"createRole","rolename":"fanout_reader","acls":[{"acltype":"publishClientReceive","topic":"fanout/new","priority":0,"allow":true}]}]}"#,
            )
            .expect("recreate payload should converge pending persistence");
    assert!(repair_targets.persist_warning.is_none());
    assert!(
        policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed")
            .is_empty()
    );

    let raw = fs::read_to_string(&path).expect("dynsec config should be readable");
    let root: Value = serde_json::from_str(&raw).expect("dynsec config should parse");
    let client = root["clients"]
        .as_array()
        .and_then(|clients| {
            clients
                .iter()
                .find(|entry| entry["username"].as_str() == Some("test_user"))
        })
        .expect("test_user client should exist");
    let roles = client["roles"]
        .as_array()
        .expect("client roles should be an array");
    assert!(
        roles
            .iter()
            .all(|role| role["rolename"].as_str() != Some("fanout_reader"))
    );

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        !reloaded
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/new",
                ACL_READ
            )
            .expect("reload should not regain stale role access")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_delete_group_clears_superseded_pending_add_group_client() {
    let path = write_test_dynsec_client_side_group_notify_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let original = replace_dynsec_file_with_directory(&path);

    let first_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"addGroupClient","groupname":"fanout","username":"ghost","priority":5}]}"#,
            )
            .expect("persist failure should still apply runtime mutations");
    assert!(first_targets.persist_warning.is_some());

    restore_dynsec_file(&path, &original);

    let delete_targets = policy
        .apply_control_payload(br#"{"commands":[{"command":"deleteGroup","groupname":"fanout"}]}"#)
        .expect("delete payload should converge pending persistence");
    assert!(delete_targets.persist_warning.is_none());
    assert!(
        policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed")
            .is_empty()
    );

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        !reloaded
            .check(
                Some("ghost"),
                Some("ghost_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed after durable delete")
    );

    let _ = fs::remove_file(path);
}

#[cfg(unix)]
#[test]
fn apply_control_payload_create_group_repair_stays_pending_after_write_failure() {
    let path = write_test_dynsec_client_side_group_notify_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let original = replace_dynsec_file_with_directory(&path);

    let first_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"addGroupClient","groupname":"fanout","username":"ghost","priority":5}]}"#,
            )
            .expect("persist failure should still apply runtime mutations");
    assert!(first_targets.persist_warning.is_some());

    restore_dynsec_file(&path, &original);
    remove_group_from_dynsec_file(&path, "fanout");

    let original_mode = set_dynsec_file_mode(&path, 0o444);
    let repair_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"createGroup","groupname":"fanout","roles":[{"rolename":"fanout_reader","priority":0}]}]}"#,
            )
            .expect("repair payload should keep runtime changes on write failure");
    let _ = set_dynsec_file_mode(&path, original_mode);

    assert!(
        repair_targets
            .persist_warning
            .as_deref()
            .is_some_and(|warning| warning.contains("dynsec config write failed"))
    );
    let pending = policy
        .pending_persist_mutations
        .lock()
        .expect("pending persist lock should succeed")
        .clone();
    assert_eq!(pending.len(), 2);
    assert!(matches!(
        pending.as_slice(),
        [
            PersistMutation::CreateGroup { groupname, .. },
            PersistMutation::AddGroupClient {
                groupname: add_group,
                username,
                priority
            }
        ] if groupname == "fanout"
            && add_group == "fanout"
            && username == "ghost"
            && *priority == 5
    ));

    let retry_targets = policy
        .apply_control_payload(br#"{"commands":[{"command":"listRoles"}]}"#)
        .expect("later control command should retry pending persistence");
    assert!(retry_targets.persist_warning.is_none());
    assert!(
        policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed")
            .is_empty()
    );

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        reloaded
            .check(
                Some("ghost"),
                Some("ghost_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed after durable retry")
    );

    let _ = fs::remove_file(path);
}

#[cfg(unix)]
#[test]
fn apply_control_payload_create_role_repair_stays_pending_after_write_failure() {
    let path = write_test_dynsec_notify_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let original = replace_dynsec_file_with_directory(&path);

    let first_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"addRoleACL","rolename":"fanout_reader","acltype":"subscribeLiteral","topic":"fanout/broadcast","priority":0,"allow":true}]}"#,
            )
            .expect("persist failure should still apply runtime mutations");
    assert!(first_targets.persist_warning.is_some());

    restore_dynsec_file(&path, &original);
    remove_role_definition_from_dynsec_file(&path, "fanout_reader");

    let original_mode = set_dynsec_file_mode(&path, 0o444);
    let repair_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"createRole","rolename":"fanout_reader","acls":[{"acltype":"publishClientReceive","topic":"fanout/broadcast","priority":0,"allow":true}]}]}"#,
            )
            .expect("repair payload should keep runtime changes on write failure");
    let _ = set_dynsec_file_mode(&path, original_mode);

    assert!(
        repair_targets
            .persist_warning
            .as_deref()
            .is_some_and(|warning| warning.contains("dynsec config write failed"))
    );
    let pending = policy
        .pending_persist_mutations
        .lock()
        .expect("pending persist lock should succeed")
        .clone();
    assert_eq!(pending.len(), 2);
    assert!(matches!(
        pending.as_slice(),
        [
            PersistMutation::CreateRole { rolename, .. },
            PersistMutation::RoleAcl(RoleAclMutation::Add {
                rolename: acl_role,
                acltype,
                topic,
                priority,
                allow
            })
        ] if rolename == "fanout_reader"
            && acl_role == "fanout_reader"
            && acltype == "subscribeLiteral"
            && topic == "fanout/broadcast"
            && *priority == 0
            && *allow
    ));

    let retry_targets = policy
        .apply_control_payload(br#"{"commands":[{"command":"listRoles"}]}"#)
        .expect("later control command should retry pending persistence");
    assert!(retry_targets.persist_warning.is_none());
    assert!(
        policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed")
            .is_empty()
    );

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        reloaded
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_SUBSCRIBE
            )
            .expect("policy check should succeed after durable retry")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_duplicate_create_role_does_not_persist_new_acls() {
    let path = write_test_dynsec_notify_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let raw_before = fs::read_to_string(&path).expect("test dynsec config should be readable");

    let targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"createRole","rolename":"fanout_reader","acls":[{"acltype":"subscribeLiteral","topic":"fanout/broadcast","priority":0,"allow":true}]}]}"#,
            )
            .expect("duplicate createRole should be a no-op");
    assert!(targets.persist_warning.is_none());
    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_SUBSCRIBE
            )
            .expect("duplicate createRole must not change live auth")
    );

    let raw_after = fs::read_to_string(&path).expect("test dynsec config should be readable");
    assert_eq!(raw_before, raw_after);

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        !reloaded
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_SUBSCRIBE
            )
            .expect("duplicate createRole must not change durable auth")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_duplicate_create_group_does_not_persist_new_roles() {
    let path = write_test_dynsec_client_side_group_notify_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let raw_before = fs::read_to_string(&path).expect("test dynsec config should be readable");

    let targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"createGroup","groupname":"fanout","roles":[{"rolename":"backup_reader","priority":5}]}]}"#,
            )
            .expect("duplicate createGroup should be a no-op");
    assert!(targets.persist_warning.is_none());

    let raw_after = fs::read_to_string(&path).expect("test dynsec config should be readable");
    assert_eq!(raw_before, raw_after);

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        reloaded
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("duplicate createGroup must preserve durable auth")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_retries_schema_invalid_pending_mutations_after_repair() {
    let path = write_test_dynsec_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let original = fs::read_to_string(&path).expect("test dynsec config should be readable");
    set_top_level_field_to_object(&path, "groups");

    let first_targets = policy
        .apply_control_payload(group_grant_payload())
        .expect("schema-invalid persist should still apply runtime mutations");
    assert!(first_targets.persist_warning.is_some());

    restore_dynsec_file(&path, &original);
    let retry_targets = policy
        .apply_control_payload(group_grant_payload())
        .expect("later control command should retry pending persistence");
    assert!(retry_targets.persist_warning.is_none());
    assert!(
        policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed")
            .is_empty()
    );

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        reloaded
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn check_preserves_cached_state_across_read_reload_failures() {
    let path = write_test_dynsec_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let original = replace_dynsec_file_with_directory(&path);

    {
        let mut last_loaded = policy
            .last_loaded
            .lock()
            .expect("reload lock should succeed");
        *last_loaded = Some(Instant::now() - Duration::from_secs(120));
    }

    let last_loaded_before_failure = policy
        .last_loaded
        .lock()
        .expect("reload lock should succeed")
        .expect("last_loaded should be set before reload failure");
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("policy check should keep cached state on read failure")
    );
    let last_loaded_after_failure = policy
        .last_loaded
        .lock()
        .expect("reload lock should succeed")
        .expect("last_loaded should stay populated after fallback");
    assert_eq!(last_loaded_after_failure, last_loaded_before_failure);

    restore_dynsec_file(&path, &original);
    set_client_disabled(&path, "test_user", true);
    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("repaired file should be retried on the next check")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn new_fails_when_dynsec_file_is_missing() {
    let unique = DYNSEC_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir()
        .join(format!("dynsec-missing-startup-{unique}.json"))
        .to_string_lossy()
        .into_owned();

    let err = DynamicSecurityPolicy::new(path, Duration::from_secs(60))
        .expect_err("missing dynsec file must fail startup");
    assert!(err.contains("dynsec config read failed"));
}

#[test]
fn new_fails_when_dynsec_file_is_malformed() {
    let path = write_test_dynsec_config();
    write_invalid_json(&path);

    let err = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect_err("malformed dynsec file must fail startup");
    assert!(err.contains("dynsec config parse failed"));

    let _ = fs::remove_file(path);
}

#[test]
fn forced_reload_falls_back_only_after_a_valid_load_exists() {
    let path = write_test_dynsec_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let last_loaded_before_failure = policy
        .last_loaded
        .lock()
        .expect("reload lock should succeed")
        .expect("last_loaded should be set after initial load");
    let original = replace_dynsec_file_with_directory(&path);

    policy
        .reload_if_needed(true)
        .expect("forced reload should keep cached state after a valid load");
    let last_loaded_after_failure = policy
        .last_loaded
        .lock()
        .expect("reload lock should succeed")
        .expect("last_loaded should stay populated after fallback");
    assert_eq!(last_loaded_after_failure, last_loaded_before_failure);
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("cached state should remain usable after forced fallback")
    );

    restore_dynsec_file(&path, &original);
    let _ = fs::remove_file(path);
}

#[test]
fn forced_reload_uses_fresh_disk_state_when_pending_replay_blocks() {
    let path = write_test_dynsec_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    {
        let mut pending = policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed");
        pending.push(PersistMutation::AddGroupClient {
            groupname: "missing_group".to_string(),
            username: "ghost".to_string(),
            priority: 5,
        });
    }

    set_client_disabled(&path, "test_user", true);
    crate::reset_debug_logs();
    policy
        .reload_if_needed(true)
        .expect("forced reload should absorb fresh disk state even when pending replay blocks");
    let logs = crate::debug_logs_snapshot();
    assert!(logs.iter().any(|entry| {
            entry.contains(
                "Dynsec pending replay skipped blocked mutations during reload: blocked=1 changed=0 already_satisfied=0",
            )
        }));

    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("policy check should succeed")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_uses_fresh_disk_state_when_pending_replay_blocks() {
    let path = write_test_dynsec_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    {
        let mut pending = policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed");
        pending.push(PersistMutation::AddGroupClient {
            groupname: "missing_group".to_string(),
            username: "ghost".to_string(),
            priority: 5,
        });
    }

    set_client_disabled(&path, "test_user", true);
    crate::reset_debug_logs();
    let targets = policy
        .apply_control_payload(br#"{"commands":[{"command":"listRoles"}]}"#)
        .expect("control refresh should still succeed when pending replay blocks");
    let logs = crate::debug_logs_snapshot();
    assert!(logs.iter().any(|entry| {
            entry.contains(
                "Dynsec pending replay skipped blocked mutations during reload: blocked=1 changed=0 already_satisfied=0",
            )
        }));
    assert!(
        targets
            .persist_warning
            .as_deref()
            .is_some_and(|warning| warning.contains("blocked by divergent state"))
    );
    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("policy check should succeed")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn forced_reload_does_not_log_blocked_pending_replay_summary_without_blocked_mutations() {
    let path = write_test_dynsec_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    {
        let mut pending = policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed");
        pending.push(PersistMutation::SetClientDisabled {
            username: "test_user".to_string(),
            disabled: true,
        });
    }

    crate::reset_debug_logs();
    policy
        .reload_if_needed(true)
        .expect("forced reload should replay clean pending mutations without blocked summary");
    let logs = crate::debug_logs_snapshot();
    assert!(logs.iter().all(|entry| {
        !entry.contains("Dynsec pending replay skipped blocked mutations during reload:")
    }));
    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("policy check should succeed")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn forced_reload_applies_later_pending_replayable_mutations_after_earlier_blocked_replay() {
    let path = write_test_dynsec_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    {
        let mut pending = policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed");
        pending.extend([
            PersistMutation::AddGroupClient {
                groupname: "missing_group".to_string(),
                username: "ghost".to_string(),
                priority: 5,
            },
            PersistMutation::SetClientDisabled {
                username: "test_user".to_string(),
                disabled: true,
            },
        ]);
    }

    policy
        .reload_if_needed(true)
        .expect("forced reload should continue replay after a blocked mutation");

    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("policy check should succeed")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn check_preserves_cached_state_across_parse_reload_failures() {
    let path = write_test_dynsec_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let original = fs::read_to_string(&path).expect("test dynsec config should be readable");
    write_invalid_json(&path);

    {
        let mut last_loaded = policy
            .last_loaded
            .lock()
            .expect("reload lock should succeed");
        *last_loaded = Some(Instant::now() - Duration::from_secs(120));
    }

    let last_loaded_before_failure = policy
        .last_loaded
        .lock()
        .expect("reload lock should succeed")
        .expect("last_loaded should be set before reload failure");
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("policy check should keep cached state on parse failure")
    );
    let last_loaded_after_failure = policy
        .last_loaded
        .lock()
        .expect("reload lock should succeed")
        .expect("last_loaded should stay populated after fallback");
    assert_eq!(last_loaded_after_failure, last_loaded_before_failure);

    restore_dynsec_file(&path, &original);
    set_client_disabled(&path, "test_user", true);
    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE
            )
            .expect("repaired file should be retried on the next check")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_valid_noop_persist_clears_pending_mutations() {
    let path = write_test_dynsec_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    policy
        .apply_control_payload(group_grant_payload())
        .expect("initial payload should persist");

    {
        let mut pending = policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed");
        pending.extend([
            PersistMutation::CreateRole {
                rolename: "fanout_reader".to_string(),
                acls: vec![
                    AclConfig {
                        acltype: "subscribeLiteral".to_string(),
                        topic: "fanout/broadcast".to_string(),
                        priority: Some(1),
                        allow: Some(true),
                    },
                    AclConfig {
                        acltype: "publishClientReceive".to_string(),
                        topic: "fanout/broadcast".to_string(),
                        priority: Some(1),
                        allow: Some(true),
                    },
                ],
            },
            PersistMutation::CreateGroup {
                groupname: "fanout".to_string(),
                roles: vec![RoleRef {
                    rolename: "fanout_reader".to_string(),
                    priority: Some(5),
                }],
            },
            PersistMutation::AddGroupClient {
                groupname: "fanout".to_string(),
                username: "test_user".to_string(),
                priority: 7,
            },
        ]);
    }

    let targets = policy
        .apply_control_payload(br#"{"commands":[{"command":"listRoles"}]}"#)
        .expect("noop control payload should still flush pending persistence");
    assert!(targets.persist_warning.is_none());
    assert!(
        policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed")
            .is_empty()
    );

    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_disable_placeholder_client_persists_disabled_state() {
    let path = write_test_dynsec_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");

    policy
        .apply_control_payload(
            br#"{
  "commands": [
    {
      "command": "createRole",
      "rolename": "synthetic_reader",
      "acls": [
        {
          "acltype": "publishClientReceive",
          "topic": "synthetic/broadcast",
          "priority": 1,
          "allow": true
        }
      ]
    },
    {
      "command": "createGroup",
      "groupname": "synthetic",
      "roles": [
        {"rolename": "synthetic_reader", "priority": 1}
      ]
    },
    {
      "command": "addGroupClient",
      "groupname": "synthetic",
      "username": "ghost",
      "priority": 1
    }
  ]
}"#,
        )
        .expect("synthetic grant payload should apply");
    assert!(
        policy
            .check(
                Some("ghost"),
                Some("ghost_client"),
                "synthetic/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    policy
        .apply_control_payload(br#"{"commands":[{"command":"disableClient","username":"ghost"}]}"#)
        .expect("disable payload should apply");
    assert!(
        !policy
            .check(
                Some("ghost"),
                Some("ghost_client"),
                "synthetic/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );
    assert_persisted_disabled_placeholder_client(&path, "ghost");

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        !reloaded
            .check(
                Some("ghost"),
                Some("ghost_client"),
                "synthetic/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn pending_disable_placeholder_survives_remove_group_client_retry() {
    let path = write_test_dynsec_anonymous_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");

    policy
        .apply_control_payload(anonymous_placeholder_group_payload())
        .expect("create payload should apply");
    let original = fs::read_to_string(&path).expect("test dynsec config should be readable");
    replace_dynsec_file_with_directory(&path);

    let disable_targets = policy
        .apply_control_payload(br#"{"commands":[{"command":"disableClient","username":"ghost"}]}"#)
        .expect("disable payload should apply despite persist failure");
    assert!(disable_targets.persist_warning.is_some());
    assert!(
        !policy
            .check(
                Some("ghost"),
                Some("ghost_client"),
                "private/announce",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    restore_dynsec_file(&path, &original);
    let retry_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"removeGroupClient","groupname":"private","username":"ghost"}]}"#,
            )
            .expect("remove payload should durably preserve disabled placeholder");
    assert!(retry_targets.persist_warning.is_none());
    assert!(
        policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed")
            .is_empty()
    );
    assert_persisted_disabled_placeholder_client(&path, "ghost");

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        !reloaded
            .check(
                Some("ghost"),
                Some("ghost_client"),
                "private/announce",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn pending_disable_placeholder_survives_delete_group_retry() {
    let path = write_test_dynsec_anonymous_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");

    policy
        .apply_control_payload(anonymous_placeholder_group_payload())
        .expect("create payload should apply");
    let original = fs::read_to_string(&path).expect("test dynsec config should be readable");
    replace_dynsec_file_with_directory(&path);

    let disable_targets = policy
        .apply_control_payload(br#"{"commands":[{"command":"disableClient","username":"ghost"}]}"#)
        .expect("disable payload should apply despite persist failure");
    assert!(disable_targets.persist_warning.is_some());

    restore_dynsec_file(&path, &original);
    let retry_targets = policy
        .apply_control_payload(br#"{"commands":[{"command":"deleteGroup","groupname":"private"}]}"#)
        .expect("delete payload should durably preserve disabled placeholder");
    assert!(retry_targets.persist_warning.is_none());
    assert!(
        policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed")
            .is_empty()
    );
    assert_persisted_disabled_placeholder_client(&path, "ghost");

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        !reloaded
            .check(
                Some("ghost"),
                Some("ghost_client"),
                "private/announce",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn remove_group_client_prunes_persisted_placeholder_and_restores_anonymous_fallback_after_reload() {
    let path = write_test_dynsec_anonymous_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");

    policy
        .apply_control_payload(anonymous_placeholder_group_payload())
        .expect("create payload should apply");
    policy
        .apply_control_payload(br#"{"commands":[{"command":"disableClient","username":"ghost"}]}"#)
        .expect("disable payload should apply");
    policy
        .apply_control_payload(br#"{"commands":[{"command":"enableClient","username":"ghost"}]}"#)
        .expect("enable payload should apply");
    policy
            .apply_control_payload(
                br#"{"commands":[{"command":"removeGroupClient","groupname":"private","username":"ghost"}]}"#,
            )
            .expect("remove payload should apply");

    let raw = fs::read_to_string(&path).expect("dynsec config should be readable");
    let root: Value = serde_json::from_str(&raw).expect("dynsec config should parse");
    let clients = root["clients"]
        .as_array()
        .expect("clients should be an array");
    assert!(
        clients
            .iter()
            .all(|client| client["username"].as_str() != Some("ghost"))
    );

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        reloaded
            .check(
                Some("ghost"),
                Some("ghost_client"),
                "public/announce",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn default_docker_dynsec_fixture_keeps_dynsec_client_1_pinned_to_client_1() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docker/dynamic-security.json");
    let raw = fs::read_to_string(&path).expect("docker dynsec fixture should be readable");
    let root: Value = serde_json::from_str(&raw).expect("docker dynsec fixture should parse");
    let clients = root["clients"]
        .as_array()
        .expect("clients should be an array");
    let dynsec_client = clients
        .iter()
        .find(|client| client["username"].as_str() == Some("dynsec_client_1"))
        .expect("dynsec_client_1 should exist in the default docker fixture");
    assert_eq!(dynsec_client["clientid"].as_str(), Some("client_1"));
}

#[test]
fn delete_group_prunes_persisted_placeholder_and_restores_anonymous_fallback_after_reload() {
    let path = write_test_dynsec_anonymous_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");

    policy
        .apply_control_payload(anonymous_placeholder_group_payload())
        .expect("create payload should apply");
    policy
        .apply_control_payload(br#"{"commands":[{"command":"disableClient","username":"ghost"}]}"#)
        .expect("disable payload should apply");
    policy
        .apply_control_payload(br#"{"commands":[{"command":"enableClient","username":"ghost"}]}"#)
        .expect("enable payload should apply");
    policy
        .apply_control_payload(br#"{"commands":[{"command":"deleteGroup","groupname":"private"}]}"#)
        .expect("delete payload should apply");

    let raw = fs::read_to_string(&path).expect("dynsec config should be readable");
    let root: Value = serde_json::from_str(&raw).expect("dynsec config should parse");
    let clients = root["clients"]
        .as_array()
        .expect("clients should be an array");
    assert!(
        clients
            .iter()
            .all(|client| client["username"].as_str() != Some("ghost"))
    );

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        reloaded
            .check(
                Some("ghost"),
                Some("ghost_client"),
                "public/announce",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn pending_delete_anonymous_group_clears_anonymous_binding_on_reload() {
    let path = write_test_dynsec_anonymous_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let original = replace_dynsec_file_with_directory(&path);

    let targets = policy
        .apply_control_payload(
            br#"{"commands":[{"command":"deleteGroup","groupname":"anonymous"}]}"#,
        )
        .expect("persist failure should still apply runtime mutations");
    assert!(targets.persist_warning.is_some());
    assert!(
        !policy
            .check(None, None, "public/announce", ACL_READ)
            .expect("anonymous policy check should succeed")
    );

    restore_dynsec_file(&path, &original);
    policy
        .reload_if_needed(true)
        .expect("forced reload should replay pending anonymous delete");

    let state = policy
        .state
        .read()
        .expect("dynsec state lock should succeed");
    assert!(!state.groups.contains_key("anonymous"));
    assert_eq!(state.anonymous_group, None);
    drop(state);

    assert!(
        !policy
            .check(None, None, "public/announce", ACL_READ)
            .expect("anonymous policy check should succeed")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn pending_create_mutations_merge_into_stub_objects_on_reload_and_retry() {
    let path = write_test_dynsec_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    let original = replace_dynsec_file_with_directory(&path);

    let first_targets = policy
        .apply_control_payload(group_grant_payload())
        .expect("persist failure should still apply runtime mutations");
    assert!(first_targets.persist_warning.is_some());

    restore_dynsec_file(&path, &original);
    set_stub_group_grant(&path, "fanout", "fanout_reader");

    policy
        .reload_if_needed(true)
        .expect("forced reload should merge pending create payloads into stub objects");
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    let state = policy
        .state
        .read()
        .expect("dynsec state lock should succeed");
    let role = state
        .roles
        .get("fanout_reader")
        .expect("fanout_reader role should exist");
    assert_eq!(
        role.match_acl(AccessKind::PublishReceive, "fanout/broadcast"),
        Some(true)
    );
    let group = state
        .groups
        .get("fanout")
        .expect("fanout group should exist");
    assert!(group.roles.iter().any(|role| role.name == "fanout_reader"));
    drop(state);

    let retry_targets = policy
        .apply_control_payload(br#"{"commands":[{"command":"listRoles"}]}"#)
        .expect("later control command should retry pending persistence");
    assert!(retry_targets.persist_warning.is_none());
    assert!(
        policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed")
            .is_empty()
    );

    let raw = fs::read_to_string(&path).expect("dynsec config should be readable");
    let root: Value = serde_json::from_str(&raw).expect("dynsec config should parse");
    let role = root["roles"]
        .as_array()
        .and_then(|roles| {
            roles
                .iter()
                .find(|role| role["rolename"].as_str() == Some("fanout_reader"))
        })
        .expect("fanout_reader role should be persisted");
    let role_acls = role["acls"]
        .as_array()
        .expect("role acls should be an array");
    assert!(role_acls.iter().any(|acl| {
        acl["acltype"].as_str() == Some("publishClientReceive")
            && acl["topic"].as_str() == Some("fanout/broadcast")
            && acl["allow"].as_bool() == Some(true)
    }));
    let group = root["groups"]
        .as_array()
        .and_then(|groups| {
            groups
                .iter()
                .find(|group| group["groupname"].as_str() == Some("fanout"))
        })
        .expect("fanout group should be persisted");
    let group_roles = group["roles"]
        .as_array()
        .expect("group roles should be an array");
    assert!(group_roles.iter().any(|role| {
        role["rolename"].as_str() == Some("fanout_reader") && role["priority"].as_i64() == Some(5)
    }));

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        reloaded
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn from_config_keeps_highest_priority_for_duplicate_group_memberships() {
    let path = write_test_dynsec_conflicting_membership_priority_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");

    let state = policy
        .state
        .read()
        .expect("dynsec state lock should succeed");
    let membership = state
        .clients
        .get("test_user")
        .and_then(|client| client.groups.iter().find(|group| group.name == "high_deny"))
        .expect("client should keep duplicated high_deny membership");
    assert_eq!(membership.priority, 10);
    drop(state);

    policy
        .reload_if_needed(true)
        .expect("forced reload should preserve max-priority merge semantics");
    let reloaded_state = policy
        .state
        .read()
        .expect("dynsec state lock should succeed");
    let reloaded_membership = reloaded_state
        .clients
        .get("test_user")
        .and_then(|client| client.groups.iter().find(|group| group.name == "high_deny"))
        .expect("client should keep duplicated high_deny membership after reload");
    assert_eq!(reloaded_membership.priority, 10);

    let _ = fs::remove_file(path);
}

#[test]
fn reload_keeps_acl_changes_for_pending_created_roles() {
    let path = write_test_dynsec_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    {
        let mut pending = policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed");
        pending.extend([
            PersistMutation::CreateRole {
                rolename: "ephemeral_reader".to_string(),
                acls: Vec::new(),
            },
            PersistMutation::CreateGroup {
                groupname: "ephemeral".to_string(),
                roles: vec![RoleRef {
                    rolename: "ephemeral_reader".to_string(),
                    priority: Some(5),
                }],
            },
            PersistMutation::AddGroupClient {
                groupname: "ephemeral".to_string(),
                username: "test_user".to_string(),
                priority: 7,
            },
        ]);
    }
    {
        let mut overrides = policy
            .runtime_role_acl_overrides
            .lock()
            .expect("runtime role-acl lock should succeed");
        overrides.insert(
            RoleAclKey::new(
                "ephemeral_reader",
                AclType::PublishClientReceive,
                "ephemeral/broadcast",
            ),
            RuntimeRoleAclOverride::Add {
                priority: 1,
                allow: true,
            },
        );
    }

    policy
        .reload_if_needed(true)
        .expect("forced reload should preserve ACL changes on pending-created roles");
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "ephemeral/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
        .expect("reloaded policy must load");
    assert!(
        !reloaded
            .check(
                Some("test_user"),
                Some("test_client"),
                "ephemeral/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );
    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_delete_group_uses_current_file_state_within_reload_interval() {
    let path = write_test_dynsec_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    add_external_group_grant(
        &path,
        "external_fanout",
        "external_reader",
        "external/broadcast",
    );

    let targets = policy
        .apply_control_payload(
            br#"{"commands":[{"command":"deleteGroup","groupname":"external_fanout"}]}"#,
        )
        .expect("delete payload should apply");

    assert!(targets.kick_client_ids.is_empty());
    assert!(targets.kick_usernames.is_empty());
    assert_eq!(targets.notify_events.len(), 1);
    assert_eq!(targets.notify_events[0].command, "deleteGroup");
    assert_eq!(
        targets.notify_events[0].usernames,
        vec!["test_user".to_string()]
    );
    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "external/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    let raw = fs::read_to_string(&path).expect("dynsec config should be readable");
    let root: Value = serde_json::from_str(&raw).expect("dynsec config should parse");
    let groups = root["groups"]
        .as_array()
        .expect("groups should be an array");
    assert!(
        groups
            .iter()
            .all(|group| group["groupname"].as_str() != Some("external_fanout"))
    );
    let clients = root["clients"]
        .as_array()
        .expect("clients should be an array");
    let client = clients
        .iter()
        .find(|entry| entry["username"].as_str() == Some("test_user"))
        .expect("test_user client should exist");
    let memberships = client["groups"]
        .as_array()
        .expect("client groups should be an array");
    assert!(
        memberships
            .iter()
            .all(|entry| entry["groupname"].as_str() != Some("external_fanout"))
    );

    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_create_group_uses_current_file_state_within_reload_interval() {
    let path = write_test_dynsec_config();
    let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
        .expect("policy must load");
    add_external_group_grant(
        &path,
        "external_fanout",
        "external_reader",
        "external/broadcast",
    );

    let targets = policy
        .apply_control_payload(
            br#"{"commands":[{"command":"createGroup","groupname":"external_fanout","roles":[]}]}"#,
        )
        .expect("create payload should apply");

    assert!(targets.kick_client_ids.is_empty());
    assert!(targets.kick_usernames.is_empty());
    assert!(targets.notify_events.is_empty());
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "external/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );

    let state = policy
        .state
        .read()
        .expect("dynsec state lock should succeed");
    let group = state
        .groups
        .get("external_fanout")
        .expect("external_fanout group should exist");
    assert_eq!(group.roles.len(), 1);
    assert_eq!(group.roles[0].name, "external_reader");
    drop(state);

    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_delete_group_notifies_client_side_only_members() {
    let path = write_test_dynsec_client_side_group_notify_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");

    let targets = policy
        .apply_control_payload(br#"{"commands":[{"command":"deleteGroup","groupname":"fanout"}]}"#)
        .expect("delete payload should apply");

    assert!(targets.kick_client_ids.is_empty());
    assert!(targets.kick_usernames.is_empty());
    assert_eq!(targets.notify_events.len(), 1);
    let event = &targets.notify_events[0];
    assert_eq!(event.command, "deleteGroup");
    assert_eq!(event.rolename.as_deref(), Some("fanout_reader"));
    assert_eq!(event.acltype.as_deref(), Some("publishClientReceive"));
    assert_eq!(event.topic.as_deref(), Some("fanout/broadcast"));
    assert_eq!(event.usernames, vec!["test_user".to_string()]);

    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_remove_role_acl_emits_notify_event() {
    let path = write_test_dynsec_notify_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");

    let payload = br#"{"commands":[{"command":"removeRoleACL","rolename":"fanout_reader","acltype":"publishClientReceive","topic":"fanout/broadcast"}]}"#;
    let targets = policy
        .apply_control_payload(payload)
        .expect("control payload should apply");

    assert!(targets.kick_client_ids.is_empty());
    assert!(targets.kick_usernames.is_empty());
    assert_eq!(targets.notify_events.len(), 1);
    let event = &targets.notify_events[0];
    assert_eq!(event.command, "removeRoleACL");
    assert_eq!(event.rolename.as_deref(), Some("fanout_reader"));
    assert_eq!(event.acltype.as_deref(), Some("publishClientReceive"));
    assert_eq!(event.topic.as_deref(), Some("fanout/broadcast"));
    assert_eq!(event.usernames, vec!["test_user".to_string()]);

    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );
    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_add_deny_role_acl_emits_notify_event() {
    let path = write_test_dynsec_notify_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");

    let payload = br#"{"commands":[{"command":"addRoleACL","rolename":"fanout_reader","acltype":"publishClientReceive","topic":"fanout/broadcast","priority":10,"allow":false}]}"#;
    let targets = policy
        .apply_control_payload(payload)
        .expect("control payload should apply");

    assert!(targets.kick_client_ids.is_empty());
    assert!(targets.kick_usernames.is_empty());
    assert_eq!(targets.notify_events.len(), 1);
    let event = &targets.notify_events[0];
    assert_eq!(event.command, "addRoleACL");
    assert_eq!(event.usernames, vec!["test_user".to_string()]);

    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );
    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_delete_role_skips_notify_when_access_remains_allowed() {
    let path = write_test_dynsec_overlap_notify_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");

    let targets = policy
        .apply_control_payload(
            br#"{"commands":[{"command":"deleteRole","rolename":"fanout_reader"}]}"#,
        )
        .expect("delete payload should apply");

    assert!(targets.notify_events.is_empty());
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );
    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_delete_group_skips_notify_when_access_remains_allowed() {
    let path = write_test_dynsec_overlap_notify_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");

    let targets = policy
        .apply_control_payload(br#"{"commands":[{"command":"deleteGroup","groupname":"fanout"}]}"#)
        .expect("delete payload should apply");

    assert!(targets.notify_events.is_empty());
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );
    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_remove_group_client_skips_notify_when_access_remains_allowed() {
    let path = write_test_dynsec_overlap_notify_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");

    let targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"removeGroupClient","groupname":"fanout","username":"test_user"}]}"#,
            )
            .expect("remove payload should apply");

    assert!(targets.notify_events.is_empty());
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );
    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_remove_role_acl_skips_notify_when_access_remains_allowed() {
    let path = write_test_dynsec_overlap_notify_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");

    let targets = policy
            .apply_control_payload(br#"{"commands":[{"command":"removeRoleACL","rolename":"fanout_reader","acltype":"publishClientReceive","topic":"fanout/broadcast"}]}"#)
            .expect("control payload should apply");

    assert!(targets.notify_events.is_empty());
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );
    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_add_deny_role_acl_skips_notify_when_access_remains_allowed() {
    let path = write_test_dynsec_overlap_notify_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");

    let targets = policy
            .apply_control_payload(br#"{"commands":[{"command":"addRoleACL","rolename":"fanout_reader","acltype":"publishClientReceive","topic":"fanout/broadcast","priority":10,"allow":false}]}"#)
            .expect("control payload should apply");

    assert!(targets.notify_events.is_empty());
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );
    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_group_churn_same_payload_skips_notify_when_access_never_changes() {
    let path = write_test_dynsec_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");

    let payload = br#"{"commands":[
            {"command":"createRole","rolename":"fanout_reader","acls":[{"acltype":"publishClientReceive","topic":"fanout/broadcast","priority":0,"allow":true}]},
            {"command":"createGroup","groupname":"fanout","roles":[{"rolename":"fanout_reader","priority":0}]},
            {"command":"addGroupClient","groupname":"fanout","username":"test_user","priority":0},
            {"command":"removeGroupClient","groupname":"fanout","username":"test_user"},
            {"command":"deleteGroup","groupname":"fanout"},
            {"command":"deleteRole","rolename":"fanout_reader"}
        ]}"#;
    let targets = policy
        .apply_control_payload(payload)
        .expect("control payload should apply");

    assert!(targets.notify_events.is_empty());
    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );
    let _ = fs::remove_file(path);
}

#[test]
fn apply_control_payload_remove_role_acl_then_restore_same_payload_skips_notify() {
    let path = write_test_dynsec_notify_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");

    let payload = br#"{"commands":[
            {"command":"removeRoleACL","rolename":"fanout_reader","acltype":"publishClientReceive","topic":"fanout/broadcast"},
            {"command":"addRoleACL","rolename":"fanout_reader","acltype":"publishClientReceive","topic":"fanout/broadcast","priority":0,"allow":true}
        ]}"#;
    let targets = policy
        .apply_control_payload(payload)
        .expect("control payload should apply");

    assert!(targets.notify_events.is_empty());
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );
    let _ = fs::remove_file(path);
}

#[test]
fn remove_role_acl_overlay_survives_stale_file_reload() {
    let path = write_test_dynsec_notify_config();
    let policy =
        DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0)).expect("policy must load");

    let payload = br#"{"commands":[{"command":"removeRoleACL","rolename":"fanout_reader","acltype":"publishClientReceive","topic":"fanout/broadcast"}]}"#;
    policy
        .apply_control_payload(payload)
        .expect("control payload should apply");

    // Simulate stale file state that still contains the removed ACL.
    restore_fanout_reader_publish_receive_acl(&path);

    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                ACL_READ
            )
            .expect("policy check should succeed")
    );
    let _ = fs::remove_file(path);
}
