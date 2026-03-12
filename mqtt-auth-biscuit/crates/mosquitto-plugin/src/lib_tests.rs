use super::*;
use crate::config::BiscuitAuthorizerProfile;
use crate::jwt_handler::Claims;
use biscuit_auth::{Biscuit, KeyPair, PrivateKey};
use std::ffi::CString;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static TEST_DYNSEC_COUNTER: AtomicU64 = AtomicU64::new(0);

fn root_keypair() -> KeyPair {
    let root_bytes = [1u8; 32];
    KeyPair::from(&PrivateKey::from_bytes(&root_bytes, biscuit_auth::Algorithm::Ed25519).unwrap())
}

fn setup_plugin_with_config() -> (*mut c_void, MosquittoPluginId) {
    let jwt_pub_pem = format!("{}/../../docker/jwt_public.pem", env!("CARGO_MANIFEST_DIR"));
    let biscuit_root_key_file = format!(
        "{}/../../docker/biscuit_public.key",
        env!("CARGO_MANIFEST_DIR")
    );

    let cstrings: Vec<CString> = vec![
        CString::new("jwt_alg").unwrap(),
        CString::new("ES256").unwrap(),
        CString::new("jwt_key_file").unwrap(),
        CString::new(jwt_pub_pem).unwrap(),
        CString::new("biscuit_root_key_file").unwrap(),
        CString::new(biscuit_root_key_file).unwrap(),
    ];

    let mut opts = vec![
        MosquittoOpt {
            key: cstrings[0].as_ptr().cast_mut(),
            value: cstrings[1].as_ptr().cast_mut(),
        },
        MosquittoOpt {
            key: cstrings[2].as_ptr().cast_mut(),
            value: cstrings[3].as_ptr().cast_mut(),
        },
        MosquittoOpt {
            key: cstrings[4].as_ptr().cast_mut(),
            value: cstrings[5].as_ptr().cast_mut(),
        },
    ];

    let mut userdata: *mut c_void = ptr::null_mut();
    let userdata_ptr: *mut *mut c_void = &raw mut userdata;
    let mut identifier = MosquittoPluginId { _unused: [] };

    let rc = unsafe {
        mosquitto_plugin_init(
            &raw mut identifier,
            userdata_ptr,
            opts.as_mut_ptr(),
            c_int::try_from(opts.len()).expect("opts len fits c_int"),
        )
    };
    assert_eq!(rc, MOSQ_ERR_SUCCESS);
    assert!(!userdata.is_null());

    (userdata, identifier)
}

fn teardown_plugin(userdata: *mut c_void) {
    let rc = unsafe { mosquitto_plugin_cleanup(userdata, ptr::null_mut(), 0) };
    assert_eq!(rc, MOSQ_ERR_SUCCESS);
}

fn set_acl_read_full_authz(userdata: *mut c_void, enabled: bool) {
    let state = unsafe { plugin_state_mut(userdata) };
    state.config.acl_read_full_authz = enabled;
}

fn enable_dynamic_security_anonymous_mode(userdata: *mut c_void) {
    let state = unsafe { plugin_state_mut(userdata) };
    let dynsec_path = format!(
        "{}/../../docker/dynamic-security-anon.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let policy = DynamicSecurityPolicy::new(dynsec_path.clone(), Duration::from_secs(1))
        .expect("dynamic security anon policy should load for tests");
    state.config.policy.mode = PolicyMode::DynamicSecurity;
    state.config.policy.dynamic_security_url = Some(dynsec_path);
    state.config.allow_anonymous_no_token = true;
    state.dynamic_security_policy = Some(policy);
}

fn unique_test_prefix() -> String {
    let pid = std::process::id();
    let thread_id = format!("{:?}", std::thread::current().id());
    format!("{pid}-{thread_id}")
}

fn enable_dynamic_security_control_mode_with_client_id(
    userdata: *mut c_void,
    include_client_id: bool,
) -> String {
    let unique = TEST_DYNSEC_COUNTER.fetch_add(1, Ordering::Relaxed);
    let prefix = unique_test_prefix();
    let dynsec_path =
        std::env::temp_dir().join(format!("dynsec-control-lib-{}-{}.json", prefix, unique));
    let client_id_line = if include_client_id {
        "\"clientid\": \"test_client\","
    } else {
        ""
    };
    let dynsec_cfg = format!(
        r#"{{
  "clients": [
    {{
      "username": "test_user",
      {client_id_line}
      "roles": [{{"rolename": "controller", "priority": 0}}],
      "disabled": false
    }}
  ],
  "groups": [],
  "roles": [
    {{
      "rolename": "controller",
      "acls": [
        {{
          "acltype": "publishClientSend",
          "topic": "$CONTROL/dynamic-security/v1",
          "priority": 0,
          "allow": true
        }}
      ]
    }}
  ],
  "defaultACLAccess": {{
    "publishClientSend": false,
    "publishClientReceive": false,
    "subscribe": false,
    "unsubscribe": false
  }}
}}"#
    );
    fs::write(&dynsec_path, dynsec_cfg).expect("dynsec test control config must be writable");
    let state = unsafe { plugin_state_mut(userdata) };
    let policy = DynamicSecurityPolicy::new(
        dynsec_path.to_string_lossy().into_owned(),
        Duration::from_secs(60),
    )
    .expect("dynamic security control policy should load for tests");
    state.config.policy.mode = PolicyMode::DynamicSecurity;
    state.config.policy.dynamic_security_url = Some(dynsec_path.to_string_lossy().into_owned());
    state.dynamic_security_policy = Some(policy);
    dynsec_path.to_string_lossy().into_owned()
}

fn enable_dynamic_security_control_mode(userdata: *mut c_void) -> String {
    enable_dynamic_security_control_mode_with_client_id(userdata, true)
}

fn enable_dynamic_security_control_notify_mode(userdata: *mut c_void) -> String {
    let unique = TEST_DYNSEC_COUNTER.fetch_add(1, Ordering::Relaxed);
    let prefix = unique_test_prefix();
    let dynsec_path =
        std::env::temp_dir().join(format!("dynsec-control-notify-lib-{prefix}-{unique}.json"));
    let dynsec_cfg = r#"{
  "clients": [
    {
      "username": "test_user",
      "clientid": "test_client",
      "roles": [
        {"rolename": "controller", "priority": 0},
        {"rolename": "fanout_reader", "priority": 0}
      ],
      "disabled": false
    }
  ],
  "groups": [],
  "roles": [
    {
      "rolename": "controller",
      "acls": [
        {
          "acltype": "publishClientSend",
          "topic": "$CONTROL/dynamic-security/v1",
          "priority": 0,
          "allow": true
        },
        {
          "acltype": "publishClientSend",
          "topic": "fanout/broadcast",
          "priority": 0,
          "allow": true
        }
      ]
    },
    {
      "rolename": "fanout_reader",
      "acls": [
        {
          "acltype": "subscribeLiteral",
          "topic": "fanout/broadcast",
          "priority": 0,
          "allow": true
        },
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
    fs::write(&dynsec_path, dynsec_cfg).expect("dynsec notify config must be writable");
    let state = unsafe { plugin_state_mut(userdata) };
    let policy = DynamicSecurityPolicy::new(
        dynsec_path.to_string_lossy().into_owned(),
        Duration::from_secs(60),
    )
    .expect("dynamic security notify policy should load for tests");
    state.config.policy.mode = PolicyMode::DynamicSecurity;
    state.config.policy.dynamic_security_url = Some(dynsec_path.to_string_lossy().into_owned());
    state.config.control_notify_topic_prefix = "system_notification".to_string();
    state.dynamic_security_policy = Some(policy);
    dynsec_path.to_string_lossy().into_owned()
}

fn replace_dynsec_file_with_directory(path: &str) {
    fs::remove_file(path).expect("dynsec test control config should be removable");
    fs::create_dir(path).expect("dynsec test control config path should become a directory");
}

fn cleanup_dynsec_test_path(path: &str) {
    let dynsec_path = Path::new(path);
    if dynsec_path.is_dir() {
        let _ = fs::remove_dir(dynsec_path);
    } else if dynsec_path.exists() {
        let _ = fs::remove_file(dynsec_path);
    }
}

fn cache_test_jwt_for_client(userdata: *mut c_void, client_id: &str, exp: i64) {
    let state = unsafe { plugin_state_mut(userdata) };
    let token = TokenType::Jwt {
        claims: Claims {
            sub: client_id.to_string(),
            exp,
            iss: None,
            aud: None,
            client_id: None,
            roles: None,
            grants: None,
            denies: None,
        },
        raw: "cached_token".to_string(),
    };
    state
        .cache
        .insert(client_id.to_string(), token, Duration::from_secs(60));
}

fn cache_test_jwt(userdata: *mut c_void, exp: i64) {
    cache_test_jwt_for_client(userdata, "test_client", exp);
}

fn cache_test_biscuit(userdata: *mut c_void, expires_at: Option<i64>) {
    let state = unsafe { plugin_state_mut(userdata) };
    let token = TokenType::Biscuit {
        bytes: vec![1, 2, 3],
        expires_at,
        roles: None,
        biscuit: None,
    };
    state
        .cache
        .insert("test_client".to_string(), token, Duration::from_secs(60));
}

#[test]
fn ffi_init_and_cleanup_are_miri_safe() {
    let (userdata, _identifier) = setup_plugin_with_config();
    teardown_plugin(userdata);
}

#[test]
fn normalize_username_maps_empty_to_none() {
    assert_eq!(normalize_username(None), None);
    assert_eq!(normalize_username(Some(String::new())), None);
    assert_eq!(
        normalize_username(Some("device_a".to_string())),
        Some("device_a".to_string())
    );
}

#[test]
fn no_token_basic_auth_defer_policy_matrix() {
    assert!(!should_defer_no_token_basic_auth(
        PolicyMode::TokenOnly,
        false
    ));
    assert!(!should_defer_no_token_basic_auth(
        PolicyMode::DynamicSecurity,
        false
    ));
    assert!(should_defer_no_token_basic_auth(
        PolicyMode::DynamicSecurity,
        true
    ));
    assert!(should_defer_no_token_basic_auth(
        PolicyMode::StaticAcl,
        false
    ));
    assert!(should_defer_no_token_basic_auth(
        PolicyMode::StaticAclStrict,
        false
    ));
}

#[test]
fn is_acl_read_only_bitmask_matrix() {
    assert!(!is_acl_read_only(0));
    assert!(is_acl_read_only(MOSQ_ACL_READ));
    assert!(!is_acl_read_only(MOSQ_ACL_WRITE));
    assert!(!is_acl_read_only(MOSQ_ACL_SUBSCRIBE));
    assert!(!is_acl_read_only(MOSQ_ACL_CONTROL));
    assert!(!is_acl_read_only(MOSQ_ACL_READ | MOSQ_ACL_WRITE));
    assert!(!is_acl_read_only(MOSQ_ACL_READ | MOSQ_ACL_SUBSCRIBE));
    assert!(!is_acl_read_only(MOSQ_ACL_READ | MOSQ_ACL_CONTROL));
    assert!(!is_acl_read_only(
        MOSQ_ACL_READ | MOSQ_ACL_WRITE | MOSQ_ACL_SUBSCRIBE
    ));
}

#[test]
fn static_acl_bias_warning_logs_for_biscuit_role_right_in_rbac_profile() {
    let keypair = root_keypair();
    let biscuit = Biscuit::builder()
        .fact(r#"role("writer")"#)
        .unwrap()
        .fact(r#"role_right("writer", "publish", "sensors/client_1/#")"#)
        .unwrap()
        .build(&keypair)
        .unwrap();
    let token_type = TokenType::Biscuit {
        bytes: biscuit.to_vec().unwrap(),
        expires_at: None,
        roles: None,
        biscuit: None,
    };

    let (userdata, _identifier) = setup_plugin_with_config();
    let mut config = unsafe { plugin_state(userdata).config.clone() };
    teardown_plugin(userdata);
    config.policy.mode = PolicyMode::StaticAcl;
    config.biscuit_authorizer_profile = BiscuitAuthorizerProfile::Rbac;
    config.biscuit.root_public_key = keypair.public();

    reset_debug_logs();
    log_static_acl_policy_bias(&token_type, &config);
    let logs = debug_logs_snapshot();
    assert!(
        logs.iter()
            .any(|entry| entry.contains("StaticAcl warning: Biscuit token includes grant facts"))
    );
}

#[test]
fn basic_auth_callback_handles_null_pointers() {
    let rc = basic_auth_callback(MOSQ_EVT_BASIC_AUTH, ptr::null_mut(), ptr::null_mut());
    assert_eq!(rc, MOSQ_ERR_INVAL);
}

#[test]
fn basic_auth_callback_handles_null_password() {
    let (userdata, _identifier) = setup_plugin_with_config();

    let mut evt = MosquittoEvtBasicAuth {
        future: ptr::null_mut(),
        client: ptr::null_mut(),
        username: ptr::null_mut(),
        password: ptr::null_mut(),
        extra: MosquittoEvtBasicAuthFuture {
            future2: [ptr::null_mut(); 4],
        },
    };

    let rc = basic_auth_callback(
        MOSQ_EVT_BASIC_AUTH,
        (&raw mut evt).cast::<c_void>(),
        userdata,
    );
    assert_eq!(rc, MOSQ_ERR_AUTH);

    teardown_plugin(userdata);
}

#[test]
fn basic_auth_callback_handles_valid_pointers() {
    let (userdata, _identifier) = setup_plugin_with_config();

    let username = CString::new("test_user").unwrap();
    let password = CString::new("invalid_token").unwrap();
    let mut evt = MosquittoEvtBasicAuth {
        future: ptr::null_mut(),
        client: ptr::null_mut(),
        username: username.as_ptr().cast_mut(),
        password: password.as_ptr().cast_mut(),
        extra: MosquittoEvtBasicAuthFuture {
            password_len: u16::try_from(password.as_bytes().len())
                .expect("password length fits u16"),
        },
    };

    let rc = basic_auth_callback(
        MOSQ_EVT_BASIC_AUTH,
        (&raw mut evt).cast::<c_void>(),
        userdata,
    );
    assert_eq!(rc, MOSQ_ERR_AUTH);

    teardown_plugin(userdata);
}

#[test]
fn basic_auth_callback_accepts_binary_biscuit_password_with_nul_bytes() {
    let (userdata, _identifier) = setup_plugin_with_config();
    let keypair = root_keypair();
    unsafe {
        (*(userdata as *mut PluginState))
            .config
            .biscuit
            .root_public_key = keypair.public();
    }

    let biscuit = Biscuit::builder()
        .fact(r#"right("publish", "sensors/client_1/temp")"#)
        .unwrap()
        .fact(r#"right("subscribe", "sensors/client_1/temp")"#)
        .unwrap()
        .fact("expires_at(2000000000)")
        .unwrap()
        .build(&keypair)
        .unwrap();
    let mut password = biscuit.to_vec().unwrap();
    assert!(
        password.contains(&0),
        "serialized Biscuit should exercise binary password handling"
    );

    let username = CString::new("biscuit").unwrap();
    let mut evt = MosquittoEvtBasicAuth {
        future: ptr::null_mut(),
        client: std::ptr::dangling_mut::<c_void>(),
        username: username.as_ptr().cast_mut(),
        password: password.as_mut_ptr().cast(),
        extra: MosquittoEvtBasicAuthFuture {
            password_len: u16::try_from(password.len()).expect("password length fits u16"),
        },
    };

    let rc = basic_auth_callback(
        MOSQ_EVT_BASIC_AUTH,
        (&raw mut evt).cast::<c_void>(),
        userdata,
    );
    assert_eq!(rc, MOSQ_ERR_SUCCESS);

    teardown_plugin(userdata);
}

#[test]
fn ext_auth_start_callback_handles_null_pointers() {
    let rc = ext_auth_start_callback(MOSQ_EVT_EXT_AUTH_START, ptr::null_mut(), ptr::null_mut());
    assert_eq!(rc, MOSQ_ERR_INVAL);
}

#[test]
fn ext_auth_start_callback_handles_null_data() {
    let (userdata, _identifier) = setup_plugin_with_config();

    let auth_method = CString::new("token").unwrap();
    let mut evt = MosquittoEvtExtendedAuth {
        future: ptr::null_mut(),
        client: ptr::null_mut(),
        data_in: ptr::null(),
        data_out: ptr::null_mut(),
        data_in_len: 0,
        data_out_len: 0,
        auth_method: auth_method.as_ptr().cast::<c_char>(),
        future2: [ptr::null_mut(); 3],
    };

    let rc = ext_auth_start_callback(
        MOSQ_EVT_EXT_AUTH_START,
        (&raw mut evt).cast::<c_void>(),
        userdata,
    );
    assert_eq!(rc, MOSQ_ERR_AUTH);

    teardown_plugin(userdata);
}

#[test]
fn ext_auth_start_callback_handles_valid_pointers() {
    let (userdata, _identifier) = setup_plugin_with_config();

    let auth_method = CString::new("token").unwrap();
    let token_data = b"invalid_token";
    let mut evt = MosquittoEvtExtendedAuth {
        future: ptr::null_mut(),
        client: ptr::null_mut(),
        data_in: token_data.as_ptr().cast::<c_void>(),
        data_out: ptr::null_mut(),
        data_in_len: u16::try_from(token_data.len()).expect("token data length fits u16"),
        data_out_len: 0,
        auth_method: auth_method.as_ptr().cast::<c_char>(),
        future2: [ptr::null_mut(); 3],
    };

    let rc = ext_auth_start_callback(
        MOSQ_EVT_EXT_AUTH_START,
        (&raw mut evt).cast::<c_void>(),
        userdata,
    );
    assert_eq!(rc, MOSQ_ERR_AUTH);

    teardown_plugin(userdata);
}

#[test]
fn ext_auth_continue_callback_handles_null_pointers() {
    let rc =
        ext_auth_continue_callback(MOSQ_EVT_EXT_AUTH_CONTINUE, ptr::null_mut(), ptr::null_mut());
    assert_eq!(rc, MOSQ_ERR_INVAL);
}

#[test]
fn ext_auth_continue_callback_delegates_to_start() {
    let (userdata, _identifier) = setup_plugin_with_config();

    let auth_method = CString::new("token").unwrap();
    let token_data = b"invalid_token";
    let mut evt = MosquittoEvtExtendedAuth {
        future: ptr::null_mut(),
        client: ptr::null_mut(),
        data_in: token_data.as_ptr().cast::<c_void>(),
        data_out: ptr::null_mut(),
        data_in_len: u16::try_from(token_data.len()).expect("token data length fits u16"),
        data_out_len: 0,
        auth_method: auth_method.as_ptr().cast::<c_char>(),
        future2: [ptr::null_mut(); 3],
    };

    let rc = ext_auth_continue_callback(
        MOSQ_EVT_EXT_AUTH_CONTINUE,
        (&raw mut evt).cast::<c_void>(),
        userdata,
    );
    assert_eq!(rc, MOSQ_ERR_AUTH);

    teardown_plugin(userdata);
}

#[test]
fn acl_check_callback_handles_null_pointers() {
    let rc = acl_check_callback(MOSQ_EVT_ACL_CHECK, ptr::null_mut(), ptr::null_mut());
    assert_eq!(rc, MOSQ_ERR_INVAL);
}

#[test]
fn acl_check_callback_handles_null_topic() {
    let mut evt = MosquittoEvtAclCheck {
        future: ptr::null_mut(),
        client: ptr::null_mut(),
        topic: ptr::null(),
        payload: ptr::null(),
        properties: ptr::null_mut(),
        access: 1,
        payloadlen: 0,
        qos: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = acl_check_callback(
        MOSQ_EVT_ACL_CHECK,
        (&raw mut evt).cast::<c_void>(),
        ptr::null_mut(),
    );
    assert_eq!(rc, MOSQ_ERR_INVAL);
}

#[test]
fn acl_check_callback_handles_valid_pointers() {
    let (userdata, _identifier) = setup_plugin_with_config();

    let topic = CString::new("test/topic").unwrap();
    let mut evt = MosquittoEvtAclCheck {
        future: ptr::null_mut(),
        client: ptr::null_mut(),
        topic: topic.as_ptr().cast_mut(),
        payload: ptr::null(),
        properties: ptr::null_mut(),
        access: 1,
        payloadlen: 0,
        qos: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = acl_check_callback(
        MOSQ_EVT_ACL_CHECK,
        (&raw mut evt).cast::<c_void>(),
        userdata,
    );
    assert_eq!(rc, MOSQ_ERR_ACL_DENIED);

    teardown_plugin(userdata);
}

#[test]
fn acl_read_expiry_only_allows_without_grants_when_flag_disabled() {
    let (userdata, _identifier) = setup_plugin_with_config();
    set_acl_read_full_authz(userdata, false);
    cache_test_jwt(userdata, time::unix_timestamp_now() + 60);

    let topic = CString::new("fanout/broadcast").unwrap();
    let mut evt = MosquittoEvtAclCheck {
        future: ptr::null_mut(),
        client: std::ptr::dangling_mut::<c_void>(),
        topic: topic.as_ptr(),
        payload: ptr::null(),
        properties: ptr::null_mut(),
        access: MOSQ_ACL_READ,
        payloadlen: 0,
        qos: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = acl_check_callback(
        MOSQ_EVT_ACL_CHECK,
        (&raw mut evt).cast::<c_void>(),
        userdata,
    );
    assert_eq!(rc, MOSQ_ERR_SUCCESS);

    teardown_plugin(userdata);
}

#[test]
fn acl_read_uses_full_authz_when_flag_enabled() {
    reset_kick_client_call();
    let (userdata, _identifier) = setup_plugin_with_config();
    set_acl_read_full_authz(userdata, true);
    cache_test_jwt(userdata, time::unix_timestamp_now() + 60);

    let topic = CString::new("fanout/broadcast").unwrap();
    let mut evt = MosquittoEvtAclCheck {
        future: ptr::null_mut(),
        client: std::ptr::dangling_mut::<c_void>(),
        topic: topic.as_ptr(),
        payload: ptr::null(),
        properties: ptr::null_mut(),
        access: MOSQ_ACL_READ,
        payloadlen: 0,
        qos: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = acl_check_callback(
        MOSQ_EVT_ACL_CHECK,
        (&raw mut evt).cast::<c_void>(),
        userdata,
    );
    assert_eq!(rc, MOSQ_ERR_ACL_DENIED);
    let kick = kick_client_call_snapshot();
    assert_eq!(kick.count, 0);

    teardown_plugin(userdata);
}

#[test]
fn acl_write_still_requires_full_authz_when_read_fast_path_disabled() {
    reset_kick_client_call();
    let (userdata, _identifier) = setup_plugin_with_config();
    set_acl_read_full_authz(userdata, false);
    cache_test_jwt(userdata, time::unix_timestamp_now() + 60);

    let topic = CString::new("fanout/broadcast").unwrap();
    let mut evt = MosquittoEvtAclCheck {
        future: ptr::null_mut(),
        client: std::ptr::dangling_mut::<c_void>(),
        topic: topic.as_ptr(),
        payload: ptr::null(),
        properties: ptr::null_mut(),
        access: MOSQ_ACL_WRITE,
        payloadlen: 0,
        qos: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = acl_check_callback(
        MOSQ_EVT_ACL_CHECK,
        (&raw mut evt).cast::<c_void>(),
        userdata,
    );
    assert_eq!(rc, MOSQ_ERR_ACL_DENIED);
    let kick = kick_client_call_snapshot();
    assert_eq!(kick.count, 0);

    teardown_plugin(userdata);
}

#[test]
fn acl_subscribe_still_requires_full_authz_when_read_fast_path_disabled() {
    let (userdata, _identifier) = setup_plugin_with_config();
    set_acl_read_full_authz(userdata, false);
    cache_test_jwt(userdata, time::unix_timestamp_now() + 60);

    let topic = CString::new("fanout/broadcast").unwrap();
    let mut evt = MosquittoEvtAclCheck {
        future: ptr::null_mut(),
        client: std::ptr::dangling_mut::<c_void>(),
        topic: topic.as_ptr(),
        payload: ptr::null(),
        properties: ptr::null_mut(),
        access: MOSQ_ACL_SUBSCRIBE,
        payloadlen: 0,
        qos: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = acl_check_callback(
        MOSQ_EVT_ACL_CHECK,
        (&raw mut evt).cast::<c_void>(),
        userdata,
    );
    assert_eq!(rc, MOSQ_ERR_ACL_DENIED);

    teardown_plugin(userdata);
}

#[test]
fn acl_read_rejects_expired_token_when_read_fast_path_disabled() {
    reset_kick_client_call();
    let (userdata, _identifier) = setup_plugin_with_config();
    set_acl_read_full_authz(userdata, false);
    cache_test_jwt(userdata, time::unix_timestamp_now() - 1);

    let topic = CString::new("fanout/broadcast").unwrap();
    let mut evt = MosquittoEvtAclCheck {
        future: ptr::null_mut(),
        client: std::ptr::dangling_mut::<c_void>(),
        topic: topic.as_ptr(),
        payload: ptr::null(),
        properties: ptr::null_mut(),
        access: MOSQ_ACL_READ,
        payloadlen: 0,
        qos: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = acl_check_callback(
        MOSQ_EVT_ACL_CHECK,
        (&raw mut evt).cast::<c_void>(),
        userdata,
    );
    assert_eq!(rc, MOSQ_ERR_ACL_DENIED);
    let kick = kick_client_call_snapshot();
    assert_eq!(kick.count, 1);
    assert_eq!(kick.last_client_id.as_deref(), Some("test_client"));
    assert_eq!(kick.last_with_will, Some(false));

    teardown_plugin(userdata);
}

#[test]
#[cfg_attr(miri, ignore)]
fn acl_read_expired_token_does_not_fall_back_to_dynamic_security_anonymous_after_kick() {
    reset_kick_client_call();
    let (userdata, _identifier) = setup_plugin_with_config();
    set_acl_read_full_authz(userdata, false);
    enable_dynamic_security_anonymous_mode(userdata);
    cache_test_jwt(userdata, time::unix_timestamp_now() - 1);

    let topic = CString::new("public/announce").unwrap();
    let mut evt = MosquittoEvtAclCheck {
        future: ptr::null_mut(),
        client: std::ptr::dangling_mut::<c_void>(),
        topic: topic.as_ptr(),
        payload: ptr::null(),
        properties: ptr::null_mut(),
        access: MOSQ_ACL_READ,
        payloadlen: 0,
        qos: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc1 = acl_check_callback(
        MOSQ_EVT_ACL_CHECK,
        (&raw mut evt).cast::<c_void>(),
        userdata,
    );
    assert_eq!(rc1, MOSQ_ERR_ACL_DENIED);

    let rc2 = acl_check_callback(
        MOSQ_EVT_ACL_CHECK,
        (&raw mut evt).cast::<c_void>(),
        userdata,
    );
    assert_eq!(rc2, MOSQ_ERR_ACL_DENIED);

    let kick = kick_client_call_snapshot();
    assert_eq!(kick.count, 2);
    assert_eq!(kick.last_client_id.as_deref(), Some("test_client"));
    assert_eq!(kick.last_with_will, Some(false));

    teardown_plugin(userdata);
}

#[test]
fn acl_read_rejects_expired_token_with_disconnect_when_full_authz_enabled() {
    reset_kick_client_call();
    let (userdata, _identifier) = setup_plugin_with_config();
    set_acl_read_full_authz(userdata, true);
    cache_test_jwt(userdata, time::unix_timestamp_now() - 1);

    let topic = CString::new("fanout/broadcast").unwrap();
    let mut evt = MosquittoEvtAclCheck {
        future: ptr::null_mut(),
        client: std::ptr::dangling_mut::<c_void>(),
        topic: topic.as_ptr(),
        payload: ptr::null(),
        properties: ptr::null_mut(),
        access: MOSQ_ACL_READ,
        payloadlen: 0,
        qos: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = acl_check_callback(
        MOSQ_EVT_ACL_CHECK,
        (&raw mut evt).cast::<c_void>(),
        userdata,
    );
    assert_eq!(rc, MOSQ_ERR_ACL_DENIED);
    let kick = kick_client_call_snapshot();
    assert_eq!(kick.count, 1);
    assert_eq!(kick.last_client_id.as_deref(), Some("test_client"));
    assert_eq!(kick.last_with_will, Some(false));

    teardown_plugin(userdata);
}

#[test]
fn acl_read_expiry_only_allows_biscuit_when_flag_disabled() {
    let (userdata, _identifier) = setup_plugin_with_config();
    set_acl_read_full_authz(userdata, false);
    cache_test_biscuit(userdata, Some(time::unix_timestamp_now() + 60));

    let topic = CString::new("fanout/broadcast").unwrap();
    let mut evt = MosquittoEvtAclCheck {
        future: ptr::null_mut(),
        client: std::ptr::dangling_mut::<c_void>(),
        topic: topic.as_ptr(),
        payload: ptr::null(),
        properties: ptr::null_mut(),
        access: MOSQ_ACL_READ,
        payloadlen: 0,
        qos: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = acl_check_callback(
        MOSQ_EVT_ACL_CHECK,
        (&raw mut evt).cast::<c_void>(),
        userdata,
    );
    assert_eq!(rc, MOSQ_ERR_SUCCESS);

    teardown_plugin(userdata);
}

#[test]
fn acl_read_uses_full_authz_for_biscuit_when_flag_enabled() {
    let (userdata, _identifier) = setup_plugin_with_config();
    set_acl_read_full_authz(userdata, true);
    cache_test_biscuit(userdata, Some(time::unix_timestamp_now() + 60));

    let topic = CString::new("fanout/broadcast").unwrap();
    let mut evt = MosquittoEvtAclCheck {
        future: ptr::null_mut(),
        client: std::ptr::dangling_mut::<c_void>(),
        topic: topic.as_ptr(),
        payload: ptr::null(),
        properties: ptr::null_mut(),
        access: MOSQ_ACL_READ,
        payloadlen: 0,
        qos: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = acl_check_callback(
        MOSQ_EVT_ACL_CHECK,
        (&raw mut evt).cast::<c_void>(),
        userdata,
    );
    assert_eq!(rc, MOSQ_ERR_ACL_DENIED);

    teardown_plugin(userdata);
}

#[test]
fn acl_read_rejects_expired_biscuit_when_flag_disabled() {
    reset_kick_client_call();
    let (userdata, _identifier) = setup_plugin_with_config();
    set_acl_read_full_authz(userdata, false);
    cache_test_biscuit(userdata, Some(time::unix_timestamp_now() - 1));

    let topic = CString::new("fanout/broadcast").unwrap();
    let mut evt = MosquittoEvtAclCheck {
        future: ptr::null_mut(),
        client: std::ptr::dangling_mut::<c_void>(),
        topic: topic.as_ptr(),
        payload: ptr::null(),
        properties: ptr::null_mut(),
        access: MOSQ_ACL_READ,
        payloadlen: 0,
        qos: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = acl_check_callback(
        MOSQ_EVT_ACL_CHECK,
        (&raw mut evt).cast::<c_void>(),
        userdata,
    );
    assert_eq!(rc, MOSQ_ERR_ACL_DENIED);
    let kick = kick_client_call_snapshot();
    assert_eq!(kick.count, 1);
    assert_eq!(kick.last_client_id.as_deref(), Some("test_client"));
    assert_eq!(kick.last_with_will, Some(false));

    teardown_plugin(userdata);
}

#[test]
fn message_callback_handles_null_pointers() {
    let rc = message_callback(MOSQ_EVT_MESSAGE, ptr::null_mut(), ptr::null_mut());
    assert_eq!(rc, MOSQ_ERR_INVAL);
}

#[test]
fn message_callback_handles_null_topic() {
    let mut evt = MosquittoEvtMessage {
        future: ptr::null_mut(),
        client: ptr::null_mut(),
        topic: ptr::null_mut(),
        payload: ptr::null_mut(),
        properties: ptr::null_mut(),
        reason_string: ptr::null_mut(),
        payloadlen: 0,
        qos: 0,
        reason_code: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = message_callback(
        MOSQ_EVT_MESSAGE,
        (&raw mut evt).cast::<c_void>(),
        ptr::null_mut(),
    );
    assert_eq!(rc, MOSQ_ERR_INVAL);
}

#[test]
fn message_callback_handles_valid_pointers() {
    let (userdata, _identifier) = setup_plugin_with_config();

    let topic = CString::new("test/topic").unwrap();
    let mut evt = MosquittoEvtMessage {
        future: ptr::null_mut(),
        client: ptr::null_mut(),
        topic: topic.as_ptr().cast_mut(),
        payload: ptr::null_mut(),
        properties: ptr::null_mut(),
        reason_string: ptr::null_mut(),
        payloadlen: 0,
        qos: 0,
        reason_code: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = message_callback(MOSQ_EVT_MESSAGE, (&raw mut evt).cast::<c_void>(), userdata);
    assert_eq!(rc, MOSQ_ERR_SUCCESS);

    teardown_plugin(userdata);
}

#[test]
fn message_callback_applies_dynamic_security_disable_client_control_payload() {
    reset_kick_client_call();
    let (userdata, _identifier) = setup_plugin_with_config();
    let dynsec_path = enable_dynamic_security_control_mode(userdata);
    cache_test_jwt(userdata, time::unix_timestamp_now() + 60);

    let topic = CString::new("$CONTROL/dynamic-security/v1").unwrap();
    let payload = br#"{"commands":[{"command":"disableClient","username":"test_user"}]}"#;
    let mut evt = MosquittoEvtMessage {
        future: ptr::null_mut(),
        client: std::ptr::dangling_mut::<c_void>(),
        topic: topic.as_ptr().cast_mut(),
        payload: payload.as_ptr().cast::<c_void>().cast_mut(),
        properties: ptr::null_mut(),
        reason_string: ptr::null_mut(),
        payloadlen: u32::try_from(payload.len()).expect("payload length fits u32"),
        qos: 1,
        reason_code: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = message_callback(MOSQ_EVT_MESSAGE, (&raw mut evt).cast::<c_void>(), userdata);
    assert_eq!(rc, MOSQ_ERR_SUCCESS);
    let kick = kick_client_call_snapshot();
    assert_eq!(kick.count, 1);
    assert_eq!(kick.last_client_id.as_deref(), Some("test_client"));

    let state = unsafe { plugin_state(userdata) };
    assert!(state.cache.get(&"test_client".to_string()).is_none());
    let _ = fs::remove_file(dynsec_path);
    teardown_plugin(userdata);
}

#[test]
fn session_client_lookup_prunes_stale_bindings() {
    let (userdata, _identifier) = setup_plugin_with_config();
    let state = unsafe { plugin_state(userdata) };
    bind_session_username(state, "stale_client", Some("test_user"));

    let resolved = session_client_ids_for_username(state, "test_user");
    assert!(resolved.is_empty());

    let remaining = state
        .session_index
        .lock()
        .expect("session index lock should succeed")
        .client_ids_for_username("test_user");
    assert!(remaining.is_empty());

    teardown_plugin(userdata);
}

#[test]
fn control_callback_handles_null_pointers() {
    let rc = control_callback(MOSQ_EVT_CONTROL, ptr::null_mut(), ptr::null_mut());
    assert_eq!(rc, MOSQ_ERR_INVAL);
}

#[test]
fn control_callback_handles_null_topic() {
    let mut evt = MosquittoEvtControl {
        future: ptr::null_mut(),
        client: ptr::null_mut(),
        topic: ptr::null(),
        payload: ptr::null(),
        properties: ptr::null(),
        reason_string: ptr::null_mut(),
        payloadlen: 0,
        qos: 0,
        reason_code: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = control_callback(
        MOSQ_EVT_CONTROL,
        (&raw mut evt).cast::<c_void>(),
        ptr::null_mut(),
    );
    assert_eq!(rc, MOSQ_ERR_INVAL);
}

#[test]
fn control_callback_defers_non_control_topics() {
    let (userdata, _identifier) = setup_plugin_with_config();

    // Non-control topics should be deferred (MOSQ_ERR_PLUGIN_DEFER)
    let topic = CString::new("regular/topic/path").unwrap();
    let mut evt = MosquittoEvtControl {
        future: ptr::null_mut(),
        client: ptr::null_mut(),
        topic: topic.as_ptr().cast::<c_char>(),
        payload: ptr::null(),
        properties: ptr::null(),
        reason_string: ptr::null_mut(),
        payloadlen: 0,
        qos: 0,
        reason_code: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = control_callback(MOSQ_EVT_CONTROL, (&raw mut evt).cast::<c_void>(), userdata);
    // Non-$CONTROL topics should defer to other plugins
    assert_eq!(rc, MOSQ_ERR_PLUGIN_DEFER);

    teardown_plugin(userdata);
}

#[test]
fn control_callback_handles_valid_pointers() {
    let (userdata, _identifier) = setup_plugin_with_config();

    let topic = CString::new("$CONTROL/test").unwrap();
    let mut evt = MosquittoEvtControl {
        future: ptr::null_mut(),
        client: ptr::null_mut(),
        topic: topic.as_ptr().cast::<c_char>(),
        payload: ptr::null(),
        properties: ptr::null(),
        reason_string: ptr::null_mut(),
        payloadlen: 0,
        qos: 0,
        reason_code: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = control_callback(MOSQ_EVT_CONTROL, (&raw mut evt).cast::<c_void>(), userdata);
    assert_eq!(rc, MOSQ_ERR_ACL_DENIED);

    teardown_plugin(userdata);
}

#[test]
fn control_callback_disable_client_kicks_target_and_evicts_cache() {
    reset_kick_client_call();
    let (userdata, _identifier) = setup_plugin_with_config();
    let dynsec_path = enable_dynamic_security_control_mode(userdata);
    cache_test_jwt(userdata, time::unix_timestamp_now() + 60);

    let topic = CString::new("$CONTROL/dynamic-security/v1").unwrap();
    let payload = br#"{"commands":[{"command":"disableClient","username":"test_user"}]}"#;
    let mut evt = MosquittoEvtControl {
        future: ptr::null_mut(),
        client: std::ptr::dangling_mut::<c_void>(),
        topic: topic.as_ptr().cast::<c_char>(),
        payload: payload.as_ptr().cast::<c_void>(),
        properties: ptr::null(),
        reason_string: ptr::null_mut(),
        payloadlen: u32::try_from(payload.len()).expect("payload length fits u32"),
        qos: 1,
        reason_code: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = control_callback(MOSQ_EVT_CONTROL, (&raw mut evt).cast::<c_void>(), userdata);
    assert_eq!(rc, MOSQ_ERR_SUCCESS);

    let kick = kick_client_call_snapshot();
    assert_eq!(kick.count, 1);
    assert_eq!(kick.last_client_id.as_deref(), Some("test_client"));
    assert_eq!(kick.last_with_will, Some(false));

    let state = unsafe { plugin_state(userdata) };
    assert!(state.cache.get(&"test_client".to_string()).is_none());
    let policy = state
        .dynamic_security_policy
        .as_ref()
        .expect("dynamic security policy should be configured");
    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                MOSQ_ACL_WRITE
            )
            .expect("policy check should succeed")
    );

    let _ = fs::remove_file(dynsec_path);
    teardown_plugin(userdata);
}

#[test]
fn control_callback_disable_client_kicks_session_index_target_without_client_id() {
    reset_kick_client_call();
    let (userdata, _identifier) = setup_plugin_with_config();
    let dynsec_path = enable_dynamic_security_control_mode_with_client_id(userdata, false);
    cache_test_jwt(userdata, time::unix_timestamp_now() + 60);
    cache_test_jwt_for_client(userdata, "target_client", time::unix_timestamp_now() + 60);

    let state = unsafe { plugin_state(userdata) };
    bind_session_username(state, "target_client", Some("test_user"));

    let topic = CString::new("$CONTROL/dynamic-security/v1").unwrap();
    let payload = br#"{"commands":[{"command":"disableClient","username":"test_user"}]}"#;
    let mut evt = MosquittoEvtControl {
        future: ptr::null_mut(),
        client: std::ptr::dangling_mut::<c_void>(),
        topic: topic.as_ptr().cast::<c_char>(),
        payload: payload.as_ptr().cast::<c_void>(),
        properties: ptr::null(),
        reason_string: ptr::null_mut(),
        payloadlen: u32::try_from(payload.len()).expect("payload length fits u32"),
        qos: 1,
        reason_code: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = control_callback(MOSQ_EVT_CONTROL, (&raw mut evt).cast::<c_void>(), userdata);
    assert_eq!(rc, MOSQ_ERR_SUCCESS);

    let kick = kick_client_call_snapshot();
    assert_eq!(kick.count, 1);
    assert_eq!(kick.last_client_id.as_deref(), Some("target_client"));
    assert_eq!(kick.last_with_will, Some(false));

    let state = unsafe { plugin_state(userdata) };
    assert!(state.cache.get(&"target_client".to_string()).is_none());

    let _ = fs::remove_file(dynsec_path);
    teardown_plugin(userdata);
}

#[test]
fn control_callback_disable_client_stale_session_index_target_skips_kick() {
    reset_kick_client_call();
    let (userdata, _identifier) = setup_plugin_with_config();
    let dynsec_path = enable_dynamic_security_control_mode_with_client_id(userdata, false);
    cache_test_jwt(userdata, time::unix_timestamp_now() + 60);

    let state = unsafe { plugin_state(userdata) };
    bind_session_username(state, "stale_client", Some("test_user"));

    let topic = CString::new("$CONTROL/dynamic-security/v1").unwrap();
    let payload = br#"{"commands":[{"command":"disableClient","username":"test_user"}]}"#;
    let mut evt = MosquittoEvtControl {
        future: ptr::null_mut(),
        client: std::ptr::dangling_mut::<c_void>(),
        topic: topic.as_ptr().cast::<c_char>(),
        payload: payload.as_ptr().cast::<c_void>(),
        properties: ptr::null(),
        reason_string: ptr::null_mut(),
        payloadlen: u32::try_from(payload.len()).expect("payload length fits u32"),
        qos: 1,
        reason_code: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = control_callback(MOSQ_EVT_CONTROL, (&raw mut evt).cast::<c_void>(), userdata);
    assert_eq!(rc, MOSQ_ERR_SUCCESS);

    let kick = kick_client_call_snapshot();
    assert_eq!(kick.count, 0);

    let remaining = state
        .session_index
        .lock()
        .expect("session index lock should succeed")
        .client_ids_for_username("test_user");
    assert!(remaining.is_empty());

    let _ = fs::remove_file(dynsec_path);
    teardown_plugin(userdata);
}

#[test]
fn control_callback_remove_role_acl_publishes_notification_without_kick() {
    reset_kick_client_call();
    reset_broker_publish_call();
    let (userdata, _identifier) = setup_plugin_with_config();
    let dynsec_path = enable_dynamic_security_control_notify_mode(userdata);
    cache_test_jwt(userdata, time::unix_timestamp_now() + 60);

    let state = unsafe { plugin_state(userdata) };
    bind_session_username(state, "test_client", Some("test_user"));

    let topic = CString::new("$CONTROL/dynamic-security/v1").unwrap();
    let payload = br#"{"commands":[{"command":"removeRoleACL","rolename":"fanout_reader","acltype":"publishClientReceive","topic":"fanout/broadcast"}]}"#;
    let mut evt = MosquittoEvtControl {
        future: ptr::null_mut(),
        client: std::ptr::dangling_mut::<c_void>(),
        topic: topic.as_ptr().cast::<c_char>(),
        payload: payload.as_ptr().cast::<c_void>(),
        properties: ptr::null(),
        reason_string: ptr::null_mut(),
        payloadlen: u32::try_from(payload.len()).expect("payload length fits u32"),
        qos: 1,
        reason_code: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = control_callback(MOSQ_EVT_CONTROL, (&raw mut evt).cast::<c_void>(), userdata);
    assert_eq!(rc, MOSQ_ERR_SUCCESS);

    let kick = kick_client_call_snapshot();
    assert_eq!(kick.count, 0);

    let publish = broker_publish_call_snapshot();
    assert_eq!(publish.count, 1);
    assert_eq!(publish.last_client_id.as_deref(), Some("test_client"));
    assert_eq!(
        publish.last_topic.as_deref(),
        Some("system_notification/test_client")
    );
    let payload_text = publish.last_payload.unwrap_or_default();
    assert!(payload_text.contains("\"command\":\"removeRoleACL\""));
    assert!(payload_text.contains("\"topic\":\"fanout/broadcast\""));

    let state = unsafe { plugin_state(userdata) };
    assert!(state.cache.get(&"test_client".to_string()).is_some());

    let _ = fs::remove_file(dynsec_path);
    teardown_plugin(userdata);
}

#[test]
fn control_callback_group_membership_churn_publishes_notify_without_kick() {
    reset_kick_client_call();
    reset_broker_publish_call();
    let (userdata, _identifier) = setup_plugin_with_config();
    let dynsec_path = enable_dynamic_security_control_mode(userdata);
    cache_test_jwt(userdata, time::unix_timestamp_now() + 60);

    let state = unsafe { plugin_state_mut(userdata) };
    state.config.control_notify_topic_prefix = "system_notification".to_string();
    bind_session_username(state, "test_client", Some("test_user"));

    let topic = CString::new("$CONTROL/dynamic-security/v1").unwrap();
    let grant_payload = br#"{
          "commands": [
            {
              "command":"createRole",
              "rolename":"fanout_reader",
              "acls":[
                {"acltype":"subscribeLiteral","topic":"fanout/broadcast","priority":1,"allow":true},
                {"acltype":"publishClientReceive","topic":"fanout/broadcast","priority":1,"allow":true}
              ]
            },
            {
              "command":"createGroup",
              "groupname":"fanout",
              "roles":[{"rolename":"fanout_reader","priority":5}]
            },
            {
              "command":"addGroupClient",
              "groupname":"fanout",
              "username":"test_user",
              "priority":7
            }
          ]
        }"#;
    let mut grant_evt = MosquittoEvtControl {
        future: ptr::null_mut(),
        client: std::ptr::dangling_mut::<c_void>(),
        topic: topic.as_ptr().cast::<c_char>(),
        payload: grant_payload.as_ptr().cast::<c_void>(),
        properties: ptr::null(),
        reason_string: ptr::null_mut(),
        payloadlen: u32::try_from(grant_payload.len()).expect("payload length fits u32"),
        qos: 1,
        reason_code: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = control_callback(
        MOSQ_EVT_CONTROL,
        (&raw mut grant_evt).cast::<c_void>(),
        userdata,
    );
    assert_eq!(rc, MOSQ_ERR_SUCCESS);

    let kick = kick_client_call_snapshot();
    assert_eq!(kick.count, 0);
    let publish = broker_publish_call_snapshot();
    assert_eq!(publish.count, 0);

    let state = unsafe { plugin_state(userdata) };
    assert!(state.cache.get(&"test_client".to_string()).is_some());
    let policy = state
        .dynamic_security_policy
        .as_ref()
        .expect("dynamic security policy should be configured");
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                MOSQ_ACL_READ
            )
            .expect("policy check should succeed")
    );

    let revoke_payload =
            br#"{"commands":[{"command":"removeGroupClient","groupname":"fanout","username":"test_user"}]}"#;
    let mut revoke_evt = MosquittoEvtControl {
        future: ptr::null_mut(),
        client: std::ptr::dangling_mut::<c_void>(),
        topic: topic.as_ptr().cast::<c_char>(),
        payload: revoke_payload.as_ptr().cast::<c_void>(),
        properties: ptr::null(),
        reason_string: ptr::null_mut(),
        payloadlen: u32::try_from(revoke_payload.len()).expect("payload length fits u32"),
        qos: 1,
        reason_code: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = control_callback(
        MOSQ_EVT_CONTROL,
        (&raw mut revoke_evt).cast::<c_void>(),
        userdata,
    );
    assert_eq!(rc, MOSQ_ERR_SUCCESS);

    let kick = kick_client_call_snapshot();
    assert_eq!(kick.count, 0);
    let publish = broker_publish_call_snapshot();
    assert_eq!(publish.count, 1);
    assert_eq!(publish.last_client_id.as_deref(), Some("test_client"));
    assert_eq!(
        publish.last_topic.as_deref(),
        Some("system_notification/test_client")
    );
    let payload_text = publish.last_payload.unwrap_or_default();
    assert!(payload_text.contains("\"command\":\"removeGroupClient\""));
    assert!(payload_text.contains("\"topic\":\"fanout/broadcast\""));
    let state = unsafe { plugin_state(userdata) };
    assert!(state.cache.get(&"test_client".to_string()).is_some());
    let policy = state
        .dynamic_security_policy
        .as_ref()
        .expect("dynamic security policy should be configured");
    assert!(
        !policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                MOSQ_ACL_READ
            )
            .expect("policy check should succeed")
    );

    let _ = fs::remove_file(dynsec_path);
    teardown_plugin(userdata);
}

#[test]
fn control_callback_add_group_client_updates_existing_priority_without_side_effects() {
    reset_kick_client_call();
    reset_broker_publish_call();
    let (userdata, _identifier) = setup_plugin_with_config();
    let dynsec_path = enable_dynamic_security_control_mode(userdata);
    cache_test_jwt(userdata, time::unix_timestamp_now() + 60);

    let topic = CString::new("$CONTROL/dynamic-security/v1").unwrap();
    let grant_payload = br#"{
          "commands": [
            {
              "command":"createRole",
              "rolename":"fanout_reader",
              "acls":[
                {"acltype":"subscribeLiteral","topic":"fanout/broadcast","priority":1,"allow":true},
                {"acltype":"publishClientReceive","topic":"fanout/broadcast","priority":1,"allow":true}
              ]
            },
            {
              "command":"createGroup",
              "groupname":"fanout",
              "roles":[{"rolename":"fanout_reader","priority":5}]
            },
            {
              "command":"addGroupClient",
              "groupname":"fanout",
              "username":"test_user",
              "priority":7
            }
          ]
        }"#;
    let mut grant_evt = MosquittoEvtControl {
        future: ptr::null_mut(),
        client: std::ptr::dangling_mut::<c_void>(),
        topic: topic.as_ptr().cast::<c_char>(),
        payload: grant_payload.as_ptr().cast::<c_void>(),
        properties: ptr::null(),
        reason_string: ptr::null_mut(),
        payloadlen: u32::try_from(grant_payload.len()).expect("payload length fits u32"),
        qos: 1,
        reason_code: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = control_callback(
        MOSQ_EVT_CONTROL,
        (&raw mut grant_evt).cast::<c_void>(),
        userdata,
    );
    assert_eq!(rc, MOSQ_ERR_SUCCESS);

    let update_payload =
            br#"{"commands":[{"command":"addGroupClient","groupname":"fanout","username":"test_user","priority":1}]}"#;
    let mut update_evt = MosquittoEvtControl {
        future: ptr::null_mut(),
        client: std::ptr::dangling_mut::<c_void>(),
        topic: topic.as_ptr().cast::<c_char>(),
        payload: update_payload.as_ptr().cast::<c_void>(),
        properties: ptr::null(),
        reason_string: ptr::null_mut(),
        payloadlen: u32::try_from(update_payload.len()).expect("payload length fits u32"),
        qos: 1,
        reason_code: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = control_callback(
        MOSQ_EVT_CONTROL,
        (&raw mut update_evt).cast::<c_void>(),
        userdata,
    );
    assert_eq!(rc, MOSQ_ERR_SUCCESS);

    let kick = kick_client_call_snapshot();
    assert_eq!(kick.count, 0);
    let publish = broker_publish_call_snapshot();
    assert_eq!(publish.count, 0);

    let raw = fs::read_to_string(&dynsec_path).expect("dynsec config should be readable");
    let root: serde_json::Value = serde_json::from_str(&raw).expect("dynsec config should parse");
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
        .expect("test_user group client should exist");
    assert_eq!(test_user["priority"].as_i64(), Some(1));

    let _ = fs::remove_file(dynsec_path);
    teardown_plugin(userdata);
}

#[test]
fn control_callback_persist_failure_keeps_transport_success_and_applies_runtime_change() {
    reset_kick_client_call();
    reset_broker_publish_call();
    let (userdata, _identifier) = setup_plugin_with_config();
    let dynsec_path = enable_dynamic_security_control_mode(userdata);
    cache_test_jwt(userdata, time::unix_timestamp_now() + 60);

    let state = unsafe { plugin_state_mut(userdata) };
    bind_session_username(state, "test_client", Some("test_user"));
    state.config.control_notify_topic_prefix = "system_notification".to_string();
    replace_dynsec_file_with_directory(&dynsec_path);

    let topic = CString::new("$CONTROL/dynamic-security/v1").unwrap();
    let payload = br#"{
          "commands": [
            {
              "command":"createRole",
              "rolename":"fanout_reader",
              "acls":[
                {"acltype":"subscribeLiteral","topic":"fanout/broadcast","priority":1,"allow":true},
                {"acltype":"publishClientReceive","topic":"fanout/broadcast","priority":1,"allow":true}
              ]
            },
            {
              "command":"createGroup",
              "groupname":"fanout",
              "roles":[{"rolename":"fanout_reader","priority":5}]
            },
            {
              "command":"addGroupClient",
              "groupname":"fanout",
              "username":"test_user",
              "priority":7
            }
          ]
        }"#;
    let mut evt = MosquittoEvtControl {
        future: ptr::null_mut(),
        client: std::ptr::dangling_mut::<c_void>(),
        topic: topic.as_ptr().cast::<c_char>(),
        payload: payload.as_ptr().cast::<c_void>(),
        properties: ptr::null(),
        reason_string: ptr::null_mut(),
        payloadlen: u32::try_from(payload.len()).expect("payload length fits u32"),
        qos: 1,
        reason_code: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = control_callback(MOSQ_EVT_CONTROL, (&raw mut evt).cast::<c_void>(), userdata);
    assert_eq!(rc, MOSQ_ERR_SUCCESS);

    let kick = kick_client_call_snapshot();
    assert_eq!(kick.count, 0);
    let publish = broker_publish_call_snapshot();
    assert_eq!(publish.count, 1);
    assert_eq!(publish.last_client_id.as_deref(), Some("test_client"));
    assert_eq!(
        publish.last_topic.as_deref(),
        Some("system_notification/test_client")
    );
    let payload_text = publish.last_payload.unwrap_or_default();
    assert!(payload_text.contains("\"event\":\"control_persist_warning\""));
    assert!(payload_text.contains("\"durable\":false"));
    assert!(payload_text.contains("\"topic\":\"$CONTROL/dynamic-security/v1\""));
    assert!(payload_text.contains("dynsec config read failed"));

    let state = unsafe { plugin_state(userdata) };
    assert!(state.cache.get(&"test_client".to_string()).is_some());
    let policy = state
        .dynamic_security_policy
        .as_ref()
        .expect("dynamic security policy should be configured");
    assert!(
        policy
            .check(
                Some("test_user"),
                Some("test_client"),
                "fanout/broadcast",
                MOSQ_ACL_READ
            )
            .expect("policy check should succeed")
    );

    cleanup_dynsec_test_path(&dynsec_path);
    teardown_plugin(userdata);
}

#[test]
fn control_callback_self_disable_publishes_persist_warning_before_kick() {
    reset_kick_client_call();
    reset_broker_publish_call();
    reset_control_action_log();
    let (userdata, _identifier) = setup_plugin_with_config();
    let dynsec_path = enable_dynamic_security_control_mode(userdata);
    cache_test_jwt(userdata, time::unix_timestamp_now() + 60);

    let state = unsafe { plugin_state_mut(userdata) };
    state.config.control_notify_topic_prefix = "system_notification".to_string();
    replace_dynsec_file_with_directory(&dynsec_path);

    let topic = CString::new("$CONTROL/dynamic-security/v1").unwrap();
    let payload = br#"{"commands":[{"command":"disableClient","username":"test_user"}]}"#;
    let mut evt = MosquittoEvtControl {
        future: ptr::null_mut(),
        client: std::ptr::dangling_mut::<c_void>(),
        topic: topic.as_ptr().cast::<c_char>(),
        payload: payload.as_ptr().cast::<c_void>(),
        properties: ptr::null(),
        reason_string: ptr::null_mut(),
        payloadlen: u32::try_from(payload.len()).expect("payload length fits u32"),
        qos: 1,
        reason_code: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = control_callback(MOSQ_EVT_CONTROL, (&raw mut evt).cast::<c_void>(), userdata);
    assert_eq!(rc, MOSQ_ERR_SUCCESS);

    let publish = broker_publish_call_snapshot();
    assert_eq!(publish.count, 1);
    assert_eq!(publish.last_client_id.as_deref(), Some("test_client"));
    let payload_text = publish.last_payload.unwrap_or_default();
    assert!(payload_text.contains("\"event\":\"control_persist_warning\""));

    let kick = kick_client_call_snapshot();
    assert_eq!(kick.count, 1);
    assert_eq!(kick.last_client_id.as_deref(), Some("test_client"));

    let actions = control_action_log_snapshot();
    assert_eq!(
        actions,
        vec![
            TestControlAction::Publish {
                client_id: Some("test_client".to_string()),
            },
            TestControlAction::Kick {
                client_id: Some("test_client".to_string()),
            },
        ]
    );

    cleanup_dynsec_test_path(&dynsec_path);
    teardown_plugin(userdata);
}

#[test]
fn control_callback_invalid_payload_does_not_kick_or_evict_cache() {
    reset_kick_client_call();
    let (userdata, _identifier) = setup_plugin_with_config();
    let dynsec_path = enable_dynamic_security_control_mode(userdata);
    cache_test_jwt(userdata, time::unix_timestamp_now() + 60);

    let topic = CString::new("$CONTROL/dynamic-security/v1").unwrap();
    let payload = br#"{"commands":[{"command":"disableClient","username":"test_user""#;
    let mut evt = MosquittoEvtControl {
        future: ptr::null_mut(),
        client: std::ptr::dangling_mut::<c_void>(),
        topic: topic.as_ptr().cast::<c_char>(),
        payload: payload.as_ptr().cast::<c_void>(),
        properties: ptr::null(),
        reason_string: ptr::null_mut(),
        payloadlen: u32::try_from(payload.len()).expect("payload length fits u32"),
        qos: 1,
        reason_code: 0,
        retain: false,
        future2: [ptr::null_mut(); 4],
    };

    let rc = control_callback(MOSQ_EVT_CONTROL, (&raw mut evt).cast::<c_void>(), userdata);
    assert_eq!(rc, MOSQ_ERR_SUCCESS);

    let kick = kick_client_call_snapshot();
    assert_eq!(kick.count, 0);
    let state = unsafe { plugin_state(userdata) };
    assert!(state.cache.get(&"test_client".to_string()).is_some());

    let _ = fs::remove_file(dynsec_path);
    teardown_plugin(userdata);
}
