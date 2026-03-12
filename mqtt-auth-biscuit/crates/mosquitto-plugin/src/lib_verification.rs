use super::*;
use crate::auth::AuthEngine;
use crate::cache::SessionCache;
use crate::config::{BiscuitConfig, JwtConfig, PluginConfig};
use crate::policy::{PolicyBackendConfig, PolicyMode};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use std::ptr;
use std::sync::Arc;

/// Helper to generate a symbolic C string of fixed size
fn symbolic_cstr<const N: usize>() -> [c_char; N] {
    let mut bytes: [c_char; N] = kani::any();
    bytes[N - 1] = 0; // Ensure null termination
    bytes
}

/// Creates a valid mock PluginState for verification
fn mock_plugin_state() -> *mut PluginState {
    let decoding_key = DecodingKey::from_secret(kani::any::<[u8; 16]>().as_slice());
    let validation = Validation::new(Algorithm::HS256);

    let jwt_config = JwtConfig {
        decoding_key,
        validation,
    };

    // Use a dummy public key for Ed25519
    let biscuit_pub_key =
        biscuit_auth::PublicKey::from_bytes(&[0u8; 32], biscuit_auth::Algorithm::Ed25519).unwrap();
    let biscuit_config = BiscuitConfig {
        root_public_key: biscuit_pub_key,
    };

    let config = PluginConfig {
        jwt: jwt_config,
        biscuit: biscuit_config,
        policy: PolicyBackendConfig {
            mode: PolicyMode::TokenOnly,
            sqlite_path: None,
            http_url: None,
            http_ca_file: None,
            http_tls_insecure: false,
        },
        sqlite_seed_demo_rules: false,
        cache_ttl_seconds: 3600,
        allow_anonymous_no_token: false,
        acl_read_full_authz: false,
        control_notify_topic_prefix: "system_notification".to_string(),
        ext_auth_method: Some("token".to_string()),
        role_username_prefix: "role:".to_string(),
        biscuit_role_fact: "role".to_string(),
        biscuit_authorizer_profile: crate::config::BiscuitAuthorizerProfile::Simple,
        biscuit_authorizer_max_time_ms: 25,
    };

    let state = Box::new(PluginState {
        auth_engine: Arc::new(AuthEngine::new(
            config.jwt.decoding_key.clone(),
            config.jwt.validation.clone(),
        )),
        cache: Arc::new(SessionCache::new(10)),
        session_index: Mutex::new(SessionIndex::default()),
        config,
        sqlite_policy: None,
        dynamic_security_policy: None,
    });

    Box::into_raw(state)
}

#[kani::proof]
#[kani::unwind(2)]
fn verify_mosquitto_plugin_init_full() {
    let mut identifier = MosquittoPluginId { _unused: [] };
    let mut userdata: *mut c_void = ptr::null_mut();

    let option_count: c_int = kani::any_where(|&x| x >= 0 && x <= 1);
    let mut option = MosquittoOpt {
        key: ptr::null_mut(),
        value: ptr::null_mut(),
    };

    let options_ptr = if option_count > 0 {
        &mut option as *mut _
    } else {
        ptr::null_mut()
    };

    unsafe {
        let rc = mosquitto_plugin_init(&mut identifier, &mut userdata, options_ptr, option_count);

        if rc == MOSQ_ERR_SUCCESS {
            assert!(!userdata.is_null());
            mosquitto_plugin_cleanup(userdata, ptr::null_mut(), 0);
        } else {
            assert_eq!(rc, MOSQ_ERR_INVAL);
        }
    }
}

#[kani::proof]
fn verify_mosquitto_plugin_cleanup_safety() {
    unsafe {
        if kani::any() {
            let state_ptr = mock_plugin_state() as *mut c_void;
            mosquitto_plugin_cleanup(state_ptr, ptr::null_mut(), 0);
        } else {
            mosquitto_plugin_cleanup(ptr::null_mut(), ptr::null_mut(), 0);
        }
    }
}

#[kani::proof]
fn verify_basic_auth_callback_with_symbolic_inputs() {
    let state = mock_plugin_state();
    let username = symbolic_cstr::<8>();
    let password = kani::any::<[u8; 16]>();

    let mut evt = MosquittoEvtBasicAuth {
        future: ptr::null_mut(),
        client: 0x1 as *mut c_void,
        username: username.as_ptr() as *mut _,
        password: password.as_ptr() as *mut _,
        extra: MosquittoEvtBasicAuthFuture { password_len: 16 },
    };

    unsafe {
        let rc = basic_auth_callback(
            MOSQ_EVT_BASIC_AUTH,
            &mut evt as *mut _ as *mut c_void,
            state as *mut c_void,
        );
        assert!(rc == MOSQ_ERR_SUCCESS || rc == MOSQ_ERR_AUTH || rc == MOSQ_ERR_INVAL);
        mosquitto_plugin_cleanup(state as *mut _, ptr::null_mut(), 0);
    }
}

#[kani::proof]
fn verify_ext_auth_start_callback_with_symbolic_inputs() {
    let state = mock_plugin_state();
    let auth_data = kani::any::<[u8; 8]>();
    let auth_method = symbolic_cstr::<8>();

    let mut evt = MosquittoEvtExtendedAuth {
        future: ptr::null_mut(),
        client: 0x1 as *mut c_void,
        data_in: auth_data.as_ptr() as *const _,
        data_out: ptr::null_mut(),
        data_in_len: 8,
        data_out_len: 0,
        auth_method: auth_method.as_ptr() as *const _,
        future2: [ptr::null_mut(); 3],
    };

    unsafe {
        let rc = ext_auth_start_callback(
            MOSQ_EVT_EXT_AUTH_START,
            &mut evt as *mut _ as *mut c_void,
            state as *mut c_void,
        );
        assert!(
            rc == MOSQ_ERR_SUCCESS
                || rc == MOSQ_ERR_AUTH
                || rc == MOSQ_ERR_INVAL
                || rc == MOSQ_ERR_AUTH_CONTINUE
        );
        mosquitto_plugin_cleanup(state as *mut _, ptr::null_mut(), 0);
    }
}

#[kani::proof]
fn verify_ext_auth_continue_callback_with_symbolic_inputs() {
    let state = mock_plugin_state();
    let auth_data = kani::any::<[u8; 8]>();

    let mut evt = MosquittoEvtExtendedAuth {
        future: ptr::null_mut(),
        client: 0x1 as *mut c_void,
        data_in: auth_data.as_ptr() as *const _,
        data_out: ptr::null_mut(),
        data_in_len: 8,
        data_out_len: 0,
        auth_method: ptr::null(),
        future2: [ptr::null_mut(); 3],
    };

    unsafe {
        let rc = ext_auth_continue_callback(
            MOSQ_EVT_EXT_AUTH_CONTINUE,
            &mut evt as *mut _ as *mut c_void,
            state as *mut c_void,
        );
        assert!(
            rc == MOSQ_ERR_SUCCESS
                || rc == MOSQ_ERR_AUTH
                || rc == MOSQ_ERR_INVAL
                || rc == MOSQ_ERR_AUTH_CONTINUE
        );
        mosquitto_plugin_cleanup(state as *mut _, ptr::null_mut(), 0);
    }
}

#[kani::proof]
fn verify_acl_check_callback_with_symbolic_inputs() {
    let state = mock_plugin_state();
    let topic = symbolic_cstr::<16>();

    let mut evt = MosquittoEvtAclCheck {
        future: ptr::null_mut(),
        client: 0x1 as *mut c_void,
        topic: topic.as_ptr() as *const _,
        payload: ptr::null(),
        properties: ptr::null_mut(),
        access: kani::any(),
        payloadlen: 0,
        qos: kani::any(),
        retain: kani::any(),
        future2: [ptr::null_mut(); 4],
    };

    unsafe {
        let rc = acl_check_callback(
            MOSQ_EVT_ACL_CHECK,
            &mut evt as *mut _ as *mut c_void,
            state as *mut c_void,
        );
        assert!(rc == MOSQ_ERR_SUCCESS || rc == MOSQ_ERR_ACL_DENIED || rc == MOSQ_ERR_INVAL);
        mosquitto_plugin_cleanup(state as *mut _, ptr::null_mut(), 0);
    }
}

#[kani::proof]
fn verify_message_callback_with_symbolic_inputs() {
    let state = mock_plugin_state();
    let topic = symbolic_cstr::<16>();

    let mut evt = MosquittoEvtMessage {
        future: ptr::null_mut(),
        client: 0x1 as *mut c_void,
        topic: topic.as_ptr() as *mut _,
        payload: ptr::null_mut(),
        properties: ptr::null_mut(),
        reason_string: ptr::null_mut(),
        payloadlen: 0,
        qos: kani::any(),
        reason_code: kani::any(),
        retain: kani::any(),
        future2: [ptr::null_mut(); 4],
    };

    unsafe {
        let rc = message_callback(
            MOSQ_EVT_MESSAGE,
            &mut evt as *mut _ as *mut c_void,
            state as *mut c_void,
        );
        assert!(rc == MOSQ_ERR_SUCCESS || rc == MOSQ_ERR_ACL_DENIED || rc == MOSQ_ERR_INVAL);
        mosquitto_plugin_cleanup(state as *mut _, ptr::null_mut(), 0);
    }
}

#[kani::proof]
fn verify_control_callback_with_symbolic_inputs() {
    let state = mock_plugin_state();
    let topic = symbolic_cstr::<16>();

    let mut evt = MosquittoEvtControl {
        future: ptr::null_mut(),
        client: 0x1 as *mut c_void,
        topic: topic.as_ptr() as *const _,
        payload: ptr::null(),
        properties: ptr::null(),
        reason_string: ptr::null_mut(),
        payloadlen: 0,
        qos: kani::any(),
        reason_code: kani::any(),
        retain: kani::any(),
        future2: [ptr::null_mut(); 4],
    };

    unsafe {
        let rc = control_callback(
            MOSQ_EVT_CONTROL,
            &mut evt as *mut _ as *mut c_void,
            state as *mut c_void,
        );
        assert!(rc == MOSQ_ERR_SUCCESS || rc == MOSQ_ERR_ACL_DENIED || rc == MOSQ_ERR_INVAL);
        mosquitto_plugin_cleanup(state as *mut _, ptr::null_mut(), 0);
    }
}

#[kani::proof]
fn verify_callbacks_with_null_inputs() {
    let state = mock_plugin_state();
    unsafe {
        // Test all callbacks with null event_data
        assert_eq!(
            basic_auth_callback(MOSQ_EVT_BASIC_AUTH, ptr::null_mut(), state as *mut c_void),
            MOSQ_ERR_INVAL
        );
        assert_eq!(
            ext_auth_start_callback(
                MOSQ_EVT_EXT_AUTH_START,
                ptr::null_mut(),
                state as *mut c_void
            ),
            MOSQ_ERR_INVAL
        );
        assert_eq!(
            ext_auth_continue_callback(
                MOSQ_EVT_EXT_AUTH_CONTINUE,
                ptr::null_mut(),
                state as *mut c_void
            ),
            MOSQ_ERR_INVAL
        );
        assert_eq!(
            acl_check_callback(MOSQ_EVT_ACL_CHECK, ptr::null_mut(), state as *mut c_void),
            MOSQ_ERR_INVAL
        );
        assert_eq!(
            message_callback(MOSQ_EVT_MESSAGE, ptr::null_mut(), state as *mut c_void),
            MOSQ_ERR_INVAL
        );
        assert_eq!(
            control_callback(MOSQ_EVT_CONTROL, ptr::null_mut(), state as *mut c_void),
            MOSQ_ERR_INVAL
        );

        // Test all callbacks with null userdata
        assert_eq!(
            basic_auth_callback(MOSQ_EVT_BASIC_AUTH, 0x1 as *mut c_void, ptr::null_mut()),
            MOSQ_ERR_INVAL
        );
        assert_eq!(
            ext_auth_start_callback(MOSQ_EVT_EXT_AUTH_START, 0x1 as *mut c_void, ptr::null_mut()),
            MOSQ_ERR_INVAL
        );
        assert_eq!(
            ext_auth_continue_callback(
                MOSQ_EVT_EXT_AUTH_CONTINUE,
                0x1 as *mut c_void,
                ptr::null_mut()
            ),
            MOSQ_ERR_INVAL
        );
        assert_eq!(
            acl_check_callback(MOSQ_EVT_ACL_CHECK, 0x1 as *mut c_void, ptr::null_mut()),
            MOSQ_ERR_INVAL
        );
        assert_eq!(
            message_callback(MOSQ_EVT_MESSAGE, 0x1 as *mut c_void, ptr::null_mut()),
            MOSQ_ERR_INVAL
        );
        assert_eq!(
            control_callback(MOSQ_EVT_CONTROL, 0x1 as *mut c_void, ptr::null_mut()),
            MOSQ_ERR_INVAL
        );

        mosquitto_plugin_cleanup(state as *mut _, ptr::null_mut(), 0);
    }
}
