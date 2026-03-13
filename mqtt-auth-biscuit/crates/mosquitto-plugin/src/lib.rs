use crate::auth::{AuthEngine, TokenType};
use crate::authz::{AuthzOutcome, AuthzParams, check_authorization};
use crate::biscuit_handler::{expiry_stats, has_profile_grant_facts_with_limits};
use crate::cache::SessionCache;
use crate::config::{PluginConfig, parse_options};
use crate::dynamic_security_policy::{
    ControlEnforcementTargets, ControlNotifyEvent, DynamicSecurityPolicy,
};
use crate::policy::PolicyMode;
use crate::sqlite_policy::SqlitePolicy;
use serde_json::json;
use std::collections::HashSet;
#[cfg(any(test, kani))]
use std::ffi::c_char;
use std::ffi::{CString, c_int, c_void};
use std::ptr;
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

mod auth;
mod auth_runtime;
mod authz;
mod biscuit_handler;
/// Kani builds skip the real cache to keep proofs lightweight and deterministic.
/// The stubbed cache exposes the same API surface without stateful behavior.
#[cfg(not(kani))]
mod cache;
mod dynamic_security_policy;
#[cfg(kani)]
mod cache {
    use std::marker::PhantomData;
    use std::time::Duration;

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct CacheStats {
        pub hits: u64,
        pub misses: u64,
    }

    pub struct SessionCache<K, V> {
        _marker: PhantomData<(K, V)>,
    }

    impl<K, V> SessionCache<K, V>
    where
        K: std::hash::Hash + Eq + Clone,
    {
        pub fn new(_capacity: usize) -> Self {
            Self {
                _marker: PhantomData,
            }
        }

        pub fn insert(&self, _key: K, _value: V, _ttl: Duration) {}

        pub fn get(&self, _key: &K) -> Option<V>
        where
            V: Clone,
        {
            None
        }

        pub fn remove(&self, _key: &K) -> bool {
            false
        }

        pub fn contains_live(&self, _key: &K) -> bool {
            false
        }

        pub fn stats(&self) -> CacheStats {
            CacheStats::default()
        }
    }
}
mod config;
mod http_policy;
mod jwt_handler;
mod policy;
mod sqlite_policy;
mod time;

mod mosquitto_ffi;
#[cfg(test)]
use auth_runtime::{is_acl_read_only, normalize_username, should_defer_no_token_basic_auth};
use callbacks::*;
use mosquitto_ffi::mosquitto_abi::{
    MOSQ_ACL_CONTROL, MOSQ_ERR_INVAL, MOSQ_ERR_SUCCESS, MOSQ_EVT_ACL_CHECK, MOSQ_EVT_BASIC_AUTH,
    MOSQ_EVT_CONTROL, MOSQ_EVT_EXT_AUTH_CONTINUE, MOSQ_EVT_EXT_AUTH_START, MOSQ_EVT_MESSAGE,
    MosqFuncGenericCallback, MosquittoOpt, MosquittoPluginId,
};
#[cfg(test)]
use mosquitto_ffi::mosquitto_abi::{MOSQ_ACL_READ, MOSQ_ACL_SUBSCRIBE, MOSQ_ACL_WRITE};
#[cfg(any(test, kani))]
use mosquitto_ffi::mosquitto_abi::{
    MOSQ_ERR_ACL_DENIED, MOSQ_ERR_AUTH, MOSQ_ERR_PLUGIN_DEFER, MosquittoEvtAclCheck,
    MosquittoEvtBasicAuth, MosquittoEvtBasicAuthFuture, MosquittoEvtControl,
    MosquittoEvtExtendedAuth, MosquittoEvtMessage,
};
use mosquitto_ffi::mosquitto_runtime::{
    broker_publish_copy_raw, kick_client_by_clientid_raw, log_debug, log_info,
};
mod session;
use session::*;
mod callbacks;
mod token_utils;
#[cfg(test)]
use mosquitto_ffi::mosquitto_test_api::{
    TestControlAction, broker_publish_call_snapshot, control_action_log_snapshot,
    debug_logs_snapshot, kick_client_call_snapshot, reset_broker_publish_call,
    reset_control_action_log, reset_debug_logs, reset_kick_client_call,
};

#[cfg(not(any(test, miri, kani)))]
unsafe extern "C" {
    fn mosquitto_callback_register(
        identifier: *mut MosquittoPluginId,
        event: c_int,
        cb_func: MosqFuncGenericCallback,
        event_data: *const c_void,
        userdata: *mut c_void,
    ) -> c_int;
}

#[cfg(any(test, miri, kani))]
#[unsafe(no_mangle)]
pub extern "C" fn mosquitto_callback_register(
    _identifier: *mut MosquittoPluginId,
    _event: c_int,
    _cb_func: MosqFuncGenericCallback,
    _event_data: *const c_void,
    _userdata: *mut c_void,
) -> c_int {
    MOSQ_ERR_SUCCESS
}

#[cfg(not(test))]
static STATIC_ACL_BIAS_WARN_ONCE: Once = Once::new();
static STATIC_ACL_ROLE_MISSING_WARN_ONCE: Once = Once::new();

fn log_static_acl_policy_bias(token_type: &TokenType, config: &PluginConfig) {
    if !matches!(
        config.policy.mode,
        PolicyMode::StaticAcl | PolicyMode::StaticAclStrict
    ) {
        return;
    }
    // This warning is intentionally conservative: in StaticAcl modes we flag any
    // token grant shape that can authorize independently of ACL identity under
    // the active Biscuit profile. It is a safety diagnostic, not a per-request
    // allow/deny decision.
    let warn_message = match token_type {
        TokenType::Jwt { claims, .. } => {
            let has_roles = claims
                .roles
                .as_ref()
                .is_some_and(|roles| roles.iter().any(|role| !role.trim().is_empty()));
            if has_roles {
                None
            } else {
                Some(
                    "StaticAcl warning: JWT token missing roles; token-only rules may allow beyond ACL identity."
                        .to_string(),
                )
            }
        }
        TokenType::Biscuit { bytes, .. } => {
            match has_profile_grant_facts_with_limits(
                bytes,
                &config.biscuit.root_public_key,
                config.biscuit_authorizer_profile,
                config.biscuit_authorizer_max_time_ms,
            ) {
                Ok(true) => {
                    Some(
                        "StaticAcl warning: Biscuit token includes grant facts (right(...) and/or profile-derived role_right(...)); token-only rules may allow beyond ACL identity."
                            .to_string(),
                    )
                }
                Ok(false) => None,
                Err(err) => {
                    Some(format!(
                        "StaticAcl warning: failed to inspect Biscuit grant facts: {err}"
                    ))
                }
            }
        }
    };

    if let Some(message) = warn_message {
        #[cfg(test)]
        log_debug(&message);
        #[cfg(not(test))]
        STATIC_ACL_BIAS_WARN_ONCE.call_once(|| log_debug(&message));
    }
}

pub struct PluginState {
    auth_engine: Arc<AuthEngine>,
    cache: Arc<SessionCache<String, TokenType>>,
    session_index: Mutex<SessionIndex>,
    config: PluginConfig,
    sqlite_policy: Option<SqlitePolicy>,
    dynamic_security_policy: Option<DynamicSecurityPolicy>,
}

fn apply_dynamic_security_control_enforcement(
    state: &PluginState,
    client_id: &str,
    username: Option<&str>,
    topic: &str,
    payload: &[u8],
) {
    if state.config.policy.mode != PolicyMode::DynamicSecurity
        || topic != "$CONTROL/dynamic-security/v1"
        || payload.is_empty()
    {
        return;
    }

    let client_id_key = client_id.to_string();
    let Some(token_type) = state.cache.get(&client_id_key) else {
        log_debug(&format!(
            "Control command skipped: missing cached session for client={client_id}"
        ));
        return;
    };

    let params = AuthzParams {
        username,
        client_id,
        topic,
        access: MOSQ_ACL_CONTROL,
        is_control_request: true,
        biscuit_authorizer_profile: state.config.biscuit_authorizer_profile,
        biscuit_authorizer_max_time_ms: state.config.biscuit_authorizer_max_time_ms,
        biscuit_root_key: &state.config.biscuit.root_public_key,
        policy_mode: state.config.policy.mode,
        sqlite_policy: state.sqlite_policy.as_ref(),
        dynamic_security_policy: state.dynamic_security_policy.as_ref(),
        http_url: state.config.policy.http_url.as_deref(),
        http_ca_file: state.config.policy.http_ca_file.as_deref(),
        http_tls_insecure: state.config.policy.http_tls_insecure,
        http_timeout_seconds: state.config.policy.http_timeout_seconds,
        http_max_response_bytes: state.config.policy.http_max_response_bytes,
    };
    if check_authorization(&token_type, params) != AuthzOutcome::Allowed {
        log_debug(&format!(
            "Control command skipped: authorization denied for client={client_id} topic={topic}"
        ));
        return;
    }

    let Some(policy) = state.dynamic_security_policy.as_ref() else {
        return;
    };
    match policy.apply_control_payload(payload) {
        Ok(ControlEnforcementTargets {
            kick_client_ids,
            kick_usernames,
            notify_events,
            persist_warning,
        }) => {
            let mut kick_targets: HashSet<String> = kick_client_ids.into_iter().collect();
            for username in kick_usernames {
                for session_client_id in session_client_ids_for_username(state, &username) {
                    kick_targets.insert(session_client_id);
                }
            }

            if let Some(warning) = persist_warning {
                publish_control_persist_warning(state, client_id, username, topic, &warning);
                log_info(&format!(
                    "Control command applied without durable persistence: client={client_id} topic={topic} warning={warning}"
                ));
            }

            for affected_client in kick_targets {
                let evicted = state.cache.remove(&affected_client);
                let session_binding_removed = remove_session_username(state, &affected_client);
                log_debug(&format!(
                    "Control enforcement target: client={affected_client} cache_evicted={evicted} session_binding_removed={session_binding_removed}"
                ));
                if evicted {
                    disconnect_control_enforcement_client(&affected_client);
                } else {
                    log_debug(&format!(
                        "Control enforcement kick skipped: client={affected_client} not present in live session cache"
                    ));
                }
            }

            for notify_event in notify_events {
                publish_control_notify_event(state, &notify_event);
            }
        }
        Err(err) => {
            log_debug(&format!(
                "Control command processing failed: client={client_id} topic={topic} error={err}"
            ));
        }
    }
}

fn disconnect_expired_acl_client(client_id: &str) {
    let client_id_cstr = if let Ok(value) = CString::new(client_id) {
        value
    } else {
        log_debug(&format!(
            "ACL expiry disconnect skipped: invalid client id '{client_id}'"
        ));
        return;
    };
    // ACL callbacks do not support MQTT v5 reason signaling.
    // Enforce expiry by denying ACL and forcefully disconnecting the client.
    let rc = kick_client_by_clientid_raw(client_id_cstr.as_ptr(), false);
    if rc == MOSQ_ERR_SUCCESS {
        log_debug(&format!(
            "ACL expiry disconnect applied: client={client_id} with_will=false"
        ));
    } else {
        log_debug(&format!(
            "ACL expiry disconnect failed: client={client_id} with_will=false rc={rc}"
        ));
    }
}

fn disconnect_control_enforcement_client(client_id: &str) {
    let client_id_cstr = if let Ok(value) = CString::new(client_id) {
        value
    } else {
        log_debug(&format!(
            "Control enforcement kick skipped: invalid client id '{client_id}'"
        ));
        return;
    };
    let rc = kick_client_by_clientid_raw(client_id_cstr.as_ptr(), false);
    if rc == MOSQ_ERR_SUCCESS {
        log_debug(&format!(
            "Control enforcement kick applied: client={client_id} with_will=false"
        ));
    } else {
        log_debug(&format!(
            "Control enforcement kick failed: client={client_id} with_will=false rc={rc}"
        ));
    }
}

fn publish_control_notify_event(state: &PluginState, event: &ControlNotifyEvent) {
    let prefix = state
        .config
        .control_notify_topic_prefix
        .trim_end_matches('/');
    if prefix.is_empty() {
        log_debug("Control notify skipped: empty topic prefix");
        return;
    }
    for username in &event.usernames {
        let session_client_ids = session_client_ids_for_username(state, username);
        if session_client_ids.is_empty() {
            log_debug(&format!(
                "Control notify skipped: no live sessions for username={username}"
            ));
            continue;
        }
        for session_client_id in session_client_ids {
            let notification_topic = format!("{prefix}/{session_client_id}");
            let payload = json!({
                "event": "acl_read_policy_changed",
                "source": "$CONTROL/dynamic-security/v1",
                "command": event.command,
                "role": event.rolename,
                "acltype": event.acltype,
                "topic": event.topic,
                "username": username,
                "client_id": session_client_id,
            })
            .to_string();
            publish_control_notification(&session_client_id, &notification_topic, &payload);
        }
    }
}

fn publish_control_persist_warning(
    state: &PluginState,
    client_id: &str,
    username: Option<&str>,
    topic: &str,
    warning: &str,
) {
    let prefix = state
        .config
        .control_notify_topic_prefix
        .trim_end_matches('/');
    if prefix.is_empty() {
        log_debug("Control notify skipped: empty topic prefix");
        return;
    }

    let notification_topic = format!("{prefix}/{client_id}");
    let payload = json!({
        "event": "control_persist_warning",
        "source": "$CONTROL/dynamic-security/v1",
        "topic": topic,
        "username": username,
        "client_id": client_id,
        "durable": false,
        "warning": warning,
    })
    .to_string();
    publish_control_notification(client_id, &notification_topic, &payload);
}

fn publish_control_notification(client_id: &str, topic: &str, payload: &str) {
    let client_id_cstr = if let Ok(value) = CString::new(client_id) {
        value
    } else {
        log_debug(&format!(
            "Control notify skipped: invalid client id '{client_id}'"
        ));
        return;
    };
    let topic_cstr = if let Ok(value) = CString::new(topic) {
        value
    } else {
        log_debug(&format!("Control notify skipped: invalid topic '{topic}'"));
        return;
    };
    let payload_bytes = payload.as_bytes();
    let Ok(payload_len) = c_int::try_from(payload_bytes.len()) else {
        log_debug(&format!(
            "Control notify skipped: payload too large ({} bytes)",
            payload_bytes.len()
        ));
        return;
    };
    let rc = broker_publish_copy_raw(
        client_id_cstr.as_ptr(),
        topic_cstr.as_ptr(),
        payload_len,
        payload_bytes.as_ptr().cast::<c_void>(),
        0,
        false,
        ptr::null_mut(),
    );
    if rc == MOSQ_ERR_SUCCESS {
        log_debug(&format!(
            "Control notify published: client={client_id} topic={topic}"
        ));
    } else {
        log_debug(&format!(
            "Control notify publish failed: client={client_id} topic={topic} rc={rc}"
        ));
    }
}

#[unsafe(no_mangle)]
pub const extern "C" fn mosquitto_plugin_version(
    _supported_version_count: c_int,
    _supported_versions: *const c_int,
) -> c_int {
    5
}

/// # Safety
///
/// This function is part of the Mosquitto plugin FFI interface.
/// - `identifier` must be a valid pointer to a `MosquittoPluginId`
/// - `userdata` must be a valid pointer to a null pointer that will be set to plugin state
/// - `options` must be valid for `option_count` iterations or null if `option_count` is 0
/// - The caller ensures all pointers are valid and properly aligned
/// - This function initializes global plugin state and registers callbacks
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mosquitto_plugin_init(
    identifier: *mut MosquittoPluginId,
    userdata: *mut *mut c_void,
    options: *mut MosquittoOpt,
    option_count: c_int,
) -> c_int {
    unsafe {
        if identifier.is_null() || userdata.is_null() {
            return MOSQ_ERR_INVAL;
        }

        let config = match parse_options(options, option_count) {
            Ok(c) => c,
            Err(_) => return MOSQ_ERR_INVAL,
        };

        let sqlite_policy = match config.policy.mode {
            PolicyMode::Sqlite => {
                let Some(path) = config.policy.sqlite_path.as_deref() else {
                    return MOSQ_ERR_INVAL;
                };
                let policy = match SqlitePolicy::open(path) {
                    Ok(policy) => policy,
                    Err(err) => {
                        log_info(&format!("SQLite policy open failed ({path}): {err}"));
                        return MOSQ_ERR_INVAL;
                    }
                };

                if config.sqlite_seed_demo_rules
                    && let Err(err) = policy.seed_demo_rules()
                {
                    log_info(&format!("SQLite demo seed failed ({path}): {err}"));
                    return MOSQ_ERR_INVAL;
                }

                Some(policy)
            }
            _ => None,
        };

        let dynamic_security_policy = match config.policy.mode {
            PolicyMode::DynamicSecurity => {
                let Some(path) = config.policy.dynamic_security_url.as_deref() else {
                    return MOSQ_ERR_INVAL;
                };
                let interval = config
                    .policy
                    .dynamic_security_reload_interval_seconds
                    .unwrap_or(1)
                    .max(1);
                match DynamicSecurityPolicy::new(path, Duration::from_secs(interval)) {
                    Ok(policy) => Some(policy),
                    Err(err) => {
                        log_info(&format!(
                            "Dynamic security config load failed ({path}): {err}"
                        ));
                        return MOSQ_ERR_INVAL;
                    }
                }
            }
            _ => None,
        };

        if matches!(
            config.policy.mode,
            PolicyMode::StaticAcl | PolicyMode::StaticAclStrict
        ) {
            log_info(
                "StaticAcl mode enabled: tokens should carry only role identity to avoid bias.",
            );
        }

        let state = Box::new(PluginState {
            auth_engine: Arc::new(AuthEngine::new(
                config.jwt.decoding_key.clone(),
                config.jwt.validation.clone(),
            )),
            cache: Arc::new(SessionCache::new(1000)),
            session_index: Mutex::new(SessionIndex::default()),
            config,
            sqlite_policy,
            dynamic_security_policy,
        });
        *userdata = Box::into_raw(state).cast::<c_void>();

        mosquitto_callback_register(
            identifier,
            MOSQ_EVT_BASIC_AUTH,
            basic_auth_callback,
            ptr::null(),
            *userdata,
        );
        mosquitto_callback_register(
            identifier,
            MOSQ_EVT_ACL_CHECK,
            acl_check_callback,
            ptr::null(),
            *userdata,
        );

        mosquitto_callback_register(
            identifier,
            MOSQ_EVT_EXT_AUTH_START,
            ext_auth_start_callback,
            ptr::null(),
            *userdata,
        );
        mosquitto_callback_register(
            identifier,
            MOSQ_EVT_EXT_AUTH_CONTINUE,
            ext_auth_continue_callback,
            ptr::null(),
            *userdata,
        );

        mosquitto_callback_register(
            identifier,
            MOSQ_EVT_MESSAGE,
            message_callback,
            ptr::null(),
            *userdata,
        );
        mosquitto_callback_register(
            identifier,
            MOSQ_EVT_CONTROL,
            control_callback,
            ptr::null(),
            *userdata,
        );

        log_info("Biscuit Auth Plugin initialized");

        MOSQ_ERR_SUCCESS
    }
}

/// # Safety
///
/// This function is part of the Mosquitto plugin FFI interface.
/// - `userdata` must be a valid pointer that was previously set by `mosquitto_plugin_init`
/// - `options` and `option_count` are ignored in this implementation but may be valid pointers
/// - The caller ensures all pointers are valid and properly aligned
/// - This function cleans up plugin state and must be called before plugin unload
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mosquitto_plugin_cleanup(
    userdata: *mut c_void,
    _options: *mut MosquittoOpt,
    _option_count: c_int,
) -> c_int {
    unsafe {
        if !userdata.is_null() {
            let state = plugin_state(userdata);
            let cache_stats = state.cache.stats();
            let expiry_stats = expiry_stats();
            log_info(&format!(
                "Session cache stats: hits={}, misses={}",
                cache_stats.hits, cache_stats.misses
            ));
            log_info(&format!(
                "Biscuit expiry extraction stats: calls={}, failures={}, total_nanos={}",
                expiry_stats.calls, expiry_stats.failures, expiry_stats.total_nanos
            ));
            let _ = Box::from_raw(userdata.cast::<PluginState>());
        }
        MOSQ_ERR_SUCCESS
    }
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;

#[cfg(kani)]
#[path = "lib_verification.rs"]
mod verification;
