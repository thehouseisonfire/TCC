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
use std::collections::{HashMap, HashSet};
#[cfg(any(test, kani))]
use std::ffi::c_char;
use std::ffi::{CString, c_int, c_void};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::thread::{self, JoinHandle};
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
mod identity_binding;
mod jwt_handler;
mod policy;
mod sqlite_policy;
mod time;

mod mosquitto_ffi;
#[cfg(test)]
use auth_runtime::{is_acl_read_only, normalize_username, should_defer_no_token_basic_auth};
use callbacks::{
    acl_check_callback, basic_auth_callback, control_callback, disconnect_callback,
    ext_auth_continue_callback, ext_auth_start_callback, message_callback, message_out_callback,
    tick_callback,
};
use mosquitto_ffi::mosquitto_abi::{
    MOSQ_ACL_CONTROL, MOSQ_ERR_INVAL, MOSQ_ERR_SUCCESS, MOSQ_EVT_ACL_CHECK, MOSQ_EVT_BASIC_AUTH,
    MOSQ_EVT_CONTROL, MOSQ_EVT_DISCONNECT, MOSQ_EVT_EXT_AUTH_CONTINUE, MOSQ_EVT_EXT_AUTH_START,
    MOSQ_EVT_MESSAGE, MOSQ_EVT_MESSAGE_OUT, MOSQ_EVT_TICK, MosqFuncGenericCallback, MosquittoOpt,
    MosquittoPluginId,
};
#[cfg(test)]
use mosquitto_ffi::mosquitto_abi::{MOSQ_ACL_READ, MOSQ_ACL_SUBSCRIBE, MOSQ_ACL_WRITE};
#[cfg(any(test, kani))]
use mosquitto_ffi::mosquitto_abi::{
    MOSQ_ERR_ACL_DENIED, MOSQ_ERR_AUTH, MOSQ_ERR_PLUGIN_DEFER, MosquittoEvtAclCheck,
    MosquittoEvtBasicAuth, MosquittoEvtBasicAuthFuture, MosquittoEvtControl,
    MosquittoEvtExtendedAuth, MosquittoEvtMessage, MosquittoEvtTick,
};
use mosquitto_ffi::mosquitto_runtime::{
    broker_publish_copy_raw, kick_client_by_clientid_raw, log_debug, log_info,
};
use serde_json::Value;
mod session;
use session::{
    SessionIndex, plugin_state, remove_session_username, session_client_ids_for_username,
};
#[cfg(test)]
use session::{bind_session_username, plugin_state_mut};
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
    fn mosquitto_callback_unregister(
        identifier: *mut MosquittoPluginId,
        event: c_int,
        cb_func: MosqFuncGenericCallback,
        event_data: *const c_void,
    ) -> c_int;
}

#[cfg(test)]
#[derive(Default)]
struct TestCallbackRegistrationState {
    fail_registration_event: Option<c_int>,
    fail_unregistration_event: Option<c_int>,
    successful_registrations: Vec<c_int>,
    unregister_attempts: Vec<c_int>,
}

#[cfg(test)]
thread_local! {
    static TEST_CALLBACK_REGISTRATION_STATE: std::cell::RefCell<TestCallbackRegistrationState> =
        std::cell::RefCell::new(TestCallbackRegistrationState::default());
}

#[cfg(test)]
fn reset_callback_registration_state(
    fail_registration_event: Option<c_int>,
    fail_unregistration_event: Option<c_int>,
) {
    TEST_CALLBACK_REGISTRATION_STATE.with(|state| {
        *state.borrow_mut() = TestCallbackRegistrationState {
            fail_registration_event,
            fail_unregistration_event,
            ..TestCallbackRegistrationState::default()
        };
    });
}

#[cfg(test)]
fn callback_registration_state_snapshot() -> (Vec<c_int>, Vec<c_int>) {
    TEST_CALLBACK_REGISTRATION_STATE.with(|state| {
        let state = state.borrow();
        (
            state.successful_registrations.clone(),
            state.unregister_attempts.clone(),
        )
    })
}

#[cfg(any(test, miri, kani))]
#[unsafe(no_mangle)]
pub extern "C" fn mosquitto_callback_register(
    _identifier: *mut MosquittoPluginId,
    event: c_int,
    _cb_func: MosqFuncGenericCallback,
    _event_data: *const c_void,
    _userdata: *mut c_void,
) -> c_int {
    #[cfg(test)]
    {
        TEST_CALLBACK_REGISTRATION_STATE.with(|state| {
            let mut state = state.borrow_mut();
            if state.fail_registration_event == Some(event) {
                MOSQ_ERR_INVAL
            } else {
                state.successful_registrations.push(event);
                MOSQ_ERR_SUCCESS
            }
        })
    }
    #[cfg(not(test))]
    MOSQ_ERR_SUCCESS
}

#[cfg(any(test, miri, kani))]
#[unsafe(no_mangle)]
pub extern "C" fn mosquitto_callback_unregister(
    _identifier: *mut MosquittoPluginId,
    event: c_int,
    _cb_func: MosqFuncGenericCallback,
    _event_data: *const c_void,
) -> c_int {
    #[cfg(test)]
    {
        TEST_CALLBACK_REGISTRATION_STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.unregister_attempts.push(event);
            if state.fail_unregistration_event == Some(event) {
                MOSQ_ERR_INVAL
            } else {
                MOSQ_ERR_SUCCESS
            }
        })
    }
    #[cfg(not(test))]
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
    deferred_control_disconnects: Mutex<DeferredControlDisconnects>,
    deferred_control_disconnect_pending: AtomicBool,
    config: PluginConfig,
    sqlite_policy: Option<SqlitePolicy>,
    dynamic_security_policy: Option<DynamicSecurityPolicy>,
    auth_metrics: Arc<AuthMetrics>,
    authz_metrics: Arc<AuthzMetrics>,
    _diagnostics_server: Option<BenchmarkDiagnosticsServer>,
}

const DYNAMIC_SECURITY_CONTROL_RESPONSE_TOPIC: &str = "$CONTROL/dynamic-security/v1/response";

#[derive(Default)]
struct DeferredControlDisconnects {
    awaiting_response_dispatch: HashMap<String, Vec<u8>>,
    response_dispatched: HashSet<String>,
}

fn defer_control_disconnect_until_response(
    state: &PluginState,
    client_id: &str,
    response_payload: &[u8],
) -> bool {
    let Ok(mut deferred) = state.deferred_control_disconnects.lock() else {
        log_debug("Control disconnect could not be deferred: lock poisoned");
        return false;
    };
    deferred.response_dispatched.remove(client_id);
    deferred
        .awaiting_response_dispatch
        .insert(client_id.to_string(), response_payload.to_vec());
    state
        .deferred_control_disconnect_pending
        .store(true, Ordering::Release);
    true
}

fn cancel_deferred_control_disconnect(state: &PluginState, client_id: &str) {
    if let Ok(mut deferred) = state.deferred_control_disconnects.lock() {
        deferred.awaiting_response_dispatch.remove(client_id);
        deferred.response_dispatched.remove(client_id);
        state.deferred_control_disconnect_pending.store(
            !deferred.awaiting_response_dispatch.is_empty()
                || !deferred.response_dispatched.is_empty(),
            Ordering::Release,
        );
    } else {
        log_debug("Deferred control disconnect cancellation skipped: lock poisoned");
    }
}

fn has_deferred_control_disconnect(state: &PluginState) -> bool {
    state
        .deferred_control_disconnect_pending
        .load(Ordering::Acquire)
}

fn is_pending_control_response(state: &PluginState, client_id: &str, topic: &str) -> bool {
    if topic != DYNAMIC_SECURITY_CONTROL_RESPONSE_TOPIC {
        return false;
    }
    state
        .deferred_control_disconnects
        .lock()
        .is_ok_and(|deferred| {
            deferred.awaiting_response_dispatch.contains_key(client_id)
                || deferred.response_dispatched.contains(client_id)
        })
}

fn mark_control_response_dispatched(state: &PluginState, client_id: &str, response_payload: &[u8]) {
    let Ok(mut deferred) = state.deferred_control_disconnects.lock() else {
        log_debug("Deferred control disconnect dispatch skipped: lock poisoned");
        return;
    };
    if deferred
        .awaiting_response_dispatch
        .get(client_id)
        .is_some_and(|expected| expected.as_slice() == response_payload)
    {
        deferred.awaiting_response_dispatch.remove(client_id);
        deferred.response_dispatched.insert(client_id.to_string());
        log_debug(&format!(
            "Control response reached outbound dispatch: client={client_id}"
        ));
    }
}

fn take_dispatched_control_disconnects(state: &PluginState) -> Vec<String> {
    let Ok(mut deferred) = state.deferred_control_disconnects.lock() else {
        log_debug("Deferred control disconnect drain skipped: lock poisoned");
        return Vec::new();
    };
    let mut client_ids = deferred.response_dispatched.drain().collect::<Vec<_>>();
    state.deferred_control_disconnect_pending.store(
        !deferred.awaiting_response_dispatch.is_empty(),
        Ordering::Release,
    );
    client_ids.sort_unstable();
    client_ids
}

#[derive(Default)]
struct AuthMetrics {
    attempts: AtomicU64,
    successes: AtomicU64,
    failures: AtomicU64,
    anonymous_deferrals: AtomicU64,
    jwt_validations: AtomicU64,
    biscuit_validations: AtomicU64,
}

#[derive(Default)]
struct AuthzMetrics {
    checks: AtomicU64,
    allows: AtomicU64,
    denies: AtomicU64,
    expired: AtomicU64,
    anonymous_checks: AtomicU64,
    anonymous_allows: AtomicU64,
    anonymous_denies: AtomicU64,
}

impl AuthzMetrics {
    fn observe(&self, outcome: crate::authz::AuthzOutcome) {
        self.checks.fetch_add(1, Ordering::Relaxed);
        match outcome {
            crate::authz::AuthzOutcome::Allowed => &self.allows,
            crate::authz::AuthzOutcome::Denied => &self.denies,
            crate::authz::AuthzOutcome::Expired => &self.expired,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    fn observe_anonymous(&self, allowed: bool) {
        self.anonymous_checks.fetch_add(1, Ordering::Relaxed);
        if allowed {
            self.anonymous_allows.fetch_add(1, Ordering::Relaxed);
        } else {
            self.anonymous_denies.fetch_add(1, Ordering::Relaxed);
        }
    }
}

const BENCHMARK_DIAGNOSTICS_PORT: u16 = 18_083;

struct BenchmarkDiagnosticsServer {
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl BenchmarkDiagnosticsServer {
    fn start(
        auth: Arc<AuthMetrics>,
        authz: Arc<AuthzMetrics>,
        cache: Arc<SessionCache<String, TokenType>>,
        policy_mode: PolicyMode,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", BENCHMARK_DIAGNOSTICS_PORT))?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = Arc::clone(&shutdown);
        let thread = thread::Builder::new()
            .name("mqtt-auth-benchmark-diagnostics".to_string())
            .spawn(move || {
                for connection in listener.incoming() {
                    if thread_shutdown.load(Ordering::Acquire) {
                        break;
                    }
                    let Ok(mut stream) = connection else {
                        continue;
                    };
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let mut command = String::new();
                    if BufReader::new(&stream).read_line(&mut command).is_err()
                        || command.trim() != "snapshot"
                    {
                        continue;
                    }
                    let cache_stats = cache.stats();
                    let payload = json!({
                        "authentication": {
                            "attempts": auth.attempts.load(Ordering::Acquire),
                            "successes": auth.successes.load(Ordering::Acquire),
                            "failures": auth.failures.load(Ordering::Acquire),
                            "anonymous_deferrals": auth
                                .anonymous_deferrals
                                .load(Ordering::Acquire),
                            "jwt_validations": auth.jwt_validations.load(Ordering::Acquire),
                            "biscuit_validations": auth.biscuit_validations.load(Ordering::Acquire),
                            "cache_hits": cache_stats.hits,
                            "cache_misses": cache_stats.misses,
                        },
                        "authorization": {
                            "policy_mode": format!("{policy_mode:?}"),
                            "checks": authz.checks.load(Ordering::Acquire),
                            "allows": authz.allows.load(Ordering::Acquire),
                            "denies": authz.denies.load(Ordering::Acquire),
                            "expired": authz.expired.load(Ordering::Acquire),
                            "anonymous_checks": authz.anonymous_checks.load(Ordering::Acquire),
                            "anonymous_allows": authz.anonymous_allows.load(Ordering::Acquire),
                            "anonymous_denies": authz.anonymous_denies.load(Ordering::Acquire),
                        },
                    });
                    let _ = writeln!(stream, "{payload}");
                }
            })?;
        Ok(Self {
            shutdown,
            thread: Some(thread),
        })
    }
}

impl Drop for BenchmarkDiagnosticsServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = TcpStream::connect(("127.0.0.1", BENCHMARK_DIAGNOSTICS_PORT));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct DynamicSecurityControlEnforcement {
    kick_targets: Vec<String>,
    command_errors: Vec<Option<String>>,
    command_data: Vec<Option<Value>>,
}

fn apply_dynamic_security_control_enforcement(
    state: &PluginState,
    client_id: &str,
    username: Option<&str>,
    topic: &str,
    payload: &[u8],
) -> Result<DynamicSecurityControlEnforcement, String> {
    if state.config.policy.mode != PolicyMode::DynamicSecurity {
        return Err("dynamic security control is unavailable outside dynamic-security mode".into());
    }
    if topic != "$CONTROL/dynamic-security/v1" || payload.is_empty() {
        return Err("invalid dynamic security control request".into());
    }

    let client_id_key = client_id.to_string();
    let Some(token_type) = state.cache.get(&client_id_key) else {
        log_debug(&format!(
            "Control command skipped: missing cached session for client={client_id}"
        ));
        return Err(format!("missing cached session for client={client_id}"));
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
        return Err(format!("authorization denied for client={client_id}"));
    }

    let Some(policy) = state.dynamic_security_policy.as_ref() else {
        return Err("dynamic security policy is not configured".to_string());
    };
    match policy.apply_control_payload(payload) {
        Ok(ControlEnforcementTargets {
            kick_client_ids,
            kick_usernames,
            notify_events,
            persist_warning,
            command_errors,
            command_data,
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

            for notify_event in notify_events {
                publish_control_notify_event(state, &notify_event);
            }
            let mut kick_targets = kick_targets.into_iter().collect::<Vec<_>>();
            kick_targets.sort_unstable();
            Ok(DynamicSecurityControlEnforcement {
                kick_targets,
                command_errors,
                command_data,
            })
        }
        Err(err) => {
            log_debug(&format!(
                "Control command processing failed: client={client_id} topic={topic} error={err}"
            ));
            Err(err.to_string())
        }
    }
}

fn apply_dynamic_security_control_disconnects(state: &PluginState, kick_targets: Vec<String>) {
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
}

fn dynamic_security_control_response(
    payload: &[u8],
    command_errors: &[Option<String>],
    command_data: &[Option<Value>],
) -> String {
    let commands: Vec<Value> = serde_json::from_slice::<Value>(payload)
        .ok()
        .and_then(|value| value.get("commands").and_then(Value::as_array).cloned())
        .unwrap_or_default();
    let responses = commands
        .iter()
        .enumerate()
        .map(|(index, command)| {
            let mut response = serde_json::Map::new();
            response.insert(
                "command".to_string(),
                command
                    .get("command")
                    .cloned()
                    .unwrap_or_else(|| Value::String("Unknown command".to_string())),
            );
            if let Some(correlation) = command.get("correlationData") {
                response.insert("correlationData".to_string(), correlation.clone());
            }
            if let Some(error) = command_errors.get(index).and_then(Option::as_deref) {
                response.insert("error".to_string(), Value::String(error.to_string()));
            } else if let Some(data) = command_data.get(index).and_then(|data| data.clone()) {
                response.insert("data".to_string(), data);
            }
            Value::Object(response)
        })
        .collect::<Vec<_>>();
    json!({"responses": responses}).to_string()
}

fn dynamic_security_control_command_errors(payload: &[u8], error: &str) -> Vec<Option<String>> {
    serde_json::from_slice::<Value>(payload)
        .ok()
        .and_then(|value| value.get("commands").and_then(Value::as_array).cloned())
        .unwrap_or_default()
        .iter()
        .map(|_| Some(error.to_string()))
        .collect()
}

fn publish_dynamic_security_control_response(client_id: &str, response: &str) -> bool {
    publish_control_notification(client_id, DYNAMIC_SECURITY_CONTROL_RESPONSE_TOPIC, response)
}

fn disconnect_expired_acl_client(client_id: &str) {
    let Ok(client_id_cstr) = CString::new(client_id) else {
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
    let Ok(client_id_cstr) = CString::new(client_id) else {
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

fn publish_control_notification(client_id: &str, topic: &str, payload: &str) -> bool {
    let Ok(client_id_cstr) = CString::new(client_id) else {
        log_debug(&format!(
            "Control notify skipped: invalid client id '{client_id}'"
        ));
        return false;
    };
    let Ok(topic_cstr) = CString::new(topic) else {
        log_debug(&format!("Control notify skipped: invalid topic '{topic}'"));
        return false;
    };
    let payload_bytes = payload.as_bytes();
    let Ok(payload_len) = c_int::try_from(payload_bytes.len()) else {
        log_debug(&format!(
            "Control notify skipped: payload too large ({} bytes)",
            payload_bytes.len()
        ));
        return false;
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
    rc == MOSQ_ERR_SUCCESS
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
#[allow(clippy::too_many_lines)]
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

        let Ok(config) = parse_options(options, option_count) else {
            return MOSQ_ERR_INVAL;
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

        let auth_metrics = Arc::new(AuthMetrics::default());
        let authz_metrics = Arc::new(AuthzMetrics::default());
        let cache = Arc::new(SessionCache::new(1000));
        let diagnostics_server = if config.benchmark_diagnostics {
            match BenchmarkDiagnosticsServer::start(
                Arc::clone(&auth_metrics),
                Arc::clone(&authz_metrics),
                Arc::clone(&cache),
                config.policy.mode,
            ) {
                Ok(server) => Some(server),
                Err(err) => {
                    log_info(&format!(
                        "Benchmark diagnostics server failed to start: {err}"
                    ));
                    return MOSQ_ERR_INVAL;
                }
            }
        } else {
            None
        };
        let state = Box::new(PluginState {
            auth_engine: Arc::new(AuthEngine::new(
                config.jwt.decoding_key.clone(),
                config.jwt.validation.clone(),
            )),
            cache,
            session_index: Mutex::new(SessionIndex::default()),
            deferred_control_disconnects: Mutex::new(DeferredControlDisconnects::default()),
            deferred_control_disconnect_pending: AtomicBool::new(false),
            config,
            sqlite_policy,
            dynamic_security_policy,
            auth_metrics,
            authz_metrics,
            _diagnostics_server: diagnostics_server,
        });
        *userdata = Box::into_raw(state).cast::<c_void>();

        let registrations = [
            (
                MOSQ_EVT_BASIC_AUTH,
                basic_auth_callback as MosqFuncGenericCallback,
                ptr::null(),
            ),
            (
                MOSQ_EVT_ACL_CHECK,
                acl_check_callback as MosqFuncGenericCallback,
                ptr::null(),
            ),
            (
                MOSQ_EVT_EXT_AUTH_START,
                ext_auth_start_callback as MosqFuncGenericCallback,
                ptr::null(),
            ),
            (
                MOSQ_EVT_EXT_AUTH_CONTINUE,
                ext_auth_continue_callback as MosqFuncGenericCallback,
                ptr::null(),
            ),
            (
                MOSQ_EVT_MESSAGE,
                message_callback as MosqFuncGenericCallback,
                ptr::null(),
            ),
            (
                MOSQ_EVT_MESSAGE_OUT,
                message_out_callback as MosqFuncGenericCallback,
                ptr::null(),
            ),
            (
                MOSQ_EVT_TICK,
                tick_callback as MosqFuncGenericCallback,
                ptr::null(),
            ),
            (
                MOSQ_EVT_DISCONNECT,
                disconnect_callback as MosqFuncGenericCallback,
                ptr::null(),
            ),
            (
                MOSQ_EVT_CONTROL,
                control_callback as MosqFuncGenericCallback,
                c"$CONTROL/dynamic-security/v1".as_ptr().cast::<c_void>(),
            ),
        ];
        let mut registered_callbacks = Vec::with_capacity(registrations.len());
        for (event, callback, event_data) in registrations {
            let rc =
                mosquitto_callback_register(identifier, event, callback, event_data, *userdata);
            if rc != MOSQ_ERR_SUCCESS {
                log_info(&format!(
                    "Callback registration failed: event={event} rc={rc}"
                ));
                let mut rollback_succeeded = true;
                for &(registered_event, registered_callback, registered_event_data) in
                    registered_callbacks.iter().rev()
                {
                    let unregister_rc = mosquitto_callback_unregister(
                        identifier,
                        registered_event,
                        registered_callback,
                        registered_event_data,
                    );
                    if unregister_rc != MOSQ_ERR_SUCCESS {
                        rollback_succeeded = false;
                        log_info(&format!(
                            "Callback registration rollback failed: event={registered_event} rc={unregister_rc}"
                        ));
                    }
                }
                if rollback_succeeded {
                    drop(Box::from_raw((*userdata).cast::<PluginState>()));
                    *userdata = ptr::null_mut();
                } else {
                    log_info(
                        "Plugin state retained after callback rollback failure for broker cleanup",
                    );
                }
                return rc;
            }
            registered_callbacks.push((event, callback, event_data));
        }

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
