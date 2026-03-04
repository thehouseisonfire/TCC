use crate::auth::{AuthEngine, AuthError, TokenType};
use crate::authz::{AuthzOutcome, AuthzParams, check_authorization, check_token_expiry};
use crate::biscuit_handler::{
    expiry_stats, extract_min_expiry_from_biscuit_with_limits,
    extract_roles_from_biscuit_with_limits, has_profile_grant_facts_with_limits, parse_biscuit,
};
use crate::cache::SessionCache;
use crate::config::{PluginConfig, parse_options};
use crate::dynamic_security_policy::{
    ControlEnforcementTargets, ControlNotifyEvent, DynamicSecurityPolicy,
};
use crate::policy::PolicyMode;
use crate::sqlite_policy::SqlitePolicy;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::ptr;
use std::slice;
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;
#[cfg(test)]
use std::{cell::RefCell, thread_local};

mod auth;
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
                .map(|roles| roles.iter().any(|role| !role.trim().is_empty()))
                .unwrap_or(false);
            if !has_roles {
                Some(
                    "StaticAcl warning: JWT token missing roles; token-only rules may allow beyond ACL identity."
                        .to_string(),
                )
            } else {
                None
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
        STATIC_ACL_BIAS_WARN_ONCE.call_once(|| log_debug(&message));
    }
}

// Mosquitto Error Codes
pub const MOSQ_ERR_SUCCESS: c_int = 0;
pub const MOSQ_ERR_NOMEM: c_int = 1;
pub const MOSQ_ERR_INVAL: c_int = 3;
pub const MOSQ_ERR_AUTH: c_int = 11;
pub const MOSQ_ERR_ACL_DENIED: c_int = 12;
pub const MOSQ_ERR_PLUGIN_DEFER: c_int = 17;
pub const MOSQ_ERR_AUTH_CONTINUE: c_int = -4;

// Mosquitto ACL access constants
// Reference: mosquitto.h header - MOSQ_ACL_READ=1, MOSQ_ACL_WRITE=2, MOSQ_ACL_SUBSCRIBE=4
pub const MOSQ_ACL_READ: c_int = 0x01;
pub const MOSQ_ACL_WRITE: c_int = 0x02;
pub const MOSQ_ACL_SUBSCRIBE: c_int = 0x04;

/// Control-plane access flag for $CONTROL topic authorization.
/// This is distinct from data-plane ACL types (READ/WRITE/SUBSCRIBE)
/// and allows policy engines to apply different rules for control operations.
pub const MOSQ_ACL_CONTROL: c_int = 0x08;

// MQTT v5 reason codes (subset needed for auth signaling)
pub const MQTT_RC_CONTINUE_AUTHENTICATION: u8 = 24;
pub const MQTT_RC_REAUTHENTICATE: u8 = 25;
pub const MQTT_RC_NOT_AUTHORIZED: u8 = 135;

// Mosquitto Event Types
pub const MOSQ_EVT_ACL_CHECK: c_int = 2;
pub const MOSQ_EVT_BASIC_AUTH: c_int = 3;
pub const MOSQ_EVT_EXT_AUTH_START: c_int = 4;
pub const MOSQ_EVT_EXT_AUTH_CONTINUE: c_int = 5;
pub const MOSQ_EVT_CONTROL: c_int = 6;
pub const MOSQ_EVT_MESSAGE: c_int = 7;

/// Fallback cache TTL when tokens do not expose an expiry; meant as a sane default only.
const FALLBACK_CACHE_TTL_SECONDS: u64 = 300;
/// Keep expired sessions briefly in cache so ACL callbacks can enforce
/// disconnect-on-expiry semantics deterministically at runtime.
const EXPIRY_DISCONNECT_GRACE_SECONDS: u64 = 10;

#[repr(C)]
pub struct MosquittoOpt {
    pub key: *mut c_char,
    pub value: *mut c_char,
}

#[repr(C)]
pub struct MosquittoEvtExtendedAuth {
    pub future: *mut c_void,
    pub client: *mut c_void,
    pub data_in: *const c_void,
    pub data_out: *mut c_void,
    pub data_in_len: u16,
    pub data_out_len: u16,
    pub auth_method: *const c_char,
    pub future2: [*mut c_void; 3],
}

#[repr(C)]
pub struct MosquittoEvtMessage {
    pub future: *mut c_void,
    pub client: *mut c_void,
    pub topic: *mut c_char,
    pub payload: *mut c_void,
    pub properties: *mut c_void,
    pub reason_string: *mut c_char,
    pub payloadlen: u32,
    pub qos: u8,
    pub reason_code: u8,
    pub retain: bool,
    pub future2: [*mut c_void; 4],
}

#[repr(C)]
pub struct MosquittoEvtControl {
    pub future: *mut c_void,
    pub client: *mut c_void,
    pub topic: *const c_char,
    pub payload: *const c_void,
    pub properties: *const c_void,
    pub reason_string: *mut c_char,
    pub payloadlen: u32,
    pub qos: u8,
    pub reason_code: u8,
    pub retain: bool,
    pub future2: [*mut c_void; 4],
}

#[repr(C)]
pub struct MosquittoPluginId {
    _unused: [u8; 0],
}

#[repr(C)]
pub struct MosquittoEvtBasicAuth {
    pub future: *mut c_void,
    pub client: *mut c_void,
    pub username: *mut c_char,
    pub password: *mut c_char,
    pub future2: [*mut c_void; 4],
}

#[repr(C)]
pub struct MosquittoEvtAclCheck {
    pub future: *mut c_void,
    pub client: *mut c_void,
    pub topic: *const c_char,
    pub payload: *const c_void,
    pub properties: *mut c_void,
    pub access: c_int,
    pub payloadlen: u32,
    pub qos: u8,
    pub retain: bool,
    pub future2: [*mut c_void; 4],
}

pub type MosqFuncGenericCallback = extern "C" fn(c_int, *mut c_void, *mut c_void) -> c_int;

#[cfg(not(any(test, miri, kani)))]
unsafe extern "C" {
    pub fn mosquitto_callback_register(
        identifier: *mut MosquittoPluginId,
        event: c_int,
        cb_func: MosqFuncGenericCallback,
        event_data: *const c_void,
        userdata: *mut c_void,
    ) -> c_int;

    pub fn mosquitto_log_printf(level: c_int, fmt: *const c_char, ...);
    pub fn mosquitto_client_id(client: *const c_void) -> *const c_char;
    pub fn mosquitto_client_username(client: *const c_void) -> *const c_char;
    pub fn mosquitto_malloc(size: usize) -> *mut c_void;
    pub fn mosquitto_set_username(client: *mut c_void, username: *const c_char) -> c_int;
    pub fn mosquitto_kick_client_by_clientid(clientid: *const c_char, with_will: bool) -> c_int;
    pub fn mosquitto_broker_publish_copy(
        clientid: *const c_char,
        topic: *const c_char,
        payloadlen: c_int,
        payload: *const c_void,
        qos: c_int,
        retain: bool,
        properties: *mut c_void,
    ) -> c_int;
}

#[cfg(not(any(test, miri, kani)))]
fn set_username_raw(client: *mut c_void, username: *const c_char) -> c_int {
    unsafe { mosquitto_set_username(client, username) }
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

#[cfg(any(test, miri, kani))]
#[unsafe(no_mangle)]
pub extern "C" fn mosquitto_set_username(_client: *mut c_void, _username: *const c_char) -> c_int {
    MOSQ_ERR_SUCCESS
}

#[cfg(any(test, miri, kani))]
#[unsafe(no_mangle)]
pub extern "C" fn mosquitto_kick_client_by_clientid(
    clientid: *const c_char,
    with_will: bool,
) -> c_int {
    #[cfg(test)]
    record_kick_client_call(clientid, with_will);
    MOSQ_ERR_SUCCESS
}

#[cfg(any(test, miri, kani))]
#[unsafe(no_mangle)]
pub extern "C" fn mosquitto_broker_publish_copy(
    clientid: *const c_char,
    topic: *const c_char,
    payloadlen: c_int,
    payload: *const c_void,
    qos: c_int,
    retain: bool,
    _properties: *mut c_void,
) -> c_int {
    #[cfg(test)]
    record_broker_publish_call(clientid, topic, payloadlen, payload, qos, retain);
    MOSQ_ERR_SUCCESS
}

#[cfg(any(test, miri, kani))]
fn set_username_raw(client: *mut c_void, username: *const c_char) -> c_int {
    mosquitto_set_username(client, username)
}

#[cfg(not(any(test, miri, kani)))]
fn kick_client_by_clientid_raw(clientid: *const c_char, with_will: bool) -> c_int {
    unsafe { mosquitto_kick_client_by_clientid(clientid, with_will) }
}

#[cfg(any(test, miri, kani))]
fn kick_client_by_clientid_raw(clientid: *const c_char, with_will: bool) -> c_int {
    mosquitto_kick_client_by_clientid(clientid, with_will)
}

#[cfg(not(any(test, miri, kani)))]
fn broker_publish_copy_raw(
    clientid: *const c_char,
    topic: *const c_char,
    payloadlen: c_int,
    payload: *const c_void,
    qos: c_int,
    retain: bool,
    properties: *mut c_void,
) -> c_int {
    unsafe {
        mosquitto_broker_publish_copy(
            clientid, topic, payloadlen, payload, qos, retain, properties,
        )
    }
}

#[cfg(any(test, miri, kani))]
fn broker_publish_copy_raw(
    clientid: *const c_char,
    topic: *const c_char,
    payloadlen: c_int,
    payload: *const c_void,
    qos: c_int,
    retain: bool,
    properties: *mut c_void,
) -> c_int {
    mosquitto_broker_publish_copy(
        clientid, topic, payloadlen, payload, qos, retain, properties,
    )
}

#[cfg(any(test, miri, kani))]
static TEST_CLIENT_ID: &[u8; 12] = b"test_client\0";

#[cfg(any(test, miri, kani))]
static TEST_USERNAME: &[u8; 10] = b"test_user\0";

#[cfg(test)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct KickClientCall {
    count: usize,
    last_client_id: Option<String>,
    last_with_will: Option<bool>,
}

#[cfg(test)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct BrokerPublishCall {
    count: usize,
    last_client_id: Option<String>,
    last_topic: Option<String>,
    last_payload: Option<String>,
    last_qos: Option<c_int>,
    last_retain: Option<bool>,
}

#[cfg(test)]
thread_local! {
    static TEST_KICK_CLIENT_CALL: RefCell<KickClientCall> = RefCell::new(KickClientCall::default());
    static TEST_BROKER_PUBLISH_CALL: RefCell<BrokerPublishCall> = RefCell::new(BrokerPublishCall::default());
    static TEST_DEBUG_LOGS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn reset_kick_client_call() {
    TEST_KICK_CLIENT_CALL.with(|call| {
        *call.borrow_mut() = KickClientCall::default();
    });
}

#[cfg(test)]
fn reset_broker_publish_call() {
    TEST_BROKER_PUBLISH_CALL.with(|call| {
        *call.borrow_mut() = BrokerPublishCall::default();
    });
}

#[cfg(test)]
fn kick_client_call_snapshot() -> KickClientCall {
    TEST_KICK_CLIENT_CALL.with(|call| call.borrow().clone())
}

#[cfg(test)]
fn broker_publish_call_snapshot() -> BrokerPublishCall {
    TEST_BROKER_PUBLISH_CALL.with(|call| call.borrow().clone())
}

#[cfg(test)]
fn reset_debug_logs() {
    TEST_DEBUG_LOGS.with(|logs| logs.borrow_mut().clear());
}

#[cfg(test)]
fn debug_logs_snapshot() -> Vec<String> {
    TEST_DEBUG_LOGS.with(|logs| logs.borrow().clone())
}

#[cfg(test)]
fn record_debug_log(message: &str) {
    TEST_DEBUG_LOGS.with(|logs| logs.borrow_mut().push(message.to_string()));
}

#[cfg(test)]
fn record_kick_client_call(clientid: *const c_char, with_will: bool) {
    TEST_KICK_CLIENT_CALL.with(|call| {
        let mut state = call.borrow_mut();
        state.count += 1;
        state.last_client_id = cstr_to_string(clientid);
        state.last_with_will = Some(with_will);
    });
}

#[cfg(test)]
fn record_broker_publish_call(
    clientid: *const c_char,
    topic: *const c_char,
    payloadlen: c_int,
    payload: *const c_void,
    qos: c_int,
    retain: bool,
) {
    let payload_text = if payload.is_null() || payloadlen <= 0 {
        Some(String::new())
    } else {
        let bytes = unsafe { slice::from_raw_parts(payload.cast::<u8>(), payloadlen as usize) };
        Some(String::from_utf8_lossy(bytes).into_owned())
    };
    TEST_BROKER_PUBLISH_CALL.with(|call| {
        let mut state = call.borrow_mut();
        state.count += 1;
        state.last_client_id = cstr_to_string(clientid);
        state.last_topic = cstr_to_string(topic);
        state.last_payload = payload_text;
        state.last_qos = Some(qos);
        state.last_retain = Some(retain);
    });
}

#[cfg(any(test, miri, kani))]
#[unsafe(no_mangle)]
pub extern "C" fn mosquitto_client_id(_client: *const c_void) -> *const c_char {
    TEST_CLIENT_ID.as_ptr().cast::<c_char>()
}

#[cfg(any(test, miri, kani))]
#[unsafe(no_mangle)]
pub extern "C" fn mosquitto_client_username(_client: *const c_void) -> *const c_char {
    TEST_USERNAME.as_ptr().cast::<c_char>()
}

#[cfg(any(test, miri, kani))]
#[unsafe(no_mangle)]
pub extern "C" fn mosquitto_malloc(size: usize) -> *mut c_void {
    unsafe { libc::malloc(size) }
}

pub const MOSQ_LOG_INFO: c_int = 1 << 0;
pub const MOSQ_LOG_ERR: c_int = 1 << 3;
pub const MOSQ_LOG_DEBUG: c_int = 1 << 4;

#[cfg(not(any(test, miri, kani)))]
fn log_info(msg: &str) {
    if let Ok(c_msg) = CString::new(msg) {
        unsafe {
            mosquitto_log_printf(MOSQ_LOG_INFO, c_msg.as_ptr());
        }
    }
}

#[derive(Debug)]
enum CacheTtlError {
    Expired,
}

impl std::fmt::Display for CacheTtlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheTtlError::Expired => write!(f, "token expired"),
        }
    }
}

fn cache_ttl_for_token(
    token_type: &TokenType,
    configured_ttl_seconds: u64,
) -> Result<Duration, CacheTtlError> {
    let configured_ttl = Duration::from_secs(configured_ttl_seconds);
    let now = time::unix_timestamp_now();
    let expires_at = match token_type {
        TokenType::Jwt { claims, .. } => Some(claims.exp),
        TokenType::Biscuit { expires_at, .. } => *expires_at,
    };

    let ttl = match expires_at {
        Some(exp) => {
            let remaining = exp - now;
            if remaining <= 0 {
                return Err(CacheTtlError::Expired);
            }
            // Preserve a short post-expiry grace window so ACL_CHECK can still
            // observe expired sessions and force disconnect.
            let remaining_with_grace =
                Duration::from_secs((remaining as u64) + EXPIRY_DISCONNECT_GRACE_SECONDS);
            if remaining_with_grace < configured_ttl {
                remaining_with_grace
            } else {
                configured_ttl
            }
        }
        None => {
            let fallback = Duration::from_secs(FALLBACK_CACHE_TTL_SECONDS);
            if fallback < configured_ttl {
                fallback
            } else {
                configured_ttl
            }
        }
    };

    Ok(ttl)
}

#[cfg(any(test, miri, kani))]
fn log_info(_msg: &str) {}

#[cfg(not(any(test, miri, kani)))]
fn log_debug(msg: &str) {
    if let Ok(c_msg) = CString::new(msg) {
        unsafe {
            mosquitto_log_printf(MOSQ_LOG_DEBUG, c_msg.as_ptr());
        }
    }
}

#[cfg(any(test, miri, kani))]
fn log_debug(msg: &str) {
    #[cfg(test)]
    record_debug_log(msg);
    #[cfg(not(test))]
    let _ = msg;
}

fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned(),
    )
}

fn normalize_username(username: Option<String>) -> Option<String> {
    username.and_then(|u| if u.is_empty() { None } else { Some(u) })
}

fn should_defer_no_token_basic_auth(mode: PolicyMode, allow_anonymous_no_token: bool) -> bool {
    matches!(mode, PolicyMode::StaticAcl | PolicyMode::StaticAclStrict)
        || (mode == PolicyMode::DynamicSecurity && allow_anonymous_no_token)
}

fn is_acl_read_only(access: c_int) -> bool {
    (access & MOSQ_ACL_READ) != 0
        && (access & (MOSQ_ACL_WRITE | MOSQ_ACL_SUBSCRIBE | MOSQ_ACL_CONTROL)) == 0
}

fn mosq_client_id_string(client: *const c_void) -> Option<String> {
    if client.is_null() {
        return None;
    }
    let ptr = mosquitto_client_id_ptr(client);
    cstr_to_string(ptr)
}

fn mosq_client_username_string(client: *const c_void) -> Option<String> {
    if client.is_null() {
        return None;
    }
    let ptr = mosquitto_client_username_ptr(client);
    cstr_to_string(ptr)
}

#[cfg(not(any(test, miri, kani)))]
fn mosquitto_client_id_ptr(client: *const c_void) -> *const c_char {
    unsafe { mosquitto_client_id(client) }
}

#[cfg(any(test, miri, kani))]
fn mosquitto_client_id_ptr(client: *const c_void) -> *const c_char {
    mosquitto_client_id(client)
}

#[cfg(not(any(test, miri, kani)))]
fn mosquitto_client_username_ptr(client: *const c_void) -> *const c_char {
    unsafe { mosquitto_client_username(client) }
}

#[cfg(any(test, miri, kani))]
fn mosquitto_client_username_ptr(client: *const c_void) -> *const c_char {
    mosquitto_client_username(client)
}

pub struct PluginState {
    auth_engine: Arc<AuthEngine>,
    cache: Arc<SessionCache<String, TokenType>>,
    session_index: Mutex<SessionIndex>,
    config: PluginConfig,
    sqlite_policy: Option<SqlitePolicy>,
    dynamic_security_policy: Option<DynamicSecurityPolicy>,
}

#[derive(Debug, Default)]
struct SessionIndex {
    usernames_by_client_id: HashMap<String, String>,
    client_ids_by_username: HashMap<String, HashSet<String>>,
}

impl SessionIndex {
    fn bind(&mut self, client_id: &str, username: Option<&str>) {
        self.remove_client_id(client_id);
        let Some(username) = username.map(str::trim).filter(|value| !value.is_empty()) else {
            return;
        };
        self.usernames_by_client_id
            .insert(client_id.to_string(), username.to_string());
        self.client_ids_by_username
            .entry(username.to_string())
            .or_default()
            .insert(client_id.to_string());
    }

    fn remove_client_id(&mut self, client_id: &str) -> bool {
        let Some(username) = self.usernames_by_client_id.remove(client_id) else {
            return false;
        };
        if let Some(client_ids) = self.client_ids_by_username.get_mut(&username) {
            client_ids.remove(client_id);
            if client_ids.is_empty() {
                self.client_ids_by_username.remove(&username);
            }
        }
        true
    }

    fn client_ids_for_username(&self, username: &str) -> Vec<String> {
        self.client_ids_by_username
            .get(username)
            .map(|ids| ids.iter().cloned().collect())
            .unwrap_or_default()
    }

    fn all_client_ids(&self) -> Vec<String> {
        self.usernames_by_client_id.keys().cloned().collect()
    }
}

fn set_reason_string(target: *mut *mut c_char, message: &str) {
    if target.is_null() {
        return;
    }
    if let Ok(c_msg) = CString::new(message) {
        unsafe {
            let len = c_msg.as_bytes_with_nul().len();
            let ptr = mosquitto_malloc(len).cast::<c_char>();
            if ptr.is_null() {
                return;
            }
            ptr::copy_nonoverlapping(c_msg.as_ptr(), ptr, len);
            // Mosquitto takes ownership and frees this buffer.
            *target = ptr;
        }
    }
}

fn set_control_reauth_signal(evt: &mut MosquittoEvtControl, message: &str) {
    evt.reason_code = MQTT_RC_REAUTHENTICATE;
    set_reason_string(&raw mut evt.reason_string, message);
}

fn control_payload_bytes(evt: &MosquittoEvtControl) -> &[u8] {
    if evt.payload.is_null() || evt.payloadlen == 0 {
        return &[];
    }
    unsafe { slice::from_raw_parts(evt.payload.cast::<u8>(), evt.payloadlen as usize) }
}

fn message_payload_bytes(evt: &MosquittoEvtMessage) -> &[u8] {
    if evt.payload.is_null() || evt.payloadlen == 0 {
        return &[];
    }
    unsafe { slice::from_raw_parts(evt.payload as *const u8, evt.payloadlen as usize) }
}

fn acl_payload_bytes(evt: &MosquittoEvtAclCheck) -> &[u8] {
    if evt.payload.is_null() || evt.payloadlen == 0 {
        return &[];
    }
    unsafe { slice::from_raw_parts(evt.payload.cast::<u8>(), evt.payloadlen as usize) }
}

fn bind_session_username(state: &PluginState, client_id: &str, username: Option<&str>) {
    if let Ok(mut session_index) = state.session_index.lock() {
        session_index.bind(client_id, username);
    } else {
        log_debug("Session index bind skipped: lock poisoned");
    }
}

fn remove_session_username(state: &PluginState, client_id: &str) -> bool {
    if let Ok(mut session_index) = state.session_index.lock() {
        session_index.remove_client_id(client_id)
    } else {
        log_debug("Session index removal skipped: lock poisoned");
        false
    }
}

fn prune_session_index_against_cache(state: &PluginState) {
    let indexed_client_ids = if let Ok(session_index) = state.session_index.lock() {
        session_index.all_client_ids()
    } else {
        log_debug("Session index prune skipped: lock poisoned");
        return;
    };

    let mut stale_client_ids = Vec::new();
    for client_id in indexed_client_ids {
        if !state.cache.contains_live(&client_id) {
            stale_client_ids.push(client_id);
        }
    }

    if stale_client_ids.is_empty() {
        return;
    }

    if let Ok(mut session_index) = state.session_index.lock() {
        for client_id in stale_client_ids {
            session_index.remove_client_id(&client_id);
        }
    } else {
        log_debug("Session index stale cleanup skipped: lock poisoned");
    }
}

fn session_client_ids_for_username(state: &PluginState, username: &str) -> Vec<String> {
    let candidate_ids = if let Ok(session_index) = state.session_index.lock() {
        session_index.client_ids_for_username(username)
    } else {
        log_debug("Session index lookup skipped: lock poisoned");
        return Vec::new();
    };

    let mut live_ids = Vec::new();
    let mut stale_ids = Vec::new();
    for client_id in candidate_ids {
        if state.cache.contains_live(&client_id) {
            live_ids.push(client_id);
        } else {
            stale_ids.push(client_id);
        }
    }

    if !stale_ids.is_empty() {
        if let Ok(mut session_index) = state.session_index.lock() {
            for stale_id in stale_ids {
                session_index.remove_client_id(&stale_id);
            }
        } else {
            log_debug("Session index stale cleanup skipped: lock poisoned");
        }
    }

    live_ids
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
            "Control command skipped: missing cached session for client={}",
            client_id
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
            "Control command skipped: authorization denied for client={} topic={}",
            client_id, topic
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
        }) => {
            let mut kick_targets: HashSet<String> = kick_client_ids.into_iter().collect();
            for username in kick_usernames {
                for session_client_id in session_client_ids_for_username(state, &username) {
                    kick_targets.insert(session_client_id);
                }
            }

            for affected_client in kick_targets {
                let evicted = state.cache.remove(&affected_client);
                let session_binding_removed = remove_session_username(state, &affected_client);
                log_debug(&format!(
                    "Control enforcement target: client={} cache_evicted={} session_binding_removed={}",
                    affected_client, evicted, session_binding_removed
                ));
                if evicted {
                    disconnect_control_enforcement_client(&affected_client);
                } else {
                    log_debug(&format!(
                        "Control enforcement kick skipped: client={} not present in live session cache",
                        affected_client
                    ));
                }
            }

            for notify_event in notify_events {
                publish_control_notify_event(state, &notify_event);
            }
        }
        Err(err) => {
            log_debug(&format!(
                "Control command processing failed: client={} topic={} error={}",
                client_id, topic, err
            ));
        }
    }
}

fn disconnect_expired_acl_client(client_id: &str) {
    let client_id_cstr = match CString::new(client_id) {
        Ok(value) => value,
        Err(_) => {
            log_debug(&format!(
                "ACL expiry disconnect skipped: invalid client id '{}'",
                client_id
            ));
            return;
        }
    };
    // ACL callbacks do not support MQTT v5 reason signaling.
    // Enforce expiry by denying ACL and forcefully disconnecting the client.
    let rc = kick_client_by_clientid_raw(client_id_cstr.as_ptr(), false);
    if rc == MOSQ_ERR_SUCCESS {
        log_debug(&format!(
            "ACL expiry disconnect applied: client={} with_will=false",
            client_id
        ));
    } else {
        log_debug(&format!(
            "ACL expiry disconnect failed: client={} with_will=false rc={}",
            client_id, rc
        ));
    }
}

fn disconnect_control_enforcement_client(client_id: &str) {
    let client_id_cstr = match CString::new(client_id) {
        Ok(value) => value,
        Err(_) => {
            log_debug(&format!(
                "Control enforcement kick skipped: invalid client id '{}'",
                client_id
            ));
            return;
        }
    };
    let rc = kick_client_by_clientid_raw(client_id_cstr.as_ptr(), false);
    if rc == MOSQ_ERR_SUCCESS {
        log_debug(&format!(
            "Control enforcement kick applied: client={} with_will=false",
            client_id
        ));
    } else {
        log_debug(&format!(
            "Control enforcement kick failed: client={} with_will=false rc={}",
            client_id, rc
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
                "Control notify skipped: no live sessions for username={}",
                username
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

fn publish_control_notification(client_id: &str, topic: &str, payload: &str) {
    let client_id_cstr = match CString::new(client_id) {
        Ok(value) => value,
        Err(_) => {
            log_debug(&format!(
                "Control notify skipped: invalid client id '{}'",
                client_id
            ));
            return;
        }
    };
    let topic_cstr = match CString::new(topic) {
        Ok(value) => value,
        Err(_) => {
            log_debug(&format!(
                "Control notify skipped: invalid topic '{}'",
                topic
            ));
            return;
        }
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
            "Control notify published: client={} topic={}",
            client_id, topic
        ));
    } else {
        log_debug(&format!(
            "Control notify publish failed: client={} topic={} rc={}",
            client_id, topic, rc
        ));
    }
}

fn attach_biscuit_expiry(
    token_type: TokenType,
    root_public_key: &biscuit_auth::PublicKey,
    biscuit_authorizer_max_time_ms: u64,
) -> Result<TokenType, biscuit_auth::error::Token> {
    match token_type {
        TokenType::Biscuit {
            bytes,
            expires_at,
            roles,
            biscuit,
        } => {
            let biscuit = match biscuit {
                Some(token) => token,
                None => parse_biscuit(&bytes, root_public_key)?,
            };
            let expires_at = match expires_at {
                Some(value) => Some(value),
                None => extract_min_expiry_from_biscuit_with_limits(
                    &biscuit,
                    biscuit_authorizer_max_time_ms,
                )?,
            };
            Ok(TokenType::Biscuit {
                bytes,
                expires_at,
                roles,
                biscuit: Some(biscuit),
            })
        }
        other => Ok(other),
    }
}

fn attach_biscuit_roles(token_type: TokenType, config: &PluginConfig) -> TokenType {
    match token_type {
        TokenType::Biscuit {
            bytes,
            expires_at,
            roles,
            biscuit,
        } => {
            if roles.is_some() {
                return TokenType::Biscuit {
                    bytes,
                    expires_at,
                    roles,
                    biscuit,
                };
            }
            let roles = match biscuit.as_ref() {
                Some(token) => extract_roles_from_biscuit_with_limits(
                    token.as_ref(),
                    &config.biscuit_role_fact,
                    config.biscuit_authorizer_max_time_ms,
                )
                .ok(),
                None => None,
            };
            TokenType::Biscuit {
                bytes,
                expires_at,
                roles,
                biscuit,
            }
        }
        other => other,
    }
}

fn select_preferred_role(roles: &[String]) -> Option<String> {
    if roles.is_empty() {
        return None;
    }
    if roles.len() > 1 {
        log_debug(&format!(
            "Static ACL role selection prefers a single role; candidates={:?}",
            roles
        ));
    }
    if let Some(role) = roles.iter().find(|r| r.trim() == "admin") {
        return Some(role.clone());
    }
    roles.iter().find(|r| !r.trim().is_empty()).cloned()
}

fn role_to_username(token_type: &TokenType, config: &PluginConfig) -> Option<String> {
    match token_type {
        TokenType::Jwt { claims, .. } => claims
            .roles
            .as_ref()
            .and_then(|roles| select_preferred_role(&roles[..]))
            .map(|role| format!("{}{}", config.role_username_prefix, role)),
        TokenType::Biscuit {
            bytes: _,
            roles,
            biscuit,
            ..
        } => {
            if roles.is_none()
                && biscuit.is_none()
                && matches!(
                    config.policy.mode,
                    PolicyMode::StaticAcl | PolicyMode::StaticAclStrict
                )
            {
                STATIC_ACL_ROLE_MISSING_WARN_ONCE.call_once(|| {
                    log_debug(
                        "StaticAcl warning: Biscuit roles unavailable because token was not parsed; ACL role mapping skipped.",
                    );
                });
            }
            let roles = roles.as_ref().cloned().or_else(|| {
                biscuit.as_ref().and_then(|token| {
                    extract_roles_from_biscuit_with_limits(
                        token.as_ref(),
                        &config.biscuit_role_fact,
                        config.biscuit_authorizer_max_time_ms,
                    )
                    .ok()
                })
            });
            roles
                .and_then(|roles| select_preferred_role(&roles[..]))
                .map(|role| format!("{}{}", config.role_username_prefix, role))
        }
    }
}

/// Synthetic usernames are derived once during auth callbacks for static ACLs.
fn set_synthetic_username(
    client: *mut c_void,
    token_type: &TokenType,
    config: &PluginConfig,
) -> Result<(), String> {
    if !matches!(
        config.policy.mode,
        PolicyMode::StaticAcl | PolicyMode::StaticAclStrict
    ) {
        return Ok(());
    }
    if client.is_null() {
        return Ok(());
    }
    let Some(username) = role_to_username(token_type, config) else {
        return Ok(());
    };
    let c_username = CString::new(username).map_err(|e| e.to_string())?;
    // mosquitto_set_username duplicates the provided string (mosquitto__strdup).
    let rc = set_username_raw(client, c_username.as_ptr());
    if rc == MOSQ_ERR_SUCCESS {
        Ok(())
    } else {
        Err(format!("mosquitto_set_username failed: {rc}"))
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn mosquitto_plugin_version(
    _supported_version_count: c_int,
    _supported_versions: *const c_int,
) -> c_int {
    5
}

/// # Safety
///
/// This function is part of the Mosquitto plugin FFI interface.
/// - `identifier` must be a valid pointer to a MosquittoPluginId
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
/// - `userdata` must be a valid pointer that was previously set by mosquitto_plugin_init
/// - `options` and `option_count` are ignored in this implementation but may be valid pointers
/// - The caller ensures all pointers are valid and properly aligned
/// - This function cleans up plugin state and must be called before plugin unload
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mosquitto_plugin_cleanup(
    _userdata: *mut c_void,
    _options: *mut MosquittoOpt,
    _option_count: c_int,
) -> c_int {
    unsafe {
        if !_userdata.is_null() {
            let state = &*_userdata.cast::<PluginState>();
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
            let _ = Box::from_raw(_userdata.cast::<PluginState>());
        }
        MOSQ_ERR_SUCCESS
    }
}

extern "C" fn basic_auth_callback(
    _event: c_int,
    event_data: *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    if event_data.is_null() || userdata.is_null() {
        return MOSQ_ERR_INVAL;
    }
    let evt = unsafe { &mut *event_data.cast::<MosquittoEvtBasicAuth>() };
    let state = unsafe { &*userdata.cast::<PluginState>() };

    if evt.password.is_null() {
        return if should_defer_no_token_basic_auth(
            state.config.policy.mode,
            state.config.allow_anonymous_no_token,
        ) {
            MOSQ_ERR_PLUGIN_DEFER
        } else {
            MOSQ_ERR_AUTH
        };
    }

    let password = unsafe { CStr::from_ptr(evt.password).to_string_lossy() };
    if password.is_empty() {
        return if should_defer_no_token_basic_auth(
            state.config.policy.mode,
            state.config.allow_anonymous_no_token,
        ) {
            MOSQ_ERR_PLUGIN_DEFER
        } else {
            MOSQ_ERR_AUTH
        };
    }

    match state.auth_engine.authenticate(&password) {
        Ok(token_type) => {
            let token_type = match attach_biscuit_expiry(
                token_type,
                &state.config.biscuit.root_public_key,
                state.config.biscuit_authorizer_max_time_ms,
            ) {
                Ok(token_type) => token_type,
                Err(err) => {
                    log_debug(&format!(
                        "Authentication rejected: biscuit expiry extraction failed: {err}"
                    ));
                    return MOSQ_ERR_AUTH;
                }
            };
            let token_type = attach_biscuit_roles(token_type, &state.config);
            log_static_acl_policy_bias(&token_type, &state.config);
            if let Err(err) = set_synthetic_username(evt.client, &token_type, &state.config) {
                log_debug(&format!("Authentication rejected: {err}"));
                return MOSQ_ERR_AUTH;
            }
            let cache_ttl = match cache_ttl_for_token(&token_type, state.config.cache_ttl_seconds) {
                Ok(ttl) => ttl,
                Err(err) => {
                    log_debug(&format!("Authentication rejected: {err}"));
                    return MOSQ_ERR_AUTH;
                }
            };
            let Some(client_id) = mosq_client_id_string(evt.client) else {
                return MOSQ_ERR_AUTH;
            };
            state.cache.insert(client_id.clone(), token_type, cache_ttl);
            prune_session_index_against_cache(state);
            let session_username = mosq_client_username_string(evt.client);
            bind_session_username(state, &client_id, session_username.as_deref());
            MOSQ_ERR_SUCCESS
        }
        Err(AuthError::Expired) => {
            log_debug("Authentication rejected: token expired");
            MOSQ_ERR_AUTH
        }
        Err(AuthError::Invalid(msg)) => {
            log_debug(&format!("Authentication rejected: {msg}"));
            MOSQ_ERR_AUTH
        }
    }
}

extern "C" fn ext_auth_start_callback(
    _event: c_int,
    event_data: *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    if event_data.is_null() || userdata.is_null() {
        return MOSQ_ERR_INVAL;
    }
    let evt = unsafe { &mut *event_data.cast::<MosquittoEvtExtendedAuth>() };
    let state = unsafe { &*userdata.cast::<PluginState>() };

    if !state
        .config
        .ext_auth_method
        .as_deref()
        .map(|m| {
            if evt.auth_method.is_null() {
                return false;
            }
            let am = unsafe { CStr::from_ptr(evt.auth_method).to_string_lossy() };
            am == m
        })
        .unwrap_or(false)
    {
        return MOSQ_ERR_PLUGIN_DEFER;
    }

    if evt.data_in.is_null() || evt.data_in_len == 0 {
        return MOSQ_ERR_AUTH;
    }

    let data =
        unsafe { std::slice::from_raw_parts(evt.data_in.cast::<u8>(), evt.data_in_len as usize) };

    match state
        .auth_engine
        .authenticate_binary(data, state.config.biscuit_transport)
    {
        Ok(token_type) => {
            let token_type = match attach_biscuit_expiry(
                token_type,
                &state.config.biscuit.root_public_key,
                state.config.biscuit_authorizer_max_time_ms,
            ) {
                Ok(token_type) => token_type,
                Err(err) => {
                    log_debug(&format!(
                        "Enhanced auth rejected: biscuit expiry extraction failed: {err}"
                    ));
                    return MOSQ_ERR_AUTH;
                }
            };
            let token_type = attach_biscuit_roles(token_type, &state.config);
            log_static_acl_policy_bias(&token_type, &state.config);
            if let Err(err) = set_synthetic_username(evt.client, &token_type, &state.config) {
                log_debug(&format!("Enhanced auth rejected: {err}"));
                return MOSQ_ERR_AUTH;
            }
            let cache_ttl = match cache_ttl_for_token(&token_type, state.config.cache_ttl_seconds) {
                Ok(ttl) => ttl,
                Err(err) => {
                    log_debug(&format!("Enhanced auth rejected: {err}"));
                    return MOSQ_ERR_AUTH;
                }
            };
            let Some(client_id) = mosq_client_id_string(evt.client) else {
                return MOSQ_ERR_AUTH;
            };
            state.cache.insert(client_id.clone(), token_type, cache_ttl);
            prune_session_index_against_cache(state);
            let session_username = mosq_client_username_string(evt.client);
            bind_session_username(state, &client_id, session_username.as_deref());
            MOSQ_ERR_SUCCESS
        }
        Err(AuthError::Expired) => {
            log_debug("Enhanced auth rejected: token expired");
            MOSQ_ERR_AUTH
        }
        Err(AuthError::Invalid(msg)) => {
            log_debug(&format!("Enhanced auth rejected: {msg}"));
            MOSQ_ERR_AUTH
        }
    }
}

extern "C" fn ext_auth_continue_callback(
    _event: c_int,
    event_data: *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    // For this plugin, we treat auth as single-step: new token in data_in.
    ext_auth_start_callback(_event, event_data, userdata)
}

extern "C" fn acl_check_callback(
    _event: c_int,
    event_data: *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    // ACL callbacks are the authoritative data-plane gate but do not carry
    // MQTT v5 reason signaling fields. Expired sessions are denied and kicked.
    if event_data.is_null() || userdata.is_null() {
        return MOSQ_ERR_INVAL;
    }
    let evt = unsafe { &*event_data.cast::<MosquittoEvtAclCheck>() };
    let state = unsafe { &*userdata.cast::<PluginState>() };

    if evt.topic.is_null() {
        return MOSQ_ERR_INVAL;
    }

    let Some(client_id) = mosq_client_id_string(evt.client) else {
        return MOSQ_ERR_ACL_DENIED;
    };
    let username = normalize_username(mosq_client_username_string(evt.client));
    let topic = unsafe { CStr::from_ptr(evt.topic).to_string_lossy() };

    if let Some(token_type) = state.cache.get(&client_id) {
        if is_acl_read_only(evt.access) && !state.config.acl_read_full_authz {
            match check_token_expiry(&token_type) {
                AuthzOutcome::Allowed => return MOSQ_ERR_SUCCESS,
                AuthzOutcome::Expired => {
                    log_debug("ACL check rejected: token expired; disconnecting client");
                    disconnect_expired_acl_client(&client_id);
                    return MOSQ_ERR_ACL_DENIED;
                }
                AuthzOutcome::Denied => {}
            }
        }

        let params = AuthzParams {
            username: username.as_deref(),
            client_id: &client_id,
            topic: &topic,
            access: evt.access,
            is_control_request: false,
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

        match check_authorization(&token_type, params) {
            AuthzOutcome::Allowed => {
                if topic.starts_with("$CONTROL/") && (evt.access & MOSQ_ACL_WRITE) != 0 {
                    apply_dynamic_security_control_enforcement(
                        state,
                        &client_id,
                        username.as_deref(),
                        topic.as_ref(),
                        acl_payload_bytes(evt),
                    );
                }
                if state.config.policy.mode == PolicyMode::StaticAclStrict {
                    return MOSQ_ERR_PLUGIN_DEFER;
                }
                return MOSQ_ERR_SUCCESS;
            }
            AuthzOutcome::Expired => {
                log_debug("ACL check rejected: token expired; disconnecting client");
                disconnect_expired_acl_client(&client_id);
                return MOSQ_ERR_ACL_DENIED;
            }
            AuthzOutcome::Denied => {
                if state.config.policy.mode == PolicyMode::StaticAcl {
                    return MOSQ_ERR_PLUGIN_DEFER;
                }
                if state.config.policy.mode == PolicyMode::StaticAclStrict {
                    return MOSQ_ERR_ACL_DENIED;
                }
            }
        }
    }

    match state.config.policy.mode {
        PolicyMode::DynamicSecurity if state.config.allow_anonymous_no_token => {
            let Some(policy) = state.dynamic_security_policy.as_ref() else {
                return MOSQ_ERR_ACL_DENIED;
            };
            let allowed = policy
                .check(username.as_deref(), Some(&client_id), &topic, evt.access)
                .unwrap_or(false);
            if allowed {
                MOSQ_ERR_SUCCESS
            } else {
                MOSQ_ERR_ACL_DENIED
            }
        }
        PolicyMode::StaticAcl | PolicyMode::StaticAclStrict => MOSQ_ERR_PLUGIN_DEFER,
        _ => MOSQ_ERR_ACL_DENIED,
    }
}

extern "C" fn message_callback(
    _event: c_int,
    event_data: *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    if event_data.is_null() || userdata.is_null() {
        return MOSQ_ERR_INVAL;
    }
    let evt = unsafe { &mut *event_data.cast::<MosquittoEvtMessage>() };
    let state = unsafe { &*userdata.cast::<PluginState>() };
    if evt.topic.is_null() {
        return MOSQ_ERR_INVAL;
    }
    let topic = unsafe { CStr::from_ptr(evt.topic).to_string_lossy() };
    if let Some(client_id) = mosq_client_id_string(evt.client) {
        let username = mosq_client_username_string(evt.client);
        apply_dynamic_security_control_enforcement(
            state,
            &client_id,
            username.as_deref(),
            topic.as_ref(),
            message_payload_bytes(evt),
        );
    }
    MOSQ_ERR_SUCCESS
}

/// Control-plane authorization callback for Mosquitto $CONTROL topics.
///
/// # Semantics
///
/// This callback is invoked by Mosquitto when a client publishes to a topic
/// starting with `$CONTROL/`. It allows the plugin to authorize control-plane
/// operations (e.g., Dynamic Security policy changes) separately from data-plane
/// operations.
///
/// ## When CONTROL is Used
///
/// The Mosquitto `$CONTROL` topic hierarchy is used for:
/// - **Dynamic Security**: `$CONTROL/dynamic-security/v1` for role/group/ACL management
/// - **Plugin-specific control**: `$CONTROL/<plugin>/v1` for custom control operations
///
/// ## Authorization Flow
///
/// 1. Topic must start with `$CONTROL/` (otherwise deferred to other plugins)
/// 2. Token validation (expiry, signature verification cached from auth phase)
/// 3. Policy evaluation using `MOSQ_ACL_CONTROL` access type
/// 4. Outcome:
///    - **Allowed**: Return `MOSQ_ERR_SUCCESS` (message accepted)
///    - **Denied**: Return `MOSQ_ERR_ACL_DENIED` (message rejected)
///    - **Expired**: Set reauth signal (`MQTT_RC_REAUTHENTICATE`) and deny
///
/// ## Control-Triggered Enforcement Variants
///
/// When a control message modifies policies (e.g., revoking a role), the broker
/// can apply enforcement via two strategies:
///
/// ### Variant A: Kick/Re-authenticate (No ACL_READ checks)
/// - Immediately disconnect affected clients
/// - Clients must re-authenticate with new token reflecting updated policies
/// - Lower overhead for high fan-out scenarios
/// - Requires clients to handle reconnection gracefully
///
/// ### Variant B: ACL_READ + Warning Publication
/// - Keep sessions alive
/// - Enforce new policies via `ACL_READ` on next message delivery
/// - Publish warning to affected clients (e.g., `system/notification/<client_id>`)
/// - Higher per-message overhead but no disruption
/// - Clients learn of privilege changes via notification topic
///
/// The plugin supports both variants through policy configuration:
/// - DynamicSecurity mode: Supports control-triggered kick for `disableClient`
/// - SQLite/HTTP modes: Configurable per deployment
///
/// ## Research Alignment
///
/// This callback enables H₂/H₃ validation by measuring:
/// - Control-plane latency vs data-plane (token verification costs)
/// - Policy churn impact (cache invalidation overhead)
/// - Enforcement variant comparison (kick vs ACL_READ scaling)
extern "C" fn control_callback(
    _event: c_int,
    event_data: *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    if event_data.is_null() || userdata.is_null() {
        return MOSQ_ERR_INVAL;
    }
    let evt = unsafe { &mut *event_data.cast::<MosquittoEvtControl>() };
    let state = unsafe { &*userdata.cast::<PluginState>() };
    if evt.topic.is_null() {
        return MOSQ_ERR_INVAL;
    }

    let topic = unsafe { CStr::from_ptr(evt.topic).to_string_lossy() };

    // CONTROL callback only processes $CONTROL/... topics per Mosquitto semantics.
    // Non-control topics are deferred to other plugins or default ACLs.
    if !topic.starts_with("$CONTROL/") {
        log_debug(&format!(
            "Control callback: deferring non-control topic '{}'",
            topic
        ));
        return MOSQ_ERR_PLUGIN_DEFER;
    }

    let Some(client_id) = mosq_client_id_string(evt.client) else {
        return MOSQ_ERR_ACL_DENIED;
    };
    let username = mosq_client_username_string(evt.client);

    if let Some(token_type) = state.cache.get(&client_id) {
        let params = AuthzParams {
            username: username.as_deref(),
            client_id: &client_id,
            topic: &topic,
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

        match check_authorization(&token_type, params) {
            AuthzOutcome::Allowed => {
                log_debug(&format!(
                    "Control authorized: client={} topic={}",
                    client_id, topic
                ));
                apply_dynamic_security_control_enforcement(
                    state,
                    &client_id,
                    username.as_deref(),
                    topic.as_ref(),
                    control_payload_bytes(evt),
                );
                if state.config.policy.mode == PolicyMode::StaticAclStrict {
                    return MOSQ_ERR_PLUGIN_DEFER;
                }
                return MOSQ_ERR_SUCCESS;
            }
            AuthzOutcome::Expired => {
                set_control_reauth_signal(evt, "token expired; reauthenticate");
                log_debug(&format!(
                    "Control rejected (expired): client={} topic={}",
                    client_id, topic
                ));
                return MOSQ_ERR_ACL_DENIED;
            }
            AuthzOutcome::Denied => {
                log_debug(&format!(
                    "Control denied: client={} topic={}",
                    client_id, topic
                ));
                if state.config.policy.mode == PolicyMode::StaticAcl {
                    return MOSQ_ERR_PLUGIN_DEFER;
                }
                if state.config.policy.mode == PolicyMode::StaticAclStrict {
                    return MOSQ_ERR_ACL_DENIED;
                }
            }
        }
    } else {
        log_debug(&format!(
            "Control rejected (no session): client={} topic={}",
            client_id, topic
        ));
    }
    MOSQ_ERR_ACL_DENIED
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BiscuitAuthorizerProfile;
    use crate::jwt_handler::Claims;
    use biscuit_auth::{Biscuit, KeyPair, PrivateKey};
    use std::ffi::CString;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    static TEST_DYNSEC_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn root_keypair() -> KeyPair {
        let root_bytes = [1u8; 32];
        KeyPair::from(
            &PrivateKey::from_bytes(&root_bytes, biscuit_auth::Algorithm::Ed25519).unwrap(),
        )
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
        let state = unsafe { &mut *userdata.cast::<PluginState>() };
        state.config.acl_read_full_authz = enabled;
    }

    fn enable_dynamic_security_anonymous_mode(userdata: *mut c_void) {
        let state = unsafe { &mut *userdata.cast::<PluginState>() };
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

    fn enable_dynamic_security_control_mode_with_client_id(
        userdata: *mut c_void,
        include_client_id: bool,
    ) -> String {
        let unique = TEST_DYNSEC_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dynsec_path = std::env::temp_dir().join(format!("dynsec-control-lib-{unique}.json"));
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
        let state = unsafe { &mut *userdata.cast::<PluginState>() };
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
        let dynsec_path =
            std::env::temp_dir().join(format!("dynsec-control-notify-lib-{unique}.json"));
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
        let state = unsafe { &mut *userdata.cast::<PluginState>() };
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

    fn cache_test_jwt_for_client(userdata: *mut c_void, client_id: &str, exp: i64) {
        let state = unsafe { &mut *userdata.cast::<PluginState>() };
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
        let state = unsafe { &mut *userdata.cast::<PluginState>() };
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
        let mut config = unsafe { (&*userdata.cast::<PluginState>()).config.clone() };
        teardown_plugin(userdata);
        config.policy.mode = PolicyMode::StaticAcl;
        config.biscuit_authorizer_profile = BiscuitAuthorizerProfile::Rbac;
        config.biscuit.root_public_key = keypair.public();

        reset_debug_logs();
        log_static_acl_policy_bias(&token_type, &config);
        let logs = debug_logs_snapshot();
        assert!(
            logs.iter().any(
                |entry| entry.contains("StaticAcl warning: Biscuit token includes grant facts")
            )
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
            future2: [ptr::null_mut(); 4],
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
            future2: [ptr::null_mut(); 4],
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
        let rc = ext_auth_continue_callback(
            MOSQ_EVT_EXT_AUTH_CONTINUE,
            ptr::null_mut(),
            ptr::null_mut(),
        );
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

        let state = unsafe { &*userdata.cast::<PluginState>() };
        assert!(state.cache.get(&"test_client".to_string()).is_none());
        let _ = fs::remove_file(dynsec_path);
        teardown_plugin(userdata);
    }

    #[test]
    fn session_client_lookup_prunes_stale_bindings() {
        let (userdata, _identifier) = setup_plugin_with_config();
        let state = unsafe { &*userdata.cast::<PluginState>() };
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

        let state = unsafe { &*userdata.cast::<PluginState>() };
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

        let state = unsafe { &*userdata.cast::<PluginState>() };
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

        let state = unsafe { &*userdata.cast::<PluginState>() };
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

        let state = unsafe { &*userdata.cast::<PluginState>() };
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

        let state = unsafe { &*userdata.cast::<PluginState>() };
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

        let state = unsafe { &*userdata.cast::<PluginState>() };
        assert!(state.cache.get(&"test_client".to_string()).is_some());

        let _ = fs::remove_file(dynsec_path);
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
        let state = unsafe { &*userdata.cast::<PluginState>() };
        assert!(state.cache.get(&"test_client".to_string()).is_some());

        let _ = fs::remove_file(dynsec_path);
        teardown_plugin(userdata);
    }
}

#[cfg(kani)]
mod verification {
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
            biscuit_auth::PublicKey::from_bytes(&[0u8; 32], biscuit_auth::Algorithm::Ed25519)
                .unwrap();
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
            biscuit_transport: crate::config::BiscuitTransportMode::Base64Url,
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
            let rc =
                mosquitto_plugin_init(&mut identifier, &mut userdata, options_ptr, option_count);

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
        let password = symbolic_cstr::<16>();

        let mut evt = MosquittoEvtBasicAuth {
            future: ptr::null_mut(),
            client: 0x1 as *mut c_void,
            username: username.as_ptr() as *mut _,
            password: password.as_ptr() as *mut _,
            future2: [ptr::null_mut(); 4],
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
                ext_auth_start_callback(
                    MOSQ_EVT_EXT_AUTH_START,
                    0x1 as *mut c_void,
                    ptr::null_mut()
                ),
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
}
