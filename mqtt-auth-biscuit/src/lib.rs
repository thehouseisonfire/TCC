use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr;
use std::sync::Arc;
use crate::auth::{AuthEngine, TokenType};
use crate::authz::check_authorization;
use crate::cache::SessionCache;
use std::time::Duration;
use crate::config::{parse_options, PluginConfig};
use crate::policy::PolicyMode;
use crate::sqlite_policy::SqlitePolicy;

mod auth;
mod authz;
mod config;
mod http_policy;
mod jwt_handler;
mod biscuit_handler;
mod cache;
mod policy;
mod sqlite_policy;

// Mosquitto Error Codes
pub const MOSQ_ERR_SUCCESS: c_int = 0;
pub const MOSQ_ERR_NOMEM: c_int = 1;
pub const MOSQ_ERR_INVAL: c_int = 3;
pub const MOSQ_ERR_AUTH: c_int = 11;
pub const MOSQ_ERR_ACL_DENIED: c_int = 12;
pub const MOSQ_ERR_PLUGIN_DEFER: c_int = 17;
pub const MOSQ_ERR_AUTH_CONTINUE: c_int = -4;

// Mosquitto Event Types
pub const MOSQ_EVT_ACL_CHECK: c_int = 2;
pub const MOSQ_EVT_BASIC_AUTH: c_int = 3;
pub const MOSQ_EVT_EXT_AUTH_START: c_int = 4;
pub const MOSQ_EVT_EXT_AUTH_CONTINUE: c_int = 5;
pub const MOSQ_EVT_CONTROL: c_int = 6;
pub const MOSQ_EVT_MESSAGE: c_int = 7;

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

extern "C" {
    pub fn mosquitto_callback_register(
        identifier: *mut MosquittoPluginId,
        event: c_int,
        cb_func: MosqFuncGenericCallback,
        event_data: *const c_void,
        userdata: *mut c_void,
    ) -> c_int;

    pub fn mosquitto_log_printf(level: c_int, fmt: *const c_char, ...);
    pub fn mosquitto_client_id(client: *const c_void) -> *const c_char;
}

pub const MOSQ_LOG_INFO: c_int = 1 << 0;
pub const MOSQ_LOG_ERR: c_int = 1 << 3;

pub struct PluginState {
    auth_engine: Arc<AuthEngine>,
    cache: Arc<SessionCache<String, TokenType>>,
    config: PluginConfig,
    sqlite_policy: Option<SqlitePolicy>,
}

#[no_mangle]
pub extern "C" fn mosquitto_plugin_version(
    _supported_version_count: c_int,
    _supported_versions: *const c_int,
) -> c_int {
    5
}

#[no_mangle]
pub unsafe extern "C" fn mosquitto_plugin_init(
    identifier: *mut MosquittoPluginId,
    userdata: *mut *mut c_void,
    options: *mut MosquittoOpt,
    option_count: c_int,
) -> c_int {
    let config = match parse_options(options, option_count) {
        Ok(c) => c,
        Err(_) => return MOSQ_ERR_INVAL,
    };

    let sqlite_policy = match config.policy.mode {
        PolicyMode::Sqlite => {
            let Some(path) = config.policy.sqlite_path.as_deref() else { return MOSQ_ERR_INVAL };
            let policy = SqlitePolicy::open(path).ok();
            if let Some(p) = policy.as_ref() {
                let _ = p.seed_demo_rules();
            }
            policy
        }
        _ => None,
    };

    let state = Box::new(PluginState {
        auth_engine: Arc::new(AuthEngine::new(config.jwt.decoding_key.clone(), config.jwt.validation.clone())),
        cache: Arc::new(SessionCache::new(1000)),
        config,
        sqlite_policy,
    });
    *userdata = Box::into_raw(state) as *mut c_void;

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

    let msg = CString::new("Biscuit Auth Plugin initialized").unwrap();
    mosquitto_log_printf(MOSQ_LOG_INFO, msg.as_ptr());

    MOSQ_ERR_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn mosquitto_plugin_cleanup(
    _userdata: *mut c_void,
    _options: *mut MosquittoOpt,
    _option_count: c_int,
) -> c_int {
    if !_userdata.is_null() {
        let _ = Box::from_raw(_userdata as *mut PluginState);
    }
    MOSQ_ERR_SUCCESS
}

extern "C" fn basic_auth_callback(
    _event: c_int,
    event_data: *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    let evt = unsafe { &mut *(event_data as *mut MosquittoEvtBasicAuth) };
    let state = unsafe { &*(userdata as *mut PluginState) };

    if evt.password.is_null() {
        return MOSQ_ERR_AUTH;
    }

    let password = unsafe { CStr::from_ptr(evt.password).to_string_lossy() };
    
    match state.auth_engine.authenticate(&password) {
        Ok(token_type) => {
            let client_id = unsafe { CStr::from_ptr(mosquitto_client_id(evt.client)).to_string_lossy().into_owned() };
            state.cache.insert(client_id, token_type, Duration::from_secs(state.config.cache_ttl_seconds));
            MOSQ_ERR_SUCCESS
        }
        Err(_) => MOSQ_ERR_AUTH,
    }
}

extern "C" fn ext_auth_start_callback(
    _event: c_int,
    event_data: *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    let evt = unsafe { &mut *(event_data as *mut MosquittoEvtExtendedAuth) };
    let state = unsafe { &*(userdata as *mut PluginState) };

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

    let data = unsafe { std::slice::from_raw_parts(evt.data_in as *const u8, evt.data_in_len as usize) };
    let token = String::from_utf8_lossy(data);

    match state.auth_engine.authenticate(&token) {
        Ok(token_type) => {
            let client_id = unsafe { CStr::from_ptr(mosquitto_client_id(evt.client)).to_string_lossy().into_owned() };
            state.cache.insert(client_id, token_type, Duration::from_secs(state.config.cache_ttl_seconds));
            MOSQ_ERR_SUCCESS
        }
        Err(_) => MOSQ_ERR_AUTH,
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
    let evt = unsafe { &*(event_data as *mut MosquittoEvtAclCheck) };
    let state = unsafe { &*(userdata as *mut PluginState) };

    let client_id = unsafe { CStr::from_ptr(mosquitto_client_id(evt.client)).to_string_lossy().into_owned() };
    let topic = unsafe { CStr::from_ptr(evt.topic).to_string_lossy() };

    if let Some(token_type) = state.cache.get(&client_id) {
        if check_authorization(
            &token_type,
            &client_id,
            &topic,
            evt.access,
            &state.config.biscuit.root_public_key,
            state.config.policy.mode,
            state.sqlite_policy.as_ref(),
            state.config.policy.http_url.as_deref(),
        ) {
            return MOSQ_ERR_SUCCESS;
        }
    }

    MOSQ_ERR_ACL_DENIED
}

extern "C" fn message_callback(
    _event: c_int,
    event_data: *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    let evt = unsafe { &*(event_data as *mut MosquittoEvtMessage) };
    let state = unsafe { &*(userdata as *mut PluginState) };
    if evt.topic.is_null() {
        return MOSQ_ERR_INVAL;
    }

    let client_id = unsafe { CStr::from_ptr(mosquitto_client_id(evt.client)).to_string_lossy().into_owned() };
    let topic = unsafe { CStr::from_ptr(evt.topic).to_string_lossy() };

    if let Some(token_type) = state.cache.get(&client_id) {
        if check_authorization(
            &token_type,
            &client_id,
            &topic,
            2,
            &state.config.biscuit.root_public_key,
            state.config.policy.mode,
            state.sqlite_policy.as_ref(),
            state.config.policy.http_url.as_deref(),
        ) {
            return MOSQ_ERR_SUCCESS;
        }
    }
    MOSQ_ERR_ACL_DENIED
}

extern "C" fn control_callback(
    _event: c_int,
    event_data: *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    let evt = unsafe { &*(event_data as *mut MosquittoEvtControl) };
    let state = unsafe { &*(userdata as *mut PluginState) };
    if evt.topic.is_null() {
        return MOSQ_ERR_INVAL;
    }

    let client_id = unsafe { CStr::from_ptr(mosquitto_client_id(evt.client)).to_string_lossy().into_owned() };
    let topic = unsafe { CStr::from_ptr(evt.topic).to_string_lossy() };

    if let Some(token_type) = state.cache.get(&client_id) {
        if check_authorization(
            &token_type,
            &client_id,
            &topic,
            2,
            &state.config.biscuit.root_public_key,
            state.config.policy.mode,
            state.sqlite_policy.as_ref(),
            state.config.policy.http_url.as_deref(),
        ) {
            return MOSQ_ERR_SUCCESS;
        }
    }
    MOSQ_ERR_ACL_DENIED
}
