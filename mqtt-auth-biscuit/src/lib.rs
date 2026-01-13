use crate::auth::{AuthEngine, TokenType};
use crate::authz::{check_authorization, AuthzParams};
use crate::cache::SessionCache;
use crate::config::{parse_options, PluginConfig};
use crate::policy::PolicyMode;
use crate::sqlite_policy::SqlitePolicy;
use std::ffi::{c_char, c_int, c_void, CStr};
#[cfg(not(any(test, miri)))]
use std::ffi::CString;
use std::ptr;
use std::sync::Arc;
use std::time::Duration;

mod auth;
mod authz;
mod biscuit_handler;
mod cache;
mod config;
mod http_policy;
mod jwt_handler;
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

#[cfg(not(any(test, miri)))]
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

#[cfg(any(test, miri))]
#[no_mangle]
pub extern "C" fn mosquitto_callback_register(
    _identifier: *mut MosquittoPluginId,
    _event: c_int,
    _cb_func: MosqFuncGenericCallback,
    _event_data: *const c_void,
    _userdata: *mut c_void,
) -> c_int {
    MOSQ_ERR_SUCCESS
}

#[cfg(any(test, miri))]
static TEST_CLIENT_ID: &[u8; 12] = b"test_client\0";

#[cfg(any(test, miri))]
#[no_mangle]
pub extern "C" fn mosquitto_client_id(_client: *const c_void) -> *const c_char {
    TEST_CLIENT_ID.as_ptr() as *const c_char
}

pub const MOSQ_LOG_INFO: c_int = 1 << 0;
pub const MOSQ_LOG_ERR: c_int = 1 << 3;

#[cfg(not(any(test, miri)))]
fn log_info(msg: &str) {
    if let Ok(c_msg) = CString::new(msg) {
        unsafe {
            mosquitto_log_printf(MOSQ_LOG_INFO, c_msg.as_ptr());
        }
    }
}

#[cfg(any(test, miri))]
fn log_info(_msg: &str) {}

fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned())
}

fn mosq_client_id_string(client: *const c_void) -> Option<String> {
    if client.is_null() {
        return None;
    }
    let ptr = mosquitto_client_id_ptr(client);
    cstr_to_string(ptr)
}

#[cfg(not(any(test, miri)))]
fn mosquitto_client_id_ptr(client: *const c_void) -> *const c_char {
    unsafe { mosquitto_client_id(client) }
}

#[cfg(any(test, miri))]
fn mosquitto_client_id_ptr(client: *const c_void) -> *const c_char {
    mosquitto_client_id(client)
}

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

/// # Safety
/// 
/// This function is part of the Mosquitto plugin FFI interface.
/// - `identifier` must be a valid pointer to a MosquittoPluginId
/// - `userdata` must be a valid pointer to a null pointer that will be set to plugin state
/// - `options` must be valid for `option_count` iterations or null if `option_count` is 0
/// - The caller ensures all pointers are valid and properly aligned
/// - This function initializes global plugin state and registers callbacks
#[no_mangle]
pub unsafe extern "C" fn mosquitto_plugin_init(
    identifier: *mut MosquittoPluginId,
    userdata: *mut *mut c_void,
    options: *mut MosquittoOpt,
    option_count: c_int,
) -> c_int {
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
            let policy = SqlitePolicy::open(path).ok();
            if let Some(p) = policy.as_ref() {
                let _ = p.seed_demo_rules();
            }
            policy
        }
        _ => None,
    };

    let state = Box::new(PluginState {
        auth_engine: Arc::new(AuthEngine::new(
            config.jwt.decoding_key.clone(),
            config.jwt.validation.clone(),
        )),
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

    log_info("Biscuit Auth Plugin initialized");

    MOSQ_ERR_SUCCESS
}

/// # Safety
/// 
/// This function is part of the Mosquitto plugin FFI interface.
/// - `userdata` must be a valid pointer that was previously set by mosquitto_plugin_init
/// - `options` and `option_count` are ignored in this implementation but may be valid pointers
/// - The caller ensures all pointers are valid and properly aligned
/// - This function cleans up plugin state and must be called before plugin unload
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
    if event_data.is_null() || userdata.is_null() {
        return MOSQ_ERR_INVAL;
    }
    let evt = unsafe { &mut *(event_data as *mut MosquittoEvtBasicAuth) };
    let state = unsafe { &*(userdata as *mut PluginState) };

    if evt.password.is_null() {
        return MOSQ_ERR_AUTH;
    }

    let password = unsafe { CStr::from_ptr(evt.password).to_string_lossy() };

    match state.auth_engine.authenticate(&password) {
        Ok(token_type) => {
            let Some(client_id) = mosq_client_id_string(evt.client) else {
                return MOSQ_ERR_AUTH;
            };
            state.cache.insert(
                client_id,
                token_type,
                Duration::from_secs(state.config.cache_ttl_seconds),
            );
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
    if event_data.is_null() || userdata.is_null() {
        return MOSQ_ERR_INVAL;
    }
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

    let data =
        unsafe { std::slice::from_raw_parts(evt.data_in as *const u8, evt.data_in_len as usize) };
    let token = String::from_utf8_lossy(data);

    match state.auth_engine.authenticate(&token) {
        Ok(token_type) => {
            let Some(client_id) = mosq_client_id_string(evt.client) else {
                return MOSQ_ERR_AUTH;
            };
            state.cache.insert(
                client_id,
                token_type,
                Duration::from_secs(state.config.cache_ttl_seconds),
            );
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
    if event_data.is_null() || userdata.is_null() {
        return MOSQ_ERR_INVAL;
    }
    let evt = unsafe { &*(event_data as *mut MosquittoEvtAclCheck) };
    let state = unsafe { &*(userdata as *mut PluginState) };

    if evt.topic.is_null() {
        return MOSQ_ERR_INVAL;
    }

    let Some(client_id) = mosq_client_id_string(evt.client) else {
        return MOSQ_ERR_ACL_DENIED;
    };
    let topic = unsafe { CStr::from_ptr(evt.topic).to_string_lossy() };

    if let Some(token_type) = state.cache.get(&client_id) {
        let params = AuthzParams {
            client_id: &client_id,
            topic: &topic,
            access: evt.access,
            biscuit_root_key: &state.config.biscuit.root_public_key,
            policy_mode: state.config.policy.mode,
            sqlite_policy: state.sqlite_policy.as_ref(),
            http_url: state.config.policy.http_url.as_deref(),
        };
        
        if check_authorization(&token_type, params) {
            return MOSQ_ERR_SUCCESS;
        }
    }

    MOSQ_ERR_ACL_DENIED
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn ffi_init_and_cleanup_are_miri_safe() {
        let jwt_pub_pem = format!("{}/docker/jwt_public.pem", env!("CARGO_MANIFEST_DIR"));
        let biscuit_root_key_hex = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

        let cstrings: Vec<CString> = vec![
            CString::new("jwt_alg").unwrap(),
            CString::new("ES256").unwrap(),
            CString::new("jwt_key_file").unwrap(),
            CString::new(jwt_pub_pem).unwrap(),
            CString::new("biscuit_root_key_hex").unwrap(),
            CString::new(biscuit_root_key_hex).unwrap(),
        ];

        let mut opts = vec![
            MosquittoOpt {
                key: cstrings[0].as_ptr() as *mut c_char,
                value: cstrings[1].as_ptr() as *mut c_char,
            },
            MosquittoOpt {
                key: cstrings[2].as_ptr() as *mut c_char,
                value: cstrings[3].as_ptr() as *mut c_char,
            },
            MosquittoOpt {
                key: cstrings[4].as_ptr() as *mut c_char,
                value: cstrings[5].as_ptr() as *mut c_char,
            },
        ];

        let mut userdata: *mut c_void = ptr::null_mut();
        let userdata_ptr: *mut *mut c_void = &mut userdata;
        let mut identifier = MosquittoPluginId { _unused: [] };

        let rc = unsafe {
            mosquitto_plugin_init(
                &mut identifier,
                userdata_ptr,
                opts.as_mut_ptr(),
                opts.len() as c_int,
            )
        };
        assert_eq!(rc, MOSQ_ERR_SUCCESS);
        assert!(!userdata.is_null());

        let rc = unsafe { mosquitto_plugin_cleanup(userdata, ptr::null_mut(), 0) };
        assert_eq!(rc, MOSQ_ERR_SUCCESS);
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
    let evt = unsafe { &*(event_data as *mut MosquittoEvtMessage) };
    let state = unsafe { &*(userdata as *mut PluginState) };
    if evt.topic.is_null() {
        return MOSQ_ERR_INVAL;
    }

    let Some(client_id) = mosq_client_id_string(evt.client) else {
        return MOSQ_ERR_ACL_DENIED;
    };
    let topic = unsafe { CStr::from_ptr(evt.topic).to_string_lossy() };

    if let Some(token_type) = state.cache.get(&client_id) {
        let params = AuthzParams {
            client_id: &client_id,
            topic: &topic,
            access: 2,
            biscuit_root_key: &state.config.biscuit.root_public_key,
            policy_mode: state.config.policy.mode,
            sqlite_policy: state.sqlite_policy.as_ref(),
            http_url: state.config.policy.http_url.as_deref(),
        };
        
        if check_authorization(&token_type, params) {
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
    if event_data.is_null() || userdata.is_null() {
        return MOSQ_ERR_INVAL;
    }
    let evt = unsafe { &*(event_data as *mut MosquittoEvtControl) };
    let state = unsafe { &*(userdata as *mut PluginState) };
    if evt.topic.is_null() {
        return MOSQ_ERR_INVAL;
    }

    let Some(client_id) = mosq_client_id_string(evt.client) else {
        return MOSQ_ERR_ACL_DENIED;
    };
    let topic = unsafe { CStr::from_ptr(evt.topic).to_string_lossy() };

    if let Some(token_type) = state.cache.get(&client_id) {
        let params = AuthzParams {
            client_id: &client_id,
            topic: &topic,
            access: 2,
            biscuit_root_key: &state.config.biscuit.root_public_key,
            policy_mode: state.config.policy.mode,
            sqlite_policy: state.sqlite_policy.as_ref(),
            http_url: state.config.policy.http_url.as_deref(),
        };
        
        if check_authorization(&token_type, params) {
            return MOSQ_ERR_SUCCESS;
        }
    }
    MOSQ_ERR_ACL_DENIED
}
