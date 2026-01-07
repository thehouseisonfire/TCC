use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr;
use std::sync::Arc;
use crate::auth::{AuthEngine, TokenType};
use crate::authz::check_authorization;
use crate::cache::SessionCache;
use jsonwebtoken::DecodingKey;
use biscuit_auth::PublicKey as BiscuitPublicKey;
use std::time::Duration;

mod auth;
mod authz;
mod jwt_handler;
mod biscuit_handler;
mod cache;

// Mosquitto Error Codes
pub const MOSQ_ERR_SUCCESS: c_int = 0;
pub const MOSQ_ERR_NOMEM: c_int = 1;
pub const MOSQ_ERR_INVAL: c_int = 3;
pub const MOSQ_ERR_AUTH: c_int = 11;
pub const MOSQ_ERR_ACL_DENIED: c_int = 12;
pub const MOSQ_ERR_PLUGIN_DEFER: c_int = 17;

// Mosquitto Event Types
pub const MOSQ_EVT_ACL_CHECK: c_int = 2;
pub const MOSQ_EVT_BASIC_AUTH: c_int = 3;

#[repr(C)]
pub struct MosquittoOpt {
    pub key: *mut c_char,
    pub value: *mut c_char,
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
    biscuit_root_key: BiscuitPublicKey,
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
    _options: *mut MosquittoOpt,
    _option_count: c_int,
) -> c_int {
    // In a real implementation, keys would be loaded from _options
    // For now, using dummy keys or placeholders
    
    // Placeholder JWT Key (needs to be actual RSA/EC key for RS256)
    // For simplicity in this demo, we'll use a weak one or skip actual verification if needed
    // but here we try to follow the guide.
    let jwt_key = DecodingKey::from_secret(b"secret"); // This is for HS256, guide says RS256. 
    // I'll adjust to HS256 for the demo if needed, or generate one.
    
    // Biscuit root key
    let biscuit_root_key_bytes = [0u8; 32];
    let biscuit_root_key = BiscuitPublicKey::from_bytes(&biscuit_root_key_bytes, biscuit_auth::Algorithm::Ed25519).unwrap();

    let state = Box::new(PluginState {
        auth_engine: Arc::new(AuthEngine::new(jwt_key, biscuit_root_key)),
        cache: Arc::new(SessionCache::new(1000)),
        biscuit_root_key,
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
            state.cache.insert(client_id, token_type, Duration::from_secs(3600));
            MOSQ_ERR_SUCCESS
        }
        Err(_) => MOSQ_ERR_AUTH,
    }
}

extern "C" fn acl_check_callback(
    _event: c_int,
    event_data: *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    let evt = unsafe { &*(event_data as *mut MosquittoEvtAclCheck) };
    let state = unsafe { &*(userdata as *mut PluginState) };

    let client_id = unsafe { CStr::from_ptr(mosquitto_client_id(evt.client)).to_string_lossy() };
    let topic = unsafe { CStr::from_ptr(evt.topic).to_string_lossy() };

    if let Some(token_type) = state.cache.get(&client_id.into_owned()) {
        if check_authorization(&token_type, &topic, evt.access, &state.biscuit_root_key) {
            return MOSQ_ERR_SUCCESS;
        }
    }

    MOSQ_ERR_ACL_DENIED
}
