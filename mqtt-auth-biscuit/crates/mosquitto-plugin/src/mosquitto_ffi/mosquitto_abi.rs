use std::ffi::{c_char, c_int, c_void};

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
    pub _unused: [u8; 0],
}

#[repr(C)]
pub union MosquittoEvtBasicAuthFuture {
    pub future2: [*mut c_void; 4],
    pub password_len: u16,
}

#[repr(C)]
pub struct MosquittoEvtBasicAuth {
    pub future: *mut c_void,
    pub client: *mut c_void,
    pub username: *mut c_char,
    pub password: *mut c_char,
    pub extra: MosquittoEvtBasicAuthFuture,
}

impl MosquittoEvtBasicAuth {
    #[inline]
    pub fn password_len(&self) -> usize {
        unsafe { usize::from(self.extra.password_len) }
    }
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
