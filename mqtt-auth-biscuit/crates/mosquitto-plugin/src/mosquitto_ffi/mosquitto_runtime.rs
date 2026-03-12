use super::ffi_utils::cstr_to_string;
use super::mosquitto_abi::{MQTT_RC_REAUTHENTICATE, MosquittoEvtControl};
use std::ffi::{CString, c_char, c_int, c_void};
use std::ptr;

#[cfg(not(any(test, miri, kani)))]
use super::mosquitto_abi::{
    mosquitto_broker_publish_copy, mosquitto_client_id, mosquitto_client_username,
    mosquitto_kick_client_by_clientid, mosquitto_log_printf, mosquitto_malloc,
    mosquitto_set_username,
};

#[cfg(any(test, miri, kani))]
use super::mosquitto_test_api::{
    mosquitto_broker_publish_copy, mosquitto_client_id, mosquitto_client_username,
    mosquitto_kick_client_by_clientid, mosquitto_malloc, mosquitto_set_username,
};

#[allow(dead_code)]
pub const MOSQ_LOG_INFO: c_int = 1 << 0;
#[allow(dead_code)]
pub const MOSQ_LOG_ERR: c_int = 1 << 3;
#[allow(dead_code)]
pub const MOSQ_LOG_DEBUG: c_int = 1 << 4;

#[cfg(not(any(test, miri, kani)))]
pub fn log_info(msg: &str) {
    if let Ok(c_msg) = CString::new(msg) {
        unsafe {
            mosquitto_log_printf(MOSQ_LOG_INFO, c_msg.as_ptr());
        }
    }
}

#[cfg(any(test, miri, kani))]
pub const fn log_info(_msg: &str) {}

#[cfg(not(any(test, miri, kani)))]
pub fn log_debug(msg: &str) {
    if let Ok(c_msg) = CString::new(msg) {
        unsafe {
            mosquitto_log_printf(MOSQ_LOG_DEBUG, c_msg.as_ptr());
        }
    }
}

#[cfg(any(test, miri, kani))]
pub fn log_debug(msg: &str) {
    #[cfg(test)]
    super::mosquitto_test_api::record_debug_log(msg);
    #[cfg(not(test))]
    let _ = msg;
}

#[cfg(not(any(test, miri, kani)))]
pub fn set_username_raw(client: *mut c_void, username: *const c_char) -> c_int {
    unsafe { mosquitto_set_username(client, username) }
}

#[cfg(any(test, miri, kani))]
pub const fn set_username_raw(client: *mut c_void, username: *const c_char) -> c_int {
    mosquitto_set_username(client, username)
}

#[cfg(not(any(test, miri, kani)))]
pub fn kick_client_by_clientid_raw(clientid: *const c_char, with_will: bool) -> c_int {
    unsafe { mosquitto_kick_client_by_clientid(clientid, with_will) }
}

#[cfg(any(test, miri, kani))]
pub fn kick_client_by_clientid_raw(clientid: *const c_char, with_will: bool) -> c_int {
    mosquitto_kick_client_by_clientid(clientid, with_will)
}

#[cfg(not(any(test, miri, kani)))]
pub fn broker_publish_copy_raw(
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
pub fn broker_publish_copy_raw(
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

#[cfg(not(any(test, miri, kani)))]
pub fn mosquitto_client_id_ptr(client: *const c_void) -> *const c_char {
    unsafe { mosquitto_client_id(client) }
}

#[cfg(any(test, miri, kani))]
pub fn mosquitto_client_id_ptr(client: *const c_void) -> *const c_char {
    mosquitto_client_id(client)
}

#[cfg(not(any(test, miri, kani)))]
pub fn mosquitto_client_username_ptr(client: *const c_void) -> *const c_char {
    unsafe { mosquitto_client_username(client) }
}

#[cfg(any(test, miri, kani))]
pub fn mosquitto_client_username_ptr(client: *const c_void) -> *const c_char {
    mosquitto_client_username(client)
}

pub fn mosq_client_id_string(client: *const c_void) -> Option<String> {
    if client.is_null() {
        return None;
    }
    let ptr = mosquitto_client_id_ptr(client);
    cstr_to_string(ptr)
}

pub fn mosq_client_username_string(client: *const c_void) -> Option<String> {
    if client.is_null() {
        return None;
    }
    let ptr = mosquitto_client_username_ptr(client);
    cstr_to_string(ptr)
}

pub fn set_reason_string(target: *mut *mut c_char, message: &str) {
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

pub fn set_control_reauth_signal(evt: &mut MosquittoEvtControl, message: &str) {
    evt.reason_code = MQTT_RC_REAUTHENTICATE;
    set_reason_string(&raw mut evt.reason_string, message);
}
