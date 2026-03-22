use std::ffi::{c_char, c_int, c_void};
#[cfg(test)]
use std::{cell::RefCell, thread_local};

#[cfg(test)]
use super::ffi_utils::{bytes_from_c_void, bytes_from_payload_len, cstr_to_string};
use super::mosquitto_abi::MOSQ_ERR_SUCCESS;

pub static TEST_CLIENT_ID: &[u8; 12] = b"test_client\0";
pub static TEST_USERNAME: &[u8; 10] = b"test_user\0";

#[unsafe(no_mangle)]
pub const extern "C" fn mosquitto_set_username(
    _client: *mut c_void,
    _username: *const c_char,
) -> c_int {
    MOSQ_ERR_SUCCESS
}

#[unsafe(no_mangle)]
pub extern "C" fn mosquitto_kick_client_by_clientid(
    clientid: *const c_char,
    with_will: bool,
) -> c_int {
    #[cfg(test)]
    record_kick_client_call(clientid, with_will);
    MOSQ_ERR_SUCCESS
}

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

#[unsafe(no_mangle)]
pub extern "C" fn mosquitto_client_id(_client: *const c_void) -> *const c_char {
    TEST_CLIENT_ID.as_ptr().cast::<c_char>()
}

#[unsafe(no_mangle)]
pub extern "C" fn mosquitto_client_username(_client: *const c_void) -> *const c_char {
    TEST_USERNAME.as_ptr().cast::<c_char>()
}

#[unsafe(no_mangle)]
pub extern "C" fn mosquitto_malloc(size: usize) -> *mut c_void {
    unsafe { libc::malloc(size) }
}

#[cfg(test)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KickClientCall {
    pub count: usize,
    pub last_client_id: Option<String>,
    pub last_with_will: Option<bool>,
}

#[cfg(test)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BrokerPublishCall {
    pub count: usize,
    pub last_client_id: Option<String>,
    pub last_topic: Option<String>,
    pub last_payload: Option<String>,
    pub last_qos: Option<c_int>,
    pub last_retain: Option<bool>,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestControlAction {
    Kick { client_id: Option<String> },
    Publish { client_id: Option<String> },
}

#[cfg(test)]
thread_local! {
    static TEST_KICK_CLIENT_CALL: RefCell<KickClientCall> = RefCell::new(KickClientCall::default());
    static TEST_BROKER_PUBLISH_CALL: RefCell<BrokerPublishCall> = RefCell::new(BrokerPublishCall::default());
    static TEST_CONTROL_ACTIONS: RefCell<Vec<TestControlAction>> = const { RefCell::new(Vec::new()) };
    static TEST_DEBUG_LOGS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

#[cfg(test)]
pub fn reset_kick_client_call() {
    TEST_KICK_CLIENT_CALL.with(|call| {
        *call.borrow_mut() = KickClientCall::default();
    });
}

#[cfg(test)]
pub fn reset_broker_publish_call() {
    TEST_BROKER_PUBLISH_CALL.with(|call| {
        *call.borrow_mut() = BrokerPublishCall::default();
    });
}

#[cfg(test)]
pub fn kick_client_call_snapshot() -> KickClientCall {
    TEST_KICK_CLIENT_CALL.with(|call| call.borrow().clone())
}

#[cfg(test)]
pub fn broker_publish_call_snapshot() -> BrokerPublishCall {
    TEST_BROKER_PUBLISH_CALL.with(|call| call.borrow().clone())
}

#[cfg(test)]
pub fn reset_control_action_log() {
    TEST_CONTROL_ACTIONS.with(|actions| actions.borrow_mut().clear());
}

#[cfg(test)]
pub fn control_action_log_snapshot() -> Vec<TestControlAction> {
    TEST_CONTROL_ACTIONS.with(|actions| actions.borrow().clone())
}

#[cfg(test)]
pub fn reset_debug_logs() {
    TEST_DEBUG_LOGS.with(|logs| logs.borrow_mut().clear());
}

#[cfg(test)]
pub fn debug_logs_snapshot() -> Vec<String> {
    TEST_DEBUG_LOGS.with(|logs| logs.borrow().clone())
}

#[cfg(test)]
pub fn record_debug_log(message: &str) {
    TEST_DEBUG_LOGS.with(|logs| logs.borrow_mut().push(message.to_string()));
}

#[cfg(test)]
pub fn record_kick_client_call(clientid: *const c_char, with_will: bool) {
    let client_id_text = cstr_to_string(clientid);
    TEST_KICK_CLIENT_CALL.with(|call| {
        let mut state = call.borrow_mut();
        state.count += 1;
        state.last_client_id = client_id_text.clone();
        state.last_with_will = Some(with_will);
    });
    TEST_CONTROL_ACTIONS.with(|actions| {
        actions.borrow_mut().push(TestControlAction::Kick {
            client_id: client_id_text,
        });
    });
}

#[cfg(test)]
pub fn record_broker_publish_call(
    clientid: *const c_char,
    topic: *const c_char,
    payloadlen: c_int,
    payload: *const c_void,
    qos: c_int,
    retain: bool,
) {
    let client_id_text = cstr_to_string(clientid);
    let payload_text = if payload.is_null() {
        Some(String::new())
    } else {
        bytes_from_payload_len(payloadlen).map_or(Some(String::new()), |len| {
            let bytes = unsafe { bytes_from_c_void(payload, len) };
            Some(String::from_utf8_lossy(bytes).into_owned())
        })
    };
    TEST_BROKER_PUBLISH_CALL.with(|call| {
        let mut state = call.borrow_mut();
        state.count += 1;
        state.last_client_id = client_id_text.clone();
        state.last_topic = cstr_to_string(topic);
        state.last_payload = payload_text;
        state.last_qos = Some(qos);
        state.last_retain = Some(retain);
    });
    TEST_CONTROL_ACTIONS.with(|actions| {
        actions.borrow_mut().push(TestControlAction::Publish {
            client_id: client_id_text,
        });
    });
}
