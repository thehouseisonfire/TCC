use super::mosquitto_abi::{MosquittoEvtAclCheck, MosquittoEvtControl, MosquittoEvtMessage};
#[cfg(test)]
use std::ffi::c_int;
use std::ffi::{CStr, c_char, c_void};
use std::slice;

pub fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned(),
    )
}

#[inline]
pub const unsafe fn bytes_from_c_void<'a>(ptr: *const c_void, len: usize) -> &'a [u8] {
    unsafe { slice::from_raw_parts(ptr.cast::<u8>(), len) }
}

#[inline]
#[cfg(test)]
pub fn bytes_from_payload_len(payloadlen: c_int) -> Option<usize> {
    usize::try_from(payloadlen).ok().filter(|len| *len > 0)
}

pub const fn control_payload_bytes(evt: &MosquittoEvtControl) -> &[u8] {
    if evt.payload.is_null() || evt.payloadlen == 0 {
        return &[];
    }
    unsafe { bytes_from_c_void(evt.payload, evt.payloadlen as usize) }
}

pub const fn message_payload_bytes(evt: &MosquittoEvtMessage) -> &[u8] {
    if evt.payload.is_null() || evt.payloadlen == 0 {
        return &[];
    }
    unsafe { bytes_from_c_void(evt.payload, evt.payloadlen as usize) }
}

pub const fn acl_payload_bytes(evt: &MosquittoEvtAclCheck) -> &[u8] {
    if evt.payload.is_null() || evt.payloadlen == 0 {
        return &[];
    }
    unsafe { bytes_from_c_void(evt.payload, evt.payloadlen as usize) }
}
