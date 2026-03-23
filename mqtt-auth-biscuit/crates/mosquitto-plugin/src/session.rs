use super::PluginState;
use crate::mosquitto_ffi::mosquitto_runtime::log_debug;
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;

#[derive(Debug, Default)]
pub struct SessionIndex {
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

    pub fn client_ids_for_username(&self, username: &str) -> Vec<String> {
        self.client_ids_by_username
            .get(username)
            .map(|ids| ids.iter().cloned().collect())
            .unwrap_or_default()
    }

    fn all_client_ids(&self) -> Vec<String> {
        self.usernames_by_client_id.keys().cloned().collect()
    }
}

#[inline]
pub unsafe fn plugin_state<'a>(userdata: *mut c_void) -> &'a PluginState {
    unsafe { &*userdata.cast::<PluginState>() }
}

#[inline]
#[cfg(any(test, miri, kani))]
pub unsafe fn plugin_state_mut<'a>(userdata: *mut c_void) -> &'a mut PluginState {
    unsafe { &mut *userdata.cast::<PluginState>() }
}

#[inline]
pub unsafe fn event_ref<'a, T>(event_data: *mut c_void) -> &'a T {
    unsafe { &*event_data.cast::<T>() }
}

#[inline]
pub unsafe fn event_mut<'a, T>(event_data: *mut c_void) -> &'a mut T {
    unsafe { &mut *event_data.cast::<T>() }
}

pub fn bind_session_username(state: &PluginState, client_id: &str, username: Option<&str>) {
    if let Ok(mut session_index) = state.session_index.lock() {
        session_index.bind(client_id, username);
    } else {
        log_debug("Session index bind skipped: lock poisoned");
    }
}

pub fn remove_session_username(state: &PluginState, client_id: &str) -> bool {
    state.session_index.lock().map_or_else(
        |_| {
            log_debug("Session index removal skipped: lock poisoned");
            false
        },
        |mut session_index| session_index.remove_client_id(client_id),
    )
}

pub fn prune_session_index_against_cache(state: &PluginState) {
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

pub fn session_client_ids_for_username(state: &PluginState, username: &str) -> Vec<String> {
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
