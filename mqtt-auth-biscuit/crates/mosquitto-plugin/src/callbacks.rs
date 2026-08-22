use super::{
    apply_dynamic_security_control_enforcement, disconnect_expired_acl_client,
    log_static_acl_policy_bias,
};
use crate::auth::AuthError;
use crate::auth_runtime::{
    cache_ttl_for_token, is_acl_read_only, normalize_username, should_defer_no_token_basic_auth,
};
use crate::authz::{AuthzOutcome, AuthzParams, check_authorization, check_token_expiry};
use crate::identity_binding::enforce_identity_binding;
use crate::mosquitto_ffi::ffi_utils::{
    acl_payload_bytes, bytes_from_c_void, control_payload_bytes, message_payload_bytes,
};
use crate::mosquitto_ffi::mosquitto_abi::{
    MOSQ_ACL_CONTROL, MOSQ_ACL_WRITE, MOSQ_ERR_ACL_DENIED, MOSQ_ERR_AUTH, MOSQ_ERR_INVAL,
    MOSQ_ERR_PLUGIN_DEFER, MOSQ_ERR_SUCCESS, MosquittoEvtAclCheck, MosquittoEvtBasicAuth,
    MosquittoEvtControl, MosquittoEvtExtendedAuth, MosquittoEvtMessage,
};
use crate::mosquitto_ffi::mosquitto_runtime::{
    log_debug, mosq_client_id_string, mosq_client_username_string, set_control_reauth_signal,
};
use crate::policy::PolicyMode;
use crate::session::{
    bind_session_username, event_mut, event_ref, plugin_state, prune_session_index_against_cache,
};
use crate::token_utils::{attach_biscuit_expiry, attach_biscuit_roles, set_synthetic_username};
use std::ffi::c_int;
use std::ffi::{CStr, c_void};
use std::slice;
use std::sync::atomic::Ordering;

pub extern "C" fn basic_auth_callback(
    _event: c_int,
    event_data: *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    if event_data.is_null() || userdata.is_null() {
        return MOSQ_ERR_INVAL;
    }
    let evt = unsafe { event_mut::<MosquittoEvtBasicAuth>(event_data) };
    let state = unsafe { plugin_state(userdata) };
    state.auth_metrics.attempts.fetch_add(1, Ordering::Relaxed);

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

    let password_len = evt.password_len();
    if password_len == 0 {
        return if should_defer_no_token_basic_auth(
            state.config.policy.mode,
            state.config.allow_anonymous_no_token,
        ) {
            MOSQ_ERR_PLUGIN_DEFER
        } else {
            MOSQ_ERR_AUTH
        };
    }
    let password = unsafe { slice::from_raw_parts(evt.password.cast::<u8>(), password_len) };

    match state.auth_engine.authenticate_basic(password) {
        Ok(token_type) => {
            match &token_type {
                crate::auth::TokenType::Jwt { .. } => state
                    .auth_metrics
                    .jwt_validations
                    .fetch_add(1, Ordering::Relaxed),
                crate::auth::TokenType::Biscuit { .. } => state
                    .auth_metrics
                    .biscuit_validations
                    .fetch_add(1, Ordering::Relaxed),
            };
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
            let Some(client_id) = mosq_client_id_string(evt.client) else {
                log_debug("Authentication rejected: live MQTT client_id missing");
                return MOSQ_ERR_AUTH;
            };
            if let Err(err) =
                enforce_identity_binding(&token_type, Some(client_id.as_str()), &state.config)
            {
                log_debug(&format!("Authentication rejected: {err}"));
                return MOSQ_ERR_AUTH;
            }
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
            state.cache.insert(client_id.clone(), token_type, cache_ttl);
            prune_session_index_against_cache(state);
            let session_username = mosq_client_username_string(evt.client);
            bind_session_username(state, &client_id, session_username.as_deref());
            state.auth_metrics.successes.fetch_add(1, Ordering::Relaxed);
            if state.config.benchmark_diagnostics {
                state.auth_metrics.log_snapshot(&state.cache);
            }
            MOSQ_ERR_SUCCESS
        }
        Err(AuthError::Expired) => {
            state.auth_metrics.failures.fetch_add(1, Ordering::Relaxed);
            if state.config.benchmark_diagnostics {
                state.auth_metrics.log_snapshot(&state.cache);
            }
            log_debug("Authentication rejected: token expired");
            MOSQ_ERR_AUTH
        }
        Err(AuthError::Invalid(msg)) => {
            state.auth_metrics.failures.fetch_add(1, Ordering::Relaxed);
            if state.config.benchmark_diagnostics {
                state.auth_metrics.log_snapshot(&state.cache);
            }
            log_debug(&format!("Authentication rejected: {msg}"));
            MOSQ_ERR_AUTH
        }
    }
}

pub extern "C" fn ext_auth_start_callback(
    _event: c_int,
    event_data: *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    if event_data.is_null() || userdata.is_null() {
        return MOSQ_ERR_INVAL;
    }
    let evt = unsafe { event_mut::<MosquittoEvtExtendedAuth>(event_data) };
    let state = unsafe { plugin_state(userdata) };

    if !state.config.ext_auth_method.as_deref().is_some_and(|m| {
        if evt.auth_method.is_null() {
            return false;
        }
        let am = unsafe { CStr::from_ptr(evt.auth_method).to_string_lossy() };
        am == m
    }) {
        return MOSQ_ERR_PLUGIN_DEFER;
    }

    if evt.data_in.is_null() || evt.data_in_len == 0 {
        return MOSQ_ERR_AUTH;
    }

    let data = unsafe { bytes_from_c_void(evt.data_in, evt.data_in_len as usize) };

    match state.auth_engine.authenticate_binary(data) {
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
            let Some(client_id) = mosq_client_id_string(evt.client) else {
                log_debug("Enhanced auth rejected: live MQTT client_id missing");
                return MOSQ_ERR_AUTH;
            };
            if let Err(err) =
                enforce_identity_binding(&token_type, Some(client_id.as_str()), &state.config)
            {
                log_debug(&format!("Enhanced auth rejected: {err}"));
                return MOSQ_ERR_AUTH;
            }
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

pub extern "C" fn ext_auth_continue_callback(
    event: c_int,
    event_data: *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    // For this plugin, we treat auth as single-step: new token in data_in.
    ext_auth_start_callback(event, event_data, userdata)
}

pub extern "C" fn acl_check_callback(
    _event: c_int,
    event_data: *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    // ACL callbacks are the authoritative data-plane gate but do not carry
    // MQTT v5 reason signaling fields. Expired sessions are denied and kicked.
    if event_data.is_null() || userdata.is_null() {
        return MOSQ_ERR_INVAL;
    }
    let evt = unsafe { event_ref::<MosquittoEvtAclCheck>(event_data) };
    let state = unsafe { plugin_state(userdata) };

    if evt.topic.is_null() {
        return MOSQ_ERR_INVAL;
    }

    let Some(client_id) = mosq_client_id_string(evt.client) else {
        return MOSQ_ERR_ACL_DENIED;
    };
    let username = normalize_username(mosq_client_username_string(evt.client));
    let topic = unsafe { CStr::from_ptr(evt.topic).to_string_lossy() };

    let cached_token = state.cache.get(&client_id);
    if state.config.benchmark_diagnostics {
        state.auth_metrics.observe_cache(&state.cache);
    }
    if let Some(token_type) = cached_token {
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

pub extern "C" fn message_callback(
    _event: c_int,
    event_data: *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    if event_data.is_null() || userdata.is_null() {
        return MOSQ_ERR_INVAL;
    }
    let evt = unsafe { event_mut::<MosquittoEvtMessage>(event_data) };
    let state = unsafe { plugin_state(userdata) };
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
/// ### Variant A: Kick/Re-authenticate (No `ACL_READ` checks)
/// - Immediately disconnect affected clients
/// - Clients must re-authenticate with new token reflecting updated policies
/// - Lower overhead for high fan-out scenarios
/// - Requires clients to handle reconnection gracefully
///
/// ### Variant B: `ACL_READ` + Warning Publication
/// - Keep sessions alive
/// - Enforce new policies via `ACL_READ` on next message delivery
/// - Publish warning to affected clients (e.g., `system/notification/<client_id>`)
/// - Higher per-message overhead but no disruption
/// - Clients learn of privilege changes via notification topic
///
/// The plugin supports both variants through policy configuration:
/// - `DynamicSecurity` mode: Supports control-triggered kick for `disableClient`
/// - SQLite/HTTP modes: Configurable per deployment
///
/// ## Research Alignment
///
/// This callback enables H₂/H₃ validation by measuring:
/// - Control-plane latency vs data-plane (token verification costs)
/// - Policy churn impact (cache invalidation overhead)
/// - Enforcement variant comparison (kick vs `ACL_READ` scaling)
pub extern "C" fn control_callback(
    _event: c_int,
    event_data: *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    if event_data.is_null() || userdata.is_null() {
        return MOSQ_ERR_INVAL;
    }
    let evt = unsafe { event_mut::<MosquittoEvtControl>(event_data) };
    let state = unsafe { plugin_state(userdata) };
    if evt.topic.is_null() {
        return MOSQ_ERR_INVAL;
    }

    let topic = unsafe { CStr::from_ptr(evt.topic).to_string_lossy() };

    // CONTROL callback only processes $CONTROL/... topics per Mosquitto semantics.
    // Non-control topics are deferred to other plugins or default ACLs.
    if !topic.starts_with("$CONTROL/") {
        log_debug(&format!(
            "Control callback: deferring non-control topic '{topic}'"
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
                    "Control authorized: client={client_id} topic={topic}"
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
                    "Control rejected (expired): client={client_id} topic={topic}"
                ));
                return MOSQ_ERR_ACL_DENIED;
            }
            AuthzOutcome::Denied => {
                log_debug(&format!("Control denied: client={client_id} topic={topic}"));
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
            "Control rejected (no session): client={client_id} topic={topic}"
        ));
    }
    MOSQ_ERR_ACL_DENIED
}
