use crate::STATIC_ACL_ROLE_MISSING_WARN_ONCE;
use crate::auth::TokenType;
use crate::biscuit_handler::{
    extract_min_expiry_from_biscuit_with_limits, extract_roles_from_biscuit_with_limits,
    parse_biscuit,
};
use crate::config::PluginConfig;
use crate::mosquitto_ffi::mosquitto_abi::MOSQ_ERR_SUCCESS;
use crate::mosquitto_ffi::mosquitto_runtime::{log_debug, set_username_raw};
use crate::policy::PolicyMode;
use std::ffi::{CString, c_void};

pub(crate) fn attach_biscuit_expiry(
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
        other @ TokenType::Jwt { .. } => Ok(other),
    }
}

pub(crate) fn attach_biscuit_roles(token_type: TokenType, config: &PluginConfig) -> TokenType {
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
        other @ TokenType::Jwt { .. } => other,
    }
}

pub(crate) fn select_preferred_role(roles: &[String]) -> Option<String> {
    if roles.is_empty() {
        return None;
    }
    if roles.len() > 1 {
        log_debug(&format!(
            "Static ACL role selection prefers a single role; candidates={roles:?}"
        ));
    }
    if let Some(role) = roles.iter().find(|r| r.trim() == "admin") {
        return Some(role.clone());
    }
    roles.iter().find(|r| !r.trim().is_empty()).cloned()
}

pub(crate) fn role_to_username(token_type: &TokenType, config: &PluginConfig) -> Option<String> {
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
            let roles = roles.clone().or_else(|| {
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
pub(crate) fn set_synthetic_username(
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
