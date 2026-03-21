use crate::auth::TokenType;
use crate::mosquitto_ffi::mosquitto_abi::{
    MOSQ_ACL_CONTROL, MOSQ_ACL_READ, MOSQ_ACL_SUBSCRIBE, MOSQ_ACL_WRITE,
};
use crate::policy::PolicyMode;
use crate::time;
use std::ffi::c_int;
use std::time::Duration;

/// Fallback cache TTL when tokens do not expose an expiry; meant as a sane default only.
const FALLBACK_CACHE_TTL_SECONDS: u64 = 300;
/// Keep expired sessions briefly in cache so ACL callbacks can enforce
/// disconnect-on-expiry semantics deterministically at runtime.
const EXPIRY_DISCONNECT_GRACE_SECONDS: u64 = 10;

#[derive(Debug)]
pub(crate) enum CacheTtlError {
    Expired,
}

impl std::fmt::Display for CacheTtlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Expired => write!(f, "token expired"),
        }
    }
}

pub(crate) fn cache_ttl_for_token(
    token_type: &TokenType,
    configured_ttl_seconds: u64,
) -> Result<Duration, CacheTtlError> {
    let configured_ttl = Duration::from_secs(configured_ttl_seconds);
    let now = time::unix_timestamp_now();
    let expires_at = match token_type {
        TokenType::Jwt { claims, .. } => Some(claims.exp),
        TokenType::Biscuit { expires_at, .. } => *expires_at,
    };

    let ttl = if let Some(exp) = expires_at {
        let remaining = exp - now;
        if remaining <= 0 {
            return Err(CacheTtlError::Expired);
        }
        // Preserve a short post-expiry grace window so ACL_CHECK can still
        // observe expired sessions and force disconnect.
        let remaining_with_grace =
            Duration::from_secs(remaining.cast_unsigned() + EXPIRY_DISCONNECT_GRACE_SECONDS);
        if remaining_with_grace < configured_ttl {
            remaining_with_grace
        } else {
            configured_ttl
        }
    } else {
        let fallback = Duration::from_secs(FALLBACK_CACHE_TTL_SECONDS);
        if fallback < configured_ttl {
            fallback
        } else {
            configured_ttl
        }
    };

    Ok(ttl)
}

pub(crate) fn normalize_username(username: Option<String>) -> Option<String> {
    username.and_then(|u| if u.is_empty() { None } else { Some(u) })
}

pub(crate) const fn should_defer_no_token_basic_auth(
    mode: PolicyMode,
    allow_anonymous_no_token: bool,
) -> bool {
    matches!(
        (mode, allow_anonymous_no_token),
        (PolicyMode::StaticAcl | PolicyMode::StaticAclStrict, _)
            | (PolicyMode::DynamicSecurity, true)
    )
}

pub(crate) const fn is_acl_read_only(access: c_int) -> bool {
    (access & MOSQ_ACL_READ) != 0
        && (access & (MOSQ_ACL_WRITE | MOSQ_ACL_SUBSCRIBE | MOSQ_ACL_CONTROL)) == 0
}
