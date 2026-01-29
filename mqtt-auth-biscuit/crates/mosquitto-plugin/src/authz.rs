use crate::auth::TokenType;
use crate::biscuit_handler::{verify_biscuit_token, BiscuitAuthOutcome};
use crate::dynamic_security_policy::DynamicSecurityPolicy;
use crate::http_policy;
use crate::policy::PolicyMode;
use crate::sqlite_policy::SqlitePolicy;
use biscuit_auth::PublicKey as BiscuitPublicKey;
use chrono::Utc;

/// Lightweight authorization parameters using references to avoid allocations
#[derive(Copy, Clone)]
pub struct AuthzParams<'a> {
    pub username: Option<&'a str>,
    pub client_id: &'a str,
    pub topic: &'a str,
    pub access: i32,
    pub biscuit_root_key: &'a BiscuitPublicKey,
    pub policy_mode: PolicyMode,
    pub sqlite_policy: Option<&'a SqlitePolicy>,
    pub dynamic_security_policy: Option<&'a DynamicSecurityPolicy>,
    pub http_url: Option<&'a str>,
    pub http_ca_file: Option<&'a str>,
    pub http_tls_insecure: bool,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AuthzOutcome {
    Allowed,
    Denied,
    Expired,
}

pub fn check_authorization(token_type: &TokenType, params: AuthzParams<'_>) -> AuthzOutcome {
    match token_type {
        TokenType::Jwt { claims, raw } => {
            if Utc::now().timestamp() >= claims.exp {
                return AuthzOutcome::Expired;
            }

            let token_only = || {
                let roles = claims.roles.as_ref();
                if let Some(roles) = roles {
                    if roles.iter().any(|r| r.trim() == "admin") {
                        return AuthzOutcome::Allowed;
                    }
                }

                let subject = claims.sub.trim();
                let prefix = format!("sensors/{}", subject);
                if params.topic.contains(&prefix) || params.topic.contains(subject) {
                    AuthzOutcome::Allowed
                } else {
                    AuthzOutcome::Denied
                }
            };

            match params.policy_mode {
                PolicyMode::TokenOnly => token_only(),
                PolicyMode::StaticAcl => token_only(),
                PolicyMode::Sqlite => {
                    let Some(sqlite_policy) = params.sqlite_policy else {
                        return AuthzOutcome::Denied;
                    };
                    if sqlite_policy
                        .check(params.client_id, params.topic, params.access)
                        .unwrap_or(false)
                    {
                        AuthzOutcome::Allowed
                    } else {
                        AuthzOutcome::Denied
                    }
                }
                PolicyMode::Http => {
                    let Some(url) = params.http_url else {
                        return AuthzOutcome::Denied;
                    };
                    let allowed = http_policy::check_http(
                        url,
                        params.client_id,
                        params.topic,
                        params.access,
                        Some(raw),
                        params.http_ca_file,
                        params.http_tls_insecure,
                    )
                    .unwrap_or(false);
                    if allowed {
                        AuthzOutcome::Allowed
                    } else {
                        AuthzOutcome::Denied
                    }
                }
                PolicyMode::Hybrid => {
                    let Some(url) = params.http_url else {
                        return token_only();
                    };

                    match http_policy::check_http(
                        url,
                        params.client_id,
                        params.topic,
                        params.access,
                        Some(raw),
                        params.http_ca_file,
                        params.http_tls_insecure,
                    ) {
                        Ok(allowed) => {
                            if allowed {
                                AuthzOutcome::Allowed
                            } else {
                                AuthzOutcome::Denied
                            }
                        }
                        Err(_) => token_only(),
                    }
                }
                PolicyMode::DynamicSecurity => {
                    let Some(policy) = params.dynamic_security_policy else {
                        return AuthzOutcome::Denied;
                    };
                    if policy
                        .check(
                            params.username,
                            Some(params.client_id),
                            params.topic,
                            params.access,
                        )
                        .unwrap_or(false)
                    {
                        AuthzOutcome::Allowed
                    } else {
                        AuthzOutcome::Denied
                    }
                }
            }
        }
        TokenType::Biscuit {
            bytes,
            expires_at,
            roles: _,
        } => {
            if let Some(expires_at) = expires_at {
                if Utc::now().timestamp() >= *expires_at {
                    return AuthzOutcome::Expired;
                }
            }

            let operation = if (params.access & 0x02) != 0 {
                "publish"
            } else if (params.access & 0x04) != 0 || (params.access & 0x01) != 0 {
                "subscribe"
            } else {
                "read"
            };

            let token_only = || match verify_biscuit_token(
                bytes,
                params.biscuit_root_key,
                params.topic,
                operation,
            ) {
                BiscuitAuthOutcome::Allowed => AuthzOutcome::Allowed,
                BiscuitAuthOutcome::Denied => AuthzOutcome::Denied,
                BiscuitAuthOutcome::Error(err) => {
                    let _ = err;
                    AuthzOutcome::Denied
                }
            };

            match params.policy_mode {
                PolicyMode::TokenOnly => token_only(),
                PolicyMode::StaticAcl => token_only(),
                PolicyMode::Sqlite => {
                    let Some(sqlite_policy) = params.sqlite_policy else {
                        return AuthzOutcome::Denied;
                    };
                    if sqlite_policy
                        .check(params.client_id, params.topic, params.access)
                        .unwrap_or(false)
                    {
                        AuthzOutcome::Allowed
                    } else {
                        AuthzOutcome::Denied
                    }
                }
                PolicyMode::Http => {
                    let Some(url) = params.http_url else {
                        return AuthzOutcome::Denied;
                    };
                    let allowed = http_policy::check_http(
                        url,
                        params.client_id,
                        params.topic,
                        params.access,
                        None,
                        params.http_ca_file,
                        params.http_tls_insecure,
                    )
                    .unwrap_or(false);
                    if allowed {
                        AuthzOutcome::Allowed
                    } else {
                        AuthzOutcome::Denied
                    }
                }
                PolicyMode::Hybrid => {
                    let Some(url) = params.http_url else {
                        return token_only();
                    };

                    match http_policy::check_http(
                        url,
                        params.client_id,
                        params.topic,
                        params.access,
                        None,
                        params.http_ca_file,
                        params.http_tls_insecure,
                    ) {
                        Ok(allowed) => {
                            if allowed {
                                AuthzOutcome::Allowed
                            } else {
                                AuthzOutcome::Denied
                            }
                        }
                        Err(_) => token_only(),
                    }
                }
                PolicyMode::DynamicSecurity => {
                    let Some(policy) = params.dynamic_security_policy else {
                        return AuthzOutcome::Denied;
                    };
                    if policy
                        .check(
                            params.username,
                            Some(params.client_id),
                            params.topic,
                            params.access,
                        )
                        .unwrap_or(false)
                    {
                        AuthzOutcome::Allowed
                    } else {
                        AuthzOutcome::Denied
                    }
                }
            }
        }
    }
}
