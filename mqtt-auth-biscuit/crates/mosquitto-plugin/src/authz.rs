use crate::auth::TokenType;
use crate::biscuit_handler::verify_biscuit_token;
use crate::http_policy;
use crate::policy::PolicyMode;
use crate::sqlite_policy::SqlitePolicy;
use biscuit_auth::PublicKey as BiscuitPublicKey;
use chrono::Utc;

/// Lightweight authorization parameters using references to avoid allocations
#[derive(Copy, Clone)]
pub struct AuthzParams<'a> {
    pub client_id: &'a str,
    pub topic: &'a str,
    pub access: i32,
    pub biscuit_root_key: &'a BiscuitPublicKey,
    pub policy_mode: PolicyMode,
    pub sqlite_policy: Option<&'a SqlitePolicy>,
    pub http_url: Option<&'a str>,
    pub http_ca_file: Option<&'a str>,
    pub http_tls_insecure: bool,
}

pub fn check_authorization(
    token_type: &TokenType,
    params: AuthzParams<'_>,
) -> bool {
    match token_type {
        TokenType::Jwt { claims, raw } => {
            if Utc::now().timestamp() >= claims.exp {
                return false;
            }

            let token_only = || {
                let roles = claims.roles.as_ref();
                if let Some(roles) = roles {
                    if roles.iter().any(|r| r.trim() == "admin") {
                        return true;
                    }
                }

                let subject = claims.sub.trim();
                let prefix = format!("sensors/{}", subject);
                params.topic.contains(&prefix) || params.topic.contains(subject)
            };

            match params.policy_mode {
                PolicyMode::TokenOnly => token_only(),
                PolicyMode::Sqlite => {
                    let Some(sqlite_policy) = params.sqlite_policy else {
                        return false;
                    };
                    sqlite_policy
                        .check(params.client_id, params.topic, params.access)
                        .unwrap_or(false)
                }
                PolicyMode::Http => {
                    let Some(url) = params.http_url else { return false };
                    http_policy::check_http(
                        url,
                        params.client_id,
                        params.topic,
                        params.access,
                        Some(raw),
                        params.http_ca_file,
                        params.http_tls_insecure,
                    )
                        .unwrap_or(false)
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
                        Ok(allowed) => allowed,
                        Err(_) => token_only(),
                    }
                }
            }
        }
        TokenType::Biscuit(token_bytes) => {
            let operation = if (params.access & 0x02) != 0 {
                "publish"
            } else if (params.access & 0x04) != 0 || (params.access & 0x01) != 0 {
                "subscribe"
            } else {
                "read"
            };

            let token_only = || {
                verify_biscuit_token(token_bytes, params.biscuit_root_key, params.topic, operation)
                    .unwrap_or(false)
            };

            match params.policy_mode {
                PolicyMode::TokenOnly => token_only(),
                PolicyMode::Sqlite => {
                    let Some(sqlite_policy) = params.sqlite_policy else {
                        return false;
                    };
                    sqlite_policy
                        .check(params.client_id, params.topic, params.access)
                        .unwrap_or(false)
                }
                PolicyMode::Http => {
                    let Some(url) = params.http_url else { return false };
                    http_policy::check_http(
                        url,
                        params.client_id,
                        params.topic,
                        params.access,
                        None,
                        params.http_ca_file,
                        params.http_tls_insecure,
                    )
                    .unwrap_or(false)
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
                        Ok(allowed) => allowed,
                        Err(_) => token_only(),
                    }
                }
            }
        }
    }
}
