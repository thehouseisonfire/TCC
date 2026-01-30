use crate::auth::TokenType;
use crate::biscuit_handler::{verify_biscuit_token, BiscuitAuthOutcome};
use crate::dynamic_security_policy::DynamicSecurityPolicy;
use crate::http_policy;
use crate::jwt_handler::JwtGrant;
use crate::policy::PolicyMode;
use crate::sqlite_policy::SqlitePolicy;
use biscuit_auth::PublicKey as BiscuitPublicKey;
use chrono::Utc;

// Mosquitto ACL access bitmask mapping:
// MOSQ_ACL_READ=0x01, MOSQ_ACL_WRITE=0x02, MOSQ_ACL_SUBSCRIBE=0x04.
fn access_to_operation(access: i32) -> &'static str {
    if (access & 0x02) != 0 {
        "publish"
    } else if (access & 0x04) != 0 {
        "subscribe"
    } else {
        "read"
    }
}

#[cfg(test)]
mod tests {
    use super::topic_matches;

    #[test]
    fn topic_matches_exact() {
        assert!(topic_matches(
            "sensors/client_1/temp",
            "sensors/client_1/temp"
        ));
        assert!(!topic_matches(
            "sensors/client_1/temp",
            "sensors/client_1/humidity"
        ));
    }

    #[test]
    fn topic_matches_single_level_wildcard() {
        assert!(topic_matches("sensors/+/temp", "sensors/client_1/temp"));
        assert!(!topic_matches(
            "sensors/+/temp",
            "sensors/client_1/humidity"
        ));
        assert!(!topic_matches(
            "sensors/+/temp",
            "sensors/client_1/temp/extra"
        ));
    }

    #[test]
    fn topic_matches_multi_level_wildcard() {
        assert!(topic_matches("sensors/#", "sensors/client_1/temp"));
        assert!(topic_matches("#", "sensors/client_1/temp"));
        assert!(topic_matches("sensors/client_1/#", "sensors/client_1"));
        assert!(topic_matches("sensors/client_1/#", "sensors/client_1/temp"));
        assert!(!topic_matches("devices/#", "sensors/client_1/temp"));
    }

    #[test]
    fn topic_matches_invalid_filters() {
        assert!(!topic_matches("sensors/#/temp", "sensors/client_1/temp"));
        assert!(!topic_matches("sensors/#/", "sensors/client_1/temp"));
        assert!(!topic_matches("sensors/#/foo", "sensors/client_1/foo"));
        assert!(!topic_matches("sensors/#/foo", "sensors/client_1/temp"));
    }

    #[test]
    fn grants_allow_read_fallback() {
        use crate::jwt_handler::JwtGrant;

        let topic = "sensors/client_1/temp";
        let grants = vec![
            JwtGrant {
                op: "subscribe".to_string(),
                res: "sensors/client_1/#".to_string(),
            },
            JwtGrant {
                op: "publish".to_string(),
                res: "sensors/client_1/temp".to_string(),
            },
        ];

        assert!(super::grants_allow(&grants, "read", topic));
        assert!(super::grants_allow(&grants, "subscribe", topic));
        assert!(!super::grants_allow(
            &grants,
            "read",
            "sensors/client_2/temp"
        ));

        let read_grants = vec![
            JwtGrant {
                op: "read".to_string(),
                res: "sensors/client_1/temp".to_string(),
            },
            JwtGrant {
                op: "subscribe".to_string(),
                res: "sensors/client_1/#".to_string(),
            },
        ];
        assert!(super::grants_allow(&read_grants, "read", topic));
        assert!(!super::grants_allow(
            &read_grants,
            "read",
            "sensors/client_2/temp"
        ));
    }

    #[test]
    fn grants_deny_overrides_allow() {
        use crate::jwt_handler::JwtGrant;

        let topic = "sensors/client_1/temp";
        let grants = vec![
            JwtGrant {
                op: "subscribe".to_string(),
                res: "sensors/client_1/#".to_string(),
            },
            JwtGrant {
                op: "read".to_string(),
                res: "sensors/client_1/temp".to_string(),
            },
        ];
        let denies = vec![JwtGrant {
            op: "read".to_string(),
            res: "sensors/client_1/temp".to_string(),
        }];

        assert!(super::grants_allow(&grants, "read", topic));
        assert!(super::grants_deny(&denies, "read", topic));
        assert!(!super::grants_deny(&denies, "subscribe", topic));
    }

    #[test]
    fn grants_deny_read_fallback_to_subscribe() {
        use crate::jwt_handler::JwtGrant;

        let topic = "sensors/client_1/temp";
        let grants = vec![JwtGrant {
            op: "subscribe".to_string(),
            res: "sensors/client_1/#".to_string(),
        }];
        let denies = vec![JwtGrant {
            op: "subscribe".to_string(),
            res: "sensors/client_1/#".to_string(),
        }];

        assert!(super::grants_allow(&grants, "read", topic));
        assert!(super::grants_deny(&denies, "read", topic));
    }

    #[test]
    fn access_to_operation_bitmask_priority() {
        assert_eq!(super::access_to_operation(0x02), "publish");
        assert_eq!(super::access_to_operation(0x04), "subscribe");
        assert_eq!(super::access_to_operation(0x01), "read");
        assert_eq!(super::access_to_operation(0x00), "read");
        assert_eq!(super::access_to_operation(0x02 | 0x04), "publish");
        assert_eq!(super::access_to_operation(0x04 | 0x01), "subscribe");
    }
}

fn is_valid_filter(filter: &str) -> bool {
    let mut saw_hash = false;
    let parts: Vec<&str> = filter.split('/').collect();
    for (idx, part) in parts.iter().enumerate() {
        if part.contains('#') {
            if *part != "#" || saw_hash || idx != parts.len() - 1 {
                return false;
            }
            saw_hash = true;
        }
    }
    true
}

fn topic_matches(filter: &str, topic: &str) -> bool {
    if !is_valid_filter(filter) {
        return false;
    }
    if filter == "#" {
        return true;
    }

    let filter_parts: Vec<&str> = filter.split('/').collect();
    let topic_parts: Vec<&str> = topic.split('/').collect();
    let mut i = 0;

    while i < filter_parts.len() {
        let fp = filter_parts[i];
        if fp == "#" {
            return true;
        }
        if i >= topic_parts.len() {
            return false;
        }
        if fp != "+" && fp != topic_parts[i] {
            return false;
        }
        i += 1;
    }

    i == topic_parts.len()
}

fn grants_allow(grants: &[JwtGrant], operation: &str, topic: &str) -> bool {
    let op = operation.trim();
    if op == "read" {
        let has_read = grants
            .iter()
            .any(|grant| grant.op.trim() == "read" && topic_matches(grant.res.trim(), topic));
        if has_read {
            return true;
        }
        return grants
            .iter()
            .any(|grant| grant.op.trim() == "subscribe" && topic_matches(grant.res.trim(), topic));
    }

    grants
        .iter()
        .any(|grant| grant.op.trim() == op && topic_matches(grant.res.trim(), topic))
}

fn grants_deny(denies: &[JwtGrant], operation: &str, topic: &str) -> bool {
    let op = operation.trim();
    if op == "read" {
        if denies
            .iter()
            .any(|deny| deny.op.trim() == "read" && topic_matches(deny.res.trim(), topic))
        {
            return true;
        }
        return denies
            .iter()
            .any(|deny| deny.op.trim() == "subscribe" && topic_matches(deny.res.trim(), topic));
    }

    denies
        .iter()
        .any(|deny| deny.op.trim() == op && topic_matches(deny.res.trim(), topic))
}

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
                let Some(grants) = claims.grants.as_ref() else {
                    return AuthzOutcome::Denied;
                };
                let operation = access_to_operation(params.access);
                if let Some(denies) = claims.denies.as_ref() {
                    if grants_deny(denies, operation, params.topic) {
                        return AuthzOutcome::Denied;
                    }
                }
                if grants_allow(grants, operation, params.topic) {
                    AuthzOutcome::Allowed
                } else {
                    AuthzOutcome::Denied
                }
            };

            match params.policy_mode {
                PolicyMode::TokenOnly => token_only(),
                PolicyMode::StaticAcl => token_only(),
                PolicyMode::StaticAclStrict => token_only(),
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

            let operation = access_to_operation(params.access);

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
                PolicyMode::StaticAclStrict => token_only(),
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
