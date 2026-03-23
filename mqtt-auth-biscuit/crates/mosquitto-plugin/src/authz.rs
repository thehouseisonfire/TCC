use crate::auth::TokenType;
use crate::biscuit_handler::{
    BiscuitAuthOutcome, authorize_biscuit_with_limits, verify_biscuit_token_with_limits,
};
use crate::config::BiscuitAuthorizerProfile;
use crate::dynamic_security_policy::DynamicSecurityPolicy;
use crate::http_policy;
use crate::jwt_handler::JwtGrant;
use crate::policy::PolicyMode;
use crate::sqlite_policy::SqlitePolicy;
use crate::time::unix_timestamp_now;
use biscuit_auth::PublicKey as BiscuitPublicKey;

const MOSQ_ACL_WRITE: i32 = 0x02;

// Mosquitto ACL access bitmask mapping:
// MOSQ_ACL_READ=0x01, MOSQ_ACL_WRITE=0x02, MOSQ_ACL_SUBSCRIBE=0x04, MOSQ_ACL_CONTROL=0x08
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Operation {
    Read,
    Publish,
    Subscribe,
    Control,
}

impl Operation {
    const fn from_access(access: i32) -> Self {
        if (access & 0x02) != 0 {
            Self::Publish
        } else if (access & 0x04) != 0 {
            Self::Subscribe
        } else if (access & 0x08) != 0 {
            Self::Control
        } else {
            Self::Read
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Publish => "publish",
            Self::Subscribe => "subscribe",
            Self::Control => "control",
        }
    }
}

const fn access_to_operation(access: i32) -> Operation {
    Operation::from_access(access)
}

fn operation_matches_grant(operation: Operation, grant_operation: &str) -> bool {
    match (operation, grant_operation.trim()) {
        (Operation::Read, "read" | "subscribe") => true,
        (expected, actual) => expected.as_str() == actual,
    }
}

const fn authz_outcome(allowed: bool) -> AuthzOutcome {
    if allowed {
        AuthzOutcome::Allowed
    } else {
        AuthzOutcome::Denied
    }
}

fn dynamic_security_access(access: i32, is_control_request: bool) -> i32 {
    // Dynamic-security ACLs model $CONTROL publication as publish-send checks.
    // Preserve raw ACL bits for data-plane checks where 0x08 may represent unsubscribe.
    if is_control_request && access_to_operation(access) == Operation::Control {
        MOSQ_ACL_WRITE
    } else {
        access
    }
}

#[derive(Debug, Copy, Clone)]
pub struct AuthContext<'a> {
    pub topic: &'a str,
    pub operation: Operation,
}

#[cfg(test)]
mod tests {
    use super::{
        AuthContext, AuthzOutcome, AuthzParams, Operation, check_authorization, check_token_expiry,
        topic_matches,
    };
    use crate::auth::TokenType;
    use crate::config::BiscuitAuthorizerProfile;
    use crate::dynamic_security_policy::DynamicSecurityPolicy;
    use crate::jwt_handler::Claims;
    use crate::policy::PolicyMode;
    use crate::time::unix_timestamp_now;
    use biscuit_auth::{Algorithm, PublicKey};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    static DYNSEC_PATH_COUNTER: AtomicU64 = AtomicU64::new(0);

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

        assert!(super::grants_allow(
            &grants,
            AuthContext {
                operation: Operation::Read,
                topic
            }
        ));
        assert!(super::grants_allow(
            &grants,
            AuthContext {
                operation: Operation::Subscribe,
                topic
            }
        ));
        assert!(!super::grants_allow(
            &grants,
            AuthContext {
                operation: Operation::Read,
                topic: "sensors/client_2/temp"
            }
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
        assert!(super::grants_allow(
            &read_grants,
            AuthContext {
                operation: Operation::Read,
                topic
            }
        ));
        assert!(!super::grants_allow(
            &read_grants,
            AuthContext {
                operation: Operation::Read,
                topic: "sensors/client_2/temp"
            }
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

        assert!(super::grants_allow(
            &grants,
            AuthContext {
                operation: Operation::Read,
                topic
            }
        ));
        assert!(super::grants_deny(
            &denies,
            AuthContext {
                operation: Operation::Read,
                topic
            }
        ));
        assert!(!super::grants_deny(
            &denies,
            AuthContext {
                operation: Operation::Subscribe,
                topic
            }
        ));
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

        assert!(super::grants_allow(
            &grants,
            AuthContext {
                operation: Operation::Read,
                topic
            }
        ));
        assert!(super::grants_deny(
            &denies,
            AuthContext {
                operation: Operation::Read,
                topic
            }
        ));
    }

    #[test]
    fn access_to_operation_bitmask_priority() {
        // Test individual access types
        assert_eq!(super::access_to_operation(0x01), Operation::Read); // MOSQ_ACL_READ
        assert_eq!(super::access_to_operation(0x02), Operation::Publish); // MOSQ_ACL_WRITE
        assert_eq!(super::access_to_operation(0x04), Operation::Subscribe); // MOSQ_ACL_SUBSCRIBE
        assert_eq!(super::access_to_operation(0x08), Operation::Control); // MOSQ_ACL_CONTROL

        // Test priority: WRITE > SUBSCRIBE > CONTROL > READ
        assert_eq!(super::access_to_operation(0x02 | 0x04), Operation::Publish); // WRITE | SUBSCRIBE
        assert_eq!(
            super::access_to_operation(0x04 | 0x01),
            Operation::Subscribe
        ); // SUBSCRIBE | READ
        assert_eq!(super::access_to_operation(0x08 | 0x01), Operation::Control); // CONTROL | READ
        assert_eq!(super::access_to_operation(0x02 | 0x08), Operation::Publish); // WRITE | CONTROL
        assert_eq!(
            super::access_to_operation(0x04 | 0x08),
            Operation::Subscribe
        ); // SUBSCRIBE | CONTROL
        assert_eq!(
            super::access_to_operation(0x02 | 0x04 | 0x08),
            Operation::Publish
        ); // All three

        // Test edge cases
        assert_eq!(super::access_to_operation(0x00), Operation::Read); // No access flags defaults to read
        assert_eq!(super::access_to_operation(0x10), Operation::Read); // Unknown flags default to read
        assert_eq!(super::access_to_operation(0xFF), Operation::Publish); // All flags including WRITE
    }

    #[test]
    fn dynamic_security_access_maps_control_to_publish() {
        assert_eq!(super::dynamic_security_access(0x08, true), 0x02);
        assert_eq!(super::dynamic_security_access(0x08, false), 0x08);
        assert_eq!(super::dynamic_security_access(0x02, true), 0x02);
        assert_eq!(super::dynamic_security_access(0x04, true), 0x04);
        assert_eq!(super::dynamic_security_access(0x01, true), 0x01);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn dynamic_security_mode_preserves_unsubscribe_outside_control_context() {
        let now = unix_timestamp_now();
        let unique = DYNSEC_PATH_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("dynsec-authz-{unique}.json"));
        let config = r#"{
  "clients": [
    {
      "username": "test_user",
      "clientid": "client_1",
      "roles": [{"rolename": "test_role", "priority": 0}],
      "disabled": false
    }
  ],
  "groups": [],
  "roles": [
    {
      "rolename": "test_role",
      "acls": [
        {"acltype": "unsubscribeLiteral", "topic": "sensors/a", "priority": 1, "allow": true},
        {"acltype": "publishClientSend", "topic": "sensors/a", "priority": 1, "allow": false}
      ]
    }
  ],
  "defaultACLAccess": {
    "publishClientSend": false,
    "publishClientReceive": false,
    "subscribe": false,
    "unsubscribe": false
  }
}"#;
        fs::write(&path, config).expect("temporary dynsec policy should be writable");

        let policy = DynamicSecurityPolicy::new(
            path.to_string_lossy().into_owned(),
            Duration::from_secs(60),
        )
        .expect("temporary dynsec policy should load");
        let root_key =
            PublicKey::from_bytes(&[0u8; 32], Algorithm::Ed25519).expect("test root key");
        let token = TokenType::Jwt {
            claims: Claims {
                sub: "client_1".to_string(),
                exp: now + 60,
                iss: None,
                aud: None,
                client_id: None,
                roles: None,
                grants: None,
                denies: None,
            },
            raw: "token".to_string(),
        };
        let params = AuthzParams {
            username: Some("test_user"),
            client_id: "client_1",
            topic: "sensors/a",
            access: 0x08,
            is_control_request: false,
            biscuit_authorizer_profile: BiscuitAuthorizerProfile::Simple,
            biscuit_authorizer_max_time_ms: 25,
            biscuit_root_key: &root_key,
            policy_mode: PolicyMode::DynamicSecurity,
            sqlite_policy: None,
            dynamic_security_policy: Some(&policy),
            http_url: None,
            http_ca_file: None,
            http_tls_insecure: false,
            http_timeout_seconds: 1,
            http_max_response_bytes: 1024,
        };

        assert_eq!(check_authorization(&token, params), AuthzOutcome::Allowed);
        assert_eq!(
            check_authorization(
                &token,
                AuthzParams {
                    is_control_request: true,
                    ..params
                }
            ),
            AuthzOutcome::Denied
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn grants_allow_control_operations() {
        use crate::jwt_handler::JwtGrant;
        let grants = vec![
            JwtGrant {
                op: "control".to_string(),
                res: "$CONTROL/#".to_string(),
            },
            JwtGrant {
                op: "publish".to_string(),
                res: "sensors/temp".to_string(),
            },
        ];
        assert!(super::grants_allow(
            &grants,
            AuthContext {
                operation: Operation::Control,
                topic: "$CONTROL/dynsec/v1"
            }
        ));
        assert!(!super::grants_allow(
            &grants,
            AuthContext {
                operation: Operation::Control,
                topic: "sensors/temp"
            }
        ));
        assert!(super::grants_allow(
            &grants,
            AuthContext {
                operation: Operation::Publish,
                topic: "sensors/temp"
            }
        ));
    }

    #[test]
    fn check_token_expiry_handles_jwt() {
        let now = unix_timestamp_now();
        let valid = TokenType::Jwt {
            claims: Claims {
                sub: "client_1".to_string(),
                exp: now + 60,
                iss: None,
                aud: None,
                client_id: None,
                roles: None,
                grants: None,
                denies: None,
            },
            raw: "token".to_string(),
        };
        let expired = TokenType::Jwt {
            claims: Claims {
                sub: "client_1".to_string(),
                exp: now - 1,
                iss: None,
                aud: None,
                client_id: None,
                roles: None,
                grants: None,
                denies: None,
            },
            raw: "token".to_string(),
        };

        assert_eq!(check_token_expiry(&valid), AuthzOutcome::Allowed);
        assert_eq!(check_token_expiry(&expired), AuthzOutcome::Expired);
    }

    #[test]
    fn check_token_expiry_handles_biscuit() {
        let now = unix_timestamp_now();
        let valid = TokenType::Biscuit {
            bytes: vec![1, 2, 3],
            expires_at: Some(now + 60),
            roles: None,
            biscuit: None,
        };
        let expired = TokenType::Biscuit {
            bytes: vec![1, 2, 3],
            expires_at: Some(now - 1),
            roles: None,
            biscuit: None,
        };
        let no_expiry = TokenType::Biscuit {
            bytes: vec![1, 2, 3],
            expires_at: None,
            roles: None,
            biscuit: None,
        };

        assert_eq!(check_token_expiry(&valid), AuthzOutcome::Allowed);
        assert_eq!(check_token_expiry(&expired), AuthzOutcome::Expired);
        assert_eq!(check_token_expiry(&no_expiry), AuthzOutcome::Allowed);
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
            continue;
        }
        if part.contains('+') && *part != "+" {
            return false;
        }
    }
    true
}

pub fn topic_matches(filter: &str, topic: &str) -> bool {
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

fn grants_allow(grants: &[JwtGrant], auth_context: AuthContext) -> bool {
    grants.iter().any(|grant| {
        operation_matches_grant(auth_context.operation, grant.op.as_str())
            && topic_matches(grant.res.trim(), auth_context.topic)
    })
}

fn grants_deny(denies: &[JwtGrant], auth_context: AuthContext) -> bool {
    denies.iter().any(|deny| {
        operation_matches_grant(auth_context.operation, deny.op.as_str())
            && topic_matches(deny.res.trim(), auth_context.topic)
    })
}

/// Lightweight authorization parameters using references to avoid allocations
#[derive(Copy, Clone)]
pub struct AuthzParams<'a> {
    pub username: Option<&'a str>,
    pub client_id: &'a str,
    pub topic: &'a str,
    pub access: i32,
    pub is_control_request: bool,
    pub biscuit_authorizer_profile: BiscuitAuthorizerProfile,
    pub biscuit_authorizer_max_time_ms: u64,
    pub biscuit_root_key: &'a BiscuitPublicKey,
    pub policy_mode: PolicyMode,
    pub sqlite_policy: Option<&'a SqlitePolicy>,
    pub dynamic_security_policy: Option<&'a DynamicSecurityPolicy>,
    pub http_url: Option<&'a str>,
    pub http_ca_file: Option<&'a str>,
    pub http_tls_insecure: bool,
    pub http_timeout_seconds: u64,
    pub http_max_response_bytes: u64,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AuthzOutcome {
    Allowed,
    Denied,
    Expired,
}

fn sqlite_backend_outcome(params: AuthzParams<'_>) -> AuthzOutcome {
    let Some(sqlite_policy) = params.sqlite_policy else {
        return AuthzOutcome::Denied;
    };
    authz_outcome(
        sqlite_policy
            .check(params.client_id, params.topic, params.access)
            .unwrap_or(false),
    )
}

fn dynamic_security_backend_outcome(params: AuthzParams<'_>) -> AuthzOutcome {
    let Some(policy) = params.dynamic_security_policy else {
        return AuthzOutcome::Denied;
    };
    authz_outcome(
        policy
            .check(
                params.username,
                Some(params.client_id),
                params.topic,
                dynamic_security_access(params.access, params.is_control_request),
            )
            .unwrap_or(false),
    )
}

fn http_backend_outcome(params: AuthzParams<'_>, token: Option<&str>) -> Option<AuthzOutcome> {
    let url = params.http_url?;
    let allowed = http_policy::check_http(http_policy::HttpCheckParams {
        http_url: url,
        client_id: params.client_id,
        topic: params.topic,
        access: params.access,
        token,
        tls_config: http_policy::TlsConfig {
            ca_file: params.http_ca_file,
            tls_insecure: params.http_tls_insecure,
        },
        timeout_seconds: params.http_timeout_seconds,
        max_response_bytes: params.http_max_response_bytes,
    })
    .ok()?;
    Some(authz_outcome(allowed))
}

fn authorize_via_policy(
    params: AuthzParams<'_>,
    token: Option<&str>,
    token_only: impl FnOnce(Operation) -> AuthzOutcome,
) -> AuthzOutcome {
    let operation = access_to_operation(params.access);
    match params.policy_mode {
        PolicyMode::TokenOnly | PolicyMode::StaticAcl | PolicyMode::StaticAclStrict => {
            token_only(operation)
        }
        PolicyMode::Sqlite => sqlite_backend_outcome(params),
        PolicyMode::Http => http_backend_outcome(params, token).unwrap_or(AuthzOutcome::Denied),
        PolicyMode::Hybrid => {
            http_backend_outcome(params, token).unwrap_or_else(|| token_only(operation))
        }
        PolicyMode::DynamicSecurity => dynamic_security_backend_outcome(params),
    }
}

pub fn check_token_expiry(token_type: &TokenType) -> AuthzOutcome {
    let now = unix_timestamp_now();
    match token_type {
        TokenType::Jwt { claims, .. } => {
            if now >= claims.exp {
                AuthzOutcome::Expired
            } else {
                AuthzOutcome::Allowed
            }
        }
        TokenType::Biscuit { expires_at, .. } => {
            if let Some(expires_at) = expires_at
                && now >= *expires_at
            {
                AuthzOutcome::Expired
            } else {
                AuthzOutcome::Allowed
            }
        }
    }
}

fn jwt_token_only(
    claims: &crate::jwt_handler::Claims,
    topic: &str,
    operation: Operation,
) -> AuthzOutcome {
    let Some(grants) = claims.grants.as_ref() else {
        return AuthzOutcome::Denied;
    };
    let auth_context = AuthContext { topic, operation };
    if let Some(denies) = claims.denies.as_ref()
        && grants_deny(denies, auth_context)
    {
        return AuthzOutcome::Denied;
    }
    authz_outcome(grants_allow(grants, auth_context))
}

fn biscuit_token_only(
    bytes: &[u8],
    biscuit: Option<&std::sync::Arc<biscuit_auth::Biscuit>>,
    params: AuthzParams<'_>,
    operation: Operation,
) -> AuthzOutcome {
    let outcome = biscuit.map_or_else(
        || {
            verify_biscuit_token_with_limits(
                bytes,
                params.biscuit_root_key,
                AuthContext {
                    topic: params.topic,
                    operation,
                },
                params.biscuit_authorizer_profile,
                params.biscuit_authorizer_max_time_ms,
            )
        },
        |biscuit| {
            authorize_biscuit_with_limits(
                biscuit.as_ref(),
                params.topic,
                operation.as_str(),
                params.biscuit_authorizer_profile,
                params.biscuit_authorizer_max_time_ms,
            )
        },
    );

    match outcome {
        BiscuitAuthOutcome::Allowed => AuthzOutcome::Allowed,
        BiscuitAuthOutcome::Denied | BiscuitAuthOutcome::Error(_) => AuthzOutcome::Denied,
    }
}

pub fn check_authorization(token_type: &TokenType, params: AuthzParams<'_>) -> AuthzOutcome {
    if check_token_expiry(token_type) == AuthzOutcome::Expired {
        return AuthzOutcome::Expired;
    }

    match token_type {
        TokenType::Jwt { claims, raw } => authorize_via_policy(params, Some(raw), |operation| {
            jwt_token_only(claims, params.topic, operation)
        }),
        TokenType::Biscuit {
            bytes,
            expires_at: _,
            roles: _,
            biscuit,
        } => authorize_via_policy(params, None, |operation| {
            biscuit_token_only(bytes, biscuit.as_ref(), params, operation)
        }),
    }
}
