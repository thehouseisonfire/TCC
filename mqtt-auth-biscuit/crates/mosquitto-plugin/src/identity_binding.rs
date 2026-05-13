use crate::auth::TokenType;
use crate::config::{IdentityBindingMode, PluginConfig};
use biscuit_auth::{AuthorizerBuilder, Biscuit};
use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityBindingError {
    MissingLiveClientId,
    MissingJwtIdentity,
    InconsistentJwtIdentity,
    JwtIdentityMismatch,
    MissingBiscuitIdentity { predicate: String },
    AmbiguousBiscuitIdentity { predicate: String },
    BiscuitIdentityMismatch { predicate: String },
    BiscuitIdentityExtractionFailed { predicate: String },
}

impl fmt::Display for IdentityBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingLiveClientId => write!(f, "live MQTT client_id missing"),
            Self::MissingJwtIdentity => write!(f, "JWT identity missing"),
            Self::InconsistentJwtIdentity => write!(f, "JWT sub and client_id are inconsistent"),
            Self::JwtIdentityMismatch => {
                write!(f, "JWT identity does not match live MQTT client_id")
            }
            Self::MissingBiscuitIdentity { predicate } => {
                write!(f, "Biscuit identity fact {predicate}(...) missing")
            }
            Self::AmbiguousBiscuitIdentity { predicate } => {
                write!(f, "Biscuit identity fact {predicate}(...) is ambiguous")
            }
            Self::BiscuitIdentityMismatch { predicate } => write!(
                f,
                "Biscuit identity fact {predicate}(...) does not match live MQTT client_id"
            ),
            Self::BiscuitIdentityExtractionFailed { predicate } => write!(
                f,
                "Biscuit identity fact {predicate}(...) could not be extracted"
            ),
        }
    }
}

fn identity_or_missing(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.is_empty())
}

pub fn resolve_jwt_effective_identity<'a>(
    sub: &'a str,
    client_id: Option<&'a str>,
) -> Result<Option<&'a str>, IdentityBindingError> {
    let sub = identity_or_missing(Some(sub));
    let client_id = identity_or_missing(client_id);

    match (sub, client_id) {
        (Some(sub), Some(client_id)) if sub != client_id => {
            Err(IdentityBindingError::InconsistentJwtIdentity)
        }
        (Some(sub), Some(_) | None) => Ok(Some(sub)),
        (None, Some(client_id)) => Ok(Some(client_id)),
        (None, None) => Ok(None),
    }
}

fn authorizer_limits(max_time_ms: u64) -> biscuit_auth::AuthorizerLimits {
    biscuit_auth::AuthorizerLimits {
        max_time: Duration::from_millis(max_time_ms.max(1)),
        ..Default::default()
    }
}

pub fn resolve_biscuit_identity(
    biscuit: &Biscuit,
    predicate: &str,
    max_time_ms: u64,
) -> Result<String, IdentityBindingError> {
    let mut authorizer = AuthorizerBuilder::new()
        .set_limits(authorizer_limits(max_time_ms))
        .build(biscuit)
        .map_err(|_| IdentityBindingError::BiscuitIdentityExtractionFailed {
            predicate: predicate.to_string(),
        })?;
    let query = format!("data($id) <- {predicate}($id)");
    let identities: Vec<(String,)> = authorizer.query_all(query.as_str()).map_err(|_| {
        IdentityBindingError::BiscuitIdentityExtractionFailed {
            predicate: predicate.to_string(),
        }
    })?;
    let distinct: BTreeSet<String> = identities
        .into_iter()
        .map(|(identity,)| identity)
        .filter(|identity| !identity.is_empty())
        .collect();

    match distinct.len() {
        0 => Err(IdentityBindingError::MissingBiscuitIdentity {
            predicate: predicate.to_string(),
        }),
        1 => Ok(distinct
            .into_iter()
            .next()
            .expect("a single identity must be present")),
        _ => Err(IdentityBindingError::AmbiguousBiscuitIdentity {
            predicate: predicate.to_string(),
        }),
    }
}

fn live_client_id(value: Option<&str>) -> Result<&str, IdentityBindingError> {
    identity_or_missing(value).ok_or(IdentityBindingError::MissingLiveClientId)
}

const fn biscuit_from_token(token: &TokenType) -> Option<&Arc<Biscuit>> {
    match token {
        TokenType::Biscuit {
            biscuit: Some(biscuit),
            ..
        } => Some(biscuit),
        _ => None,
    }
}

pub fn enforce_identity_binding(
    token: &TokenType,
    live_client_id_value: Option<&str>,
    config: &PluginConfig,
) -> Result<(), IdentityBindingError> {
    match token {
        TokenType::Jwt { claims, .. } => {
            if config.jwt_identity_binding == IdentityBindingMode::Off {
                return Ok(());
            }

            let effective_identity =
                resolve_jwt_effective_identity(&claims.sub, claims.client_id.as_deref())?;
            let live_client_id = live_client_id(live_client_id_value)?;
            let effective_identity =
                effective_identity.ok_or(IdentityBindingError::MissingJwtIdentity)?;
            if effective_identity == live_client_id {
                Ok(())
            } else {
                Err(IdentityBindingError::JwtIdentityMismatch)
            }
        }
        TokenType::Biscuit { .. } => {
            if config.biscuit_identity_binding == IdentityBindingMode::Off {
                return Ok(());
            }

            let live_client_id = live_client_id(live_client_id_value)?;
            let biscuit = biscuit_from_token(token).ok_or_else(|| {
                IdentityBindingError::BiscuitIdentityExtractionFailed {
                    predicate: config.biscuit_client_id_fact.clone(),
                }
            })?;
            let identity = resolve_biscuit_identity(
                biscuit.as_ref(),
                &config.biscuit_client_id_fact,
                config.biscuit_authorizer_max_time_ms,
            )?;
            if identity == live_client_id {
                Ok(())
            } else {
                Err(IdentityBindingError::BiscuitIdentityMismatch {
                    predicate: config.biscuit_client_id_fact.clone(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{IdentityBindingError, enforce_identity_binding, resolve_jwt_effective_identity};
    use crate::auth::TokenType;
    use crate::config::{
        BiscuitAuthorizerProfile, BiscuitConfig, IdentityBindingMode, JwtConfig, PluginConfig,
    };
    use crate::jwt_handler::Claims;
    use crate::policy::{PolicyBackendConfig, PolicyMode};
    use biscuit_auth::{Algorithm as BiscuitAlgorithm, PublicKey};
    use jsonwebtoken::{Algorithm, DecodingKey, Validation};

    fn test_config(jwt_identity_binding: IdentityBindingMode) -> PluginConfig {
        PluginConfig {
            jwt: JwtConfig {
                decoding_key: DecodingKey::from_secret(b"test-secret"),
                validation: Validation::new(Algorithm::HS256),
            },
            biscuit: BiscuitConfig {
                root_public_key: PublicKey::from_bytes(&[0u8; 32], BiscuitAlgorithm::Ed25519)
                    .expect("test public key should parse"),
            },
            policy: PolicyBackendConfig {
                mode: PolicyMode::TokenOnly,
                sqlite_path: None,
                http_url: None,
                http_ca_file: None,
                http_tls_insecure: false,
                http_timeout_seconds: 2,
                http_max_response_bytes: 64 * 1024,
                dynamic_security_url: None,
                dynamic_security_reload_interval_seconds: None,
            },
            jwt_identity_binding,
            biscuit_identity_binding: IdentityBindingMode::Off,
            sqlite_seed_demo_rules: false,
            cache_ttl_seconds: 3600,
            allow_anonymous_no_token: false,
            acl_read_full_authz: false,
            control_notify_topic_prefix: "system_notification".to_string(),
            ext_auth_method: Some("token".to_string()),
            role_username_prefix: "role:".to_string(),
            biscuit_role_fact: "role".to_string(),
            biscuit_client_id_fact: "client_id".to_string(),
            biscuit_authorizer_profile: BiscuitAuthorizerProfile::Simple,
            biscuit_authorizer_max_time_ms: 25,
        }
    }

    #[test]
    fn resolve_jwt_identity_prefers_consistent_client_binding() {
        let identity = resolve_jwt_effective_identity("client_a", Some("client_a"))
            .expect("identity should resolve");
        assert_eq!(identity, Some("client_a"));
    }

    #[test]
    fn resolve_jwt_identity_treats_empty_values_as_missing() {
        let identity =
            resolve_jwt_effective_identity("", Some("")).expect("empty identity is allowed");
        assert_eq!(identity, None);
    }

    #[test]
    fn resolve_jwt_identity_preserves_whitespace() {
        let identity =
            resolve_jwt_effective_identity(" client_a ", None).expect("identity should resolve");
        assert_eq!(identity, Some(" client_a "));
    }

    #[test]
    fn resolve_jwt_identity_treats_whitespace_only_as_present() {
        let identity =
            resolve_jwt_effective_identity("   ", None).expect("whitespace is opaque identity");
        assert_eq!(identity, Some("   "));
    }

    #[test]
    fn resolve_jwt_identity_rejects_inconsistent_values() {
        let err = resolve_jwt_effective_identity("client_a", Some("client_b"))
            .expect_err("identity mismatch should fail");
        assert_eq!(err, IdentityBindingError::InconsistentJwtIdentity);
    }

    #[test]
    fn jwt_off_skips_claim_consistency_checks() {
        let config = test_config(IdentityBindingMode::Off);
        let token = TokenType::Jwt {
            claims: Claims {
                sub: "user-principal".to_string(),
                exp: 2_000_000_000,
                iss: None,
                aud: None,
                client_id: Some("device-metadata".to_string()),
                roles: None,
                grants: None,
                denies: None,
            },
            raw: "token".to_string(),
        };

        let result = enforce_identity_binding(&token, Some("live-client"), &config);

        assert_eq!(result, Ok(()));
    }
}
