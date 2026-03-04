use crate::authz::{AuthContext, topic_matches};
use crate::config::BiscuitAuthorizerProfile;
use crate::time::unix_timestamp_now;
use biscuit_auth::{AuthorizerBuilder, Biscuit, PublicKey};
use std::collections::HashMap;
use std::sync::Arc;
#[cfg(feature = "expiry_stats")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
#[cfg(feature = "expiry_stats")]
use std::time::Instant;

const DEFAULT_BISCUIT_AUTHORIZER_MAX_TIME_MS: u64 = 25;

static ROLE_AUTHORIZER_TEMPLATE: OnceLock<String> = OnceLock::new();
static ROLE_QUERY_CACHE: OnceLock<Mutex<HashMap<String, Arc<str>>>> = OnceLock::new();

fn get_role_authorizer_template() -> &'static str {
    ROLE_AUTHORIZER_TEMPLATE.get_or_init(|| {
        r"
        role({role});
        allow if role($role);
        "
        .to_string()
    })
}

fn cached_role_query(role_fact: &str) -> Arc<str> {
    let cache = ROLE_QUERY_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut cache) = cache.lock() {
        if let Some(query) = cache.get(role_fact) {
            return Arc::clone(query);
        }
        let query: Arc<str> = format!("data($role) <- {role_fact}($role)").into();
        cache.insert(role_fact.to_string(), Arc::clone(&query));
        return query;
    }
    format!("data($role) <- {role_fact}($role)").into()
}

pub enum BiscuitAuthOutcome {
    Allowed,
    Denied,
    Error(biscuit_auth::error::Token),
}

/// Snapshot of expiry extraction metrics for diagnostics/benchmarking.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExpiryStats {
    pub calls: u64,
    pub failures: u64,
    pub total_nanos: u64,
}

#[cfg(feature = "expiry_stats")]
#[derive(Debug, Default)]
struct ExpiryMetrics {
    calls: AtomicU64,
    failures: AtomicU64,
    total_nanos: AtomicU64,
}

#[cfg(feature = "expiry_stats")]
static EXPIRY_METRICS: ExpiryMetrics = ExpiryMetrics {
    calls: AtomicU64::new(0),
    failures: AtomicU64::new(0),
    total_nanos: AtomicU64::new(0),
};

/// Returns a snapshot of expiry extraction performance.
#[cfg(feature = "expiry_stats")]
pub fn expiry_stats() -> ExpiryStats {
    ExpiryStats {
        calls: EXPIRY_METRICS.calls.load(Ordering::Relaxed),
        failures: EXPIRY_METRICS.failures.load(Ordering::Relaxed),
        total_nanos: EXPIRY_METRICS.total_nanos.load(Ordering::Relaxed),
    }
}

#[cfg(not(feature = "expiry_stats"))]
pub fn expiry_stats() -> ExpiryStats {
    ExpiryStats::default()
}

fn with_expiry_metrics<F>(f: F) -> Result<Option<i64>, biscuit_auth::error::Token>
where
    F: FnOnce() -> Result<Option<i64>, biscuit_auth::error::Token>,
{
    #[cfg(feature = "expiry_stats")]
    EXPIRY_METRICS.calls.fetch_add(1, Ordering::Relaxed);
    #[cfg(feature = "expiry_stats")]
    let start = Instant::now();
    let result = f();
    #[cfg(feature = "expiry_stats")]
    if result.is_err() {
        EXPIRY_METRICS.failures.fetch_add(1, Ordering::Relaxed);
    }
    #[cfg(feature = "expiry_stats")]
    let elapsed_nanos = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
    #[cfg(feature = "expiry_stats")]
    EXPIRY_METRICS
        .total_nanos
        .fetch_add(elapsed_nanos, Ordering::Relaxed);
    result
}

fn authorizer_limits(max_time_ms: u64) -> biscuit_auth::AuthorizerLimits {
    biscuit_auth::AuthorizerLimits {
        max_time: Duration::from_millis(max_time_ms.max(1)),
        ..Default::default()
    }
}

fn build_empty_authorizer(
    biscuit: &Biscuit,
    max_time_ms: u64,
) -> Result<biscuit_auth::Authorizer, biscuit_auth::error::Token> {
    AuthorizerBuilder::new()
        .set_limits(authorizer_limits(max_time_ms))
        .build(biscuit)
}

fn extract_min_expiry_query(
    biscuit: &Biscuit,
    max_time_ms: u64,
) -> Result<Option<i64>, biscuit_auth::error::Token> {
    let mut authorizer = build_empty_authorizer(biscuit, max_time_ms)?;
    let expiries: Vec<(i64,)> = authorizer.query_all("data($ts) <- expires_at($ts)")?;
    Ok(expiries.into_iter().map(|(ts,)| ts).min())
}

pub fn parse_biscuit(
    token_bytes: &[u8],
    root_public_key: &PublicKey,
) -> Result<Arc<Biscuit>, biscuit_auth::error::Token> {
    Biscuit::from(token_bytes, root_public_key).map(Arc::new)
}

#[allow(dead_code)]
pub fn extract_min_expiry(
    token_bytes: &[u8],
    root_public_key: &PublicKey,
) -> Result<Option<i64>, biscuit_auth::error::Token> {
    extract_min_expiry_with_limits(
        token_bytes,
        root_public_key,
        DEFAULT_BISCUIT_AUTHORIZER_MAX_TIME_MS,
    )
}

#[allow(dead_code)]
pub fn extract_min_expiry_with_limits(
    token_bytes: &[u8],
    root_public_key: &PublicKey,
    max_time_ms: u64,
) -> Result<Option<i64>, biscuit_auth::error::Token> {
    with_expiry_metrics(|| {
        let biscuit = Biscuit::from(token_bytes, root_public_key)?;
        extract_min_expiry_query(&biscuit, max_time_ms)
    })
}

#[allow(dead_code)]
pub fn extract_min_expiry_from_biscuit(
    biscuit: &Biscuit,
) -> Result<Option<i64>, biscuit_auth::error::Token> {
    extract_min_expiry_from_biscuit_with_limits(biscuit, DEFAULT_BISCUIT_AUTHORIZER_MAX_TIME_MS)
}

pub fn extract_min_expiry_from_biscuit_with_limits(
    biscuit: &Biscuit,
    max_time_ms: u64,
) -> Result<Option<i64>, biscuit_auth::error::Token> {
    with_expiry_metrics(|| extract_min_expiry_query(biscuit, max_time_ms))
}

#[allow(dead_code)]
pub fn extract_roles(
    token_bytes: &[u8],
    root_public_key: &PublicKey,
    role_fact: &str,
) -> Result<Vec<String>, biscuit_auth::error::Token> {
    extract_roles_with_limits(
        token_bytes,
        root_public_key,
        role_fact,
        DEFAULT_BISCUIT_AUTHORIZER_MAX_TIME_MS,
    )
}

#[allow(dead_code)]
pub fn extract_roles_with_limits(
    token_bytes: &[u8],
    root_public_key: &PublicKey,
    role_fact: &str,
    max_time_ms: u64,
) -> Result<Vec<String>, biscuit_auth::error::Token> {
    // Template caching is advisory; authorizer queries are constructed explicitly below.
    let _template = get_role_authorizer_template();
    let biscuit = Biscuit::from(token_bytes, root_public_key)?;
    let mut authorizer = build_empty_authorizer(&biscuit, max_time_ms)?;
    let query = cached_role_query(role_fact);
    let roles: Vec<(String,)> = authorizer.query_all(query.as_ref())?;
    Ok(roles.into_iter().map(|(role,)| role).collect())
}

#[allow(dead_code)]
pub fn extract_roles_from_biscuit(
    biscuit: &Biscuit,
    role_fact: &str,
) -> Result<Vec<String>, biscuit_auth::error::Token> {
    extract_roles_from_biscuit_with_limits(
        biscuit,
        role_fact,
        DEFAULT_BISCUIT_AUTHORIZER_MAX_TIME_MS,
    )
}

pub fn extract_roles_from_biscuit_with_limits(
    biscuit: &Biscuit,
    role_fact: &str,
    max_time_ms: u64,
) -> Result<Vec<String>, biscuit_auth::error::Token> {
    let _template = get_role_authorizer_template();
    let mut authorizer = build_empty_authorizer(biscuit, max_time_ms)?;
    let query = cached_role_query(role_fact);
    let roles: Vec<(String,)> = authorizer.query_all(query.as_ref())?;
    Ok(roles.into_iter().map(|(role,)| role).collect())
}

#[allow(dead_code)]
pub fn has_right_facts(
    token_bytes: &[u8],
    root_public_key: &PublicKey,
) -> Result<bool, biscuit_auth::error::Token> {
    has_right_facts_with_limits(
        token_bytes,
        root_public_key,
        DEFAULT_BISCUIT_AUTHORIZER_MAX_TIME_MS,
    )
}

pub fn has_right_facts_with_limits(
    token_bytes: &[u8],
    root_public_key: &PublicKey,
    max_time_ms: u64,
) -> Result<bool, biscuit_auth::error::Token> {
    has_profile_grant_facts_with_limits(
        token_bytes,
        root_public_key,
        BiscuitAuthorizerProfile::Simple,
        max_time_ms,
    )
}

pub fn has_profile_grant_facts_with_limits(
    token_bytes: &[u8],
    root_public_key: &PublicKey,
    profile: BiscuitAuthorizerProfile,
    max_time_ms: u64,
) -> Result<bool, biscuit_auth::error::Token> {
    use biscuit_auth::macros::authorizer;

    let biscuit = Biscuit::from(token_bytes, root_public_key)?;
    let now = unix_timestamp_now();
    let authorizer = match profile {
        BiscuitAuthorizerProfile::Simple => authorizer!(
            r#"
            allow if true;
            "#
        )
        .set_limits(authorizer_limits(max_time_ms))
        .build(&biscuit),
        BiscuitAuthorizerProfile::Rbac => authorizer!(
            r#"
            right_eval($op, $res) <- right($op, $res);
            right_eval($op, $res) <- role($role), role_right($role, $op, $res);
            allow if true;
            "#
        )
        .set_limits(authorizer_limits(max_time_ms))
        .build(&biscuit),
        BiscuitAuthorizerProfile::Contextual => authorizer!(
            r#"
            time({time});
            right_eval($op, $res) <-
                role($role),
                role_right($role, $op, $res),
                role_active_from($role, $not_before),
                role_active_until($role, $not_after),
                time($now),
                $now >= $not_before,
                $now <= $not_after;
            allow if true;
            "#,
            time = now
        )
        .set_limits(authorizer_limits(max_time_ms))
        .build(&biscuit),
    }
    .map_err(|_| biscuit_auth::error::Token::InternalError)?;
    let mut authorizer = authorizer;
    let rights_query = match profile {
        BiscuitAuthorizerProfile::Simple => "data($op, $res) <- right($op, $res)",
        BiscuitAuthorizerProfile::Rbac | BiscuitAuthorizerProfile::Contextual => {
            "data($op, $res) <- right_eval($op, $res)"
        }
    };
    let rights: Vec<(String, String)> = authorizer.query_all(rights_query)?;
    Ok(!rights.is_empty())
}

#[allow(dead_code)]
pub fn verify_biscuit_token(
    token_bytes: &[u8],
    root_public_key: &PublicKey,
    auth_context: AuthContext,
    profile: BiscuitAuthorizerProfile,
) -> BiscuitAuthOutcome {
    verify_biscuit_token_with_limits(
        token_bytes,
        root_public_key,
        auth_context,
        profile,
        DEFAULT_BISCUIT_AUTHORIZER_MAX_TIME_MS,
    )
}

pub fn verify_biscuit_token_with_limits(
    token_bytes: &[u8],
    root_public_key: &PublicKey,
    auth_context: AuthContext,
    profile: BiscuitAuthorizerProfile,
    max_time_ms: u64,
) -> BiscuitAuthOutcome {
    // Deserialize token
    let biscuit = match Biscuit::from(token_bytes, root_public_key) {
        Ok(token) => token,
        Err(err) => return BiscuitAuthOutcome::Error(err),
    };

    authorize_biscuit_with_limits(
        &biscuit,
        auth_context.topic,
        auth_context.operation,
        profile,
        max_time_ms,
    )
}

#[allow(dead_code)]
pub fn authorize_biscuit(
    biscuit: &Biscuit,
    topic: &str,
    operation: &str,
    profile: BiscuitAuthorizerProfile,
) -> BiscuitAuthOutcome {
    authorize_biscuit_with_limits(
        biscuit,
        topic,
        operation,
        profile,
        DEFAULT_BISCUIT_AUTHORIZER_MAX_TIME_MS,
    )
}

pub fn authorize_biscuit_with_limits(
    biscuit: &Biscuit,
    topic: &str,
    operation: &str,
    profile: BiscuitAuthorizerProfile,
    max_time_ms: u64,
) -> BiscuitAuthOutcome {
    use biscuit_auth::macros::authorizer;
    let now = unix_timestamp_now();

    let authorizer = match profile {
        BiscuitAuthorizerProfile::Simple => authorizer!(
            r#"
            resource({topic});
            operation({operation});
            time({time});
            allow if true;
            "#,
            topic = topic,
            operation = operation,
            time = now
        )
        .set_limits(authorizer_limits(max_time_ms))
        .build(biscuit),
        BiscuitAuthorizerProfile::Rbac => authorizer!(
            r#"
            resource({topic});
            operation({operation});
            time({time});
            right_eval($op, $res) <- right($op, $res);
            deny_eval($op, $res) <- deny($op, $res);
            right_eval($op, $res) <- role($role), role_right($role, $op, $res);
            deny_eval($op, $res) <- role($role), role_deny($role, $op, $res);
            allow if true;
            "#,
            topic = topic,
            operation = operation,
            time = now
        )
        .set_limits(authorizer_limits(max_time_ms))
        .build(biscuit),
        BiscuitAuthorizerProfile::Contextual => authorizer!(
            r#"
            resource({topic});
            operation({operation});
            time({time});
            right_eval($op, $res) <-
                role($role),
                role_right($role, $op, $res),
                role_active_from($role, $not_before),
                role_active_until($role, $not_after),
                time($now),
                $now >= $not_before,
                $now <= $not_after;
            deny_eval($op, $res) <-
                role($role),
                role_deny($role, $op, $res),
                role_active_from($role, $not_before),
                role_active_until($role, $not_after),
                time($now),
                $now >= $not_before,
                $now <= $not_after;
            deny_eval($op, $res) <- deny($op, $res);
            allow if true;
            "#,
            topic = topic,
            operation = operation,
            time = now
        )
        .set_limits(authorizer_limits(max_time_ms))
        .build(biscuit),
    }
    .map_err(|_| biscuit_auth::error::Token::InternalError);
    let mut authorizer = match authorizer {
        Ok(authorizer) => authorizer,
        Err(err) => return BiscuitAuthOutcome::Error(err),
    };

    // Enforce Biscuit checks (time-based, block checks, etc.). We intentionally
    // ignore authorize()'s allow/deny decision here and perform allow/deny logic
    // manually below to support MQTT wildcard matching.
    if let Err(_err) = authorizer.authorize() {
        return BiscuitAuthOutcome::Denied; // Check failures should deny, not error
    }

    let (rights_query, denies_query) = match profile {
        BiscuitAuthorizerProfile::Simple => (
            "data($op, $res) <- right($op, $res)",
            "data($op, $res) <- deny($op, $res)",
        ),
        BiscuitAuthorizerProfile::Rbac | BiscuitAuthorizerProfile::Contextual => (
            "data($op, $res) <- right_eval($op, $res)",
            "data($op, $res) <- deny_eval($op, $res)",
        ),
    };
    let rights: Vec<(String, String)> = match authorizer.query_all(rights_query) {
        Ok(rights) => rights,
        Err(err) => return BiscuitAuthOutcome::Error(err),
    };
    let denies: Vec<(String, String)> = match authorizer.query_all(denies_query) {
        Ok(denies) => denies,
        Err(err) => return BiscuitAuthOutcome::Error(err),
    };

    let op_target = operation.trim();
    let matches = |op: &str, res: &str| {
        let op_trim = op.trim();
        let res_trim = res.trim();
        let matches_op = op_trim == op_target || (op_target == "read" && op_trim == "subscribe");
        matches_op && topic_matches(res_trim, topic)
    };

    // Short-circuit: if no rights match, check denies for errors and final decision
    let matching_rights: Vec<_> = rights.iter().filter(|(op, res)| matches(op, res)).collect();

    if matching_rights.is_empty() {
        // Still run deny query to surface errors and handle explicit denies
        if denies.iter().any(|(op, res)| matches(op, res)) {
            return BiscuitAuthOutcome::Denied;
        }
        return BiscuitAuthOutcome::Denied;
    }

    // If we have matching rights, check denies first (deny-over-allow)
    if denies.iter().any(|(op, res)| matches(op, res)) {
        return BiscuitAuthOutcome::Denied;
    }

    BiscuitAuthOutcome::Allowed
}

#[cfg(test)]
mod tests {
    use crate::config::BiscuitAuthorizerProfile;

    use super::extract_min_expiry;
    use super::{
        AuthContext, BiscuitAuthOutcome, has_profile_grant_facts_with_limits, verify_biscuit_token,
    };
    use biscuit_auth::{Biscuit, KeyPair, PrivateKey};

    fn root_keypair() -> KeyPair {
        let root_bytes = [1u8; 32];
        KeyPair::from(
            &PrivateKey::from_bytes(&root_bytes, biscuit_auth::Algorithm::Ed25519).unwrap(),
        )
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn extracts_min_expiry_from_multiple_facts() {
        let keypair = root_keypair();
        let biscuit = Biscuit::builder()
            .fact("expires_at(200)")
            .unwrap()
            .fact("expires_at(150)")
            .unwrap()
            .build(&keypair)
            .unwrap();
        let bytes = biscuit.to_vec().unwrap();

        let expiry = extract_min_expiry(&bytes, &keypair.public()).unwrap();
        assert_eq!(expiry, Some(150));
    }

    #[test]
    fn rejects_malformed_expiry_timestamps() {
        let keypair = root_keypair();
        let biscuit = Biscuit::builder()
            .fact("expires_at(\"bad\")")
            .unwrap()
            .build(&keypair)
            .unwrap();
        let bytes = biscuit.to_vec().unwrap();

        let result = extract_min_expiry(&bytes, &keypair.public());
        assert!(result.is_err());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn deny_facts_override_allow() {
        let keypair = root_keypair();
        let biscuit = Biscuit::builder()
            .fact("right(\"read\", \"sensors/client_1/temp\")")
            .unwrap()
            .fact("deny(\"read\", \"sensors/client_1/temp\")")
            .unwrap()
            .build(&keypair)
            .unwrap();
        let bytes = biscuit.to_vec().unwrap();

        let outcome = verify_biscuit_token(
            &bytes,
            &keypair.public(),
            AuthContext {
                topic: "sensors/client_1/temp",
                operation: "read",
            },
            BiscuitAuthorizerProfile::Simple,
        );
        match outcome {
            BiscuitAuthOutcome::Denied => {}
            _ => panic!("deny fact should override allow"),
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn subscribe_right_allows_read() {
        let keypair = root_keypair();
        let biscuit = Biscuit::builder()
            .fact("right(\"subscribe\", \"sensors/client_1/#\")")
            .unwrap()
            .build(&keypair)
            .unwrap();
        let bytes = biscuit.to_vec().unwrap();

        let outcome = verify_biscuit_token(
            &bytes,
            &keypair.public(),
            AuthContext {
                topic: "sensors/client_1/temp",
                operation: "read",
            },
            BiscuitAuthorizerProfile::Simple,
        );
        match outcome {
            BiscuitAuthOutcome::Allowed => {}
            _ => panic!("subscribe right should allow read"),
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn subscribe_deny_blocks_read() {
        let keypair = root_keypair();
        let biscuit = Biscuit::builder()
            .fact("right(\"subscribe\", \"sensors/client_1/#\")")
            .unwrap()
            .fact("deny(\"subscribe\", \"sensors/client_1/#\")")
            .unwrap()
            .build(&keypair)
            .unwrap();
        let bytes = biscuit.to_vec().unwrap();

        let outcome = verify_biscuit_token(
            &bytes,
            &keypair.public(),
            AuthContext {
                topic: "sensors/client_1/temp",
                operation: "read",
            },
            BiscuitAuthorizerProfile::Simple,
        );
        match outcome {
            BiscuitAuthOutcome::Denied => {}
            _ => panic!("subscribe deny should block read"),
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn wildcard_right_allows_publish() {
        let keypair = root_keypair();
        let biscuit = Biscuit::builder()
            .fact("right(\"publish\", \"sensors/client_1/#\")")
            .unwrap()
            .build(&keypair)
            .unwrap();
        let bytes = biscuit.to_vec().unwrap();

        let outcome = verify_biscuit_token(
            &bytes,
            &keypair.public(),
            AuthContext {
                topic: "sensors/client_1/temp",
                operation: "publish",
            },
            BiscuitAuthorizerProfile::Simple,
        );
        match outcome {
            BiscuitAuthOutcome::Allowed => {}
            _ => panic!("wildcard publish right should allow matching topic"),
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn checks_only_without_rights_is_denied() {
        let keypair = root_keypair();
        let biscuit = Biscuit::builder()
            .fact("resource(\"sensors/client_1/temp\")")
            .unwrap()
            .fact("operation(\"publish\")")
            .unwrap()
            .check("check if resource($res), operation($op), $res == \"sensors/client_1/temp\"")
            .unwrap()
            .build(&keypair)
            .unwrap();
        let bytes = biscuit.to_vec().unwrap();

        let outcome = verify_biscuit_token(
            &bytes,
            &keypair.public(),
            AuthContext {
                topic: "sensors/client_1/temp",
                operation: "publish",
            },
            BiscuitAuthorizerProfile::Simple,
        );
        // NOTE: This models a token that only supplies checks (no rights), which is not
        // a typical Biscuit usage pattern. We explicitly deny such tokens for safety.
        match outcome {
            BiscuitAuthOutcome::Denied => {}
            _ => panic!("token with only checks but no allow rules should be denied"),
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn rbac_profile_allows_role_derived_permission() {
        let keypair = root_keypair();
        let biscuit = Biscuit::builder()
            .fact(r#"role("writer")"#)
            .unwrap()
            .fact(r#"role_right("writer", "publish", "sensors/client_1/#")"#)
            .unwrap()
            .build(&keypair)
            .unwrap();
        let bytes = biscuit.to_vec().unwrap();

        let outcome = verify_biscuit_token(
            &bytes,
            &keypair.public(),
            AuthContext {
                topic: "sensors/client_1/temp",
                operation: "publish",
            },
            BiscuitAuthorizerProfile::Rbac,
        );
        match outcome {
            BiscuitAuthOutcome::Allowed => {}
            _ => panic!("rbac profile should allow role-derived publish right"),
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn contextual_profile_allows_within_active_window() {
        let keypair = root_keypair();
        let biscuit = Biscuit::builder()
            .fact(r#"role("writer")"#)
            .unwrap()
            .fact(r#"role_right("writer", "publish", "sensors/client_1/#")"#)
            .unwrap()
            .fact(r#"role_active_from("writer", 0)"#)
            .unwrap()
            .fact(r#"role_active_until("writer", 4102444800)"#)
            .unwrap()
            .build(&keypair)
            .unwrap();
        let bytes = biscuit.to_vec().unwrap();

        let outcome = verify_biscuit_token(
            &bytes,
            &keypair.public(),
            AuthContext {
                topic: "sensors/client_1/temp",
                operation: "publish",
            },
            BiscuitAuthorizerProfile::Contextual,
        );
        match outcome {
            BiscuitAuthOutcome::Allowed => {}
            _ => panic!("contextual profile should allow active role permission"),
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn contextual_profile_ignores_direct_right_facts() {
        let keypair = root_keypair();
        let biscuit = Biscuit::builder()
            .fact(r#"right("publish", "sensors/client_1/#")"#)
            .unwrap()
            .build(&keypair)
            .unwrap();
        let bytes = biscuit.to_vec().unwrap();

        let outcome = verify_biscuit_token(
            &bytes,
            &keypair.public(),
            AuthContext {
                topic: "sensors/client_1/temp",
                operation: "publish",
            },
            BiscuitAuthorizerProfile::Contextual,
        );
        match outcome {
            BiscuitAuthOutcome::Denied => {}
            _ => panic!("contextual profile should ignore direct right() facts"),
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn contextual_profile_direct_deny_overrides_role_right() {
        let keypair = root_keypair();
        let biscuit = Biscuit::builder()
            .fact(r#"role("writer")"#)
            .unwrap()
            .fact(r#"role_right("writer", "publish", "sensors/client_1/#")"#)
            .unwrap()
            .fact(r#"role_active_from("writer", 0)"#)
            .unwrap()
            .fact(r#"role_active_until("writer", 4102444800)"#)
            .unwrap()
            .fact(r#"deny("publish", "sensors/client_1/#")"#)
            .unwrap()
            .build(&keypair)
            .unwrap();
        let bytes = biscuit.to_vec().unwrap();

        let outcome = verify_biscuit_token(
            &bytes,
            &keypair.public(),
            AuthContext {
                topic: "sensors/client_1/temp",
                operation: "publish",
            },
            BiscuitAuthorizerProfile::Contextual,
        );
        match outcome {
            BiscuitAuthOutcome::Denied => {}
            _ => panic!("contextual profile should enforce direct deny() over role-right allow"),
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn contextual_profile_direct_subscribe_deny_blocks_read() {
        let keypair = root_keypair();
        let biscuit = Biscuit::builder()
            .fact(r#"role("writer")"#)
            .unwrap()
            .fact(r#"role_right("writer", "subscribe", "sensors/client_1/#")"#)
            .unwrap()
            .fact(r#"role_active_from("writer", 0)"#)
            .unwrap()
            .fact(r#"role_active_until("writer", 4102444800)"#)
            .unwrap()
            .fact(r#"deny("subscribe", "sensors/client_1/#")"#)
            .unwrap()
            .build(&keypair)
            .unwrap();
        let bytes = biscuit.to_vec().unwrap();

        let outcome = verify_biscuit_token(
            &bytes,
            &keypair.public(),
            AuthContext {
                topic: "sensors/client_1/temp",
                operation: "read",
            },
            BiscuitAuthorizerProfile::Contextual,
        );
        match outcome {
            BiscuitAuthOutcome::Denied => {}
            _ => panic!("contextual profile should apply direct subscribe deny() to read"),
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn contextual_profile_role_deny_overrides_role_right_within_window() {
        let keypair = root_keypair();
        let biscuit = Biscuit::builder()
            .fact(r#"role("writer")"#)
            .unwrap()
            .fact(r#"role_right("writer", "publish", "sensors/client_1/#")"#)
            .unwrap()
            .fact(r#"role_deny("writer", "publish", "sensors/client_1/#")"#)
            .unwrap()
            .fact(r#"role_active_from("writer", 0)"#)
            .unwrap()
            .fact(r#"role_active_until("writer", 4102444800)"#)
            .unwrap()
            .build(&keypair)
            .unwrap();
        let bytes = biscuit.to_vec().unwrap();

        let outcome = verify_biscuit_token(
            &bytes,
            &keypair.public(),
            AuthContext {
                topic: "sensors/client_1/temp",
                operation: "publish",
            },
            BiscuitAuthorizerProfile::Contextual,
        );
        match outcome {
            BiscuitAuthOutcome::Denied => {}
            _ => panic!("contextual role_deny() should override contextual role_right()"),
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn profile_grant_facts_simple_detects_direct_right() {
        let keypair = root_keypair();
        let biscuit = Biscuit::builder()
            .fact(r#"right("publish", "sensors/client_1/#")"#)
            .unwrap()
            .build(&keypair)
            .unwrap();
        let bytes = biscuit.to_vec().unwrap();

        let has_grants = has_profile_grant_facts_with_limits(
            &bytes,
            &keypair.public(),
            BiscuitAuthorizerProfile::Simple,
            25,
        )
        .unwrap();
        assert!(has_grants);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn profile_grant_facts_simple_ignores_role_right_only() {
        let keypair = root_keypair();
        let biscuit = Biscuit::builder()
            .fact(r#"role("writer")"#)
            .unwrap()
            .fact(r#"role_right("writer", "publish", "sensors/client_1/#")"#)
            .unwrap()
            .build(&keypair)
            .unwrap();
        let bytes = biscuit.to_vec().unwrap();

        let has_grants = has_profile_grant_facts_with_limits(
            &bytes,
            &keypair.public(),
            BiscuitAuthorizerProfile::Simple,
            25,
        )
        .unwrap();
        assert!(!has_grants);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn profile_grant_facts_rbac_detects_role_right() {
        let keypair = root_keypair();
        let biscuit = Biscuit::builder()
            .fact(r#"role("writer")"#)
            .unwrap()
            .fact(r#"role_right("writer", "publish", "sensors/client_1/#")"#)
            .unwrap()
            .build(&keypair)
            .unwrap();
        let bytes = biscuit.to_vec().unwrap();

        let has_grants = has_profile_grant_facts_with_limits(
            &bytes,
            &keypair.public(),
            BiscuitAuthorizerProfile::Rbac,
            25,
        )
        .unwrap();
        assert!(has_grants);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn profile_grant_facts_contextual_detects_active_role_right() {
        let keypair = root_keypair();
        let now = crate::time::unix_timestamp_now();
        let biscuit = Biscuit::builder()
            .fact(r#"role("writer")"#)
            .unwrap()
            .fact(r#"role_right("writer", "publish", "sensors/client_1/#")"#)
            .unwrap()
            .fact(format!(r#"role_active_from("writer", {})"#, now - 60).as_str())
            .unwrap()
            .fact(format!(r#"role_active_until("writer", {})"#, now + 60).as_str())
            .unwrap()
            .build(&keypair)
            .unwrap();
        let bytes = biscuit.to_vec().unwrap();

        let has_grants = has_profile_grant_facts_with_limits(
            &bytes,
            &keypair.public(),
            BiscuitAuthorizerProfile::Contextual,
            25,
        )
        .unwrap();
        assert!(has_grants);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn profile_grant_facts_contextual_ignores_inactive_window() {
        let keypair = root_keypair();
        let now = crate::time::unix_timestamp_now();
        let biscuit = Biscuit::builder()
            .fact(r#"role("writer")"#)
            .unwrap()
            .fact(r#"role_right("writer", "publish", "sensors/client_1/#")"#)
            .unwrap()
            .fact(format!(r#"role_active_from("writer", {})"#, now - 120).as_str())
            .unwrap()
            .fact(format!(r#"role_active_until("writer", {})"#, now - 60).as_str())
            .unwrap()
            .build(&keypair)
            .unwrap();
        let bytes = biscuit.to_vec().unwrap();

        let has_grants = has_profile_grant_facts_with_limits(
            &bytes,
            &keypair.public(),
            BiscuitAuthorizerProfile::Contextual,
            25,
        )
        .unwrap();
        assert!(!has_grants);
    }
}
