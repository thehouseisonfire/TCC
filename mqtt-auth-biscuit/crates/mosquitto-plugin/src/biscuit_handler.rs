use biscuit_auth::{Biscuit, PublicKey};
use chrono::Utc;
use std::collections::HashMap;
#[cfg(feature = "expiry_stats")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
#[cfg(feature = "expiry_stats")]
use std::time::Instant;

// Pre-compiled authorizer template to avoid recompilation overhead
// This is a small, acceptable use of global state, as the template is immutable
static AUTHORIZER_TEMPLATE: OnceLock<String> = OnceLock::new();
static ROLE_AUTHORIZER_TEMPLATE: OnceLock<String> = OnceLock::new();
static ROLE_QUERY_CACHE: OnceLock<Mutex<HashMap<String, Arc<str>>>> = OnceLock::new();

fn get_authorizer_template() -> &'static str {
    AUTHORIZER_TEMPLATE.get_or_init(|| {
        r#"
        resource({topic});
        operation({operation});
        time({time});
        deny if deny("subscribe", $res), operation("read"), resource($res);
        deny if deny($op, $res), operation($op), resource($res);
        allow if right("subscribe", $res), operation("read"), resource($res);
        allow if right($op, $res), operation($op), resource($res);
        "#
        .to_string()
    })
}

fn get_role_authorizer_template() -> &'static str {
    ROLE_AUTHORIZER_TEMPLATE.get_or_init(|| {
        r#"
        role({role});
        allow if role($role);
        "#
        .to_string()
    })
}

fn cached_role_query(role_fact: &str) -> Arc<str> {
    let cache = ROLE_QUERY_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut cache) = cache.lock() {
        if let Some(query) = cache.get(role_fact) {
            return Arc::clone(query);
        }
        let query: Arc<str> = format!("data($role) <- {}($role)", role_fact).into();
        cache.insert(role_fact.to_string(), Arc::clone(&query));
        return query;
    }
    format!("data($role) <- {}($role)", role_fact).into()
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
    EXPIRY_METRICS
        .total_nanos
        .fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
    result
}

fn extract_min_expiry_query(biscuit: &Biscuit) -> Result<Option<i64>, biscuit_auth::error::Token> {
    let mut authorizer = biscuit.authorizer()?;
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
    with_expiry_metrics(|| {
        let biscuit = Biscuit::from(token_bytes, root_public_key)?;
        extract_min_expiry_query(&biscuit)
    })
}

pub fn extract_min_expiry_from_biscuit(
    biscuit: &Biscuit,
) -> Result<Option<i64>, biscuit_auth::error::Token> {
    with_expiry_metrics(|| extract_min_expiry_query(biscuit))
}

#[allow(dead_code)]
pub fn extract_roles(
    token_bytes: &[u8],
    root_public_key: &PublicKey,
    role_fact: &str,
) -> Result<Vec<String>, biscuit_auth::error::Token> {
    // Template caching is advisory; authorizer queries are constructed explicitly below.
    let _template = get_role_authorizer_template();
    let biscuit = Biscuit::from(token_bytes, root_public_key)?;
    let mut authorizer = biscuit.authorizer()?;
    let query = cached_role_query(role_fact);
    let roles: Vec<(String,)> = authorizer.query_all(query.as_ref())?;
    Ok(roles.into_iter().map(|(role,)| role).collect())
}

pub fn extract_roles_from_biscuit(
    biscuit: &Biscuit,
    role_fact: &str,
) -> Result<Vec<String>, biscuit_auth::error::Token> {
    let _template = get_role_authorizer_template();
    let mut authorizer = biscuit.authorizer()?;
    let query = cached_role_query(role_fact);
    let roles: Vec<(String,)> = authorizer.query_all(query.as_ref())?;
    Ok(roles.into_iter().map(|(role,)| role).collect())
}

pub fn has_right_facts(
    token_bytes: &[u8],
    root_public_key: &PublicKey,
) -> Result<bool, biscuit_auth::error::Token> {
    let biscuit = Biscuit::from(token_bytes, root_public_key)?;
    let mut authorizer = biscuit.authorizer()?;
    let rights: Vec<(String, String)> =
        authorizer.query_all("data($op, $res) <- right($op, $res)")?;
    Ok(!rights.is_empty())
}

pub fn verify_biscuit_token(
    token_bytes: &[u8],
    root_public_key: &PublicKey,
    topic: &str,
    operation: &str, // "publish" or "subscribe"
) -> BiscuitAuthOutcome {
    // Deserialize token
    let biscuit = match Biscuit::from(token_bytes, root_public_key) {
        Ok(token) => token,
        Err(err) => return BiscuitAuthOutcome::Error(err),
    };

    authorize_biscuit(&biscuit, topic, operation)
}

pub fn authorize_biscuit(
    biscuit: &Biscuit,
    topic: &str,
    operation: &str, // "publish" or "subscribe"
) -> BiscuitAuthOutcome {
    use biscuit_auth::macros::authorizer;
    // The authorizer! macro requires a string literal at compile time
    // Template caching is preserved for documentation and potential future use
    let _template = get_authorizer_template(); // Keep the template cache for consistency

    let authorizer = authorizer!(
        r#"
        resource({topic});
        operation({operation});
        time({time});
        deny if deny("subscribe", $res), operation("read"), resource($res);
        deny if deny($op, $res), operation($op), resource($res);
        allow if right("subscribe", $res), operation("read"), resource($res);
        allow if right($op, $res), operation($op), resource($res);
        "#,
        topic = topic,
        operation = operation,
        time = Utc::now().timestamp()
    )
    .build(biscuit)
    .map_err(|_| biscuit_auth::error::Token::InternalError);
    let mut authorizer = match authorizer {
        Ok(authorizer) => authorizer,
        Err(err) => return BiscuitAuthOutcome::Error(err),
    };

    // Authorize
    match authorizer.authorize() {
        Ok(_) => BiscuitAuthOutcome::Allowed,
        Err(_) => BiscuitAuthOutcome::Denied,
    }
}

#[cfg(test)]
mod tests {
    use super::extract_min_expiry;
    use super::{verify_biscuit_token, BiscuitAuthOutcome};
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

        let outcome =
            verify_biscuit_token(&bytes, &keypair.public(), "sensors/client_1/temp", "read");
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

        let outcome =
            verify_biscuit_token(&bytes, &keypair.public(), "sensors/client_1/temp", "read");
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

        let outcome =
            verify_biscuit_token(&bytes, &keypair.public(), "sensors/client_1/temp", "read");
        match outcome {
            BiscuitAuthOutcome::Denied => {}
            _ => panic!("subscribe deny should block read"),
        }
    }
}
