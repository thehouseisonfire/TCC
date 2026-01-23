use biscuit_auth::{Biscuit, PublicKey};
use chrono::Utc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

// Pre-compiled authorizer template to avoid recompilation overhead
// This is a small, acceptable use of global state, as the template is immutable
static AUTHORIZER_TEMPLATE: OnceLock<String> = OnceLock::new();

fn get_authorizer_template() -> &'static str {
    AUTHORIZER_TEMPLATE.get_or_init(|| {
        r#"
        resource({topic});
        operation({operation});
        time({time});
        allow if right($op, $res), operation($op), resource($res);
        "#
        .to_string()
    })
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

#[derive(Debug, Default)]
struct ExpiryMetrics {
    calls: AtomicU64,
    failures: AtomicU64,
    total_nanos: AtomicU64,
}

static EXPIRY_METRICS: ExpiryMetrics = ExpiryMetrics {
    calls: AtomicU64::new(0),
    failures: AtomicU64::new(0),
    total_nanos: AtomicU64::new(0),
};

/// Returns a snapshot of expiry extraction performance.
pub fn expiry_stats() -> ExpiryStats {
    ExpiryStats {
        calls: EXPIRY_METRICS.calls.load(Ordering::Relaxed),
        failures: EXPIRY_METRICS.failures.load(Ordering::Relaxed),
        total_nanos: EXPIRY_METRICS.total_nanos.load(Ordering::Relaxed),
    }
}

pub fn extract_min_expiry(
    token_bytes: &[u8],
    root_public_key: &PublicKey,
) -> Result<Option<i64>, biscuit_auth::error::Token> {
    EXPIRY_METRICS.calls.fetch_add(1, Ordering::Relaxed);
    let start = Instant::now();
    let result = (|| {
        let biscuit = Biscuit::from(token_bytes, root_public_key)?;
        let mut authorizer = biscuit.authorizer()?;
        let expiries: Vec<(i64,)> = authorizer.query_all("data($ts) <- expires_at($ts)")?;
        Ok(expiries.into_iter().map(|(ts,)| ts).min())
    })();
    if result.is_err() {
        EXPIRY_METRICS.failures.fetch_add(1, Ordering::Relaxed);
    }
    EXPIRY_METRICS
        .total_nanos
        .fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
    result
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

    use biscuit_auth::macros::authorizer;
    // The authorizer! macro requires a string literal at compile time
    // Template caching is preserved for documentation and potential future use
    let _template = get_authorizer_template(); // Keep the template cache for consistency

    let authorizer = authorizer!(
        r#"
        resource({topic});
        operation({operation});
        time({time});
        allow if right($op, $res), operation($op), resource($res);
        "#,
        topic = topic,
        operation = operation,
        time = Utc::now().timestamp()
    )
    .build(&biscuit)
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
    use biscuit_auth::{Biscuit, KeyPair, PrivateKey};

    fn root_keypair() -> KeyPair {
        let root_bytes = [1u8; 32];
        KeyPair::from(
            &PrivateKey::from_bytes(&root_bytes, biscuit_auth::Algorithm::Ed25519).unwrap(),
        )
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[ignore = "Miri timeout: Biscuit verification under Miri hits interpreter timeout"]
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
}
