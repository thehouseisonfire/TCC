use biscuit_auth::{Biscuit, BlockBuilder, PublicKey};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Default)]
pub struct BiscuitAttenuationOptions {
    pub denies: Vec<String>,
    pub checks: Vec<String>,
    pub restrict_topic: Option<String>,
    pub restrict_operation: Option<String>,
    pub ttl_seconds: Option<i64>,
}

pub fn load_public_key_hex(hex_value: &str) -> Result<PublicKey, String> {
    let bytes = hex::decode(hex_value.trim()).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32-byte public key, got {}", bytes.len()));
    }
    PublicKey::from_bytes(&bytes, biscuit_auth::Algorithm::Ed25519)
        .map_err(|e| format!("invalid public key: {e}"))
}

pub fn attenuate_biscuit_token(
    token_bytes: &[u8],
    public_key: PublicKey,
    options: &BiscuitAttenuationOptions,
) -> Result<Vec<u8>, String> {
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("time error: {e}"))?
            .as_secs(),
    )
    .map_err(|_| "time error: timestamp exceeds i64 range".to_string())?;
    attenuate_biscuit_token_at(token_bytes, public_key, options, now)
}

pub fn attenuate_biscuit_token_at(
    token_bytes: &[u8],
    public_key: PublicKey,
    options: &BiscuitAttenuationOptions,
    now_unix_seconds: i64,
) -> Result<Vec<u8>, String> {
    let biscuit =
        Biscuit::from(token_bytes, public_key).map_err(|e| format!("token parse failed: {e}"))?;

    let mut block = BlockBuilder::new();
    let mut added = false;

    if let Some(restrict_topic) = options.restrict_topic.as_deref() {
        let topic = escape_datalog_str(restrict_topic);
        let check = options.restrict_operation.as_deref().map_or_else(
            || format!("check if resource(\"{topic}\")"),
            |op| {
                let op = escape_datalog_str(op);
                format!("check if operation(\"{op}\"), resource(\"{topic}\")")
            },
        );
        block = block
            .check(check.as_str())
            .map_err(|e| format!("restrict check failed: {e}"))?;
        added = true;
    } else if let Some(op) = options.restrict_operation.as_deref() {
        let op = escape_datalog_str(op);
        let check = format!("check if operation(\"{op}\")");
        block = block
            .check(check.as_str())
            .map_err(|e| format!("restrict check failed: {e}"))?;
        added = true;
    }

    for check in &options.checks {
        let check_src = normalize_check(check);
        block = block
            .check(check_src.as_str())
            .map_err(|e| format!("check failed: {e}"))?;
        added = true;
    }

    for deny in &options.denies {
        let (op, res) = parse_denied_spec(deny)?;
        let op = escape_datalog_str(&op);
        let res = escape_datalog_str(&res);
        let fact = format!("deny(\"{op}\", \"{res}\")");
        block = block
            .fact(fact.as_str())
            .map_err(|e| format!("deny fact failed: {e}"))?;
        added = true;
    }

    if let Some(ttl_seconds) = options.ttl_seconds {
        let exp = now_unix_seconds + ttl_seconds.max(1);
        let check_src = format!("check if time($t), $t < {exp}");
        let expires_fact = format!("expires_at({exp})");
        block = block
            .check(check_src.as_str())
            .map_err(|e| format!("ttl check failed: {e}"))?
            .fact(expires_fact.as_str())
            .map_err(|e| format!("ttl fact failed: {e}"))?;
        added = true;
    }

    if !added {
        return Err("no attenuation rules specified".to_string());
    }

    let attenuated = biscuit
        .append(block)
        .map_err(|e| format!("append failed: {e}"))?;
    attenuated
        .to_vec()
        .map_err(|e| format!("encode failed: {e}"))
}

fn escape_datalog_str(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn parse_denied_spec(spec: &str) -> Result<(String, String), String> {
    let separators = [':', ',', '='];
    for sep in separators {
        if let Some((op, res)) = spec.split_once(sep) {
            let op = op.trim();
            let res = res.trim();
            if op.is_empty() || res.is_empty() {
                break;
            }
            return Ok((op.to_string(), res.to_string()));
        }
    }
    Err(format!("invalid deny spec '{spec}', expected op:res"))
}

fn normalize_check(check: &str) -> String {
    let trimmed = check.trim();
    if trimmed.starts_with("check ") || trimmed.starts_with("check\t") {
        trimmed.to_string()
    } else {
        format!("check if {trimmed}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use biscuit_auth::{KeyPair, PrivateKey};

    fn root_keypair() -> KeyPair {
        let root_bytes = [1u8; 32];
        KeyPair::from(
            &PrivateKey::from_bytes(&root_bytes, biscuit_auth::Algorithm::Ed25519).unwrap(),
        )
    }

    fn base_token(keypair: &KeyPair) -> Vec<u8> {
        Biscuit::builder()
            .fact(r#"right("publish", "sensors/client_1/temp")"#)
            .unwrap()
            .fact(r#"right("subscribe", "sensors/client_1/temp")"#)
            .unwrap()
            .fact("expires_at(2000000000)")
            .unwrap()
            .build(keypair)
            .unwrap()
            .to_vec()
            .unwrap()
    }

    fn query_data(token: &[u8], keypair: &KeyPair, query: &str) -> Vec<(String, String)> {
        let biscuit = Biscuit::from(token, keypair.public()).unwrap();
        let mut authorizer = biscuit_auth::AuthorizerBuilder::new()
            .fact(r#"resource("sensors/client_1/temp")"#)
            .unwrap()
            .fact(r#"operation("publish")"#)
            .unwrap()
            .rule(r#"data($op, $res) <- deny($op, $res)"#)
            .unwrap()
            .rule(r#"data($op, $res) <- right($op, $res)"#)
            .unwrap()
            .build(&biscuit)
            .unwrap();
        authorizer.authorize().ok();
        authorizer.query_all(query).unwrap()
    }

    #[test]
    fn appends_restrict_topic_and_operation_check() {
        let keypair = root_keypair();
        let token = base_token(&keypair);
        let output = attenuate_biscuit_token_at(
            &token,
            keypair.public(),
            &BiscuitAttenuationOptions {
                restrict_topic: Some("sensors/client_1/temp".to_string()),
                restrict_operation: Some("publish".to_string()),
                ..BiscuitAttenuationOptions::default()
            },
            1000,
        )
        .unwrap();

        let biscuit = Biscuit::from(&output, keypair.public()).unwrap();
        let mut authorizer = biscuit_auth::AuthorizerBuilder::new()
            .fact(r#"resource("sensors/client_1/temp")"#)
            .unwrap()
            .fact(r#"operation("publish")"#)
            .unwrap()
            .policy("allow if true")
            .unwrap()
            .build(&biscuit)
            .unwrap();
        assert!(authorizer.authorize().is_ok());
    }

    #[test]
    fn appends_deny_fact() {
        let keypair = root_keypair();
        let token = base_token(&keypair);
        let output = attenuate_biscuit_token_at(
            &token,
            keypair.public(),
            &BiscuitAttenuationOptions {
                denies: vec!["publish:sensors/client_1/temp".to_string()],
                ..BiscuitAttenuationOptions::default()
            },
            1000,
        )
        .unwrap();

        let rows = query_data(&output, &keypair, "data($op, $res) <- deny($op, $res)");
        assert_eq!(
            rows,
            vec![("publish".to_string(), "sensors/client_1/temp".to_string())]
        );
    }

    #[test]
    fn normalizes_raw_checks() {
        let keypair = root_keypair();
        let token = base_token(&keypair);
        let output = attenuate_biscuit_token_at(
            &token,
            keypair.public(),
            &BiscuitAttenuationOptions {
                checks: vec![
                    r#"operation("publish")"#.to_string(),
                    r#"check if resource("sensors/client_1/temp")"#.to_string(),
                ],
                ..BiscuitAttenuationOptions::default()
            },
            1000,
        )
        .unwrap();
        let biscuit = Biscuit::from(&output, keypair.public()).unwrap();
        let mut authorizer = biscuit_auth::AuthorizerBuilder::new()
            .fact(r#"resource("sensors/client_1/temp")"#)
            .unwrap()
            .fact(r#"operation("publish")"#)
            .unwrap()
            .policy("allow if true")
            .unwrap()
            .build(&biscuit)
            .unwrap();
        assert!(authorizer.authorize().is_ok());
    }

    #[test]
    fn ttl_adds_minimum_expiry_fact() {
        let keypair = root_keypair();
        let token = base_token(&keypair);
        let output = attenuate_biscuit_token_at(
            &token,
            keypair.public(),
            &BiscuitAttenuationOptions {
                ttl_seconds: Some(0),
                ..BiscuitAttenuationOptions::default()
            },
            1000,
        )
        .unwrap();

        let biscuit = Biscuit::from(&output, keypair.public()).unwrap();
        let mut authorizer = biscuit_auth::AuthorizerBuilder::new()
            .build(&biscuit)
            .unwrap();
        let expiries: Vec<(i64,)> = authorizer
            .query_all("data($ts) <- expires_at($ts)")
            .unwrap();
        assert!(expiries.contains(&(1001,)));
    }

    #[test]
    fn rejects_empty_options() {
        let keypair = root_keypair();
        let token = base_token(&keypair);
        let err = attenuate_biscuit_token_at(
            &token,
            keypair.public(),
            &BiscuitAttenuationOptions::default(),
            1000,
        )
        .unwrap_err();
        assert_eq!(err, "no attenuation rules specified");
    }

    #[test]
    fn rejects_invalid_deny_spec() {
        let keypair = root_keypair();
        let token = base_token(&keypair);
        let err = attenuate_biscuit_token_at(
            &token,
            keypair.public(),
            &BiscuitAttenuationOptions {
                denies: vec!["publish".to_string()],
                ..BiscuitAttenuationOptions::default()
            },
            1000,
        )
        .unwrap_err();
        assert_eq!(err, "invalid deny spec 'publish', expected op:res");
    }

    #[test]
    fn rejects_invalid_public_key_hex() {
        let err = load_public_key_hex("abcd").unwrap_err();
        assert_eq!(err, "expected 32-byte public key, got 2");
    }
}
