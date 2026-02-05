use biscuit_auth::{Biscuit, BlockBuilder, KeyPair, PrivateKey};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use p256::SecretKey;
use pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;
use std::fs::File;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

// Constants for reproducible benchmark fixtures
const LONG_EXP: i64 = 2_000_000_000; // Year 2033
const SHORT_TTL_SECS: i64 = 5;
const BISCUIT_BLOCKS_MEDIUM: usize = 5;
const BISCUIT_BLOCKS_LARGE: usize = 25;
const BASE_TOPIC: &str = "sensors/client_1/temp";
const TEST_JWT_SK_BYTES: [u8; 32] = [1u8; 32];
const TEST_BISCUIT_ROOT_BYTES: [u8; 32] = [0u8; 32];

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    roles: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grants: Option<Vec<JwtGrant>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    denies: Option<Vec<JwtGrant>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JwtGrant {
    op: String,
    res: String,
}

fn main() {
    let now = if let Ok(val) = env::var("GEN_TOKENS_FIXED_NOW") {
        val.parse::<i64>()
            .expect("GEN_TOKENS_FIXED_NOW must be int")
    } else {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    };
    // JWT (ES256)
    // Deterministic private key material for reproducible tokens.
    // This private key is held by the token issuer (this generator) and is
    // never mounted into the Mosquitto container.
    let jwt_sk_bytes = TEST_JWT_SK_BYTES;
    let jwt_secret_key = SecretKey::from_slice(&jwt_sk_bytes).unwrap();
    let jwt_private_pem = jwt_secret_key.to_pkcs8_pem(LineEnding::LF).unwrap();
    let jwt_public_pem = jwt_secret_key
        .public_key()
        .to_public_key_pem(LineEnding::LF)
        .unwrap();

    // Write public key for the broker/PEP (mounted into the container).
    std::fs::write("docker/jwt_public.pem", jwt_public_pem.as_bytes()).unwrap();

    let jwt_encoding_key = EncodingKey::from_ec_pem(jwt_private_pem.as_bytes()).unwrap();

    let jwt_long = {
        let topic = BASE_TOPIC.to_string();
        let claims = Claims {
            sub: "client_1".to_string(),
            exp: LONG_EXP,
            roles: Some(vec!["admin".to_string()]),
            grants: Some(vec![
                JwtGrant {
                    op: "publish".to_string(),
                    res: topic.clone(),
                },
                JwtGrant {
                    op: "subscribe".to_string(),
                    res: topic,
                },
            ]),
            denies: None,
        };
        encode(&Header::new(Algorithm::ES256), &claims, &jwt_encoding_key).unwrap()
    };

    let jwt_deny = {
        let topic = BASE_TOPIC.to_string();
        let claims = Claims {
            sub: "client_1".to_string(),
            exp: LONG_EXP,
            roles: Some(vec!["admin".to_string()]),
            grants: Some(vec![
                JwtGrant {
                    op: "publish".to_string(),
                    res: topic.clone(),
                },
                JwtGrant {
                    op: "subscribe".to_string(),
                    res: topic.clone(),
                },
            ]),
            denies: Some(vec![JwtGrant {
                op: "read".to_string(),
                res: topic,
            }]),
        };
        encode(&Header::new(Algorithm::ES256), &claims, &jwt_encoding_key).unwrap()
    };

    let jwt_short = {
        let topic = BASE_TOPIC.to_string();
        let claims = Claims {
            sub: "client_1".to_string(),
            exp: now + SHORT_TTL_SECS,
            roles: Some(vec!["admin".to_string()]),
            grants: Some(vec![
                JwtGrant {
                    op: "publish".to_string(),
                    res: topic.clone(),
                },
                JwtGrant {
                    op: "subscribe".to_string(),
                    res: topic,
                },
            ]),
            denies: None,
        };
        encode(&Header::new(Algorithm::ES256), &claims, &jwt_encoding_key).unwrap()
    };

    // Biscuit
    let root_bytes = TEST_BISCUIT_ROOT_BYTES;
    let root_keypair = KeyPair::from(
        &PrivateKey::from_bytes(&root_bytes, biscuit_auth::Algorithm::Ed25519).unwrap(),
    );

    let biscuit_base = Biscuit::builder()
        .fact("right(\"publish\", \"sensors/client_1/temp\")")
        .unwrap()
        .fact("right(\"subscribe\", \"sensors/client_1/temp\")")
        .unwrap()
        .fact("expires_at(2000000000)")
        .unwrap()
        .build(&root_keypair)
        .unwrap();

    let biscuit_short = {
        let exp = now + SHORT_TTL_SECS;
        let check_src = format!("check if time($t), $t < {}", exp);
        let b = BlockBuilder::new()
            .check(check_src.as_str())
            .unwrap()
            .fact(format!("expires_at({})", exp).as_str())
            .unwrap();
        biscuit_base.append(b).unwrap()
    };

    let biscuit_1_block = biscuit_base.clone();

    let biscuit_5_blocks = {
        let mut t = biscuit_base.clone();
        for _ in 0..(BISCUIT_BLOCKS_MEDIUM - 1) {
            let b = BlockBuilder::new();
            t = t.append(b).unwrap();
        }
        t
    };

    let biscuit_25_blocks = {
        let mut t = biscuit_base.clone();
        for _ in 0..(BISCUIT_BLOCKS_LARGE - 1) {
            let b = BlockBuilder::new();
            t = t.append(b).unwrap();
        }
        t
    };

    let biscuit_delegated = {
        let master = Biscuit::builder()
            .fact("right(\"publish\", \"sensors/client_1/temp\")")
            .unwrap()
            .fact("right(\"publish\", \"sensors/client_1/humidity\")")
            .unwrap()
            .fact("expires_at(2000000000)")
            .unwrap()
            .build(&root_keypair)
            .unwrap();

        let b = BlockBuilder::new()
            .check("check if resource(\"sensors/client_1/temp\")")
            .unwrap()
            .fact("expires_at(2000000000)")
            .unwrap();
        master.append(b).unwrap()
    };

    let biscuit_deny = {
        let deny_block = BlockBuilder::new()
            .fact("deny(\"read\", \"sensors/client_1/temp\")")
            .unwrap();
        biscuit_base.append(deny_block).unwrap()
    };

    let biscuit_complex_base = Biscuit::builder()
        .fact(r#"role("sensor")"#)
        .unwrap()
        .fact(r#"role("writer")"#)
        .unwrap()
        .fact(r#"group("telemetry")"#)
        .unwrap()
        .fact(r#"op_role("sensor", "publish")"#)
        .unwrap()
        .fact(r#"op_role("sensor", "subscribe")"#)
        .unwrap()
        .fact(r#"resource_group("sensors/client_1/temp", "telemetry")"#)
        .unwrap()
        .fact(r#"allow_group("telemetry")"#)
        .unwrap()
        .fact("expires_at(2000000000)")
        .unwrap()
        .rule(r#"allow_op($op) <- role("sensor"), op_role("sensor", $op)"#)
        .unwrap()
        .rule(r#"allow_res($res) <- resource_group($res, "telemetry"), allow_group("telemetry")"#)
        .unwrap()
        .rule(
            r#"right($op, $res) <- allow_op($op), allow_res($res), operation($op), resource($res)"#,
        )
        .unwrap()
        .build(&root_keypair)
        .unwrap();

    let biscuit_complex_low = biscuit_complex_base.clone();

    let biscuit_complex_med = {
        let mut t = biscuit_complex_base.clone();
        let block_scope = BlockBuilder::new()
            .fact(r#"scope("client_1")"#)
            .unwrap()
            .fact(r#"owner("sensors/client_1/temp", "client_1")"#)
            .unwrap()
            .fact(r#"allow_scope("client_1")"#)
            .unwrap()
            .rule(r#"scoped_res($res) <- owner($res, $c), allow_scope($c)"#)
            .unwrap()
            .rule(r#"allow_res($res) <- scoped_res($res), resource_group($res, "telemetry")"#)
            .unwrap();
        t = t.append(block_scope).unwrap();

        let block_caps = BlockBuilder::new()
            .fact(r#"capability("sensor", "pubsub")"#)
            .unwrap()
            .fact(r#"capability_op("pubsub", "publish")"#)
            .unwrap()
            .fact(r#"capability_op("pubsub", "subscribe")"#)
            .unwrap()
            .rule(
                r#"allow_op($op) <- role("sensor"), capability("sensor", $cap), capability_op($cap, $op)"#,
            )
            .unwrap()
            .check("check if time($t), $t < 2000000000")
            .unwrap();
        t.append(block_caps).unwrap()
    };

    let biscuit_complex_high = {
        let mut t = biscuit_complex_med.clone();
        let block_region = BlockBuilder::new()
            .fact(r#"region("client_1", "lab")"#)
            .unwrap()
            .fact(r#"region_allow("lab")"#)
            .unwrap()
            .fact(r#"topic_region("sensors/client_1/temp", "lab")"#)
            .unwrap()
            .rule(r#"regional_res($res) <- topic_region($res, $r), region_allow($r)"#)
            .unwrap()
            .rule(r#"allow_res($res) <- scoped_res($res), regional_res($res)"#)
            .unwrap();
        t = t.append(block_region).unwrap();

        let block_device = BlockBuilder::new()
            .fact(r#"device("client_1", "sensor")"#)
            .unwrap()
            .fact(r#"device_class("sensor", "telemetry")"#)
            .unwrap()
            .fact(r#"class_op("telemetry", "publish")"#)
            .unwrap()
            .fact(r#"class_op("telemetry", "subscribe")"#)
            .unwrap()
            .rule(
                r#"device_op($op) <- device($c, $class), device_class($class, $group), class_op($group, $op)"#,
            )
            .unwrap()
            .rule(r#"allow_op($op) <- device_op($op), role("sensor")"#)
            .unwrap()
            .check("check if time($t), $t < 2000000000")
            .unwrap();
        t.append(block_device).unwrap()
    };

    let biscuit_handoff = Biscuit::builder()
        .fact("right(\"publish\", \"delegation/handoff\")")
        .unwrap()
        .fact("right(\"subscribe\", \"delegation/handoff\")")
        .unwrap()
        .fact("expires_at(2000000000)")
        .unwrap()
        .build(&root_keypair)
        .unwrap();

    // We want the token as base64 for the MQTT password field
    let biscuit_bytes = biscuit_1_block.to_vec().unwrap();
    use base64::{Engine as _, engine::general_purpose};
    let biscuit_b64 = general_purpose::STANDARD.encode(&biscuit_bytes);

    let biscuit_5_b64 = general_purpose::STANDARD.encode(biscuit_5_blocks.to_vec().unwrap());
    let biscuit_25_b64 = general_purpose::STANDARD.encode(biscuit_25_blocks.to_vec().unwrap());
    let biscuit_delegated_b64 =
        general_purpose::STANDARD.encode(biscuit_delegated.to_vec().unwrap());
    let biscuit_deny_b64 = general_purpose::STANDARD.encode(biscuit_deny.to_vec().unwrap());
    let biscuit_short_b64 = general_purpose::STANDARD.encode(biscuit_short.to_vec().unwrap());
    let biscuit_handoff_b64 = general_purpose::STANDARD.encode(biscuit_handoff.to_vec().unwrap());
    let biscuit_complex_low_b64 =
        general_purpose::STANDARD.encode(biscuit_complex_low.to_vec().unwrap());
    let biscuit_complex_med_b64 =
        general_purpose::STANDARD.encode(biscuit_complex_med.to_vec().unwrap());
    let biscuit_complex_high_b64 =
        general_purpose::STANDARD.encode(biscuit_complex_high.to_vec().unwrap());

    let biscuit_pubkey_hex = hex::encode(root_keypair.public().to_bytes());
    std::fs::write("docker/biscuit_public.key", biscuit_pubkey_hex.as_bytes()).unwrap();

    let jwt_grants_schema = json!({
        "version": "v1",
        "default_grants": [
            {"op": "publish", "res": "sensors/{subject}/temp"},
            {"op": "subscribe", "res": "sensors/{subject}/temp"}
        ]
    });

    let jwt_denies_schema = json!({
        "version": "v1",
        "rules": []
    });

    let tokens = json!({
        "jwt": jwt_long,
        "jwt_short": jwt_short,
        "jwt_deny": jwt_deny,
        "jwt_alg": "ES256",
        "jwt_grants_schema": jwt_grants_schema,
        "jwt_denies_schema": jwt_denies_schema,
        "biscuit": biscuit_b64,
        "biscuit_5": biscuit_5_b64,
        "biscuit_25": biscuit_25_b64,
        "biscuit_delegated": biscuit_delegated_b64,
        "biscuit_deny": biscuit_deny_b64,
        "biscuit_short": biscuit_short_b64,
        "biscuit_delegation_handoff": biscuit_handoff_b64,
        "biscuit_complex_low": biscuit_complex_low_b64,
        "biscuit_complex_med": biscuit_complex_med_b64,
        "biscuit_complex_high": biscuit_complex_high_b64,
        "biscuit_root_key_hex": biscuit_pubkey_hex
    });

    let mut f = File::create("benchmarks/tokens.json").unwrap();
    f.write_all(serde_json::to_string_pretty(&tokens).unwrap().as_bytes())
        .unwrap();
    println!("Wrote benchmarks/tokens.json");
}
