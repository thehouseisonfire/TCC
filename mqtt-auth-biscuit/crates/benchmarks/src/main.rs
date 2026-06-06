use base64::{Engine as _, engine::general_purpose};
use biscuit_auth::{Biscuit, BlockBuilder, KeyPair, PrivateKey};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use p256::SecretKey;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
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
const FANOUT_TOPIC: &str = "fanout/broadcast";
const TEST_JWT_SK_BYTES: [u8; 32] = [1u8; 32];
const TEST_BISCUIT_ROOT_BYTES: [u8; 32] = [0u8; 32];

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
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

fn make_claims(
    sub: &str,
    exp: i64,
    client_id: Option<&str>,
    roles: Option<Vec<String>>,
    grants: Option<Vec<JwtGrant>>,
    denies: Option<Vec<JwtGrant>>,
) -> Claims {
    Claims {
        sub: sub.to_string(),
        exp,
        client_id: client_id.map(str::to_string),
        roles,
        grants,
        denies,
    }
}

fn build_biscuit_with_identity(
    root_keypair: &KeyPair,
    facts: &[&str],
    identity_fact: Option<(&str, &str)>,
) -> Biscuit {
    let mut builder = Biscuit::builder();
    for fact in facts {
        builder = builder.fact(*fact).unwrap();
    }
    if let Some((predicate, value)) = identity_fact {
        builder = builder
            .fact(format!(r#"{predicate}("{value}")"#).as_str())
            .unwrap();
    }
    builder.build(root_keypair).unwrap()
}

#[allow(clippy::too_many_lines)]
fn main() {
    let now = env::var("GEN_TOKENS_FIXED_NOW").map_or_else(
        |_| {
            i64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )
            .expect("unix timestamp must fit in i64")
        },
        |val| {
            val.parse::<i64>()
                .expect("GEN_TOKENS_FIXED_NOW must be int")
        },
    );
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
        let claims = make_claims(
            "client_1",
            LONG_EXP,
            None,
            Some(vec!["admin".to_string()]),
            Some(vec![
                JwtGrant {
                    op: "publish".to_string(),
                    res: topic.clone(),
                },
                JwtGrant {
                    op: "subscribe".to_string(),
                    res: topic,
                },
            ]),
            None,
        );
        encode(&Header::new(Algorithm::ES256), &claims, &jwt_encoding_key).unwrap()
    };

    let jwt_deny = {
        let topic = BASE_TOPIC.to_string();
        let claims = make_claims(
            "client_1",
            LONG_EXP,
            None,
            Some(vec!["admin".to_string()]),
            Some(vec![
                JwtGrant {
                    op: "publish".to_string(),
                    res: topic.clone(),
                },
                JwtGrant {
                    op: "subscribe".to_string(),
                    res: topic.clone(),
                },
            ]),
            Some(vec![JwtGrant {
                op: "read".to_string(),
                res: topic,
            }]),
        );
        encode(&Header::new(Algorithm::ES256), &claims, &jwt_encoding_key).unwrap()
    };

    let jwt_short = {
        let topic = BASE_TOPIC.to_string();
        let claims = make_claims(
            "client_1",
            now + SHORT_TTL_SECS,
            None,
            Some(vec!["admin".to_string()]),
            Some(vec![
                JwtGrant {
                    op: "publish".to_string(),
                    res: topic.clone(),
                },
                JwtGrant {
                    op: "subscribe".to_string(),
                    res: topic,
                },
            ]),
            None,
        );
        encode(&Header::new(Algorithm::ES256), &claims, &jwt_encoding_key).unwrap()
    };

    let jwt_fanout_allow = {
        let topic = FANOUT_TOPIC.to_string();
        let claims = make_claims(
            "client_1",
            LONG_EXP,
            None,
            Some(vec!["reader".to_string(), "writer".to_string()]),
            Some(vec![
                JwtGrant {
                    op: "publish".to_string(),
                    res: topic.clone(),
                },
                JwtGrant {
                    op: "subscribe".to_string(),
                    res: topic,
                },
            ]),
            None,
        );
        encode(&Header::new(Algorithm::ES256), &claims, &jwt_encoding_key).unwrap()
    };

    let jwt_fanout_read_deny = {
        let topic = FANOUT_TOPIC.to_string();
        let claims = make_claims(
            "client_1",
            LONG_EXP,
            None,
            Some(vec!["reader".to_string()]),
            Some(vec![
                JwtGrant {
                    op: "publish".to_string(),
                    res: topic.clone(),
                },
                JwtGrant {
                    op: "subscribe".to_string(),
                    res: topic.clone(),
                },
            ]),
            Some(vec![JwtGrant {
                op: "read".to_string(),
                res: topic,
            }]),
        );
        encode(&Header::new(Algorithm::ES256), &claims, &jwt_encoding_key).unwrap()
    };

    // Static ACL isolation fixtures: role identity only (no token grants/denies).
    let jwt_static_admin = {
        let claims = make_claims(
            "client_1",
            LONG_EXP,
            None,
            Some(vec!["admin".to_string()]),
            None,
            None,
        );
        encode(&Header::new(Algorithm::ES256), &claims, &jwt_encoding_key).unwrap()
    };

    let jwt_static_writer = {
        let claims = make_claims(
            "client_1",
            LONG_EXP,
            None,
            Some(vec!["writer".to_string()]),
            None,
            None,
        );
        encode(&Header::new(Algorithm::ES256), &claims, &jwt_encoding_key).unwrap()
    };

    let jwt_static_reader = {
        let claims = make_claims(
            "client_1",
            LONG_EXP,
            None,
            Some(vec!["reader".to_string()]),
            None,
            None,
        );
        encode(&Header::new(Algorithm::ES256), &claims, &jwt_encoding_key).unwrap()
    };

    let jwt_strict_sub = {
        let claims = make_claims(
            "client_1",
            LONG_EXP,
            None,
            Some(vec!["reader".to_string()]),
            None,
            None,
        );
        encode(&Header::new(Algorithm::ES256), &claims, &jwt_encoding_key).unwrap()
    };

    let jwt_strict_sub_client_id = {
        let claims = make_claims(
            "client_1",
            LONG_EXP,
            Some("client_1"),
            Some(vec!["reader".to_string()]),
            None,
            None,
        );
        encode(&Header::new(Algorithm::ES256), &claims, &jwt_encoding_key).unwrap()
    };

    // Biscuit
    let root_bytes = TEST_BISCUIT_ROOT_BYTES;
    let root_keypair = KeyPair::from(
        &PrivateKey::from_bytes(&root_bytes, biscuit_auth::Algorithm::Ed25519).unwrap(),
    );

    let biscuit_base = build_biscuit_with_identity(
        &root_keypair,
        &[
            r#"right("publish", "sensors/client_1/temp")"#,
            r#"right("subscribe", "sensors/client_1/temp")"#,
            "expires_at(2000000000)",
        ],
        None,
    );

    let biscuit_short = {
        let exp = now + SHORT_TTL_SECS;
        let check_src = format!("check if time($t), $t < {exp}");
        let b = BlockBuilder::new()
            .check(check_src.as_str())
            .unwrap()
            .fact(format!("expires_at({exp})").as_str())
            .unwrap();
        biscuit_base.append(b).unwrap()
    };

    let biscuit_1_block = biscuit_base.clone();

    let biscuit_medium_blocks = {
        let mut t = biscuit_base.clone();
        for _ in 0..(BISCUIT_BLOCKS_MEDIUM - 1) {
            let b = BlockBuilder::new();
            t = t.append(b).unwrap();
        }
        t
    };

    let biscuit_large_blocks = {
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

    let biscuit_fanout_allow = Biscuit::builder()
        .fact("right(\"publish\", \"fanout/broadcast\")")
        .unwrap()
        .fact("right(\"subscribe\", \"fanout/broadcast\")")
        .unwrap()
        .fact("expires_at(2000000000)")
        .unwrap()
        .build(&root_keypair)
        .unwrap();

    let biscuit_fanout_read_deny = {
        let deny_block = BlockBuilder::new()
            .fact("deny(\"read\", \"fanout/broadcast\")")
            .unwrap();
        biscuit_fanout_allow.append(deny_block).unwrap()
    };

    // Static ACL isolation fixtures: role identity only (no right/deny facts).
    let biscuit_static_admin = build_biscuit_with_identity(
        &root_keypair,
        &[r#"role("admin")"#, "expires_at(2000000000)"],
        None,
    );

    let biscuit_static_writer = build_biscuit_with_identity(
        &root_keypair,
        &[r#"role("writer")"#, "expires_at(2000000000)"],
        None,
    );

    let biscuit_static_reader = build_biscuit_with_identity(
        &root_keypair,
        &[r#"role("reader")"#, "expires_at(2000000000)"],
        None,
    );

    let biscuit_strict_client_id = build_biscuit_with_identity(
        &root_keypair,
        &[r#"role("reader")"#, "expires_at(2000000000)"],
        Some(("client_id", "client_1")),
    );

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
        .rule(r"right($op, $res) <- allow_op($op), allow_res($res), operation($op), resource($res)")
        .unwrap()
        .build(&root_keypair)
        .unwrap();

    let biscuit_complex_low = biscuit_complex_base.clone();

    let biscuit_complex_med = {
        let block_scope = BlockBuilder::new()
            .fact(r#"scope("client_1")"#)
            .unwrap()
            .fact(r#"owner("sensors/client_1/temp", "client_1")"#)
            .unwrap()
            .fact(r#"allow_scope("client_1")"#)
            .unwrap()
            .rule(r"scoped_res($res) <- owner($res, $c), allow_scope($c)")
            .unwrap()
            .rule(r#"allow_res($res) <- scoped_res($res), resource_group($res, "telemetry")"#)
            .unwrap();
        let t = biscuit_complex_base.append(block_scope).unwrap();

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
        let block_region = BlockBuilder::new()
            .fact(r#"region("client_1", "lab")"#)
            .unwrap()
            .fact(r#"region_allow("lab")"#)
            .unwrap()
            .fact(r#"topic_region("sensors/client_1/temp", "lab")"#)
            .unwrap()
            .rule(r"regional_res($res) <- topic_region($res, $r), region_allow($r)")
            .unwrap()
            .rule(r"allow_res($res) <- scoped_res($res), regional_res($res)")
            .unwrap();
        let t = biscuit_complex_med.append(block_region).unwrap();

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
                r"device_op($op) <- device($c, $class), device_class($class, $group), class_op($group, $op)",
            )
            .unwrap()
            .rule(r#"allow_op($op) <- device_op($op), role("sensor")"#)
            .unwrap()
            .check("check if time($t), $t < 2000000000")
            .unwrap();
        t.append(block_device).unwrap()
    };

    // Shared fixture for authorizer-template complexity scenarios.
    // This keeps token bytes constant while plugin-side authorizer profiles change.
    let biscuit_authorizer_template = Biscuit::builder()
        .fact(r#"right("publish", "sensors/client_1/#")"#)
        .unwrap()
        .fact(r#"right("subscribe", "sensors/client_1/#")"#)
        .unwrap()
        .fact(r#"role("writer")"#)
        .unwrap()
        .fact(r#"role_right("writer", "publish", "sensors/client_1/#")"#)
        .unwrap()
        .fact(r#"role_right("writer", "subscribe", "sensors/client_1/#")"#)
        .unwrap()
        .fact(r#"role_active_from("writer", 0)"#)
        .unwrap()
        .fact(r#"role_active_until("writer", 4102444800)"#)
        .unwrap()
        .fact("expires_at(2000000000)")
        .unwrap()
        .build(&root_keypair)
        .unwrap();

    let biscuit_handoff = Biscuit::builder()
        .fact("right(\"publish\", \"delegation/handoff\")")
        .unwrap()
        .fact("right(\"subscribe\", \"delegation/handoff\")")
        .unwrap()
        .fact("expires_at(2000000000)")
        .unwrap()
        .build(&root_keypair)
        .unwrap();

    // Store Biscuit fixtures as Base64URL text for JSON/file transport.
    // MQTT clients decode these fixtures back to raw serialized bytes.
    let biscuit_bytes = biscuit_1_block.to_vec().unwrap();
    let biscuit_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&biscuit_bytes);

    let biscuit_medium_b64 =
        general_purpose::URL_SAFE_NO_PAD.encode(biscuit_medium_blocks.to_vec().unwrap());
    let biscuit_large_b64 =
        general_purpose::URL_SAFE_NO_PAD.encode(biscuit_large_blocks.to_vec().unwrap());
    let biscuit_delegated_b64 =
        general_purpose::URL_SAFE_NO_PAD.encode(biscuit_delegated.to_vec().unwrap());
    let biscuit_deny_b64 = general_purpose::URL_SAFE_NO_PAD.encode(biscuit_deny.to_vec().unwrap());
    let biscuit_short_b64 =
        general_purpose::URL_SAFE_NO_PAD.encode(biscuit_short.to_vec().unwrap());
    let biscuit_fanout_allow_b64 =
        general_purpose::URL_SAFE_NO_PAD.encode(biscuit_fanout_allow.to_vec().unwrap());
    let biscuit_fanout_read_deny_b64 =
        general_purpose::URL_SAFE_NO_PAD.encode(biscuit_fanout_read_deny.to_vec().unwrap());
    let biscuit_static_admin_b64 =
        general_purpose::URL_SAFE_NO_PAD.encode(biscuit_static_admin.to_vec().unwrap());
    let biscuit_static_writer_b64 =
        general_purpose::URL_SAFE_NO_PAD.encode(biscuit_static_writer.to_vec().unwrap());
    let biscuit_static_reader_b64 =
        general_purpose::URL_SAFE_NO_PAD.encode(biscuit_static_reader.to_vec().unwrap());
    let biscuit_strict_client_id_b64 =
        general_purpose::URL_SAFE_NO_PAD.encode(biscuit_strict_client_id.to_vec().unwrap());
    let biscuit_handoff_b64 =
        general_purpose::URL_SAFE_NO_PAD.encode(biscuit_handoff.to_vec().unwrap());
    let biscuit_complex_low_b64 =
        general_purpose::URL_SAFE_NO_PAD.encode(biscuit_complex_low.to_vec().unwrap());
    let biscuit_complex_med_b64 =
        general_purpose::URL_SAFE_NO_PAD.encode(biscuit_complex_med.to_vec().unwrap());
    let biscuit_complex_high_b64 =
        general_purpose::URL_SAFE_NO_PAD.encode(biscuit_complex_high.to_vec().unwrap());
    let biscuit_authorizer_template_b64 =
        general_purpose::URL_SAFE_NO_PAD.encode(biscuit_authorizer_template.to_vec().unwrap());

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
        "jwt_fanout_allow": jwt_fanout_allow,
        "jwt_fanout_read_deny": jwt_fanout_read_deny,
        "jwt_static_admin": jwt_static_admin,
        "jwt_static_writer": jwt_static_writer,
        "jwt_static_reader": jwt_static_reader,
        "jwt_strict_sub": jwt_strict_sub,
        "jwt_strict_sub_client_id": jwt_strict_sub_client_id,
        "jwt_alg": "ES256",
        "jwt_grants_schema": jwt_grants_schema,
        "jwt_denies_schema": jwt_denies_schema,
        "biscuit": biscuit_b64,
        "biscuit_5": biscuit_medium_b64,
        "biscuit_25": biscuit_large_b64,
        "biscuit_delegated": biscuit_delegated_b64,
        "biscuit_deny": biscuit_deny_b64,
        "biscuit_fanout_allow": biscuit_fanout_allow_b64,
        "biscuit_fanout_read_deny": biscuit_fanout_read_deny_b64,
        "biscuit_short": biscuit_short_b64,
        "biscuit_static_admin": biscuit_static_admin_b64,
        "biscuit_static_writer": biscuit_static_writer_b64,
        "biscuit_static_reader": biscuit_static_reader_b64,
        "biscuit_strict_client_id": biscuit_strict_client_id_b64,
        "biscuit_delegation_handoff": biscuit_handoff_b64,
        "biscuit_complex_low": biscuit_complex_low_b64,
        "biscuit_complex_med": biscuit_complex_med_b64,
        "biscuit_complex_high": biscuit_complex_high_b64,
        "biscuit_authorizer_template": biscuit_authorizer_template_b64,
        "biscuit_root_key_hex": biscuit_pubkey_hex
    });

    let mut f = File::create("benchmarks/tokens.json").unwrap();
    f.write_all(serde_json::to_string_pretty(&tokens).unwrap().as_bytes())
        .unwrap();
    println!("Wrote benchmarks/tokens.json");

    // Per-client static tokens: one JWT and one Biscuit per client index,
    // each scoped to that client's own topic. Written to password-map.json
    // so the loadgen can distribute them without a runtime token issuer.
    let max_clients: usize = env::var("GEN_TOKENS_MAX_CLIENTS").map_or(10_000, |v| {
        v.parse().expect("GEN_TOKENS_MAX_CLIENTS must be usize")
    });

    let mut jwt_clients = serde_json::Map::new();
    let mut biscuit_clients = serde_json::Map::new();
    for i in 1..=max_clients {
        let client_id = format!("client_{i}");
        let topic = format!("sensors/{client_id}/temp");

        let claims = make_claims(
            &client_id,
            LONG_EXP,
            None,
            Some(vec!["admin".to_string()]),
            Some(vec![
                JwtGrant {
                    op: "publish".to_string(),
                    res: topic.clone(),
                },
                JwtGrant {
                    op: "subscribe".to_string(),
                    res: topic,
                },
            ]),
            None,
        );
        let jwt = encode(&Header::new(Algorithm::ES256), &claims, &jwt_encoding_key).unwrap();
        jwt_clients.insert(client_id.clone(), serde_json::Value::String(jwt));

        let biscuit = build_biscuit_with_identity(
            &root_keypair,
            &[
                &format!(r#"right("publish", "sensors/{client_id}/temp")"#),
                &format!(r#"right("subscribe", "sensors/{client_id}/temp")"#),
                "expires_at(2000000000)",
            ],
            None,
        );
        biscuit_clients.insert(
            client_id,
            serde_json::Value::String(format!(
                "b64:{}",
                general_purpose::URL_SAFE_NO_PAD.encode(biscuit.to_vec().unwrap())
            )),
        );
    }

    let password_map = json!({
        "jwt": jwt_clients,
        "biscuit": biscuit_clients,
    });
    let mut f = File::create("benchmarks/password-map.json").unwrap();
    f.write_all(
        serde_json::to_string_pretty(&password_map)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    println!("Wrote benchmarks/password-map.json ({max_clients} clients per kind)");
}

#[cfg(test)]
mod tests {
    use super::*;
    use biscuit_auth::AuthorizerBuilder;

    fn decode_jwt_claims(token: &str) -> Claims {
        let payload = token.split('.').nth(1).expect("JWT payload should exist");
        let bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("JWT payload should decode");
        serde_json::from_slice(&bytes).expect("JWT claims should parse")
    }

    #[test]
    fn strict_jwt_fixture_can_include_matching_client_id() {
        let header = Header::new(Algorithm::ES256);
        let jwt_secret_key = SecretKey::from_slice(&TEST_JWT_SK_BYTES).unwrap();
        let jwt_private_pem = jwt_secret_key.to_pkcs8_pem(LineEnding::LF).unwrap();
        let jwt_encoding_key = EncodingKey::from_ec_pem(jwt_private_pem.as_bytes()).unwrap();
        let token = encode(
            &header,
            &make_claims(
                "client_1",
                LONG_EXP,
                Some("client_1"),
                Some(vec!["reader".to_string()]),
                None,
                None,
            ),
            &jwt_encoding_key,
        )
        .unwrap();

        let claims = decode_jwt_claims(&token);
        assert_eq!(claims.sub, "client_1");
        assert_eq!(claims.client_id.as_deref(), Some("client_1"));
    }

    #[test]
    fn strict_biscuit_fixture_can_include_identity_fact() {
        let root_keypair = KeyPair::from(
            &PrivateKey::from_bytes(&TEST_BISCUIT_ROOT_BYTES, biscuit_auth::Algorithm::Ed25519)
                .unwrap(),
        );
        let biscuit = build_biscuit_with_identity(
            &root_keypair,
            &[r#"role("reader")"#, "expires_at(2000000000)"],
            Some(("client_id", "client_1")),
        );
        let bytes = biscuit.to_vec().unwrap();
        let public_key = biscuit_auth::PublicKey::from_bytes(
            &root_keypair.public().to_bytes(),
            biscuit_auth::Algorithm::Ed25519,
        )
        .unwrap();
        let biscuit = Biscuit::from(&bytes, public_key).unwrap();
        let mut authorizer = AuthorizerBuilder::new().build(&biscuit).unwrap();
        let identities: Vec<(String,)> = authorizer
            .query_all(r"data($id) <- client_id($id)")
            .unwrap();

        assert_eq!(identities, vec![("client_1".to_string(),)]);
    }
}
