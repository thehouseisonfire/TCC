use biscuit_auth::{Biscuit, BlockBuilder, KeyPair, PrivateKey};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use p256::SecretKey;
use pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs::File;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

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
    // JWT (ES256)
    // Deterministic private key material for reproducible tokens.
    // This private key is held by the token issuer (this generator) and is
    // never mounted into the Mosquitto container.
    let jwt_sk_bytes = [1u8; 32];
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
        let topic = "sensors/client_1/temp".to_string();
        let claims = Claims {
            sub: "client_1".to_string(),
            exp: 2000000000, // Year 2033
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
        let topic = "sensors/client_1/temp".to_string();
        let claims = Claims {
            sub: "client_1".to_string(),
            exp: 2000000000, // Year 2033
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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let topic = "sensors/client_1/temp".to_string();
        let claims = Claims {
            sub: "client_1".to_string(),
            exp: now + 5,
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
    let root_bytes = [0u8; 32];
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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let exp = now + 5;
        let check_src = format!("check if time($t), $t < {exp}");
        let b = BlockBuilder::new()
            .check(check_src.as_str())
            .unwrap()
            .fact(format!("expires_at({exp})").as_str())
            .unwrap();
        biscuit_base.append(b).unwrap()
    };

    let biscuit_1_block = biscuit_base.clone();

    let biscuit_5_blocks = {
        let mut t = biscuit_base.clone();
        for _ in 0..4 {
            let b = BlockBuilder::new();
            t = t.append(b).unwrap();
        }
        t
    };

    let biscuit_25_blocks = {
        let mut t = biscuit_base.clone();
        for _ in 0..24 {
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

    // We want the token as base64 for the MQTT password field
    let biscuit_bytes = biscuit_1_block.to_vec().unwrap();
    use base64::{engine::general_purpose, Engine as _};
    let biscuit_b64 = general_purpose::STANDARD.encode(&biscuit_bytes);

    let biscuit_5_b64 = general_purpose::STANDARD.encode(biscuit_5_blocks.to_vec().unwrap());
    let biscuit_25_b64 = general_purpose::STANDARD.encode(biscuit_25_blocks.to_vec().unwrap());
    let biscuit_delegated_b64 =
        general_purpose::STANDARD.encode(biscuit_delegated.to_vec().unwrap());
    let biscuit_deny_b64 = general_purpose::STANDARD.encode(biscuit_deny.to_vec().unwrap());
    let biscuit_short_b64 = general_purpose::STANDARD.encode(biscuit_short.to_vec().unwrap());

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
        "biscuit_root_key_hex": biscuit_pubkey_hex
    });

    let mut f = File::create("benchmarks/tokens.json").unwrap();
    f.write_all(serde_json::to_string_pretty(&tokens).unwrap().as_bytes())
        .unwrap();
    println!("Wrote benchmarks/tokens.json");
}
