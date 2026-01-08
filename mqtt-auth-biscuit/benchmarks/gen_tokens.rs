use biscuit_auth::{Biscuit, KeyPair, PrivateKey};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs::File;
use std::io::Write;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    roles: Option<Vec<String>>,
}

fn main() {
    // JWT
    let claims = Claims {
        sub: "client_1".to_string(),
        exp: 2000000000, // Year 2033
        roles: Some(vec!["admin".to_string()]),
    };
    let jwt_secret = "secret";
    let jwt = encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(jwt_secret.as_bytes())).unwrap();

    // Biscuit
    let root_bytes = [0u8; 32];
    let root_keypair = KeyPair::from(&PrivateKey::from_bytes(&root_bytes, biscuit_auth::Algorithm::Ed25519).unwrap());
    
    let biscuit = Biscuit::builder()
        .fact("right(\"publish\", \"sensors/client_1/temp\")")
        .unwrap()
        .fact("right(\"subscribe\", \"sensors/client_1/temp\")")
        .unwrap()
        .build(&root_keypair)
        .unwrap();
    
    // We want the token as base64 for the MQTT password field
    let biscuit_bytes = biscuit.to_vec().unwrap();
    use base64::{Engine as _, engine::general_purpose};
    let biscuit_b64 = general_purpose::STANDARD.encode(&biscuit_bytes);
    
    let biscuit_pubkey_hex = hex::encode(root_keypair.public().to_bytes());

    let tokens = json!({
        "jwt": jwt,
        "jwt_alg": "HS256",
        "jwt_hmac_secret": jwt_secret,
        "biscuit": biscuit_b64,
        "biscuit_root_key_hex": biscuit_pubkey_hex
    });

    let mut f = File::create("benchmarks/tokens.json").unwrap();
    f.write_all(serde_json::to_string_pretty(&tokens).unwrap().as_bytes()).unwrap();
    println!("Wrote benchmarks/tokens.json");
}
