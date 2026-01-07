use biscuit_auth::{Biscuit, KeyPair, PrivateKey};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
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
    let jwt = encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(b"secret")).unwrap();
    let mut f_jwt = File::create("jwt_token.txt").unwrap();
    f_jwt.write_all(jwt.as_bytes()).unwrap();
    println!("Generated JWT: {}", jwt);

    // Biscuit
    let root_bytes = [0u8; 32];
    let root_keypair = KeyPair::from(&PrivateKey::from_bytes(&root_bytes, biscuit_auth::Algorithm::Ed25519).unwrap());
    
    let biscuit = Biscuit::builder()
        .build(&root_keypair).unwrap();
    
    // We want the token as base64 for the MQTT password field
    let biscuit_bytes = biscuit.to_vec().unwrap();
    use base64::{Engine as _, engine::general_purpose};
    let biscuit_b64 = general_purpose::STANDARD.encode(&biscuit_bytes);
    
    let mut f_biscuit = File::create("biscuit_token.txt").unwrap();
    f_biscuit.write_all(biscuit_b64.as_bytes()).unwrap();
    println!("Generated Biscuit (Base64): {}", biscuit_b64);
    println!("Public Key Bytes: {:?}", root_keypair.public().to_bytes());
}
