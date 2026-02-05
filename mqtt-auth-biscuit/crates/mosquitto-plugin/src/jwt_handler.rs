use jsonwebtoken::{DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JwtGrant {
    pub op: String,
    pub res: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,         // Subject (client ID)
    pub exp: i64,            // Expiration timestamp
    pub iss: Option<String>, // Issuer
    pub aud: Option<String>, // Audience
    pub client_id: Option<String>,
    pub roles: Option<Vec<String>>,
    pub grants: Option<Vec<JwtGrant>>,
    pub denies: Option<Vec<JwtGrant>>,
}

#[allow(dead_code)]
pub fn verify_jwt_token(
    token: &str,
    public_key: &DecodingKey,
    validation: &Validation,
) -> Result<Claims, jsonwebtoken::errors::Error> {
    let token_data = decode::<Claims>(token, public_key, validation)?;
    Ok(token_data.claims)
}
