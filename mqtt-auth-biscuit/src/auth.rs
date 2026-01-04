use crate::jwt_handler::{verify_jwt_token, Claims};
use biscuit_auth::PublicKey as BiscuitPublicKey;
use jsonwebtoken::DecodingKey;

#[derive(Clone)]
pub enum TokenType {
    JWT(Claims),
    Biscuit(Vec<u8>),
}

pub struct AuthEngine {
    jwt_key: DecodingKey,
}

impl AuthEngine {
    pub fn new(jwt_key: DecodingKey, _biscuit_root_key: BiscuitPublicKey) -> Self {
        Self {
            jwt_key,
        }
    }

    pub fn authenticate(&self, token: &str) -> Result<TokenType, String> {
        if token.starts_with("eyJ") {
            // Likely JWT
            verify_jwt_token(token, &self.jwt_key)
                .map(TokenType::JWT)
                .map_err(|e| format!("JWT verification failed: {}", e))
        } else {
            // Try Biscuit (assuming it's base64 encoded if string)
            use base64::{Engine as _, engine::general_purpose};
            let bytes = general_purpose::STANDARD.decode(token)
                .map_err(|_| "Invalid token format".to_string())?;
            
            // We just return the bytes for now, authorization will happen per topic
            Ok(TokenType::Biscuit(bytes))
        }
    }
}
