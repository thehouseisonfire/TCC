use crate::jwt_handler::{verify_jwt_token, Claims};
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Validation;

#[derive(Clone)]
pub enum TokenType {
    Jwt { claims: Claims, raw: String },
    Biscuit(Vec<u8>),
}

pub struct AuthEngine {
    jwt_key: DecodingKey,
    jwt_validation: Validation,
}

impl AuthEngine {
    pub fn new(jwt_key: DecodingKey, jwt_validation: Validation) -> Self {
        Self {
            jwt_key,
            jwt_validation,
        }
    }

    pub fn authenticate(&self, token: &str) -> Result<TokenType, String> {
        let token = token.trim_matches('\0').trim();
        if token.starts_with("eyJ") {
            // Likely JWT (Heuristic to avoid JWT parsing if the token is a Biscuit)
            verify_jwt_token(token, &self.jwt_key, &self.jwt_validation)
                .map(|claims| TokenType::Jwt {
                    claims,
                    raw: token.to_string(),
                })
                .map_err(|e| format!("JWT verification failed: {}", e))
        } else {
            // Try Biscuit (assuming it's base64 encoded if string)
            use base64::{engine::general_purpose, Engine as _};
            let bytes = general_purpose::STANDARD
                .decode(token)
                .map_err(|e| format!("Invalid token format (base64 error: {})", e))?;

            // We just return the bytes for now, authorization will happen per topic
            Ok(TokenType::Biscuit(bytes))
        }
    }
}
