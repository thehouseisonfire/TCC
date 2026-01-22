#[cfg(kani)]
use crate::jwt_handler::Claims;
#[cfg(not(kani))]
use crate::jwt_handler::{verify_jwt_token, Claims};
#[cfg(not(kani))]
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Validation;

#[derive(Clone)]
pub enum TokenType {
    Jwt {
        claims: Claims,
        raw: String,
    },
    Biscuit {
        bytes: Vec<u8>,
        expires_at: Option<i64>,
    },
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum AuthError {
    Expired,
    Invalid(String),
}

#[allow(dead_code)]
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

    #[cfg(kani)]
    pub fn authenticate(&self, _token: &str) -> Result<TokenType, AuthError> {
        if kani::any() {
            if kani::any() {
                Ok(TokenType::Jwt {
                    claims: Claims {
                        sub: "client".to_string(),
                        exp: 0,
                        iss: None,
                        aud: None,
                        client_id: None,
                        roles: None,
                    },
                    raw: "token".to_string(),
                })
            } else {
                Ok(TokenType::Biscuit {
                    bytes: vec![0u8; 1],
                    expires_at: Some(0),
                })
            }
        } else {
            Err(AuthError::Invalid("Kani mock failure".to_string()))
        }
    }

    #[cfg(not(kani))]
    pub fn authenticate(&self, token: &str) -> Result<TokenType, AuthError> {
        let token = token.trim_matches('\0').trim();
        if token.starts_with("eyJ") {
            // Likely JWT (Heuristic to avoid JWT parsing if the token is a Biscuit)
            verify_jwt_token(token, &self.jwt_key, &self.jwt_validation)
                .map(|claims| TokenType::Jwt {
                    claims,
                    raw: token.to_string(),
                })
                .map_err(|e| match e.kind() {
                    ErrorKind::ExpiredSignature => AuthError::Expired,
                    _ => AuthError::Invalid(format!("JWT verification failed: {e}")),
                })
        } else {
            // Try Biscuit (assuming it's base64 encoded if string)
            use base64::{engine::general_purpose, Engine as _};
            let bytes = general_purpose::STANDARD.decode(token).map_err(|e| {
                AuthError::Invalid(format!("Invalid token format (base64 error: {e})"))
            })?;

            // We just return the bytes for now, authorization will happen per topic
            Ok(TokenType::Biscuit {
                bytes,
                expires_at: None,
            })
        }
    }
}
