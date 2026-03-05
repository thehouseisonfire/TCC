#[cfg(kani)]
use crate::jwt_handler::Claims;
#[cfg(not(kani))]
use crate::jwt_handler::{Claims, verify_jwt_token};
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Validation;
#[cfg(not(kani))]
use jsonwebtoken::errors::ErrorKind;
use std::sync::Arc;

#[derive(Clone)]
pub enum TokenType {
    Jwt {
        claims: Claims,
        raw: String,
    },
    Biscuit {
        bytes: Vec<u8>,
        expires_at: Option<i64>,
        roles: Option<Vec<String>>,
        biscuit: Option<Arc<biscuit_auth::Biscuit>>,
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
    pub const fn new(jwt_key: DecodingKey, jwt_validation: Validation) -> Self {
        Self {
            jwt_key,
            jwt_validation,
        }
    }

    #[cfg(not(kani))]
    fn looks_like_compact_jwt(token: &str) -> bool {
        token.starts_with("eyJ") && token.bytes().filter(|&b| b == b'.').count() == 2
    }

    #[cfg(not(kani))]
    fn authenticate_mqtt_token(&self, data: &[u8]) -> Result<TokenType, AuthError> {
        if let Ok(token_str) = std::str::from_utf8(data) {
            let token_str = token_str.trim_matches('\0').trim();
            if Self::looks_like_compact_jwt(token_str) {
                return verify_jwt_token(token_str, &self.jwt_key, &self.jwt_validation)
                    .map(|claims| TokenType::Jwt {
                        claims,
                        raw: token_str.to_string(),
                    })
                    .map_err(|e| match e.kind() {
                        ErrorKind::ExpiredSignature => AuthError::Expired,
                        _ => AuthError::Invalid(format!("JWT verification failed: {e}")),
                    });
            }
        }

        Ok(TokenType::Biscuit {
            bytes: data.to_vec(),
            expires_at: None,
            roles: None,
            biscuit: None,
        })
    }

    /// Authenticate a token from MQTT `CONNECT.password`.
    ///
    /// JWT stays text-based. Biscuit is transported as raw serialized bytes,
    /// including tokens that contain embedded `NUL` bytes.
    #[cfg(not(kani))]
    pub fn authenticate_basic(&self, password: &[u8]) -> Result<TokenType, AuthError> {
        self.authenticate_mqtt_token(password)
    }

    /// Authenticate a token from MQTT v5 Authentication Data.
    ///
    /// JWT stays text-based. Biscuit is transported as raw serialized bytes.
    #[cfg(not(kani))]
    pub fn authenticate_binary(&self, data: &[u8]) -> Result<TokenType, AuthError> {
        self.authenticate_mqtt_token(data)
    }

    #[cfg(kani)]
    pub fn authenticate_basic(&self, _token: &[u8]) -> Result<TokenType, AuthError> {
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
                        grants: None,
                        denies: None,
                    },
                    raw: "token".to_string(),
                })
            } else {
                Ok(TokenType::Biscuit {
                    bytes: vec![0u8; 1],
                    expires_at: Some(0),
                    roles: None,
                    biscuit: None,
                })
            }
        } else {
            Err(AuthError::Invalid("Kani mock failure".to_string()))
        }
    }

    #[cfg(kani)]
    pub fn authenticate_binary(&self, data: &[u8]) -> Result<TokenType, AuthError> {
        self.authenticate_basic(data)
    }
}
