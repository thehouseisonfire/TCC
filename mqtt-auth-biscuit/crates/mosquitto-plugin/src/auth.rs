use crate::config::BiscuitTransportMode;
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

    /// Authenticate a token from MQTT v5 AUTH packet (binary data).
    ///
    /// For Biscuit tokens, this accepts the raw Protobuf binary format
    /// when `transport_mode` is `Mqtt5AuthData`, avoiding `Base64URL` overhead.
    /// For JWT tokens, the data is converted to a string (UTF-8) as they
    /// are inherently text-based.
    #[cfg(not(kani))]
    pub fn authenticate_binary(
        &self,
        data: &[u8],
        transport_mode: BiscuitTransportMode,
    ) -> Result<TokenType, AuthError> {
        // Try JWT first: JWT is text-based, convert to string
        if let Ok(token_str) = std::str::from_utf8(data) {
            let token_str = token_str.trim_matches('\0').trim();
            if token_str.starts_with("eyJ") {
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

        // Biscuit: handle based on transport mode
        match transport_mode {
            BiscuitTransportMode::Base64Url => {
                // Decode from Base64URL (string-encoded)
                use base64::{Engine as _, engine::general_purpose};
                let token_str = String::from_utf8_lossy(data);
                let token_str = token_str.trim_matches('\0').trim();
                let bytes = general_purpose::URL_SAFE_NO_PAD
                    .decode(token_str)
                    .map_err(|e| {
                        AuthError::Invalid(format!("Invalid token format (base64url error: {e})"))
                    })?;
                Ok(TokenType::Biscuit {
                    bytes,
                    expires_at: None,
                    roles: None,
                    biscuit: None,
                })
            }
            BiscuitTransportMode::Mqtt5AuthData => {
                // Use raw binary data directly (native Protobuf)
                Ok(TokenType::Biscuit {
                    bytes: data.to_vec(),
                    expires_at: None,
                    roles: None,
                    biscuit: None,
                })
            }
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
            // Try Biscuit (Base64URL-encoded for transport)
            use base64::{Engine as _, engine::general_purpose};
            let bytes = general_purpose::URL_SAFE_NO_PAD
                .decode(token)
                .map_err(|e| {
                    AuthError::Invalid(format!("Invalid token format (base64url error: {e})"))
                })?;

            // We just return the bytes for now, authorization will happen per topic
            Ok(TokenType::Biscuit {
                bytes,
                expires_at: None,
                roles: None,
                biscuit: None,
            })
        }
    }
}
