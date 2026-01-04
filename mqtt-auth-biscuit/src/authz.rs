use crate::auth::TokenType;
use crate::biscuit_handler::verify_biscuit_token;
use biscuit_auth::PublicKey as BiscuitPublicKey;

pub fn check_authorization(
    token_type: &TokenType,
    topic: &str,
    access: i32, // MOSQ_ACL_READ, MOSQ_ACL_WRITE
    biscuit_root_key: &BiscuitPublicKey,
) -> bool {
    match token_type {
        TokenType::JWT(claims) => {
            // For JWT, check roles or subject
            // Simplistic check: allow if role contains "admin" or if topic matches client_id
            if let Some(roles) = &claims.roles {
                if roles.contains(&"admin".to_string()) {
                    return true;
                }
            }
            
            // Check if topic matches sub (client_id)
            // e.g. "sensors/{client_id}/#"
            let client_id = &claims.sub;
            let prefix = format!("sensors/{}/", client_id);
            if topic.starts_with(&prefix) || topic == client_id {
                return true;
            }
            
            false
        }
        TokenType::Biscuit(token_bytes) => {
            let operation = if (access & 0x02) != 0 {
                "publish"
            } else if (access & 0x04) != 0 || (access & 0x01) != 0 {
                "subscribe"
            } else {
                "read"
            };

            verify_biscuit_token(token_bytes, biscuit_root_key, topic, operation).unwrap_or(false)
        }
    }
}
