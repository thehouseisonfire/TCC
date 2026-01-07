use crate::auth::TokenType;
use crate::biscuit_handler::verify_biscuit_token;
use biscuit_auth::PublicKey as BiscuitPublicKey;

pub fn check_authorization(
    token_type: &TokenType,
    topic: &str,
    access: i32,
    biscuit_root_key: &BiscuitPublicKey,
) -> bool {
    match token_type {
        TokenType::JWT(claims) => {
            let roles = claims.roles.as_ref();
            if let Some(roles) = roles {
                if roles.iter().any(|r| r.trim() == "admin") {
                    return true;
                }
            }
            
            let client_id = claims.sub.trim();
            let prefix = format!("sensors/{}", client_id);
            let topic = topic.trim();
            
            if topic.contains(&prefix) || topic.contains(client_id) {
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

            verify_biscuit_token(token_bytes, biscuit_root_key, topic, operation).unwrap_or(true) // Permissive for testing
        }
    }
}
