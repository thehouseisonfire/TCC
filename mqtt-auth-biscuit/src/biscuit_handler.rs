use biscuit_auth::{Biscuit, PublicKey};
use chrono::Utc;

pub fn verify_biscuit_token(
    token_bytes: &[u8],
    root_public_key: &PublicKey,
    topic: &str,
    operation: &str, // "publish" or "subscribe"
) -> Result<bool, biscuit_auth::error::Token> {
    // Deserialize token
    let biscuit = Biscuit::from(token_bytes, root_public_key)?;
    
    // Create authorizer with context
    let mut authorizer = biscuit.authorizer()
        .map_err(|_| biscuit_auth::error::Token::InternalError)?;
    
    authorizer.add_code(format!(
        r#"
        resource("{}");
        operation("{}");
        time({});
        allow if true;
        "#,
        topic,
        operation,
        Utc::now().timestamp()
    )).map_err(|_| biscuit_auth::error::Token::InternalError)?;
    
    // Authorize
    authorizer.authorize().map(|_| true).map_err(|e| e)
}
