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
    
    use biscuit_auth::macros::authorizer;
    let mut authorizer = authorizer!(
        r#"
        resource({topic});
        operation({operation});
        time({time});
        allow if right($op, $res), operation($op), resource($res);
        "#,
        topic = topic,
        operation = operation,
        time = Utc::now().timestamp()
    ).build(&biscuit).map_err(|_| biscuit_auth::error::Token::InternalError)?;
    
    // Authorize
    authorizer.authorize().map(|_| true).map_err(|e| e)
}
