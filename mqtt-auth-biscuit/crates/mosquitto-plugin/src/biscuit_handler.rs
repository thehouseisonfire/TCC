use biscuit_auth::{Biscuit, PublicKey};
use chrono::Utc;
use std::sync::OnceLock;

// Pre-compiled authorizer template to avoid recompilation overhead
// This is a small, acceptable use of global state, as the template is immutable
static AUTHORIZER_TEMPLATE: OnceLock<String> = OnceLock::new();

fn get_authorizer_template() -> &'static str {
    AUTHORIZER_TEMPLATE.get_or_init(|| {
        r#"
        resource({topic});
        operation({operation});
        time({time});
        allow if right($op, $res), operation($op), resource($res);
        "#
        .to_string()
    })
}

pub fn verify_biscuit_token(
    token_bytes: &[u8],
    root_public_key: &PublicKey,
    topic: &str,
    operation: &str, // "publish" or "subscribe"
) -> Result<bool, biscuit_auth::error::Token> {
    // Deserialize token
    let biscuit = Biscuit::from(token_bytes, root_public_key)?;

    use biscuit_auth::macros::authorizer;
    // The authorizer! macro requires a string literal at compile time
    // Template caching is preserved for documentation and potential future use
    let _template = get_authorizer_template(); // Keep the template cache for consistency
    
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
    )
    .build(&biscuit)
    .map_err(|_| biscuit_auth::error::Token::InternalError)?;

    // Authorize
    authorizer.authorize().map(|_| true)
}
