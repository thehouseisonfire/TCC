use biscuit_auth::{Biscuit, PublicKey};
use chrono::Utc;
use std::sync::OnceLock;

// Pre-compiled authorizer template to avoid recompilation overhead
static AUTHORIZER_TEMPLATE: OnceLock<String> = OnceLock::new();

fn get_authorizer_template() -> &'static String {
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
    let template = get_authorizer_template();
    let mut authorizer = authorizer!(
        template,
        topic = topic,
        operation = operation,
        time = Utc::now().timestamp()
    )
    .build(&biscuit)
    .map_err(|_| biscuit_auth::error::Token::InternalError)?;

    // Authorize
    authorizer.authorize().map(|_| true)
}
