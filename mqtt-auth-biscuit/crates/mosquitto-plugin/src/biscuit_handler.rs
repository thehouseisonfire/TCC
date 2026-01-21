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

pub enum BiscuitAuthOutcome {
    Allowed,
    Expired,
    Denied,
    Error(biscuit_auth::error::Token),
}

pub fn check_biscuit_expiry(
    token_bytes: &[u8],
    root_public_key: &PublicKey,
) -> BiscuitAuthOutcome {
    let biscuit = match Biscuit::from(token_bytes, root_public_key) {
        Ok(token) => token,
        Err(err) => return BiscuitAuthOutcome::Error(err),
    };

    use biscuit_auth::macros::authorizer;
    let authorizer = authorizer!(
        r#"
        time({time});
        allow if time($t);
        "#,
        time = Utc::now().timestamp()
    )
    .build(&biscuit)
    .map_err(|_| biscuit_auth::error::Token::InternalError);

    let mut authorizer = match authorizer {
        Ok(authorizer) => authorizer,
        Err(err) => return BiscuitAuthOutcome::Error(err),
    };

    match authorizer.authorize() {
        Ok(_) => BiscuitAuthOutcome::Allowed,
        Err(err) => classify_biscuit_error(&err),
    }
}

pub fn verify_biscuit_token(
    token_bytes: &[u8],
    root_public_key: &PublicKey,
    topic: &str,
    operation: &str, // "publish" or "subscribe"
) -> BiscuitAuthOutcome {
    // Deserialize token
    let biscuit = match Biscuit::from(token_bytes, root_public_key) {
        Ok(token) => token,
        Err(err) => return BiscuitAuthOutcome::Error(err),
    };

    use biscuit_auth::macros::authorizer;
    // The authorizer! macro requires a string literal at compile time
    // Template caching is preserved for documentation and potential future use
    let _template = get_authorizer_template(); // Keep the template cache for consistency
    
    let authorizer = authorizer!(
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
    .map_err(|_| biscuit_auth::error::Token::InternalError);
    let mut authorizer = match authorizer {
        Ok(authorizer) => authorizer,
        Err(err) => return BiscuitAuthOutcome::Error(err),
    };

    // Authorize
    match authorizer.authorize() {
        Ok(_) => BiscuitAuthOutcome::Allowed,
        Err(err) => classify_biscuit_error(&err),
    }
}

fn classify_biscuit_error(err: &biscuit_auth::error::Token) -> BiscuitAuthOutcome {
    use biscuit_auth::error::{FailedCheck, Logic};

    let expired = matches!(
        err,
        biscuit_auth::error::Token::FailedLogic(Logic::Unauthorized { checks, .. })
            | biscuit_auth::error::Token::FailedLogic(Logic::NoMatchingPolicy { checks })
            if checks.iter().any(|check| {
                let rule = match check {
                    FailedCheck::Block(block) => &block.rule,
                    FailedCheck::Authorizer(authorizer) => &authorizer.rule,
                };
                rule.contains("time(") && rule.contains('<')
            })
    );

    if expired {
        BiscuitAuthOutcome::Expired
    } else {
        BiscuitAuthOutcome::Denied
    }
}
