use crate::auth::TokenType;
use crate::biscuit_handler::verify_biscuit_token;
use crate::http_policy;
use crate::policy::PolicyMode;
use crate::sqlite_policy::SqlitePolicy;
use biscuit_auth::PublicKey as BiscuitPublicKey;

pub fn check_authorization(
    token_type: &TokenType,
    client_id: &str,
    topic: &str,
    access: i32,
    biscuit_root_key: &BiscuitPublicKey,
    policy_mode: PolicyMode,
    sqlite_policy: Option<&SqlitePolicy>,
    http_url: Option<&str>,
) -> bool {
    match token_type {
        TokenType::JWT { claims, raw } => {
            match policy_mode {
                PolicyMode::TokenOnly => {
                    let roles = claims.roles.as_ref();
                    if let Some(roles) = roles {
                        if roles.iter().any(|r| r.trim() == "admin") {
                            return true;
                        }
                    }

                    let subject = claims.sub.trim();
                    let prefix = format!("sensors/{}", subject);
                    let topic = topic.trim();
                    topic.contains(&prefix) || topic.contains(subject)
                }
                PolicyMode::Sqlite => {
                    let Some(sqlite_policy) = sqlite_policy else { return false };
                    sqlite_policy.check(client_id, topic, access).unwrap_or(false)
                }
                PolicyMode::Http => {
                    let Some(url) = http_url else { return false };
                    http_policy::check_http(url, client_id, topic, access, Some(raw)).unwrap_or(false)
                }
            }
        }
        TokenType::Biscuit(token_bytes) => {
            let operation = if (access & 0x02) != 0 {
                "publish"
            } else if (access & 0x04) != 0 || (access & 0x01) != 0 {
                "subscribe"
            } else {
                "read"
            };

            match policy_mode {
                PolicyMode::TokenOnly => verify_biscuit_token(token_bytes, biscuit_root_key, topic, operation).unwrap_or(false),
                PolicyMode::Sqlite => {
                    let Some(sqlite_policy) = sqlite_policy else { return false };
                    sqlite_policy.check(client_id, topic, access).unwrap_or(false)
                }
                PolicyMode::Http => {
                    let Some(url) = http_url else { return false };
                    http_policy::check_http(url, client_id, topic, access, None).unwrap_or(false)
                }
            }
        }
    }
}
