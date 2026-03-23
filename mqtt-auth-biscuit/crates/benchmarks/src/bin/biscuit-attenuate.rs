use base64::{Engine as _, engine::general_purpose};
use biscuit_auth::{Biscuit, BlockBuilder, PublicKey};
use std::env;
use std::fs;
use std::io::{self, Read};
use std::time::{SystemTime, UNIX_EPOCH};

struct Args {
    token: Option<String>,
    denies: Vec<String>,
    checks: Vec<String>,
    restrict_topic: Option<String>,
    restrict_operation: Option<String>,
    ttl_seconds: Option<i64>,
    public_key_hex: Option<String>,
    public_key_file: Option<String>,
}

fn usage() -> ! {
    eprintln!(
        "Usage: biscuit-attenuate --token <b64> --public-key-hex <hex> [options]\n\
Options:\n\
  --token <b64>                 Base64URL-encoded Biscuit token (or read from stdin)\n\
  --public-key-hex <hex>        Biscuit root public key (hex)\n\
  --public-key-file <path>      File containing hex-encoded public key\n\
  --deny <op:res>               Append deny fact (repeatable)\n\
  --check <expr>                Append check (repeatable). Accepts 'check if ...' or a raw condition.\n\
  --restrict-topic <topic>      Add check restricting resource to topic\n\
  --restrict-op <op>            Add check restricting operation to op\n\
  --ttl-seconds <seconds>       Add expiry check (time-based attenuation)\n"
    );
    std::process::exit(2);
}

fn escape_datalog_str(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn parse_denied_spec(spec: &str) -> Result<(String, String), String> {
    let separators = [':', ',', '='];
    for sep in separators {
        if let Some((op, res)) = spec.split_once(sep) {
            let op = op.trim();
            let res = res.trim();
            if op.is_empty() || res.is_empty() {
                break;
            }
            return Ok((op.to_string(), res.to_string()));
        }
    }
    Err(format!("invalid deny spec '{spec}', expected op:res"))
}

fn normalize_check(check: &str) -> String {
    let trimmed = check.trim();
    if trimmed.starts_with("check ") || trimmed.starts_with("check\t") {
        trimmed.to_string()
    } else {
        format!("check if {trimmed}")
    }
}

fn parse_args() -> Args {
    let mut args = env::args().skip(1);
    let mut out = Args {
        token: None,
        denies: Vec::new(),
        checks: Vec::new(),
        restrict_topic: None,
        restrict_operation: None,
        ttl_seconds: None,
        public_key_hex: None,
        public_key_file: None,
    };

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--token" => out.token = args.next(),
            "--deny" => {
                if let Some(value) = args.next() {
                    out.denies.push(value);
                } else {
                    usage();
                }
            }
            "--check" => {
                if let Some(value) = args.next() {
                    out.checks.push(value);
                } else {
                    usage();
                }
            }
            "--restrict-topic" => out.restrict_topic = args.next(),
            "--restrict-op" => out.restrict_operation = args.next(),
            "--ttl-seconds" => {
                let Some(value) = args.next() else {
                    usage();
                };
                out.ttl_seconds = value.parse::<i64>().ok();
            }
            "--public-key-hex" => out.public_key_hex = args.next(),
            "--public-key-file" => out.public_key_file = args.next(),
            _ => usage(),
        }
    }
    out
}

fn read_token_from_stdin() -> Result<String, String> {
    let mut buffer = String::new();
    io::stdin()
        .read_to_string(&mut buffer)
        .map_err(|e| format!("read stdin failed: {e}"))?;
    let token = buffer.trim().to_string();
    if token.is_empty() {
        return Err("token missing".to_string());
    }
    Ok(token)
}

fn load_public_key(args: &Args) -> Result<PublicKey, String> {
    let hex_value = if let Some(hex) = args.public_key_hex.as_deref() {
        hex.to_string()
    } else if let Some(path) = args.public_key_file.as_deref() {
        fs::read_to_string(path)
            .map_err(|e| format!("failed to read public key file {path}: {e}"))?
            .trim()
            .to_string()
    } else {
        env::var("BISCUIT_PUBLIC_KEY_HEX").map_err(|_| "public key hex required".to_string())?
    };

    let bytes = hex::decode(hex_value.trim()).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32-byte public key, got {}", bytes.len()));
    }
    PublicKey::from_bytes(&bytes, biscuit_auth::Algorithm::Ed25519)
        .map_err(|e| format!("invalid public key: {e}"))
}

fn main() -> Result<(), String> {
    let args = parse_args();
    let token = match args.token.as_deref() {
        Some(token) => token.to_string(),
        None => read_token_from_stdin()?,
    };

    let public_key = load_public_key(&args)?;

    let token_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(token.trim())
        .map_err(|e| format!("token decode failed: {e}"))?;
    let biscuit =
        Biscuit::from(&token_bytes, public_key).map_err(|e| format!("token parse failed: {e}"))?;

    let mut block = BlockBuilder::new();
    let mut added = false;

    if let Some(restrict_topic) = args.restrict_topic.as_deref() {
        let topic = escape_datalog_str(restrict_topic);
        let check = args.restrict_operation.as_deref().map_or_else(
            || format!("check if resource(\"{topic}\")"),
            |op| {
                let op = escape_datalog_str(op);
                format!("check if operation(\"{op}\"), resource(\"{topic}\")")
            },
        );
        block = block
            .check(check.as_str())
            .map_err(|e| format!("restrict check failed: {e}"))?;
        added = true;
    } else if let Some(op) = args.restrict_operation.as_deref() {
        let op = escape_datalog_str(op);
        let check = format!("check if operation(\"{op}\")");
        block = block
            .check(check.as_str())
            .map_err(|e| format!("restrict check failed: {e}"))?;
        added = true;
    }

    for check in &args.checks {
        let check_src = normalize_check(check);
        block = block
            .check(check_src.as_str())
            .map_err(|e| format!("check failed: {e}"))?;
        added = true;
    }

    for deny in &args.denies {
        let (op, res) = parse_denied_spec(deny)?;
        let op = escape_datalog_str(&op);
        let res = escape_datalog_str(&res);
        let fact = format!("deny(\"{op}\", \"{res}\")");
        block = block
            .fact(fact.as_str())
            .map_err(|e| format!("deny fact failed: {e}"))?;
        added = true;
    }

    if let Some(ttl_seconds) = args.ttl_seconds {
        let now = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| format!("time error: {e}"))?
                .as_secs(),
        )
        .map_err(|_| "time error: timestamp exceeds i64 range".to_string())?;
        let exp = now + ttl_seconds.max(1);
        let check_src = format!("check if time($t), $t < {exp}");
        let expires_fact = format!("expires_at({exp})");
        block = block
            .check(check_src.as_str())
            .map_err(|e| format!("ttl check failed: {e}"))?
            .fact(expires_fact.as_str())
            .map_err(|e| format!("ttl fact failed: {e}"))?;
        added = true;
    }

    if !added {
        return Err("no attenuation rules specified".to_string());
    }

    let attenuated = biscuit
        .append(block)
        .map_err(|e| format!("append failed: {e}"))?;
    let bytes = attenuated
        .to_vec()
        .map_err(|e| format!("encode failed: {e}"))?;
    let token_out = general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    println!("{token_out}");
    Ok(())
}
