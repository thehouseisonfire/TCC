use base64::{Engine as _, engine::general_purpose};
use gen_tokens::biscuit_attenuation::{
    BiscuitAttenuationOptions, attenuate_biscuit_token, load_public_key_hex,
};
use std::env;
use std::fs;
use std::io::{self, Read};

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

fn load_public_key(args: &Args) -> Result<biscuit_auth::PublicKey, String> {
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

    load_public_key_hex(&hex_value)
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
    let bytes = attenuate_biscuit_token(
        &token_bytes,
        public_key,
        &BiscuitAttenuationOptions {
            denies: args.denies,
            checks: args.checks,
            restrict_topic: args.restrict_topic,
            restrict_operation: args.restrict_operation,
            ttl_seconds: args.ttl_seconds,
        },
    )?;
    let token_out = general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    println!("{token_out}");
    Ok(())
}
