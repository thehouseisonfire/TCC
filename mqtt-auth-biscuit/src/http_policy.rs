use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn split_host_port(host_port: &str) -> Result<(&str, u16), String> {
    let mut parts = host_port.split(':');
    let host = parts.next().ok_or_else(|| "invalid host".to_string())?;
    let port = parts
        .next()
        .ok_or_else(|| "invalid port".to_string())?
        .parse::<u16>()
        .map_err(|e| format!("invalid port: {e}"))?;
    Ok((host, port))
}

pub fn check_http(
    http_url: &str,
    client_id: &str,
    topic: &str,
    access: i32,
    token: Option<&str>,
) -> Result<bool, String> {
    // Supported format: http://host:port/path
    let url = http_url
        .strip_prefix("http://")
        .ok_or_else(|| "Only http:// URLs are supported".to_string())?;

    let (host_port, path) = match url.split_once('/') {
        Some((hp, p)) => (hp, format!("/{}", p)),
        None => (url, "/".to_string()),
    };

    let (host, port) = split_host_port(host_port)?;

    let body = match token {
        Some(t) => format!(
            "{{\"client_id\":\"{}\",\"topic\":\"{}\",\"access\":{},\"token\":\"{}\"}}",
            client_id, topic, access, t
        ),
        None => format!(
            "{{\"client_id\":\"{}\",\"topic\":\"{}\",\"access\":{}}}",
            client_id, topic, access
        ),
    };

    let mut stream = TcpStream::connect((host, port)).map_err(|e| format!("http connect failed: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| format!("http set timeout failed: {e}"))?;

    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path,
        host_port,
        body.len(),
        body
    );

    stream.write_all(req.as_bytes()).map_err(|e| format!("http write failed: {e}"))?;

    let mut resp = String::new();
    stream.read_to_string(&mut resp).map_err(|e| format!("http read failed: {e}"))?;

    // Very small parser: allow if HTTP 200 and body contains "allow":true or "ALLOW".
    let status_ok = resp.lines().next().map(|l| l.contains(" 200 ")).unwrap_or(false);
    if !status_ok {
        return Err("http non-200 response".to_string());
    }

    Ok(resp.contains("\"allow\":true") || resp.to_lowercase().contains("allow"))
}
