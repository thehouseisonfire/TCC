use serde::Deserialize;
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_pemfile::certs;
use webpki_roots::TLS_SERVER_ROOTS;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthzResponse {
    allow: bool,
}

fn resolve_socket_addr(host: &str, port: u16) -> Result<SocketAddr, String> {
    let mut addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("http resolve failed: {e}"))?;
    addrs
        .next()
        .ok_or_else(|| "http resolve failed: no addresses".to_string())
}

fn split_host_port(host_port: &str, default_port: u16) -> Result<(String, u16), String> {
    if host_port.starts_with('[') {
        let end = host_port
            .find(']')
            .ok_or_else(|| "invalid host".to_string())?;
        let host = &host_port[1..end];
        let rest = &host_port[end + 1..];
        if rest.is_empty() {
            return Ok((host.to_string(), default_port));
        }
        let port_str = rest
            .strip_prefix(':')
            .ok_or_else(|| "invalid host".to_string())?;
        let port = port_str
            .parse::<u16>()
            .map_err(|_| "invalid port".to_string())?;
        return Ok((host.to_string(), port));
    }

    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| "invalid port".to_string())?;
        return Ok((host.to_string(), port));
    }

    Ok((host_port.to_string(), default_port))
}

fn read_limited_response<R: Read>(reader: &mut R, max_bytes: usize) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut limited = reader.take((max_bytes + 1) as u64);
    limited
        .read_to_end(&mut buf)
        .map_err(|e| format!("http read failed: {e}"))?;
    if buf.len() > max_bytes {
        return Err("http response too large".to_string());
    }
    Ok(buf)
}

fn parse_http_response(resp: &[u8]) -> Result<AuthzResponse, String> {
    let header_end = resp
        .windows(4)
        .position(|win| win == b"\r\n\r\n")
        .ok_or_else(|| "http missing headers".to_string())?;
    let (header_bytes, body_with_sep) = resp.split_at(header_end);
    let body = &body_with_sep[4..];

    let header_str =
        std::str::from_utf8(header_bytes).map_err(|_| "http headers not utf-8".to_string())?;
    let mut lines = header_str.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| "http missing status line".to_string())?;
    let mut status_parts = status_line.split_whitespace();
    let _version = status_parts
        .next()
        .ok_or_else(|| "http invalid status line".to_string())?;
    let status_code = status_parts
        .next()
        .ok_or_else(|| "http invalid status line".to_string())?
        .parse::<u16>()
        .map_err(|_| "http invalid status code".to_string())?;
    if status_code != 200 {
        return Err("http non-200 response".to_string());
    }

    let mut content_type = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-type") {
                content_type = Some(value.trim().to_string());
            }
        }
    }

    let content_type = content_type.ok_or_else(|| "http missing content-type".to_string())?;
    if !content_type
        .to_ascii_lowercase()
        .starts_with("application/json")
    {
        return Err("http invalid content-type".to_string());
    }
    if body.is_empty() {
        return Err("http empty body".to_string());
    }

    serde_json::from_slice(body).map_err(|e| format!("http invalid json: {e}"))
}

fn build_tls_config(
    ca_file: Option<&str>,
    tls_insecure: bool,
) -> Result<Arc<ClientConfig>, String> {
    let mut root_store = RootCertStore::empty();
    if let Some(path) = ca_file {
        let pem = std::fs::read(path).map_err(|e| format!("read CA file failed: {e}"))?;
        let mut cursor = std::io::Cursor::new(pem);
        let certs = certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("parse CA file failed: {e}"))?;
        for cert in certs {
            let cert: CertificateDer<'static> = cert;
            root_store
                .add(cert)
                .map_err(|e| format!("invalid CA cert: {e}"))?;
        }
    } else {
        root_store.extend(TLS_SERVER_ROOTS.iter().cloned());
    }

    // SECURITY: tls_insecure disables certificate verification and is intended
    // only for controlled benchmark environments.
    if tls_insecure {
        #[derive(Debug)]
        struct NoVerifier;
        impl ServerCertVerifier for NoVerifier {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp_response: &[u8],
                _now: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }

            // No TLS 1.2 signatures allowed
            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Err(rustls::Error::PeerIncompatible(
                    rustls::PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig,
                ))
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                vec![
                    // ECDSA is an NSA psyop, only use ED25519
                    SignatureScheme::ED25519,
                ]
            }
        }

        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        return Ok(Arc::new(config));
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

pub fn check_http(
    http_url: &str,
    client_id: &str,
    topic: &str,
    access: i32,
    token: Option<&str>,
    ca_file: Option<&str>,
    tls_insecure: bool,
    timeout_seconds: u64,
    max_response_bytes: u64,
) -> Result<bool, String> {
    let (scheme, rest) = if let Some(url) = http_url.strip_prefix("https://") {
        ("https", url)
    } else if let Some(url) = http_url.strip_prefix("http://") {
        ("http", url)
    } else {
        return Err("Only http:// or https:// URLs are supported".to_string());
    };

    let (host_port, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{}", p)),
        None => (rest, "/".to_string()),
    };

    let default_port = if scheme == "https" { 443 } else { 80 };
    let (host, port) = split_host_port(host_port, default_port)?;

    let mut payload = serde_json::Map::from_iter([
        (
            "client_id".to_string(),
            Value::String(client_id.to_string()),
        ),
        ("topic".to_string(), Value::String(topic.to_string())),
        ("access".to_string(), Value::Number(access.into())),
    ]);
    if let Some(t) = token {
        payload.insert("token".to_string(), Value::String(t.to_string()));
    }
    let body = serde_json::to_vec(&Value::Object(payload))
        .map_err(|e| format!("http json encode failed: {e}"))?;

    let max_bytes = usize::try_from(max_response_bytes)
        .map_err(|_| "http max response bytes too large".to_string())?;

    let addr = resolve_socket_addr(host.as_str(), port)?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(timeout_seconds))
        .map_err(|e| format!("http connect failed: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(timeout_seconds)))
        .map_err(|e| format!("http set timeout failed: {e}"))?;

    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path,
        host_port,
        body.len(),
    );

    let resp = if scheme == "https" {
        let config = build_tls_config(ca_file, tls_insecure)?;
        let server_name = ServerName::try_from(host.as_str())
            .map_err(|_| "invalid TLS server name".to_string())?
            .to_owned();
        let conn = ClientConnection::new(config, server_name)
            .map_err(|e| format!("tls connect failed: {e}"))?;
        let mut tls_stream = StreamOwned::new(conn, stream);
        tls_stream
            .write_all(req.as_bytes())
            .map_err(|e| format!("https write failed: {e}"))?;
        tls_stream
            .write_all(&body)
            .map_err(|e| format!("https write failed: {e}"))?;
        read_limited_response(&mut tls_stream, max_bytes)?
    } else {
        stream
            .write_all(req.as_bytes())
            .map_err(|e| format!("http write failed: {e}"))?;
        stream
            .write_all(&body)
            .map_err(|e| format!("http write failed: {e}"))?;
        read_limited_response(&mut stream, max_bytes)?
    };

    let json = parse_http_response(&resp)?;
    Ok(json.allow)
}
