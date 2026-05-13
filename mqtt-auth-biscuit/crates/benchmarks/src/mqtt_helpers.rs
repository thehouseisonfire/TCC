use base64::{Engine as _, engine::general_purpose};
use bytes::Bytes;
use rumqttc::mqttbytes::QoS as V5QoS;
use rumqttc::mqttbytes::v5::{ConnectReturnCode, Packet, PubAckReason, SubscribeReasonCode};
use rumqttc::{AsyncClient, Event, MqttOptions, TlsConfiguration, Transport};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use serde::Serialize;
use std::sync::Arc;
use std::sync::Once;
use std::time::{Duration, Instant};

pub const RAW_BISCUIT_MARKER: &str = "b64:";
static RUSTLS_PROVIDER: Once = Once::new();

#[derive(Debug, thiserror::Error)]
pub enum MqttHelperError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Client(#[from] rumqttc::ClientError),
    #[error(transparent)]
    Connection(#[from] rumqttc::ConnectionError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, MqttHelperError>;

#[derive(Debug, Clone)]
pub struct ClientSpec {
    pub host: String,
    pub port: u16,
    pub client_id: String,
    pub username: String,
    pub password: Vec<u8>,
    pub tls: bool,
    pub tls_ca_file: Option<String>,
    pub tls_insecure: bool,
    pub auth_method: Option<String>,
    pub auth_data: Option<Vec<u8>>,
}

#[derive(Debug, Serialize)]
pub struct ConnectReport {
    pub connect_ms: f64,
    pub connect_ok: bool,
    pub connect_reason: Option<u16>,
}

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
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

/// Decode a token CLI argument.
///
/// Arguments prefixed with `b64:` are interpreted as unpadded base64url.
///
/// # Errors
///
/// Returns an error when a `b64:` token is not valid base64url.
pub fn decode_token_arg(raw: &str) -> Result<Vec<u8>> {
    raw.strip_prefix(RAW_BISCUIT_MARKER).map_or_else(
        || Ok(raw.as_bytes().to_vec()),
        |encoded| {
            let padding = "=".repeat((4 - encoded.len() % 4) % 4);
            general_purpose::URL_SAFE
                .decode(format!("{encoded}{padding}"))
                .map_err(|err| MqttHelperError::Message(format!("invalid base64url token: {err}")))
        },
    )
}

/// Convert a numeric `QoS` level into a rumqttc `QoS` value.
///
/// # Errors
///
/// Returns an error when `value` is not `0`, `1`, or `2`.
pub fn qos(value: u8) -> Result<V5QoS> {
    match value {
        0 => Ok(V5QoS::AtMostOnce),
        1 => Ok(V5QoS::AtLeastOnce),
        2 => Ok(V5QoS::ExactlyOnce),
        other => Err(MqttHelperError::Message(format!("invalid QoS: {other}"))),
    }
}

#[must_use]
pub const fn subscribe_reason_code(code: SubscribeReasonCode) -> u16 {
    match code {
        SubscribeReasonCode::Success(V5QoS::AtMostOnce) => 0,
        SubscribeReasonCode::Success(V5QoS::AtLeastOnce) => 1,
        SubscribeReasonCode::Success(V5QoS::ExactlyOnce) => 2,
        SubscribeReasonCode::Failure | SubscribeReasonCode::Unspecified => 128,
        SubscribeReasonCode::ImplementationSpecific => 131,
        SubscribeReasonCode::NotAuthorized => 135,
        SubscribeReasonCode::TopicFilterInvalid => 143,
        SubscribeReasonCode::PkidInUse => 145,
        SubscribeReasonCode::QuotaExceeded => 151,
        SubscribeReasonCode::SharedSubscriptionsNotSupported => 158,
        SubscribeReasonCode::SubscriptionIdNotSupported => 161,
        SubscribeReasonCode::WildcardSubscriptionsNotSupported => 162,
    }
}

#[must_use]
pub const fn connect_reason_code(code: ConnectReturnCode) -> u16 {
    match code {
        ConnectReturnCode::Success => 0,
        ConnectReturnCode::RefusedProtocolVersion => 1,
        ConnectReturnCode::BadClientId => 2,
        ConnectReturnCode::ServiceUnavailable => 3,
        ConnectReturnCode::BadUserNamePassword => 4,
        ConnectReturnCode::UnspecifiedError => 128,
        ConnectReturnCode::MalformedPacket => 129,
        ConnectReturnCode::ProtocolError => 130,
        ConnectReturnCode::ImplementationSpecificError => 131,
        ConnectReturnCode::UnsupportedProtocolVersion => 132,
        ConnectReturnCode::ClientIdentifierNotValid => 133,
        ConnectReturnCode::NotAuthorized => 135,
        ConnectReturnCode::ServerUnavailable => 136,
        ConnectReturnCode::ServerBusy => 137,
        ConnectReturnCode::Banned => 138,
        ConnectReturnCode::BadAuthenticationMethod => 140,
        ConnectReturnCode::TopicNameInvalid => 144,
        ConnectReturnCode::PacketTooLarge => 149,
        ConnectReturnCode::QuotaExceeded => 151,
        ConnectReturnCode::PayloadFormatInvalid => 153,
        ConnectReturnCode::RetainNotSupported => 154,
        ConnectReturnCode::QoSNotSupported => 155,
        ConnectReturnCode::UseAnotherServer => 156,
        ConnectReturnCode::ServerMoved => 157,
        ConnectReturnCode::ConnectionRateExceeded => 159,
    }
}

#[must_use]
pub const fn puback_reason_code(code: PubAckReason) -> u16 {
    code as u16
}

fn root_store(ca_file: Option<&str>) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    if let Some(path) = ca_file {
        let certs = CertificateDer::pem_file_iter(path)
            .map_err(|err| MqttHelperError::Message(format!("invalid CA file: {err}")))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|err| MqttHelperError::Message(format!("invalid CA file: {err}")))?;
        roots.add_parsable_certificates(certs);
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    Ok(roots)
}

fn tls_config(ca_file: Option<&str>, insecure: bool) -> Result<TlsConfiguration> {
    RUSTLS_PROVIDER.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store(ca_file)?)
        .with_no_client_auth();
    if insecure {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerifier));
    }
    Ok(TlsConfiguration::Rustls(Arc::new(config)))
}

/// Build MQTT options from a benchmark client specification.
///
/// # Errors
///
/// Returns an error when TLS configuration cannot be built.
pub fn mqtt_options(spec: &ClientSpec) -> Result<MqttOptions> {
    let mut options = MqttOptions::new(spec.client_id.clone(), (spec.host.as_str(), spec.port));
    if !spec.username.is_empty() || !spec.password.is_empty() {
        options.set_credentials(spec.username.clone(), Bytes::from(spec.password.clone()));
    }
    if let Some(method) = &spec.auth_method {
        options.set_authentication_method(Some(method.clone()));
    }
    if let Some(data) = &spec.auth_data {
        options.set_authentication_data(Some(Bytes::from(data.clone())));
    }
    if spec.tls {
        options.set_transport(Transport::Tls(tls_config(
            spec.tls_ca_file.as_deref(),
            spec.tls_insecure,
        )?));
    }
    Ok(options)
}

/// Connect to the broker and wait for a `CONNACK`.
///
/// # Errors
///
/// Returns an error when connection setup fails or times out.
pub async fn connect(
    spec: &ClientSpec,
) -> Result<(AsyncClient, rumqttc::EventLoop, ConnectReport)> {
    let options = mqtt_options(spec)?;
    let (client, mut eventloop) = AsyncClient::builder(options).capacity(100).build();
    let start = Instant::now();
    loop {
        let event = tokio::time::timeout(Duration::from_secs(10), eventloop.poll())
            .await
            .map_err(|_| MqttHelperError::Message("connect_timeout".to_string()))??;
        if let Event::Incoming(Packet::ConnAck(connack)) = event {
            let reason = connect_reason_code(connack.code);
            return Ok((
                client,
                eventloop,
                ConnectReport {
                    connect_ms: start.elapsed().as_secs_f64() * 1000.0,
                    connect_ok: reason == 0,
                    connect_reason: Some(reason),
                },
            ));
        }
    }
}

/// Poll an MQTT eventloop until `f` returns a value or the timeout expires.
///
/// # Errors
///
/// Returns an error when event polling fails or the timeout elapses.
pub async fn poll_until<F, T>(
    eventloop: &mut rumqttc::EventLoop,
    timeout: Duration,
    mut f: F,
) -> Result<T>
where
    F: FnMut(Event) -> Option<T>,
{
    let deadline = Instant::now() + timeout;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(MqttHelperError::Message("mqtt_event_timeout".to_string()));
        }
        let event = tokio::time::timeout(deadline - now, eventloop.poll())
            .await
            .map_err(|_| MqttHelperError::Message("mqtt_event_timeout".to_string()))??;
        if let Some(value) = f(event) {
            return Ok(value);
        }
    }
}

/// Print a serializable value as pretty JSON.
///
/// # Errors
///
/// Returns an error when serialization fails.
pub fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rumqttc::ConnectAuth;

    fn client_spec(username: &str, password: &[u8]) -> ClientSpec {
        ClientSpec {
            host: "localhost".to_string(),
            port: 1883,
            client_id: "client".to_string(),
            username: username.to_string(),
            password: password.to_vec(),
            tls: false,
            tls_ca_file: None,
            tls_insecure: false,
            auth_method: None,
            auth_data: None,
        }
    }

    #[test]
    fn mqtt_options_omits_credentials_for_anonymous_clients() {
        let options = mqtt_options(&client_spec("", &[])).expect("options should build");

        assert_eq!(options.auth(), &ConnectAuth::None);
    }

    #[test]
    fn mqtt_options_preserves_empty_username_or_password_when_configured() {
        let password_only =
            mqtt_options(&client_spec("", b"secret")).expect("options should build");
        assert_eq!(
            password_only.auth(),
            &ConnectAuth::UsernamePassword {
                username: String::new(),
                password: Bytes::from_static(b"secret"),
            }
        );

        let username_only = mqtt_options(&client_spec("user", &[])).expect("options should build");
        assert_eq!(
            username_only.auth(),
            &ConnectAuth::UsernamePassword {
                username: "user".to_string(),
                password: Bytes::new(),
            }
        );
    }
}
