use base64::{Engine as _, engine::general_purpose};
use bytes::Bytes;
use clap::Parser;
use gen_tokens::mqtt_helpers::{
    ClientSpec, MqttHelperError, Result, connect_reason_code, mqtt_options, puback_reason_code,
    qos, subscribe_reason_code,
};
use rumqttc::mqttbytes::v5::{DisconnectReasonCode, LastWill, Packet};
use rumqttc::{AsyncClient, Event, PublishResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, BufRead, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Debug, Parser)]
struct Args {}

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum Command {
    Connect {
        host: String,
        port: u16,
        client_id: String,
        username: String,
        password_b64: Option<String>,
        tls: bool,
        tls_ca_file: Option<String>,
        tls_insecure: bool,
        will_topic: Option<String>,
        will_payload_b64: Option<String>,
        will_qos: Option<u8>,
        will_retain: Option<bool>,
    },
    Subscribe {
        topic: String,
        qos: u8,
        timeout_s: Option<f64>,
    },
    Publish {
        topic: String,
        payload_b64: String,
        qos: u8,
        retain: Option<bool>,
        timeout_s: Option<f64>,
    },
    WaitMessages {
        minimum: usize,
        timeout_s: f64,
    },
    WaitTopicMessages {
        topic: String,
        minimum: usize,
        timeout_s: f64,
    },
    WaitDisconnect {
        timeout_s: f64,
    },
    MessageCount {
        topic: Option<String>,
    },
    Close,
}

#[derive(Debug, Serialize)]
struct Response {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Default)]
struct ObservedState {
    messages: Vec<(String, Vec<u8>)>,
    disconnect_reason: Option<u16>,
}

struct ClientState {
    client: AsyncClient,
    observed: Arc<Mutex<ObservedState>>,
}

fn decode_b64(raw: Option<&str>) -> Result<Vec<u8>> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let padding = "=".repeat((4 - raw.len() % 4) % 4);
    general_purpose::URL_SAFE
        .decode(format!("{raw}{padding}"))
        .map_err(|err| MqttHelperError::Message(format!("invalid base64url payload: {err}")))
}

fn response(ok: bool, value: Option<Value>, error: Option<String>) -> Response {
    Response { ok, value, error }
}

fn disconnect_reason_code(code: DisconnectReasonCode) -> u16 {
    code as u16
}

async fn wait_until<F, Fut>(timeout_s: f64, mut predicate: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + Duration::from_secs_f64(timeout_s);
    while Instant::now() < deadline {
        if predicate().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

async fn handle(cmd: Command, state: &mut Option<ClientState>) -> Result<Response> {
    match cmd {
        Command::Connect {
            host,
            port,
            client_id,
            username,
            password_b64,
            tls,
            tls_ca_file,
            tls_insecure,
            will_topic,
            will_payload_b64,
            will_qos,
            will_retain,
        } => {
            let spec = ClientSpec {
                host,
                port,
                client_id,
                username,
                password: decode_b64(password_b64.as_deref())?,
                tls,
                tls_ca_file,
                tls_insecure,
                auth_method: None,
                auth_data: None,
            };
            let mut options = mqtt_options(&spec)?;
            if let Some(topic) = will_topic {
                let will = LastWill::new(
                    topic,
                    Bytes::from(decode_b64(will_payload_b64.as_deref())?),
                    qos(will_qos.unwrap_or(0))?,
                    will_retain.unwrap_or(false),
                    None,
                );
                options.set_last_will(will);
            }
            let (client, mut eventloop) = AsyncClient::builder(options).capacity(100).build();
            let connect_report = loop {
                let event = tokio::time::timeout(Duration::from_secs(10), eventloop.poll())
                    .await
                    .map_err(|_| MqttHelperError::Message("connect_timeout".to_string()))??;
                if let Event::Incoming(Packet::ConnAck(connack)) = event {
                    break serde_json::json!({
                        "connect_reason": connect_reason_code(connack.code),
                    });
                }
            };
            let observed = Arc::new(Mutex::new(ObservedState::default()));
            let observed_task = Arc::clone(&observed);
            tokio::spawn(async move {
                loop {
                    match eventloop.poll().await {
                        Ok(Event::Incoming(Packet::Publish(publish))) => {
                            observed_task.lock().await.messages.push((
                                String::from_utf8_lossy(&publish.topic).into_owned(),
                                publish.payload.to_vec(),
                            ));
                        }
                        Ok(Event::Incoming(Packet::Disconnect(disconnect))) => {
                            observed_task.lock().await.disconnect_reason =
                                Some(disconnect_reason_code(disconnect.reason_code));
                            break;
                        }
                        Ok(_) => {}
                        Err(_) => {
                            observed_task.lock().await.disconnect_reason = Some(0);
                            break;
                        }
                    }
                }
            });
            *state = Some(ClientState { client, observed });
            Ok(response(true, Some(connect_report), None))
        }
        Command::Subscribe {
            topic,
            qos: qos_value,
            timeout_s,
        } => {
            let state = state
                .as_ref()
                .ok_or_else(|| MqttHelperError::Message("not_connected".to_string()))?;
            let notice = state
                .client
                .subscribe_tracked(topic, qos(qos_value)?)
                .await?;
            let suback = tokio::time::timeout(
                Duration::from_secs_f64(timeout_s.unwrap_or(5.0)),
                notice.wait_async(),
            )
            .await
            .map_err(|_| MqttHelperError::Message("subscribe_timeout".to_string()))?
            .map_err(|err| MqttHelperError::Message(format!("subscribe_failed:{err}")))?;
            let codes = suback
                .return_codes
                .into_iter()
                .map(subscribe_reason_code)
                .collect::<Vec<_>>();
            Ok(response(true, Some(serde_json::json!(codes)), None))
        }
        Command::Publish {
            topic,
            payload_b64,
            qos: qos_value,
            retain,
            timeout_s,
        } => {
            let state = state
                .as_ref()
                .ok_or_else(|| MqttHelperError::Message("not_connected".to_string()))?;
            let notice = state
                .client
                .publish_tracked(
                    topic,
                    qos(qos_value)?,
                    retain.unwrap_or(false),
                    decode_b64(Some(&payload_b64))?,
                )
                .await?;
            let result = tokio::time::timeout(
                Duration::from_secs_f64(timeout_s.unwrap_or(5.0)),
                notice.wait_async(),
            )
            .await
            .map_err(|_| MqttHelperError::Message("publish_timeout".to_string()))?
            .map_err(|err| MqttHelperError::Message(format!("publish_failed:{err}")))?;
            let reason = match result {
                PublishResult::Qos0Flushed => None,
                PublishResult::Qos1(puback) => Some(puback_reason_code(puback.reason)),
                PublishResult::Qos2Completed(_) => Some(0),
                PublishResult::Qos2PubRecRejected(pubrec) => Some(pubrec.reason as u16),
            };
            Ok(response(true, Some(serde_json::json!(reason)), None))
        }
        Command::WaitMessages { minimum, timeout_s } => {
            let state = state
                .as_ref()
                .ok_or_else(|| MqttHelperError::Message("not_connected".to_string()))?;
            let observed = Arc::clone(&state.observed);
            let ok = wait_until(timeout_s, || {
                let observed = Arc::clone(&observed);
                async move { observed.lock().await.messages.len() >= minimum }
            })
            .await;
            Ok(response(true, Some(serde_json::json!(ok)), None))
        }
        Command::WaitTopicMessages {
            topic,
            minimum,
            timeout_s,
        } => {
            let state = state
                .as_ref()
                .ok_or_else(|| MqttHelperError::Message("not_connected".to_string()))?;
            let observed = Arc::clone(&state.observed);
            let ok = wait_until(timeout_s, || {
                let observed = Arc::clone(&observed);
                let topic = topic.clone();
                async move {
                    observed
                        .lock()
                        .await
                        .messages
                        .iter()
                        .filter(|(msg_topic, _)| msg_topic == &topic)
                        .count()
                        >= minimum
                }
            })
            .await;
            Ok(response(true, Some(serde_json::json!(ok)), None))
        }
        Command::WaitDisconnect { timeout_s } => {
            let state = state
                .as_ref()
                .ok_or_else(|| MqttHelperError::Message("not_connected".to_string()))?;
            let observed = Arc::clone(&state.observed);
            let ok = wait_until(timeout_s, || {
                let observed = Arc::clone(&observed);
                async move { observed.lock().await.disconnect_reason.is_some() }
            })
            .await;
            let reason = state.observed.lock().await.disconnect_reason;
            Ok(response(
                true,
                Some(serde_json::json!({"disconnected": ok, "reason": reason})),
                None,
            ))
        }
        Command::MessageCount { topic } => {
            let state = state
                .as_ref()
                .ok_or_else(|| MqttHelperError::Message("not_connected".to_string()))?;
            let observed = state.observed.lock().await;
            let count = match topic {
                Some(topic) => observed
                    .messages
                    .iter()
                    .filter(|(msg_topic, _)| msg_topic == &topic)
                    .count(),
                None => observed.messages.len(),
            };
            Ok(response(true, Some(serde_json::json!(count)), None))
        }
        Command::Close => {
            if let Some(state) = state.take() {
                let _ = state.client.disconnect().await;
            }
            Ok(response(true, Some(serde_json::json!(true)), None))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let _args = Args::parse();
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut state = None;
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Command>(&line) {
            Ok(cmd) => match handle(cmd, &mut state).await {
                Ok(response) => response,
                Err(err) => response(false, None, Some(err.to_string())),
            },
            Err(err) => response(false, None, Some(format!("invalid_command:{err}"))),
        };
        serde_json::to_writer(&mut stdout, &response)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
    Ok(())
}
