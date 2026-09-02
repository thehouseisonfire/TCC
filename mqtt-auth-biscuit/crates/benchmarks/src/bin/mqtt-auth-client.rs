use bytes::Bytes;
use clap::Parser;
use gen_tokens::mqtt_helpers::{ClientSpec, Result, connect, decode_token_arg, print_json};
use rumqttc::mqttbytes::QoS;
use rumqttc::mqttbytes::v5::AuthProperties;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "localhost")]
    host: String,
    #[arg(long, default_value_t = 1883)]
    port: u16,
    #[arg(long, default_value = "client_auth")]
    client_id: String,
    #[arg(long, default_value = "token")]
    auth_method: String,
    #[arg(long)]
    token1: String,
    #[arg(long)]
    token2: String,
    #[arg(long, default_value_t = 2.0)]
    sleep: f64,
    #[arg(long)]
    tls: bool,
    #[arg(long)]
    tls_ca_file: Option<String>,
    #[arg(long)]
    tls_insecure: bool,
    #[arg(long, default_value = "INFO")]
    log_level: String,
    #[arg(long)]
    token1_topic: String,
    #[arg(long)]
    token2_topic: String,
}

#[derive(Debug, Serialize)]
struct Output {
    connect_ms: f64,
    connect_pkt_type: u8,
    connect_reason: Option<u16>,
    connect_ok: bool,
    reauth_ms: f64,
    reauth_pkt_type: u8,
    reauth_payload_len: usize,
    token1_bytes: usize,
    token2_bytes: usize,
    reauth_ok: bool,
    reauth_error: Option<String>,
    token1_sha256: String,
    token2_sha256: String,
    pre_reauth_publish_ok: bool,
    post_reauth_publish_ok: bool,
    post_reauth_old_topic_denied: bool,
}

async fn publish_probe(
    client: &rumqttc::AsyncClient,
    eventloop: &mut rumqttc::EventLoop,
    topic: &str,
) -> std::result::Result<(), String> {
    let notice = client
        .publish_tracked(
            topic,
            b"mqtt5-auth-probe".as_slice(),
            rumqttc::PublishOptions::new(QoS::AtLeastOnce),
        )
        .await
        .map_err(|err| err.to_string())?;
    let wait = async {
        loop {
            eventloop.poll().await.map_err(|err| err.to_string())?;
        }
        #[allow(unreachable_code)]
        Ok::<(), String>(())
    };
    tokio::select! {
        result = notice.wait_completion_async() => result.map_err(|err| err.to_string()),
        result = wait => result,
        () = tokio::time::sleep(Duration::from_secs(10)) => Err("publish_probe_timeout".into()),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let token1 = decode_token_arg(&args.token1)?;
    let token2 = decode_token_arg(&args.token2)?;
    let spec = ClientSpec {
        host: args.host,
        port: args.port,
        client_id: args.client_id,
        username: String::new(),
        password: Vec::new(),
        tls: args.tls,
        tls_ca_file: args.tls_ca_file,
        tls_insecure: args.tls_insecure,
        auth_method: Some(args.auth_method.clone()),
        auth_data: Some(token1.clone()),
    };
    let (client, mut eventloop, connect_report) = connect(&spec).await?;
    let pre_reauth_publish_ok = publish_probe(&client, &mut eventloop, &args.token1_topic)
        .await
        .is_ok();

    tokio::time::sleep(Duration::from_secs_f64(args.sleep)).await;
    let props = AuthProperties {
        method: Some(args.auth_method),
        data: Some(Bytes::from(token2.clone())),
        reason: None,
        user_properties: Vec::new(),
    };

    let start = Instant::now();
    let notice = client.reauth_tracked(Some(props)).await?;
    let wait = async {
        loop {
            let _ = eventloop.poll().await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), rumqttc::ConnectionError>(())
    };
    let reauth = tokio::select! {
        result = notice.wait_async() => result.map(|_| ()).map_err(|err| err.to_string()),
        result = wait => result.map_err(|err| err.to_string()),
        () = tokio::time::sleep(Duration::from_secs(10)) => Err("reauth_timeout".to_string()),
    };
    let reauth_ms = start.elapsed().as_secs_f64() * 1000.0;
    let post_reauth_publish_ok = if reauth.is_ok() {
        publish_probe(&client, &mut eventloop, &args.token2_topic)
            .await
            .is_ok()
    } else {
        false
    };
    let post_reauth_old_topic_denied = if post_reauth_publish_ok {
        publish_probe(&client, &mut eventloop, &args.token1_topic)
            .await
            .is_err()
    } else {
        false
    };
    let _ = client.disconnect().await;

    print_json(&Output {
        connect_ms: connect_report.connect_ms,
        connect_pkt_type: 2,
        connect_reason: connect_report.connect_reason,
        connect_ok: connect_report.connect_ok,
        reauth_ms,
        reauth_pkt_type: 15,
        reauth_payload_len: 0,
        token1_bytes: token1.len(),
        token2_bytes: token2.len(),
        reauth_ok: reauth.is_ok(),
        reauth_error: reauth.err(),
        token1_sha256: hex::encode(Sha256::digest(&token1)),
        token2_sha256: hex::encode(Sha256::digest(&token2)),
        pre_reauth_publish_ok,
        post_reauth_publish_ok,
        post_reauth_old_topic_denied,
    })
}
