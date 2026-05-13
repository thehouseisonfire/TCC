#![recursion_limit = "256"]

use base64::{Engine as _, engine::general_purpose};
use biscuit_auth::PublicKey;
use clap::Parser;
use gen_tokens::biscuit_attenuation::{
    BiscuitAttenuationOptions, attenuate_biscuit_token, load_public_key_hex,
};
use gen_tokens::mqtt_helpers::{
    ClientSpec, ConnectReport, MqttHelperError, Result, connect, decode_token_arg, poll_until,
    print_json, puback_reason_code, qos,
};
use rand::{Rng as _, RngExt as _};
use rumqttc::mqttbytes::v5::Packet;
use rumqttc::{AsyncClient, Event, Outgoing};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

const SYNC_CONNECT_RELEASE_DELAY: Duration = Duration::from_millis(200);
const DEFAULT_CONTROL_TOPIC: &str = "$CONTROL/dynamic-security/v1";
const CLIENT_ID_PLACEHOLDER: &str = "{client_id}";

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Parser, Clone)]
struct Args {
    #[arg(long, env = "MQTT_HOST", default_value = "localhost")]
    host: String,
    #[arg(long, env = "MQTT_PORT", default_value_t = 1883)]
    port: u16,
    #[arg(long, env = "MQTT_USERNAME", default_value = "jwt")]
    username: String,
    #[arg(long, env = "MQTT_PASSWORD", default_value = "")]
    password: String,
    #[arg(long, env = "MQTT_CLIENTS", default_value_t = 10)]
    clients: usize,
    #[arg(long, env = "MQTT_MESSAGES", default_value_t = 50)]
    messages: usize,
    #[arg(long, env = "MQTT_TOPIC", default_value = "sensors/{client_id}/temp")]
    topic: String,
    #[arg(long, env = "MQTT_QOS", default_value_t = 1)]
    qos: u8,
    #[arg(long, env = "MQTT_QOS_DISTRIBUTION")]
    qos_distribution: Option<String>,
    #[arg(long, env = "MQTT_MESSAGE_SIZE", default_value_t = 0)]
    message_size: usize,
    #[arg(long)]
    sync_connect: bool,
    #[arg(long, env = "MQTT_MODE", default_value = "publish")]
    mode: String,
    #[arg(long, env = "MQTT_FANOUT_TOPIC", default_value = "fanout/broadcast")]
    fanout_topic: String,
    #[arg(long, env = "MQTT_FANOUT_PUBLISHER_USERNAME")]
    fanout_publisher_username: Option<String>,
    #[arg(long, env = "MQTT_FANOUT_PUBLISHER_PASSWORD")]
    fanout_publisher_password: Option<String>,
    #[arg(long)]
    tls: bool,
    #[arg(long)]
    tls_ca_file: Option<String>,
    #[arg(long)]
    tls_insecure: bool,
    #[arg(long, env = "MQTT_CONTROL_TOPIC")]
    control_topic: Option<String>,
    #[arg(long, env = "MQTT_CONTROL_PAYLOAD")]
    control_payload: Option<String>,
    #[arg(long, env = "MQTT_CONTROL_PAYLOAD_FILE")]
    control_payload_file: Option<String>,
    #[arg(long, env = "MQTT_CONTROL_MODE")]
    control_mode: bool,
    #[arg(long, env = "MQTT_CONTROL_REPEAT", default_value_t = 1)]
    control_repeat: usize,
    #[arg(long, env = "MQTT_CONTROL_QOS", default_value_t = 1)]
    control_qos: u8,
    #[arg(long, env = "MQTT_CONTROL_AFTER_MESSAGES", default_value_t = 0)]
    control_after_messages: usize,
    #[arg(long)]
    json: bool,
    #[arg(long, default_value = "INFO")]
    log_level: String,
    #[arg(long, env = "TOKEN_ISSUER_URL")]
    token_issuer_url: Option<String>,
    #[arg(long, env = "TOKEN_ISSUER_KIND")]
    token_issuer_kind: Option<String>,
    #[arg(long, env = "TOKEN_ISSUER_TTL")]
    token_issuer_ttl: Option<u64>,
    #[arg(long)]
    token_issuer_no_default_roles: bool,
    #[arg(long)]
    token_issuer_no_default_grants: bool,
    #[arg(long, env = "TOKEN_REFRESH_CODES", default_value = "5,135")]
    token_refresh_codes: Option<String>,
    #[arg(long, env = "JWT_IDENTITY_BINDING", default_value = "off")]
    jwt_identity_binding: String,
    #[arg(long, env = "BISCUIT_IDENTITY_BINDING", default_value = "off")]
    biscuit_identity_binding: String,
    #[arg(long, env = "BISCUIT_CLIENT_ID_FACT", default_value = "client_id")]
    biscuit_client_id_fact: String,
    #[arg(long)]
    biscuit_attenuate: bool,
    #[arg(long)]
    biscuit_attenuate_deny: Vec<String>,
    #[arg(long)]
    biscuit_attenuate_check: Vec<String>,
    #[arg(long)]
    biscuit_attenuate_topic: Option<String>,
    #[arg(long)]
    biscuit_attenuate_op: Option<String>,
    #[arg(long)]
    biscuit_attenuate_ttl: Option<u64>,
    #[arg(long)]
    biscuit_public_key_hex: Option<String>,
    #[arg(long)]
    biscuit_public_key_file: Option<String>,
    #[arg(long)]
    biscuit_attenuate_bin: Option<String>,
    #[arg(long)]
    biscuit_delegate: bool,
    #[arg(long)]
    biscuit_delegate_deny: Vec<String>,
    #[arg(long)]
    biscuit_delegate_check: Vec<String>,
    #[arg(long)]
    biscuit_delegate_topic: Option<String>,
    #[arg(long)]
    biscuit_delegate_op: Option<String>,
    #[arg(long)]
    biscuit_delegate_ttl: Option<u64>,
    #[arg(long)]
    biscuit_delegate_public_key_hex: Option<String>,
    #[arg(long)]
    biscuit_delegate_public_key_file: Option<String>,
    #[arg(long)]
    biscuit_delegate_bin: Option<String>,
    #[arg(long)]
    biscuit_delegate_handoff: bool,
    #[arg(long)]
    biscuit_delegate_handoff_topic: Option<String>,
    #[arg(long)]
    biscuit_delegate_handoff_token: Option<String>,
    #[arg(long, default_value_t = 1)]
    biscuit_delegate_handoff_qos: u8,
    #[arg(long)]
    biscuit_delegate_handoff_no_retain: bool,
    #[arg(long, env = "MQTT_FANOUT_CHURN_KIND")]
    fanout_churn_kind: Option<String>,
    #[arg(long, env = "MQTT_FANOUT_CHURN_AFTER_MESSAGES", default_value_t = 0)]
    fanout_churn_after_messages: usize,
    #[arg(long, env = "MQTT_FANOUT_CHURN_INTERVAL_MESSAGES", default_value_t = 0)]
    fanout_churn_interval_messages: usize,
    #[arg(long, env = "MQTT_FANOUT_CHURN_MAX_EVENTS", default_value_t = 1)]
    fanout_churn_max_events: usize,
    #[arg(long, env = "MQTT_FANOUT_CHURN_SETTLE_MS", default_value_t = 0)]
    fanout_churn_settle_ms: u64,
    #[arg(long, env = "MQTT_FANOUT_CHURN_DYNAMIC_SECURITY_SOURCE")]
    fanout_churn_dynamic_security_source: Option<String>,
    #[arg(long, env = "MQTT_FANOUT_CHURN_CONTROL_TOPIC")]
    fanout_churn_control_topic: Option<String>,
    #[arg(long, env = "MQTT_FANOUT_CHURN_CONTROL_PAYLOAD")]
    fanout_churn_control_payload: Option<String>,
    #[arg(long, env = "MQTT_FANOUT_CHURN_SQLITE_DB")]
    fanout_churn_sqlite_db: Option<String>,
    #[arg(long, env = "MQTT_FANOUT_CHURN_SQLITE_TOPIC")]
    fanout_churn_sqlite_topic: Option<String>,
    #[arg(long, env = "MQTT_FANOUT_CHURN_SQLITE_SUBSCRIBERS")]
    fanout_churn_sqlite_subscribers: Option<usize>,
}

#[derive(Debug, Default, Serialize, Clone)]
struct Summary {
    count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    min_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p50_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p95_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p99_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mean_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    median_ms: Option<f64>,
}

#[derive(Debug, Serialize)]
struct Output {
    inputs: Value,
    connect: Summary,
    token_refresh: Summary,
    token_refresh_len: Summary,
    delegation: Summary,
    delegation_len: Summary,
    attenuation: Summary,
    attenuation_len: Summary,
    publish: Summary,
    publish_qos_0: Summary,
    publish_qos_1: Summary,
    publish_qos_2: Summary,
    qos_distribution_actual: Value,
    receive: Summary,
    control: Summary,
    control_injection_delay: Summary,
    throughput_mps: f64,
    publish_throughput_mps: f64,
    receive_throughput_mps: f64,
    received_messages: Value,
    fanout_churn: Value,
    raw_publish_ms: Vec<f64>,
    errors: Vec<String>,
}

#[derive(Debug, Default)]
struct WorkerResult {
    connect_ms: Option<f64>,
    token_refresh_ms: Option<f64>,
    token_refresh_len: Option<f64>,
    delegation_ms: Option<f64>,
    delegation_len: Option<f64>,
    attenuation_ms: Option<f64>,
    attenuation_len: Option<f64>,
    publish_ms: Vec<f64>,
    publish_by_qos: [Vec<f64>; 3],
    receive_ms: Vec<f64>,
    receive_pre_churn: usize,
    receive_post_churn: usize,
    control_ms: Vec<f64>,
    control_injection_ms: Vec<f64>,
    errors: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct WorkerBootstrap {
    delegation_ms: Option<f64>,
    delegation_len: Option<f64>,
    attenuation_ms: Option<f64>,
    attenuation_len: Option<f64>,
}

struct WorkerInvocation {
    args: Args,
    index: usize,
    bootstrap: WorkerBootstrap,
    handoff_nonce: Option<String>,
    handoff_password: Option<Vec<u8>>,
    handoff_required: bool,
    sync_connect: Option<Arc<SyncConnectGate>>,
    publish_gate: Option<Arc<PublishStartGate>>,
}

struct StandardMetrics {
    connect: Vec<f64>,
    token_refresh: Vec<f64>,
    token_refresh_len: Vec<f64>,
    delegation: Vec<f64>,
    delegation_len: Vec<f64>,
    attenuation: Vec<f64>,
    attenuation_len: Vec<f64>,
    publish: Vec<f64>,
    publish_qos_0: Vec<f64>,
    publish_qos_1: Vec<f64>,
    publish_qos_2: Vec<f64>,
    receive: Vec<f64>,
    control: Vec<f64>,
    control_injection: Vec<f64>,
    errors: Vec<String>,
    publish_throughput_mps: f64,
    receive_throughput_mps: f64,
}

#[derive(Debug, Clone)]
struct HandoffPlan {
    nonce: String,
    workers: HashMap<String, WorkerBootstrap>,
    tokens: HashMap<String, String>,
    errors: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct HandoffPayload {
    client_id: String,
    token: String,
    nonce: String,
}

#[derive(Debug, Default, Clone)]
struct FanoutChurnState {
    triggered: bool,
    applied_events: usize,
}

#[derive(Debug, Clone)]
struct QosDistribution(Vec<(u8, f64)>);

impl QosDistribution {
    fn parse(raw: Option<&str>) -> Result<Option<Self>> {
        let Some(raw) = raw else {
            return Ok(None);
        };
        let mut entries = Vec::new();
        for part in raw.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (qos_raw, weight_raw) = part.split_once(':').ok_or_else(|| {
                MqttHelperError::Message(format!("invalid qos distribution entry: {part}"))
            })?;
            let qos_value = qos_raw.trim().parse::<u8>().map_err(|err| {
                MqttHelperError::Message(format!("invalid qos value {qos_raw:?}: {err}"))
            })?;
            if !matches!(qos_value, 0..=2) {
                return Err(MqttHelperError::Message(format!(
                    "invalid qos value: {qos_value}"
                )));
            }
            let weight = weight_raw.trim().parse::<f64>().map_err(|err| {
                MqttHelperError::Message(format!("invalid qos weight {weight_raw:?}: {err}"))
            })?;
            if !weight.is_finite() || weight <= 0.0 {
                return Err(MqttHelperError::Message(format!(
                    "invalid qos weight: {weight}"
                )));
            }
            entries.push((qos_value, weight));
        }
        if entries.is_empty() {
            return Ok(None);
        }
        let total = entries.iter().map(|(_, weight)| *weight).sum::<f64>();
        if !total.is_finite() || total <= 0.0 {
            return Err(MqttHelperError::Message(
                "qos distribution weights must sum to a positive value".to_string(),
            ));
        }
        for (_, weight) in &mut entries {
            *weight /= total;
        }
        Ok(Some(Self(entries)))
    }

    fn choose(&self) -> u8 {
        let mut sample = rand::rng().random::<f64>();
        for (qos_value, weight) in &self.0 {
            if sample < *weight {
                return *qos_value;
            }
            sample -= *weight;
        }
        self.0.last().map_or(0, |(qos_value, _)| *qos_value)
    }

    fn subscribe_qos(&self) -> u8 {
        self.0
            .iter()
            .map(|(qos_value, _)| *qos_value)
            .max()
            .unwrap_or(0)
    }

    fn as_json(&self) -> Value {
        Value::Array(
            self.0
                .iter()
                .map(|(qos_value, weight)| serde_json::json!({"qos": qos_value, "weight": weight}))
                .collect(),
        )
    }
}

#[derive(Debug)]
struct SyncConnectGate {
    released: AtomicBool,
    notify: Notify,
}

impl SyncConnectGate {
    fn new() -> Self {
        Self {
            released: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            if self.released.load(Ordering::Acquire) {
                break;
            }
            notified.await;
        }
    }

    fn release(&self) {
        self.released.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }
}

#[derive(Debug)]
struct PublishStartGate {
    expected: usize,
    ready: AtomicUsize,
    unavailable: AtomicUsize,
    released: AtomicBool,
    ready_notify: Notify,
    release_notify: Notify,
}

impl PublishStartGate {
    fn new(expected: usize) -> Self {
        Self {
            expected,
            ready: AtomicUsize::new(0),
            unavailable: AtomicUsize::new(0),
            released: AtomicBool::new(false),
            ready_notify: Notify::new(),
            release_notify: Notify::new(),
        }
    }

    fn mark_ready(&self) {
        self.ready.fetch_add(1, Ordering::AcqRel);
        self.ready_notify.notify_waiters();
    }

    fn mark_unavailable(&self) {
        self.unavailable.fetch_add(1, Ordering::AcqRel);
        self.ready_notify.notify_waiters();
    }

    async fn wait_until_ready_or_unavailable(&self) {
        loop {
            let notified = self.ready_notify.notified();
            let accounted =
                self.ready.load(Ordering::Acquire) + self.unavailable.load(Ordering::Acquire);
            if accounted >= self.expected {
                break;
            }
            notified.await;
        }
    }

    async fn wait_released(&self) {
        loop {
            let notified = self.release_notify.notified();
            if self.released.load(Ordering::Acquire) {
                break;
            }
            notified.await;
        }
    }

    fn release(&self) {
        self.released.store(true, Ordering::Release);
        self.release_notify.notify_waiters();
    }
}

struct PublishGateParticipant {
    gate: Option<Arc<PublishStartGate>>,
    ready: bool,
}

impl PublishGateParticipant {
    const fn new(gate: Option<Arc<PublishStartGate>>) -> Self {
        Self { gate, ready: false }
    }

    fn mark_ready(&mut self) -> Option<Arc<PublishStartGate>> {
        let gate = self.gate.as_ref()?;
        self.ready = true;
        gate.mark_ready();
        Some(Arc::clone(gate))
    }
}

impl Drop for PublishGateParticipant {
    fn drop(&mut self) {
        if !self.ready
            && let Some(gate) = &self.gate
        {
            gate.mark_unavailable();
        }
    }
}

fn parse_token_refresh_codes(raw: Option<&str>) -> Result<Vec<u16>> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let mut codes = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let value = part
            .strip_prefix("0x")
            .or_else(|| part.strip_prefix("0X"))
            .map_or_else(|| part.parse::<u16>(), |hex| u16::from_str_radix(hex, 16))
            .map_err(|err| {
                MqttHelperError::Message(format!("invalid token refresh code {part:?}: {err}"))
            })?;
        codes.push(value);
    }
    codes.sort_unstable();
    codes.dedup();
    Ok(codes)
}

fn active_token_kind(username: &str) -> Option<&'static str> {
    match username {
        "jwt" => Some("jwt"),
        "biscuit" => Some("biscuit"),
        _ => None,
    }
}

fn active_identity_binding_for<'a>(
    username: &str,
    jwt_identity_binding: &'a str,
    biscuit_identity_binding: &'a str,
) -> (Option<&'static str>, &'a str) {
    match active_token_kind(username) {
        Some("jwt") => (Some("jwt"), jwt_identity_binding),
        Some("biscuit") => (Some("biscuit"), biscuit_identity_binding),
        _ => (None, "off"),
    }
}

fn active_identity_binding(args: &Args) -> (Option<&'static str>, &str) {
    active_identity_binding_for(
        &args.username,
        args.jwt_identity_binding.as_str(),
        args.biscuit_identity_binding.as_str(),
    )
}

fn strict_multi_client_startup(args: &Args) -> bool {
    let (_, binding) = active_identity_binding(args);
    binding == "strict" && args.clients > 1
}

fn resolved_token_issuer_kind(args: &Args) -> Option<String> {
    args.token_issuer_kind
        .clone()
        .or_else(|| active_token_kind(&args.username).map(str::to_string))
}

fn apply_legacy_defaults(args: &mut Args) {
    if args.control_mode && args.control_topic.as_deref().is_none_or(str::is_empty) {
        args.control_topic = Some(DEFAULT_CONTROL_TOPIC.to_string());
    }
}

fn validate_startup_provisioning(args: &Args) -> Result<()> {
    if !strict_multi_client_startup(args) {
        return Ok(());
    }
    let active_kind = active_token_kind(&args.username).ok_or_else(|| {
        MqttHelperError::Message(
            "strict multi-client startup provisioning requires username 'jwt' or 'biscuit'"
                .to_string(),
        )
    })?;
    if args.token_issuer_url.is_none() {
        return Err(MqttHelperError::Message(
            "strict multi-client startup provisioning requires token_issuer_url".to_string(),
        ));
    }
    let resolved = resolved_token_issuer_kind(args).unwrap_or_default();
    if resolved != active_kind {
        return Err(MqttHelperError::Message(format!(
            "strict multi-client startup provisioning requires token_issuer_kind {active_kind:?}, got {resolved:?}"
        )));
    }
    Ok(())
}

fn should_provision_fanout_publisher(args: &Args, publisher_username: &str) -> Result<bool> {
    if !strict_multi_client_startup(args) {
        return Ok(false);
    }

    let (publisher_kind, publisher_binding) = active_identity_binding_for(
        publisher_username,
        args.jwt_identity_binding.as_str(),
        args.biscuit_identity_binding.as_str(),
    );
    if publisher_binding != "strict" {
        return Ok(false);
    }

    let publisher_kind = publisher_kind.ok_or_else(|| {
        MqttHelperError::Message(
            "strict multi-client startup provisioning requires fanout publisher username 'jwt' or 'biscuit'"
                .to_string(),
        )
    })?;
    let resolved = resolved_token_issuer_kind(args).unwrap_or_default();
    if resolved != publisher_kind {
        return Err(MqttHelperError::Message(format!(
            "strict multi-client startup provisioning requires fanout publisher token_issuer_kind {publisher_kind:?}, got {resolved:?}"
        )));
    }

    Ok(true)
}

async fn fetch_token(args: &Args, kind: &str, client_id: &str, topic: &str) -> Result<Vec<u8>> {
    let issuer_url = args
        .token_issuer_url
        .as_ref()
        .ok_or_else(|| MqttHelperError::Message("token_issuer_url is required".to_string()))?;
    let endpoint = match kind {
        "jwt" => "/jwt",
        "biscuit" => "/biscuit/binary",
        other => {
            return Err(MqttHelperError::Message(format!(
                "unsupported token issuer kind: {other}"
            )));
        }
    };
    let mut payload = serde_json::json!({
        "client_id": client_id,
        "ttl_seconds": args.token_issuer_ttl,
    });
    if let Some(object) = payload.as_object_mut() {
        if args.token_issuer_no_default_roles {
            object.insert("no_default_roles".to_string(), Value::Bool(true));
        }
        if args.token_issuer_no_default_grants {
            object.insert("no_default_grants".to_string(), Value::Bool(true));
        }
        match kind {
            "jwt" if args.jwt_identity_binding == "strict" => {
                object.insert("subject".to_string(), Value::String(client_id.to_string()));
            }
            "biscuit" => {
                object.insert("topic".to_string(), Value::String(topic.to_string()));
                if args.biscuit_identity_binding == "strict" {
                    object.insert(
                        "identity_fact_predicate".to_string(),
                        Value::String(args.biscuit_client_id_fact.clone()),
                    );
                    object.insert(
                        "identity_fact_value".to_string(),
                        Value::String(client_id.to_string()),
                    );
                }
            }
            _ => {}
        }
    }

    let mut builder = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(5));
    if args.tls_insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if let Some(path) = &args.tls_ca_file {
        let cert = reqwest::Certificate::from_pem(&std::fs::read(path)?).map_err(|err| {
            MqttHelperError::Message(format!("invalid token issuer CA file {path}: {err}"))
        })?;
        builder = builder.add_root_certificate(cert);
    }
    let client = builder
        .build()
        .map_err(|err| MqttHelperError::Message(format!("token issuer client failed: {err}")))?;
    let url = format!("{}{}", issuer_url.trim_end_matches('/'), endpoint);
    let response = client
        .post(url)
        .json(&payload)
        .send()
        .await
        .map_err(|err| MqttHelperError::Message(format!("token issuer request failed: {err}")))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(MqttHelperError::Message(format!(
            "token issuer returned {status}: {body}"
        )));
    }
    let body: Value = response.json().await.map_err(|err| {
        MqttHelperError::Message(format!("token issuer response JSON failed: {err}"))
    })?;
    if kind == "biscuit" {
        let encoded = body
            .get("data_b64")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                MqttHelperError::Message("token issuer response missing data_b64".to_string())
            })?;
        let padding = "=".repeat((4 - encoded.len() % 4) % 4);
        return general_purpose::URL_SAFE
            .decode(format!("{encoded}{padding}"))
            .map_err(|err| MqttHelperError::Message(format!("invalid data_b64 token: {err}")));
    }
    let token = body.get("token").and_then(Value::as_str).ok_or_else(|| {
        MqttHelperError::Message("token issuer response missing token".to_string())
    })?;
    Ok(token.as_bytes().to_vec())
}

async fn startup_password(args: &Args, client_id: &str, topic: &str) -> Result<Vec<u8>> {
    if strict_multi_client_startup(args) {
        let kind = resolved_token_issuer_kind(args).ok_or_else(|| {
            MqttHelperError::Message(
                "strict multi-client startup provisioning requires token kind".to_string(),
            )
        })?;
        fetch_token(args, &kind, client_id, topic).await
    } else {
        decode_token_arg(&args.password)
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")))
        .to_path_buf()
}

fn resolve_repo_path(path: &str) -> PathBuf {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        candidate
    } else {
        repo_root().join(candidate)
    }
}

fn handoff_topic(args: &Args) -> Option<String> {
    if args.biscuit_delegate_handoff {
        Some(
            args.biscuit_delegate_handoff_topic
                .clone()
                .unwrap_or_else(|| "delegation/handoff".to_string()),
        )
    } else {
        None
    }
}

const fn handoff_retain(args: &Args) -> bool {
    !args.biscuit_delegate_handoff_no_retain
}

fn fill_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

struct BiscuitTransform {
    password: Vec<u8>,
    elapsed_ms: f64,
    token_len: f64,
}

struct BiscuitTransformRequest<'a> {
    token: &'a [u8],
    custom_bin: Option<&'a str>,
    public_key_hex: Option<&'a str>,
    public_key_file: Option<&'a str>,
    restrict_topic: Option<&'a str>,
    restrict_operation: Option<&'a str>,
    ttl_seconds: Option<u64>,
    denies: &'a [String],
    checks: &'a [String],
}

fn usize_as_f64(value: usize) -> f64 {
    u32::try_from(value).map_or_else(
        |_| value.to_string().parse::<f64>().unwrap_or(f64::INFINITY),
        f64::from,
    )
}

fn load_biscuit_public_key(
    public_key_hex: Option<&str>,
    public_key_file: Option<&str>,
) -> Result<PublicKey> {
    let hex_value = if let Some(public_key_hex) = public_key_hex {
        public_key_hex.to_string()
    } else if let Some(public_key_file) = public_key_file {
        fs::read_to_string(public_key_file)
            .map_err(|err| {
                MqttHelperError::Message(format!(
                    "failed to read public key file {public_key_file}: {err}"
                ))
            })?
            .trim()
            .to_string()
    } else {
        std::env::var("BISCUIT_PUBLIC_KEY_HEX")
            .map_err(|_| MqttHelperError::Message("public key hex required".to_string()))?
    };
    load_public_key_hex(&hex_value).map_err(MqttHelperError::Message)
}

fn reject_custom_biscuit_transform_bin(custom_bin: Option<&str>, label: &str) -> Result<()> {
    if custom_bin.is_some() {
        return Err(MqttHelperError::Message(format!(
            "{label} custom helper binaries are no longer supported; mqtt-loadgen now attenuates Biscuit tokens in-process"
        )));
    }
    if std::env::var_os("BISCUIT_ATTENUATE_BIN").is_some() {
        return Err(MqttHelperError::Message(
            "BISCUIT_ATTENUATE_BIN is no longer supported; mqtt-loadgen now attenuates Biscuit tokens in-process"
                .to_string(),
        ));
    }
    Ok(())
}

fn transform_biscuit_token(request: &BiscuitTransformRequest<'_>) -> Result<BiscuitTransform> {
    reject_custom_biscuit_transform_bin(request.custom_bin, "Biscuit transform")?;
    let public_key = load_biscuit_public_key(request.public_key_hex, request.public_key_file)?;
    let ttl_seconds = request
        .ttl_seconds
        .map(i64::try_from)
        .transpose()
        .map_err(|_| MqttHelperError::Message("ttl seconds exceeds i64 range".to_string()))?;
    let started = Instant::now();
    let password = attenuate_biscuit_token(
        request.token,
        public_key,
        &BiscuitAttenuationOptions {
            denies: request.denies.to_vec(),
            checks: request.checks.to_vec(),
            restrict_topic: request.restrict_topic.map(str::to_string),
            restrict_operation: request.restrict_operation.map(str::to_string),
            ttl_seconds,
        },
    )
    .map_err(MqttHelperError::Message)?;
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
    if password.is_empty() {
        return Err(MqttHelperError::Message(
            "biscuit transform produced empty token".to_string(),
        ));
    }
    let token_len = usize_as_f64(password.len());
    Ok(BiscuitTransform {
        password,
        elapsed_ms,
        token_len,
    })
}

fn expand_client_template(value: &str, client_id: &str) -> String {
    value.replace(CLIENT_ID_PLACEHOLDER, client_id)
}

fn expand_client_templates(values: &[String], client_id: &str) -> Vec<String> {
    values
        .iter()
        .map(|value| expand_client_template(value, client_id))
        .collect()
}

fn expand_client_placeholders(value: &mut Value, client_id: &str) {
    match value {
        Value::String(value) => *value = expand_client_template(value, client_id),
        Value::Array(values) => {
            for value in values {
                expand_client_placeholders(value, client_id);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                expand_client_placeholders(value, client_id);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn expand_control_payload(raw: &[u8], client_id: &str) -> Vec<u8> {
    serde_json::from_slice::<Value>(raw).map_or_else(
        |_| {
            std::str::from_utf8(raw).map_or_else(
                |_| raw.to_vec(),
                |payload| expand_client_template(payload, client_id).into_bytes(),
            )
        },
        |mut value| {
            expand_client_placeholders(&mut value, client_id);
            serde_json::to_vec(&value).unwrap_or_else(|_| raw.to_vec())
        },
    )
}

fn load_control_payload(args: &Args, result: &mut WorkerResult) -> Vec<u8> {
    match (&args.control_payload, &args.control_payload_file) {
        (Some(payload), _) => payload.clone().into_bytes(),
        (None, Some(path)) => match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) => {
                result
                    .errors
                    .push(format!("control_payload_file_failed:{err}"));
                b"{}".to_vec()
            }
        },
        (None, None) => b"{}".to_vec(),
    }
}

const fn should_apply_worker_biscuit_transforms(
    handoff_nonce: Option<&str>,
    handoff_password_supplied: bool,
    handoff_required: bool,
) -> bool {
    handoff_nonce.is_none() && !handoff_password_supplied && !handoff_required
}

fn apply_biscuit_transforms(
    args: &Args,
    client_id: &str,
    result: &mut WorkerResult,
    password: &mut Vec<u8>,
) -> bool {
    if args.biscuit_attenuate {
        let restrict_topic = args
            .biscuit_attenuate_topic
            .as_deref()
            .map(|topic| expand_client_template(topic, client_id));
        let denies = expand_client_templates(&args.biscuit_attenuate_deny, client_id);
        let checks = expand_client_templates(&args.biscuit_attenuate_check, client_id);
        match transform_biscuit_token(&BiscuitTransformRequest {
            token: password,
            custom_bin: args.biscuit_attenuate_bin.as_deref(),
            public_key_hex: args.biscuit_public_key_hex.as_deref(),
            public_key_file: args.biscuit_public_key_file.as_deref(),
            restrict_topic: restrict_topic.as_deref(),
            restrict_operation: args.biscuit_attenuate_op.as_deref(),
            ttl_seconds: args.biscuit_attenuate_ttl,
            denies: &denies,
            checks: &checks,
        }) {
            Ok(transform) => {
                *password = transform.password;
                result.attenuation_ms = Some(transform.elapsed_ms);
                result.attenuation_len = Some(transform.token_len);
            }
            Err(err) => {
                result.errors.push(format!("attenuation_failed:{err}"));
                return false;
            }
        }
    }
    if args.biscuit_delegate {
        let restrict_topic = args
            .biscuit_delegate_topic
            .as_deref()
            .map(|topic| expand_client_template(topic, client_id));
        let denies = expand_client_templates(&args.biscuit_delegate_deny, client_id);
        let checks = expand_client_templates(&args.biscuit_delegate_check, client_id);
        match transform_biscuit_token(&BiscuitTransformRequest {
            token: password,
            custom_bin: args.biscuit_delegate_bin.as_deref(),
            public_key_hex: args.biscuit_delegate_public_key_hex.as_deref(),
            public_key_file: args.biscuit_delegate_public_key_file.as_deref(),
            restrict_topic: restrict_topic.as_deref(),
            restrict_operation: args.biscuit_delegate_op.as_deref(),
            ttl_seconds: args.biscuit_delegate_ttl,
            denies: &denies,
            checks: &checks,
        }) {
            Ok(transform) => {
                *password = transform.password;
                result.delegation_ms = Some(transform.elapsed_ms);
                result.delegation_len = Some(transform.token_len);
            }
            Err(err) => {
                result.errors.push(format!("delegation_failed:{err}"));
                return false;
            }
        }
    }
    true
}

async fn prepare_handoff(args: &Args, mode_topic: &str) -> Option<HandoffPlan> {
    if !(args.biscuit_delegate && args.biscuit_delegate_handoff) {
        return None;
    }
    let nonce = fill_nonce();
    let mut workers = HashMap::new();
    let mut published_tokens = HashMap::new();
    let mut errors = Vec::new();
    for index in 0..args.clients {
        let client_id = format!("client_{}", index + 1);
        let topic = if mode_topic.contains(CLIENT_ID_PLACEHOLDER) {
            expand_client_template(mode_topic, &client_id)
        } else {
            mode_topic.to_string()
        };
        let mut result = WorkerResult::default();
        let mut password = match startup_password(args, &client_id, &topic).await {
            Ok(password) => password,
            Err(err) => {
                errors.push(format!("startup_provisioning_failed:{client_id}:{err}"));
                continue;
            }
        };
        if !apply_biscuit_transforms(args, &client_id, &mut result, &mut password) {
            errors.extend(
                result
                    .errors
                    .into_iter()
                    .map(|err| format!("{client_id}:{err}")),
            );
            continue;
        }
        published_tokens.insert(
            client_id.clone(),
            general_purpose::URL_SAFE_NO_PAD.encode(&password),
        );
        workers.insert(
            client_id,
            WorkerBootstrap {
                delegation_ms: result.delegation_ms,
                delegation_len: result.delegation_len,
                attenuation_ms: result.attenuation_ms,
                attenuation_len: result.attenuation_len,
            },
        );
    }
    Some(HandoffPlan {
        nonce,
        workers,
        tokens: published_tokens,
        errors,
    })
}

fn ensure_policy_tables(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS users(client_id TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS roles(role_name TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS user_roles(
            client_id TEXT NOT NULL,
            role_name TEXT NOT NULL,
            priority INTEGER NOT NULL DEFAULT 100,
            PRIMARY KEY(client_id, role_name)
        );
        CREATE TABLE IF NOT EXISTS role_acls(
            role_name TEXT NOT NULL,
            topic_filter TEXT NOT NULL,
            access INTEGER NOT NULL,
            PRIMARY KEY(role_name, topic_filter, access)
        );
        CREATE TABLE IF NOT EXISTS role_deny_acls(
            role_name TEXT NOT NULL,
            topic_filter TEXT NOT NULL,
            access INTEGER NOT NULL,
            PRIMARY KEY(role_name, topic_filter, access)
        );
        CREATE TABLE IF NOT EXISTS acl(
            client_id TEXT NOT NULL,
            topic TEXT NOT NULL,
            access INTEGER NOT NULL,
            PRIMARY KEY(client_id, topic, access)
        );",
    )
}

fn sqlite_revoke_read(db_path: &str, topic: &str) -> Result<()> {
    let conn = rusqlite::Connection::open(resolve_repo_path(db_path))
        .map_err(|err| MqttHelperError::Message(format!("sqlite_open_failed:{err}")))?;
    ensure_policy_tables(&conn)
        .map_err(|err| MqttHelperError::Message(format!("sqlite_schema_failed:{err}")))?;
    conn.execute(
        "DELETE FROM role_acls WHERE role_name = ?1 AND topic_filter = ?2 AND access = 1",
        ("fanout_reader", topic),
    )
    .map_err(|err| MqttHelperError::Message(format!("sqlite_revoke_failed:{err}")))?;
    Ok(())
}

fn sqlite_grant_read(db_path: &str, topic: &str) -> Result<()> {
    let conn = rusqlite::Connection::open(resolve_repo_path(db_path))
        .map_err(|err| MqttHelperError::Message(format!("sqlite_open_failed:{err}")))?;
    ensure_policy_tables(&conn)
        .map_err(|err| MqttHelperError::Message(format!("sqlite_schema_failed:{err}")))?;
    conn.execute(
        "INSERT OR REPLACE INTO role_acls(role_name, topic_filter, access) VALUES(?1, ?2, 1)",
        ("fanout_reader", topic),
    )
    .map_err(|err| MqttHelperError::Message(format!("sqlite_grant_failed:{err}")))?;
    Ok(())
}

fn sqlite_toggle_read(db_path: &str, topic: &str) -> Result<()> {
    let conn = rusqlite::Connection::open(resolve_repo_path(db_path))
        .map_err(|err| MqttHelperError::Message(format!("sqlite_open_failed:{err}")))?;
    ensure_policy_tables(&conn)
        .map_err(|err| MqttHelperError::Message(format!("sqlite_schema_failed:{err}")))?;
    let exists: Option<i32> = conn
        .query_row(
            "SELECT 1 FROM role_acls WHERE role_name = ?1 AND topic_filter = ?2 AND access = 1 LIMIT 1",
            ("fanout_reader", topic),
            |row| row.get(0),
        )
        .ok();
    drop(conn);
    if exists.is_some() {
        sqlite_revoke_read(db_path, topic)
    } else {
        sqlite_grant_read(db_path, topic)
    }
}

fn sqlite_toggle_private_deny(db_path: &str, topic: &str) -> Result<()> {
    let conn = rusqlite::Connection::open(resolve_repo_path(db_path))
        .map_err(|err| MqttHelperError::Message(format!("sqlite_open_failed:{err}")))?;
    ensure_policy_tables(&conn)
        .map_err(|err| MqttHelperError::Message(format!("sqlite_schema_failed:{err}")))?;
    let exists: Option<i32> = conn
        .query_row(
            "SELECT 1 FROM role_deny_acls WHERE role_name = ?1 AND topic_filter = ?2 AND access = 1 LIMIT 1",
            ("deep_private_deny", topic),
            |row| row.get(0),
        )
        .ok();
    if exists.is_some() {
        conn.execute(
            "DELETE FROM role_deny_acls WHERE role_name = ?1 AND topic_filter = ?2 AND access IN (1, 4)",
            ("deep_private_deny", topic),
        )
    } else {
        conn.execute(
            "INSERT OR REPLACE INTO role_deny_acls(role_name, topic_filter, access) VALUES(?1, ?2, 4), (?1, ?2, 1)",
            ("deep_private_deny", topic),
        )
    }
    .map_err(|err| MqttHelperError::Message(format!("sqlite_private_deny_failed:{err}")))?;
    Ok(())
}

const fn should_apply_churn(args: &Args, sequence_id: usize, state: &FanoutChurnState) -> bool {
    if args.fanout_churn_kind.is_none()
        || sequence_id < args.fanout_churn_after_messages
        || state.applied_events >= args.fanout_churn_max_events
    {
        return false;
    }
    if sequence_id == args.fanout_churn_after_messages {
        return true;
    }
    args.fanout_churn_interval_messages > 0
        && (sequence_id - args.fanout_churn_after_messages)
            .is_multiple_of(args.fanout_churn_interval_messages)
}

async fn apply_fanout_churn(
    args: &Args,
    publisher: &rumqttc::AsyncClient,
    publisher_eventloop: &mut rumqttc::EventLoop,
) -> Option<String> {
    let kind = args.fanout_churn_kind.as_deref()?;
    let result = match kind {
        "dynamic_security_swap" => {
            let Some(source) = &args.fanout_churn_dynamic_security_source else {
                return Some("fanout_churn_missing_dynamic_security_source".to_string());
            };
            fs::copy(
                resolve_repo_path(source),
                resolve_repo_path("docker/dynamic-security.json"),
            )
            .map(|_| ())
            .map_err(|err| MqttHelperError::Message(format!("dynsec_copy_failed:{err}")))
        }
        "dynamic_security_control" => {
            let Some(topic) = &args.fanout_churn_control_topic else {
                return Some("fanout_churn_missing_control_topic".to_string());
            };
            let Some(payload) = &args.fanout_churn_control_payload else {
                return Some("fanout_churn_missing_control_payload".to_string());
            };
            publish_and_wait(
                publisher,
                publisher_eventloop,
                topic,
                payload.clone().into_bytes(),
                1,
            )
            .await
            .map(|_| ())
        }
        "sqlite_revoke_read" => {
            let Some(db) = &args.fanout_churn_sqlite_db else {
                return Some("fanout_churn_missing_sqlite_db".to_string());
            };
            let topic = args
                .fanout_churn_sqlite_topic
                .as_deref()
                .unwrap_or(&args.fanout_topic);
            sqlite_revoke_read(db, topic)
        }
        "sqlite_toggle_read" => {
            let Some(db) = &args.fanout_churn_sqlite_db else {
                return Some("fanout_churn_missing_sqlite_db".to_string());
            };
            let topic = args
                .fanout_churn_sqlite_topic
                .as_deref()
                .unwrap_or(&args.fanout_topic);
            sqlite_toggle_read(db, topic)
        }
        "sqlite_toggle_private_deny" => {
            let Some(db) = &args.fanout_churn_sqlite_db else {
                return Some("fanout_churn_missing_sqlite_db".to_string());
            };
            let topic = args
                .fanout_churn_sqlite_topic
                .as_deref()
                .unwrap_or(&args.fanout_topic);
            sqlite_toggle_private_deny(db, topic)
        }
        other => return Some(format!("fanout_churn_unknown_kind:{other}")),
    };
    if let Err(err) = result {
        return Some(format!("fanout_churn_failed:{err}"));
    }
    if args.fanout_churn_settle_ms > 0 {
        tokio::time::sleep(Duration::from_millis(args.fanout_churn_settle_ms)).await;
    }
    None
}

fn inputs_json(
    args: &Args,
    mode: &str,
    qos_distribution: Option<&QosDistribution>,
    token_refresh_codes: &[u16],
    handoff_nonce: Option<&str>,
) -> Value {
    serde_json::json!({
        "host": args.host,
        "port": args.port,
        "username": args.username,
        "fanout_publisher_username": args.fanout_publisher_username,
        "clients": args.clients,
        "message_count": args.messages,
        "qos": args.qos,
        "qos_distribution": qos_distribution.map(QosDistribution::as_json),
        "message_size": args.message_size,
        "protocol": "mqttv5",
        "token_issuer_url": args.token_issuer_url,
        "token_issuer_kind": resolved_token_issuer_kind(args),
        "token_issuer_no_default_roles": args.token_issuer_no_default_roles,
        "token_issuer_no_default_grants": args.token_issuer_no_default_grants,
        "token_refresh_codes": token_refresh_codes,
        "jwt_identity_binding": args.jwt_identity_binding,
        "biscuit_identity_binding": args.biscuit_identity_binding,
        "biscuit_client_id_fact": args.biscuit_client_id_fact,
        "biscuit_transform_mode": "in_process",
        "strict_multi_client_startup_provisioning": strict_multi_client_startup(args),
        "mode": mode,
        "fanout_topic": args.fanout_topic,
        "biscuit_attenuate": args.biscuit_attenuate,
        "biscuit_attenuate_denies": args.biscuit_attenuate_deny,
        "biscuit_attenuate_checks": args.biscuit_attenuate_check,
        "biscuit_attenuate_topic": args.biscuit_attenuate_topic,
        "biscuit_attenuate_operation": args.biscuit_attenuate_op,
        "biscuit_attenuate_ttl": args.biscuit_attenuate_ttl,
        "biscuit_public_key_hex": args.biscuit_public_key_hex,
        "biscuit_public_key_file": args.biscuit_public_key_file,
        "biscuit_delegate": args.biscuit_delegate,
        "biscuit_delegate_denies": args.biscuit_delegate_deny,
        "biscuit_delegate_checks": args.biscuit_delegate_check,
        "biscuit_delegate_topic": args.biscuit_delegate_topic,
        "biscuit_delegate_operation": args.biscuit_delegate_op,
        "biscuit_delegate_ttl": args.biscuit_delegate_ttl,
        "biscuit_delegate_public_key_hex": args.biscuit_delegate_public_key_hex,
        "biscuit_delegate_public_key_file": args.biscuit_delegate_public_key_file,
        "biscuit_delegate_bin": args.biscuit_delegate_bin,
        "biscuit_delegate_handoff": args.biscuit_delegate_handoff,
        "biscuit_delegate_handoff_topic": handoff_topic(args),
        "biscuit_delegate_handoff_nonce": handoff_nonce,
        "control": {
            "topic": args.control_topic,
            "mode": args.control_mode,
            "payload": args.control_payload,
            "repeat": args.control_repeat,
            "qos": args.control_qos,
            "after_messages": args.control_after_messages,
        },
        "fanout_churn": {
            "kind": args.fanout_churn_kind,
            "after_messages": args.fanout_churn_after_messages,
            "interval_messages": args.fanout_churn_interval_messages,
            "max_events": args.fanout_churn_max_events,
            "settle_ms": args.fanout_churn_settle_ms,
            "dynamic_security_source": args.fanout_churn_dynamic_security_source,
            "control_topic": args.fanout_churn_control_topic,
            "control_payload": args.fanout_churn_control_payload,
            "sqlite_db": args.fanout_churn_sqlite_db,
            "sqlite_topic": args.fanout_churn_sqlite_topic,
            "sqlite_subscribers": args.fanout_churn_sqlite_subscribers,
        },
    })
}

fn fanout_churn_json(
    args: &Args,
    mode: &str,
    state: Option<&FanoutChurnState>,
    received_pre_churn: Option<usize>,
    received_post_churn: Option<usize>,
) -> Value {
    let enabled = mode == "fanout" && args.fanout_churn_kind.is_some();
    let triggered = state.is_some_and(|state| state.triggered);
    let applied_events = state.map_or(0, |state| state.applied_events);
    let expected_pre = if enabled {
        Some(args.messages.min(args.fanout_churn_after_messages) * args.clients)
    } else {
        None
    };
    let expected_post = if enabled {
        Some(
            args.messages
                .saturating_sub(args.fanout_churn_after_messages)
                * args.clients,
        )
    } else {
        None
    };
    let post_ratio = match (received_post_churn, expected_post) {
        (Some(received), Some(expected)) if expected > 0 => {
            Some(usize_as_f64(received) / usize_as_f64(expected))
        }
        _ => None,
    };
    let cache_validity = match (expected_post, received_post_churn) {
        (Some(expected), Some(received)) => Some(triggered && received < expected),
        _ => None,
    };
    serde_json::json!({
        "enabled": enabled,
        "kind": if mode == "fanout" { args.fanout_churn_kind.clone() } else { None },
        "after_messages": if mode == "fanout" { Some(args.fanout_churn_after_messages) } else { None },
        "interval_messages": if mode == "fanout" { Some(args.fanout_churn_interval_messages) } else { None },
        "max_events": if mode == "fanout" { Some(args.fanout_churn_max_events) } else { None },
        "settle_ms": if mode == "fanout" { Some(args.fanout_churn_settle_ms) } else { None },
        "triggered": if mode == "fanout" { Some(triggered) } else { None },
        "applied_events": if mode == "fanout" { Some(applied_events) } else { None },
        "received_pre_churn": if mode == "fanout" { received_pre_churn.map_or(Value::Null, Value::from) } else { Value::Null },
        "received_post_churn": if mode == "fanout" { received_post_churn.map_or(Value::Null, Value::from) } else { Value::Null },
        "expected_pre_churn": if mode == "fanout" { expected_pre.map_or(Value::Null, Value::from) } else { Value::Null },
        "expected_post_churn": if mode == "fanout" { expected_post.map_or(Value::Null, Value::from) } else { Value::Null },
        "post_churn_delivery_ratio": if mode == "fanout" { post_ratio.map_or(Value::Null, Value::from) } else { Value::Null },
        "cache_validity_signal": if mode == "fanout" { cache_validity.map_or(Value::Null, Value::from) } else { Value::Null },
    })
}

fn percentile_ratio(sorted: &[f64], numerator: usize, denominator: usize) -> f64 {
    let rank_numerator = numerator.saturating_mul(sorted.len() - 1);
    let lo = rank_numerator / denominator;
    let remainder = rank_numerator % denominator;
    if remainder == 0 {
        return sorted[lo];
    }

    let hi = lo + 1;
    let weight = usize_as_f64(remainder) / usize_as_f64(denominator);
    (sorted[hi] - sorted[lo]).mul_add(weight, sorted[lo])
}

fn summarize(values: &[f64]) -> Summary {
    if values.is_empty() {
        return Summary::default();
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let sum = sorted.iter().sum::<f64>();
    Summary {
        count: sorted.len(),
        min_ms: sorted.first().copied(),
        p50_ms: Some(percentile_ratio(&sorted, 50, 100)),
        p95_ms: Some(percentile_ratio(&sorted, 95, 100)),
        p99_ms: Some(percentile_ratio(&sorted, 99, 100)),
        max_ms: sorted.last().copied(),
        mean_ms: Some(sum / usize_as_f64(sorted.len())),
        median_ms: Some(percentile_ratio(&sorted, 50, 100)),
    }
}

async fn publish_and_wait(
    client: &rumqttc::AsyncClient,
    eventloop: &mut rumqttc::EventLoop,
    topic: &str,
    payload: Vec<u8>,
    qos_value: u8,
) -> Result<f64> {
    let start = Instant::now();
    client
        .publish(topic, qos(qos_value)?, false, payload)
        .await?;
    if qos_value == 0 {
        poll_until(eventloop, Duration::from_secs(10), |event| {
            matches!(event, Event::Outgoing(Outgoing::Publish(0))).then_some(())
        })
        .await?;
    } else {
        poll_until(eventloop, Duration::from_secs(10), |event| match event {
            Event::Incoming(Packet::PubAck(puback)) => {
                let _ = puback_reason_code(puback.reason);
                Some(())
            }
            Event::Incoming(Packet::PubComp(_)) => Some(()),
            _ => None,
        })
        .await?;
    }
    Ok(start.elapsed().as_secs_f64() * 1000.0)
}

async fn publish_with_retain_and_wait(
    client: &rumqttc::AsyncClient,
    eventloop: &mut rumqttc::EventLoop,
    topic: &str,
    payload: Vec<u8>,
    qos_value: u8,
    retain: bool,
) -> Result<f64> {
    let start = Instant::now();
    client
        .publish(topic, qos(qos_value)?, retain, payload)
        .await?;
    if qos_value == 0 {
        poll_until(eventloop, Duration::from_secs(10), |event| {
            matches!(event, Event::Outgoing(Outgoing::Publish(0))).then_some(())
        })
        .await?;
    } else {
        poll_until(eventloop, Duration::from_secs(10), |event| match event {
            Event::Incoming(Packet::PubAck(_) | Packet::PubComp(_)) => Some(()),
            _ => None,
        })
        .await?;
    }
    Ok(start.elapsed().as_secs_f64() * 1000.0)
}

async fn subscribe_and_wait(
    client: &rumqttc::AsyncClient,
    eventloop: &mut rumqttc::EventLoop,
    topic: &str,
    qos_value: u8,
) -> Result<Vec<u16>> {
    let notice = client.subscribe_tracked(topic, qos(qos_value)?).await?;
    let drive_eventloop = async {
        loop {
            let _ = eventloop.poll().await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), rumqttc::ConnectionError>(())
    };
    let suback = tokio::select! {
        result = notice.wait_async() => {
            result.map_err(|err| MqttHelperError::Message(format!("subscribe_failed:{err}")))?
        }
        result = drive_eventloop => {
            result?;
            return Err(MqttHelperError::Message("subscribe_eventloop_stopped".to_string()));
        }
        () = tokio::time::sleep(Duration::from_secs(10)) => {
            return Err(MqttHelperError::Message("subscribe_timeout".to_string()));
        }
    };
    Ok(suback
        .return_codes
        .into_iter()
        .map(gen_tokens::mqtt_helpers::subscribe_reason_code)
        .collect())
}

struct HandoffReceiver {
    client: rumqttc::AsyncClient,
    eventloop: rumqttc::EventLoop,
}

async fn subscribe_handoff_receiver(args: &Args, client_id: &str) -> Result<HandoffReceiver> {
    let topic = handoff_topic(args).ok_or_else(|| {
        MqttHelperError::Message("biscuit_delegate_handoff_topic is required".to_string())
    })?;
    let handoff_password = args
        .biscuit_delegate_handoff_token
        .as_deref()
        .map(decode_token_arg)
        .transpose()?
        .unwrap_or_else(|| decode_token_arg(&args.password).unwrap_or_default());
    let spec = ClientSpec {
        host: args.host.clone(),
        port: args.port,
        client_id: format!("handoff_{client_id}"),
        username: args.username.clone(),
        password: handoff_password,
        tls: args.tls,
        tls_ca_file: args.tls_ca_file.clone(),
        tls_insecure: args.tls_insecure,
        auth_method: None,
        auth_data: None,
    };
    let (client, mut eventloop, report) = connect(&spec).await.map_err(|err| {
        MqttHelperError::Message(format!("delegation_handoff_connect_failed:{err}"))
    })?;
    if !report.connect_ok {
        return Err(MqttHelperError::Message(format!(
            "delegation_handoff_connect_denied:{:?}",
            report.connect_reason
        )));
    }
    let codes = subscribe_and_wait(
        &client,
        &mut eventloop,
        &topic,
        args.biscuit_delegate_handoff_qos,
    )
    .await
    .map_err(|err| {
        MqttHelperError::Message(format!("delegation_handoff_subscribe_failed:{err}"))
    })?;
    if !codes.iter().all(|code| matches!(code, 0..=2)) {
        return Err(MqttHelperError::Message(format!(
            "delegation_handoff_subscribe_rc:{}",
            codes
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )));
    }
    Ok(HandoffReceiver { client, eventloop })
}

async fn wait_for_handoff_token(
    mut receiver: HandoffReceiver,
    client_id: &str,
    nonce: &str,
) -> Result<Vec<u8>> {
    let password = poll_until(
        &mut receiver.eventloop,
        Duration::from_secs(10),
        |event| match event {
            Event::Incoming(Packet::Publish(publish)) => {
                let parsed = serde_json::from_slice::<HandoffPayload>(&publish.payload).ok()?;
                if parsed.client_id != client_id || parsed.nonce != nonce {
                    return None;
                }
                let padding = "=".repeat((4 - parsed.token.len() % 4) % 4);
                general_purpose::URL_SAFE
                    .decode(format!("{}{padding}", parsed.token))
                    .ok()
            }
            _ => None,
        },
    )
    .await
    .map_err(|err| MqttHelperError::Message(format!("delegation_handoff_timeout:{err}")))?;
    let _ = receiver.client.disconnect().await;
    Ok(password)
}

async fn receive_handoff_token(args: &Args, client_id: &str, nonce: &str) -> Result<Vec<u8>> {
    let receiver = subscribe_handoff_receiver(args, client_id).await?;
    wait_for_handoff_token(receiver, client_id, nonce).await
}

async fn receive_handoff_tokens(
    args: &Args,
    plan: &HandoffPlan,
) -> (HashMap<String, Vec<u8>>, Vec<String>) {
    let mut tasks = Vec::new();
    let mut errors = Vec::new();
    for client_id in plan.tokens.keys() {
        match subscribe_handoff_receiver(args, client_id).await {
            Ok(receiver) => {
                let client_id = client_id.clone();
                let nonce = plan.nonce.clone();
                tasks.push(tokio::spawn(async move {
                    let result = wait_for_handoff_token(receiver, &client_id, &nonce).await;
                    (client_id, result)
                }));
            }
            Err(err) => errors.push(format!(
                "delegation_handoff_subscribe_failed:{client_id}:{err}"
            )),
        }
    }
    errors.extend(publish_handoff_tokens(args, &plan.nonce, &plan.tokens).await);
    let mut passwords = HashMap::new();
    for task in tasks {
        match task.await {
            Ok((client_id, Ok(password))) => {
                passwords.insert(client_id, password);
            }
            Ok((client_id, Err(err))) => {
                errors.push(format!("delegation_handoff_failed:{client_id}:{err}"));
            }
            Err(err) => errors.push(format!("delegation_handoff_join_failed:{err}")),
        }
    }
    (passwords, errors)
}

async fn publish_handoff_tokens(
    args: &Args,
    nonce: &str,
    tokens: &HashMap<String, String>,
) -> Vec<String> {
    let Some(topic) = handoff_topic(args) else {
        return vec!["biscuit_delegate_handoff_topic is required".to_string()];
    };
    let password = match args
        .biscuit_delegate_handoff_token
        .as_deref()
        .map(decode_token_arg)
        .transpose()
    {
        Ok(Some(password)) => password,
        Ok(None) => match decode_token_arg(&args.password) {
            Ok(password) => password,
            Err(err) => return vec![format!("delegation_master_password_failed:{err}")],
        },
        Err(err) => return vec![format!("delegation_master_password_failed:{err}")],
    };
    let spec = ClientSpec {
        host: args.host.clone(),
        port: args.port,
        client_id: "delegation_handoff_master".to_string(),
        username: args.username.clone(),
        password,
        tls: args.tls,
        tls_ca_file: args.tls_ca_file.clone(),
        tls_insecure: args.tls_insecure,
        auth_method: None,
        auth_data: None,
    };
    let Ok((client, mut eventloop, report)) = connect(&spec).await else {
        return vec!["delegation_master_connect_failed".to_string()];
    };
    let mut errors = Vec::new();
    if !report.connect_ok {
        errors.push(format!(
            "delegation_master_connect_denied:{:?}",
            report.connect_reason
        ));
        return errors;
    }
    for (client_id, token) in tokens {
        let payload = HandoffPayload {
            client_id: client_id.clone(),
            token: token.clone(),
            nonce: nonce.to_string(),
        };
        let publish_result = match serde_json::to_vec(&payload) {
            Ok(bytes) => {
                publish_with_retain_and_wait(
                    &client,
                    &mut eventloop,
                    &topic,
                    bytes,
                    args.biscuit_delegate_handoff_qos,
                    handoff_retain(args),
                )
                .await
            }
            Err(err) => Err(MqttHelperError::from(err)),
        };
        match publish_result {
            Ok(_) => {}
            Err(err) => errors.push(format!("delegation_master_publish_failed:{err}")),
        }
    }
    let _ = client.disconnect().await;
    errors
}

struct FanoutSubscriber {
    eventloop: rumqttc::EventLoop,
    result: WorkerResult,
}

struct FanoutPreparedClient {
    client_id: String,
    password: Vec<u8>,
    bootstrap: WorkerBootstrap,
}

struct FanoutRuntime {
    handoff_plan: Option<HandoffPlan>,
    handoff_passwords: HashMap<String, Vec<u8>>,
    errors: Vec<String>,
    handoff_required: bool,
}

struct FanoutMetrics {
    connect: Vec<f64>,
    delegation: Vec<f64>,
    delegation_len: Vec<f64>,
    attenuation: Vec<f64>,
    attenuation_len: Vec<f64>,
    receive: Vec<f64>,
    received_pre: Option<usize>,
    received_post: Option<usize>,
    publish_throughput_mps: f64,
    receive_throughput_mps: f64,
}

struct FanoutOutputParts<'a> {
    qos_distribution: Option<&'a QosDistribution>,
    token_refresh_codes: &'a [u16],
    runtime: FanoutRuntime,
    fanout_publish_ms: Vec<f64>,
    fanout_publish_by_qos: &'a [Vec<f64>; 3],
    churn_state: &'a FanoutChurnState,
    metrics: &'a FanoutMetrics,
}

struct WorkerPublishPlan<'a> {
    topic: &'a str,
    control_topic: Option<&'a str>,
    control_payload: &'a [u8],
    data_payload: &'a [u8],
    qos_distribution: Option<&'a QosDistribution>,
}

async fn collect_fanout_subscriber(
    mut subscriber: FanoutSubscriber,
    start: Instant,
    expected_messages: usize,
    churn_after_messages: usize,
    publishing_done: Arc<AtomicBool>,
) -> WorkerResult {
    let drain_timeout = Duration::from_secs(10).max(Duration::from_millis(
        u64::try_from(expected_messages)
            .unwrap_or(u64::MAX)
            .saturating_mul(200),
    ));
    let mut drain_deadline = None;
    while subscriber.result.receive_ms.len() < expected_messages {
        if publishing_done.load(Ordering::Acquire) {
            let deadline = drain_deadline.get_or_insert_with(|| Instant::now() + drain_timeout);
            if Instant::now() >= *deadline {
                break;
            }
        }
        let Ok(event) =
            tokio::time::timeout(Duration::from_millis(100), subscriber.eventloop.poll()).await
        else {
            continue;
        };
        match event {
            Ok(Event::Incoming(Packet::Publish(publish))) => {
                let payload = publish.payload;
                if let Some(pos) = payload.iter().position(|byte| *byte == b'|') {
                    let sequence_id = payload
                        .iter()
                        .skip(pos + 1)
                        .position(|byte| *byte == b'|')
                        .and_then(|end| {
                            std::str::from_utf8(&payload[pos + 1..pos + 1 + end])
                                .ok()
                                .and_then(|raw| raw.parse::<usize>().ok())
                        });
                    if let Ok(sent) = std::str::from_utf8(&payload[..pos])
                        .unwrap_or_default()
                        .parse::<f64>()
                    {
                        let elapsed = (start.elapsed().as_secs_f64() - sent) * 1000.0;
                        subscriber.result.receive_ms.push(elapsed.max(0.0));
                        if let Some(sequence_id) = sequence_id {
                            if sequence_id < churn_after_messages {
                                subscriber.result.receive_pre_churn += 1;
                            } else {
                                subscriber.result.receive_post_churn += 1;
                            }
                        }
                    } else {
                        subscriber.result.receive_ms.push(0.0);
                    }
                } else {
                    subscriber.result.receive_ms.push(0.0);
                }
            }
            Ok(_) => {}
            Err(err) => {
                subscriber
                    .result
                    .errors
                    .push(format!("receive_failed:{err}"));
                break;
            }
        }
    }
    subscriber.result
}

async fn init_fanout_runtime(args: &Args) -> FanoutRuntime {
    let handoff_plan = prepare_handoff(args, &args.fanout_topic).await;
    let handoff_required = handoff_plan.is_some();
    let mut errors = Vec::new();
    if let Some(plan) = &handoff_plan {
        errors.extend(plan.errors.clone());
    }
    let mut handoff_passwords = HashMap::new();
    if let Some(plan) = &handoff_plan {
        let (passwords, handoff_errors) = receive_handoff_tokens(args, plan).await;
        handoff_passwords = passwords;
        errors.extend(handoff_errors);
    }
    FanoutRuntime {
        handoff_plan,
        handoff_passwords,
        errors,
        handoff_required,
    }
}

async fn prepare_fanout_client(
    args: &Args,
    client_id: String,
    runtime: &mut FanoutRuntime,
) -> Option<FanoutPreparedClient> {
    let mut bootstrap = runtime
        .handoff_plan
        .as_ref()
        .and_then(|plan| plan.workers.get(&client_id).cloned())
        .unwrap_or_default();
    let password = if let Some(password) = runtime.handoff_passwords.remove(&client_id) {
        password
    } else if runtime.handoff_required {
        runtime.errors.push(format!(
            "delegation_handoff_failed:{client_id}:delegation_handoff_missing_token"
        ));
        return None;
    } else {
        let mut password = match startup_password(args, &client_id, &args.fanout_topic).await {
            Ok(password) => password,
            Err(err) => {
                runtime
                    .errors
                    .push(format!("startup_provisioning_failed:{client_id}:{err}"));
                return None;
            }
        };
        let mut worker_result = WorkerResult::default();
        if !apply_biscuit_transforms(args, &client_id, &mut worker_result, &mut password) {
            runtime.errors.extend(worker_result.errors);
            return None;
        }
        bootstrap.delegation_ms = worker_result.delegation_ms;
        bootstrap.delegation_len = worker_result.delegation_len;
        bootstrap.attenuation_ms = worker_result.attenuation_ms;
        bootstrap.attenuation_len = worker_result.attenuation_len;
        password
    };
    Some(FanoutPreparedClient {
        client_id,
        password,
        bootstrap,
    })
}

async fn connect_fanout_subscriber(
    args: &Args,
    prepared: FanoutPreparedClient,
    subscribe_qos: u8,
) -> Result<(FanoutSubscriber, bool)> {
    let spec = ClientSpec {
        host: args.host.clone(),
        port: args.port,
        client_id: prepared.client_id.clone(),
        username: args.username.clone(),
        password: prepared.password,
        tls: args.tls,
        tls_ca_file: args.tls_ca_file.clone(),
        tls_insecure: args.tls_insecure,
        auth_method: None,
        auth_data: None,
    };
    let (client, mut eventloop, report) = connect(&spec).await?;
    let mut result = WorkerResult {
        connect_ms: Some(report.connect_ms),
        delegation_ms: prepared.bootstrap.delegation_ms,
        delegation_len: prepared.bootstrap.delegation_len,
        attenuation_ms: prepared.bootstrap.attenuation_ms,
        attenuation_len: prepared.bootstrap.attenuation_len,
        ..WorkerResult::default()
    };
    if !report.connect_ok {
        result
            .errors
            .push(format!("connect_denied:{:?}", report.connect_reason));
        return Ok((FanoutSubscriber { eventloop, result }, false));
    }
    match subscribe_and_wait(&client, &mut eventloop, &args.fanout_topic, subscribe_qos).await {
        Ok(codes) if codes.iter().all(|code| matches!(code, 0..=2)) => {
            Ok((FanoutSubscriber { eventloop, result }, true))
        }
        Ok(codes) => {
            result.errors.push(format!(
                "fanout_suback_rejected:{}",
                codes
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ));
            Ok((FanoutSubscriber { eventloop, result }, false))
        }
        Err(err) => {
            result.errors.push(format!("subscribe_failed:{err}"));
            Ok((FanoutSubscriber { eventloop, result }, false))
        }
    }
}

async fn build_fanout_subscribers(
    args: &Args,
    runtime: &mut FanoutRuntime,
    subscribe_qos: u8,
) -> Vec<FanoutSubscriber> {
    let mut subscribers = Vec::new();
    for index in 0..args.clients {
        let client_id = format!("client_{}", index + 1);
        let Some(prepared) = prepare_fanout_client(args, client_id.clone(), runtime).await else {
            continue;
        };
        match connect_fanout_subscriber(args, prepared, subscribe_qos).await {
            Ok((subscriber, _)) => subscribers.push(subscriber),
            Err(err) => runtime
                .errors
                .push(format!("connect_failed:{client_id}:{err}")),
        }
    }
    subscribers
}

fn count_ready_fanout_subscribers(subscribers: &[FanoutSubscriber]) -> usize {
    subscribers
        .iter()
        .filter(|subscriber| subscriber.result.errors.is_empty())
        .count()
}

async fn publish_fanout(
    args: &Args,
    start: Instant,
    publisher: &AsyncClient,
    publisher_eventloop: &mut rumqttc::EventLoop,
    qos_distribution: Option<&QosDistribution>,
    errors: &mut Vec<String>,
) -> (Vec<f64>, [Vec<f64>; 3], FanoutChurnState) {
    let mut fanout_publish_ms = Vec::new();
    let mut fanout_publish_by_qos: [Vec<f64>; 3] = Default::default();
    let mut churn_state = FanoutChurnState::default();
    for sequence_id in 0..args.messages {
        if should_apply_churn(args, sequence_id, &churn_state) {
            if let Some(err) = apply_fanout_churn(args, publisher, publisher_eventloop).await {
                errors.push(err);
            } else {
                churn_state.triggered = true;
                churn_state.applied_events += 1;
            }
        }
        let publish_qos = qos_distribution.map_or(args.qos, QosDistribution::choose);
        let sent = start.elapsed().as_secs_f64();
        let mut payload = format!("{sent:.9}|{sequence_id}|").into_bytes();
        if args.message_size > payload.len() {
            payload.extend(vec![b'A'; args.message_size - payload.len()]);
        }
        match publish_and_wait(
            publisher,
            publisher_eventloop,
            &args.fanout_topic,
            payload,
            publish_qos,
        )
        .await
        {
            Ok(ms) => {
                fanout_publish_ms.push(ms);
                if let Some(bucket) = fanout_publish_by_qos.get_mut(usize::from(publish_qos)) {
                    bucket.push(ms);
                }
            }
            Err(err) => errors.push(format!("fanout_publish_failed:{err}")),
        }
    }
    (fanout_publish_ms, fanout_publish_by_qos, churn_state)
}

fn spawn_fanout_collectors(
    start: Instant,
    subscribers: Vec<FanoutSubscriber>,
    expected_messages: usize,
    churn_after_messages: usize,
    publishing_done: &Arc<AtomicBool>,
) -> Vec<tokio::task::JoinHandle<WorkerResult>> {
    let mut subscriber_tasks = Vec::new();
    for subscriber in subscribers {
        subscriber_tasks.push(tokio::spawn(collect_fanout_subscriber(
            subscriber,
            start,
            expected_messages,
            churn_after_messages,
            Arc::clone(publishing_done),
        )));
    }
    subscriber_tasks
}

async fn collect_fanout_results(
    subscriber_tasks: Vec<tokio::task::JoinHandle<WorkerResult>>,
) -> Vec<WorkerResult> {
    let mut results = Vec::new();
    for task in subscriber_tasks {
        match task.await {
            Ok(result) => results.push(result),
            Err(err) => {
                let mut result = WorkerResult::default();
                result
                    .errors
                    .push(format!("fanout_receive_join_failed:{err}"));
                results.push(result);
            }
        }
    }
    results
}

async fn connect_fanout_publisher(
    args: &Args,
    fallback_password: &[u8],
) -> Result<(AsyncClient, rumqttc::EventLoop)> {
    let publisher_username = args
        .fanout_publisher_username
        .clone()
        .unwrap_or_else(|| args.username.clone());
    let publisher_password = if let Some(password) = args.fanout_publisher_password.as_deref() {
        decode_token_arg(password)?
    } else if should_provision_fanout_publisher(args, &publisher_username)? {
        let kind = resolved_token_issuer_kind(args).ok_or_else(|| {
            MqttHelperError::Message(
                "strict multi-client startup provisioning requires token kind".to_string(),
            )
        })?;
        fetch_token(args, &kind, "fanout_publisher", &args.fanout_topic).await?
    } else {
        fallback_password.to_vec()
    };
    let publisher_spec = ClientSpec {
        host: args.host.clone(),
        port: args.port,
        client_id: "fanout_publisher".to_string(),
        username: publisher_username,
        password: publisher_password,
        tls: args.tls,
        tls_ca_file: args.tls_ca_file.clone(),
        tls_insecure: args.tls_insecure,
        auth_method: None,
        auth_data: None,
    };
    let (publisher, publisher_eventloop, _report) = connect(&publisher_spec).await?;
    Ok((publisher, publisher_eventloop))
}

fn fanout_metrics(
    results: &[WorkerResult],
    fanout_publish_ms: &[f64],
    duration_s: f64,
    churn_enabled: bool,
) -> FanoutMetrics {
    let receive: Vec<_> = results.iter().flat_map(|r| r.receive_ms.clone()).collect();
    FanoutMetrics {
        connect: results.iter().filter_map(|r| r.connect_ms).collect(),
        delegation: results.iter().filter_map(|r| r.delegation_ms).collect(),
        delegation_len: results.iter().filter_map(|r| r.delegation_len).collect(),
        attenuation: results.iter().filter_map(|r| r.attenuation_ms).collect(),
        attenuation_len: results.iter().filter_map(|r| r.attenuation_len).collect(),
        received_pre: churn_enabled.then(|| results.iter().map(|r| r.receive_pre_churn).sum()),
        received_post: churn_enabled.then(|| results.iter().map(|r| r.receive_post_churn).sum()),
        publish_throughput_mps: usize_as_f64(fanout_publish_ms.len()) / duration_s,
        receive_throughput_mps: usize_as_f64(receive.len()) / duration_s,
        receive,
    }
}

fn fanout_output(args: &Args, parts: FanoutOutputParts<'_>) -> Output {
    let metrics = parts.metrics;
    Output {
        inputs: inputs_json(
            args,
            "fanout",
            parts.qos_distribution,
            parts.token_refresh_codes,
            parts
                .runtime
                .handoff_plan
                .as_ref()
                .map(|plan| plan.nonce.as_str()),
        ),
        connect: summarize(&metrics.connect),
        token_refresh: Summary::default(),
        token_refresh_len: Summary::default(),
        delegation: summarize(&metrics.delegation),
        delegation_len: summarize(&metrics.delegation_len),
        attenuation: summarize(&metrics.attenuation),
        attenuation_len: summarize(&metrics.attenuation_len),
        publish: summarize(&parts.fanout_publish_ms),
        publish_qos_0: summarize(&parts.fanout_publish_by_qos[0]),
        publish_qos_1: summarize(&parts.fanout_publish_by_qos[1]),
        publish_qos_2: summarize(&parts.fanout_publish_by_qos[2]),
        qos_distribution_actual: serde_json::json!({
            "qos_0_count": parts.fanout_publish_by_qos[0].len(),
            "qos_1_count": parts.fanout_publish_by_qos[1].len(),
            "qos_2_count": parts.fanout_publish_by_qos[2].len(),
        }),
        receive: summarize(&metrics.receive),
        control: Summary::default(),
        control_injection_delay: Summary::default(),
        throughput_mps: metrics.receive_throughput_mps,
        publish_throughput_mps: metrics.publish_throughput_mps,
        receive_throughput_mps: metrics.receive_throughput_mps,
        received_messages: serde_json::json!({
            "count": metrics.receive.len(),
            "expected": args.messages * args.clients,
        }),
        fanout_churn: fanout_churn_json(
            args,
            "fanout",
            Some(parts.churn_state),
            metrics.received_pre,
            metrics.received_post,
        ),
        raw_publish_ms: parts.fanout_publish_ms,
        errors: parts.runtime.errors,
    }
}

async fn run_fanout(args: Args) -> Result<Output> {
    let start = Instant::now();
    let mut runtime = init_fanout_runtime(&args).await;
    let fallback_password = decode_token_arg(&args.password)?;
    let qos_distribution = QosDistribution::parse(args.qos_distribution.as_deref())?;
    let subscribe_qos = qos_distribution
        .as_ref()
        .map_or(args.qos, QosDistribution::subscribe_qos);
    let token_refresh_codes = parse_token_refresh_codes(args.token_refresh_codes.as_deref())?;
    let mut subscribers = build_fanout_subscribers(&args, &mut runtime, subscribe_qos).await;
    let ready_subscribers = count_ready_fanout_subscribers(&subscribers);
    let fanout_ready = ready_subscribers == args.clients;
    if !fanout_ready {
        runtime
            .errors
            .push("fanout_subscribe_ready_timeout".to_string());
    }
    let (publisher, mut publisher_eventloop) =
        connect_fanout_publisher(&args, &fallback_password).await?;
    let publishing_done = Arc::new(AtomicBool::new(false));
    let subscriber_tasks = if fanout_ready {
        Some(spawn_fanout_collectors(
            start,
            std::mem::take(&mut subscribers),
            args.messages,
            args.fanout_churn_after_messages,
            &publishing_done,
        ))
    } else {
        None
    };
    let (fanout_publish_ms, fanout_publish_by_qos, churn_state) = if fanout_ready {
        publish_fanout(
            &args,
            start,
            &publisher,
            &mut publisher_eventloop,
            qos_distribution.as_ref(),
            &mut runtime.errors,
        )
        .await
    } else {
        (Vec::new(), Default::default(), FanoutChurnState::default())
    };
    publishing_done.store(true, Ordering::Release);
    let _ = publisher.disconnect().await;
    let mut results = if let Some(subscriber_tasks) = subscriber_tasks {
        collect_fanout_results(subscriber_tasks).await
    } else {
        subscribers.into_iter().map(|sub| sub.result).collect()
    };
    let duration_s = start.elapsed().as_secs_f64().max(1e-9);
    for result in &mut results {
        runtime.errors.append(&mut result.errors);
    }
    let metrics = fanout_metrics(
        &results,
        &fanout_publish_ms,
        duration_s,
        args.fanout_churn_kind.is_some(),
    );
    Ok(fanout_output(
        &args,
        FanoutOutputParts {
            qos_distribution: qos_distribution.as_ref(),
            token_refresh_codes: &token_refresh_codes,
            runtime,
            fanout_publish_ms,
            fanout_publish_by_qos: &fanout_publish_by_qos,
            churn_state: &churn_state,
            metrics: &metrics,
        },
    ))
}

async fn resolve_worker_password(
    args: &Args,
    client_id: &str,
    topic: &str,
    handoff_nonce: Option<&str>,
    handoff_password: Option<Vec<u8>>,
    handoff_required: bool,
    result: &mut WorkerResult,
) -> Option<(Vec<u8>, bool)> {
    let handoff_password_supplied = handoff_password.is_some();
    let password = if let Some(value) = handoff_password {
        value
    } else if let Some(nonce) = handoff_nonce {
        match receive_handoff_token(args, client_id, nonce).await {
            Ok(value) => value,
            Err(err) => {
                result
                    .errors
                    .push(format!("delegation_handoff_failed:{err}"));
                return None;
            }
        }
    } else if handoff_required {
        result
            .errors
            .push("delegation_handoff_failed:delegation_handoff_missing_token".to_string());
        return None;
    } else {
        match startup_password(args, client_id, topic).await {
            Ok(value) => value,
            Err(err) => {
                result.errors.push(format!("startup_password_failed:{err}"));
                return None;
            }
        }
    };
    Some((password, handoff_password_supplied))
}

fn worker_specs(args: &Args, client_id: &str, password: Vec<u8>) -> ClientSpec {
    ClientSpec {
        host: args.host.clone(),
        port: args.port,
        client_id: client_id.to_string(),
        username: args.username.clone(),
        password,
        tls: args.tls,
        tls_ca_file: args.tls_ca_file.clone(),
        tls_insecure: args.tls_insecure,
        auth_method: None,
        auth_data: None,
    }
}

async fn connect_worker(
    args: &Args,
    client_id: &str,
    topic: &str,
    token_refresh_codes: &[u16],
    spec: &mut ClientSpec,
    result: &mut WorkerResult,
) -> Option<(AsyncClient, rumqttc::EventLoop, ConnectReport)> {
    loop {
        let connect_result = match connect(spec).await {
            Ok(value) => value,
            Err(err) => {
                result.errors.push(format!("connect_failed:{err}"));
                return None;
            }
        };
        if connect_result.2.connect_ok {
            return Some(connect_result);
        }

        let reason = connect_result.2.connect_reason.unwrap_or(u16::MAX);
        result.connect_ms = Some(connect_result.2.connect_ms);
        if result.token_refresh_ms.is_some()
            || !token_refresh_codes.contains(&reason)
            || args.token_issuer_url.is_none()
        {
            result.errors.push(format!("connect_denied:{reason:?}"));
            return None;
        }
        let Some(kind) = resolved_token_issuer_kind(args) else {
            result.errors.push(format!("connect_denied:{reason:?}"));
            return None;
        };
        let started = Instant::now();
        match fetch_token(args, &kind, client_id, topic).await {
            Ok(refreshed) => {
                result.token_refresh_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
                result.token_refresh_len = Some(usize_as_f64(refreshed.len()));
                spec.password = refreshed;
            }
            Err(err) => {
                result.errors.push(format!("token_refresh_failed:{err}"));
                return None;
            }
        }
    }
}

async fn run_control_mode(
    args: &Args,
    client: &AsyncClient,
    eventloop: &mut rumqttc::EventLoop,
    control_topic: Option<&str>,
    control_payload: &[u8],
    result: &mut WorkerResult,
) {
    if let Some(topic) = control_topic {
        for _ in 0..args.control_repeat {
            match publish_and_wait(
                client,
                eventloop,
                topic,
                control_payload.to_vec(),
                args.control_qos,
            )
            .await
            {
                Ok(ms) => result.control_ms.push(ms),
                Err(err) => result.errors.push(format!("control_publish_failed:{err}")),
            }
        }
    }
}

async fn run_publish_mode(
    args: &Args,
    client: &AsyncClient,
    eventloop: &mut rumqttc::EventLoop,
    plan: WorkerPublishPlan<'_>,
    result: &mut WorkerResult,
) {
    let mut since_control = 0usize;
    for _ in 0..args.messages {
        if args.control_after_messages > 0 && since_control >= args.control_after_messages {
            if let Some(topic) = plan.control_topic {
                let start = Instant::now();
                match publish_and_wait(
                    client,
                    eventloop,
                    topic,
                    plan.control_payload.to_vec(),
                    args.control_qos,
                )
                .await
                {
                    Ok(ms) => result.control_ms.push(ms),
                    Err(err) => result.errors.push(format!("control_publish_failed:{err}")),
                }
                result
                    .control_injection_ms
                    .push(start.elapsed().as_secs_f64() * 1000.0);
            }
            since_control = 0;
        }
        let publish_qos = plan
            .qos_distribution
            .map_or(args.qos, QosDistribution::choose);
        match publish_and_wait(
            client,
            eventloop,
            plan.topic,
            plan.data_payload.to_vec(),
            publish_qos,
        )
        .await
        {
            Ok(ms) => {
                result.publish_ms.push(ms);
                if let Some(bucket) = result.publish_by_qos.get_mut(usize::from(publish_qos)) {
                    bucket.push(ms);
                }
            }
            Err(err) => {
                result.errors.push(format!("publish_failed:{err}"));
                break;
            }
        }
        since_control += 1;
    }
}

async fn run_worker_session(
    args: &Args,
    client_id: &str,
    topic: &str,
    qos_distribution: Option<&QosDistribution>,
    client: &AsyncClient,
    eventloop: &mut rumqttc::EventLoop,
    result: &mut WorkerResult,
) {
    let control_topic = args
        .control_topic
        .as_deref()
        .map(|topic| expand_client_template(topic, client_id));
    let control_payload = expand_control_payload(&load_control_payload(args, result), client_id);
    let data_payload = vec![b'A'; args.message_size];
    if args.control_mode {
        run_control_mode(
            args,
            client,
            eventloop,
            control_topic.as_deref(),
            &control_payload,
            result,
        )
        .await;
    } else {
        run_publish_mode(
            args,
            client,
            eventloop,
            WorkerPublishPlan {
                topic,
                control_topic: control_topic.as_deref(),
                control_payload: &control_payload,
                data_payload: &data_payload,
                qos_distribution,
            },
            result,
        )
        .await;
    }
}

async fn run_worker(job: WorkerInvocation) -> WorkerResult {
    let WorkerInvocation {
        args,
        index,
        bootstrap,
        handoff_nonce,
        handoff_password,
        handoff_required,
        sync_connect,
        publish_gate,
    } = job;
    let mut result = WorkerResult::default();
    let mut publish_gate_participant = PublishGateParticipant::new(publish_gate);
    let client_id = format!("client_{}", index + 1);
    let topic = expand_client_template(&args.topic, &client_id);
    result.delegation_ms = bootstrap.delegation_ms;
    result.delegation_len = bootstrap.delegation_len;
    result.attenuation_ms = bootstrap.attenuation_ms;
    result.attenuation_len = bootstrap.attenuation_len;
    let Some((mut password, handoff_password_supplied)) = resolve_worker_password(
        &args,
        &client_id,
        &topic,
        handoff_nonce.as_deref(),
        handoff_password,
        handoff_required,
        &mut result,
    )
    .await
    else {
        return result;
    };
    let token_refresh_codes = match parse_token_refresh_codes(args.token_refresh_codes.as_deref()) {
        Ok(codes) => codes,
        Err(err) => {
            result
                .errors
                .push(format!("token_refresh_codes_failed:{err}"));
            return result;
        }
    };
    let qos_distribution = match QosDistribution::parse(args.qos_distribution.as_deref()) {
        Ok(distribution) => distribution,
        Err(err) => {
            result.errors.push(format!("qos_distribution_failed:{err}"));
            return result;
        }
    };
    if should_apply_worker_biscuit_transforms(
        handoff_nonce.as_deref(),
        handoff_password_supplied,
        handoff_required,
    ) && !apply_biscuit_transforms(&args, &client_id, &mut result, &mut password)
    {
        return result;
    }
    let mut spec = worker_specs(&args, &client_id, password.clone());
    if let Some(sync_connect) = sync_connect {
        sync_connect.wait().await;
    }
    let Some((client, mut eventloop, report)) = connect_worker(
        &args,
        &client_id,
        &topic,
        &token_refresh_codes,
        &mut spec,
        &mut result,
    )
    .await
    else {
        return result;
    };
    result.connect_ms = Some(report.connect_ms);

    if let Some(gate) = publish_gate_participant.mark_ready() {
        gate.wait_released().await;
    }

    run_worker_session(
        &args,
        &client_id,
        &topic,
        qos_distribution.as_ref(),
        &client,
        &mut eventloop,
        &mut result,
    )
    .await;
    let _ = client.disconnect().await;
    result
}

async fn collect_worker_results(
    tasks: Vec<tokio::task::JoinHandle<WorkerResult>>,
) -> Vec<WorkerResult> {
    let mut results = Vec::new();
    for task in tasks {
        match task.await {
            Ok(result) => results.push(result),
            Err(err) => {
                let mut result = WorkerResult::default();
                result.errors.push(format!("worker_join_failed:{err}"));
                results.push(result);
            }
        }
    }
    results
}

fn standard_metrics(
    results: Vec<WorkerResult>,
    duration_s: f64,
    handoff_plan: Option<&HandoffPlan>,
    handoff_errors: Vec<String>,
) -> StandardMetrics {
    let connect = results.iter().filter_map(|r| r.connect_ms).collect();
    let token_refresh = results.iter().filter_map(|r| r.token_refresh_ms).collect();
    let token_refresh_len = results.iter().filter_map(|r| r.token_refresh_len).collect();
    let delegation = results.iter().filter_map(|r| r.delegation_ms).collect();
    let delegation_len = results.iter().filter_map(|r| r.delegation_len).collect();
    let attenuation = results.iter().filter_map(|r| r.attenuation_ms).collect();
    let attenuation_len = results.iter().filter_map(|r| r.attenuation_len).collect();
    let publish: Vec<_> = results.iter().flat_map(|r| r.publish_ms.clone()).collect();
    let publish_qos_0 = results
        .iter()
        .flat_map(|r| r.publish_by_qos[0].clone())
        .collect();
    let publish_qos_1 = results
        .iter()
        .flat_map(|r| r.publish_by_qos[1].clone())
        .collect();
    let publish_qos_2 = results
        .iter()
        .flat_map(|r| r.publish_by_qos[2].clone())
        .collect();
    let receive: Vec<_> = results.iter().flat_map(|r| r.receive_ms.clone()).collect();
    let control = results.iter().flat_map(|r| r.control_ms.clone()).collect();
    let control_injection = results
        .iter()
        .flat_map(|r| r.control_injection_ms.clone())
        .collect();
    let mut errors: Vec<_> = results.into_iter().flat_map(|r| r.errors).collect();
    if let Some(plan) = handoff_plan {
        errors.extend(plan.errors.clone());
    }
    errors.extend(handoff_errors);
    StandardMetrics {
        publish_throughput_mps: usize_as_f64(publish.len()) / duration_s,
        receive_throughput_mps: usize_as_f64(receive.len()) / duration_s,
        connect,
        token_refresh,
        token_refresh_len,
        delegation,
        delegation_len,
        attenuation,
        attenuation_len,
        publish,
        publish_qos_0,
        publish_qos_1,
        publish_qos_2,
        receive,
        control,
        control_injection,
        errors,
    }
}

fn standard_output(
    args: &Args,
    qos_distribution: Option<&QosDistribution>,
    token_refresh_codes: &[u16],
    handoff_nonce: Option<&str>,
    metrics: StandardMetrics,
) -> Output {
    Output {
        inputs: inputs_json(
            args,
            args.mode.as_str(),
            qos_distribution,
            token_refresh_codes,
            handoff_nonce,
        ),
        connect: summarize(&metrics.connect),
        token_refresh: summarize(&metrics.token_refresh),
        token_refresh_len: summarize(&metrics.token_refresh_len),
        delegation: summarize(&metrics.delegation),
        delegation_len: summarize(&metrics.delegation_len),
        attenuation: summarize(&metrics.attenuation),
        attenuation_len: summarize(&metrics.attenuation_len),
        publish: summarize(&metrics.publish),
        publish_qos_0: summarize(&metrics.publish_qos_0),
        publish_qos_1: summarize(&metrics.publish_qos_1),
        publish_qos_2: summarize(&metrics.publish_qos_2),
        qos_distribution_actual: serde_json::json!({
            "qos_0_count": metrics.publish_qos_0.len(),
            "qos_1_count": metrics.publish_qos_1.len(),
            "qos_2_count": metrics.publish_qos_2.len(),
        }),
        receive: summarize(&metrics.receive),
        control: summarize(&metrics.control),
        control_injection_delay: summarize(&metrics.control_injection),
        throughput_mps: if args.mode == "fanout" {
            metrics.receive_throughput_mps
        } else {
            metrics.publish_throughput_mps
        },
        publish_throughput_mps: metrics.publish_throughput_mps,
        receive_throughput_mps: metrics.receive_throughput_mps,
        received_messages: serde_json::json!({
            "count": metrics.receive.len(),
            "expected": if args.mode == "fanout" { args.messages * args.clients } else { 0 },
        }),
        fanout_churn: fanout_churn_json(args, args.mode.as_str(), None, None, None),
        raw_publish_ms: metrics.publish,
        errors: metrics.errors,
    }
}

async fn run_standard_mode(
    args: Args,
    qos_distribution: Option<QosDistribution>,
    token_refresh_codes: Vec<u16>,
) -> Result<()> {
    let handoff_plan = prepare_handoff(&args, &args.topic).await;
    let handoff_nonce = handoff_plan.as_ref().map(|plan| plan.nonce.clone());
    let handoff_required = handoff_plan.is_some();
    let mut handoff_errors = Vec::new();
    let mut handoff_passwords = HashMap::new();
    if let Some(plan) = &handoff_plan {
        let (passwords, errors) = receive_handoff_tokens(&args, plan).await;
        handoff_passwords = passwords;
        handoff_errors = errors;
    }
    let mut tasks = Vec::new();
    let sync_connect = args.sync_connect.then(|| Arc::new(SyncConnectGate::new()));
    let publish_gate = (!args.sync_connect).then(|| Arc::new(PublishStartGate::new(args.clients)));
    for index in 0..args.clients {
        let client_id = format!("client_{}", index + 1);
        let bootstrap = handoff_plan
            .as_ref()
            .and_then(|plan| plan.workers.get(&client_id).cloned())
            .unwrap_or_default();
        tasks.push(tokio::spawn(run_worker(WorkerInvocation {
            args: args.clone(),
            index,
            bootstrap,
            handoff_nonce: None,
            handoff_password: handoff_passwords.remove(&client_id),
            handoff_required,
            sync_connect: sync_connect.clone(),
            publish_gate: publish_gate.clone(),
        })));
    }

    let start = if let Some(publish_gate) = &publish_gate {
        publish_gate.wait_until_ready_or_unavailable().await;
        let start = Instant::now();
        publish_gate.release();
        start
    } else {
        let start = Instant::now();
        if let Some(sync_connect) = &sync_connect {
            tokio::time::sleep(SYNC_CONNECT_RELEASE_DELAY).await;
            sync_connect.release();
        }
        start
    };
    let results = collect_worker_results(tasks).await;
    let duration_s = start.elapsed().as_secs_f64().max(1e-9);
    let metrics = standard_metrics(results, duration_s, handoff_plan.as_ref(), handoff_errors);
    let output = standard_output(
        &args,
        qos_distribution.as_ref(),
        &token_refresh_codes,
        handoff_nonce.as_deref(),
        metrics,
    );
    print_json(&output)
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = Args::parse();
    apply_legacy_defaults(&mut args);
    validate_startup_provisioning(&args)?;
    let qos_distribution = QosDistribution::parse(args.qos_distribution.as_deref())?;
    let token_refresh_codes = parse_token_refresh_codes(args.token_refresh_codes.as_deref())?;
    if args.mode == "fanout" {
        let output = run_fanout(args).await?;
        return print_json(&output);
    }
    run_standard_mode(args, qos_distribution, token_refresh_codes).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    fn output_keys_for(args: &Args, mode: &str) -> Vec<String> {
        let distribution = QosDistribution::parse(args.qos_distribution.as_deref())
            .expect("qos distribution should parse");
        let refresh_codes = parse_token_refresh_codes(args.token_refresh_codes.as_deref())
            .expect("refresh codes should parse");
        let output = Output {
            inputs: inputs_json(args, mode, distribution.as_ref(), &refresh_codes, None),
            connect: Summary::default(),
            token_refresh: Summary::default(),
            token_refresh_len: Summary::default(),
            delegation: Summary::default(),
            delegation_len: Summary::default(),
            attenuation: Summary::default(),
            attenuation_len: Summary::default(),
            publish: Summary::default(),
            publish_qos_0: Summary::default(),
            publish_qos_1: Summary::default(),
            publish_qos_2: Summary::default(),
            qos_distribution_actual: serde_json::json!({
                "qos_0_count": 0,
                "qos_1_count": 0,
                "qos_2_count": 0,
            }),
            receive: Summary::default(),
            control: Summary::default(),
            control_injection_delay: Summary::default(),
            throughput_mps: 0.0,
            publish_throughput_mps: 0.0,
            receive_throughput_mps: 0.0,
            received_messages: serde_json::json!({"count": 0, "expected": 0}),
            fanout_churn: fanout_churn_json(args, mode, None, None, None),
            raw_publish_ms: Vec::new(),
            errors: Vec::new(),
        };
        let value = serde_json::to_value(output).expect("output should serialize");
        let mut keys = value
            .as_object()
            .expect("output should be an object")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();
        keys
    }

    fn env_for(arg_id: &str) -> Option<String> {
        Args::command()
            .get_arguments()
            .find(|arg| arg.get_id() == arg_id)
            .and_then(|arg| arg.get_env())
            .map(|env| env.to_string_lossy().into_owned())
    }

    #[test]
    fn parses_refresh_codes_with_hex_literals() {
        assert_eq!(
            parse_token_refresh_codes(Some("135,0x87, 0X04,135")).unwrap(),
            vec![4, 135]
        );
    }

    #[test]
    fn parses_and_normalizes_qos_distribution() {
        let distribution = QosDistribution::parse(Some("0:6,1:3,2:1"))
            .unwrap()
            .expect("distribution should be present");
        assert_eq!(distribution.subscribe_qos(), 2);
        assert_eq!(distribution.as_json()[0]["qos"], 0);
        assert!((distribution.as_json()[0]["weight"].as_f64().unwrap() - 0.6).abs() < 1e-12);
    }

    #[test]
    fn rejects_invalid_qos_distribution_values() {
        assert!(QosDistribution::parse(Some("3:1")).is_err());
        assert!(QosDistribution::parse(Some("1:0")).is_err());
    }

    #[test]
    fn expands_biscuit_transform_templates_per_client() {
        assert_eq!(
            expand_client_template("sensors/{client_id}/temp", "client_7"),
            "sensors/client_7/temp"
        );
        assert_eq!(
            expand_client_templates(
                &[
                    "publish:sensors/{client_id}/temp".to_string(),
                    r#"resource("sensors/{client_id}/temp")"#.to_string(),
                ],
                "client_7",
            ),
            vec![
                "publish:sensors/client_7/temp",
                r#"resource("sensors/client_7/temp")"#,
            ]
        );
    }

    #[test]
    fn expands_client_placeholders_recursively_in_control_payloads() {
        let payload = br#"{
            "commands": [{
                "command": "createRole",
                "rolename": "dynamic_role_{client_id}",
                "acls": [
                    {"topic": "test/{client_id}/#"},
                    {"topic": "metrics/{region}/#"}
                ]
            }],
            "metadata": [
                "{client_id}",
                {"owner": "{client_id}", "literal": "{}", "scoped": "metrics/{region}/#"}
            ]
        }"#;

        let expanded = expand_control_payload(payload, "client_7");
        let expanded: Value =
            serde_json::from_slice(&expanded).expect("expanded payload should remain JSON");

        assert_eq!(expanded["commands"][0]["rolename"], "dynamic_role_client_7");
        assert_eq!(
            expanded["commands"][0]["acls"][0]["topic"],
            "test/client_7/#"
        );
        assert_eq!(
            expanded["commands"][0]["acls"][1]["topic"],
            "metrics/{region}/#"
        );
        assert_eq!(expanded["metadata"][0], "client_7");
        assert_eq!(expanded["metadata"][1]["owner"], "client_7");
        assert_eq!(expanded["metadata"][1]["literal"], "{}");
        assert_eq!(expanded["metadata"][1]["scoped"], "metrics/{region}/#");
    }

    #[tokio::test]
    async fn sync_connect_gate_blocks_until_released() {
        let gate = Arc::new(SyncConnectGate::new());
        let worker_gate = Arc::clone(&gate);
        let mut worker = tokio::spawn(async move {
            worker_gate.wait().await;
        });

        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut worker)
                .await
                .is_err()
        );
        gate.release();
        worker.await.expect("worker should finish after release");
    }

    #[tokio::test]
    async fn publish_start_gate_waits_for_ready_and_unavailable_workers() {
        let gate = Arc::new(PublishStartGate::new(2));
        gate.mark_ready();

        assert!(
            tokio::time::timeout(
                Duration::from_millis(10),
                gate.wait_until_ready_or_unavailable()
            )
            .await
            .is_err()
        );

        gate.mark_unavailable();
        tokio::time::timeout(
            Duration::from_millis(10),
            gate.wait_until_ready_or_unavailable(),
        )
        .await
        .expect("gate should account for workers that cannot publish");
    }

    #[test]
    fn handoff_tokens_skip_worker_biscuit_transforms() {
        assert!(!should_apply_worker_biscuit_transforms(None, true, true));
        assert!(!should_apply_worker_biscuit_transforms(
            Some("nonce"),
            false,
            true
        ));
        assert!(!should_apply_worker_biscuit_transforms(None, false, true));
        assert!(should_apply_worker_biscuit_transforms(None, false, false));
    }

    #[test]
    fn publish_output_preserves_legacy_result_shape() {
        let args = Args::parse_from(["mqtt-loadgen", "--clients", "1", "--messages", "1"]);
        let keys = output_keys_for(&args, "publish");
        assert_eq!(
            keys,
            vec![
                "attenuation",
                "attenuation_len",
                "connect",
                "control",
                "control_injection_delay",
                "delegation",
                "delegation_len",
                "errors",
                "fanout_churn",
                "inputs",
                "publish",
                "publish_qos_0",
                "publish_qos_1",
                "publish_qos_2",
                "publish_throughput_mps",
                "qos_distribution_actual",
                "raw_publish_ms",
                "receive",
                "receive_throughput_mps",
                "received_messages",
                "throughput_mps",
                "token_refresh",
                "token_refresh_len",
            ]
        );
    }

    #[test]
    fn control_and_fanout_inputs_include_legacy_metadata() {
        let control_args = Args::parse_from([
            "mqtt-loadgen",
            "--control-mode",
            "--control-topic",
            "$CONTROL/dynamic-security/v1",
            "--token-refresh-codes",
            "0x87",
        ]);
        let control_inputs = inputs_json(&control_args, "publish", None, &[135], None);
        assert_eq!(control_inputs["control"]["mode"], true);
        assert_eq!(control_inputs["biscuit_transform_mode"], "in_process");
        assert_eq!(
            control_inputs["token_refresh_codes"],
            serde_json::json!([135])
        );

        let fanout_args = Args::parse_from([
            "mqtt-loadgen",
            "--mode",
            "fanout",
            "--qos-distribution",
            "0:0.5,1:0.5",
        ]);
        let distribution = QosDistribution::parse(fanout_args.qos_distribution.as_deref())
            .unwrap()
            .unwrap();
        let fanout_inputs = inputs_json(&fanout_args, "fanout", Some(&distribution), &[], None);
        assert_eq!(fanout_inputs["mode"], "fanout");
        assert_eq!(fanout_inputs["qos_distribution"][0]["qos"], 0);
    }

    #[test]
    fn biscuit_transform_rejects_custom_helper_binary() {
        let err =
            reject_custom_biscuit_transform_bin(Some("biscuit-attenuate"), "Biscuit transform")
                .unwrap_err()
                .to_string();
        assert!(err.contains("custom helper binaries are no longer supported"));
        assert!(err.contains("in-process"));
    }

    #[test]
    fn control_mode_applies_legacy_default_topic() {
        let mut args = Args::parse_from(["mqtt-loadgen", "--control-mode"]);
        assert_eq!(args.control_topic, None);

        apply_legacy_defaults(&mut args);

        assert_eq!(args.control_topic.as_deref(), Some(DEFAULT_CONTROL_TOPIC));
        let inputs = inputs_json(&args, "publish", None, &[], None);
        assert_eq!(inputs["control"]["topic"], DEFAULT_CONTROL_TOPIC);
    }

    #[test]
    fn explicit_control_topic_overrides_legacy_default() {
        let mut args = Args::parse_from([
            "mqtt-loadgen",
            "--control-mode",
            "--control-topic",
            "custom/control/{client_id}",
        ]);

        apply_legacy_defaults(&mut args);

        assert_eq!(
            args.control_topic.as_deref(),
            Some("custom/control/{client_id}")
        );
    }

    #[test]
    fn rust_cli_preserves_python_wrapper_env_vars() {
        assert_eq!(env_for("host").as_deref(), Some("MQTT_HOST"));
        assert_eq!(env_for("username").as_deref(), Some("MQTT_USERNAME"));
        assert_eq!(env_for("password").as_deref(), Some("MQTT_PASSWORD"));
        assert_eq!(
            env_for("token_issuer_url").as_deref(),
            Some("TOKEN_ISSUER_URL")
        );
        assert_eq!(
            env_for("control_payload_file").as_deref(),
            Some("MQTT_CONTROL_PAYLOAD_FILE")
        );
        assert_eq!(
            env_for("fanout_churn_sqlite_subscribers").as_deref(),
            Some("MQTT_FANOUT_CHURN_SQLITE_SUBSCRIBERS")
        );
    }

    #[test]
    fn strict_startup_validation_matches_legacy_rules() {
        let missing_url = Args::parse_from([
            "mqtt-loadgen",
            "--clients",
            "2",
            "--jwt-identity-binding",
            "strict",
        ]);
        assert!(validate_startup_provisioning(&missing_url).is_err());

        let valid = Args::parse_from([
            "mqtt-loadgen",
            "--clients",
            "2",
            "--jwt-identity-binding",
            "strict",
            "--token-issuer-url",
            "http://issuer",
            "--token-issuer-kind",
            "jwt",
        ]);
        assert!(validate_startup_provisioning(&valid).is_ok());
    }

    #[test]
    fn strict_fanout_publisher_uses_dedicated_startup_provisioning() {
        let args = Args::parse_from([
            "mqtt-loadgen",
            "--mode",
            "fanout",
            "--clients",
            "2",
            "--jwt-identity-binding",
            "strict",
            "--token-issuer-url",
            "http://issuer",
            "--token-issuer-kind",
            "jwt",
        ]);
        assert!(should_provision_fanout_publisher(&args, "jwt").unwrap());

        let non_strict = Args::parse_from([
            "mqtt-loadgen",
            "--mode",
            "fanout",
            "--clients",
            "2",
            "--jwt-identity-binding",
            "off",
        ]);
        assert!(!should_provision_fanout_publisher(&non_strict, "jwt").unwrap());
    }
}
