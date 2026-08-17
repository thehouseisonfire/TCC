#![recursion_limit = "256"]

use base64::{Engine as _, engine::general_purpose};
use biscuit_auth::PublicKey;
use clap::Parser;
use gen_tokens::biscuit_attenuation::{
    BiscuitAttenuationOptions, attenuate_biscuit_token, load_public_key_hex,
};
use gen_tokens::mqtt_helpers::{
    ClientSpec, ConnectReport, MqttHelperError, Result, connect, decode_token_arg, poll_until,
    puback_reason_code, qos,
};
use rand::{Rng as _, RngExt as _};
use rumqttc::mqttbytes::v5::{AuthProperties, Packet};
use rumqttc::{AsyncClient, Event, Outgoing};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;

const SYNC_CONNECT_RELEASE_DELAY: Duration = Duration::from_millis(200);
const DEFAULT_CONTROL_TOPIC: &str = "$CONTROL/dynamic-security/v1";
const CLIENT_ID_PLACEHOLDER: &str = "{client_id}";

#[derive(Debug, Deserialize)]
struct PasswordMapFile {
    version: u64,
    max_clients: usize,
    profiles: HashMap<String, PasswordMapProfile>,
}

#[derive(Debug, Deserialize)]
struct PasswordMapProfile {
    kind: String,
    entries: HashMap<String, PasswordMapEntry>,
}

#[derive(Debug, Deserialize)]
struct PasswordMapEntry {
    token: String,
    exp: Option<i64>,
}

#[derive(Debug, Clone)]
struct ResolvedPassword {
    bytes: Vec<u8>,
    exp: Option<i64>,
}

#[derive(Debug)]
struct PasswordMap {
    max_clients: usize,
    profiles: HashMap<String, HashMap<String, ResolvedPassword>>,
}

fn load_password_map(path: &Path) -> Result<PasswordMap> {
    let data = fs::read_to_string(path)
        .map_err(|e| MqttHelperError::Message(format!("failed to read password-map: {e}")))?;
    let raw: PasswordMapFile = serde_json::from_str(&data)
        .map_err(|e| MqttHelperError::Message(format!("failed to parse password-map: {e}")))?;
    if raw.version != 1 {
        return Err(MqttHelperError::Message(format!(
            "unsupported password-map version {}; expected 1",
            raw.version
        )));
    }
    let mut profiles = HashMap::new();
    for (name, profile) in raw.profiles {
        if profile.kind != "jwt" && profile.kind != "biscuit" {
            return Err(MqttHelperError::Message(format!(
                "password-map profile {name:?} has unsupported kind {:?}",
                profile.kind
            )));
        }
        let mut entries = HashMap::new();
        for (client_id, entry) in profile.entries {
            entries.insert(
                client_id,
                ResolvedPassword {
                    bytes: decode_token_arg(&entry.token)?,
                    exp: entry.exp,
                },
            );
        }
        profiles.insert(name, entries);
    }
    Ok(PasswordMap {
        max_clients: raw.max_clients,
        profiles,
    })
}

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
    #[arg(long, env = "MQTT_CLIENT_INDEX_START", default_value_t = 1)]
    client_index_start: usize,
    #[arg(long, env = "MQTT_CLIENT_ID")]
    client_id: Option<String>,
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
    #[arg(long, env = "MQTT_SYNC_CONNECT_BARRIER_URL")]
    sync_connect_barrier_url: Option<String>,
    #[arg(long, env = "MQTT_SYNC_CONNECT_RUN_ID")]
    sync_connect_run_id: Option<String>,
    #[arg(long, env = "MQTT_SYNC_CONNECT_PARTICIPANT_ID")]
    sync_connect_participant_id: Option<String>,
    #[arg(long, env = "MQTT_SYNC_CONNECT_PARTICIPANTS")]
    sync_connect_participants: Option<usize>,
    #[arg(
        long,
        env = "MQTT_SYNC_CONNECT_BARRIER_TIMEOUT_SECONDS",
        default_value_t = 120
    )]
    sync_connect_barrier_timeout_seconds: u64,
    #[arg(long, env = "MQTT_MODE", default_value = "publish")]
    mode: String,
    #[arg(long, env = "MQTT_FANOUT_TOPIC", default_value = "fanout/broadcast")]
    fanout_topic: String,
    #[arg(long, env = "MQTT_FANOUT_PUBLISHER_USERNAME")]
    fanout_publisher_username: Option<String>,
    #[arg(long, env = "MQTT_FANOUT_PUBLISHER_PASSWORD")]
    fanout_publisher_password: Option<String>,
    #[arg(long, env = "MQTT_FANOUT_ROLE", default_value = "combined")]
    fanout_role: String,
    #[arg(long, env = "MQTT_FANOUT_READY_DIR")]
    fanout_ready_dir: Option<String>,
    #[arg(long, env = "MQTT_FANOUT_READY_TIMEOUT_SECONDS", default_value_t = 120)]
    fanout_ready_timeout_seconds: u64,
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
    #[arg(long, env = "MQTT_RUNTIME_CONTROL_USERNAME")]
    runtime_control_username: Option<String>,
    #[arg(long, env = "MQTT_RUNTIME_CONTROL_PASSWORD")]
    runtime_control_password: Option<String>,
    #[arg(long, env = "MQTT_RUNTIME_CONTROL_AFTER_MESSAGES", default_value_t = 0)]
    runtime_control_after_messages: usize,
    #[arg(long, env = "MQTT_RUNTIME_CONTROL_EXPECT_DENIAL")]
    runtime_control_expect_denial: bool,
    #[arg(long, env = "MQTT_RUNTIME_CONTROL_BARRIER_URL")]
    runtime_control_barrier_url: Option<String>,
    #[arg(long, env = "MQTT_RUNTIME_CONTROL_RUN_ID")]
    runtime_control_run_id: Option<String>,
    #[arg(long, env = "MQTT_RUNTIME_CONTROL_PARTICIPANT_ID")]
    runtime_control_participant_id: Option<String>,
    #[arg(long, env = "MQTT_RUNTIME_CONTROL_PARTICIPANTS")]
    runtime_control_participants: Option<usize>,
    #[arg(long, env = "MQTT_RUNTIME_CONTROL_LOCAL_AFTER_MESSAGES")]
    runtime_control_local_after_messages: Option<usize>,
    #[arg(
        long,
        env = "MQTT_RUNTIME_CONTROL_BARRIER_TIMEOUT_SECONDS",
        default_value_t = 120
    )]
    runtime_control_barrier_timeout_seconds: u64,
    #[arg(long)]
    json: bool,
    #[arg(long, env = "MQTT_OUTPUT_JSON_FILE")]
    output_json_file: Option<String>,
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
    #[arg(long, env = "MQTT_PROACTIVE_REFRESH")]
    proactive_refresh: bool,
    #[arg(
        long,
        env = "MQTT_PROACTIVE_REFRESH_MARGIN_SECONDS",
        default_value_t = 60
    )]
    proactive_refresh_margin_seconds: u64,
    #[arg(
        long,
        env = "MQTT_PROACTIVE_REFRESH_TIMEOUT_SECONDS",
        default_value_t = 10
    )]
    proactive_refresh_timeout_seconds: u64,
    #[arg(long, env = "MQTT_PROACTIVE_REFRESH_ASSERT_CONTINUITY")]
    proactive_refresh_assert_continuity: bool,
    #[arg(long, env = "MQTT_REAUTH_STORM")]
    reauth_storm: bool,
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
    #[arg(
        long,
        env = "BISCUIT_DELEGATE_HANDOFF_ROLE",
        default_value = "combined"
    )]
    biscuit_delegate_handoff_role: String,
    #[arg(long, env = "BISCUIT_DELEGATE_HANDOFF_NONCE")]
    biscuit_delegate_handoff_nonce: Option<String>,
    #[arg(long, env = "BISCUIT_DELEGATE_HANDOFF_READY_DIR")]
    biscuit_delegate_handoff_ready_dir: Option<String>,
    #[arg(
        long,
        env = "BISCUIT_DELEGATE_HANDOFF_READY_TIMEOUT_SECONDS",
        default_value_t = 120
    )]
    biscuit_delegate_handoff_ready_timeout_seconds: u64,
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
    #[arg(long, env = "MQTT_PASSWORD_MAP")]
    password_map: Option<PathBuf>,
    #[arg(long, env = "MQTT_PASSWORD_MAP_PROFILE")]
    password_map_profile: Option<String>,
    #[arg(long, env = "MQTT_FANOUT_PUBLISHER_PASSWORD_MAP_PROFILE")]
    fanout_publisher_password_map_profile: Option<String>,
    #[arg(skip)]
    password_map_data: Option<Arc<PasswordMap>>,
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
    proactive_refresh: Summary,
    proactive_refresh_len: Summary,
    proactive_refresh_attempts: usize,
    proactive_refresh_successes: usize,
    proactive_refresh_failures: usize,
    session_continuity_ok: bool,
    expiry_denial_count: usize,
    delegation: Summary,
    delegation_len: Summary,
    delegation_handoff_publish: Summary,
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
    sync_connect: Value,
    reauth_storm: Value,
    raw_publish_ms: Vec<f64>,
    raw_metrics: Value,
    errors: Vec<String>,
}

#[derive(Debug, Default)]
struct WorkerResult {
    connect_ms: Option<f64>,
    token_refresh_ms: Option<f64>,
    token_refresh_len: Option<f64>,
    proactive_refresh_ms: Vec<f64>,
    proactive_refresh_len: Vec<f64>,
    proactive_refresh_attempts: usize,
    proactive_refresh_successes: usize,
    proactive_refresh_failures: usize,
    proactive_refresh_attempt_unix_ms: Vec<u128>,
    expiry_denial_count: usize,
    policy_denial_count: usize,
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
    sync_barrier_wait_ms: Option<f64>,
    sync_barrier_released_at_unix_ms: Option<u128>,
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
    reauth_storm: Option<Arc<ReauthStormGate>>,
    runtime_control: Option<Arc<RuntimeControlState>>,
}

struct StandardMetrics {
    connect: Vec<f64>,
    token_refresh: Vec<f64>,
    token_refresh_len: Vec<f64>,
    proactive_refresh: Vec<f64>,
    proactive_refresh_len: Vec<f64>,
    proactive_refresh_attempts: usize,
    proactive_refresh_successes: usize,
    proactive_refresh_failures: usize,
    proactive_refresh_attempt_unix_ms: Vec<u128>,
    expiry_denial_count: usize,
    policy_denial_count: usize,
    runtime_control_connect_ms: Option<f64>,
    delegation: Vec<f64>,
    delegation_len: Vec<f64>,
    delegation_handoff_publish: Vec<f64>,
    attenuation: Vec<f64>,
    attenuation_len: Vec<f64>,
    publish: Vec<f64>,
    publish_qos_0: Vec<f64>,
    publish_qos_1: Vec<f64>,
    publish_qos_2: Vec<f64>,
    receive: Vec<f64>,
    control: Vec<f64>,
    control_injection: Vec<f64>,
    sync_barrier_wait: Vec<f64>,
    sync_barrier_released_at_unix_ms: Vec<u128>,
    errors: Vec<String>,
    publish_throughput_mps: f64,
    receive_throughput_mps: f64,
}

#[derive(Debug, Default)]
struct RuntimeControlState {
    successful_publishes: AtomicUsize,
    publishers_finished: AtomicBool,
    applied: AtomicBool,
    progress: Notify,
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
struct IssuedToken {
    bytes: Vec<u8>,
    exp: Option<i64>,
}

impl IssuedToken {
    fn static_token(bytes: Vec<u8>) -> Self {
        Self { bytes, exp: None }
    }
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
struct ReauthStormGate {
    expected: usize,
    ready: AtomicUsize,
    released: AtomicBool,
    notify: Notify,
    ready_unix_ms: Mutex<Vec<u128>>,
}

impl ReauthStormGate {
    fn new(expected: usize) -> Self {
        Self {
            expected,
            ready: AtomicUsize::new(0),
            released: AtomicBool::new(false),
            notify: Notify::new(),
            ready_unix_ms: Mutex::new(Vec::with_capacity(expected)),
        }
    }

    async fn wait(&self, timeout: Duration) -> bool {
        if let Ok(mut ready) = self.ready_unix_ms.lock() {
            ready.push(unix_ms_now());
        }
        if self.ready.fetch_add(1, Ordering::AcqRel) + 1 >= self.expected {
            self.released.store(true, Ordering::Release);
            self.notify.notify_waiters();
            return true;
        }
        let wait = async {
            loop {
                let notified = self.notify.notified();
                if self.released.load(Ordering::Acquire) {
                    break;
                }
                notified.await;
            }
        };
        tokio::time::timeout(timeout, wait).await.is_ok()
    }
}

#[derive(Debug, Clone)]
struct ExternalSyncBarrier {
    url: String,
    run_id: String,
    participant_id: String,
    participants: usize,
    timeout: Duration,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct SyncBarrierStatus {
    ok: bool,
    run_id: String,
    participants: usize,
    ready_count: usize,
    released: bool,
    released_at_unix_ms: Option<u128>,
    max_ready_skew_ms: Option<f64>,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct SyncBarrierWaitReport {
    wait_ms: f64,
    status: SyncBarrierStatus,
}

fn external_sync_barrier(args: &Args) -> Result<Option<ExternalSyncBarrier>> {
    let fields_set = [
        args.sync_connect_barrier_url.is_some(),
        args.sync_connect_run_id.is_some(),
        args.sync_connect_participant_id.is_some(),
        args.sync_connect_participants.is_some(),
    ];
    if fields_set.iter().all(|set| !set) {
        return Ok(None);
    }
    if !args.sync_connect {
        return Err(MqttHelperError::Message(
            "sync_connect barrier options require --sync-connect".to_string(),
        ));
    }
    if fields_set.iter().any(|set| !set) {
        return Err(MqttHelperError::Message(
            "sync_connect external barrier requires url, run_id, participant_id, and participants"
                .to_string(),
        ));
    }
    let participants = args.sync_connect_participants.unwrap_or_default();
    if participants == 0 {
        return Err(MqttHelperError::Message(
            "sync_connect_participants must be greater than zero".to_string(),
        ));
    }
    if args.clients != 1 {
        return Err(MqttHelperError::Message(
            "external sync_connect barrier requires --clients 1".to_string(),
        ));
    }
    Ok(Some(ExternalSyncBarrier {
        url: args
            .sync_connect_barrier_url
            .clone()
            .unwrap_or_default()
            .trim_end_matches('/')
            .to_string(),
        run_id: args.sync_connect_run_id.clone().unwrap_or_default(),
        participant_id: args.sync_connect_participant_id.clone().unwrap_or_default(),
        participants,
        timeout: Duration::from_secs(args.sync_connect_barrier_timeout_seconds.max(1)),
    }))
}

fn external_runtime_control_barrier(args: &Args) -> Result<Option<(ExternalSyncBarrier, usize)>> {
    let fields_set = [
        args.runtime_control_barrier_url.is_some(),
        args.runtime_control_run_id.is_some(),
        args.runtime_control_participant_id.is_some(),
        args.runtime_control_participants.is_some(),
        args.runtime_control_local_after_messages.is_some(),
    ];
    if fields_set.iter().all(|set| !set) {
        return Ok(None);
    }
    if fields_set.iter().any(|set| !set) {
        return Err(MqttHelperError::Message(
            "external runtime control requires barrier_url, run_id, participant_id, participants, and local_after_messages"
                .to_string(),
        ));
    }
    if args.runtime_control_username.is_some() {
        return Err(MqttHelperError::Message(
            "external runtime control cannot be combined with an in-process runtime controller"
                .to_string(),
        ));
    }
    if args.clients != 1 {
        return Err(MqttHelperError::Message(
            "external runtime control requires --clients 1".to_string(),
        ));
    }
    let participants = args.runtime_control_participants.unwrap_or_default();
    if participants == 0 {
        return Err(MqttHelperError::Message(
            "runtime_control_participants must be greater than zero".to_string(),
        ));
    }
    let local_after_messages = args
        .runtime_control_local_after_messages
        .unwrap_or_default();
    if local_after_messages > args.messages {
        return Err(MqttHelperError::Message(format!(
            "runtime control local after-messages ({local_after_messages}) exceeds configured messages ({})",
            args.messages
        )));
    }
    Ok(Some((
        ExternalSyncBarrier {
            url: args
                .runtime_control_barrier_url
                .clone()
                .unwrap_or_default()
                .trim_end_matches('/')
                .to_string(),
            run_id: args.runtime_control_run_id.clone().unwrap_or_default(),
            participant_id: args
                .runtime_control_participant_id
                .clone()
                .unwrap_or_default(),
            participants,
            timeout: Duration::from_secs(args.runtime_control_barrier_timeout_seconds.max(1)),
        },
        local_after_messages,
    )))
}

async fn wait_external_sync_barrier(
    barrier: &ExternalSyncBarrier,
) -> Result<SyncBarrierWaitReport> {
    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(barrier.timeout.saturating_add(Duration::from_secs(5)))
        .build()
        .map_err(|err| MqttHelperError::Message(format!("sync barrier client failed: {err}")))?;
    let ready_url = format!(
        "{}/runs/{}/ready/{}?participants={}",
        barrier.url, barrier.run_id, barrier.participant_id, barrier.participants
    );
    let ready = client
        .post(ready_url)
        .send()
        .await
        .map_err(|err| MqttHelperError::Message(format!("sync barrier ready failed: {err}")))?;
    let ready_status = ready.status();
    if !ready_status.is_success() {
        let body = ready.text().await.unwrap_or_default();
        return Err(MqttHelperError::Message(format!(
            "sync barrier ready returned {ready_status}: {body}"
        )));
    }
    let started = Instant::now();
    let wait_url = format!(
        "{}/runs/{}/wait?timeout_ms={}",
        barrier.url,
        barrier.run_id,
        barrier.timeout.as_millis()
    );
    let response = client
        .get(wait_url)
        .send()
        .await
        .map_err(|err| MqttHelperError::Message(format!("sync barrier wait failed: {err}")))?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(MqttHelperError::Message(format!(
            "sync barrier wait returned {status}: {body}"
        )));
    }
    let barrier_status = serde_json::from_str::<SyncBarrierStatus>(&body).map_err(|err| {
        MqttHelperError::Message(format!("sync barrier wait response JSON failed: {err}"))
    })?;
    if !barrier_status.released {
        return Err(MqttHelperError::Message(
            "sync barrier wait returned before release".to_string(),
        ));
    }
    Ok(SyncBarrierWaitReport {
        wait_ms: started.elapsed().as_secs_f64() * 1000.0,
        status: barrier_status,
    })
}

fn sync_connect_json(
    args: &Args,
    barrier_wait: &[f64],
    released_at: &[u128],
    errors: &[String],
) -> Value {
    if !args.sync_connect {
        return serde_json::json!({"enabled": false});
    }
    let barrier = if args.sync_connect_barrier_url.is_some() {
        "external"
    } else {
        "in_process"
    };
    let first_release = released_at.iter().min().copied();
    serde_json::json!({
        "enabled": true,
        "barrier": barrier,
        "run_id": args.sync_connect_run_id,
        "participants": args.sync_connect_participants.unwrap_or(args.clients),
        "ready_count": if barrier == "external" { barrier_wait.len() } else { args.clients },
        "released_at_unix_ms": first_release,
        "client_wait": summarize(barrier_wait),
        "errors": errors
            .iter()
            .filter(|err| err.starts_with("sync_barrier_"))
            .cloned()
            .collect::<Vec<_>>(),
    })
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

fn explicit_startup_provisioning(args: &Args) -> bool {
    args.password.is_empty() && args.token_issuer_url.is_some()
}

fn should_startup_provision_token(args: &Args) -> bool {
    strict_multi_client_startup(args)
        || args.proactive_refresh
        || explicit_startup_provisioning(args)
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
    if args.client_index_start == 0 {
        return Err(MqttHelperError::Message(
            "client_index_start must be greater than zero".to_string(),
        ));
    }
    if args.client_id.is_some() && args.clients != 1 {
        return Err(MqttHelperError::Message(
            "client_id override requires --clients 1".to_string(),
        ));
    }
    if args.control_after_messages > 0 {
        if args.control_mode {
            return Err(MqttHelperError::Message(
                "control after-messages cannot be combined with control mode".to_string(),
            ));
        }
        if args.control_topic.as_deref().is_none_or(str::is_empty) {
            return Err(MqttHelperError::Message(
                "control after-messages requires a control topic".to_string(),
            ));
        }
        if args.control_payload.is_none() && args.control_payload_file.is_none() {
            return Err(MqttHelperError::Message(
                "control after-messages requires a control payload or payload file".to_string(),
            ));
        }
        if args.messages < args.control_after_messages {
            return Err(MqttHelperError::Message(format!(
                "control after-messages ({}) exceeds messages per client ({})",
                args.control_after_messages, args.messages
            )));
        }
    }
    if args.runtime_control_username.is_some() {
        if args.runtime_control_after_messages == 0 {
            return Err(MqttHelperError::Message(
                "runtime control after-messages must be greater than zero".to_string(),
            ));
        }
        let publish_capacity = args.clients.checked_mul(args.messages).ok_or_else(|| {
            MqttHelperError::Message(
                "runtime control publish capacity overflowed clients * messages".to_string(),
            )
        })?;
        if args.runtime_control_after_messages > publish_capacity {
            return Err(MqttHelperError::Message(format!(
                "runtime control after-messages ({}) exceeds configured publish capacity ({publish_capacity})",
                args.runtime_control_after_messages
            )));
        }
        if args.runtime_control_expect_denial
            && args.runtime_control_after_messages >= publish_capacity
        {
            return Err(MqttHelperError::Message(format!(
                "runtime control expected-denial mode requires after-messages ({}) to be below configured publish capacity ({publish_capacity})",
                args.runtime_control_after_messages
            )));
        }
    }
    if !matches!(
        args.biscuit_delegate_handoff_role.as_str(),
        "combined" | "delegator" | "delegatee"
    ) {
        return Err(MqttHelperError::Message(format!(
            "biscuit_delegate_handoff_role must be combined, delegator, or delegatee; got {:?}",
            args.biscuit_delegate_handoff_role
        )));
    }
    if args.biscuit_delegate_handoff_role != "combined" {
        if !(args.biscuit_delegate && args.biscuit_delegate_handoff) {
            return Err(MqttHelperError::Message(
                "biscuit delegation handoff roles require --biscuit-delegate and --biscuit-delegate-handoff".to_string(),
            ));
        }
        if args.mode == "fanout" {
            return Err(MqttHelperError::Message(
                "biscuit delegation handoff roles are only supported for standard publish/control mode".to_string(),
            ));
        }
        if args.biscuit_delegate_handoff_nonce.is_none() {
            return Err(MqttHelperError::Message(
                "biscuit delegation handoff roles require biscuit_delegate_handoff_nonce"
                    .to_string(),
            ));
        }
        if args.biscuit_delegate_handoff_ready_dir.is_none() {
            return Err(MqttHelperError::Message(
                "biscuit delegation handoff roles require biscuit_delegate_handoff_ready_dir"
                    .to_string(),
            ));
        }
    }
    if args.biscuit_delegate_handoff_role == "delegatee" && args.clients != 1 {
        return Err(MqttHelperError::Message(
            "biscuit_delegate_handoff_role=delegatee requires clients=1".to_string(),
        ));
    }
    external_sync_barrier(args)?;
    external_runtime_control_barrier(args)?;
    if !matches!(
        args.fanout_role.as_str(),
        "combined" | "publisher" | "subscriber"
    ) {
        return Err(MqttHelperError::Message(format!(
            "fanout_role must be combined, publisher, or subscriber; got {:?}",
            args.fanout_role
        )));
    }
    if args.fanout_role != "combined" {
        if args.mode != "fanout" {
            return Err(MqttHelperError::Message(
                "fanout_role publisher/subscriber is only valid with mode=fanout".to_string(),
            ));
        }
        if args.fanout_ready_dir.is_none() {
            return Err(MqttHelperError::Message(
                "fanout_role publisher/subscriber requires fanout_ready_dir".to_string(),
            ));
        }
        if args.biscuit_delegate_handoff {
            return Err(MqttHelperError::Message(
                "biscuit delegation handoff is not supported with split fanout roles".to_string(),
            ));
        }
    }
    if args.fanout_role == "subscriber" && args.clients != 1 {
        return Err(MqttHelperError::Message(
            "fanout_role=subscriber requires clients=1".to_string(),
        ));
    }
    if args.proactive_refresh {
        if args.mode == "fanout" {
            return Err(MqttHelperError::Message(
                "proactive refresh is not currently supported in fanout mode.".to_string(),
            ));
        }
        if args.token_issuer_url.is_none() {
            return Err(MqttHelperError::Message(
                "proactive refresh requires token_issuer_url".to_string(),
            ));
        }
        if resolved_token_issuer_kind(args).is_none() {
            return Err(MqttHelperError::Message(
                "proactive refresh requires token_issuer_kind or username 'jwt'/'biscuit'"
                    .to_string(),
            ));
        }
        if let Some(ttl) = args.token_issuer_ttl
            && ttl <= args.proactive_refresh_margin_seconds
        {
            return Err(MqttHelperError::Message(format!(
                "proactive refresh requires token_issuer_ttl ({ttl}s) to be greater than proactive_refresh_margin_seconds ({}s)",
                args.proactive_refresh_margin_seconds
            )));
        }
        for (label, ttl) in [
            (
                "biscuit_attenuate_ttl",
                args.biscuit_attenuate
                    .then_some(args.biscuit_attenuate_ttl)
                    .flatten(),
            ),
            (
                "biscuit_delegate_ttl",
                args.biscuit_delegate
                    .then_some(args.biscuit_delegate_ttl)
                    .flatten(),
            ),
        ] {
            if let Some(ttl) = ttl
                && ttl <= args.proactive_refresh_margin_seconds
            {
                return Err(MqttHelperError::Message(format!(
                    "proactive refresh requires {label} ({ttl}s) to be greater than proactive_refresh_margin_seconds ({}s)",
                    args.proactive_refresh_margin_seconds
                )));
            }
        }
    }
    if args.reauth_storm {
        if !args.proactive_refresh {
            return Err(MqttHelperError::Message(
                "reauth storm requires --proactive-refresh".to_string(),
            ));
        }
        if args.clients <= 1 {
            return Err(MqttHelperError::Message(
                "reauth storm requires more than one client".to_string(),
            ));
        }
        if args.sync_connect_barrier_url.is_some() {
            return Err(MqttHelperError::Message(
                "reauth storm uses an in-process refresh barrier and is not supported with external sync_connect barriers".to_string(),
            ));
        }
    }
    if explicit_startup_provisioning(args) && resolved_token_issuer_kind(args).is_none() {
        return Err(MqttHelperError::Message(
            "startup provisioning requires token_issuer_kind or username 'jwt'/'biscuit'"
                .to_string(),
        ));
    }
    if !strict_multi_client_startup(args) {
        return Ok(());
    }
    if args.password_map_profile.is_some() {
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
    if args.fanout_publisher_password_map_profile.is_some() {
        return Ok(false);
    }
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

async fn fetch_token(args: &Args, kind: &str, client_id: &str, topic: &str) -> Result<IssuedToken> {
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
    let exp = body.get("exp").and_then(Value::as_i64);
    if kind == "biscuit" {
        let encoded = body
            .get("data_b64")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                MqttHelperError::Message("token issuer response missing data_b64".to_string())
            })?;
        let padding = "=".repeat((4 - encoded.len() % 4) % 4);
        let bytes = general_purpose::URL_SAFE
            .decode(format!("{encoded}{padding}"))
            .map_err(|err| MqttHelperError::Message(format!("invalid data_b64 token: {err}")))?;
        return Ok(IssuedToken { bytes, exp });
    }
    let token = body.get("token").and_then(Value::as_str).ok_or_else(|| {
        MqttHelperError::Message("token issuer response missing token".to_string())
    })?;
    Ok(IssuedToken {
        bytes: token.as_bytes().to_vec(),
        exp,
    })
}

async fn startup_password(args: &Args, client_id: &str, topic: &str) -> Result<IssuedToken> {
    if let Some(profile) = args.password_map_profile.as_deref() {
        return password_map_token(args, profile, client_id);
    }
    if should_startup_provision_token(args) {
        let kind = resolved_token_issuer_kind(args).ok_or_else(|| {
            MqttHelperError::Message("startup provisioning requires token kind".to_string())
        })?;
        fetch_token(args, &kind, client_id, topic).await
    } else {
        decode_token_arg(&args.password).map(IssuedToken::static_token)
    }
}

fn password_map_token(args: &Args, profile: &str, client_id: &str) -> Result<IssuedToken> {
    let map = args.password_map_data.as_ref().ok_or_else(|| {
        MqttHelperError::Message(format!(
            "password-map profile {profile:?} requested without --password-map"
        ))
    })?;
    let entries = map.profiles.get(profile).ok_or_else(|| {
        MqttHelperError::Message(format!("password-map profile {profile:?} not found"))
    })?;
    let entry = entries.get(client_id).ok_or_else(|| {
        MqttHelperError::Message(format!(
            "password-map profile {profile:?} has no entry for {client_id:?} \
             (max_clients={})",
            map.max_clients
        ))
    })?;
    Ok(IssuedToken {
        bytes: entry.bytes.clone(),
        exp: entry.exp,
    })
}

fn repo_root() -> PathBuf {
    if let Ok(path) = std::env::var("MQTT_AUTH_BISCUIT_REPO_ROOT") {
        return PathBuf::from(path);
    }
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

fn handoff_nonce(args: &Args) -> String {
    args.biscuit_delegate_handoff_nonce
        .clone()
        .unwrap_or_else(fill_nonce)
}

fn handoff_ready_dir(args: &Args) -> Result<PathBuf> {
    args.biscuit_delegate_handoff_ready_dir
        .as_deref()
        .map(resolve_repo_path)
        .ok_or_else(|| {
            MqttHelperError::Message("biscuit_delegate_handoff_ready_dir is required".to_string())
        })
}

fn handoff_ready_path(dir: &Path, client_id: &str) -> PathBuf {
    dir.join(format!("{client_id}.ready"))
}

fn handoff_release_path(dir: &Path) -> PathBuf {
    dir.join("handoff.release")
}

fn write_handoff_ready(dir: &Path, client_id: &str, nonce: &str) -> Result<()> {
    fs::create_dir_all(dir)?;
    let payload = serde_json::json!({
        "client_id": client_id,
        "nonce": nonce,
        "ready": true,
    });
    fs::write(
        handoff_ready_path(dir, client_id),
        serde_json::to_vec(&payload)?,
    )?;
    Ok(())
}

fn write_handoff_release(dir: &Path, nonce: &str) -> Result<()> {
    fs::create_dir_all(dir)?;
    let payload = serde_json::json!({
        "nonce": nonce,
        "release": true,
    });
    fs::write(handoff_release_path(dir), serde_json::to_vec(&payload)?)?;
    Ok(())
}

fn valid_handoff_ready_file(dir: &Path, client_id: &str, nonce: &str) -> bool {
    let Ok(bytes) = fs::read(handoff_ready_path(dir, client_id)) else {
        return false;
    };
    let Ok(payload) = serde_json::from_slice::<Value>(&bytes) else {
        return false;
    };
    payload.get("ready").and_then(Value::as_bool) == Some(true)
        && payload.get("client_id").and_then(Value::as_str) == Some(client_id)
        && payload.get("nonce").and_then(Value::as_str) == Some(nonce)
}

fn valid_handoff_release_file(dir: &Path, nonce: &str) -> bool {
    let Ok(bytes) = fs::read(handoff_release_path(dir)) else {
        return false;
    };
    let Ok(payload) = serde_json::from_slice::<Value>(&bytes) else {
        return false;
    };
    payload.get("release").and_then(Value::as_bool) == Some(true)
        && payload.get("nonce").and_then(Value::as_str) == Some(nonce)
}

async fn wait_for_handoff_ready_files(
    dir: &Path,
    client_ids: &[String],
    nonce: &str,
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if client_ids
            .iter()
            .all(|client_id| valid_handoff_ready_file(dir, client_id, nonce))
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_handoff_release_file(dir: &Path, nonce: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if valid_handoff_release_file(dir, nonce) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
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

fn unix_timestamp_now() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| MqttHelperError::Message(format!("system clock before epoch: {err}")))?;
    i64::try_from(duration.as_secs())
        .map_err(|_| MqttHelperError::Message("system timestamp exceeds i64 range".to_string()))
}

fn unix_ms_now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn proactive_refresh_delay(exp: Option<i64>, margin_seconds: u64, now: i64) -> Option<Duration> {
    let exp = exp?;
    if exp <= now {
        return Some(Duration::ZERO);
    }
    let margin = i64::try_from(margin_seconds).unwrap_or(i64::MAX);
    let deadline = exp.saturating_sub(margin);
    if deadline > now {
        return u64::try_from(deadline - now).ok().map(Duration::from_secs);
    }
    Some(Duration::ZERO)
}

fn proactive_assertion_wait_timeout(args: &Args, exp: Option<i64>) -> Duration {
    let delay = unix_timestamp_now()
        .ok()
        .and_then(|now| proactive_refresh_delay(exp, args.proactive_refresh_margin_seconds, now))
        .unwrap_or_default();
    delay
        + Duration::from_secs(args.proactive_refresh_timeout_seconds.max(1))
        + Duration::from_secs(1)
}

fn validate_proactive_refresh_assertion(args: &Args, output: &Output) -> Result<()> {
    if !args.proactive_refresh_assert_continuity {
        return Ok(());
    }
    if output.proactive_refresh_attempts == 0 {
        return Err(MqttHelperError::Message(
            "proactive refresh continuity assertion failed: no proactive refresh ran".to_string(),
        ));
    }
    if !output.session_continuity_ok {
        return Err(MqttHelperError::Message(
            "proactive refresh continuity assertion failed: session continuity was not maintained"
                .to_string(),
        ));
    }
    Ok(())
}

fn expiry_denial_error(error: &str) -> bool {
    error.contains("NotAuthorized")
        || error.contains("not authorized")
        || error.contains("AuthenticationFailed")
        || error.contains("authentication failed")
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

fn client_id_for(args: &Args, index: usize) -> String {
    if let Some(client_id) = &args.client_id {
        return client_id.clone();
    }
    format!("client_{}", args.client_index_start + index)
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

fn transformed_biscuit_expiry(args: &Args, current_exp: Option<i64>) -> Result<Option<i64>> {
    let now = unix_timestamp_now()?;
    let mut exp = current_exp;
    for ttl in [
        args.biscuit_attenuate
            .then_some(args.biscuit_attenuate_ttl)
            .flatten(),
        args.biscuit_delegate
            .then_some(args.biscuit_delegate_ttl)
            .flatten(),
    ]
    .into_iter()
    .flatten()
    {
        let ttl = i64::try_from(ttl)
            .map_err(|_| MqttHelperError::Message("ttl seconds exceeds i64 range".to_string()))?;
        let transform_exp = now.saturating_add(ttl);
        exp = Some(exp.map_or(transform_exp, |existing| existing.min(transform_exp)));
    }
    Ok(exp)
}

fn refresh_token_expiry(args: &Args, token: &mut IssuedToken, transformed: bool) -> Result<()> {
    if transformed {
        token.exp = transformed_biscuit_expiry(args, token.exp)?;
    }
    Ok(())
}

async fn prepare_handoff(args: &Args, mode_topic: &str) -> Option<HandoffPlan> {
    if !(args.biscuit_delegate && args.biscuit_delegate_handoff) {
        return None;
    }
    let nonce = handoff_nonce(args);
    let mut workers = HashMap::new();
    let mut published_tokens = HashMap::new();
    let mut errors = Vec::new();
    for index in 0..args.clients {
        let client_id = client_id_for(args, index);
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
        if !apply_biscuit_transforms(args, &client_id, &mut result, &mut password.bytes) {
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
            general_purpose::URL_SAFE_NO_PAD.encode(&password.bytes),
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
        "fanout_role": args.fanout_role,
        "fanout_ready_timeout_seconds": args.fanout_ready_timeout_seconds,
        "clients": args.clients,
        "message_count": args.messages,
        "qos": args.qos,
        "qos_distribution": qos_distribution.map(QosDistribution::as_json),
        "message_size": args.message_size,
        "protocol": "mqttv5",
        "sync_connect": args.sync_connect,
        "sync_connect_barrier_url": args.sync_connect_barrier_url,
        "sync_connect_run_id": args.sync_connect_run_id,
        "sync_connect_participant_id": args.sync_connect_participant_id,
        "sync_connect_participants": args.sync_connect_participants,
        "sync_connect_barrier_timeout_seconds": args.sync_connect_barrier_timeout_seconds,
        "token_issuer_url": args.token_issuer_url,
        "token_issuer_kind": resolved_token_issuer_kind(args),
        "token_issuer_no_default_roles": args.token_issuer_no_default_roles,
        "token_issuer_no_default_grants": args.token_issuer_no_default_grants,
        "token_refresh_codes": token_refresh_codes,
        "proactive_refresh": args.proactive_refresh,
        "proactive_refresh_margin_seconds": args.proactive_refresh_margin_seconds,
        "proactive_refresh_timeout_seconds": args.proactive_refresh_timeout_seconds,
        "proactive_refresh_assert_continuity": args.proactive_refresh_assert_continuity,
        "reauth_storm": args.reauth_storm,
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
        "biscuit_delegate_handoff_role": args.biscuit_delegate_handoff_role,
        "biscuit_delegate_handoff_ready_timeout_seconds": args.biscuit_delegate_handoff_ready_timeout_seconds,
        "control": {
            "topic": args.control_topic,
            "mode": args.control_mode,
            "payload": args.control_payload,
            "repeat": args.control_repeat,
            "qos": args.control_qos,
            "after_messages": args.control_after_messages,
            "runtime_username": args.runtime_control_username,
            "runtime_after_messages": args.runtime_control_after_messages,
            "runtime_expect_denial": args.runtime_control_expect_denial,
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

async fn publish_tracked_and_wait(
    client: &rumqttc::AsyncClient,
    topic: &str,
    payload: Vec<u8>,
    qos_value: u8,
) -> Result<f64> {
    let start = Instant::now();
    let notice = client
        .publish_tracked(topic, qos(qos_value)?, false, payload)
        .await?;
    tokio::time::timeout(Duration::from_secs(10), notice.wait_completion_async())
        .await
        .map_err(|_| MqttHelperError::Message("publish_timeout".to_string()))?
        .map_err(|err| MqttHelperError::Message(format!("publish_failed:{err}")))?;
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
    timeout: Duration,
) -> Result<Vec<u8>> {
    let password = poll_until(&mut receiver.eventloop, timeout, |event| match event {
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
    })
    .await
    .map_err(|err| MqttHelperError::Message(format!("delegation_handoff_timeout:{err}")))?;
    let _ = receiver.client.disconnect().await;
    Ok(password)
}

async fn receive_handoff_token(args: &Args, client_id: &str, nonce: &str) -> Result<Vec<u8>> {
    let receiver = subscribe_handoff_receiver(args, client_id).await?;
    wait_for_handoff_token(
        receiver,
        client_id,
        nonce,
        Duration::from_secs(args.biscuit_delegate_handoff_ready_timeout_seconds.max(1)),
    )
    .await
}

async fn receive_handoff_tokens(
    args: &Args,
    plan: &HandoffPlan,
) -> (HashMap<String, Vec<u8>>, Vec<f64>, Vec<String>) {
    let mut tasks = Vec::new();
    let mut errors = Vec::new();
    for client_id in plan.tokens.keys() {
        match subscribe_handoff_receiver(args, client_id).await {
            Ok(receiver) => {
                let client_id = client_id.clone();
                let nonce = plan.nonce.clone();
                let timeout =
                    Duration::from_secs(args.biscuit_delegate_handoff_ready_timeout_seconds.max(1));
                tasks.push(tokio::spawn(async move {
                    let result =
                        wait_for_handoff_token(receiver, &client_id, &nonce, timeout).await;
                    (client_id, result)
                }));
            }
            Err(err) => errors.push(format!(
                "delegation_handoff_subscribe_failed:{client_id}:{err}"
            )),
        }
    }
    let (publish_ms, publish_errors) =
        publish_handoff_tokens(args, &plan.nonce, &plan.tokens).await;
    errors.extend(publish_errors);
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
    (passwords, publish_ms, errors)
}

async fn publish_handoff_tokens(
    args: &Args,
    nonce: &str,
    tokens: &HashMap<String, String>,
) -> (Vec<f64>, Vec<String>) {
    let Some(topic) = handoff_topic(args) else {
        return (
            Vec::new(),
            vec!["biscuit_delegate_handoff_topic is required".to_string()],
        );
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
            Err(err) => {
                return (
                    Vec::new(),
                    vec![format!("delegation_master_password_failed:{err}")],
                );
            }
        },
        Err(err) => {
            return (
                Vec::new(),
                vec![format!("delegation_master_password_failed:{err}")],
            );
        }
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
        return (
            Vec::new(),
            vec!["delegation_master_connect_failed".to_string()],
        );
    };
    let mut publish_ms = Vec::new();
    let mut errors = Vec::new();
    if !report.connect_ok {
        errors.push(format!(
            "delegation_master_connect_denied:{:?}",
            report.connect_reason
        ));
        return (publish_ms, errors);
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
            Ok(ms) => publish_ms.push(ms),
            Err(err) => errors.push(format!("delegation_master_publish_failed:{err}")),
        }
    }
    let _ = client.disconnect().await;
    (publish_ms, errors)
}

struct FanoutSubscriber {
    _client: AsyncClient,
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
    handoff_publish_ms: Vec<f64>,
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

struct FanoutMessage {
    sent: f64,
    sequence_id: Option<usize>,
}

fn parse_fanout_message(payload: &[u8]) -> Option<FanoutMessage> {
    let pos = payload.iter().position(|byte| *byte == b'|')?;
    let sent = std::str::from_utf8(&payload[..pos])
        .ok()?
        .parse::<f64>()
        .ok()?;
    let sequence_id = payload
        .iter()
        .skip(pos + 1)
        .position(|byte| *byte == b'|')
        .and_then(|end| {
            std::str::from_utf8(&payload[pos + 1..pos + 1 + end])
                .ok()
                .and_then(|raw| raw.parse::<usize>().ok())
        });
    Some(FanoutMessage { sent, sequence_id })
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
                if let Some(message) = parse_fanout_message(&publish.payload) {
                    let elapsed = (start.elapsed().as_secs_f64() - message.sent) * 1000.0;
                    subscriber.result.receive_ms.push(elapsed.max(0.0));
                    if let Some(sequence_id) = message.sequence_id {
                        if sequence_id < churn_after_messages {
                            subscriber.result.receive_pre_churn += 1;
                        } else {
                            subscriber.result.receive_post_churn += 1;
                        }
                    }
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
    let mut handoff_publish_ms = Vec::new();
    if let Some(plan) = &handoff_plan {
        let (passwords, publish_ms, handoff_errors) = receive_handoff_tokens(args, plan).await;
        handoff_passwords = passwords;
        handoff_publish_ms = publish_ms;
        errors.extend(handoff_errors);
    }
    FanoutRuntime {
        handoff_plan,
        handoff_passwords,
        handoff_publish_ms,
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
        if !apply_biscuit_transforms(args, &client_id, &mut worker_result, &mut password.bytes) {
            runtime.errors.extend(worker_result.errors);
            return None;
        }
        bootstrap.delegation_ms = worker_result.delegation_ms;
        bootstrap.delegation_len = worker_result.delegation_len;
        bootstrap.attenuation_ms = worker_result.attenuation_ms;
        bootstrap.attenuation_len = worker_result.attenuation_len;
        password.bytes
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
        return Ok((
            FanoutSubscriber {
                _client: client,
                eventloop,
                result,
            },
            false,
        ));
    }
    match subscribe_and_wait(&client, &mut eventloop, &args.fanout_topic, subscribe_qos).await {
        Ok(codes) if codes.iter().all(|code| matches!(code, 0..=2)) => Ok((
            FanoutSubscriber {
                _client: client,
                eventloop,
                result,
            },
            true,
        )),
        Ok(codes) => {
            result.errors.push(format!(
                "fanout_suback_rejected:{}",
                codes
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ));
            Ok((
                FanoutSubscriber {
                    _client: client,
                    eventloop,
                    result,
                },
                false,
            ))
        }
        Err(err) => {
            result.errors.push(format!("subscribe_failed:{err}"));
            Ok((
                FanoutSubscriber {
                    _client: client,
                    eventloop,
                    result,
                },
                false,
            ))
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
        let client_id = client_id_for(args, index);
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

fn fanout_ready_dir(args: &Args) -> Result<PathBuf> {
    args.fanout_ready_dir
        .as_deref()
        .map(resolve_repo_path)
        .ok_or_else(|| MqttHelperError::Message("fanout_ready_dir is required".to_string()))
}

fn fanout_ready_path(dir: &Path, client_id: &str) -> PathBuf {
    dir.join(format!("{client_id}.ready"))
}

fn fanout_done_path(dir: &Path) -> PathBuf {
    dir.join("publisher.done")
}

fn write_fanout_ready(dir: &Path, client_id: &str) -> Result<()> {
    fs::create_dir_all(dir)?;
    let payload = serde_json::json!({
        "client_id": client_id,
        "ready": true,
    });
    fs::write(
        fanout_ready_path(dir, client_id),
        serde_json::to_vec(&payload)?,
    )?;
    Ok(())
}

fn write_fanout_done(dir: &Path, applied_events: usize, errors: &[String]) -> Result<()> {
    fs::create_dir_all(dir)?;
    let payload = serde_json::json!({
        "done": true,
        "fanout_churn_applied_events": applied_events,
        "errors": errors,
    });
    fs::write(fanout_done_path(dir), serde_json::to_vec(&payload)?)?;
    Ok(())
}

async fn wait_for_fanout_ready_files(dir: &Path, client_ids: &[String], timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if client_ids
            .iter()
            .all(|client_id| fanout_ready_path(dir, client_id).exists())
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn watch_fanout_done_file(dir: PathBuf, timeout: Duration, done: Arc<AtomicBool>) -> bool {
    let done_path = fanout_done_path(&dir);
    let deadline = Instant::now() + timeout;
    loop {
        if done_path.exists() {
            done.store(true, Ordering::Release);
            return true;
        }
        if Instant::now() >= deadline {
            done.store(true, Ordering::Release);
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
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
    let publisher_password =
        if let Some(profile) = args.fanout_publisher_password_map_profile.as_deref() {
            password_map_token(args, profile, "fanout_publisher")?.bytes
        } else if let Some(password) = args.fanout_publisher_password.as_deref() {
            decode_token_arg(password)?
        } else if should_provision_fanout_publisher(args, &publisher_username)? {
            let kind = resolved_token_issuer_kind(args).ok_or_else(|| {
                MqttHelperError::Message(
                    "strict multi-client startup provisioning requires token kind".to_string(),
                )
            })?;
            fetch_token(args, &kind, "fanout_publisher", &args.fanout_topic)
                .await?
                .bytes
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
    let raw_metrics = serde_json::json!({
        "connect": metrics.connect.clone(),
        "token_refresh": [],
        "token_refresh_len": [],
        "proactive_refresh": [],
        "proactive_refresh_len": [],
        "proactive_refresh_attempt_unix_ms": [],
        "delegation": metrics.delegation.clone(),
        "delegation_len": metrics.delegation_len.clone(),
        "delegation_handoff_publish": parts.runtime.handoff_publish_ms.clone(),
        "attenuation": metrics.attenuation.clone(),
        "attenuation_len": metrics.attenuation_len.clone(),
        "publish": parts.fanout_publish_ms.clone(),
        "publish_qos_0": parts.fanout_publish_by_qos[0].clone(),
        "publish_qos_1": parts.fanout_publish_by_qos[1].clone(),
        "publish_qos_2": parts.fanout_publish_by_qos[2].clone(),
        "receive": metrics.receive.clone(),
        "control": [],
        "control_injection_delay": [],
        "sync_connect_barrier_wait": [],
    });
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
        proactive_refresh: Summary::default(),
        proactive_refresh_len: Summary::default(),
        proactive_refresh_attempts: 0,
        proactive_refresh_successes: 0,
        proactive_refresh_failures: 0,
        session_continuity_ok: !args.proactive_refresh,
        expiry_denial_count: 0,
        delegation: summarize(&metrics.delegation),
        delegation_len: summarize(&metrics.delegation_len),
        delegation_handoff_publish: summarize(&parts.runtime.handoff_publish_ms),
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
        sync_connect: sync_connect_json(args, &[], &[], &parts.runtime.errors),
        reauth_storm: serde_json::json!({"enabled": false}),
        raw_publish_ms: parts.fanout_publish_ms,
        raw_metrics,
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

async fn run_fanout_subscriber(args: Args) -> Result<Output> {
    let start = Instant::now();
    let ready_dir = fanout_ready_dir(&args)?;
    let mut runtime = init_fanout_runtime(&args).await;
    let qos_distribution = QosDistribution::parse(args.qos_distribution.as_deref())?;
    let subscribe_qos = qos_distribution
        .as_ref()
        .map_or(args.qos, QosDistribution::subscribe_qos);
    let token_refresh_codes = parse_token_refresh_codes(args.token_refresh_codes.as_deref())?;
    let mut subscribers = build_fanout_subscribers(&args, &mut runtime, subscribe_qos).await;
    let ready_subscribers = count_ready_fanout_subscribers(&subscribers);
    if ready_subscribers != 1 {
        runtime
            .errors
            .push("fanout_subscribe_ready_timeout".to_string());
    } else {
        let client_id = client_id_for(&args, 0);
        if let Err(err) = write_fanout_ready(&ready_dir, &client_id) {
            runtime
                .errors
                .push(format!("fanout_ready_write_failed:{err}"));
        }
    }

    let publishing_done = Arc::new(AtomicBool::new(false));
    let done_timeout = Duration::from_secs(
        args.fanout_ready_timeout_seconds.max(1).saturating_add(
            u64::try_from(args.messages)
                .unwrap_or(u64::MAX)
                .saturating_mul(5),
        ),
    );
    let watcher = tokio::spawn(watch_fanout_done_file(
        ready_dir,
        done_timeout,
        Arc::clone(&publishing_done),
    ));
    let results = if ready_subscribers == 1 {
        if let Some(subscriber) = subscribers.pop() {
            vec![
                collect_fanout_subscriber(
                    subscriber,
                    start,
                    args.messages,
                    args.fanout_churn_after_messages,
                    Arc::clone(&publishing_done),
                )
                .await,
            ]
        } else {
            Vec::new()
        }
    } else {
        subscribers.into_iter().map(|sub| sub.result).collect()
    };
    let done_seen = watcher.await.unwrap_or(false);
    if !done_seen {
        runtime.errors.push("fanout_done_timeout".to_string());
    }

    let duration_s = start.elapsed().as_secs_f64().max(1e-9);
    let mut results = results;
    for result in &mut results {
        runtime.errors.append(&mut result.errors);
    }
    let fanout_publish_by_qos: [Vec<f64>; 3] = Default::default();
    let fanout_publish_ms = Vec::new();
    let churn_state = FanoutChurnState::default();
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

async fn run_fanout_publisher(args: Args) -> Result<Output> {
    let start = Instant::now();
    let ready_dir = fanout_ready_dir(&args)?;
    let mut runtime = FanoutRuntime {
        handoff_plan: None,
        handoff_passwords: HashMap::new(),
        handoff_publish_ms: Vec::new(),
        errors: Vec::new(),
        handoff_required: false,
    };
    let subscriber_ids = (0..args.clients)
        .map(|index| client_id_for(&args, index))
        .collect::<Vec<_>>();
    let ready = wait_for_fanout_ready_files(
        &ready_dir,
        &subscriber_ids,
        Duration::from_secs(args.fanout_ready_timeout_seconds.max(1)),
    )
    .await;
    if !ready {
        runtime
            .errors
            .push("fanout_subscribe_ready_timeout".to_string());
        let _ = write_fanout_done(&ready_dir, 0, &runtime.errors);
    }

    let fallback_password = decode_token_arg(&args.password)?;
    let qos_distribution = QosDistribution::parse(args.qos_distribution.as_deref())?;
    let token_refresh_codes = parse_token_refresh_codes(args.token_refresh_codes.as_deref())?;
    let mut fanout_publish_ms = Vec::new();
    let mut fanout_publish_by_qos: [Vec<f64>; 3] = Default::default();
    let mut churn_state = FanoutChurnState::default();
    if ready {
        let (publisher, mut publisher_eventloop) =
            connect_fanout_publisher(&args, &fallback_password).await?;
        let published = publish_fanout(
            &args,
            start,
            &publisher,
            &mut publisher_eventloop,
            qos_distribution.as_ref(),
            &mut runtime.errors,
        )
        .await;
        fanout_publish_ms = published.0;
        fanout_publish_by_qos = published.1;
        churn_state = published.2;
        let _ = publisher.disconnect().await;
        if let Err(err) = write_fanout_done(&ready_dir, churn_state.applied_events, &runtime.errors)
        {
            runtime
                .errors
                .push(format!("fanout_done_write_failed:{err}"));
        }
    }

    let duration_s = start.elapsed().as_secs_f64().max(1e-9);
    let metrics = fanout_metrics(
        &[],
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
) -> Option<(IssuedToken, bool)> {
    let handoff_password_supplied = handoff_password.is_some();
    let password = if let Some(value) = handoff_password {
        IssuedToken::static_token(value)
    } else if let Some(nonce) = handoff_nonce {
        match receive_handoff_token(args, client_id, nonce).await {
            Ok(value) => IssuedToken::static_token(value),
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

async fn fetch_worker_token(
    args: &Args,
    kind: &str,
    client_id: &str,
    topic: &str,
    result: &mut WorkerResult,
) -> Result<IssuedToken> {
    let mut token = fetch_token(args, kind, client_id, topic).await?;
    if !apply_biscuit_transforms(args, client_id, result, &mut token.bytes) {
        let err = result
            .errors
            .last()
            .cloned()
            .unwrap_or_else(|| "biscuit_transform_failed".to_string());
        return Err(MqttHelperError::Message(err));
    }
    refresh_token_expiry(args, &mut token, true)?;
    Ok(token)
}

fn worker_specs(args: &Args, client_id: &str, password: Vec<u8>) -> ClientSpec {
    if args.proactive_refresh {
        return ClientSpec {
            host: args.host.clone(),
            port: args.port,
            client_id: client_id.to_string(),
            username: String::new(),
            password: Vec::new(),
            tls: args.tls,
            tls_ca_file: args.tls_ca_file.clone(),
            tls_insecure: args.tls_insecure,
            auth_method: Some("token".to_string()),
            auth_data: Some(password),
        };
    }
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
    apply_refresh_transforms: bool,
    spec: &mut ClientSpec,
    result: &mut WorkerResult,
) -> Option<(AsyncClient, rumqttc::EventLoop, ConnectReport, Option<i64>)> {
    let mut current_exp = None;
    loop {
        let connect_result = match connect(spec).await {
            Ok(value) => value,
            Err(err) => {
                result.errors.push(format!("connect_failed:{err}"));
                return None;
            }
        };
        if connect_result.2.connect_ok {
            return Some((
                connect_result.0,
                connect_result.1,
                connect_result.2,
                current_exp,
            ));
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
        let refreshed = if apply_refresh_transforms {
            fetch_worker_token(args, &kind, client_id, topic, result).await
        } else {
            fetch_token(args, &kind, client_id, topic).await
        };
        match refreshed {
            Ok(refreshed) => {
                result.token_refresh_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
                result.token_refresh_len = Some(usize_as_f64(refreshed.bytes.len()));
                current_exp = refreshed.exp;
                if args.proactive_refresh {
                    spec.auth_data = Some(refreshed.bytes);
                } else {
                    spec.password = refreshed.bytes;
                }
            }
            Err(err) => {
                result.errors.push(format!("token_refresh_failed:{err}"));
                return None;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn perform_proactive_reauth(
    args: &Args,
    client_id: &str,
    topic: &str,
    client: &AsyncClient,
    current_exp: &mut Option<i64>,
    result: &mut WorkerResult,
    shutdown: Option<&Notify>,
    apply_refresh_transforms: bool,
    reauth_storm: Option<&ReauthStormGate>,
) -> bool {
    if !args.proactive_refresh {
        return true;
    }
    if args.token_issuer_url.is_none() {
        result
            .errors
            .push("proactive_refresh_failed:token_issuer_url_required".to_string());
        result.proactive_refresh_failures += 1;
        return false;
    }
    let Some(kind) = resolved_token_issuer_kind(args) else {
        result
            .errors
            .push("proactive_refresh_failed:token_kind_required".to_string());
        result.proactive_refresh_failures += 1;
        return false;
    };
    if let Some(gate) = reauth_storm {
        let timeout = Duration::from_secs(args.proactive_refresh_timeout_seconds.max(1));
        if !gate.wait(timeout).await {
            result.proactive_refresh_failures += 1;
            result
                .errors
                .push("proactive_refresh_failed:reauth_storm_barrier_timeout".to_string());
            return false;
        }
    }
    result.proactive_refresh_attempts += 1;
    result.proactive_refresh_attempt_unix_ms.push(unix_ms_now());
    let started = Instant::now();
    let refreshed = if apply_refresh_transforms {
        fetch_worker_token(args, &kind, client_id, topic, result).await
    } else {
        fetch_token(args, &kind, client_id, topic).await
    };
    let refreshed = match refreshed {
        Ok(token) => token,
        Err(err) => {
            result.proactive_refresh_failures += 1;
            result
                .errors
                .push(format!("proactive_refresh_failed:{err}"));
            return false;
        }
    };
    let token_len = refreshed.bytes.len();
    let props = AuthProperties {
        method: Some("token".to_string()),
        data: Some(bytes::Bytes::from(refreshed.bytes)),
        reason: None,
        user_properties: Vec::new(),
    };
    let notice = match client.reauth_tracked(Some(props)).await {
        Ok(notice) => notice,
        Err(err) => {
            result.proactive_refresh_failures += 1;
            result
                .errors
                .push(format!("proactive_refresh_failed:reauth_send:{err}"));
            return false;
        }
    };
    let timeout = Duration::from_secs(args.proactive_refresh_timeout_seconds.max(1));
    let wait_reauth = async {
        if let Some(shutdown) = shutdown {
            tokio::select! {
                result = notice.wait_async() => result.map(|_| ()).map_err(|err| err.to_string()),
                () = shutdown.notified() => Err("reauth_cancelled".to_string()),
            }
        } else {
            notice
                .wait_async()
                .await
                .map(|_| ())
                .map_err(|err| err.to_string())
        }
    };
    let outcome = tokio::select! {
        result = wait_reauth => result,
        () = tokio::time::sleep(timeout) => Err("reauth_timeout".to_string()),
    };
    match outcome {
        Ok(()) => {
            result
                .proactive_refresh_ms
                .push(started.elapsed().as_secs_f64() * 1000.0);
            result.proactive_refresh_len.push(usize_as_f64(token_len));
            result.proactive_refresh_successes += 1;
            *current_exp = refreshed.exp;
            true
        }
        Err(err) if err == "reauth_cancelled" => true,
        Err(err) => {
            result.proactive_refresh_failures += 1;
            if expiry_denial_error(&err) {
                result.expiry_denial_count += 1;
            }
            result
                .errors
                .push(format!("proactive_refresh_failed:reauth:{err}"));
            false
        }
    }
}

async fn drive_worker_eventloop(
    mut eventloop: rumqttc::EventLoop,
    shutdown: Arc<Notify>,
    shutdown_requested: Arc<AtomicBool>,
) -> Option<String> {
    loop {
        if shutdown_requested.load(Ordering::Acquire) {
            return None;
        }
        tokio::select! {
            () = shutdown.notified() => return None,
            result = eventloop.poll() => {
                if let Err(err) = result {
                    return Some(format!("eventloop_failed:{err}"));
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_proactive_refresh_timer(
    args: Args,
    client_id: String,
    topic: String,
    client: AsyncClient,
    mut current_exp: Option<i64>,
    shutdown: Arc<Notify>,
    shutdown_requested: Arc<AtomicBool>,
    first_attempt_notify: Arc<Notify>,
    first_attempt_observed: Arc<AtomicBool>,
    apply_refresh_transforms: bool,
    reauth_storm: Option<Arc<ReauthStormGate>>,
) -> WorkerResult {
    let mut result = WorkerResult::default();
    if !args.proactive_refresh {
        return result;
    }
    loop {
        if shutdown_requested.load(Ordering::Acquire) {
            return result;
        }
        let now = match unix_timestamp_now() {
            Ok(now) => now,
            Err(_) => {
                result
                    .errors
                    .push("proactive_refresh_failed:timestamp_unavailable".to_string());
                result.proactive_refresh_failures += 1;
                return result;
            }
        };
        let Some(delay) =
            proactive_refresh_delay(current_exp, args.proactive_refresh_margin_seconds, now)
        else {
            return result;
        };
        tokio::select! {
            () = shutdown.notified() => return result,
            () = tokio::time::sleep(delay) => {}
        }
        if shutdown_requested.load(Ordering::Acquire) {
            return result;
        }
        let refresh_ok = perform_proactive_reauth(
            &args,
            &client_id,
            &topic,
            &client,
            &mut current_exp,
            &mut result,
            Some(&shutdown),
            apply_refresh_transforms,
            reauth_storm.as_deref(),
        )
        .await;
        first_attempt_observed.store(true, Ordering::Release);
        first_attempt_notify.notify_waiters();
        if !refresh_ok {
            return result;
        }
    }
}

fn merge_proactive_result(result: &mut WorkerResult, proactive: &mut WorkerResult) {
    result
        .proactive_refresh_ms
        .append(&mut proactive.proactive_refresh_ms);
    result
        .proactive_refresh_len
        .append(&mut proactive.proactive_refresh_len);
    result.proactive_refresh_attempts += proactive.proactive_refresh_attempts;
    result.proactive_refresh_successes += proactive.proactive_refresh_successes;
    result.proactive_refresh_failures += proactive.proactive_refresh_failures;
    result
        .proactive_refresh_attempt_unix_ms
        .append(&mut proactive.proactive_refresh_attempt_unix_ms);
    result.expiry_denial_count += proactive.expiry_denial_count;
    result.errors.append(&mut proactive.errors);
}

async fn run_control_mode(
    args: &Args,
    client: &AsyncClient,
    control_topic: Option<&str>,
    control_payload: &[u8],
    result: &mut WorkerResult,
) {
    if let Some(control_topic) = control_topic {
        for _ in 0..args.control_repeat {
            match publish_tracked_and_wait(
                client,
                control_topic,
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
    plan: WorkerPublishPlan<'_>,
    runtime_control: Option<&RuntimeControlState>,
    result: &mut WorkerResult,
) {
    let mut since_control = 0usize;
    let external_runtime_control = match external_runtime_control_barrier(args) {
        Ok(barrier) => barrier,
        Err(err) => {
            result
                .errors
                .push(format!("runtime_control_barrier_config_failed:{err}"));
            return;
        }
    };
    let mut local_successful_publishes = 0usize;
    let mut external_policy_applied = false;
    if let Some((barrier, 0)) = external_runtime_control.as_ref() {
        match wait_external_sync_barrier(barrier).await {
            Ok(_) => external_policy_applied = true,
            Err(err) => {
                result
                    .errors
                    .push(format!("runtime_control_barrier_failed:{err}"));
                return;
            }
        }
    }
    for _ in 0..args.messages {
        let publish_qos = plan
            .qos_distribution
            .map_or(args.qos, QosDistribution::choose);
        match publish_tracked_and_wait(client, plan.topic, plan.data_payload.to_vec(), publish_qos)
            .await
        {
            Ok(ms) => {
                result.publish_ms.push(ms);
                if let Some(bucket) = result.publish_by_qos.get_mut(usize::from(publish_qos)) {
                    bucket.push(ms);
                }
                if let Some(runtime_control) = runtime_control {
                    let total = runtime_control
                        .successful_publishes
                        .fetch_add(1, Ordering::AcqRel)
                        + 1;
                    runtime_control.progress.notify_waiters();
                    if total >= args.runtime_control_after_messages {
                        while !runtime_control.applied.load(Ordering::Acquire) {
                            let notified = runtime_control.progress.notified();
                            if runtime_control.applied.load(Ordering::Acquire) {
                                break;
                            }
                            notified.await;
                        }
                    }
                }
                local_successful_publishes += 1;
                if let Some((barrier, local_after_messages)) = external_runtime_control.as_ref()
                    && !external_policy_applied
                    && local_successful_publishes >= *local_after_messages
                {
                    match wait_external_sync_barrier(barrier).await {
                        Ok(_) => external_policy_applied = true,
                        Err(err) => {
                            result
                                .errors
                                .push(format!("runtime_control_barrier_failed:{err}"));
                            return;
                        }
                    }
                }
            }
            Err(err) => {
                if args.runtime_control_expect_denial
                    && (runtime_control.is_some_and(|state| state.applied.load(Ordering::Acquire))
                        || external_policy_applied)
                    && expiry_denial_error(&err.to_string())
                {
                    result.policy_denial_count += 1;
                } else {
                    result.errors.push(format!("publish_failed:{err}"));
                }
                break;
            }
        }
        since_control += 1;
        if control_injection_due(since_control, args.control_after_messages) {
            if let Some(topic) = plan.control_topic {
                let start = Instant::now();
                match publish_tracked_and_wait(
                    client,
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
    }
}

const fn control_injection_due(messages_since_control: usize, after_messages: usize) -> bool {
    after_messages > 0 && messages_since_control >= after_messages
}

async fn run_worker_session(
    args: &Args,
    client_id: &str,
    topic: &str,
    qos_distribution: Option<&QosDistribution>,
    client: &AsyncClient,
    runtime_control: Option<&RuntimeControlState>,
    result: &mut WorkerResult,
) {
    let control_topic = args
        .runtime_control_username
        .is_none()
        .then(|| {
            args.control_topic
                .as_deref()
                .map(|topic| expand_client_template(topic, client_id))
        })
        .flatten();
    let control_payload = expand_control_payload(&load_control_payload(args, result), client_id);
    let data_payload = vec![b'A'; args.message_size];
    if args.control_mode {
        run_control_mode(
            args,
            client,
            control_topic.as_deref(),
            &control_payload,
            result,
        )
        .await;
    } else {
        run_publish_mode(
            args,
            client,
            WorkerPublishPlan {
                topic,
                control_topic: control_topic.as_deref(),
                control_payload: &control_payload,
                data_payload: &data_payload,
                qos_distribution,
            },
            runtime_control,
            result,
        )
        .await;
    }
}

async fn wait_for_proactive_assertion_attempt(
    args: &Args,
    current_exp: Option<i64>,
    first_attempt_notify: &Notify,
    first_attempt_observed: &AtomicBool,
) {
    if !args.proactive_refresh_assert_continuity || first_attempt_observed.load(Ordering::Acquire) {
        return;
    }
    let timeout = proactive_assertion_wait_timeout(args, current_exp);
    let wait = async {
        loop {
            let notified = first_attempt_notify.notified();
            if first_attempt_observed.load(Ordering::Acquire) {
                break;
            }
            notified.await;
        }
    };
    let _ = tokio::time::timeout(timeout, wait).await;
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
        reauth_storm,
        runtime_control,
    } = job;
    let mut result = WorkerResult::default();
    let mut publish_gate_participant = PublishGateParticipant::new(publish_gate);
    let client_id = client_id_for(&args, index);
    let topic = expand_client_template(&args.topic, &client_id);
    result.delegation_ms = bootstrap.delegation_ms;
    result.delegation_len = bootstrap.delegation_len;
    result.attenuation_ms = bootstrap.attenuation_ms;
    result.attenuation_len = bootstrap.attenuation_len;
    let Some((issued_token, handoff_password_supplied)) = resolve_worker_password(
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
    let mut issued_token = issued_token;
    let mut password = issued_token.bytes;
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
    let apply_refresh_transforms = should_apply_worker_biscuit_transforms(
        handoff_nonce.as_deref(),
        handoff_password_supplied,
        handoff_required,
    );
    if apply_refresh_transforms
        && !apply_biscuit_transforms(&args, &client_id, &mut result, &mut password)
    {
        return result;
    }
    issued_token.bytes = password.clone();
    if let Err(err) = refresh_token_expiry(&args, &mut issued_token, apply_refresh_transforms) {
        result
            .errors
            .push(format!("startup_token_expiry_failed:{err}"));
        return result;
    }
    let mut current_exp = issued_token.exp;
    let mut spec = worker_specs(&args, &client_id, password.clone());
    match external_sync_barrier(&args) {
        Ok(Some(barrier)) => match wait_external_sync_barrier(&barrier).await {
            Ok(report) => {
                result.sync_barrier_wait_ms = Some(report.wait_ms);
                result.sync_barrier_released_at_unix_ms = report.status.released_at_unix_ms;
            }
            Err(err) => {
                result.errors.push(format!("sync_barrier_failed:{err}"));
                return result;
            }
        },
        Ok(None) => {
            if let Some(sync_connect) = sync_connect {
                sync_connect.wait().await;
            }
        }
        Err(err) => {
            result
                .errors
                .push(format!("sync_barrier_config_failed:{err}"));
            return result;
        }
    }
    let Some((client, eventloop, report, refreshed_exp)) = connect_worker(
        &args,
        &client_id,
        &topic,
        &token_refresh_codes,
        apply_refresh_transforms,
        &mut spec,
        &mut result,
    )
    .await
    else {
        return result;
    };
    if refreshed_exp.is_some() {
        current_exp = refreshed_exp;
    }
    result.connect_ms = Some(report.connect_ms);

    if let Some(gate) = publish_gate_participant.mark_ready() {
        gate.wait_released().await;
    }

    let shutdown = Arc::new(Notify::new());
    let shutdown_requested = Arc::new(AtomicBool::new(false));
    let first_attempt_notify = Arc::new(Notify::new());
    let first_attempt_observed = Arc::new(AtomicBool::new(false));
    let eventloop_task = tokio::spawn(drive_worker_eventloop(
        eventloop,
        Arc::clone(&shutdown),
        Arc::clone(&shutdown_requested),
    ));
    let proactive_task = tokio::spawn(run_proactive_refresh_timer(
        args.clone(),
        client_id.clone(),
        topic.clone(),
        client.clone(),
        current_exp,
        Arc::clone(&shutdown),
        Arc::clone(&shutdown_requested),
        Arc::clone(&first_attempt_notify),
        Arc::clone(&first_attempt_observed),
        apply_refresh_transforms,
        reauth_storm.clone(),
    ));

    run_worker_session(
        &args,
        &client_id,
        &topic,
        qos_distribution.as_ref(),
        &client,
        runtime_control.as_deref(),
        &mut result,
    )
    .await;
    wait_for_proactive_assertion_attempt(
        &args,
        current_exp,
        &first_attempt_notify,
        &first_attempt_observed,
    )
    .await;
    let _ = client.disconnect().await;
    shutdown_requested.store(true, Ordering::Release);
    shutdown.notify_waiters();
    match proactive_task.await {
        Ok(mut proactive_result) => merge_proactive_result(&mut result, &mut proactive_result),
        Err(err) => result
            .errors
            .push(format!("proactive_refresh_join_failed:{err}")),
    }
    match eventloop_task.await {
        Ok(Some(err)) => result.errors.push(err),
        Ok(None) => {}
        Err(err) => result.errors.push(format!("eventloop_join_failed:{err}")),
    }
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
    handoff_publish_ms: Vec<f64>,
    handoff_errors: Vec<String>,
) -> StandardMetrics {
    let connect = results.iter().filter_map(|r| r.connect_ms).collect();
    let token_refresh = results.iter().filter_map(|r| r.token_refresh_ms).collect();
    let token_refresh_len = results.iter().filter_map(|r| r.token_refresh_len).collect();
    let proactive_refresh = results
        .iter()
        .flat_map(|r| r.proactive_refresh_ms.clone())
        .collect();
    let proactive_refresh_len = results
        .iter()
        .flat_map(|r| r.proactive_refresh_len.clone())
        .collect();
    let proactive_refresh_attempts = results.iter().map(|r| r.proactive_refresh_attempts).sum();
    let proactive_refresh_successes = results.iter().map(|r| r.proactive_refresh_successes).sum();
    let proactive_refresh_failures = results.iter().map(|r| r.proactive_refresh_failures).sum();
    let proactive_refresh_attempt_unix_ms = results
        .iter()
        .flat_map(|r| r.proactive_refresh_attempt_unix_ms.clone())
        .collect();
    let expiry_denial_count = results.iter().map(|r| r.expiry_denial_count).sum();
    let policy_denial_count = results.iter().map(|r| r.policy_denial_count).sum();
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
    let sync_barrier_wait = results
        .iter()
        .filter_map(|r| r.sync_barrier_wait_ms)
        .collect();
    let sync_barrier_released_at_unix_ms = results
        .iter()
        .filter_map(|r| r.sync_barrier_released_at_unix_ms)
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
        proactive_refresh,
        proactive_refresh_len,
        proactive_refresh_attempts,
        proactive_refresh_successes,
        proactive_refresh_failures,
        proactive_refresh_attempt_unix_ms,
        expiry_denial_count,
        policy_denial_count,
        runtime_control_connect_ms: None,
        delegation,
        delegation_len,
        delegation_handoff_publish: handoff_publish_ms,
        attenuation,
        attenuation_len,
        publish,
        publish_qos_0,
        publish_qos_1,
        publish_qos_2,
        receive,
        control,
        control_injection,
        sync_barrier_wait,
        sync_barrier_released_at_unix_ms,
        errors,
    }
}

fn merge_runtime_control_result(metrics: &mut StandardMetrics, result: WorkerResult) {
    metrics.runtime_control_connect_ms = result.connect_ms;
    metrics.control.extend(result.control_ms);
    metrics.errors.extend(result.errors);
}

fn max_timestamp_skew_ms(values: &[u128]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let min = values.iter().min().copied().unwrap_or_default();
    let max = values.iter().max().copied().unwrap_or_default();
    Some(max.saturating_sub(min) as f64)
}

fn reauth_storm_json(args: &Args, metrics: &StandardMetrics, session_continuity_ok: bool) -> Value {
    if !args.reauth_storm {
        return serde_json::json!({"enabled": false});
    }
    serde_json::json!({
        "enabled": true,
        "clients": args.clients,
        "attempts": metrics.proactive_refresh_attempts,
        "successes": metrics.proactive_refresh_successes,
        "failures": metrics.proactive_refresh_failures,
        "max_refresh_skew_ms": max_timestamp_skew_ms(&metrics.proactive_refresh_attempt_unix_ms),
        "session_continuity_ok": session_continuity_ok,
    })
}

fn standard_output(
    args: &Args,
    qos_distribution: Option<&QosDistribution>,
    token_refresh_codes: &[u16],
    handoff_nonce: Option<&str>,
    metrics: StandardMetrics,
) -> Output {
    let session_continuity_ok = !args.proactive_refresh
        || (metrics.proactive_refresh_attempts > 0
            && metrics.proactive_refresh_failures == 0
            && metrics.expiry_denial_count == 0);
    let raw_metrics = serde_json::json!({
        "connect": metrics.connect.clone(),
        "token_refresh": metrics.token_refresh.clone(),
        "token_refresh_len": metrics.token_refresh_len.clone(),
        "proactive_refresh": metrics.proactive_refresh.clone(),
        "proactive_refresh_len": metrics.proactive_refresh_len.clone(),
        "proactive_refresh_attempt_unix_ms": metrics.proactive_refresh_attempt_unix_ms.clone(),
        "policy_denial_count": metrics.policy_denial_count,
        "runtime_control_connect_ms": metrics.runtime_control_connect_ms,
        "delegation": metrics.delegation.clone(),
        "delegation_len": metrics.delegation_len.clone(),
        "delegation_handoff_publish": metrics.delegation_handoff_publish.clone(),
        "attenuation": metrics.attenuation.clone(),
        "attenuation_len": metrics.attenuation_len.clone(),
        "publish": metrics.publish.clone(),
        "publish_qos_0": metrics.publish_qos_0.clone(),
        "publish_qos_1": metrics.publish_qos_1.clone(),
        "publish_qos_2": metrics.publish_qos_2.clone(),
        "receive": metrics.receive.clone(),
        "control": metrics.control.clone(),
        "control_injection_delay": metrics.control_injection.clone(),
        "sync_connect_barrier_wait": metrics.sync_barrier_wait.clone(),
    });
    let sync_connect = sync_connect_json(
        args,
        &metrics.sync_barrier_wait,
        &metrics.sync_barrier_released_at_unix_ms,
        &metrics.errors,
    );
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
        proactive_refresh: summarize(&metrics.proactive_refresh),
        proactive_refresh_len: summarize(&metrics.proactive_refresh_len),
        proactive_refresh_attempts: metrics.proactive_refresh_attempts,
        proactive_refresh_successes: metrics.proactive_refresh_successes,
        proactive_refresh_failures: metrics.proactive_refresh_failures,
        session_continuity_ok,
        expiry_denial_count: metrics.expiry_denial_count,
        delegation: summarize(&metrics.delegation),
        delegation_len: summarize(&metrics.delegation_len),
        delegation_handoff_publish: summarize(&metrics.delegation_handoff_publish),
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
        sync_connect,
        reauth_storm: reauth_storm_json(args, &metrics, session_continuity_ok),
        raw_publish_ms: metrics.publish,
        raw_metrics,
        errors: metrics.errors,
    }
}

async fn wait_for_runtime_control_threshold(state: &RuntimeControlState, threshold: usize) -> bool {
    while state.successful_publishes.load(Ordering::Acquire) < threshold
        && !state.publishers_finished.load(Ordering::Acquire)
    {
        let notified = state.progress.notified();
        if state.successful_publishes.load(Ordering::Acquire) >= threshold
            || state.publishers_finished.load(Ordering::Acquire)
        {
            break;
        }
        notified.await;
    }
    state.successful_publishes.load(Ordering::Acquire) >= threshold
}

async fn spawn_runtime_control(
    args: &Args,
    state: Arc<RuntimeControlState>,
) -> Result<tokio::task::JoinHandle<WorkerResult>> {
    let username = args.runtime_control_username.as_deref().ok_or_else(|| {
        MqttHelperError::Message("runtime control username is required".to_string())
    })?;
    let password = args.runtime_control_password.as_deref().ok_or_else(|| {
        MqttHelperError::Message("runtime control password is required".to_string())
    })?;
    let topic = args
        .control_topic
        .as_deref()
        .ok_or_else(|| MqttHelperError::Message("runtime control topic is required".to_string()))?;
    if args.runtime_control_after_messages == 0 {
        return Err(MqttHelperError::Message(
            "runtime control after-messages must be greater than zero".to_string(),
        ));
    }

    let mut payload_result = WorkerResult::default();
    let payload = load_control_payload(args, &mut payload_result);
    if !payload_result.errors.is_empty() {
        return Err(MqttHelperError::Message(payload_result.errors.join(",")));
    }
    let spec = ClientSpec {
        host: args.host.clone(),
        port: args.port,
        client_id: "runtime-dynsec-controller".to_string(),
        username: username.to_string(),
        password: decode_token_arg(password)?,
        tls: args.tls,
        tls_ca_file: args.tls_ca_file.clone(),
        tls_insecure: args.tls_insecure,
        auth_method: None,
        auth_data: None,
    };
    let (client, eventloop, report) = connect(&spec).await?;
    if !report.connect_ok {
        return Err(MqttHelperError::Message(format!(
            "runtime control connect rejected with reason {:?}",
            report.connect_reason
        )));
    }

    let topic = topic.to_string();
    let control_qos = args.control_qos;
    let threshold = args.runtime_control_after_messages;
    Ok(tokio::spawn(async move {
        let mut result = WorkerResult {
            connect_ms: Some(report.connect_ms),
            ..WorkerResult::default()
        };
        let shutdown = Arc::new(Notify::new());
        let shutdown_requested = Arc::new(AtomicBool::new(false));
        let eventloop_task = tokio::spawn(drive_worker_eventloop(
            eventloop,
            Arc::clone(&shutdown),
            Arc::clone(&shutdown_requested),
        ));

        if wait_for_runtime_control_threshold(&state, threshold).await {
            match publish_tracked_and_wait(&client, &topic, payload, control_qos).await {
                Ok(ms) => result.control_ms.push(ms),
                Err(err) => result
                    .errors
                    .push(format!("runtime_control_publish_failed:{err}")),
            }
        } else {
            let successful_publishes = state.successful_publishes.load(Ordering::Acquire);
            result.errors.push(format!(
                "runtime_control_threshold_unreachable:required={threshold},successful={successful_publishes}"
            ));
        }
        state.applied.store(true, Ordering::Release);
        state.progress.notify_waiters();

        let _ = client.disconnect().await;
        shutdown_requested.store(true, Ordering::Release);
        shutdown.notify_waiters();
        match eventloop_task.await {
            Ok(Some(err)) => result.errors.push(err),
            Ok(None) => {}
            Err(err) => result
                .errors
                .push(format!("runtime_control_eventloop_join_failed:{err}")),
        }
        result
    }))
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
    let mut handoff_publish_ms = Vec::new();
    if let Some(plan) = &handoff_plan {
        let (passwords, publish_ms, errors) = receive_handoff_tokens(&args, plan).await;
        handoff_passwords = passwords;
        handoff_publish_ms = publish_ms;
        handoff_errors = errors;
    }
    let mut tasks = Vec::new();
    let sync_connect = args.sync_connect.then(|| Arc::new(SyncConnectGate::new()));
    let publish_gate = (!args.sync_connect).then(|| Arc::new(PublishStartGate::new(args.clients)));
    let reauth_storm = args
        .reauth_storm
        .then(|| Arc::new(ReauthStormGate::new(args.clients)));
    let runtime_control = args
        .runtime_control_username
        .as_ref()
        .map(|_| Arc::new(RuntimeControlState::default()));
    let runtime_control_task = if let Some(state) = &runtime_control {
        Some(spawn_runtime_control(&args, Arc::clone(state)).await?)
    } else {
        None
    };
    for index in 0..args.clients {
        let client_id = client_id_for(&args, index);
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
            reauth_storm: reauth_storm.clone(),
            runtime_control: runtime_control.clone(),
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
    if let Some(state) = &runtime_control {
        state.publishers_finished.store(true, Ordering::Release);
        state.progress.notify_waiters();
    }
    let duration_s = start.elapsed().as_secs_f64().max(1e-9);
    let mut metrics = standard_metrics(
        results,
        duration_s,
        handoff_plan.as_ref(),
        handoff_publish_ms,
        handoff_errors,
    );
    if let Some(task) = runtime_control_task {
        match task.await {
            Ok(result) => merge_runtime_control_result(&mut metrics, result),
            Err(err) => metrics
                .errors
                .push(format!("runtime_control_join_failed:{err}")),
        }
    }
    if args.runtime_control_expect_denial && metrics.policy_denial_count == 0 {
        metrics
            .errors
            .push("runtime_control_expected_policy_denial_not_observed".to_string());
    }
    let output = standard_output(
        &args,
        qos_distribution.as_ref(),
        &token_refresh_codes,
        handoff_nonce.as_deref(),
        metrics,
    );
    validate_proactive_refresh_assertion(&args, &output)?;
    emit_output(&args, &output)
}

fn empty_standard_metrics() -> StandardMetrics {
    StandardMetrics {
        connect: Vec::new(),
        token_refresh: Vec::new(),
        token_refresh_len: Vec::new(),
        proactive_refresh: Vec::new(),
        proactive_refresh_len: Vec::new(),
        proactive_refresh_attempts: 0,
        proactive_refresh_successes: 0,
        proactive_refresh_failures: 0,
        proactive_refresh_attempt_unix_ms: Vec::new(),
        expiry_denial_count: 0,
        policy_denial_count: 0,
        runtime_control_connect_ms: None,
        delegation: Vec::new(),
        delegation_len: Vec::new(),
        delegation_handoff_publish: Vec::new(),
        attenuation: Vec::new(),
        attenuation_len: Vec::new(),
        publish: Vec::new(),
        publish_qos_0: Vec::new(),
        publish_qos_1: Vec::new(),
        publish_qos_2: Vec::new(),
        receive: Vec::new(),
        control: Vec::new(),
        control_injection: Vec::new(),
        sync_barrier_wait: Vec::new(),
        sync_barrier_released_at_unix_ms: Vec::new(),
        errors: Vec::new(),
        publish_throughput_mps: 0.0,
        receive_throughput_mps: 0.0,
    }
}

async fn run_handoff_delegator(
    args: Args,
    qos_distribution: Option<QosDistribution>,
    token_refresh_codes: Vec<u16>,
) -> Result<Output> {
    let start = Instant::now();
    let ready_dir = handoff_ready_dir(&args)?;
    let plan = prepare_handoff(&args, &args.topic).await.ok_or_else(|| {
        MqttHelperError::Message("biscuit delegation handoff plan required".to_string())
    })?;
    let client_ids = (0..args.clients)
        .map(|index| client_id_for(&args, index))
        .collect::<Vec<_>>();
    let mut errors = plan.errors.clone();
    let ready = wait_for_handoff_ready_files(
        &ready_dir,
        &client_ids,
        &plan.nonce,
        Duration::from_secs(args.biscuit_delegate_handoff_ready_timeout_seconds.max(1)),
    )
    .await;
    let publish_ms = if ready {
        match write_handoff_release(&ready_dir, &plan.nonce) {
            Ok(()) => {
                let (publish_ms, publish_errors) =
                    publish_handoff_tokens(&args, &plan.nonce, &plan.tokens).await;
                errors.extend(publish_errors);
                publish_ms
            }
            Err(err) => {
                errors.push(format!("delegation_handoff_release_write_failed:{err}"));
                Vec::new()
            }
        }
    } else {
        errors.push("delegation_handoff_delegatee_ready_timeout".to_string());
        Vec::new()
    };
    let duration_s = start.elapsed().as_secs_f64().max(1e-9);
    let mut metrics = empty_standard_metrics();
    metrics.delegation = plan
        .workers
        .values()
        .filter_map(|worker| worker.delegation_ms)
        .collect();
    metrics.delegation_len = plan
        .workers
        .values()
        .filter_map(|worker| worker.delegation_len)
        .collect();
    metrics.attenuation = plan
        .workers
        .values()
        .filter_map(|worker| worker.attenuation_ms)
        .collect();
    metrics.attenuation_len = plan
        .workers
        .values()
        .filter_map(|worker| worker.attenuation_len)
        .collect();
    metrics.delegation_handoff_publish = publish_ms;
    metrics.publish_throughput_mps =
        usize_as_f64(metrics.delegation_handoff_publish.len()) / duration_s;
    metrics.errors = errors;
    Ok(standard_output(
        &args,
        qos_distribution.as_ref(),
        &token_refresh_codes,
        Some(&plan.nonce),
        metrics,
    ))
}

async fn run_handoff_delegatee(
    args: Args,
    qos_distribution: Option<QosDistribution>,
    token_refresh_codes: Vec<u16>,
) -> Result<Output> {
    let start = Instant::now();
    let ready_dir = handoff_ready_dir(&args)?;
    let nonce = args
        .biscuit_delegate_handoff_nonce
        .clone()
        .ok_or_else(|| MqttHelperError::Message("handoff nonce required".to_string()))?;
    let client_id = client_id_for(&args, 0);
    let mut handoff_password = None;
    let mut setup_errors = Vec::new();
    match subscribe_handoff_receiver(&args, &client_id).await {
        Ok(receiver) => {
            if let Err(err) = write_handoff_ready(&ready_dir, &client_id, &nonce) {
                setup_errors.push(format!("delegation_handoff_ready_write_failed:{err}"));
            } else if !wait_for_handoff_release_file(
                &ready_dir,
                &nonce,
                Duration::from_secs(args.biscuit_delegate_handoff_ready_timeout_seconds.max(1)),
            )
            .await
            {
                setup_errors.push("delegation_handoff_release_timeout".to_string());
            } else {
                match wait_for_handoff_token(
                    receiver,
                    &client_id,
                    &nonce,
                    Duration::from_secs(args.biscuit_delegate_handoff_ready_timeout_seconds.max(1)),
                )
                .await
                {
                    Ok(password) => handoff_password = Some(password),
                    Err(err) => setup_errors.push(format!("delegation_handoff_failed:{err}")),
                }
            }
        }
        Err(err) => setup_errors.push(format!("delegation_handoff_subscribe_failed:{err}")),
    }
    let mut results = Vec::new();
    if let Some(password) = handoff_password {
        let result = run_worker(WorkerInvocation {
            args: args.clone(),
            index: 0,
            bootstrap: WorkerBootstrap::default(),
            handoff_nonce: None,
            handoff_password: Some(password),
            handoff_required: true,
            sync_connect: None,
            publish_gate: None,
            reauth_storm: None,
            runtime_control: None,
        })
        .await;
        results.push(result);
    } else {
        let mut result = WorkerResult::default();
        result.errors.append(&mut setup_errors);
        results.push(result);
    }
    let duration_s = start.elapsed().as_secs_f64().max(1e-9);
    let mut metrics = standard_metrics(results, duration_s, None, Vec::new(), Vec::new());
    metrics.errors.extend(setup_errors);
    Ok(standard_output(
        &args,
        qos_distribution.as_ref(),
        &token_refresh_codes,
        Some(&nonce),
        metrics,
    ))
}

fn emit_output(args: &Args, output: &Output) -> Result<()> {
    let rendered = serde_json::to_string_pretty(output)?;
    if let Some(path) = &args.output_json_file {
        fs::write(path, rendered.as_bytes())?;
    }
    println!("{rendered}");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = Args::parse();
    if let Some(path) = &args.password_map {
        if !path.exists() {
            return Err(MqttHelperError::Message(format!(
                "password-map file does not exist: {}",
                path.display()
            )));
        }
        args.password_map_data = Some(Arc::new(load_password_map(path)?));
    }
    if (args.password_map_profile.is_some() || args.fanout_publisher_password_map_profile.is_some())
        && args.password_map_data.is_none()
    {
        return Err(MqttHelperError::Message(
            "password-map profiles require --password-map".to_string(),
        ));
    }
    apply_legacy_defaults(&mut args);
    validate_startup_provisioning(&args)?;
    let qos_distribution = QosDistribution::parse(args.qos_distribution.as_deref())?;
    let token_refresh_codes = parse_token_refresh_codes(args.token_refresh_codes.as_deref())?;
    if args.mode == "fanout" {
        let output = match args.fanout_role.as_str() {
            "combined" => run_fanout(args.clone()).await?,
            "subscriber" => run_fanout_subscriber(args.clone()).await?,
            "publisher" => run_fanout_publisher(args.clone()).await?,
            other => {
                return Err(MqttHelperError::Message(format!(
                    "unknown fanout_role: {other}"
                )));
            }
        };
        validate_proactive_refresh_assertion(&args, &output)?;
        return emit_output(&args, &output);
    }
    if args.biscuit_delegate_handoff_role == "delegator" {
        let output =
            run_handoff_delegator(args.clone(), qos_distribution, token_refresh_codes).await?;
        validate_proactive_refresh_assertion(&args, &output)?;
        return emit_output(&args, &output);
    }
    if args.biscuit_delegate_handoff_role == "delegatee" {
        let output =
            run_handoff_delegatee(args.clone(), qos_distribution, token_refresh_codes).await?;
        validate_proactive_refresh_assertion(&args, &output)?;
        return emit_output(&args, &output);
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
            proactive_refresh: Summary::default(),
            proactive_refresh_len: Summary::default(),
            proactive_refresh_attempts: 0,
            proactive_refresh_successes: 0,
            proactive_refresh_failures: 0,
            session_continuity_ok: true,
            expiry_denial_count: 0,
            delegation: Summary::default(),
            delegation_len: Summary::default(),
            delegation_handoff_publish: Summary::default(),
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
            sync_connect: serde_json::json!({"enabled": false}),
            reauth_storm: serde_json::json!({"enabled": false}),
            raw_publish_ms: Vec::new(),
            raw_metrics: serde_json::json!({}),
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

    fn empty_standard_metrics() -> StandardMetrics {
        StandardMetrics {
            connect: Vec::new(),
            token_refresh: Vec::new(),
            token_refresh_len: Vec::new(),
            proactive_refresh: Vec::new(),
            proactive_refresh_len: Vec::new(),
            proactive_refresh_attempts: 0,
            proactive_refresh_successes: 0,
            proactive_refresh_failures: 0,
            proactive_refresh_attempt_unix_ms: Vec::new(),
            expiry_denial_count: 0,
            policy_denial_count: 0,
            runtime_control_connect_ms: None,
            delegation: Vec::new(),
            delegation_len: Vec::new(),
            delegation_handoff_publish: Vec::new(),
            attenuation: Vec::new(),
            attenuation_len: Vec::new(),
            publish: Vec::new(),
            publish_qos_0: Vec::new(),
            publish_qos_1: Vec::new(),
            publish_qos_2: Vec::new(),
            receive: Vec::new(),
            control: Vec::new(),
            control_injection: Vec::new(),
            sync_barrier_wait: Vec::new(),
            sync_barrier_released_at_unix_ms: Vec::new(),
            errors: Vec::new(),
            publish_throughput_mps: 0.0,
            receive_throughput_mps: 0.0,
        }
    }

    #[test]
    fn client_index_start_offsets_generated_client_ids() {
        let args = Args::parse_from(["mqtt-loadgen", "--client-index-start", "7"]);

        assert_eq!(client_id_for(&args, 0), "client_7");
        assert_eq!(client_id_for(&args, 2), "client_9");
    }

    #[test]
    fn zero_client_index_start_is_rejected() {
        let args = Args::parse_from(["mqtt-loadgen", "--client-index-start", "0"]);

        assert!(validate_startup_provisioning(&args).is_err());
    }

    #[test]
    fn explicit_client_id_requires_single_client() {
        let valid = Args::parse_from([
            "mqtt-loadgen",
            "--clients",
            "1",
            "--client-id",
            "runtime-dynsec-controller",
        ]);
        let invalid = Args::parse_from([
            "mqtt-loadgen",
            "--clients",
            "2",
            "--client-id",
            "runtime-dynsec-controller",
        ]);

        assert_eq!(client_id_for(&valid, 0), "runtime-dynsec-controller");
        assert!(validate_startup_provisioning(&valid).is_ok());
        assert!(validate_startup_provisioning(&invalid).is_err());
    }

    #[test]
    fn runtime_control_threshold_cannot_exceed_publish_capacity() {
        let args = Args::parse_from([
            "mqtt-loadgen",
            "--clients",
            "2",
            "--messages",
            "3",
            "--runtime-control-username",
            "admin",
            "--runtime-control-after-messages",
            "7",
        ]);

        let err = validate_startup_provisioning(&args)
            .expect_err("threshold above publish capacity should be rejected");
        assert!(
            err.to_string()
                .contains("exceeds configured publish capacity")
        );
    }

    #[test]
    fn interleaved_control_requires_complete_reachable_configuration() {
        for args in [
            Args::parse_from([
                "mqtt-loadgen",
                "--messages",
                "10",
                "--control-after-messages",
                "10",
                "--control-payload",
                "{}",
            ]),
            Args::parse_from([
                "mqtt-loadgen",
                "--messages",
                "10",
                "--control-after-messages",
                "10",
                "--control-topic",
                "control/topic",
            ]),
            Args::parse_from([
                "mqtt-loadgen",
                "--messages",
                "9",
                "--control-after-messages",
                "10",
                "--control-topic",
                "control/topic",
                "--control-payload",
                "{}",
            ]),
        ] {
            assert!(validate_startup_provisioning(&args).is_err());
        }

        let valid = Args::parse_from([
            "mqtt-loadgen",
            "--messages",
            "10",
            "--control-after-messages",
            "10",
            "--control-topic",
            "control/topic",
            "--control-payload",
            "{}",
        ]);
        assert!(validate_startup_provisioning(&valid).is_ok());
    }

    #[test]
    fn interleaved_control_is_due_on_the_nth_message() {
        assert!(!control_injection_due(9, 10));
        assert!(control_injection_due(10, 10));
        assert!(!control_injection_due(10, 0));
    }

    #[test]
    fn runtime_control_expected_denial_requires_post_control_publish_capacity() {
        let denied = Args::parse_from([
            "mqtt-loadgen",
            "--clients",
            "2",
            "--messages",
            "3",
            "--runtime-control-username",
            "admin",
            "--runtime-control-after-messages",
            "6",
            "--runtime-control-expect-denial",
        ]);
        let allowed = Args::parse_from([
            "mqtt-loadgen",
            "--clients",
            "2",
            "--messages",
            "3",
            "--runtime-control-username",
            "admin",
            "--runtime-control-after-messages",
            "6",
        ]);

        let err = validate_startup_provisioning(&denied)
            .expect_err("expected-denial mode must reserve a post-control publish");
        assert!(err.to_string().contains("requires after-messages"));
        assert!(validate_startup_provisioning(&allowed).is_ok());
    }

    #[test]
    fn external_runtime_control_requires_complete_single_client_configuration() {
        let incomplete = Args::parse_from([
            "mqtt-loadgen",
            "--runtime-control-barrier-url",
            "http://sync-barrier:8083",
        ]);
        assert!(external_runtime_control_barrier(&incomplete).is_err());

        let valid = Args::parse_from([
            "mqtt-loadgen",
            "--clients",
            "1",
            "--messages",
            "3",
            "--runtime-control-barrier-url",
            "http://sync-barrier:8083",
            "--runtime-control-run-id",
            "run-1",
            "--runtime-control-participant-id",
            "client_1",
            "--runtime-control-participants",
            "2",
            "--runtime-control-local-after-messages",
            "1",
        ]);
        assert!(external_runtime_control_barrier(&valid).unwrap().is_some());

        let invalid_quota = Args::parse_from([
            "mqtt-loadgen",
            "--clients",
            "1",
            "--messages",
            "3",
            "--runtime-control-barrier-url",
            "http://sync-barrier:8083",
            "--runtime-control-run-id",
            "run-1",
            "--runtime-control-participant-id",
            "client_1",
            "--runtime-control-participants",
            "2",
            "--runtime-control-local-after-messages",
            "4",
        ]);
        assert!(external_runtime_control_barrier(&invalid_quota).is_err());
    }

    #[test]
    fn runtime_controller_is_excluded_from_worker_connection_metrics() {
        let workers = vec![
            WorkerResult {
                connect_ms: Some(1.0),
                ..WorkerResult::default()
            },
            WorkerResult {
                connect_ms: Some(2.0),
                ..WorkerResult::default()
            },
        ];
        let mut metrics = standard_metrics(workers, 1.0, None, Vec::new(), Vec::new());
        merge_runtime_control_result(
            &mut metrics,
            WorkerResult {
                connect_ms: Some(99.0),
                control_ms: vec![3.0],
                errors: vec!["controller-warning".to_string()],
                ..WorkerResult::default()
            },
        );

        assert_eq!(metrics.connect, vec![1.0, 2.0]);
        assert_eq!(metrics.runtime_control_connect_ms, Some(99.0));
        assert_eq!(metrics.control, vec![3.0]);
        assert_eq!(metrics.errors, vec!["controller-warning"]);
    }

    #[tokio::test]
    async fn runtime_control_wait_can_be_released_when_publishers_finish_early() {
        let state = Arc::new(RuntimeControlState::default());
        let waiting_state = Arc::clone(&state);
        let waiter =
            tokio::spawn(
                async move { wait_for_runtime_control_threshold(&waiting_state, 2).await },
            );

        state.successful_publishes.store(1, Ordering::Release);
        state.publishers_finished.store(true, Ordering::Release);
        state.progress.notify_waiters();

        let reached = tokio::time::timeout(Duration::from_millis(100), waiter)
            .await
            .expect("runtime control waiter should stop")
            .expect("runtime control waiter should not panic");
        assert!(!reached);
    }

    #[test]
    fn external_sync_barrier_requires_single_client_and_complete_config() {
        let incomplete = Args::parse_from([
            "mqtt-loadgen",
            "--sync-connect",
            "--sync-connect-barrier-url",
            "http://sync-barrier:8083",
        ]);
        assert!(external_sync_barrier(&incomplete).is_err());

        let multi_client = Args::parse_from([
            "mqtt-loadgen",
            "--sync-connect",
            "--clients",
            "2",
            "--sync-connect-barrier-url",
            "http://sync-barrier:8083",
            "--sync-connect-run-id",
            "run-1",
            "--sync-connect-participant-id",
            "client_1",
            "--sync-connect-participants",
            "2",
        ]);
        assert!(external_sync_barrier(&multi_client).is_err());

        let valid = Args::parse_from([
            "mqtt-loadgen",
            "--sync-connect",
            "--clients",
            "1",
            "--sync-connect-barrier-url",
            "http://sync-barrier:8083",
            "--sync-connect-run-id",
            "run-1",
            "--sync-connect-participant-id",
            "client_1",
            "--sync-connect-participants",
            "2",
        ]);
        assert!(external_sync_barrier(&valid).unwrap().is_some());
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
    fn split_handoff_receive_timeout_uses_configured_timeout() {
        let args = Args::parse_from([
            "mqtt-loadgen",
            "--clients",
            "1",
            "--biscuit-delegate",
            "--biscuit-delegate-handoff",
            "--biscuit-delegate-handoff-role",
            "delegatee",
            "--biscuit-delegate-handoff-nonce",
            "run-1",
            "--biscuit-delegate-handoff-ready-dir",
            "/tmp/handoff-ready",
            "--biscuit-delegate-handoff-ready-timeout-seconds",
            "37",
        ]);

        assert_eq!(args.biscuit_delegate_handoff_ready_timeout_seconds, 37);
        assert!(validate_startup_provisioning(&args).is_ok());
    }

    #[tokio::test]
    async fn handoff_readiness_requires_current_nonce_and_client_id() {
        let mut ready_dir = std::env::temp_dir();
        ready_dir.push(format!("mqtt-loadgen-handoff-ready-{}", fill_nonce()));
        fs::create_dir_all(&ready_dir).expect("ready dir should be created");
        let client_ids = vec!["client_1".to_string()];

        write_handoff_ready(&ready_dir, "client_1", "old-run")
            .expect("stale ready file should be written");
        assert!(
            !wait_for_handoff_ready_files(
                &ready_dir,
                &client_ids,
                "new-run",
                Duration::from_millis(1),
            )
            .await
        );

        fs::write(
            handoff_ready_path(&ready_dir, "client_1"),
            br#"{"client_id":"client_2","nonce":"new-run","ready":true}"#,
        )
        .expect("wrong-client ready file should be written");
        assert!(
            !wait_for_handoff_ready_files(
                &ready_dir,
                &client_ids,
                "new-run",
                Duration::from_millis(1),
            )
            .await
        );

        write_handoff_ready(&ready_dir, "client_1", "new-run")
            .expect("current ready file should be written");
        assert!(
            wait_for_handoff_ready_files(
                &ready_dir,
                &client_ids,
                "new-run",
                Duration::from_millis(1),
            )
            .await
        );

        let _ = fs::remove_dir_all(ready_dir);
    }

    #[tokio::test]
    async fn handoff_release_requires_current_nonce() {
        let mut ready_dir = std::env::temp_dir();
        ready_dir.push(format!("mqtt-loadgen-handoff-release-{}", fill_nonce()));
        fs::create_dir_all(&ready_dir).expect("ready dir should be created");
        fs::write(
            handoff_release_path(&ready_dir),
            br#"{"nonce":"old-run","release":true}"#,
        )
        .expect("stale release file should be written");
        assert!(
            !wait_for_handoff_release_file(&ready_dir, "new-run", Duration::from_millis(1)).await
        );

        write_handoff_release(&ready_dir, "new-run")
            .expect("current release file should be written");
        assert!(
            wait_for_handoff_release_file(&ready_dir, "new-run", Duration::from_millis(1)).await
        );

        let _ = fs::remove_dir_all(ready_dir);
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
                "delegation_handoff_publish",
                "delegation_len",
                "errors",
                "expiry_denial_count",
                "fanout_churn",
                "inputs",
                "proactive_refresh",
                "proactive_refresh_attempts",
                "proactive_refresh_failures",
                "proactive_refresh_len",
                "proactive_refresh_successes",
                "publish",
                "publish_qos_0",
                "publish_qos_1",
                "publish_qos_2",
                "publish_throughput_mps",
                "qos_distribution_actual",
                "raw_metrics",
                "raw_publish_ms",
                "reauth_storm",
                "receive",
                "receive_throughput_mps",
                "received_messages",
                "session_continuity_ok",
                "sync_connect",
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
        assert_eq!(control_inputs["proactive_refresh"], false);
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
    fn proactive_refresh_deadline_uses_exp_minus_margin() {
        assert_eq!(
            proactive_refresh_delay(Some(1_000), 60, 939),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            proactive_refresh_delay(Some(1_000), 60, 940),
            Some(Duration::ZERO)
        );
        assert_eq!(
            proactive_refresh_delay(Some(1_060), 60, 1_000),
            Some(Duration::ZERO)
        );
        assert_eq!(
            proactive_refresh_delay(Some(1_000), 60, 1_000),
            Some(Duration::ZERO)
        );
        assert_eq!(proactive_refresh_delay(None, 60, 940), None);
    }

    #[test]
    fn proactive_refresh_assertion_requires_successful_continuity() {
        let args = Args::parse_from([
            "mqtt-loadgen",
            "--proactive-refresh",
            "--proactive-refresh-assert-continuity",
        ]);

        let no_refresh = standard_output(&args, None, &[], None, empty_standard_metrics());
        assert!(
            validate_proactive_refresh_assertion(&args, &no_refresh)
                .unwrap_err()
                .to_string()
                .contains("no proactive refresh ran")
        );

        let mut failed_metrics = empty_standard_metrics();
        failed_metrics.proactive_refresh_attempts = 1;
        failed_metrics.proactive_refresh_failures = 1;
        let failed_continuity = standard_output(&args, None, &[], None, failed_metrics);
        assert!(
            validate_proactive_refresh_assertion(&args, &failed_continuity)
                .unwrap_err()
                .to_string()
                .contains("session continuity was not maintained")
        );

        let mut successful_metrics = empty_standard_metrics();
        successful_metrics.proactive_refresh_attempts = 1;
        successful_metrics.proactive_refresh_successes = 1;
        let successful = standard_output(&args, None, &[], None, successful_metrics);
        validate_proactive_refresh_assertion(&args, &successful)
            .expect("successful proactive refresh should satisfy continuity assertion");
    }

    #[test]
    fn reauth_storm_output_reports_attempt_skew_and_counts() {
        let args = Args::parse_from([
            "mqtt-loadgen",
            "--clients",
            "2",
            "--proactive-refresh",
            "--reauth-storm",
        ]);
        let mut metrics = empty_standard_metrics();
        metrics.proactive_refresh_attempts = 2;
        metrics.proactive_refresh_successes = 2;
        metrics.proactive_refresh_attempt_unix_ms = vec![1_000, 1_018];

        let output = standard_output(&args, None, &[], None, metrics);

        assert_eq!(output.reauth_storm["enabled"], true);
        assert_eq!(output.reauth_storm["clients"], 2);
        assert_eq!(output.reauth_storm["attempts"], 2);
        assert_eq!(output.reauth_storm["successes"], 2);
        assert_eq!(output.reauth_storm["failures"], 0);
        assert_eq!(output.reauth_storm["max_refresh_skew_ms"], 18.0);
        assert_eq!(output.reauth_storm["session_continuity_ok"], true);
    }

    #[test]
    fn reauth_storm_requires_multi_client_proactive_refresh() {
        let no_refresh = Args::parse_from(["mqtt-loadgen", "--clients", "2", "--reauth-storm"]);
        assert!(
            validate_startup_provisioning(&no_refresh)
                .unwrap_err()
                .to_string()
                .contains("requires --proactive-refresh")
        );

        let single_client = Args::parse_from([
            "mqtt-loadgen",
            "--clients",
            "1",
            "--proactive-refresh",
            "--token-issuer-url",
            "http://issuer",
            "--reauth-storm",
        ]);
        assert!(
            validate_startup_provisioning(&single_client)
                .unwrap_err()
                .to_string()
                .contains("more than one client")
        );
    }

    #[test]
    fn expiry_denial_classification_ignores_reauth_transport_errors() {
        assert!(expiry_denial_error("AuthenticationFailed: expired"));
        assert!(expiry_denial_error("authentication failed: token expired"));
        assert!(expiry_denial_error("NotAuthorized"));
        assert!(!expiry_denial_error("reauth_timeout"));
        assert!(!expiry_denial_error("reauth_send: channel closed"));
    }

    #[test]
    fn transformed_biscuit_expiry_uses_shortest_transform_ttl() {
        let args = Args::parse_from([
            "mqtt-loadgen",
            "--biscuit-attenuate",
            "--biscuit-attenuate-ttl",
            "30",
            "--biscuit-delegate",
            "--biscuit-delegate-ttl",
            "45",
        ]);
        let now = unix_timestamp_now().expect("system time should be available");
        let exp = transformed_biscuit_expiry(&args, Some(now + 300))
            .expect("expiry should calculate")
            .expect("transformed expiry should exist");

        assert!(exp >= now + 29);
        assert!(exp <= now + 31);
    }

    #[test]
    fn refresh_token_expiry_updates_initial_transformed_token_expiry() {
        let args = Args::parse_from([
            "mqtt-loadgen",
            "--biscuit-attenuate",
            "--biscuit-attenuate-ttl",
            "30",
        ]);
        let now = unix_timestamp_now().expect("system time should be available");
        let mut token = IssuedToken {
            bytes: b"token".to_vec(),
            exp: Some(now + 300),
        };

        refresh_token_expiry(&args, &mut token, true).expect("expiry should update");
        let exp = token.exp.expect("transformed token should retain expiry");

        assert!(exp >= now + 29);
        assert!(exp <= now + 31);
    }

    #[test]
    fn transformed_biscuit_expiry_ignores_ttl_for_disabled_transforms() {
        let args = Args::parse_from([
            "mqtt-loadgen",
            "--biscuit-attenuate-ttl",
            "30",
            "--biscuit-delegate-ttl",
            "45",
        ]);
        let now = unix_timestamp_now().expect("system time should be available");

        assert_eq!(
            transformed_biscuit_expiry(&args, Some(now + 300)).expect("expiry should calculate"),
            Some(now + 300)
        );
    }

    #[test]
    fn proactive_startup_validation_requires_issuer_and_kind() {
        let missing_url = Args::parse_from(["mqtt-loadgen", "--proactive-refresh"]);
        assert!(validate_startup_provisioning(&missing_url).is_err());

        let valid = Args::parse_from([
            "mqtt-loadgen",
            "--proactive-refresh",
            "--token-issuer-url",
            "http://issuer",
            "--token-issuer-kind",
            "jwt",
        ]);
        assert!(validate_startup_provisioning(&valid).is_ok());
        let inputs = inputs_json(&valid, "publish", None, &[], None);
        assert_eq!(inputs["proactive_refresh"], true);
        assert_eq!(inputs["proactive_refresh_margin_seconds"], 60);

        let invalid_ttl = Args::parse_from([
            "mqtt-loadgen",
            "--proactive-refresh",
            "--token-issuer-url",
            "http://issuer",
            "--token-issuer-kind",
            "jwt",
            "--token-issuer-ttl",
            "60",
            "--proactive-refresh-margin-seconds",
            "60",
        ]);
        assert!(validate_startup_provisioning(&invalid_ttl).is_err());

        let invalid_transform_ttl = Args::parse_from([
            "mqtt-loadgen",
            "--proactive-refresh",
            "--token-issuer-url",
            "http://issuer",
            "--token-issuer-kind",
            "biscuit",
            "--biscuit-attenuate",
            "--biscuit-attenuate-ttl",
            "60",
            "--proactive-refresh-margin-seconds",
            "60",
        ]);
        assert!(validate_startup_provisioning(&invalid_transform_ttl).is_err());

        let fanout = Args::parse_from([
            "mqtt-loadgen",
            "--mode",
            "fanout",
            "--proactive-refresh",
            "--token-issuer-url",
            "http://issuer",
            "--token-issuer-kind",
            "jwt",
        ]);
        let err = validate_startup_provisioning(&fanout)
            .expect_err("fanout proactive refresh should be rejected");
        assert!(err.to_string().contains("fanout mode"));
    }

    #[test]
    fn proactive_worker_connect_uses_enhanced_auth_data() {
        let args = Args::parse_from([
            "mqtt-loadgen",
            "--proactive-refresh",
            "--token-issuer-url",
            "http://issuer",
            "--token-issuer-kind",
            "jwt",
        ]);
        let spec = worker_specs(&args, "client_1", b"fresh-token".to_vec());

        assert_eq!(spec.username, "");
        assert!(spec.password.is_empty());
        assert_eq!(spec.auth_method.as_deref(), Some("token"));
        assert_eq!(spec.auth_data.as_deref(), Some(&b"fresh-token"[..]));
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

    #[test]
    fn password_map_profiles_preserve_token_and_expiry() {
        let path = std::env::temp_dir().join(format!(
            "mqtt-password-map-{}-{}.json",
            std::process::id(),
            unix_ms_now()
        ));
        fs::write(
            &path,
            r#"{"version":1,"max_clients":2,"profiles":{"jwt":{"kind":"jwt","entries":{"client_1":{"token":"token-1","exp":2000000000},"fanout_publisher":{"token":"publisher","exp":2000000000}}}}}"#,
        )
        .unwrap();

        let map = load_password_map(&path).unwrap();
        fs::remove_file(path).unwrap();
        let client = &map.profiles["jwt"]["client_1"];
        assert_eq!(client.bytes, b"token-1");
        assert_eq!(client.exp, Some(2_000_000_000));
        assert_eq!(map.profiles["jwt"]["fanout_publisher"].bytes, b"publisher");
    }

    #[test]
    fn parse_fanout_message_matches_publisher_format() {
        let payload = format!("{:.9}|7|", 1.25).into_bytes();
        let message = parse_fanout_message(&payload).unwrap();
        assert!((message.sent - 1.25).abs() < 1e-9);
        assert_eq!(message.sequence_id, Some(7));
    }

    #[test]
    fn parse_fanout_message_accepts_size_padding() {
        let mut payload = format!("{:.9}|3|", 0.5).into_bytes();
        payload.extend(vec![b'A'; 64]);
        let message = parse_fanout_message(&payload).unwrap();
        assert!((message.sent - 0.5).abs() < 1e-9);
        assert_eq!(message.sequence_id, Some(3));
    }

    #[test]
    fn parse_fanout_message_rejects_json_notification() {
        assert!(
            parse_fanout_message(br#"{"event":"acl_read_policy_changed","client_id":"client_1"}"#)
                .is_none()
        );
    }

    #[test]
    fn parse_fanout_message_rejects_unparseable_prefix() {
        assert!(parse_fanout_message(b"not-a-number|5|").is_none());
    }

    #[test]
    fn parse_fanout_message_accepts_missing_sequence_id() {
        let message = parse_fanout_message(b"0.5|").unwrap();
        assert!((message.sent - 0.5).abs() < 1e-9);
        assert_eq!(message.sequence_id, None);
    }
}
