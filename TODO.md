# TODO: Replace Paho MQTT Python with `rumqttc-v5-next`

## Goal

Replace all Python-side Paho MQTT clients with Rust MQTT 5 clients built on the local
`rumqttc-v5-next` fork in `rumqtt/rumqttc-v5`. The replacement must preserve existing benchmark
semantics while removing Paho from the measurement path and enabling true MQTT 5 client-sent
`AUTH` re-authentication after `CONNACK`.

Use only the MQTT 5 crate. Ignore the MQTT 3.1.1/v4 crate.

## Current Paho Usage

- `/home/eagle/TCC2/pyproject.toml`
  - Declares `paho-mqtt==2.1.0`.
- `/home/eagle/TCC2/uv.lock`
  - Locks `paho-mqtt==2.1.0`.
- `/home/eagle/TCC2/requirements.txt`
  - Exported lock output includes `paho-mqtt==2.1.0`.
- `/home/eagle/TCC2/run_benchmarks.py`
  - `check_paho()` imports `paho.mqtt.client`.
  - `main()` hard-requires Paho before invoking benchmark scenarios.
- `/home/eagle/TCC2/mqtt-auth-biscuit/benchmarks/run_scenarios.py`
  - `_ensure_paho_mqtt()` imports `paho.mqtt.client`.
  - `main()` calls `_ensure_paho_mqtt()` for all non-`mqtt5_auth` scenarios.
  - `_run_mqtt5_auth()` shells out to `benchmarks/mqtt_auth_client.py`, which currently exists
    because Paho cannot send MQTT 5 `AUTH` after `CONNACK`.
- `/home/eagle/TCC2/mqtt-auth-biscuit/benchmarks/loadgen.py`
  - Imports `paho.mqtt.client as mqtt`.
  - Creates Paho clients for normal workers, fan-out subscribers/publishers, control-plane
    publishers, delegation handoff, and delegated-token publisher flows.
  - Uses Paho APIs: `Client(...)`, `username_pw_set(...)`, `tls_set(...)`,
    `tls_insecure_set(...)`, `connect(...)`, `loop_start()`, `subscribe(...)`, `publish(...)`,
    `wait_for_publish(...)`, `disconnect()`, and `loop_stop()`.
  - Uses Paho constants and callback data: `MQTTv5`, `CallbackAPIVersion.VERSION2`,
    `MQTT_ERR_SUCCESS`, CONNACK/SUBACK/PUBACK reason codes, and message callbacks.
- `/home/eagle/TCC2/mqtt-auth-biscuit/benchmarks/metrics_collector.py`
  - Imports `paho.mqtt.client as mqtt`.
  - Runs a smaller JWT/Biscuit publish-latency helper with one client, TLS options, binary Biscuit
    password decoding, `on_publish` timing, and `benchmarks/results.json` output.
- `/home/eagle/TCC2/mqtt-auth-biscuit/benchmarks/test_scenario_semantics.py`
  - Monkeypatches `run_scenarios._ensure_paho_mqtt`; update this test after the Paho gate is
    removed.
- `/home/eagle/TCC2/mqtt-auth-biscuit/tests/integration/conftest.py`
  - Imports `paho.mqtt.client as mqtt`.
  - `ObservedMqttClient` wraps a Paho MQTT 5 client for integration tests.
  - Exercises connect, subscribe, publish, message collection, disconnect observation, TLS, will
    messages, username/password authentication, and binary password support.
- `/home/eagle/TCC2/PROGRESS.md`
  - Mentions a future containerized load generator image as `Python + paho-mqtt`; update this note
    to the Rust/`rumqttc-v5-next` load generator once the migration starts.

Not Paho Python:

- `/home/eagle/TCC2/mqtt-auth-biscuit/benchmarks/mqtt_auth_client.py` hand-encodes MQTT 5 packets
  with sockets. It should still be replaced because `rumqttc-v5-next` now supports this flow.
- `/home/eagle/TCC2/rumqtt/benchmarks/go.mod` depends on Eclipse Paho Go; this is unrelated to
  the Python Paho migration.
- `/home/eagle/TCC2/rumqtt/benchmarks/Cargo.toml` has commented Paho Rust entries; leave them alone
  unless benchmark cleanup is done separately.

## Relevant `rumqttc-v5-next` Capabilities

The local fork exposes the needed primitives:

- Package name: `rumqttc-v5-next`; library crate name: `rumqttc`.
- `MqttOptions::new(client_id, (host, port))`.
- `MqttOptions::set_credentials(username, Bytes)` and `set_password(Bytes)` for binary CONNECT
  password data.
- `MqttOptions::set_authentication_method(Some("token".to_string()))`.
- `MqttOptions::set_authentication_data(Some(Bytes))` for MQTT 5 CONNECT authentication data.
- `AsyncClient::builder(options).capacity(...).build()` or `Client::builder(options)...build()`.
- `AsyncClient::reauth(Some(AuthProperties { method, data, reason: None, user_properties: vec![] }))`
  for client-sent MQTT 5 `AUTH` after the connection is established.
- TLS can be configured through `Transport::Tls(...)` and the crate's TLS features.

Useful local references:

- `rumqtt/rumqttc-v5/examples/async_auth_oauth.rs`
- `rumqtt/rumqttc-v5/examples/sync_auth_scram.rs`
- `rumqtt/rumqttc-v5/examples/auth.rs`
- `rumqtt/rumqttc-v5/src/client.rs`
- `rumqtt/rumqttc-v5/src/lib.rs`

## Migration Plan

1. Add a Rust load generator binary.
   - Create a new binary in `mqtt-auth-biscuit/crates/benchmarks`, for example
     `src/bin/mqtt-loadgen.rs`, or split a dedicated crate if the CLI grows too large.
   - Add dependencies to `mqtt-auth-biscuit/crates/benchmarks/Cargo.toml`:
     `rumqttc = { package = "rumqttc-v5-next", version = "...", features = [...] }`.
   - During local development, consider a temporary path override to
     `/home/eagle/TCC2/rumqtt/rumqttc-v5` so the repository uses the checked-out fork.
   - Keep the binary JSON output schema compatible with `benchmarks/loadgen.py` so
     `run_scenarios.py` and result aggregation do not need a broad rewrite.

2. Port `benchmarks/loadgen.py` MQTT behavior to Rust.
   - Preserve the current CLI inputs: host, port, client count, username, password, topic template,
     QoS, QoS distribution, message count/size, TLS flags, fan-out mode, control mode, token refresh
     settings, delegation/handoff options, and churn settings.
   - Use `rumqttc` for all MQTT I/O:
     - CONNECT with username and binary password.
     - SUBSCRIBE and SUBACK reason-code capture.
     - PUBLISH and publish completion timing.
     - fan-out subscriber message timing.
     - control-topic publishing.
     - TLS and insecure TLS test mode.
   - Keep token issuer HTTP calls either in Python initially or port them to Rust with `reqwest`.
     The key benchmark fix is that MQTT work must move out of Paho.

3. Replace `benchmarks/metrics_collector.py`.
   - Either delete it if `loadgen` fully supersedes it, or add an equivalent subcommand to the Rust
     load generator.
   - Preserve its current result shape if any downstream scripts still consume
     `benchmarks/results.json`.

4. Replace token refresh reconnect behavior with MQTT 5 re-auth where appropriate.
   - For scenarios that explicitly test refresh-on-auth failure, keep reconnect semantics if the
     scenario name/definition requires it.
   - For `TOKEN-MQTT5-REAUTH-*` scenarios, use `AsyncClient::reauth(...)` after `CONNACK` with:
     - `AuthProperties.method = Some("token".to_string())`
     - `AuthProperties.data = Some(new_token_bytes.into())`
   - Measure `reauth_ms` around the client `reauth` request and the corresponding auth completion
     event/notice, not around a raw socket write.

5. Retire `benchmarks/mqtt_auth_client.py`.
   - Replace `_run_mqtt5_auth()` in `benchmarks/run_scenarios.py` with a call to the Rust binary.
   - Delete the manual MQTT packet encoder once equivalent Rust coverage exists.
   - Keep the output fields currently used by scenario summaries: `connect_ms`, `connect_ok`,
     `connect_reason`, `reauth_ms`, token byte lengths, and any AUTH response status fields.

6. Replace integration-test Paho fixture.
   - Implement a small Rust test client binary, for example
     `mqtt-auth-biscuit/crates/benchmarks/src/bin/observed-mqtt-client.rs`, or a more general
     command-oriented helper.
   - Expose commands for connect, subscribe, publish, wait-for-message, wait-disconnect, and close.
   - Update `tests/integration/conftest.py::ObservedMqttClient` to wrap this helper instead of Paho.
   - Preserve existing Python test APIs so `test_runtime_enforcement.py` and
     `test_acl_read_profiles_matrix.py` remain mostly unchanged.

7. Remove Python Paho dependency gates.
   - Delete `check_paho()` from `run_benchmarks.py`.
   - Delete `_ensure_paho_mqtt()` from `benchmarks/run_scenarios.py`.
   - Update tests that monkeypatch `_ensure_paho_mqtt`.
   - Remove `paho-mqtt==2.1.0` from `pyproject.toml`.
   - Regenerate `uv.lock`.
   - Regenerate `requirements.txt` with `uv export --locked --no-hashes --no-emit-project
     --format requirements-txt --output-file requirements.txt`.
   - Update `PROGRESS.md` so the containerized load-generator item no longer calls for
     `Python + paho-mqtt`.

8. Add migration tests.
   - Unit-test binary password handling with raw Biscuit bytes, including NUL and non-UTF-8 bytes.
   - Integration-test CONNECT username/password auth for JWT and binary Biscuit tokens.
   - Integration-test MQTT 5 AUTH re-auth after CONNACK for both JWT and Biscuit refresh tokens.
   - Run representative fan-out and control scenarios to verify existing summary JSON is stable.

## Suggested Execution Order

1. Build the Rust MQTT client core for connect, publish, subscribe, TLS, binary password, and JSON
   result output.
2. Wire `run_scenarios.py` to call the Rust load generator while leaving the Python CLI as a thin
   compatibility wrapper if needed.
3. Replace or retire `metrics_collector.py`.
4. Add AUTH re-auth support to the Rust load generator and replace `mqtt_auth_client.py`.
5. Convert `ObservedMqttClient` integration tests to the Rust helper.
6. Remove Paho dependencies and import checks.
7. Run validation.

## Validation Commands

From `/home/eagle/TCC2/mqtt-auth-biscuit`:

```sh
cargo check --workspace
cargo test --workspace
pytest tests/integration -q
python benchmarks/run_scenarios.py --scenarios-arg TOKEN-MQTT5-REAUTH-JWT,TOKEN-MQTT5-REAUTH-BISCUIT --clients 1 --messages 1
python benchmarks/run_scenarios.py --scenarios-arg TOKEN-BASELINE-JWT,TOKEN-BASELINE-BISCUIT --clients 10 --messages 5
python benchmarks/run_scenarios.py --scenarios-arg TOKEN-ACL-READ-FANOUT-EXPIRY-ONLY-JWT-10,TOKEN-ACL-READ-FANOUT-EXPIRY-ONLY-BISCUIT-10 --clients 10 --messages 5
```

From `/home/eagle/TCC2/rumqtt`:

```sh
cargo test -p rumqttc-v5-next
```

## Acceptance Criteria

- `rg -n "paho|paho-mqtt|paho\\.mqtt|mqtt\\.client" /home/eagle/TCC2 -g '!rumqtt/**'`
  returns no active Python dependency or import sites.
- MQTT benchmark traffic is generated by Rust code using `rumqttc-v5-next`.
- Binary Biscuit tokens are sent as MQTT password bytes without base64/string coercion in the MQTT
  client layer.
- MQTT 5 re-auth scenarios send an `AUTH` packet after `CONNACK` through `rumqttc`, not through a
  manual socket encoder.
- Existing benchmark result JSON/CSV consumers continue to work.
- Integration tests no longer require Paho.
