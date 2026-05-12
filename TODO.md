# Rust MQTT Benchmark Migration Summary

## Transition Status

The Python Paho-based benchmark/runtime paths have been migrated to Rust MQTT 5 helpers built on
the local `rumqttc-v5-next` fork.

Python remains as orchestration and reporting glue, but normal MQTT data-plane work now delegates
to Rust binaries:

- `benchmarks/loadgen.py` delegates to `mqtt-loadgen`.
- `benchmarks/mqtt_auth_client.py` delegates to `mqtt-auth-client`.
- `tests/integration/conftest.py::ObservedMqttClient` wraps `observed-mqtt-client`.
- Python dependency metadata no longer includes `paho-mqtt`.
- `run_benchmarks.py` and `benchmarks/run_scenarios.py` no longer gate on Paho.

## Completed Implementation

- `mqtt-loadgen` preserves the legacy top-level result JSON shape and input metadata.
- Strict multi-client startup provisioning fetches per-client JWT/Biscuit tokens from the token
  issuer.
- Refresh-on-denied-CONNACK retries once with a fresh token and records refresh latency/length.
- Direct Biscuit attenuation and delegation use `biscuit-attenuate` and emit raw MQTT password
  bytes.
- Biscuit delegation handoff is implemented in Rust:
  - pre-generates delegated tokens per worker;
  - publishes `client_id`, `token`, and `nonce` JSON payloads;
  - honors handoff QoS and retain/no-retain flags;
  - retrieves and filters delegated tokens before measured worker connect;
  - records `delegation`, `delegation_len`, and handoff metadata.
- Fanout readiness now behaves as an all-subscriber barrier:
  - failed connects or rejected/missing SUBACKs prevent publisher traffic;
  - readiness timeout is reported as `fanout_subscribe_ready_timeout`;
  - publish and receive metrics preserve the legacy result shape.
- Fanout churn side effects are owned by Rust:
  - dynamic security snapshot swap;
  - dynamic security control publish;
  - SQLite read revoke;
  - SQLite read toggle;
  - SQLite private-deny toggle.
- Fanout churn result fields are populated, including trigger state, applied event count,
  pre/post receive counts, expected pre/post counts, delivery ratio, and cache-validity signal.
- Raw publish samples are emitted by `mqtt-loadgen`; `metrics_collector.py` consumes raw samples
  instead of reconstructing repeated summary means.
- `observed-mqtt-client` replaces the temporary manual Python MQTT packet client and supports:
  - username/password, including raw binary password;
  - TLS and insecure TLS;
  - last will;
  - SUBACK/PUBACK reason capture;
  - message counting and topic-specific waits;
  - disconnect observation.
- Docker build workspaces for Mosquitto and token-issuer were narrowed so container builds do not
  load the benchmark crate's host-local `rumqtt` path dependency.

## Verified So Far

Run from `/home/eagle/TCC2/mqtt-auth-biscuit`:

```sh
cargo test -p gen-tokens --bins
cargo check --workspace
cargo fmt --all --check
python -m ruff check benchmarks/metrics_collector.py tests/integration/conftest.py tests/integration/test_runtime_enforcement.py
python -m pytest benchmarks -q
python -m pytest tests/integration/test_runtime_enforcement.py::test_runtime_basic_auth_over_tls_stays_functional -q
python -m pytest tests/integration/test_runtime_enforcement.py::test_runtime_enhanced_auth_entrypoint_over_tcp_and_tls --quiet
```

The enhanced-auth integration check passes for JWT and Biscuit over TCP and TLS.

## Remaining Validation

No known migration implementation blocker remains, but the full broker-backed validation matrix is
not complete.

Before running scenario validation, regenerate or restore `benchmarks/tokens.json`; the scenario
runner currently fails before execution when this file is absent.

Recommended remaining checks:

```sh
cd /home/eagle/TCC2/mqtt-auth-biscuit
cargo test --workspace
python -m pytest tests/integration -q
PYTHONPATH=. python benchmarks/run_scenarios.py --scenarios-arg TOKEN-MQTT5-REAUTH-JWT,TOKEN-MQTT5-REAUTH-BISCUIT --clients 1 --messages 1
PYTHONPATH=. python benchmarks/run_scenarios.py --scenarios-arg TOKEN-DELEGATION-HANDOFF-BISCUIT --clients 1 --messages 1
PYTHONPATH=. python benchmarks/run_scenarios.py --scenarios-arg TOKEN-ACL-READ-FANOUT-EXPIRY-ONLY-JWT-10,TOKEN-ACL-READ-FANOUT-EXPIRY-ONLY-BISCUIT-10 --clients 10 --messages 5
python benchmarks/metrics_collector.py --messages 10 --qos 1

cd /home/eagle/TCC2/rumqtt
cargo test -p rumqttc-v5-next
```

Also run representative fanout churn scenario families after `benchmarks/tokens.json` exists:

- dynamic security swap;
- dynamic security control;
- SQLite read revoke;
- SQLite read toggle;
- SQLite private-deny toggle.

## Acceptance Notes

- Confirm scenario JSON for MQTT 5 reauth includes `connect_ms`, `connect_ok`, `connect_reason`,
  `reauth_ms`, `reauth_pkt_type`, `token1_bytes`, and `token2_bytes`.
- Confirm `benchmarks/results.json` from `metrics_collector.py` keeps the legacy `jwt.*` and
  `biscuit.*` summary keys and computes values from raw samples.
- Confirm the Paho acceptance search remains empty:

```sh
rg -n "paho|paho-mqtt|paho\\.mqtt|mqtt\\.client" /home/eagle/TCC2 -g '!rumqtt/**'
```
