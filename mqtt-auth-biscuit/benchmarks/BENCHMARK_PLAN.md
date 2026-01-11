# MQTT Auth Plugin Benchmark Plan

This document outlines the benchmarking methodology and test scenarios for
evaluating the performance of the JWT vs Biscuit authentication/authorization
plugin.

## Objectives

1. Compare latency of connection establishment (CONNECT/CONNACK) between JWT and
   Biscuit.
2. Evaluate authorization latency for PUBLISH/SUBSCRIBE operations.
3. Measure CPU and memory consumption of the Mosquitto broker under various
   loads.
4. Assess the impact of token size on network throughput.

## Test Matrix

| Scenario ID | Token Type | Operation | Clients | QoS | Policy Complexity      |
| ----------- | ---------- | --------- | ------- | --- | ---------------------- |
| BASE-01     | None       | Pub/Sub   | 100     | 0   | N/A                    |
| JWT-01      | JWT        | Pub/Sub   | 100     | 1   | Simple (Admin)         |
| JWT-02      | JWT        | Pub/Sub   | 1000    | 1   | Simple (Admin)         |
| BIS-01      | Biscuit    | Pub/Sub   | 100     | 1   | Simple (Allow if true) |
| BIS-02      | Biscuit    | Pub/Sub   | 100     | 1   | Attenuated (5 blocks)  |

## Metrics Collection

- **Latency**: Measured from client-side using `paho-mqtt`.
- **Resource Usage**: Tracked via `docker stats` and Prometheus.
- **Throughput**: Measured in messages per second (mps).

## Reproducibility

- All tests run within the provided `docker compose` environment.
- Tokens are generated using the `gen-tokens` tool with deterministic keys.
- Network conditions (latency/loss) emulated via `tc` on the bridge network.
