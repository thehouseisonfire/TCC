# Running MQTT Auth benchmarks

This guide explains how to run the benchmarks for the JWT and Biscuit
authentication plugin.

## Prerequisites

- **Rust**: For building the plugin and token generator.
- **Docker & Docker Compose**: For running the test environment.
- **Python 3**: For running the metrics collector.
  - Install dependency: `pip install paho-mqtt`

## Step 1: Build the Plugin

The Mosquitto plugin must be built in release mode:

```bash
cargo build --release
```

This generates `target/release/libmosquitto_auth_biscuit.so`.

## Step 2: Generate Tokens

The benchmarking suite uses predefined tokens. Generate them with:

```bash
cargo run --bin gen-tokens
```

This will create/update `benchmarks/tokens.json`.

The Docker Mosquitto configuration is pre-wired to the deterministic keys used
by `gen-tokens` (see `docker/mosquitto.conf`).

## Step 3: Start the Environment

Start the Mosquitto broker and metrics collector (Prometheus) using Docker
Compose:

```bash
docker-compose -f docker/docker-compose.yml up --build -d
```

> [!NOTE]
> The `--build` flag ensures that the plugin is copied into the Docker image
> correctly.

## Step 4: Run Benchmarks

You can run the benchmark script to measure latency and throughput:

```bash
python3 benchmarks/metrics_collector.py
```

You can also run the full scenario battery from `ARTICLE.MD` (MTU sweep, thundering herd, policy complexity, HTTP introspection latency/loss, hybrid contingency, and MQTT5 reauthentication):

```bash
python3 benchmarks/run_scenarios.py
```

To select a different Mosquitto configuration for a run (e.g. HTTP policy or hybrid policy), set `MOSQUITTO_CONF`:

```bash
MOSQUITTO_CONF=docker/mosquitto_http.conf python3 benchmarks/run_scenarios.py
```

For the MQTT5 `AUTH` reauthentication microbenchmark only:

```bash
python3 benchmarks/mqtt5_auth_client.py --token1 "<token>" --token2 "<token>"
```

You can also monitor resource usage via:

- **Prometheus**: `http://localhost:9090`
- **Docker Stats**: `docker stats`

## Step 5: Cleanup

When finished, stop the environment:

```bash
docker-compose -f docker/docker-compose.yml down
```
