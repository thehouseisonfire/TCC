# Running MQTT Auth benchmarks

This guide explains how to run the benchmarks for the JWT and Biscuit
authentication plugin.

**Important Note**: This implementation supports **MQTT v5 only**. MQTT v3.1 is not implemented and will not be analyzed in these benchmarks.

## Prerequisites

- **Rust**: For building the plugin and token generator.
- **Docker & Docker Compose**: For running the test environment.
- **Python 3**: For running the metrics collector.
  - Install dependency: `pip install paho-mqtt`

## Step 1: Build the Plugin

The Mosquitto plugin must be built in release mode:

```bash
cargo build --release -p mosquitto-auth-biscuit
```

This generates `target/release/libmosquitto_auth_biscuit.so`.

## Step 2: Generate Tokens

The benchmarking suite uses predefined tokens. Generate them with:

```bash
cargo run -p gen-tokens
```

This will create/update `benchmarks/tokens.json` and write `docker/biscuit_public.key` for the Mosquitto plugin.

The Docker Mosquitto configuration is pre-wired to the deterministic keys used
by `gen-tokens` (see `docker/mosquitto.conf`).

## Step 3: Start the Environment

Start the Mosquitto broker and metrics collector (Prometheus) using Docker
Compose:

```bash
docker compose -f docker/docker-compose.yml up --build -d
```

> [!NOTE]
> The `--build` flag ensures that the plugin is copied into the Docker image
> correctly.

## Step 4: Run Benchmarks

You can run the benchmark script to measure latency and throughput:

```bash
python3 benchmarks/metrics_collector.py
```

### Smoke test

Run a lightweight health check + single publish for JWT and Biscuit:

```bash
python3 benchmarks/smoke_test.py
```

TLS smoke test:

```bash
bash docker/tls/generate_certs.sh
python3 benchmarks/smoke_test.py --tls
```

You can also run the full scenario battery from `ARTICLE.MD` (MTU sweep, thundering herd, policy complexity, HTTP introspection latency/loss, hybrid contingency, and MQTT reauthentication):

```bash
python3 benchmarks/run_scenarios.py
```

### TLS-enabled runs

To measure TLS overhead across all network paths (MQTT, token issuer, authz HTTP, Prometheus):

```bash
bash docker/tls/generate_certs.sh
docker compose -f docker/docker-compose.yml -f docker/docker-compose.tls.yml up --build -d
python3 benchmarks/run_scenarios.py --tls
```

Optional TLS flags:

- `--tls-ca-file <path>`: custom CA bundle (default: `docker/tls/ca.pem`)
- `--tls-insecure`: disable certificate verification for local testing (obviously not recommended for production)

For the microbenchmark or single-run metrics collector over TLS:

```bash
python3 benchmarks/mqtt_auth_client.py --token1 "<token>" --token2 "<token>" --tls
python3 benchmarks/metrics_collector.py --tls --port 8883
```

To select a different Mosquitto configuration for a run (e.g. HTTP policy or hybrid policy), set `MOSQUITTO_CONF`:

```bash
MOSQUITTO_CONF=docker/mosquitto_http.conf python3 benchmarks/run_scenarios.py
```

For the MQTT `AUTH` reauthentication microbenchmark only:

```bash
python3 benchmarks/mqtt_auth_client.py --token1 "<token>" --token2 "<token>"
```

You can also monitor resource usage via:

- **Prometheus**: `http://localhost:9090`
- **Docker Stats**: `docker stats`

## Step 5: Cleanup

When finished, stop the environment:

```bash
docker compose -f docker/docker-compose.yml down
```
