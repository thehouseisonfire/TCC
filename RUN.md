# Full Benchmark Run Plan

This document describes how to execute the complete MQTT authorization benchmark
suite for the TCC2 project. It covers every scenario, exercises every parameter
lever, and produces a reproducible dataset for analysis.

## Overview

The benchmark suite has **428 scenarios** (214 base + 214 TLS variants) across
multiple functional categories. The run plan has two parts:

| Part | What | Runs | Est. time |
|------|------|------|-----------|
| 1 | All 428 scenarios × 2 clients × 2 messages × 3 runs | 5,136 | ~4–7 days |
| 2 | 32 scenarios × 3 clients × 2 messages × 3 QoS × 2 token issuer × 3 runs | 3,456 | ~4–7 days |
| **Total** | | **8,592** | **~9–14 days** |

## Research Dimensions

Every lever below is pulled at least twice across the full plan.

| Dimension | Part 1 levels | Part 2 levels | Source |
|-----------|--------------|---------------|--------|
| Auth mechanism | None, JWT, Biscuit | None, JWT, Biscuit | Scenario ID |
| Policy backend | Static ACL, DynSec, HTTP, SQLite, Hybrid | (same) | Scenario ID |
| Token complexity | Baseline, Chain-1/5/25, Datalog-low/med/high | (same) | Scenario ID |
| TLS | Off, On | Off, On | `-TLS` suffix |
| Client count | 10, 200 | 10, 50, 200 | `--clients` |
| Message volume | 10, 100 | 10, 100 | `--messages` |
| QoS | 1 (default) | 0, 1, 2 | `--qos` |
| Token issuer | Default | Default, Stripped | `--token-issuer-no-default-roles` |

Part 1 runs every scenario across a 2×2 matrix of client counts and message
densities (3 runs each). Part 2 deepens the sweep on 32 representative
scenarios by adding a third client level, all three QoS levels, and token
issuer configuration, while excluding scenarios whose workload shape is already
defined by the scenario itself.

## Sweep Scenarios (Part 2)

32 scenarios, 2 per category where applicable:

| # | Category | Scenario 1 | Scenario 2 |
|---|----------|------------|------------|
| 1 | Baseline no-auth | `BASELINE-NO-AUTH` | — |
| 2 | Token baseline | `TOKEN-BASELINE-JWT` | `TOKEN-BASELINE-BISCUIT` |
| 3 | Static ACL | `STATIC-ACL-PUBLISH-JWT` | `STATIC-ACL-PUBLISH-BISCUIT` |
| 4 | DynSec baseline | `DYNAMIC-SECURITY-BASELINE` | `DYNAMIC-SECURITY-CHURN` |
| 5 | HTTP profile simple | `HTTP-PROFILE-SIMPLE-JWT` | `HTTP-PROFILE-SIMPLE-BISCUIT` |
| 6 | HTTP profile complex | `HTTP-PROFILE-COMPLEX-JWT` | `HTTP-PROFILE-COMPLEX-BISCUIT` |
| 7 | HTTP latency | `HTTP-LATENCY-200MS-JWT` | `HTTP-LATENCY-1000MS-JWT` |
| 8 | Hybrid fallback | `HYBRID-FALLBACK-AUTHZ-DOWN-JWT` | — |
| 9 | Token complexity chain | `TOKEN-COMPLEXITY-CHAIN-5-BISCUIT` | `TOKEN-COMPLEXITY-CHAIN-25-BISCUIT` |
| 10 | Token complexity datalog | `TOKEN-COMPLEXITY-DATALOG-MED-BISCUIT` | `TOKEN-COMPLEXITY-DATALOG-HIGH-BISCUIT` |
| 11 | Token attenuation | `TOKEN-ATTENUATION-CLIENT-BISCUIT` | `TOKEN-ATTENUATION-DENY-BISCUIT` |
| 12 | Network MTU | `NETWORK-MTU-200-JWT` | `NETWORK-MTU-1500-JWT` |
| 13 | MQTT5 reauth | `TOKEN-MQTT5-REAUTH-JWT` | `TOKEN-MQTT5-REAUTH-BISCUIT` |
| 14 | Token deny | `TOKEN-DENY-READ-JWT` | `TOKEN-ATTENUATED-DENY-BISCUIT` |
| 15 | QoS | `TOKEN-QOS2-JWT` | `TOKEN-QOS2-BISCUIT` |
| 16 | Thundering herd | `TOKEN-THUNDERING-HERD-JWT` | `TOKEN-THUNDERING-HERD-BISCUIT` |

The following fixed-workload scenarios are intentionally excluded from Part 2
because they hard-code their own client/message counts and would not participate
meaningfully in the `--clients` / `--messages` matrix:

- `TOKEN-PUBLISH-STRESS-JWT`
- `TOKEN-PUBLISH-STRESS-BISCUIT`
- `TOKEN-PUBLISH-STRESS-RECONNECT-JWT`
- `TOKEN-PUBLISH-STRESS-RECONNECT-BISCUIT`
- `TOKEN-DATALOG-STRESS-LOW-BISCUIT`
- `TOKEN-DATALOG-STRESS-MED-BISCUIT`
- `TOKEN-DATALOG-STRESS-HIGH-BISCUIT`
- `TOKEN-COMPOSABILITY-ATTENUATED-DATALOG-MED-BISCUIT`
- `TOKEN-COMPOSABILITY-ATTENUATED-DATALOG-HIGH-BISCUIT`
- `TOKEN-COMPOSABILITY-DELEGATED-DATALOG-MED-BISCUIT`
- `TOKEN-COMPOSABILITY-DELEGATED-DATALOG-HIGH-BISCUIT`
- `HTTP-AUTHZ-COMPLEXITY-SIMPLE-JWT`
- `HTTP-AUTHZ-COMPLEXITY-SIMPLE-BISCUIT`
- `HTTP-AUTHZ-COMPLEXITY-MED-JWT`
- `HTTP-AUTHZ-COMPLEXITY-MED-BISCUIT`
- `HTTP-AUTHZ-COMPLEXITY-COMPLEX-JWT`
- `HTTP-AUTHZ-COMPLEXITY-COMPLEX-BISCUIT`

Run those as targeted scenarios instead of mixing them into the parameter
sweep.

The following scenario families are also excluded from Part 2 because their
primary workload axis is already scenario-defined, so the generic matrix would
blur the point of the experiment:

- `TOKEN-LIFECYCLE-REAUTH-STORM-{JWT,BISCUIT}`
- `TOKEN-LIFECYCLE-PROACTIVE-REAUTH-{JWT,BISCUIT}`
- `TOKEN-LIFECYCLE-RECONNECT-PUBLISH-{JWT,BISCUIT}`
- `CONTROL-OVERHEAD-KICK-REAUTH-JWT`
- `CONTROL-OVERHEAD-ACL-READ-NOTIFY-JWT`
- `CONTROL-CHURN-ACL-MODIFY-JWT`
- `CONTROL-CHURN-GROUP-CLIENT-JWT`
- `SQLITE-RBAC-CHURN-{JWT,BISCUIT}`

Run those as targeted slices with their scenario-defined workload shape.

Two Part 2 scenarios remain in the sweep but do not vary on the QoS axis:

- `BASELINE-NO-AUTH` pins `qos=0`
- `TOKEN-QOS2-{JWT,BISCUIT}` pin `qos=2`

Include them in Part 2 for client/message and token-issuer coverage, but do not
interpret their results as a QoS sweep.

## Prerequisites

```bash
# Rust toolchain (rustc 1.93.1, pinned in rust-toolchain.toml)
rustc --version

# Python environment
uv sync --locked
python --version  # 3.14.2

# Docker
docker --version
docker compose version

# iperf3 (client binary, server runs in Docker)
iperf3 --version  # sudo apt-get install iperf3
```

## Step-by-Step Execution

All commands run from the repository root (`TCC2/`).

**Default client topology:** run every scenario with `--client-topology container-per-client` unless a step explicitly requires a different mode.

**Default client memory:** keep every `container-per-client` run at `--client-memory 96m` because the previous 512 MB default is not feasible at high client counts.

### Step 1: Build the plugin and generate tokens

Build once and reuse across all iterations:

```bash
cd mqtt-auth-biscuit
cargo build --locked --release -p mosquitto-auth-biscuit
cargo run --locked -p gen-tokens --bin gen-tokens
cd ../..
```

### Step 2: Part 1 — Full baseline (all 428 × 2 clients × 2 messages × 3 runs)

Generate the full scenario list:

```bash
readarray -t SCENARIO_GROUPS < <(cd mqtt-auth-biscuit && uv run --locked python -c "
from benchmarks.run_scenarios import _read_tokens, _build_available_scenarios, _expand_tls_matrix
t = _read_tokens('benchmarks/tokens.json')
a = _expand_tls_matrix(_build_available_scenarios(
    t, token_issuer_no_default_roles=False, token_issuer_no_default_grants=False))
reauth = sorted(name for name in a if name.startswith('TOKEN-LIFECYCLE-REAUTH-STORM-'))
regular = sorted(name for name in a if name not in reauth)
print(','.join(regular))
print(','.join(reauth))
" 2>/dev/null)
SCENARIOS=${SCENARIO_GROUPS[0]}
REAUTH_STORM_SCENARIOS=${SCENARIO_GROUPS[1]}
```

Run the 2×2 matrix (clients × messages) with 3 repetitions:

```bash
for clients in 10 200; do
  for messages in 10 100; do
    for run in 1 2 3; do
      echo "=== Part 1: clients=$clients messages=$messages run=$run ==="
      ./scripts/run-benchmarks \
        --scenarios "$SCENARIOS" \
        --clients "$clients" \
        --messages "$messages" \
        --client-topology container-per-client \
        --client-memory 96m \
        --skip-build \
        --skip-tokens

      # Reauth storms are incompatible with container-per-client.
      ./scripts/run-benchmarks \
        --scenarios "$REAUTH_STORM_SCENARIOS" \
        --clients "$clients" \
        --messages "$messages" \
        --client-topology host \
        --skip-build \
        --skip-tokens

      # Preserve results to avoid stale data in aggregator
      mv mqtt-auth-biscuit/benchmarks/results \
         mqtt-auth-biscuit/benchmarks/results-p1-c${clients}-m${messages}-r${run}
    done
  done
done
```

This produces 5,136 scenario runs across 12 invocations of `run-benchmarks`.

### Step 3: Part 2 — Parameter sweep (32 scenarios × 36 combos × 3 runs)

Define the sweep scenarios:

```bash
SWEEP_SCENARIOS="BASELINE-NO-AUTH,\
TOKEN-BASELINE-JWT,TOKEN-BASELINE-BISCUIT,\
STATIC-ACL-PUBLISH-JWT,STATIC-ACL-PUBLISH-BISCUIT,\
DYNAMIC-SECURITY-BASELINE,DYNAMIC-SECURITY-CHURN,\
HTTP-PROFILE-SIMPLE-JWT,HTTP-PROFILE-SIMPLE-BISCUIT,\
HTTP-PROFILE-COMPLEX-JWT,HTTP-PROFILE-COMPLEX-BISCUIT,\
HTTP-LATENCY-200MS-JWT,HTTP-LATENCY-1000MS-JWT,\
HYBRID-FALLBACK-AUTHZ-DOWN-JWT,\
TOKEN-COMPLEXITY-CHAIN-5-BISCUIT,TOKEN-COMPLEXITY-CHAIN-25-BISCUIT,\
TOKEN-COMPLEXITY-DATALOG-MED-BISCUIT,TOKEN-COMPLEXITY-DATALOG-HIGH-BISCUIT,\
TOKEN-ATTENUATION-CLIENT-BISCUIT,TOKEN-ATTENUATION-DENY-BISCUIT,\
NETWORK-MTU-200-JWT,NETWORK-MTU-1500-JWT,\
TOKEN-MQTT5-REAUTH-JWT,TOKEN-MQTT5-REAUTH-BISCUIT,\
TOKEN-DENY-READ-JWT,TOKEN-ATTENUATED-DENY-BISCUIT,\
TOKEN-QOS2-JWT,TOKEN-QOS2-BISCUIT,\
TOKEN-THUNDERING-HERD-JWT,TOKEN-THUNDERING-HERD-BISCUIT"
```

Run the fixed-workload stress scenarios separately with explicit targeted
invocations:

```bash
./scripts/run-benchmarks \
  --scenarios TOKEN-PUBLISH-STRESS-JWT,TOKEN-PUBLISH-STRESS-BISCUIT,\
TOKEN-DATALOG-STRESS-LOW-BISCUIT,TOKEN-DATALOG-STRESS-MED-BISCUIT,\
TOKEN-DATALOG-STRESS-HIGH-BISCUIT,\
TOKEN-COMPOSABILITY-ATTENUATED-DATALOG-MED-BISCUIT,\
TOKEN-COMPOSABILITY-ATTENUATED-DATALOG-HIGH-BISCUIT,\
TOKEN-COMPOSABILITY-DELEGATED-DATALOG-MED-BISCUIT,\
TOKEN-COMPOSABILITY-DELEGATED-DATALOG-HIGH-BISCUIT,\
HTTP-AUTHZ-COMPLEXITY-SIMPLE-JWT,HTTP-AUTHZ-COMPLEXITY-SIMPLE-BISCUIT,\
HTTP-AUTHZ-COMPLEXITY-MED-JWT,HTTP-AUTHZ-COMPLEXITY-MED-BISCUIT,\
HTTP-AUTHZ-COMPLEXITY-COMPLEX-JWT,HTTP-AUTHZ-COMPLEXITY-COMPLEX-BISCUIT \
  --client-topology container-per-client \
  --client-memory 96m \
  --skip-build \
  --skip-tokens

./scripts/run-benchmarks \
  --scenarios TOKEN-PUBLISH-STRESS-RECONNECT-JWT,TOKEN-PUBLISH-STRESS-RECONNECT-BISCUIT \
  --client-topology container-per-client \
  --client-memory 96m \
  --skip-build \
  --skip-tokens
```

Run the excluded lifecycle/control/fan-out targeted scenarios separately:

```bash
./scripts/run-benchmarks \
  --scenarios TOKEN-LIFECYCLE-PROACTIVE-REAUTH-JWT,TOKEN-LIFECYCLE-PROACTIVE-REAUTH-BISCUIT,\
TOKEN-LIFECYCLE-RECONNECT-PUBLISH-JWT,TOKEN-LIFECYCLE-RECONNECT-PUBLISH-BISCUIT,\
CONTROL-OVERHEAD-KICK-REAUTH-JWT,CONTROL-OVERHEAD-ACL-READ-NOTIFY-JWT,\
CONTROL-CHURN-ACL-MODIFY-JWT,CONTROL-CHURN-GROUP-CLIENT-JWT,\
SQLITE-RBAC-CHURN-JWT,SQLITE-RBAC-CHURN-BISCUIT \
  --client-topology container-per-client \
  --client-memory 96m \
  --skip-build \
  --skip-tokens

./scripts/run-benchmarks \
  --scenarios TOKEN-LIFECYCLE-REAUTH-STORM-JWT,TOKEN-LIFECYCLE-REAUTH-STORM-BISCUIT \
  --client-topology host \
  --skip-build \
  --skip-tokens
```

Run the full sweep (3 clients × 2 messages × 3 QoS × 2 token issuer × 3 runs
= 108 iterations, 3,456 scenario runs total):

```bash
for clients in 10 50 200; do
  for messages in 10 100; do
    for qos in 0 1 2; do
      for stripped in 0 1; do
        for run in 1 2 3; do
          echo "=== Part 2: c=$clients m=$messages qos=$qos stripped=$stripped run=$run ==="
          if [ "$stripped" -eq 1 ]; then
            ./scripts/run-benchmarks \
              --scenarios "$SWEEP_SCENARIOS" \
              --clients "$clients" \
              --messages "$messages" \
              --qos "$qos" \
              --client-topology container-per-client \
              --client-memory 96m \
              --token-issuer-no-default-roles \
              --skip-build \
              --skip-tokens
          else
            ./scripts/run-benchmarks \
              --scenarios "$SWEEP_SCENARIOS" \
              --clients "$clients" \
              --messages "$messages" \
              --qos "$qos" \
              --client-topology container-per-client \
              --client-memory 96m \
              --skip-build \
              --skip-tokens
          fi
          mv mqtt-auth-biscuit/benchmarks/results \
             mqtt-auth-biscuit/benchmarks/results-p2-c${clients}-m${messages}-q${qos}-s${stripped}-r${run}
        done
      done
    done
  done
done
```

**Note**: `--token-issuer-no-default-grants` is now forwarded by the Rust wrapper, but if you need to invoke the Python module directly for other lower-level flags, use:

```bash
cd mqtt-auth-biscuit
uv run --locked python -m benchmarks.run_scenarios \
  --scenarios-arg "$SWEEP_SCENARIOS" \
  --clients "$clients" \
  --messages "$messages" \
  --qos "$qos" \
  --client-topology container-per-client \
  --client-memory 96m \
  --token-issuer-no-default-roles \
  --token-issuer-no-default-grants
cd ..
```

### Step 4: Collect results

All results land in `mqtt-auth-biscuit/benchmarks/results-p{1,2}-*/`.

Each directory contains:

| File | Content |
|------|---------|
| `<SCENARIO_ID>.json` | Per-scenario metrics (latency, throughput, resource snapshots) |
| `summary.json` | Aggregated metrics across all scenarios in that run |
| `summary.csv` | Same as CSV |
| `pcap/<SCENARIO_ID>.pcap` | Packet captures (if tcpdump enabled) |
| `perf/perf-*.json` | CPU profiling data (if `--perf` enabled) |

## Runtime Estimates

| Component | Per-invocation time | Invocations | Subtotal |
|-----------|-------------------|-------------|----------|
| Part 1 (428 scenarios, 10 clients, 10 msgs) | ~4–8 h | 3 | ~12–24 h |
| Part 1 (428 scenarios, 200 clients, 10 msgs) | ~8–16 h | 3 | ~24–48 h |
| Part 1 (428 scenarios, 10 clients, 100 msgs) | ~6–12 h | 3 | ~18–36 h |
| Part 1 (428 scenarios, 200 clients, 100 msgs) | ~12–24 h | 3 | ~36–72 h |
| Part 2 (32 scenarios per invocation) | ~1–3 h | 108 | ~108–324 h |

**Conservative total: 9–14 days continuous execution.** Plan for overnight and
weekend runs. Consider splitting across multiple machines if available.

## Verifying Completeness

After all runs, count result files:

```bash
# Part 1: expect 428 JSON files per run
for d in mqtt-auth-biscuit/benchmarks/results-p1-*/; do
  count=$(ls "$d"/*.json 2>/dev/null | grep -v summary | wc -l)
  echo "$d: $count scenarios"
done

# Part 2: expect 32 JSON files per sweep run
for d in mqtt-auth-biscuit/benchmarks/results-p2-*/; do
  count=$(ls "$d"/*.json 2>/dev/null | grep -v summary | wc -l)
  echo "$d: $count scenarios"
done
```

## Analyzing Results

Use the aggregation script on any results directory:

```bash
uv run --locked python benchmarks/aggregate_results.py \
  --input mqtt-auth-biscuit/benchmarks/results-p1-c10-m10-r1 \
  --out-json summary.json \
  --out-csv summary.csv
```

Or aggregate across all Part 1 runs for a combined view:

```bash
mkdir -p combined-part1
for d in mqtt-auth-biscuit/benchmarks/results-p1-*/; do
  cp "$d"/*.json combined-part1/ 2>/dev/null
done
uv run --locked python benchmarks/aggregate_results.py \
  --input combined-part1 \
  --out-json combined-part1/summary.json \
  --out-csv combined-part1/summary.csv
```

## Notes

- The `--skip-build` and `--skip-tokens` flags avoid rebuilding the plugin and
  regenerating tokens on every iteration. Build once in Step 1.
- Docker is brought up and torn down by each `run-benchmarks` invocation. No
  stale container state leaks between runs.
- The results directory is **not** cleaned between runs. The `mv` after each
  invocation preserves results and prevents the aggregator from picking up
  stale data.
- MTU scenarios (`NETWORK-MTU-*`) use `netem` for traffic shaping. These
  require `NET_ADMIN` capability on the mosquitto container (already configured
  in `docker-compose.yml`).
- Every compatible command in this run plan uses `--client-topology container-per-client` because the research environment expects one independent container per MQTT client. REAUTH-STORM scenarios explicitly use `host` because the runner does not support them with `container-per-client`.
- Every command in this run plan also uses `--client-memory 96m` for `container-per-client` runs because the default 512 MB loadgen limit is not feasible at high client counts. Keep this explicit memory override unless the documented step intentionally changes the limit.
- REAUTH-STORM, RECONNECT-PUBLISH, and THUNDERING-HERD scenarios have internal
  client counts that override `--clients`. The `--clients` flag still affects
  other scenarios in the same batch.
