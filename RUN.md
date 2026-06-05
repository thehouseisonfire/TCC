# Full Benchmark Run Plan

This document describes how to execute the complete MQTT authorization benchmark
suite for the TCC2 project. It covers every scenario, exercises every parameter
lever, and produces a reproducible dataset for analysis.

## Overview

The benchmark suite has **402 scenarios** (201 base + 201 TLS variants) across
20 functional categories. The run plan has two parts:

| Part | What | Runs | Est. time |
|------|------|------|-----------|
| 1 | All 402 scenarios × 2 clients × 2 messages × 3 runs | 4,824 | ~4–7 days |
| 2 | 40 scenarios × 3 clients × 2 messages × 3 QoS × 2 token issuer × 3 runs | 4,320 | ~5–8 days |
| **Total** | | **9,144** | **~10–15 days** |

## Research Dimensions

Every lever below is pulled at least twice across the full plan.

| Dimension | Part 1 levels | Part 2 levels | Source |
|-----------|--------------|---------------|--------|
| Auth mechanism | None, JWT, Biscuit | None, JWT, Biscuit | Scenario ID |
| Policy backend | Static ACL, DynSec, HTTP, SQLite, Hybrid | (same) | Scenario ID |
| Token complexity | Baseline, Chain-1/5/25, Datalog-low/med/high | (same) | Scenario ID |
| TLS | Off, On | Off, On | `-TLS` suffix |
| Client count | 10, 500 | 10, 50, 500 | `--clients` |
| Message volume | 10, 100 | 10, 100 | `--messages` |
| QoS | 1 (default) | 0, 1, 2 | `--qos` |
| Token issuer | Default | Default, Stripped | `--token-issuer-no-default-roles` |

Part 1 runs every scenario across a 2×2 matrix of client counts and message
densities (3 runs each). Part 2 deepens the sweep on 40 representative
scenarios by adding a third client level, all three QoS levels, and token
issuer configuration.

## Sweep Scenarios (Part 2)

40 scenarios, 2 per category:

| # | Category | Scenario 1 | Scenario 2 |
|---|----------|------------|------------|
| 1 | Baseline no-auth | `BASELINE-NO-AUTH` | — |
| 2 | Token baseline | `TOKEN-BASELINE-JWT` | `TOKEN-BASELINE-BISCUIT` |
| 3 | Static ACL | `STATIC-ACL-PUBLISH-JWT` | `STATIC-ACL-PUBLISH-BISCUIT` |
| 4 | DynSec baseline | `DYNAMIC-SECURITY-BASELINE` | `DYNAMIC-SECURITY-CHURN` |
| 5 | HTTP profile simple | `HTTP-PROFILE-SIMPLE-JWT` | `HTTP-PROFILE-SIMPLE-BISCUIT` |
| 6 | HTTP profile complex | `HTTP-PROFILE-COMPLEX-JWT` | `HTTP-PROFILE-COMPLEX-BISCUIT` |
| 7 | HTTP latency | `HTTP-LATENCY-200MS-JWT` | `HTTP-LATENCY-1000MS-JWT` |
| 8 | SQLite RBAC | `SQLITE-RBAC-CHURN-JWT` | `SQLITE-RBAC-CHURN-BISCUIT` |
| 9 | Hybrid fallback | `HYBRID-FALLBACK-AUTHZ-DOWN-JWT` | — |
| 10 | Token complexity chain | `TOKEN-COMPLEXITY-CHAIN-5-BISCUIT` | `TOKEN-COMPLEXITY-CHAIN-25-BISCUIT` |
| 11 | Token complexity datalog | `TOKEN-COMPLEXITY-DATALOG-MED-BISCUIT` | `TOKEN-COMPLEXITY-DATALOG-HIGH-BISCUIT` |
| 12 | Token attenuation | `TOKEN-ATTENUATION-CLIENT-BISCUIT` | `TOKEN-ATTENUATION-DENY-BISCUIT` |
| 13 | Network MTU | `NETWORK-MTU-200-JWT` | `NETWORK-MTU-1500-JWT` |
| 14 | Lifecycle reauth | `TOKEN-LIFECYCLE-REAUTH-STORM-JWT` | `TOKEN-LIFECYCLE-PROACTIVE-REAUTH-JWT` |
| 15 | MQTT5 reauth | `TOKEN-MQTT5-REAUTH-JWT` | `TOKEN-MQTT5-REAUTH-BISCUIT` |
| 16 | Control overhead | `CONTROL-OVERHEAD-KICK-REAUTH-JWT` | `CONTROL-OVERHEAD-ACL-READ-NOTIFY-JWT` |
| 17 | Control churn | `CONTROL-CHURN-ACL-MODIFY-JWT` | `CONTROL-CHURN-GROUP-CLIENT-JWT` |
| 18 | Token deny | `TOKEN-DENY-READ-JWT` | `TOKEN-ATTENUATED-DENY-BISCUIT` |
| 19 | QoS | `TOKEN-QOS2-JWT` | `TOKEN-QOS2-BISCUIT` |
| 20 | Thundering herd | `TOKEN-THUNDERING-HERD-BISCUIT` | — |

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
```

## Step-by-Step Execution

All commands run from the repository root (`TCC2/`).

### Step 1: Build the plugin and generate tokens

Build once and reuse across all iterations:

```bash
cd mqtt-auth-biscuit
cargo build --locked --release -p mosquitto-auth-biscuit
cargo run --locked -p gen-tokens --bin gen-tokens
cd ../..
```

### Step 2: Part 1 — Full baseline (all 402 × 2 clients × 2 messages × 3 runs)

Generate the full scenario list:

```bash
SCENARIOS=$(cd mqtt-auth-biscuit && uv run --locked python -c "
from benchmarks.run_scenarios import _read_tokens, _build_available_scenarios, _expand_tls_matrix
t = _read_tokens('benchmarks/tokens.json')
a = _expand_tls_matrix(_build_available_scenarios(
    t, token_issuer_no_default_roles=False, token_issuer_no_default_grants=False))
print(','.join(sorted(a.keys())))
" 2>/dev/null)
```

Run the 2×2 matrix (clients × messages) with 3 repetitions:

```bash
for clients in 10 500; do
  for messages in 10 500; do
    for run in 1 2 3; do
      echo "=== Part 1: clients=$clients messages=$messages run=$run ==="
      ./scripts/run-benchmarks \
        --scenarios "$SCENARIOS" \
        --clients "$clients" \
        --messages "$messages" \
        --skip-build \
        --skip-tokens
      # Preserve results to avoid stale data in aggregator
      mv mqtt-auth-biscuit/benchmarks/results \
         mqtt-auth-biscuit/benchmarks/results-p1-c${clients}-m${messages}-r${run}
    done
  done
done
```

This produces 4,824 scenario runs across 12 invocations of `run-benchmarks`.

### Step 3: Part 2 — Parameter sweep (40 scenarios × 36 combos × 3 runs)

Define the sweep scenarios:

```bash
SWEEP_SCENARIOS="BASELINE-NO-AUTH,\
TOKEN-BASELINE-JWT,TOKEN-BASELINE-BISCUIT,\
STATIC-ACL-PUBLISH-JWT,STATIC-ACL-PUBLISH-BISCUIT,\
DYNAMIC-SECURITY-BASELINE,DYNAMIC-SECURITY-CHURN,\
HTTP-PROFILE-SIMPLE-JWT,HTTP-PROFILE-SIMPLE-BISCUIT,\
HTTP-PROFILE-COMPLEX-JWT,HTTP-PROFILE-COMPLEX-BISCUIT,\
HTTP-LATENCY-200MS-JWT,HTTP-LATENCY-1000MS-JWT,\
SQLITE-RBAC-CHURN-JWT,SQLITE-RBAC-CHURN-BISCUIT,\
HYBRID-FALLBACK-AUTHZ-DOWN-JWT,\
TOKEN-COMPLEXITY-CHAIN-5-BISCUIT,TOKEN-COMPLEXITY-CHAIN-25-BISCUIT,\
TOKEN-COMPLEXITY-DATALOG-MED-BISCUIT,TOKEN-COMPLEXITY-DATALOG-HIGH-BISCUIT,\
TOKEN-ATTENUATION-CLIENT-BISCUIT,TOKEN-ATTENUATION-DENY-BISCUIT,\
NETWORK-MTU-200-JWT,NETWORK-MTU-1500-JWT,\
TOKEN-LIFECYCLE-REAUTH-STORM-JWT,TOKEN-LIFECYCLE-PROACTIVE-REAUTH-JWT,\
TOKEN-MQTT5-REAUTH-JWT,TOKEN-MQTT5-REAUTH-BISCUIT,\
CONTROL-OVERHEAD-KICK-REAUTH-JWT,CONTROL-OVERHEAD-ACL-READ-NOTIFY-JWT,\
CONTROL-CHURN-ACL-MODIFY-JWT,CONTROL-CHURN-GROUP-CLIENT-JWT,\
TOKEN-DENY-READ-JWT,TOKEN-ATTENUATED-DENY-BISCUIT,\
TOKEN-QOS2-JWT,TOKEN-QOS2-BISCUIT,\
TOKEN-THUNDERING-HERD-BISCUIT"
```

Run the full sweep (3 clients × 2 messages × 3 QoS × 2 token issuer × 3 runs
= 108 iterations):

```bash
for clients in 10 50 500; do
  for messages in 10 50 500; do
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
              --token-issuer-no-default-roles \
              --skip-build \
              --skip-tokens
          else
            ./scripts/run-benchmarks \
              --scenarios "$SWEEP_SCENARIOS" \
              --clients "$clients" \
              --messages "$messages" \
              --qos "$qos" \
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

**Note**: `--token-issuer-no-default-grants` is not exposed by the Rust wrapper.
To include it, invoke the Python module directly instead of `run-benchmarks`:

```bash
cd mqtt-auth-biscuit
uv run --locked python -m benchmarks.run_scenarios \
  --scenarios-arg "$SWEEP_SCENARIOS" \
  --clients "$clients" \
  --messages "$messages" \
  --qos "$qos" \
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
| Part 1 (402 scenarios, 10 clients, 10 msgs) | ~4–8 h | 3 | ~12–24 h |
| Part 1 (402 scenarios, 500 clients, 10 msgs) | ~8–16 h | 3 | ~24–48 h |
| Part 1 (402 scenarios, 10 clients, 100 msgs) | ~6–12 h | 3 | ~18–36 h |
| Part 1 (402 scenarios, 500 clients, 100 msgs) | ~12–24 h | 3 | ~36–72 h |
| Part 2 (40 scenarios per invocation) | ~1–3 h | 108 | ~108–324 h |

**Conservative total: 10–15 days continuous execution.** Plan for overnight and
weekend runs. Consider splitting across multiple machines if available.

## Verifying Completeness

After all runs, count result files:

```bash
# Part 1: expect 402 JSON files per run
for d in mqtt-auth-biscuit/benchmarks/results-p1-*/; do
  count=$(ls "$d"/*.json 2>/dev/null | grep -v summary | wc -l)
  echo "$d: $count scenarios"
done

# Part 2: expect 40 JSON files per sweep run
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
- REAUTH-STORM and THUNDERING-HERD scenarios have internal client counts that
  override `--clients`. The `--clients` flag still affects other scenarios in
  the same batch.
