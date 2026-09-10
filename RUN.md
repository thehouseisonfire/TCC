# Full Benchmark Run Plan

This document describes how to execute the complete MQTT authorization benchmark
suite for the TCC2 project. It covers every scenario, exercises every parameter
lever, and produces a reproducible dataset for analysis.

Use [`TESTING.md`](TESTING.md) for the phased semantic-verification and
suspicious-result review procedure, and
[`SEMANTIC-VERIFIED.md`](SEMANTIC-VERIFIED.md) for recorded verification status.

Terminology: *Parts* are the execution matrices defined in this document;
*Phases* are verification stages in [`TESTING.md`](TESTING.md). The two
numbering schemes are unrelated: `TESTING.md` Phase 2 is an infrastructure
preflight, not Part 2 of this plan.

## Overview

The benchmark suite currently has **444 scenarios** (222 base + 222 TLS variants) across
multiple functional categories. The run plan has two parts:

| Part | What | Runs | Est. time |
|------|------|------|-----------|
| 1 | All 444 scenarios, varying every non-fixed workload axis, × 3 runs | 3,186 | ~3–5 days |
| 2 | Axis-aware representative cohorts × 3 runs | 1,530 | ~2–4 days |
| **Total** | | **4,716** | **~5–9 days** |

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
| Token issuer | Default | Default, Stripped | issuer cohort with roles/grants controls |

Part 1 runs every scenario three times and varies each workload axis that the
scenario does not define itself. Thus an ordinary scenario uses the full 2×2
client/message matrix, a fan-out scenario with a fixed subscriber slice still
uses both message levels, and a fully fixed stress workload runs once per
repetition. Part 2 deepens representative workloads only along axes that change
their effective execution. Issuer configuration uses a dedicated issuer-backed
cohort rather than being recorded against fixture credentials.

## Sweep Scenarios (Part 2)

The executable `PART2_SWEEP_COHORTS` inventory is the source of truth. It contains
32 registered scenarios partitioned by their effective workload axes:

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
| 11 | Token attenuation | `TOKEN-ATTENUATION-COMBINED-BISCUIT` | `TOKEN-ATTENUATION-SUBSCRIBE-DENY-BISCUIT` |
| 12 | Network MTU | `NETWORK-MTU-200-JWT` | `NETWORK-MTU-1500-JWT` |
| 13 | MQTT5 reauth | `TOKEN-MQTT5-REAUTH-JWT` | `TOKEN-MQTT5-REAUTH-BISCUIT` |
| 14 | Token deny | `TOKEN-DENY-READ-JWT` | `TOKEN-ATTENUATED-DENY-BISCUIT` |
| 15 | QoS | `TOKEN-QOS2-JWT` | `TOKEN-QOS2-BISCUIT` |
| 16 | Thundering herd | `TOKEN-THUNDERING-HERD-JWT` | `TOKEN-THUNDERING-HERD-BISCUIT` |
| 17 | Issuer-backed baseline | `TOKEN-ISSUER-BASELINE-JWT` | `TOKEN-ISSUER-BASELINE-BISCUIT` |

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
- `CONTROL-ENFORCEMENT-KICK-{JWT,BISCUIT}`
- `CONTROL-ENFORCEMENT-ACL-READ-NOTIFY-{JWT,BISCUIT}`
- `CONTROL-CHURN-ACL-MODIFY-{JWT,BISCUIT}`
- `CONTROL-CHURN-GROUP-CLIENT-{JWT,BISCUIT}`
- `SQLITE-RBAC-CHURN-{JWT,BISCUIT}`

Run those as targeted slices with their scenario-defined workload shape.

Part 2 omits axes that do not affect a scenario:

- `BASELINE-NO-AUTH` and `TOKEN-QOS2-{JWT,BISCUIT}` omit the QoS loop.
- `TOKEN-DENY-READ-JWT` and `TOKEN-ATTENUATED-DENY-BISCUIT` omit client and QoS loops.
- `TOKEN-MQTT5-REAUTH-{JWT,BISCUIT}` run once per repetition.

The dedicated issuer cohort is the only cohort with a default/stripped issuance axis.

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
cd ..
```

### Step 2: Part 1 — Full baseline

Generate the full scenario list (444 total scenarios across 112 matrix, 282 fixed-client, 46 fixed, and 4 reauth-storm, totaling 3,186 runs across their respective cells and 3 repetitions):

```bash
readarray -t SCENARIO_GROUPS < <(cd mqtt-auth-biscuit && uv run --locked python -c "
from benchmarks.run_scenarios import (
    _read_tokens, _build_available_scenarios, _expand_tls_matrix, _scenario_workload_shape,
)
t = _read_tokens('benchmarks/tokens.json')
a = _expand_tls_matrix(_build_available_scenarios(
    t, token_issuer_no_default_roles=False, token_issuer_no_default_grants=False))
reauth = sorted(name for name in a if name.startswith('TOKEN-LIFECYCLE-REAUTH-STORM-'))
regular = {name: scenario for name, scenario in a.items() if name not in reauth}
for shape in ('matrix', 'fixed-clients', 'fixed-messages', 'fixed'):
    print(','.join(sorted(name for name, scenario in regular.items()
                          if _scenario_workload_shape(scenario) == shape)))
print(','.join(reauth))
" 2>/dev/null)
MATRIX_SCENARIOS=${SCENARIO_GROUPS[0]}
FIXED_CLIENT_SCENARIOS=${SCENARIO_GROUPS[1]}
FIXED_MESSAGE_SCENARIOS=${SCENARIO_GROUPS[2]}
FIXED_SCENARIOS=${SCENARIO_GROUPS[3]}
REAUTH_STORM_SCENARIOS=${SCENARIO_GROUPS[4]}
```

Run the 2×2 matrix (clients × messages) with 3 repetitions:

```bash
for clients in 10 200; do
  for messages in 10 100; do
    for run in 1 2 3; do
      echo "=== Part 1: clients=$clients messages=$messages run=$run ==="
      ./scripts/run-benchmarks \
        --scenarios "$MATRIX_SCENARIOS" \
        --workload-shape matrix \
        --clients "$clients" \
        --messages "$messages" \
        --client-topology container-per-client \
        --client-memory 96m \
        --skip-build \
        --skip-tokens

      # Preserve results to avoid stale data in aggregator
      mv mqtt-auth-biscuit/benchmarks/results \
         mqtt-auth-biscuit/benchmarks/results-p1-c${clients}-m${messages}-r${run}
    done
  done
done
```

Run partially fixed workloads over the axis they do not define:

```bash
for messages in 10 100; do
  for run in 1 2 3; do
    ./scripts/run-benchmarks \
      --scenarios "$FIXED_CLIENT_SCENARIOS" \
      --workload-shape fixed-clients \
      --messages "$messages" \
      --client-topology container-per-client \
      --client-memory 96m \
      --skip-build --skip-tokens
    mv mqtt-auth-biscuit/benchmarks/results \
       mqtt-auth-biscuit/benchmarks/results-p1-fixed-clients-m${messages}-r${run}
  done
done

# This group is currently empty, but keeps the procedure correct if a scenario
# later fixes messages while leaving clients parameterized.
if [[ -n "$FIXED_MESSAGE_SCENARIOS" ]]; then
  for clients in 10 200; do
    for run in 1 2 3; do
      ./scripts/run-benchmarks \
        --scenarios "$FIXED_MESSAGE_SCENARIOS" \
        --workload-shape fixed-messages \
        --clients "$clients" \
        --client-topology container-per-client \
        --client-memory 96m \
        --skip-build --skip-tokens
      mv mqtt-auth-biscuit/benchmarks/results \
         mqtt-auth-biscuit/benchmarks/results-p1-fixed-messages-c${clients}-r${run}
    done
  done
fi
```

Run fully scenario-defined workloads once per repetition. Reauth storms use
host topology because they are incompatible with container-per-client.

```bash
for run in 1 2 3; do
  ./scripts/run-benchmarks \
    --scenarios "$FIXED_SCENARIOS" \
    --workload-shape fixed \
    --client-topology container-per-client \
    --client-memory 96m \
    --skip-build --skip-tokens
  mv mqtt-auth-biscuit/benchmarks/results \
     mqtt-auth-biscuit/benchmarks/results-p1-fixed-r${run}

  ./scripts/run-benchmarks \
    --scenarios "$REAUTH_STORM_SCENARIOS" \
    --workload-shape fixed \
    --client-topology host \
    --skip-build --skip-tokens
  mv mqtt-auth-biscuit/benchmarks/results \
     mqtt-auth-biscuit/benchmarks/results-p1-reauth-r${run}
done
```

Every result records both requested and effective clients, messages, and QoS,
plus whether each workload axis came from the CLI matrix or the scenario.

### Step 3: Part 2 — Axis-aware parameter sweep (1,530 runs)

Load the validated executable cohorts:

```bash
readarray -t PART2_COHORTS < <(cd mqtt-auth-biscuit && uv run --locked python -c '
from benchmarks.run_scenarios import PART2_SWEEP_COHORTS
for name in ("matrix", "fixed_qos", "fixed_clients_qos", "reauth", "issuer"):
    print(",".join(PART2_SWEEP_COHORTS[name]))
')
MATRIX_SCENARIOS=${PART2_COHORTS[0]}
FIXED_QOS_SCENARIOS=${PART2_COHORTS[1]}
FIXED_CLIENTS_QOS_SCENARIOS=${PART2_COHORTS[2]}
REAUTH_SCENARIOS=${PART2_COHORTS[3]}
ISSUER_SCENARIOS=${PART2_COHORTS[4]}
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
CONTROL-ENFORCEMENT-KICK-JWT,CONTROL-ENFORCEMENT-KICK-BISCUIT,\
CONTROL-ENFORCEMENT-ACL-READ-NOTIFY-JWT,CONTROL-ENFORCEMENT-ACL-READ-NOTIFY-BISCUIT,\
CONTROL-CHURN-ACL-MODIFY-JWT,CONTROL-CHURN-ACL-MODIFY-BISCUIT,\
CONTROL-CHURN-GROUP-CLIENT-JWT,CONTROL-CHURN-GROUP-CLIENT-BISCUIT,\
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

Run each cohort only across its effective axes. The ordinary cohorts contribute
1,314 runs and the issuer-backed default/stripped cohort contributes 216 runs:

```bash
run_p2() {
  label=$1 scenarios=$2 clients=$3 messages=$4 qos=$5
  shift 5
  ./scripts/run-benchmarks --scenarios "$scenarios" --clients "$clients" \
    --messages "$messages" --qos "$qos" --client-topology container-per-client \
    --client-memory 96m --skip-build --skip-tokens "$@"
  mv mqtt-auth-biscuit/benchmarks/results "mqtt-auth-biscuit/benchmarks/results-p2-${label}"
}

for run in 1 2 3; do
  for clients in 10 50 200; do
    for messages in 10 100; do
      for qos in 0 1 2; do
        run_p2 "matrix-c${clients}-m${messages}-q${qos}-r${run}" \
          "$MATRIX_SCENARIOS" "$clients" "$messages" "$qos"
      done
      run_p2 "fixed-qos-c${clients}-m${messages}-r${run}" \
        "$FIXED_QOS_SCENARIOS" "$clients" "$messages" 1
    done
  done
  for messages in 10 100; do
    run_p2 "fixed-clients-qos-m${messages}-r${run}" \
      "$FIXED_CLIENTS_QOS_SCENARIOS" 10 "$messages" 1
  done
  run_p2 "reauth-r${run}" "$REAUTH_SCENARIOS" 1 1 1

  for kind in JWT BISCUIT; do
    scenario="TOKEN-ISSUER-BASELINE-${kind}"
    for clients in 10 50 200; do for messages in 10 100; do for qos in 0 1 2; do
      run_p2 "issuer-${kind}-default-c${clients}-m${messages}-q${qos}-r${run}" \
        "$scenario" "$clients" "$messages" "$qos"
      if [ "$kind" = JWT ]; then
        run_p2 "issuer-${kind}-stripped-c${clients}-m${messages}-q${qos}-r${run}" \
          "$scenario" "$clients" "$messages" "$qos" \
          --token-issuer-no-default-roles --token-issuer-no-default-grants
      else
        run_p2 "issuer-${kind}-stripped-c${clients}-m${messages}-q${qos}-r${run}" \
          "$scenario" "$clients" "$messages" "$qos" --token-issuer-no-default-grants
      fi
    done; done; done
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

The workload-shape split means Part 1 is no longer four invocations of every
scenario. Matrix scenarios run for all four client/message combinations,
partially fixed scenarios run only over their free axis, and fully fixed
scenarios run once per repetition.

| Component | Planned scenario-runs | Estimated time |
|-----------|----------------------:|---------------:|
| Part 1 | 3,186 | ~3–5 days |
| Part 2 | 1,530 | ~2–4 days |
| **Total** | **4,716** | **~5–9 days** |

These are planning estimates, not performance results. Plan for overnight and
weekend runs and preserve each invocation's output separately.

## Verifying Completeness

After all runs, count result files:

```bash
# Part 1: each directory contains only its workload-shape group. Across all
# Part 1 directories, expect 3,186 non-summary scenario JSON files.
total=0
for d in mqtt-auth-biscuit/benchmarks/results-p1-*/; do
  count=$(find "$d" -maxdepth 1 -type f -name '*.json' \
    ! -name 'summary.json' | wc -l)
  echo "$d: $count scenarios"
  total=$((total + count))
done
echo "Part 1 total: $total / 3186"

# Part 2: expect 32 JSON files per sweep run
for d in mqtt-auth-biscuit/benchmarks/results-p2-*/; do
  count=$(find "$d" -maxdepth 1 -type f -name '*.json' \
    ! -name 'summary.json' | wc -l)
  echo "$d: $count scenarios"
done
```

## Analyzing Results

Use the aggregation script on any results directory:

```bash
cd mqtt-auth-biscuit
uv run --locked python -m benchmarks.aggregate_results \
  --input benchmarks/results-p1-c10-m10-r1 \
  --out-json summary.json \
  --out-csv summary.csv
cd ..
```

Or aggregate across all Part 1 runs for a combined view:

```bash
cd mqtt-auth-biscuit
mkdir -p benchmarks/combined-part1
for d in benchmarks/results-p1-*/; do
  cp "$d"/*.json benchmarks/combined-part1/ 2>/dev/null
done
uv run --locked python -m benchmarks.aggregate_results \
  --input benchmarks/combined-part1 \
  --out-json benchmarks/combined-part1/summary.json \
  --out-csv benchmarks/combined-part1/summary.csv
cd ..
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
