# Full Benchmark Run Plan

This plan describes how to reproduce the nominal full benchmark matrix.
The completed campaign used a prospectively reduced scope. See the
[final dataset and provenance](SEMANTIC-VERIFIED.md#final-dataset-and-provenance)
for the 4,101 accepted results and their analysis index. Use the
[verification procedure](TESTING.md) to qualify and review a new run.

## Overview

The benchmark suite currently has **444 scenarios** (222 base + 222 TLS variants) across
multiple functional categories. The run plan has two parts:

| Part | What | Runs |
| --- | --- | ---: |
| 1 | All 444 scenarios, varying every non-fixed workload axis, × 3 runs | 3,186 |
| 2 | Axis-aware representative cohorts × 3 runs | 1,512 |
| **Total** | | **4,698** |

## Research Dimensions

| Dimension | Part 1 levels | Part 2 levels | Source |
|-----------|--------------|---------------|--------|
| Auth mechanism | None, JWT, Biscuit | None, JWT, Biscuit | Scenario ID |
| Policy backend | Static ACL, DynSec, HTTP, SQLite, Hybrid | (same) | Scenario ID |
| Token complexity | Baseline, Chain-1/5/25, Datalog-low/med/high | (same) | Scenario ID |
| TLS | Off, On | Off | `-TLS` suffix |
| Client count | 10, 200 | 10, 50, 200 | `--clients` |
| Message volume | 10, 100 | 10, 100 | `--messages` |
| QoS | 1 (default) | 0, 1, 2 (churn cohort: 1, 2 only) | `--qos` |
| Token issuer | Default | Default, Stripped | issuer cohort with roles/grants controls |

Part 1 runs every scenario three times and varies each workload axis that the
scenario does not define itself. Thus an ordinary scenario uses the full 2×2
client/message matrix, a fan-out scenario with a fixed subscriber slice still
uses both message levels, and a fully fixed stress workload runs once per
repetition. Part 2 deepens representative workloads only along axes that change
their effective execution. A dedicated issuer-backed cohort varies the
issuer configuration.

## Sweep Scenarios (Part 2)

The executable `PART2_SWEEP_COHORTS` inventory is the source of truth. It contains
32 registered scenarios partitioned by their effective workload axes.
`PART2_SWEEP_COHORT_QOS` and `PART2_SWEEP_COHORT_AXES` are the executable
QoS/client/message contract. The commands below read the variable QoS levels
from that metadata.

| # | Category | Scenario 1 | Scenario 2 |
|---|----------|------------|------------|
| 1 | Baseline no-auth | `BASELINE-NO-AUTH` | — |
| 2 | Token baseline | `TOKEN-BASELINE-JWT` | `TOKEN-BASELINE-BISCUIT` |
| 3 | Static ACL | `STATIC-ACL-PUBLISH-JWT` | `STATIC-ACL-PUBLISH-BISCUIT` |
| 4 | DynSec baseline | `DYNAMIC-SECURITY-BASELINE` | — |
| 4b | DynSec churn (dedicated QoS 1/2 cohort) | `DYNAMIC-SECURITY-CHURN` | — |
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

Part 1 covers the fixed-workload stress, lifecycle, control, and fanout families
outside the Part 2 inventory. Use the [benchmark runbook](mqtt-auth-biscuit/benchmarks/RUNNING_BENCHMARKS.md)
to rerun individual scenarios.

Part 2 omits axes that do not affect a scenario:

- `BASELINE-NO-AUTH` and `TOKEN-QOS2-{JWT,BISCUIT}` omit the QoS loop.
- `TOKEN-DENY-READ-JWT` and `TOKEN-ATTENUATED-DENY-BISCUIT` omit client and QoS loops.
- `TOKEN-MQTT5-REAUTH-{JWT,BISCUIT}` run once per repetition.
- `DYNAMIC-SECURITY-CHURN` runs only at QoS 1 and QoS 2 in its dedicated
  `churn` cohort. Its `runtime_control_expect_denial` contract is only
  client-observable at QoS 1 (PUBACK rc135 / NotAuthorized) and QoS 2 (PUBREC
  rc135 / NotAuthorized). At QoS 0 Mosquitto denies the PUBLISH server-side
  but there is no acknowledgement carrying the denial, so the result contract
  is impossible to satisfy. The runner rejects `DYNAMIC-SECURITY-CHURN` with
  `--qos 0` explicitly (`_validate_part2_qos_for_scenario`), and
  `_validate_part2_sweep_inventory` rejects any placement of a
  `runtime_control_expect_denial` scenario outside the `churn` cohort.

The dedicated issuer cohort is the only cohort with a default/stripped issuance axis.

Part 2 slot arithmetic (× 3 repetitions):

- full matrix: 22 × 3 × 2 × 3 × 3 = 1,188
- churn QoS 1/2: 1 × 3 × 2 × 2 × 3 = 36
- fixed_qos: 3 × 3 × 2 × 1 × 3 = 54
- fixed_clients_qos: 2 × 1 × 2 × 1 × 3 = 12
- reauth: 2 × 1 × 1 × 1 × 3 = 6
- issuer (× 2 default/stripped modes): 2 × 3 × 2 × 3 × 2 × 3 = 216
- **Part 2 total = 1,512**

Verify mechanically with:

```bash
cd mqtt-auth-biscuit && uv run --locked python -c \
  'from benchmarks.run_scenarios import part2_expected_slot_total; print(part2_expected_slot_total())'
# expected: 1512
```

## Prerequisites

```bash
# Rust toolchain (rustc 1.93.1, pinned in rust-toolchain.toml)
rustc --version

# Python environment
uv sync --locked
uv run --locked python --version  # 3.14.2

# Docker
docker --version
docker compose version

# iperf3 (host client) and OpenSSL (TLS certificates)
iperf3 --version
openssl version
```

## Step-by-Step Execution

Run the examples from the repository root in a dedicated Bash shell. The full plan uses
`container-per-client` with a 96 MiB memory limit per client, except for the
reauthentication storms, which use host topology. Check the
[host limits for jumbo MTU scenarios](SEMANTIC-VERIFIED.md#known-interpretation-boundaries)
before attempting the full plan.

### Step 1: Prepare credentials and batch output

```bash
cd mqtt-auth-biscuit
cargo build --locked --release -p mosquitto-auth-biscuit
cargo run --locked -p gen-tokens --bin gen-tokens
bash docker/tls/generate_certs.sh
cd ..
```

For frozen Docker images, follow the [image-freeze procedure](mqtt-auth-biscuit/benchmarks/RUNNING_BENCHMARKS.md#frozen-docker-images)
and run this in the same Bash shell before starting batches:

```bash
export MQTT_NO_BUILD_IMAGES=1
```

Define this helper once. The wrapper writes to its default output directory,
including the default pcap subdirectory. The helper moves the whole output
directory only after a successful run. On failure it leaves partial output
available for review and the loop stops. The move changes the capture's
location. Resolve recorded pcap names under the archived batch's `pcap/`
directory when inspecting results.

```bash
run_full_batch() {
  local batch_dir="mqtt-auth-biscuit/benchmarks/results-$1"
  local work_dir="mqtt-auth-biscuit/benchmarks/results"
  shift
  if [[ -e "$work_dir" || -L "$work_dir" || -e "$batch_dir" || -L "$batch_dir" ]]; then
    printf 'Preserve existing output before running: %s or %s\n' "$work_dir" "$batch_dir" >&2
    return 1
  fi
  ./scripts/run-benchmarks --skip-build --skip-tokens --exclusive-out "$@" &&
    mv -T --no-clobber -- "$work_dir" "$batch_dir" &&
    [[ ! -e "$work_dir" ]]
}
```

### Step 2: Part 1 — Full baseline

Generate the scenario groups. The three repetitions cover 112 matrix scenarios,
282 fixed-client scenarios, 46 fully fixed scenarios, and four reauthentication
storms, for 3,186 results.

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
")
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
      run_full_batch "p1-c${clients}-m${messages}-r${run}" \
        --scenarios "$MATRIX_SCENARIOS" \
        --workload-shape matrix \
        --clients "$clients" \
        --messages "$messages" \
        --client-topology container-per-client \
        --client-memory 96m || exit 1
    done
  done
done
```

Run partially fixed workloads over the axis they do not define:

```bash
for messages in 10 100; do
  for run in 1 2 3; do
    run_full_batch "p1-fixed-clients-m${messages}-r${run}" \
      --scenarios "$FIXED_CLIENT_SCENARIOS" \
      --workload-shape fixed-clients \
      --messages "$messages" \
      --client-topology container-per-client \
      --client-memory 96m || exit 1
  done
done

# This group is currently empty, but keeps the procedure correct if a scenario
# later fixes messages while leaving clients parameterized.
if [[ -n "$FIXED_MESSAGE_SCENARIOS" ]]; then
  for clients in 10 200; do
    for run in 1 2 3; do
      run_full_batch "p1-fixed-messages-c${clients}-r${run}" \
        --scenarios "$FIXED_MESSAGE_SCENARIOS" \
        --workload-shape fixed-messages \
        --clients "$clients" \
        --client-topology container-per-client \
        --client-memory 96m || exit 1
    done
  done
fi
```

Run fully scenario-defined workloads once per repetition. Reauth storms use
host topology because they are incompatible with container-per-client.

```bash
for run in 1 2 3; do
  run_full_batch "p1-fixed-r${run}" \
    --scenarios "$FIXED_SCENARIOS" \
    --workload-shape fixed \
    --client-topology container-per-client \
    --client-memory 96m || exit 1

  run_full_batch "p1-reauth-r${run}" \
    --scenarios "$REAUTH_STORM_SCENARIOS" \
    --workload-shape fixed \
    --client-topology host || exit 1
done
```

Every result records both requested and effective clients, messages, and QoS,
plus whether each workload axis came from the CLI matrix or the scenario.

### Step 3: Part 2 — Axis-aware parameter sweep (1,512 runs)

Load the validated executable cohorts (including the dedicated `churn` cohort
and its machine-readable QoS levels):

```bash
readarray -t PART2_COHORTS < <(cd mqtt-auth-biscuit && uv run --locked python -c '
from benchmarks.run_scenarios import PART2_SWEEP_COHORTS
for name in ("matrix", "churn", "fixed_qos", "fixed_clients_qos", "reauth", "issuer"):
    print(",".join(PART2_SWEEP_COHORTS[name]))
')
MATRIX_SCENARIOS=${PART2_COHORTS[0]}
CHURN_SCENARIOS=${PART2_COHORTS[1]}
FIXED_QOS_SCENARIOS=${PART2_COHORTS[2]}
FIXED_CLIENTS_QOS_SCENARIOS=${PART2_COHORTS[3]}
REAUTH_SCENARIOS=${PART2_COHORTS[4]}
ISSUER_SCENARIOS=${PART2_COHORTS[5]}
readarray -t PART2_QOS_LEVELS < <(cd mqtt-auth-biscuit && uv run --locked python -c '
from benchmarks.run_scenarios import PART2_SWEEP_COHORT_QOS
for name in ("matrix", "churn", "fixed_qos", "fixed_clients_qos", "reauth", "issuer"):
    print(" ".join(map(str, PART2_SWEEP_COHORT_QOS[name])))
')
MATRIX_QOS=${PART2_QOS_LEVELS[0]}
CHURN_QOS=${PART2_QOS_LEVELS[1]}
ISSUER_QOS=${PART2_QOS_LEVELS[5]}
```

Run each cohort only across its effective axes. The ordinary cohorts contribute
1,296 runs and the issuer-backed default/stripped cohort contributes 216 runs:

```bash
run_p2() {
  local label=$1 scenarios=$2 clients=$3 messages=$4 qos=$5
  shift 5
  run_full_batch "p2-${label}" --scenarios "$scenarios" --clients "$clients" \
    --messages "$messages" --qos "$qos" --client-topology container-per-client \
    --client-memory 96m "$@" || exit 1
}

for run in 1 2 3; do
  for clients in 10 50 200; do
    for messages in 10 100; do
      for qos in $MATRIX_QOS; do
        run_p2 "matrix-c${clients}-m${messages}-q${qos}-r${run}" \
          "$MATRIX_SCENARIOS" "$clients" "$messages" "$qos"
      done
      for qos in $CHURN_QOS; do
        run_p2 "churn-c${clients}-m${messages}-q${qos}-r${run}" \
          "$CHURN_SCENARIOS" "$clients" "$messages" "$qos"
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

  for scenario in ${ISSUER_SCENARIOS//,/ }; do
    kind=${scenario##*-}
    for clients in 10 50 200; do for messages in 10 100; do for qos in $ISSUER_QOS; do
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

### Step 4: Collect results

All results land in `mqtt-auth-biscuit/benchmarks/results-p{1,2}-*/`.

Each directory contains these outputs when applicable.

| File | Content |
|------|---------|
| `<SCENARIO_ID>.json` | Per-scenario metrics (latency, throughput, resource snapshots) |
| `summary.json` | Aggregated metrics across all scenarios in that run |
| `summary.csv` | Same as CSV |
| `pcap/<SCENARIO_ID>.pcap` | Packet captures for MTU scenarios |

## Verifying completeness

For a new full reproduction, reconcile each batch with the registry inventory,
workload coordinates, and repetition before reviewing the measurements. Expect
3,186 Part 1 and 1,512 Part 2 scenario JSONs. A Part 2 batch contains 22 matrix
results, one churn result, three fixed-QoS results, two fixed-client/QoS results,
two reauth results, or one result per issuer kind and mode. Use the
[verification procedure](TESTING.md#phase-8--final-completeness-and-sign-off)
to check uniqueness, result contracts, and exclusions. A file count alone
cannot establish completeness.

## Analyzing results

For the completed campaign, start with the
[final analysis index](SEMANTIC-VERIFIED.md#final-dataset-and-provenance).

For a new invocation, inspect its raw scenario JSONs and generated summaries.
You can regenerate the summaries for an individual batch:

```bash
cd mqtt-auth-biscuit
batch=benchmarks/results-p1-c10-m10-r1
uv run --locked python -m benchmarks.aggregate_results \
  --input "$batch" \
  --out-json "$PWD/${batch}-summary-review.json" \
  --out-csv "$PWD/${batch}-summary-review.csv"
cd ..
```

The aggregator resolves relative output paths inside the input batch and
reads every top-level JSON except `summary.json`. Use absolute paths to write
review summaries beside the batch. Keep each result tied to
its batch coordinates and repetition when pooling data for analysis. Filenames
repeat across batches, so copying them into one directory can overwrite
results. Per-run latency percentiles summarize different samples and cannot
be pooled by treating their average as a sample-level percentile.
