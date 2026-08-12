# Full Session Summary

## The Project

MQTT authorization benchmark suite for TCC2 (undergraduate thesis). It measures the performance overhead of different authorization mechanisms (**None**, **JWT**, **Biscuit**) across multiple policy backends (**Static ACL**, **DynSec**, **HTTP**, **SQLite**, **Hybrid**) on a Mosquitto MQTT broker with a custom plugin (`mosquitto-auth-biscuit`).

## What RUN.md Describes

- **428 scenarios** (214 base + 214 TLS variants), organized into batches.
- Parameter matrix of client counts, message volumes, QoS levels, and token issuer configurations.
- Full run is estimated at **9–14 days** of continuous execution.

## What We Did (Chronologically)

### Phase 1: Smoke testing the 32 Part 2 sweep scenarios

Ran each of the 32 targeted sweep scenarios from `RUN.md` with a minimal config (10 clients, 10 messages, 1 run) to verify they work. Several scenarios were broken and required multiple attempts:

- **DYNAMIC-SECURITY-BASELINE** — `SameFileError` bug in `policy_churn.py` (copying a file to itself). Also, the DynSec config pinned `dynsec_client_1` to `clientid: client_1`, so 9 of 10 loadgen clients got rejected.
- **DYNAMIC-SECURITY-CHURN** — Same DynSec issue, plus no mechanism to apply ACL changes mid-benchmark.
- **NETWORK-MTU-200-JWT / NETWORK-MTU-1500-JWT** — Docker compose rejected the tcpdump volume path (`benchmarks/results/pcap` is not a valid volume name).
- **TOKEN-MQTT5-REAUTH-JWT/BISCUIT** — Used a different code path (`_run_mqtt5_auth`) that returns a different output shape. Initially appeared broken but was actually correct.
- **TOKEN-THUNDERING-HERD-\*** — Swapped out preemptively; turned out to work fine later.

**Major commit `c4ce14e`** added:

- The `runtime_control` mechanism for DynSec churn scenarios.
- Fix for the client ID pin issue via the `publish_multi_client_base` profile.
- Mosquitto restart after DynSec cleanup.
- Coordinated container-per-client controller support.

**Additional fixes found and applied:**

- `policy_denial_count` not shown at top level — the loadgen put it in `raw_metrics`, but nothing promoted it. Fixed by adding 3 lines in `run_scenarios.py`.
- Stale `openssl` pin in Dockerfile — Alpine repo updated from 3.5.5 to 3.5.7, breaking the Docker build. Fixed by updating the pin.

### Phase 2: Fixed-workload stress scenarios (17 scenarios)

Ran all 17 stress scenarios (publish stress, datalog stress, composability, HTTP authz complexity). **All passed with zero errors.**

One more issue found:

- `openssl` pin stale again in a different build stage. Fixed.

### Phase 3: Lifecycle/control targeted scenarios (12 scenarios)

Ran all 12. Issues found:

- **SQLITE-RBAC-CHURN-JWT/BISCUIT** — `OperationalError: attempt to write a readonly database`. The Docker container created `policy.db` as `nobody:nobody`, and the Python runner could not write to it. Fixed by adding an `os.access` check plus unlink in `policy_churn.py`.
- **SQLITE-RBAC-CHURN-BISCUIT** — Persistent Docker namespace error (`lstat /proc/.../ns/net`), caused by the netem container starting before Mosquitto was ready.

**Major commit `0a85f13`** included:

- SQLite seeding moved before compose startup (DB is created with correct ownership).
- Mosquitto healthcheck (`nc -z`) added in `docker-compose.yml`.
- Compose deployment split into phases (core services first, then namespace services after healthcheck).
- Added `_compose_checked` and `_compose_diagnostics` for better error reporting.
- Added `_validate_fanout_result` to catch silent failures.

After this, both SQLite scenarios passed cleanly (50 connects, 20 publishes, 600 receives, 0 errors).

### Phase 4: Part 1 smoke test (50 scenarios)

Attempted to run the first 50 alphabetically-sorted scenarios from the full 428-scenario list:

- **First attempt failed** — TLS variants (`-TLS` suffix) were included, and TLS certs are not set up.
- **Second attempt** (50 non-TLS scenarios) — ran 25 of 50 before `DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-BISCUIT-100` was OOM-killed (exit code 137). The loadgen container hit its 512 MB memory limit with 100 fanout clients.

All 25 completed scenarios had **zero errors**.

## Current State

| Batch | Scenarios | Status |
| --- | --- | --- |
| Part 2 sweep (32) | 32/32 | All passing |
| Fixed-workload stress (17) | 17/17 | All passing |
| Lifecycle/control targeted (12) | 12/12 | All passing |
| Part 1 smoke (50 non-TLS) | 25/50 | 25 passed, 25 remaining (OOM on 100-client fanout) |

## Remaining Work

1. **Re-run the remaining 25 Part 1 scenarios** with `--client-topology container-per-client --client-memory 256m` to handle the 100-client fanout scenarios.
2. **TLS scenarios** — TLS certificates must be generated before they can run.
3. **Full Part 1 matrix** — 428 scenarios × 2 clients × 2 messages × 3 runs = **5,136 total** (4–7 days).
4. **Full Part 2 sweep** — 32 scenarios × 36 parameter combos × 3 runs = **3,456 total** (4–7 days).

## Fixes Applied (Unstaged)

- `policy_churn.py`: added `import os` + read-only database guard in `seed_sqlite_fanout_policy`.

## Fixes Applied (Committed)

- `b97a182` — openssl pin fix
- `547151f` — `policy_denial_count` display fix
- `c87ed3c` / `019d3f4` — more pin fixes
- `c4ce14e` — runtime DynSec control mode (major)
- `0a85f13` — SQLite seeding + compose healthcheck + fanout validation (major)
