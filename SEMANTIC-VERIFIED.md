# SEMANTIC-VERIFIED.md

Status of the Part 1 fanout smoke re-run: **22 of 25 scenarios succeeded and had
their semantics verified against their declared design.**

## Run Parameters

- Command template:
  `./scripts/run-benchmarks --scenarios <NAME> --clients 10 --messages 10 --client-topology container-per-client --client-memory 256m --skip-build --skip-tokens`
- Executed one scenario at a time; each validated on exit code, loadgen
  `errors == []` (except the CONTROL-DISABLE kick signature), publish count,
  receive counts, and `fanout_churn` metadata (`triggered`, `applied_events`,
  `cache_validity_signal`, pre/post buckets).

## Verified Scenarios (22)

### DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-{BISCUIT|JWT}-{100|50|10} (5)

Design: strict ACL_READ; single allow→deny policy swap at message 5;
post-churn deliveries denied; `cache_validity_signal=true`; no errors.

| Scenario | pre | post | result |
|---|---|---|---|
| `...CHURN-BISCUIT-100` | 500/500 | 0/500 | pass |
| `...CHURN-BISCUIT-50` | 250/250 | 0/250 | pass |
| `...CHURN-JWT-10` | 50/50 | 0/50 | pass |
| `...CHURN-JWT-100` | 500/500 | 0/500 | pass |
| `...CHURN-JWT-50` | 250/250 | 0/250 | pass |

All: `triggered=true`, `applied_events=1`, `post_churn_delivery_ratio=0.0`,
`cache_validity_signal=true`, publish 10/10, errors 0.

### DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-DISABLE-{BISCUIT|JWT}-{10|100|50} (6)

Design: runtime `disableClient` at message 5; plugin kicks live sessions,
producing exactly one `receive_failed` per subscriber; post-churn 0.

| Scenario | errors | pre | post |
|---|---|---|---|
| `...DISABLE-BISCUIT-10` | 10 `receive_failed` | 50/50 | 0/50 |
| `...DISABLE-BISCUIT-100` | 100 `receive_failed` | 500/500 | 0/500 |
| `...DISABLE-BISCUIT-50` | 50 `receive_failed` | 250/250 | 0/250 |
| `...DISABLE-JWT-10` | 10 `receive_failed` | 50/50 | 0/50 |
| `...DISABLE-JWT-100` | 100 `receive_failed` | 500/500 | 0/500 |
| `...DISABLE-JWT-50` | 50 `receive_failed` | 250/250 | 0/250 |

All: `triggered=true`, `applied_events=1`, `cache_validity_signal=true`,
publish 10/10.

### DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-REVOKE-{BISCUIT|JWT}-{10|50} (4)

Design: runtime `removeRoleACL` at message 5; sessions remain connected;
post-churn deliveries denied; no errors.

| Scenario | pre | post | result |
|---|---|---|---|
| `...REVOKE-BISCUIT-10` | 50/50 | 0/50 | pass |
| `...REVOKE-BISCUIT-50` | 250/250 | 0/250 | pass |
| `...REVOKE-JWT-10` | 50/50 | 0/50 | pass |
| `...REVOKE-JWT-50` | 250/250 | 0/250 | pass |

All: `triggered=true`, `applied_events=1`, `cache_validity_signal=true`,
publish 10/10, errors 0. Rerun after the collector fix (non-fanout payloads are
no longer counted): receive counts equal pre-churn exactly, zero-latency
placeholder entries eliminated (`min_ms > 0`).

### DYNAMIC-SECURITY-ANONYMOUS-BASELINE (1)

Design: fanout with anonymous subscribers/publisher via dynsec `anonymousGroup`;
no churn; all deliveries allowed.

Verified: 10 published → 100 received (10 × 10), `fanout_churn.enabled=false`,
errors 0. Runs after `mosquitto_anon.conf` fix (dynsec URL pointed at a file
that is never mounted in the container).

### DYNAMIC-SECURITY-BASELINE (1)

Design: publish-only baseline; no subscriber; no control.

Verified: 100 published (10 clients × 10 messages), 0 received, no control
events, errors 0.

### DYNAMIC-SECURITY-CHURN (1)

Design: publish-only with runtime-control barrier; quota 1 message per client,
control injected once after 10 total pre-control publishes, then first
post-control publish denied per client (loop breaks).

Verified: publish 10, control count 1, `policy_denial_count=10`,
`expiry_denial_count=0`, errors 0.

### DYNAMIC-SECURITY-READ-FANOUT (1)

Design: fanout with a single subscriber; no churn.

Verified: 10 published → 10 received, `fanout_churn.enabled=false`, errors 0.

### HTTP-ACL-READ-FANOUT-STRICT-COMPLEX-ALLOW-{BISCUIT|JWT|PARITY-BISCUIT}-10 (3)

Design: strict HTTP ACL allow; fanout with 10 subscribers; no churn.

| Scenario | published | received | result |
|---|---|---|---|
| `...ALLOW-BISCUIT-10` | 10 | 100/100 | pass |
| `...ALLOW-JWT-10` | 10 | 100/100 | pass |
| `...ALLOW-PARITY-BISCUIT-10` | 10 | 100/100 | pass |

All: `fanout_churn.enabled=false`, errors 0. Publish p50 ≈ 455 ms (per-publish
HTTP authorization round-trip, consistent across the HTTP family).

## Excluded Scenarios (3)

- **13 `...CONTROL-REVOKE-BISCUIT-100`** and **16 `...CONTROL-REVOKE-JWT-100`**:
  failed before data collection — loadgen containers were OOM-killed at the
  256m limit while loading `benchmarks/password-map.json` (kernel
  `mem_cgroup_oom`, anon-rss ~260 MB); 7–15 subscribers missing readiness
  files. No result JSON. Rerun pending the loadgen memory decision.
- **22 `DYNAMIC-SECURITY-READ-FANOUT-CHURN`**: runs successfully after the
  fixture fix (`subscriber_count: 1` + churn-snapshot rework), but its
  semantics were **not** verified: it uses `mosquitto_dynsec.conf`
  (expiry_only enforcement), where read-only ACL checks short-circuit on token
  expiry and never consult the dynsec policy, so the READ revocation in the
  churn state has no observable delivery effect (repeat 2 still delivered
  10/10). Strict READ-churn measurement is covered by the
  `...ACL-READ-FANOUT-CHURN-*` family instead.

## Notes

- Receive-latency values (2–30 s) are dominated by subscriber-vs-publisher
  startup skew; they are not per-delivery costs. Publish-side latency is the
  trustworthy signal (p50 0.04–0.8 ms, except HTTP ~455 ms).
- The plugin publishes `system_notification/{client_id}` JSON on REVOKE churn;
  the loadgen collector was counting these as fanout messages (zero-latency
  entries). Fixed via `parse_fanout_message` gate in `mqtt-loadgen.rs`;
  REVOKE scenarios 12/14/15/17 rerun with clean metrics.