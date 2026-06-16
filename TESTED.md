# Smoke Test Results

Run config: `--clients 5 --messages 5 --client-topology container-per-client --client-memory 96m`

## Scenarios 1–40

| # | Scenario | Status |
|---|----------|--------|
| 1 | BASELINE-NO-AUTH | Completed |
| 2 | BASELINE-NO-AUTH-QOS0 | Completed |
| 3 | BASELINE-NO-AUTH-QOS0-TLS | Completed |
| 4 | BASELINE-NO-AUTH-TLS | Completed |
| 5 | CONTROL-CHURN-ACL-MODIFY-BISCUIT | Completed |
| 6 | CONTROL-CHURN-ACL-MODIFY-BISCUIT-TLS | Completed |
| 7 | CONTROL-CHURN-ACL-MODIFY-JWT | Completed |
| 8 | CONTROL-CHURN-ACL-MODIFY-JWT-TLS | Completed |
| 9 | CONTROL-CHURN-CONCURRENT-CONTROLLERS-BISCUIT | Completed |
| 10 | CONTROL-CHURN-CONCURRENT-CONTROLLERS-BISCUIT-TLS | Completed |
| 11 | CONTROL-CHURN-CONCURRENT-CONTROLLERS-JWT | Completed |
| 12 | CONTROL-CHURN-CONCURRENT-CONTROLLERS-JWT-TLS | Completed |
| 13 | CONTROL-CHURN-CREATE-ROLE-BISCUIT | Completed |
| 14 | CONTROL-CHURN-CREATE-ROLE-BISCUIT-TLS | Completed |
| 15 | CONTROL-CHURN-CREATE-ROLE-JWT | Completed |
| 16 | CONTROL-CHURN-CREATE-ROLE-JWT-TLS | Completed |
| 17 | CONTROL-CHURN-GROUP-CLIENT-BISCUIT | Completed |
| 18 | CONTROL-CHURN-GROUP-CLIENT-BISCUIT-TLS | Completed |
| 19 | CONTROL-CHURN-GROUP-CLIENT-JWT | Completed |
| 20 | CONTROL-CHURN-GROUP-CLIENT-JWT-TLS | Completed |
| 21 | CONTROL-CHURN-LARGE-STATE-GROUP-CLIENT-BISCUIT | Completed |
| 22 | CONTROL-CHURN-LARGE-STATE-GROUP-CLIENT-BISCUIT-TLS | Completed |
| 23 | CONTROL-CHURN-LARGE-STATE-GROUP-CLIENT-JWT | Completed |
| 24 | CONTROL-CHURN-LARGE-STATE-GROUP-CLIENT-JWT-TLS | Completed |
| 25 | CONTROL-CHURN-NOOP-GROUP-CLIENT-BISCUIT | Completed |
| 26 | CONTROL-CHURN-NOOP-GROUP-CLIENT-BISCUIT-TLS | Completed |
| 27 | CONTROL-CHURN-NOOP-GROUP-CLIENT-JWT | Completed |
| 28 | CONTROL-CHURN-NOOP-GROUP-CLIENT-JWT-TLS | Completed |
| 29 | CONTROL-CHURN-REPEAT-DISTINCT-ENTITY-BISCUIT | Completed |
| 30 | CONTROL-CHURN-REPEAT-DISTINCT-ENTITY-BISCUIT-TLS | Completed |
| 31 | CONTROL-CHURN-REPEAT-DISTINCT-ENTITY-JWT | Completed |
| 32 | CONTROL-CHURN-REPEAT-DISTINCT-ENTITY-JWT-TLS | Completed |
| 33 | CONTROL-CHURN-REPEAT-SAME-ENTITY-BISCUIT | Completed |
| 34 | CONTROL-CHURN-REPEAT-SAME-ENTITY-BISCUIT-TLS | Completed |
| 35 | CONTROL-CHURN-REPEAT-SAME-ENTITY-JWT | Completed |
| 36 | CONTROL-CHURN-REPEAT-SAME-ENTITY-JWT-TLS | Completed |
| 37 | CONTROL-INTERLEAVED-DATA-BISCUIT | Completed |
| 38 | CONTROL-INTERLEAVED-DATA-BISCUIT-TLS | Completed |
| 39 | CONTROL-INTERLEAVED-DATA-JWT | Completed |
| 40 | CONTROL-INTERLEAVED-DATA-JWT-TLS | Completed |

## Scenarios 41–84

| # | Scenario | Status |
|---|----------|--------|
| 41 | CONTROL-OVERHEAD-ACL-READ-NOTIFY-BISCUIT | Completed |
| 42 | CONTROL-OVERHEAD-ACL-READ-NOTIFY-BISCUIT-TLS | Completed |
| 43 | CONTROL-OVERHEAD-ACL-READ-NOTIFY-JWT | Completed |
| 44 | CONTROL-OVERHEAD-ACL-READ-NOTIFY-JWT-TLS | Completed |
| 45 | CONTROL-OVERHEAD-KICK-REAUTH-BISCUIT | Completed |
| 46 | CONTROL-OVERHEAD-KICK-REAUTH-BISCUIT-TLS | Completed |
| 47 | CONTROL-OVERHEAD-KICK-REAUTH-JWT | Completed |
| 48 | CONTROL-OVERHEAD-KICK-REAUTH-JWT-TLS | Completed |
| 49 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-BISCUIT-10 | Completed |
| 50 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-BISCUIT-10-TLS | Completed |
| 51 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-BISCUIT-100 | Completed |
| 52 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-BISCUIT-100-TLS | Completed |
| 53 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-BISCUIT-50 | Completed |
| 54 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-BISCUIT-50-TLS | Completed |
| 55 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-JWT-10 | Completed |
| 56 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-JWT-10-TLS | Completed |
| 57 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-JWT-100 | Completed |
| 58 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-JWT-100-TLS | Completed |
| 59 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-JWT-50 | Completed |
| 60 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-JWT-50-TLS | Completed |
| 61 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-DISABLE-BISCUIT-10 | Completed |
| 62 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-DISABLE-BISCUIT-10-TLS | Completed |
| 63 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-DISABLE-BISCUIT-100 | Completed |
| 64 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-DISABLE-BISCUIT-100-TLS | Completed |
| 65 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-DISABLE-BISCUIT-50 | Completed |
| 66 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-DISABLE-BISCUIT-50-TLS | Completed |
| 67 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-DISABLE-JWT-10 | Completed |
| 68 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-DISABLE-JWT-10-TLS | Completed |
| 69 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-DISABLE-JWT-100 | Completed |
| 70 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-DISABLE-JWT-100-TLS | Completed |
| 71 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-DISABLE-JWT-50 | Completed |
| 72 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-DISABLE-JWT-50-TLS | Completed |
| 73 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-REVOKE-BISCUIT-10 | Completed |
| 74 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-REVOKE-BISCUIT-10-TLS | Completed |
| 75 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-REVOKE-BISCUIT-100 | Completed |
| 76 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-REVOKE-BISCUIT-100-TLS | Completed |
| 77 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-REVOKE-BISCUIT-50 | Completed |
| 78 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-REVOKE-BISCUIT-50-TLS | Completed |
| 79 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-REVOKE-JWT-10 | Completed |
| 80 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-REVOKE-JWT-10-TLS | Completed |
| 81 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-REVOKE-JWT-100 | Completed |
| 82 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-REVOKE-JWT-100-TLS | Completed |
| 83 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-REVOKE-JWT-50 | Completed |
| 84 | DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-REVOKE-JWT-50-TLS | Completed |

## Bugs Found

### Per-scenario TLS CA resolution (`run_scenarios.py:6118`)

When `--tls` global flag is not set but a scenario has `tls: True` (via `-TLS` suffix expansion), `tls_ca` was `None`. The health check then connected to `https://localhost:8443/health` without a CA bundle and failed with `CERTIFICATE_VERIFY_FAILED`.

Fix: default `tls_ca` to `docker/tls/ca.pem` when `scenario_tls` is True, even without the global `--tls` flag.

### CA cert missing key usage extensions (`generate_certs.sh`)

The CA cert was generated with a bare `openssl req -x509` without `basicConstraints=CA:TRUE` or `keyUsage=keyCertSign,cRLSign` extensions. Modern Python/OpenSSL rejects certs without these for chain validation.

Fix: added `-extensions ca_extensions -config ca_ext.cnf` to the CA generation step.

## Concerns

### High receive latency in non-TLS CHURN scenarios

The `dynamic_security_swap` churn operation (used by `DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-*`) writes a new DynSec JSON config to disk and restarts mosquitto. This produces much higher receive latencies than the `dynamic_security_control` churn (used by `CONTROL-DISABLE` and `CONTROL-REVOKE`), which sends an in-memory MQTT control message.

Non-TLS CHURN latencies at scale are significantly worse than their TLS counterparts, suggesting Docker scheduling contention when many containers are active:

| Scenario | recv_p50 (non-TLS) | recv_p50 (TLS) |
|----------|-------------------|----------------|
| CHURN-BISCUIT-10 | 2,351ms | 658ms |
| CHURN-BISCUIT-50 | 3,448ms | 1,284ms |
| CHURN-BISCUIT-100 | 5,189ms | 1,734ms |
| CHURN-JWT-50 | **16,947ms** | 2,564ms |
| CHURN-JWT-100 | **13,420ms** | 2,111ms |

Contrast with CONTROL-DISABLE (same subscriber counts, `dynamic_security_control`):

| Scenario | recv_p50 (non-TLS) | recv_p50 (TLS) |
|----------|-------------------|----------------|
| DISABLE-BISCUIT-10 | 571ms | 585ms |
| DISABLE-BISCUIT-50 | 1,012ms | 10,171ms |
| DISABLE-BISCUIT-100 | 1,453ms | 1,860ms |

The CHURN scenarios are not broken — they produce correct message counts — but the latency profile at higher subscriber counts may not be representative of steady-state behavior. The `dynamic_security_swap` disk I/O + mosquitto restart is the bottleneck, not the MQTT path itself.
