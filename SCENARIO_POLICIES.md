# Scenario Policies (Issue 9)

This document enumerates the **authorization policies** used across benchmark scenarios and
analyzes parity between JWT and Biscuit enforcement. It is intended to keep the experimental
comparison aligned with the research goals and constraints in `ARTICLE.md` and to avoid
unfairly advantaging one token format.

Execution commands and run workflow are documented in
`mqtt-auth-biscuit/benchmarks/RUNNING_BENCHMARKS.md`.

## 1) Policy Sources (What Decides Access)

| Policy Source | Where Defined | Used By | Notes |
| --- | --- | --- | --- |
| Token-only rules | JWT claims (`grants`, `denies`), Biscuit facts (`right`, `deny`) | `policy_mode=token` | Same deny-over-allow semantics. JWT uses MQTT wildcard filters; Biscuit uses MQTT wildcard filters via topic matching. |
| HTTP policy (introspection) | `crates/authz-server/src/main.rs` | `policy_mode=http` or `hybrid` | Rule engine with deny-over-allow semantics, operation/client/role/topic matching, MQTT wildcards, and explicit `simple`/`med`/`complex` or `custom` scenario policy. Reset baseline is neutral `custom` + empty rules (default deny). |
| Static ACL file | `docker/static-acl.conf` | `policy_mode=static_acl` | Compound gate with token + Mosquitto native ACLs. Token allow short-circuits; token deny defers to ACL. |
| Dynamic Security snapshot | `docker/dynamic-security*.json` | `policy_mode=dynamic_security` | Local snapshot of Mosquitto dynsec-like RBAC, reloaded on interval. |
| SQLite policy | `sqlite_policy.rs` + `benchmarks/policy_churn.py` | `policy_mode=sqlite` | RBAC-aware SQLite backend (`users`, `roles`, `user_roles`, `role_acls`, `role_deny_acls`) with role priorities, deny-over-allow precedence, legacy `acl` fallback for compatibility, and deterministic fan-out seed/churn helpers. |

### Token-Only Authorization Semantics

JWT and Biscuit follow the same evaluation order:

1. **Deny-first:** if a deny matches, access is rejected.
2. **Allow-next:** if an allow matches, access is accepted.
3. **Default deny** if no match.

See `mqtt-auth-biscuit/crates/mosquitto-plugin/src/authz.rs` and
`mqtt-auth-biscuit/crates/mosquitto-plugin/src/biscuit_handler.rs` for the
policy logic and authorizer template.

### JWT Token-Only Claims

JWTs carry the following in `grants` and `denies`:

```json
{ "op": "publish|subscribe|read", "res": "topic/filter" }
```

- Wildcards are supported (`+`, `#`).
- `read` falls back to `subscribe` when no explicit read rule exists.
- Deny rules can be used to override a broad allow.

Claims are generated in `gen-tokens` and `token-issuer`
(`mqtt-auth-biscuit/crates/benchmarks/src/main.rs` and
`mqtt-auth-biscuit/crates/token-issuer/src/main.rs`).

### Biscuit Token-Only Facts

Tokens include facts such as:

- `right("publish", "sensors/client_1/temp")`
- `right("subscribe", "sensors/client_1/temp")`
- `deny("op", "res")`
- `expires_at(<unix>)`

The authorizer collects `right/deny` facts and applies MQTT wildcard matching
(`+`, `#`) against the request topic, with deny-over-allow semantics. See
`mqtt-auth-biscuit/crates/mosquitto-plugin/src/biscuit_handler.rs`.

**Topic-matching parity note:** JWT and Biscuit both honor wildcard topic filters in token-only mode, keeping policy templates aligned for fair comparisons. This is not the same as `parity_identity_bound`: token-only scenarios remain `capability` unless the scenario is an explicit `-PARITY-` variant with strict binding enabled for both token types.

## 1.1 Scenario Semantic Classes (Source Of Truth)

The benchmark registry in `benchmarks/run_scenarios.py` classifies every runnable
scenario with:

- `semantic_class`: `capability`, `mixed`, or `parity_identity_bound`
- `jwt_identity_binding`: `off` or `strict`
- `biscuit_identity_binding`: `off` or `strict`

For strict Biscuit binding, the plugin also accepts `biscuit_client_id_fact`.
The default predicate is `client_id`. Scenarios that override it must keep the
issued Biscuit facts and generated Mosquitto plugin config aligned to the same
predicate.

The current inventory is:

| Scenario family / IDs | semantic_class | JWT binding | Biscuit binding | Provisioning / interpretation |
| --- | --- | --- | --- | --- |
| `BASELINE-*`, `TOKEN-BASELINE-*`, `TOKEN-DENY-READ-JWT`, `TOKEN-ATTENUATED-DENY-BISCUIT`, `TOKEN-QOS*`, `NETWORK-MTU-*`, `TOKEN-THUNDERING-HERD-BISCUIT` | `capability` | `off` | `off` | Shared fixture tokens are allowed when the scenario declares bearer/capability semantics. `BASELINE-NO-AUTH-QOS0` is the no-auth QoS 0 baseline variant. `TOKEN-THUNDERING-HERD-BISCUIT` uses synchronized connection start orchestration, but remains a capability scenario. |
| `TOKEN-COMPLEXITY-*`, `TOKEN-AUTHORIZER-PROFILE-*` | `capability` | `off` | `off` | Cost-isolation scenarios, not identity-bound parity. |
| `HTTP-LATENCY-*` without `-PARITY-`, `HTTP-PROFILE-*` without `-PARITY-`, `HYBRID-FALLBACK-AUTHZ-DOWN-JWT` | `capability` | `off` | `off` | Policy behavior may be compared, but these are not identity-bound parity claims. |
| `HTTP-LATENCY-200MS-PARITY-*`, `HTTP-PROFILE-{SIMPLE,MED,COMPLEX}-PARITY-*` | `parity_identity_bound` | `strict` | `strict` | Single-client parity variants. JWT variants require strict JWT fixtures; Biscuit variants require strict Biscuit fixtures. |
| `TOKEN-ACL-READ-FANOUT-EXPIRY-ONLY-*`, `TOKEN-ACL-READ-FANOUT-STRICT-*` without `-PARITY-`, `HTTP-ACL-READ-FANOUT-STRICT-*` without `-PARITY-`, `HYBRID-ACL-READ-FANOUT-STRICT-*` without `-PARITY-` | `capability` | `off` | `off` | Multi-client shared-token fan-out remains intentional here, so these strict `ACL_READ` scenarios are not parity scenarios. |
| `HTTP-ACL-READ-FANOUT-STRICT-*-PARITY-*`, `HYBRID-ACL-READ-FANOUT-STRICT-*-PARITY-*` | `parity_identity_bound` | `strict` | `strict` | Runnable multi-client parity now depends on per-client strict provisioning at startup. The harness provisions one token per client identity instead of reusing a shared token. Token-backed strict fan-out stays `capability`, because runtime-issued startup tokens do not reproduce the fixture-specific fan-out grants/denies. |
| `STATIC-ACL-*` | `capability` | `off` | `off` | Role-only tokens feed Mosquitto ACL evaluation; ACL files remain authoritative. |
| `DYNAMIC-SECURITY-*` (including `DYNAMIC-SECURITY-ANONYMOUS-BASELINE`, control revoke/disable, fan-out churn) | `capability` | `off` | `off` | Policy source is Dynamic Security, not identity-bound parity. |
| `SQLITE-ACL-READ-FANOUT-CHURN-*`, `SQLITE-RBAC-CHURN-*`, `SQLITE-RBAC-DEEP-CONFLICT-*` | `capability` | `off` | `off` | SQLite policy churn / conflict scenarios, not identity parity. |
| `CONTROL-INTERLEAVED-DATA-*`, `CONTROL-CHURN-CONCURRENT-CONTROLLERS-*`, `CONTROL-CHURN-REPEAT-*`, `CONTROL-OVERHEAD-ACL-READ-NOTIFY-*` | `capability` | `off` | `off` | Control-plane measurements that intentionally keep shared-token-capability semantics. |
| `CONTROL-OVERHEAD-KICK-REAUTH-*`, `CONTROL-CHURN-{CREATE-ROLE,GROUP-CLIENT,ACL-MODIFY,LARGE-STATE-GROUP-CLIENT,NOOP-GROUP-CLIENT}-*`, `SQLITE-RBAC-DEEP-CONTROL-*` | `mixed` | `strict` | `off` | JWT client binding is enabled, Biscuit client binding is not. These scenarios must not be described as parity. |
| `TOKEN-MQTT5-REAUTH-*`, `TOKEN-LIFECYCLE-SHORT-RECONNECT-*`, `TOKEN-LIFECYCLE-PROACTIVE-REAUTH-*` | `capability` | `off` | `off` | Lifecycle behavior with capability fixtures. |
| `TOKEN-ATTENUATION-*`, `TOKEN-DELEGATION-*` | `capability` | `off` | `off` | Biscuit-only capability scenarios. They are intentionally not parity scenarios because attenuation/delegation are the feature under test. |

## 2) Scenario-To-Policy Mapping

The scenario IDs are defined in `benchmarks/run_scenarios.py`. Generated
families are also expanded there at runtime, so this document intentionally
references scenario family names rather than brittle source-line ranges.

### 2.1 Baseline Token-Only Comparison (`capability`, JWT `off`, Biscuit `off`)

| Scenario | Token | Policy Source | Policy Detail | Expected Outcome |
| --- | --- | --- | --- | --- |
| BASELINE-NO-AUTH | None | None | No authn/authz | Allows all |
| BASELINE-NO-AUTH-QOS0 | None | None | No authn/authz with explicit QoS 0 baseline | Allows all |
| TOKEN-BASELINE-JWT | JWT | Token-only | `grants` include publish/subscribe on `sensors/{client_id}/temp` | Allows |
| TOKEN-BASELINE-BISCUIT | Biscuit | Token-only | `right(publish|subscribe, sensors/{client_id}/temp)` | Allows |
| TOKEN-DENY-READ-JWT | JWT | Token-only | Fan-out subscriber token grants publish/subscribe and denies read on `fanout/broadcast`; a separate allowed publisher emits the workload | Strict ACL_READ deny; zero deliveries required |
| TOKEN-ATTENUATED-DENY-BISCUIT | Biscuit | Token-only | Fan-out subscriber token has base rights plus a deny-read fact on `fanout/broadcast`; a separate allowed publisher emits the workload | Strict ACL_READ deny; zero deliveries required |
| TOKEN-QOS2-JWT / TOKEN-QOS2-BISCUIT | JWT/Biscuit | Token-only | Baseline token policy with QoS 2 publishing | Allows |
| TOKEN-QOS-MIXED-JWT / TOKEN-QOS-MIXED-BISCUIT | JWT/Biscuit | Token-only | Baseline token policy with mixed QoS distribution | Allows |

Tokens are in `benchmarks/tokens.json` (generated by `gen-tokens`).

### 2.1.1 Synchronized Connection Burst (`capability`, JWT `off`, Biscuit `off`)

| Scenario | Token | Policy Source | Policy Detail | Expected Outcome |
| --- | --- | --- | --- | --- |
| TOKEN-THUNDERING-HERD-BISCUIT | Biscuit | Token-only | Baseline Biscuit token policy with synchronized client connection start | Allows; measures burst connection/authentication cost |

This scenario is an orchestration stress test, not an identity-bound parity
claim. In `container-single` topology, Rust `mqtt-loadgen` uses an in-process
sync gate. In `container-per-client` topology, `run_scenarios.py` launches one
loadgen container per MQTT client and coordinates release through the
`sync-barrier` service, recording barrier readiness/skew metadata in the
scenario result.

### 2.2 Policy Complexity (Biscuit Only)

#### A) Block-Chain Length (Empty Blocks)

| Scenario | Token | Policy Source | Policy Detail | Expected Outcome |
| --- | --- | --- | --- | --- |
| TOKEN-COMPLEXITY-CHAIN-1-BISCUIT | Biscuit | Token-only | 1 block, same rights | Allows |
| TOKEN-COMPLEXITY-CHAIN-5-BISCUIT | Biscuit | Token-only | 5 blocks (extra empty blocks) | Allows |
| TOKEN-COMPLEXITY-CHAIN-25-BISCUIT | Biscuit | Token-only | 25 blocks (extra empty blocks) | Allows |

**Analysis:** these scenarios **stress block-chain length**, not policy complexity. Datalog
rules are unchanged across 1/5/25; they isolate signature chain overhead, not rule
complexity. Scenario outputs include `complexity.axis = "chain_length"`.

#### B) Datalog Complexity (Rich Rules)

| Scenario | Token | Policy Source | Policy Detail | Expected Outcome |
| --- | --- | --- | --- | --- |
| TOKEN-COMPLEXITY-DATALOG-LOW-BISCUIT | Biscuit | Token-only | Base RBAC + group mapping | Allows |
| TOKEN-COMPLEXITY-DATALOG-MED-BISCUIT | Biscuit | Token-only | Adds scoped ownership + capability checks + time constraint | Allows |
| TOKEN-COMPLEXITY-DATALOG-HIGH-BISCUIT | Biscuit | Token-only | Adds regional + device-class derivations + extra time checks | Allows |

**Analysis:** these scenarios keep the same topic/operation and token size class, while
increasing rule count and block structure to isolate Datalog evaluation cost.
Scenario outputs include `complexity.axis = "datalog"`. Tokens are defined in
`gen-tokens` (see `biscuit_complex_*` in
`mqtt-auth-biscuit/crates/benchmarks/src/main.rs`).

#### C) Explicit Publish-Path Stress

| Scenario | Token | Policy Source | Policy Detail | Expected Outcome |
| --- | --- | --- | --- | --- |
| TOKEN-PUBLISH-STRESS-JWT | JWT | Token-only | Baseline JWT grants on `sensors/{client_id}/temp`, fixed at 25 clients x 1000 publishes/client | Allows |
| TOKEN-PUBLISH-STRESS-BISCUIT | Biscuit | Token-only | Baseline Biscuit rights on `sensors/{client_id}/temp`, fixed at 25 clients x 1000 publishes/client | Allows |
| TOKEN-PUBLISH-STRESS-RECONNECT-JWT | JWT | Token-only | Same publish workload, repeated across 6 full reconnect cycles with issuer-backed refresh | Allows |
| TOKEN-PUBLISH-STRESS-RECONNECT-BISCUIT | Biscuit | Token-only | Same publish workload, repeated across 6 full reconnect cycles with issuer-backed refresh | Allows |

**Analysis:** these scenarios make publish-path authorization stress explicit
instead of relying on caller-supplied `--messages`. The reconnect variants stay
on the standard full CONNECT / publish / disconnect path rather than MQTT v5
in-session reauth, so they combine authentication churn and steady-state
publish-path ACL evaluation in one workload.

#### D) Fixed-Workload Datalog Stress

| Scenario | Token | Policy Source | Policy Detail | Expected Outcome |
| --- | --- | --- | --- | --- |
| TOKEN-DATALOG-STRESS-LOW-BISCUIT | Biscuit | Token-only | Low-complexity Datalog token on `sensors/{client_id}/temp`, fixed at 25 clients x 1000 publishes/client | Allows |
| TOKEN-DATALOG-STRESS-MED-BISCUIT | Biscuit | Token-only | Medium-complexity Datalog token on `sensors/{client_id}/temp`, fixed at 25 clients x 1000 publishes/client | Allows |
| TOKEN-DATALOG-STRESS-HIGH-BISCUIT | Biscuit | Token-only | High-complexity Datalog token on `sensors/{client_id}/temp`, fixed at 25 clients x 1000 publishes/client | Allows |

**Analysis:** these scenarios reuse the existing low/med/high complex Biscuit
fixtures but pin the publish workload so local Datalog evaluation cost can be
measured under an explicit high-volume slice rather than caller-supplied
message counts.

#### E) Authorizer Template Complexity (Constant Token Size)

| Scenario | Token | Policy Source | Policy Detail | Expected Outcome |
| --- | --- | --- | --- | --- |
| TOKEN-AUTHORIZER-PROFILE-SIMPLE-BISCUIT | Biscuit | Token-only | `plugin_opt_biscuit_authorizer_profile=simple` with direct `right/deny` evaluation | Allows |
| TOKEN-AUTHORIZER-PROFILE-RBAC-BISCUIT | Biscuit | Token-only | `plugin_opt_biscuit_authorizer_profile=rbac` with role-derived `role_right/role_deny` support | Allows |
| TOKEN-AUTHORIZER-PROFILE-CONTEXTUAL-BISCUIT | Biscuit | Token-only | `plugin_opt_biscuit_authorizer_profile=contextual` with strict role + active-window evaluation for role-derived rights/denies; direct `right` ignored and direct `deny` enforced | Allows |

**Analysis:** these scenarios reuse a single deterministic token fixture
(`biscuit_authorizer_template`) so `token_len` remains constant while only the
plugin-side authorizer template/rule complexity changes. Scenario outputs include
`complexity.axis = "authorizer_template"`.

### 2.3 HTTP Introspection Capability Runs (`capability`, JWT `off`, Biscuit `off`)

| Scenario | Token | Policy Source | Policy Detail | Expected Outcome |
| --- | --- | --- | --- | --- |
| HTTP-LATENCY-200MS-JWT | JWT | HTTP | Explicit `simple` profile with 200 ms PDP delay | Allows |
| HTTP-LATENCY-1000MS-JWT | JWT | HTTP | Explicit `simple` profile with 1000 ms PDP delay | Allows |
| HTTP-LATENCY-200MS-BISCUIT | Biscuit | HTTP | Explicit `simple` profile with 200 ms PDP delay; no JWT passed to PDP | Allows |
| HTTP-LATENCY-200MS-FAILURE-1PCT-JWT / HTTP-LATENCY-200MS-FAILURE-5PCT-JWT | JWT | HTTP | Explicit `simple` profile with injected failures | Flaky by design |
| HYBRID-FALLBACK-AUTHZ-DOWN-JWT | JWT | Hybrid | Explicit `simple` profile; HTTP always fails, fallback to token-only | Allows (token-only) |
| HTTP-PROFILE-SIMPLE-JWT/BIS | JWT/Biscuit | HTTP | Profile `simple`: operation-aware + wildcard allow/deny baseline | Allows |
| HTTP-PROFILE-MED-JWT/BIS | JWT/Biscuit | HTTP | Profile `med`: adds deny rules and role-aware rules | Allows |
| HTTP-PROFILE-COMPLEX-JWT/BIS | JWT/Biscuit | HTTP | Profile `complex`: deny-first with client/role/topic constraints | Allows |
| HTTP-AUTHZ-COMPLEXITY-SIMPLE-JWT/BIS | JWT/Biscuit | HTTP | Profile `simple`, fixed at 25 clients x 1000 publishes/client | Allows |
| HTTP-AUTHZ-COMPLEXITY-MED-JWT/BIS | JWT/Biscuit | HTTP | Profile `med`, fixed at 25 clients x 1000 publishes/client | Allows |
| HTTP-AUTHZ-COMPLEXITY-COMPLEX-JWT/BIS | JWT/Biscuit | HTTP | Profile `complex`, fixed at 25 clients x 1000 publishes/client | Allows |

HTTP server behavior is defined in `crates/authz-server/src/main.rs`.
It now evaluates rules in this order: `deny` first, then `allow`, then default deny.
Rule selectors include operation, MQTT filter topic, client ID, and roles
(roles can come from static `client_roles` mapping and JWT claims when present).
The authz server reset baseline is intentionally neutral: `authz_profile=custom`
with empty rules, which denies by default until the scenario applies an
explicit profile or `custom` rule set. Benchmark scenarios must not rely on
startup/reset state to silently provide allow semantics.

The `HTTP-AUTHZ-COMPLEXITY-*` family exists to provide a cross-token
authorization-complexity comparison that does not depend on Biscuit-specific
token structure. Complexity here is PDP rule evaluation cost, not token
evaluation depth.

The scenarios in this table are still `capability`, not `parity_identity_bound`.
They may compare policy behavior under HTTP/hybrid authorization, but they do
not enable strict identity binding for both token types.

#### 2.3.1 HTTP Identity-Bound Parity Variants (`parity_identity_bound`, JWT `strict`, Biscuit `strict`)

| Scenario | Token | Policy Source | Policy Detail | Expected Outcome |
| --- | --- | --- | --- | --- |
| HTTP-LATENCY-200MS-PARITY-JWT | JWT | HTTP | Same rule-engine slice as `HTTP-LATENCY-200MS-JWT`, but with strict JWT fixture and strict binding on both token types | Allows |
| HTTP-LATENCY-200MS-PARITY-BISCUIT | Biscuit | HTTP | Same rule-engine slice as `HTTP-LATENCY-200MS-BISCUIT`, but with strict Biscuit fixture and strict binding on both token types | Allows |
| HTTP-PROFILE-SIMPLE-PARITY-JWT/BISCUIT | JWT/Biscuit | HTTP | `simple` profile under strict identity binding for both token types | Allows |
| HTTP-PROFILE-MED-PARITY-JWT/BISCUIT | JWT/Biscuit | HTTP | `med` profile under strict identity binding for both token types | Allows |
| HTTP-PROFILE-COMPLEX-PARITY-JWT/BISCUIT | JWT/Biscuit | HTTP | `complex` profile under strict identity binding for both token types | Allows |

These are the single-client HTTP scenarios that may honestly claim identity
parity. They depend on strict token fixtures (`jwt_strict_sub_client_id`,
`biscuit_strict_client_id`) rather than shared baseline tokens.

### 2.3.2 Issue 37: Strict `ACL_READ` Fan-Out Across Policy Profiles

Issue 37 adds strict fan-out (`plugin_opt_acl_read_full_authz=true`) scenarios for
token-only, HTTP profiles (`simple|med|complex`), and hybrid profiles
(`simple|med|complex`) so read-path comparisons are not limited to
`ACL_SUBSCRIBE`.

| Scenario Family | Token | Policy Source | Policy Detail | Expected Outcome |
| --- | --- | --- | --- | --- |
| `TOKEN-ACL-READ-FANOUT-STRICT-ALLOW-{JWT\|BISCUIT}-{10,50,100}` | JWT/Biscuit | Token-only | Strict token mode (`mosquitto_integration_acl_read_full.conf`), fan-out allow token on `fanout/broadcast` | Delivery allowed under strict `ACL_READ` |
| `TOKEN-ACL-READ-FANOUT-STRICT-DENY-{JWT\|BISCUIT}-10` | JWT/Biscuit | Token-only | Subscriber token keeps subscribe grant but denies read on `fanout/broadcast`; publisher uses allow token | Subscribe accepted; fan-out delivery denied |
| `HTTP-ACL-READ-FANOUT-STRICT-{SIMPLE\|MED\|COMPLEX}-ALLOW-{JWT\|BISCUIT}-10` | JWT/Biscuit | HTTP | Strict HTTP mode + profile-specific baseline + custom allow rules for publish/subscribe/read on fan-out topic | Delivery allowed |
| `HTTP-ACL-READ-FANOUT-STRICT-{SIMPLE\|MED\|COMPLEX}-DENY-{JWT\|BISCUIT}-10` | JWT/Biscuit | HTTP | Same as above with explicit deny(`read`) on fan-out topic | Delivery denied while subscribers stay connected |
| `HTTP-ACL-READ-FANOUT-STRICT-MED-ALLOW-{JWT\|BISCUIT}-{50,100}` | JWT/Biscuit | HTTP | Balanced scaling slices for representative `med` profile | Read-path scaling under strict mode |
| `HYBRID-ACL-READ-FANOUT-STRICT-{SIMPLE\|MED\|COMPLEX}-ALLOW-{JWT\|BISCUIT}-10` | JWT/Biscuit | Hybrid | Strict hybrid mode with same profile+rule approach | Delivery allowed |
| `HYBRID-ACL-READ-FANOUT-STRICT-{SIMPLE\|MED\|COMPLEX}-DENY-{JWT\|BISCUIT}-10` | JWT/Biscuit | Hybrid | Same as above with explicit deny(`read`) on fan-out topic | Delivery denied while subscribers stay connected |
| `HYBRID-ACL-READ-FANOUT-STRICT-MED-ALLOW-{JWT\|BISCUIT}-{50,100}` | JWT/Biscuit | Hybrid | Balanced scaling slices for representative `med` profile | Read-path scaling under strict mode |

These base strict fan-out families remain `capability` (`jwt_identity_binding=off`,
`biscuit_identity_binding=off`). They exercise strict `ACL_READ` authorization,
but they intentionally keep shared-token multi-client behavior, so they must not
be labeled parity.

Runnable identity-bound parity fan-out is represented by the generated
HTTP/Hybrid `-PARITY-` families:

- `HTTP-ACL-READ-FANOUT-STRICT-*-PARITY-*`
- `HYBRID-ACL-READ-FANOUT-STRICT-*-PARITY-*`

Those are `parity_identity_bound` scenarios with `jwt_identity_binding=strict`
and `biscuit_identity_binding=strict`. Because they are multi-client runs, the
harness provisions one strict-bound token per client identity at startup instead
of reusing a shared token.

Issue 37 metadata in benchmark outputs now includes:

- `scenario_config.policy_source`
- `scenario_config.authz_profile`
- `scenario_config.acl_read_enforcement`
- `scenario_config.subscriber_count`

### 2.4 Static ACL (Compound Gate, `capability`, JWT `off`, Biscuit `off`)

| Scenario | Token | Policy Source | Policy Detail | Expected Outcome |
| --- | --- | --- | --- | --- |
| STATIC-ACL-PUBLISH-JWT | JWT | Token role identity + ACL | Writer role token (`roles=["writer"]`) + `static-acl.conf` on `sensors/{client_id}/temp` | Allows publish path |
| STATIC-ACL-PUBLISH-BISCUIT | Biscuit | Token role identity + ACL | Writer role token (`role("writer")`) + `static-acl.conf` on `sensors/{client_id}/temp` | Allows publish path |
| STATIC-ACL-FANOUT-JWT | JWT | Token role identity + ACL | Reader subscribers + writer publisher on `fanout/broadcast` | Allows subscribe/fanout path |
| STATIC-ACL-FANOUT-BISCUIT | Biscuit | Token role identity + ACL | Reader subscribers + writer publisher on `fanout/broadcast` | Allows subscribe/fanout path |

ACL rules in `docker/static-acl.conf` grant:
- `role:admin` read/write on all topics
- `role:reader` read on `sensors/#`
- `role:writer` write on `sensors/#`
- fallback `pattern readwrite sensors/%c/#`
- `fanout/broadcast` grants for the same roles

**Parity requirement (implemented):** STATIC-ACL scenarios use **roles-only**
tokens (no JWT `grants`/`denies`, no Biscuit `right`/`deny`) so the ACL file is
the authoritative access policy.

**ACL subtype coverage:**
- `STATIC-ACL-PUBLISH-JWT` / `STATIC-ACL-PUBLISH-BISCUIT`: cover `ACL_WRITE` via publish operations.
- `STATIC-ACL-FANOUT-JWT` / `STATIC-ACL-FANOUT-BISCUIT`: cover `ACL_SUBSCRIBE` on
  subscriber setup and include `ACL_READ` during fan-out delivery.
- For static ACL benchmark mode, `acl_read_full_authz` is set to `false` in
  `mosquitto_static.conf` to keep `ACL_READ` as documented expiry-only behavior.

### 2.5 Dynamic Security (Snapshot RBAC, `capability`, JWT `off`, Biscuit `off`)

| Scenario | Token | Policy Source | Policy Detail | Expected Outcome |
| --- | --- | --- | --- | --- |
| DYNAMIC-SECURITY-BASELINE | JWT | Dynamic Security | `dynamic-security.json` roles + groups | Allows |
| DYNAMIC-SECURITY-CHURN | JWT | Dynamic Security | `dynamic-security.json`/`dynamic-security-churn.json` swap | Mixed (read-only) |
| DYNAMIC-SECURITY-READ-FANOUT | JWT | Dynamic Security | fanout roles/ACLs enabled | Allows |
| DYNAMIC-SECURITY-READ-FANOUT-CHURN | JWT | Dynamic Security | fanout ACLs change on churn | Mixed |
| DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-JWT-{10,50,100} | JWT | Dynamic Security | `acl_read_full_authz=true`; churn after message 5 swaps to `dynamic-security-fanout-read-deny-unpinned.json` (subscribe kept, receive removed) | Existing subscribers denied on post-churn fan-out |
| DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-BISCUIT-{10,50,100} | Biscuit | Dynamic Security | Same as JWT variant with Biscuit token path | Existing subscribers denied on post-churn fan-out |
| DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-REVOKE-JWT/BISCUIT-{10,50,100} | JWT/Biscuit | Dynamic Security | `acl_read_full_authz=true`; control command removes the fan-out receive ACL during the run | Existing subscribers denied on post-control fan-out |
| DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-DISABLE-JWT/BISCUIT-{10,50,100} | JWT/Biscuit | Dynamic Security | `acl_read_full_authz=true`; control command disables the subscriber identity during the run | Existing subscribers are kicked/denied after control enforcement |

Issue 30 dynamic-security notes:
- Uses strict config `mosquitto_dynsec_acl_read.conf` (`plugin_opt_acl_read_full_authz true`) so fan-out delivery checks go through full policy authorization.
- Churn is applied mid-run (not between repeats), targeting already-subscribed clients.
- Control-driven fan-out churn uses `fanout_churn_kind=dynamic_security_control`
  and publishes a Dynamic Security command instead of swapping the JSON snapshot.
- Result payload includes pre/post churn receive counters under `fanout_churn`.

### 2.5.1 SQLite Fan-Out Churn Coverage (Issue 30, `capability`, JWT `off`, Biscuit `off`)

| Scenario | Token | Policy Source | Policy Detail | Expected Outcome |
| --- | --- | --- | --- | --- |
| SQLITE-ACL-READ-FANOUT-CHURN-JWT-{10,50,100} | JWT | SQLite | `acl_read_full_authz=true`; seeded fan-out RBAC grants (reader subscribe/read + publisher write) then mid-run revoke of reader-role `ACL_READ` grant after message 5 | Existing subscribers denied on post-churn fan-out |
| SQLITE-ACL-READ-FANOUT-CHURN-BISCUIT-{10,50,100} | Biscuit | SQLite | Same as JWT variant with Biscuit token path | Existing subscribers denied on post-churn fan-out |
| SQLITE-RBAC-CHURN-JWT | JWT | SQLite | Strict `ACL_READ` with periodic `sqlite_toggle_read` churn (message 4, every 4, max 4 events) | Alternating delivery drop/recovery windows |
| SQLITE-RBAC-CHURN-BISCUIT | Biscuit | SQLite | Same as JWT periodic churn variant with Biscuit token path | Alternating delivery drop/recovery windows |
| SQLITE-RBAC-DEEP-CONFLICT-JWT | JWT | SQLite | Deep RBAC profile with explicit deny-over-allow conflicts and priority tiers; periodic `sqlite_toggle_private_deny` churn on `sensors/private/broadcast` | Deterministic partial fan-out + alternating deny/allow windows |
| SQLITE-RBAC-DEEP-CONFLICT-BISCUIT | Biscuit | SQLite | Same deep conflict profile/churn as JWT variant | Deterministic partial fan-out + alternating deny/allow windows |
| SQLITE-RBAC-DEEP-CONTROL-JWT | JWT | SQLite | Deep control-family profile with `CONTROL` + `system/notifications` grants; control-mode publishes on `$CONTROL/...` | Control-plane allow path validated under SQLite RBAC |
| SQLITE-RBAC-DEEP-CONTROL-BISCUIT | Biscuit | SQLite | Same deep control profile as JWT variant | Control-plane allow path validated under SQLite RBAC |

Issue 30/22 sqlite notes:
- Uses `mosquitto_sqlite_acl_read.conf` with `policy_mode=sqlite` and `plugin_opt_acl_read_full_authz true`.
- `plugin_opt_sqlite_seed_demo_rules false` keeps benchmark policy source deterministic and externalized to scenario helpers.
- `benchmarks/policy_churn.py` supports deterministic seed profiles:
  - `fanout_basic`: reader/publisher RBAC baseline.
  - `rbac_deep`: explicit deny-over-allow conflicts + multi-role priority tiers.
  - `rbac_deep_control_allow`: deep profile plus control-admin assignment for `client_1`.
- Issue 30 one-shot churn removes reader-role `ACL_READ` grant for `fanout/broadcast` (subscribe/read split preserved).
- Issue 22 periodic churn toggles reader-role `ACL_READ` grant at deterministic message intervals during the same run.
- Deep conflict churn toggles private-topic deny rows (`sqlite_toggle_private_deny`) to
  expose cache-sensitive authorization transitions under strict `ACL_READ`.


### 2.6 Lifecycle And Reauthentication (`capability`, JWT `off`, Biscuit `off`)

| Scenario | Token | Policy Source | Policy Detail | Expected Outcome |
| --- | --- | --- | --- | --- |
| TOKEN-MQTT5-REAUTH-JWT | JWT | Token-only | Short TTL then refresh with long-lived token | Allows |
| TOKEN-MQTT5-REAUTH-BISCUIT | Biscuit | Token-only | Short TTL then refresh | Allows |
| TOKEN-LIFECYCLE-SHORT-RECONNECT-JWT | JWT | Token-only | Short TTL, refresh via issuer | Reconnect |
| TOKEN-LIFECYCLE-SHORT-RECONNECT-BISCUIT | Biscuit | Token-only | Short TTL, refresh via issuer | Reconnect |
| TOKEN-LIFECYCLE-PROACTIVE-REAUTH-JWT | JWT | Token-only | Timer-driven refresh before expiry via MQTT v5 `AUTH` | Continuity without expiry disconnect |
| TOKEN-LIFECYCLE-PROACTIVE-REAUTH-BISCUIT | Biscuit | Token-only | Timer-driven refresh before expiry via MQTT v5 `AUTH` | Continuity without expiry disconnect |

Tokens are issued with the same default grants/rights in token-only mode.

### 2.7 Biscuit-Only Capability Scenarios (`capability`, JWT `off`, Biscuit `off`)

| Scenario | Policy Source | Policy Detail | Notes |
| --- | --- | --- | --- |
| TOKEN-ATTENUATION-CLIENT-BISCUIT | Token-only | Client appends a subscribe deny plus TTL, leaving the measured publish right intact | Measures attenuation cost with a complete publish workload |
| TOKEN-ATTENUATION-TTL-BISCUIT | Token-only | Client adds TTL block only | Attenuation baseline |
| TOKEN-ATTENUATION-DENY-BISCUIT | Token-only | Client adds deny + resource check | Policy restriction |
| TOKEN-ATTENUATION-OP-ONLY-BISCUIT | Token-only | Client restricts operation only | Policy restriction |
| TOKEN-DELEGATION-TEMP-ONLY-BISCUIT | Token-only | Client delegates limited token | Measures delegation cost |
| TOKEN-DELEGATION-HANDOFF-BISCUIT | Token-only | Delegated token passed over MQTT | Handoff overhead |
| TOKEN-DELEGATION-SIMULATED-BISCUIT | Token-only | Pre-generated delegated token | Baseline for delegation |
| TOKEN-COMPOSABILITY-ATTENUATED-DATALOG-MED-BISCUIT | Token-only | Complex medium Datalog token with runtime attenuation (publish/topic/TTL restriction) | Measures composability of local rules + attenuation |
| TOKEN-COMPOSABILITY-ATTENUATED-DATALOG-HIGH-BISCUIT | Token-only | Complex high Datalog token with runtime attenuation (publish/topic/TTL restriction) | Measures composability of local rules + attenuation |
| TOKEN-COMPOSABILITY-DELEGATED-DATALOG-MED-BISCUIT | Token-only | Complex medium Datalog token with runtime delegation (publish/topic/TTL restriction) | Measures composability of local rules + delegation |
| TOKEN-COMPOSABILITY-DELEGATED-DATALOG-HIGH-BISCUIT | Token-only | Complex high Datalog token with runtime delegation (publish/topic/TTL restriction) | Measures composability of local rules + delegation |

These are marked `capability_flags.biscuit_only=true` in scenario output and **must not**
be used in JWT-vs-Biscuit parity comparisons. Biscuit attenuation/delegation are
intentionally not parity scenarios because the experiment is measuring a Biscuit
capability that JWT does not provide in the same form.

The `TOKEN-COMPOSABILITY-*` family combines existing Biscuit-only features
rather than introducing a new parity claim. It exists to measure whether richer
local Datalog policies remain practical when attenuation or delegation is also
performed at runtime.

### 2.8 Control Plane And Dynamic Security Command Scenarios

Control-plane scenarios use Dynamic Security policy state and `$CONTROL/...`
publishes to measure authorization overhead and policy-mutation cost. They are
not identity-bound parity scenarios unless explicitly classified otherwise in
the registry.

| Scenario Family | Token | Policy Source | Policy Detail | Expected Outcome |
| --- | --- | --- | --- | --- |
| `CONTROL-OVERHEAD-KICK-REAUTH-*` | JWT/Biscuit admin token | Dynamic Security | Authorizes control-topic publish without modeling a data-plane fan-out workload | Control publish allowed; classified `mixed` because JWT binding is strict and Biscuit binding is off |
| `CONTROL-OVERHEAD-ACL-READ-NOTIFY-*` | JWT/Biscuit admin token | Dynamic Security | Control-topic publish plus notification fan-out path | Control/notification path allowed under capability semantics |
| `CONTROL-CHURN-{CREATE-ROLE,GROUP-CLIENT,ACL-MODIFY,LARGE-STATE-GROUP-CLIENT,NOOP-GROUP-CLIENT}-*` | JWT/Biscuit admin token | Dynamic Security | Publishes concrete Dynamic Security command payloads that mutate roles, groups, ACLs, large state, or idempotent membership | Command path succeeds and mutation cost is measured; classified `mixed` |
| `CONTROL-CHURN-REPEAT-SAME-ENTITY-*` | JWT/Biscuit admin token | Dynamic Security | Repeated mutations against one shared Dynamic Security entity | Measures repeated-update control-plane cost under capability semantics |
| `CONTROL-CHURN-REPEAT-DISTINCT-ENTITY-*` | JWT/Biscuit admin token | Dynamic Security | Repeated mutations against worker-specific Dynamic Security entities | Measures per-entity churn cost under capability semantics |
| `CONTROL-CHURN-CONCURRENT-CONTROLLERS-*` | JWT/Biscuit admin token | Dynamic Security | Multiple controller clients publish mutation commands concurrently | Measures contention/control-plane scalability under capability semantics |
| `CONTROL-INTERLEAVED-DATA-*` | JWT/Biscuit token | Dynamic Security | Interleaves `$CONTROL/...` publishes with normal data-plane publishes | Measures control latency while data traffic is active |

Control command payloads are generated by
`mqtt-auth-biscuit/benchmarks/dynsec_commands.py`; scenario orchestration and
semantic classification live in `mqtt-auth-biscuit/benchmarks/run_scenarios.py`.

### 2.9 Anonymous Flow (DYNAMIC-SECURITY-ANONYMOUS-BASELINE, `capability`, JWT `off`, Biscuit `off`)

| Scenario | Token | Policy Source | Policy Detail | Expected Outcome |
| --- | --- | --- | --- | --- |
| DYNAMIC-SECURITY-ANONYMOUS-BASELINE | None | Dynamic Security (`anonymousGroup`) | `allow_anonymous true` + `dynamic-security-anon.json` policy on `public/announce` | Allows scoped anonymous pub/sub |

Configuration files:

- Mosquitto config: `docker/mosquitto_anon.conf`
- Dynamic Security snapshot: `docker/dynamic-security-anon.json`

Security and interpretation notes:

- Anonymous clients have no username identity; attribution relies on client IDs.
- Authorization is still enforced by Dynamic Security ACLs (not open access).
- Topic scope should stay narrow (for example `public/#`) to reduce blast radius.
- Anonymous mode raises DoS exposure compared to authenticated-only deployments.
- This scenario is for functional viability and overhead comparison, not identity assurance.

Research alignment:

- DYNAMIC-SECURITY-ANONYMOUS-BASELINE validates functional handling of unauthenticated clients with policy enforcement.
- Compare with `BASELINE-NO-AUTH` (no authz) and token scenarios (`TOKEN-BASELINE-JWT`, `TOKEN-BASELINE-BISCUIT`) to estimate overhead.

## 3) Fairness And Alignment Tracking

To avoid duplicated backlog text, parity gaps and action items are tracked in:
`PROGRESS.md#7-policy-parity-gaps-tracking` and `PROGRESS.md#8-open-issues`.

This file remains the source of truth for:

1. Policy source definitions and semantics (`## 1`).
2. Scenario-to-policy mapping (`## 2`).
3. Implementation references (`## 4`).

## 4) Reference File Index

- Scenario definitions: `benchmarks/run_scenarios.py`
- Token fixtures: `benchmarks/tokens.json` + `crates/benchmarks/src/main.rs`
- JWT/Biscuit authz: `crates/mosquitto-plugin/src/authz.rs`, `biscuit_handler.rs`
- HTTP policy server: `crates/authz-server/src/main.rs`
- Static ACL file: `docker/static-acl.conf`
- Dynamic security snapshots: `docker/dynamic-security*.json`
- SQLite policy: `crates/mosquitto-plugin/src/sqlite_policy.rs`
- Policy churn helpers: `benchmarks/policy_churn.py`
