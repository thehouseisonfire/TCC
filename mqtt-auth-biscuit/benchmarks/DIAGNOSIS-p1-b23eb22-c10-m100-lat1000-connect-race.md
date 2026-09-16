# Diagnosis: `HTTP-LATENCY-1000MS-JWT` c10/m100 `connect_failed:Connection timeout`

Date: 2026-09-16. Campaign remains HOLD. No Batch data touched; no code/config changed.
Evidence: `results-quarantine-p1-b23eb22-c10-m100-diag-lat1000-conn-race-r1/`
(success + broker log), `...-r2/` (reproduction + broker log).

## 1. Exact root cause (established, broker-log proven)

A late client's CONNECT waits behind the single-threaded broker's in-flight
1 s HTTP authorizations long enough to exceed rumqttc's **hidden 5 s internal
CONNACK timer**, which the harness never overrides.

Reproduction (quarantined run 2, single scenario, same flags as Batch B):

- Barrier release 23:51:25. Nine clients CONNECT at broker-second 1789527086
  with same-second CONNACKs (broker idle at release).
- Victim `client_9` (172.22.0.18:37338): `New connection` at **1789527087**,
  `New client connected` at **1789527095** — an **8 s CONNACK delay**. By then
  the 9 early publishers had saturated the broker thread with serialized 1 s
  `/authorize` sleeps, so the CONNECT queued ~8 s.
- Client-side, rumqttc's internal `connect_timeout` (default 5 s,
  `MqttOptions::connect_timeout`, never `set_connect_timeout` by
  `mqtt_options` in `crates/benchmarks/src/mqtt_helpers.rs:220-241`) fired
  first, recording `connect_failed:Connection timeout`
  (`ConnectionError::Timeout`, `eventloop.rs:191`) in `connect_worker`
  (`mqtt-loadgen.rs:4523-4528`). The harness's own 25 s outer timer
  (`mqtt_helpers.rs:260-262`, lowercase `connect_timeout`) never got to fire.
- The 9 survivors ran ~900 s; contract validation reported the early error at
  00:06:28. Hence "failure after ~900 s" with an error recorded at ~T+5 s.

Supporting facts:

- `basic_auth_callback` (`callbacks.rs:33-151`) is local JWT verification —
  CONNECT is fast unless the broker thread is blocked in
  `block_on(check_http_pooled)` (`http_policy.rs:711-712`) serving a
  publisher's 1 s PDP sleep (`authz-server main.rs:877-878`).
- Quarantined run 1 (success): all 10 CONNACKs in one broker-second,
  `connect` 13.9–20.6 ms, barrier ready-skew 4394 ms tolerated — skew in
  *ready* times is harmless; only *release-observation* skew (victim ~1 s
  late here) past a saturated broker kills.
- Keepalive (k60, rumqttc default, visible in broker log) is uninvolved:
  PINGRESP delay is bounded by one ~1 s PDP slice; no keepalive expiries or
  socket errors in either broker log; clean client-initiated disconnects.
- c10/m10 "survival" is unproven as a message dependence: connect phases are
  identical across message levels; 0/6 vs 2/6 (now 3/8 with reproductions) is
  consistent with a startup race, not a workload-size effect.

## 2. Classification

Primarily a **benchmark-harness defect**: the documented 25 s CONNACK
headroom (`run_scenarios.py:1650-1665`, designed exactly for
`clients × delay` queueing) is silently defeated by the library's 5 s
internal default the harness never overrides. Interacting causes, not root
causes: the scenario's intended serial 1 s PDP semantics, plus few-second
environment startup/release-observation skew as trigger variance.

## 3. Minimal corrective options (none applied)

- A. `options.set_connect_timeout(...)` ≥ outer budget in `mqtt_options`
  (e.g. match `connect_timeout_seconds`). One-line, semantics-preserving:
  still records true `connect_ms`; all healthy connects are 10–100 ms, so
  passing distributions are unaffected; only the doomed tail waits longer.
  Recommended.
- B. Raise only the outer/publish budget — useless; the 5 s inner timer binds.
- C. Reduce startup stagger (container pacing, tighter barrier polling) —
  narrows the race window without closing it; flake remains possible.
- D. Deliberately stagger connects — changes the measured startup semantics;
  rejected.

## 4. Refreeze / requalification requirement

Any code change breaks the frozen identity (`b23eb22` + artifact hashes), so
option A requires re-freeze (new commit, re-recorded plugin/token hashes) and,
minimum, LATENCY-family requalification: `HTTP-LATENCY-{200MS,1000MS}-{JWT,
BISCUIT}` × c10/m10 + c10/m100 triplets with semantic/numerical review,
before final collection resumes. Broader requalification scope (all HTTP
families sharing the serial PDP path) to be sized when the fix lands. Batch
B r2 stays non-final; the two pre-reboot failures plus this reproduction are
excluded-attempt evidence, not data.
