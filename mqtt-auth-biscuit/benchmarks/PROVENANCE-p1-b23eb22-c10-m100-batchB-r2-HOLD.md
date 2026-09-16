# Batch B (c10/m100, idx014-031) r2 provenance adjudication — HOLD

Date: 2026-09-16. Frozen commit `b23eb22`, clean worktree, `--skip-build --skip-tokens`.
Gate applied: strict pre-workload only (operator-confirmed).

## Verdict: HOLD — Batch B r2 MUST NOT be declared final on this evidence

The two failed exact-command attempts preceding the successful r2 are NOT
demonstrably pre-workload infrastructure/startup failures. Measured workload
demonstrably began in both attempts, so the "cleanly attributable to
pre-workload infrastructure" bar is not met. Per resume instructions:
do not retain r2 as final, do not rerun Batch B for another success, stop.

## Evidence (preserved under `~/tcc2-reboot-preserve-20260915/opencode/`)

- `batchB-r2.log` is byte-identical to `batchB-r2-FAILED-connect-timeout.log`
  (sha256 `7da8c5a2…`; duplicate copy, not a separate attempt).
- Two genuine failed attempts, identical command (18-scenario Batch B list,
  `--workload-shape matrix --clients 10 --messages 100 --client-topology
  container-per-client --client-memory 96m --skip-build --skip-tokens`):
  - Attempt 1: start 15:38:56 → sync-barrier `release?participants=10` 200 OK
    at 15:39:15 → `RuntimeError: HTTP-LATENCY-1000MS-JWT: loadgen errors:
    connect_failed:Connection timeout` raised after `/stats` GET at 15:54:16
    (~901 s of workload elapsed).
  - Attempt 2 (`batchB-r2-retry.log`): start 15:58:44 → release 200 OK at
    15:59:03 → identical failure at 16:14:06 (~903 s elapsed).
- Startup checks PASSED in both failures (hence not startup failures):
  Docker containers Started, authz `config/reset`/`config`/`stats/reset` 200,
  `sync-barrier` created/started, `/health` 200, run-status `404 → 200`.
- Failure point: first scenario `HTTP-LATENCY-1000MS-JWT`, at
  `_validate_result_contract` (`run_scenarios.py:3227`), after the workload
  window. No scenario JSON was written by either failed run.
- Successful `batchB-r2-retry2.log` (start 16:39:01, release 16:39:25, first
  `Wrote` 16:56:08 ≈ 1003 s for the first scenario, summary 17:47:47) shows
  the ~900 s window in the failures IS the measured LAT1000 workload, not
  startup. Final r2 `HTTP-LATENCY-1000MS-JWT.json`: `errors: []`,
  `connect.count: 10`, `publish.count: 1000`.
- Quarantined `diag-lat1000.log` (standalone LAT1000, 16:19:14→16:36:17,
  success) proves the scenario can pass in isolation but does not explain the
  two full-batch failures and does not satisfy the pre-workload bar.

## Dimension-by-dimension (per resume instructions)

- sync/barrier readiness: READY (health/status/release all 200 in failures).
- Docker/container startup: OK (all Started, images Built/CACHED).
- broker/authz readiness: authz HTTP endpoints 200; broker per-scenario
  readiness not separately logged — not exculpatory.
- measured workload began: YES (~900 s elapsed, matching successful run).
- host/resource state: baselines normal (83/73 Gbps); no OOM/throttle
  evidence captured — insufficient to attribute.
- exact failure point: workload-phase connect timeout at contract
  validation of the first scenario, not a pre-workload abort.

## Consequence

- Batch B r1/r2/r3 final dirs remain on disk UNCHANGED but r2 is not
  accepted as final data pending resolution of the flaky LAT1000 connect
  timeout (2 failures in 6 full-batch executions of this cell).
- Batch C–G NOT started (stop on HOLD). No Batch C quarantine check
  performed; no Batch A/B data modified.
