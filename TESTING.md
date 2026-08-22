# Scenario testing and result-verification plan

This document defines the gates for testing every benchmark scenario and
reviewing every result for semantic errors or suspicious measurements.
[`RUN.md`](RUN.md) remains the canonical source for the complete execution
matrix and commands. [`SEMANTIC-VERIFIED.md`](SEMANTIC-VERIFIED.md) records what
has actually been verified.

Terminology: *Phases* are verification stages in this document; *Parts* are the
execution matrices defined in [`RUN.md`](RUN.md). Phases 6 and 7 execute
Part 1 and Part 2, respectively; the two numbering schemes are unrelated.

The process deliberately separates three questions:

1. Does the scenario definition describe the intended experiment?
2. Did the run exercise that definition and satisfy its result contract?
3. Are the resulting measurements plausible and reproducible enough to use?

A successful exit answers only part of the second question. Do not promote a
batch to the next phase until every failure and suspicious result has been
resolved, rerun, or explicitly documented as an expected outcome.

## Evidence and naming rules

- Run commands from the repository root.
- Build and generate credentials once for a batch. Use `--skip-build` and
  `--skip-tokens` only after recording the commit and confirming that the
  generated artifacts match it.
- Never reuse `mqtt-auth-biscuit/benchmarks/results` across invocations. Move it
  to a directory whose name records every varied dimension, as shown in
  `RUN.md`.
- Preserve the scenario JSON, `summary.json`, `summary.csv`, runner log, Docker
  diagnostics, packet captures, and profiling output produced by the run.
- Record the Git commit, worktree status, Rust/Python/Docker versions, host,
  topology, resource limits, and exact command beside each batch.
- Treat results from a dirty worktree or changed generated credentials as a
  separate dataset.
- Do not average away a failed or suspicious repetition. Investigate the raw run
  first.

## Mandatory test-review-fix loop

Apply this loop after **every invocation or small batch**, not after completing a
phase:

1. **Test:** run the smallest currently planned batch and preserve its raw
   output.
2. **Review semantics:** verify configuration provenance, counters, policy
   outcome, delivery/control contract, errors, and metric sample counts.
3. **Review numbers:** inspect the raw latency, throughput, resource, network,
   token-size, and backend-counter values using the checklist below. Compare
   repetitions and the nearest meaningful scenario/workload peers as soon as
   those peers exist.
4. **Classify:** mark every result `accepted`, `suspicious`, or `failed`. Never
   leave an unreviewed result in a directory that will later be aggregated.
5. **Fix and rerun:** diagnose suspicious or failed results while containers,
   logs, host conditions, and configuration are still available. After a code,
   fixture, or environment fix, discard the affected cell from the accepted set
   and rerun it from the beginning.
6. **Advance:** start the next batch only when the current batch is accepted or
   explicitly recorded as blocked with evidence and an owner.

### Immediate suspicious-number checklist

Review raw repetitions before aggregates. Flag, but do not automatically reject:

- zero latency or throughput for a nonempty workload;
- identical timing distributions across materially different scenarios;
- large discontinuities between adjacent client/message/QoS levels;
- reversed complexity ordering that repeats consistently enough to suggest the
  wrong profile or cached path;
- HTTP request counts, rule counts, or configured delays inconsistent with
  publishes;
- flat connect cost in reconnect/reauth scenarios when session or issuer counts
  changed;
- receive counts that are correct only in aggregate but wrong by churn phase;
- CPU, memory, network, or latency spikes present in only one repetition;
- token sizes inconsistent with credential type, Biscuit chain/Datalog tier, or
  attenuation/delegation;
- packet captures absent from MTU scenarios, or MTU/fragmentation observations
  inconsistent with the applied network configuration;
- resource metrics with missing intervals, container-name mismatches, or host
  saturation affecting unrelated scenarios simultaneously.

Use comparisons appropriate to the claim:

| Claim | Primary evidence | Required cross-check |
|---|---|---|
| Authentication overhead | connect/reauth timing | successful session count and credential path |
| Publish authorization cost | publish completion timing | expected authorization decisions and QoS |
| HTTP policy complexity | PDP and publish timing | profile requests and rules examined |
| Local Biscuit complexity | publish timing and token size | credential tier attestation |
| Fanout scaling | publisher timing/resources | exact per-subscriber delivery contract |
| Churn/control effect | phase timing and control timing | applied event and pre/post outcomes |
| MTU effect | publish/network timing | fatal netem success and packet capture |
| TLS overhead | TLS/base paired result | identical non-performance semantics |

An unusual value becomes acceptable only after confirming the correct path,
reproducing it, and ruling out collection or environmental errors. Record the
reasoning; “probably noise” is not sufficient.

## Phase 0 — Freeze and inventory the test subject

Goal: establish exactly what will be tested before starting Docker workloads.

1. Record the repository state:

   ```bash
   git rev-parse HEAD
   git status --short
   rustc --version
   uv run --locked python --version
   docker version
   docker compose version
   ```

2. Confirm pins and install the locked environment:

   ```bash
   uv sync --locked
   ./scripts/check-pins
   ```

3. Generate the registry from the current code and confirm the expected total:

   ```bash
   cd mqtt-auth-biscuit
   uv run --locked python -c '
   from benchmarks.run_scenarios import (
       _build_available_scenarios,
       _expand_tls_matrix,
       _read_tokens,
   )
   tokens = _read_tokens("benchmarks/tokens.json")
   scenarios = _expand_tls_matrix(_build_available_scenarios(
       tokens,
       token_issuer_no_default_roles=False,
       token_issuer_no_default_grants=False,
   ))
   print(len(scenarios))
   for name in sorted(scenarios):
       print(name)
   '
   cd ..
   ```

   Expected total: 440 scenarios, comprising 220 base scenarios and 220 TLS
   variants. Stop if this differs from `RUN.md`; reconcile the registry and
   documentation before testing.

4. Save the generated scenario list as the batch inventory. Every scenario in
   that inventory must eventually have either verified run evidence or a written
   blocking reason.

Exit gate: repository state, tool versions, and the 440-scenario inventory are
recorded and internally consistent.

## Phase 1 — Static semantic and contract checks

Goal: catch wrong definitions, fixtures, credentials, and result contracts
without interpreting benchmark numbers.

Run all inexpensive checks:

```bash
cargo test --locked --workspace
cargo test --locked --manifest-path mqtt-auth-biscuit/Cargo.toml
cargo fmt --all --manifest-path Cargo.toml -- --check
cargo fmt --all --manifest-path mqtt-auth-biscuit/Cargo.toml -- --check
uv run --locked --group dev ruff check .
uv run --locked --group dev mypy mqtt-auth-biscuit
./run_python_tests.sh
```

For every scenario family, review the registry and assert that the following
agree with its name and documented purpose:

- authorization mechanism and username (`none`, JWT, or Biscuit);
- Mosquitto configuration and policy backend;
- policy profile, enforcement mode, and initial policy state;
- publisher/subscriber topology and client count source;
- publish, fanout, control, churn, reconnect, or reauthentication mode;
- topic templates and separate publisher/subscriber credentials where needed;
- message count, QoS, QoS distribution, payload size, and fixed versus swept
  workload axes;
- credential mode (`none`, shared, per-client, or issuer) and identity-binding
  class;
- expected allow, deny, disconnect, delivery, and phase-transition outcomes;
- metrics collected and the result contract that validates the claimed effect.

Reject a scenario definition if it can pass while selecting the wrong backend,
credential profile, workload axis, topology, or control path. Add an executable
test whenever the intended invariant can be checked statically.

Exit gate: all automated checks pass, and every scenario family has an explicit
workload and outcome contract.

## Phase 2 — Infrastructure and observability preflight

Goal: prove that failures in the broker, policy backend, network fixture, or
metrics path cannot be mistaken for valid measurements.

1. Build the plugin and generate the credentials used by the batch:

   ```bash
   cd mqtt-auth-biscuit
   cargo build --locked --release -p mosquitto-auth-biscuit
   cargo run --locked -p gen-tokens --bin gen-tokens
   cd ..
   ```

2. Confirm Docker readiness, broker health checks, token issuer, HTTP PDP,
   Prometheus/resource collection, and packet-capture permissions.

3. Exercise one small representative scenario for each backend and mechanism:

   - no authentication;
   - JWT and Biscuit token authorization;
   - Static ACL;
   - Dynamic Security;
   - HTTP;
   - SQLite;
   - Hybrid;
   - TLS versions of the same paths.

4. Include at least one expected denial, one fanout delivery, one policy change,
   one QoS 2 publish, one reconnect/reauthentication path, and one netem MTU
   scenario.

For each preflight result, verify that the recorded configuration names the
expected broker configuration, policy source, authorization profile, topology,
credential mode, effective workload axes, and TLS state. Confirm that denial and
churn cases produce the expected observable effect rather than merely an empty
error list.

Review/fix gate: apply the mandatory loop to each backend preflight immediately.
Check the first timing and resource values for zeros, missing samples, impossible
percentiles, and backend-counter mismatches before testing the next backend.

Exit gate: every backend and major client path produces correctly attributed,
numerically plausible metrics, and injected failure cases fail visibly.

## Phase 3 — One-run semantic coverage of every base scenario

Goal: execute all 220 non-TLS scenarios once at the smallest workload that still
triggers their complete behavior.

Use the workload-shape grouping from `RUN.md`. Matrix scenarios may use 10
clients and 10 messages; scenario-fixed workloads retain their defined values.
Thresholded control/churn scenarios must run enough messages to cover every
declared phase. Reauth storms use host topology; other scenarios use
container-per-client unless their contract states otherwise.

After each invocation, inspect every scenario JSON before continuing. A result
is semantically accepted only when all applicable checks below pass.

### Universal checks

- No unexpected runner or load-generator errors.
- The scenario ID and recorded policy source match the requested scenario.
- Requested and effective clients, messages, QoS, distribution, and topology
  match the scenario/CLI workload-axis provenance.
- Connect count matches the client role topology.
- Successful publish count matches the contract, including expected-denial
  exceptions.
- Per-QoS counts sum to successful publishes and match the requested schedule.
- Credential attestations contain exactly the expected roles, profiles, token
  kinds, and validated credential counts.
- No NaN, infinity, negative durations, negative counters, impossible
  percentiles, or percentile inversions (`min <= p50 <= p95 <= p99 <= max`).
- Throughput and latency summaries have nonzero sample counts when the workload
  claims to measure them.
- Resource samples cover the workload interval and refer to the expected
  containers.

### Authorization and policy checks

- Allow scenarios show workload-visible success, not only a successful connect.
- Deny scenarios observe the expected MQTT reason, disconnect, missing delivery,
  or policy-denial count; they must not pass solely because no subscriber was
  present.
- HTTP scenarios record external PDP activity. Complexity scenarios require the
  selected profile for every expected publish and consistent allow/deny/failure
  and rules-examined counters.
- Dynamic Security control scenarios record successful correlated command
  responses and the intended state transition.
- SQLite churn scenarios prove that the seeded database and mutated database are
  the files actually mounted by the broker.
- Hybrid scenarios demonstrate which primary or fallback backend made the
  decision; backend failure must be observable in counters or diagnostics.
- Biscuit complexity scenarios attest the intended block/rule tier. Attenuation
  and delegation scenarios require a changed derived credential and the
  scenario-specific authorization probe.

### Fanout, control, and lifecycle checks

- Fanout delivery count equals messages × eligible subscribers for allow phases.
- Deny phases contain no deliveries unless the contract explicitly permits an
  in-flight boundary.
- Sequence IDs are continuous; duplicates, gaps, or cross-topic notifications
  are not counted as fanout payloads.
- Every churn event is triggered and applied the declared number of times, and
  each pre/post phase satisfies its `delivery_contract`.
- Disable/kick scenarios contain exactly the expected session-termination
  signature.
- Reconnect scenarios perform the expected number of full sessions.
- Proactive reauthentication and storm scenarios report attempts, successes,
  zero unexpected expiry denials, and session continuity.
- MQTT 5 AUTH scenarios report successful initial AUTH and reauthentication with
  both timing samples present.

Exit gate: all 220 base scenarios have one accepted semantic run, or appear in a
blocking-issues list with owner, evidence, and required fix. Update
`SEMANTIC-VERIFIED.md` only with accepted evidence.

## Phase 4 — TLS parity coverage

Goal: verify all 220 TLS variants rather than assuming that base-scenario
semantics survive the transport change.

1. Generate or provision the documented certificates and verify hostname, CA,
   mount path, listener, and client trust configuration.
2. Repeat Phase 3 for every `-TLS` scenario.
3. Confirm that the TLS listener was used and that plaintext fallback was not
   possible.
4. Compare each TLS result with its non-TLS counterpart for identical workload,
   authorization backend, credential role, policy outcome, control response, and
   delivery contract.

Latency and CPU may differ under TLS; authorization decisions, message counts,
QoS, churn transitions, and delivery outcomes must not.

Review/fix gate: review each TLS/base pair immediately after the TLS run. Fix or
block the pair before moving to the next scenario; do not defer parity and
number review until all TLS variants finish.

Exit gate: all 440 inventory entries have at least one accepted semantic run.

## Phase 5 — Targeted fixed-workload and lifecycle slices

Goal: rerun scenario-defined stress and lifecycle workloads under the current
contracts before using their measurements.

Run, preserve, and review the targeted commands from `RUN.md` for:

- 17 fixed-workload publish, Datalog, composability, reconnect, and HTTP
  complexity scenarios;
- proactive reauthentication and reauthentication storms;
- reconnect-publish lifecycle scenarios;
- control enforcement/churn scenarios;
- SQLite RBAC churn scenarios;
- high-subscriber fanout and policy-change scenarios.

Use three repetitions after the first accepted semantic run. Verify that every
repetition selects the same workload and policy path. For issuer-backed
lifecycle cases, confirm issuance/refresh activity and do not infer credential
freshness solely from successful reconnects.

Review/fix gate: after each family, compare all three raw repetitions and inspect
timing, token-size, issuer/backend counters, and resource values. Resolve the
family before starting the next one.

Exit gate: every targeted family has three contract-valid repetitions and no
unresolved path ambiguity.

## Phase 6 — Part 1 full baseline matrix

Goal: produce the complete 3,174-run baseline dataset.

Execute Step 2 of `RUN.md` exactly, including workload-shape grouping and the
host-topology exception for reauthentication storms. Validate each output
directory immediately; do not wait until all Part 1 invocations finish.

For every scenario, compare its three repetitions:

- configuration and semantic counters must be identical where deterministic;
- all expected sample counts must match;
- a single repetition with errors, missing metrics, a different credential
  profile, or a different policy path invalidates the triplet;
- flag latency, throughput, CPU, memory, network, and token-size values that are
  extreme relative to both sibling repetitions and the same scenario at an
  adjacent workload level.

Do not discard an outlier automatically. Check container restarts, CPU
throttling, memory pressure/OOM events, broker reconnects, policy-server delay,
packet loss, packet-capture overhead, and host contention. Rerun the entire
three-repetition cell after fixing an environmental cause.

Exit gate: 3,174 scenario JSON files are present, contract-valid, attributable to
their intended cells, and either free of unexplained anomalies or accompanied by
an explicit exclusion record.

## Phase 7 — Part 2 parameter sweep

Goal: execute and verify all 3,456 scenario runs in the 32-scenario sweep.

Execute Step 3 of `RUN.md`: three client levels × two message levels × three QoS
levels × two issuer configurations × three repetitions. Remember that
`BASELINE-NO-AUTH` pins QoS 0 and `TOKEN-QOS2-{JWT|BISCUIT}` pins QoS 2; verify
their other axes but do not describe them as QoS sweeps.

For every cell, confirm:

- the effective axes equal the requested axes unless the scenario explicitly
  pins one;
- stripped-issuer runs record the stripped configuration and do not silently use
  credentials generated for the default issuer mode;
- QoS 0/1/2 counts and completion semantics match the effective QoS;
- authorization and delivery outcomes remain invariant across workload axes;
- only performance/resource measurements—not the selected path or policy
  result—change with load.

Review/fix gate: review all 32 raw results and their available repetitions at
the end of each sweep cell. Resolve or block that cell before changing clients,
messages, QoS, or issuer configuration.

Exit gate: all 108 sweep invocations contain 32 reviewed scenario results, for
3,456 contract-valid scenario runs in total.

## Phase 8 — Final completeness and sign-off

Goal: produce an auditable statement of exactly what can be used in analysis.

1. Count results as described in `RUN.md`: 3,174 Part 1 scenario runs and 3,456
   Part 2 scenario runs.
2. Compare result scenario IDs against the frozen Phase 0 inventory and the
   expected matrix cells. Detect missing, duplicate, stale, and extra files.
3. Regenerate summaries only from accepted raw results.
4. Sample summary rows back to source JSON and verify counts, percentiles,
   credential attestations, and scenario configuration survived aggregation.
   This is a check that aggregation preserved already reviewed results, not the
   first number review.
5. Maintain three explicit lists:

   - accepted results;
   - reruns or exclusions with reasons;
   - blocked scenarios with no usable evidence.

6. Update `SEMANTIC-VERIFIED.md` with the commit, matrix coverage, accepted
   scenario families, retired/blocked cases, and interpretation boundaries.

Final gate: every planned cell is accounted for, every accepted result passed
its semantic contract and suspicious-number review, and no aggregate contains a
failed, stale, or unexplained run.
