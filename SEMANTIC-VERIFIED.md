# Benchmark semantic verification status

This file records semantic-verification evidence for the benchmark suite. It is
not the execution plan: [`RUN.md`](RUN.md) is canonical for the current scenario
count, workload matrices, commands, and time estimates.

“Passed” below means that the observed workload and policy outcome matched the
scenario contract. A process exiting successfully is not, by itself, semantic
verification. Historical smoke runs performed before the current result
contracts are identified separately and must not be treated as completed
benchmark datasets.

## Current suite status

- The suite contains **440 scenarios**: 220 base scenarios and 220 TLS variants.
- Part 1 contains **3,174 planned runs**. It varies only workload axes that a
  scenario does not define itself.
- Part 2 is the **32-scenario parameter sweep**, comprising 3,456 planned runs
  across client count, message count, QoS, token-issuer configuration, and
  repetitions. The 17 fixed-workload stress scenarios are separate targeted
  slices and are intentionally excluded from this sweep.
- The complete Part 1 and Part 2 matrices have **not** been run and semantically
  verified. Earlier minimal executions established startup and basic workload
  viability only.
- TLS scenarios still require a TLS-capable execution environment and a complete
  run before their results can be relied upon.

## Validation enforced by the current harness

The runner and load generator now reject several classes of silent semantic
failure:

- Scenario results record requested and effective client, message, QoS, and QoS
  distribution values, plus whether each workload axis came from the scenario or
  the command line.
- Per-client credential profiles are selected explicitly. Credential
  attestations identify the client and fanout-publisher roles independently and
  validate declared Biscuit Datalog tiers.
- Normal publish workloads require the expected successful publish count.
  Explicit QoS 2 and mixed-QoS scenarios also require the expected per-QoS
  counts; mixed schedules are deterministic.
- Fanout scenarios carry an executable `delivery_contract`. Churn scenarios
  validate exact per-phase deliveries, applied event counts, sequence
  continuity, and required control responses or policy notifications.
- Dynamic Security control commands are correlated with their response-topic
  replies; missing and error responses fail the run.
- HTTP complexity scenarios require one external PDP request and allow for every
  expected publish, all requests on the selected profile, no policy denials or
  injected failures, and recorded rule-examination work.
- HTTP failure injection is deterministic and is checked against both backend
  counters and workload-visible publish failures.
- Biscuit attenuation/delegation fails if the derived credential is unchanged.
  Restrictive transformations execute a denial probe where the scenario contract
  requires one.
- Fanout latency payloads use versioned `CLOCK_MONOTONIC_RAW` timestamps. Split
  client roles attest the clock source, and merges reject negative, incompatible,
  or implausible samples.
- Netem MTU setup failures are fatal rather than silently producing an
  unmodified network workload.

These checks establish that the declared path was exercised to the extent stated
by each scenario contract. They do not replace the need to execute the full
matrix after semantic or architectural changes.

## Strict fanout and churn verification

A targeted Part 1 rerun exercised 25 fanout/control candidates with 10 messages,
container-per-client topology, and explicit result inspection. Of those
candidates, **24 currently registered scenarios have targeted run evidence whose
observed outcomes matched their declared designs**. Some of that evidence
predates the latest executable result contracts, so it is evidence for the
recorded configurations rather than proof that the scenarios have been rerun
under every current validation check. The remaining legacy scenario was retired
because its claimed policy effect was not observable on its configured
authorization path.

### Dynamic Security strict ACL-read churn

Verified scenarios:

- `DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-{BISCUIT|JWT}-{10|50|100}`

Contract: five pre-churn messages are delivered to every subscriber; one
allow-to-deny policy change is applied; the remaining five messages produce no
subscriber deliveries. Each run published 10 messages, applied one churn event,
matched its pre/post delivery contract, and reported no unexpected errors.

### Dynamic Security client disable

Verified scenarios:

- `DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-DISABLE-{BISCUIT|JWT}-{10|50|100}`

Contract: five pre-control messages are delivered to every subscriber; a
`disableClient` command then terminates the subscriber sessions; no post-control
deliveries occur. The expected receive-failure signature is one kicked session
per subscriber and is part of the contract rather than an ignored error.

### Dynamic Security ACL revoke

Verified scenarios:

- `DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-REVOKE-{BISCUIT|JWT}-{10|50|100}`

Contract: five pre-control messages are delivered to every subscriber; one
`removeRoleACL` command revokes `publishClientReceive`; sessions remain
connected; no post-control deliveries occur. The 100-subscriber variants
initially exhausted a 256 MiB load-generator limit while eagerly loading the
password map. Password-map profiles now load through a streaming selector, and
both variants passed after that fix.

### Dynamic Security baseline cases

- `DYNAMIC-SECURITY-ANONYMOUS-BASELINE`: anonymous fanout delivered all 10
  messages to all 10 subscribers after correcting the mounted DynSec fixture.
- `DYNAMIC-SECURITY-BASELINE`: 10 clients each completed 10 publish operations;
  the scenario has no subscriber or control workload.
- `DYNAMIC-SECURITY-CHURN`: the runtime-control barrier admitted exactly one
  pre-control publish per client, applied one policy update, and observed one
  post-control denial per client.
- `DYNAMIC-SECURITY-READ-FANOUT`: the single subscriber received all 10 fanout
  messages with no churn enabled.

### HTTP strict ACL-read allow

Verified scenarios:

- `HTTP-ACL-READ-FANOUT-STRICT-COMPLEX-ALLOW-BISCUIT-10`
- `HTTP-ACL-READ-FANOUT-STRICT-COMPLEX-ALLOW-JWT-10`
- `HTTP-ACL-READ-FANOUT-STRICT-COMPLEX-ALLOW-PARITY-BISCUIT-10`

Each published 10 messages and delivered all 100 expected subscriber copies with
no churn and no unexpected errors. Performance values from these smoke runs are
not retained here as semantic evidence.

## Retired invalid scenario

`DYNAMIC-SECURITY-READ-FANOUT-CHURN` is no longer registered. It used
`mosquitto_dynsec.conf` with expiry-only ACL-read enforcement, so read checks
short-circuited on token expiry and did not consult the Dynamic Security policy.
The configured read revocation therefore had no observable effect: delivery
continued after churn. Strict read-churn coverage is provided by the
`DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-*` family.

## Known interpretation boundaries

- `BASELINE-NO-AUTH` pins QoS 0 and `TOKEN-QOS2-{JWT|BISCUIT}` pins QoS 2.
  They remain in Part 2 for other sweep dimensions but are not QoS sweeps.
- Fixed-workload stress and lifecycle/control scenarios intentionally define
  their own client or message axes and must be run as targeted slices described
  in `RUN.md`.
- Removed `acl_read_cost_per_subscriber_ms` values must not be used. They were
  derived from an invalid interpretation of cross-process timing. Current
  fanout scaling uses publish-side timing and validated delivery counts; receive
  latency is retained only with the current clock-provenance contract.
- Local result files are evidence for the recorded configuration only. They do
  not imply that another QoS, topology, issuer mode, TLS mode, or workload axis
  has been verified.
