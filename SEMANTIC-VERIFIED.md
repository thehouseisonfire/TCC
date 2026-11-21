# Benchmark semantic verification status

The final campaign closed on **2026-11-17**. The final audit reconciled
**4,101 accepted scenario results across 486 execution units** with the
prospectively locked scope, with zero missing, duplicate, unexpected, or
unvalidated accepted results. Collection took 126 hours and 7 minutes
of wall-clock time, including interruptions.

| Part | Full reproduction plan | Accepted final results |
| --- | ---: | ---: |
| Part 1 | 3,186 | 2,763 |
| Part 2 | 1,512 | 1,338 |
| Total | 4,698 | 4,101 |

Use the **4,101 accepted results** in the sealed analysis index as the final
dataset for analysis. The final scope omitted 621 slots from the full
reproduction plan and added a 24-result TLS panel to Part 2, for a net
reduction of 597 results.

The full registry contains 444 scenarios (222 base scenarios and 222 TLS
variants). The final campaign used the amended BALANCED design for runtime
feasibility. Both general matrices omit the 200-client/100-message interaction.
Dedicated cohorts retain their scheduled coordinates, including some at
200 clients and 100 messages. Part 1 retained the documented host and
capacity exclusions, with six delegation-handoff slots restored before
collection. The locked scope has three campaign repetitions per selected
workload coordinate.

## Final dataset and provenance

Use `ANALYSIS-INDEX.csv` or its JSONL equivalent in the external artifact
package, `../tcc2-benchmark-artifacts/final-audit-20261117/` on the benchmark
host. Each row identifies one accepted result and points to its immutable
scenario JSON and unit summary. Use `slot_id` or the full
part/cohort/scenario/clients/messages/QoS/mode/repetition key. The index records
effective workload axes. Campaign repetition comes from the scope and
invocation, and the raw JSON can contain multiple internal runs.

Read `FINAL-AUDIT-REPORT.md` for acceptance and incident details and
`PROVENANCE-INDEX.jsonl` for each unit's invocation, source freeze, and
acceptance record. From the audit directory, run
`sha256sum -c FINAL-DATASET-SHA256SUMS` to check the sealed dataset. For a
relocated copy, preserve the artifact directory layout and place the matching
`TCC2/` checkout alongside `tcc2-benchmark-artifacts/`. The checksum manifest
references files in that checkout, including the campaign's generated
`mqtt-auth-biscuit/docker/image-freeze.json`. Resolve the index's absolute
paths against the relocated package. Use the index for
dataset membership because the campaign and recovery directories also contain
failed attempts and diagnostics.

The campaign started at `61cb4b9` and continued at `249d2b0` after a
packet-validator correction for reused TCP endpoint pairs. Workload execution,
measurement windows, and acceptance thresholds stayed the same. The audit
replayed all 189 accepted MTU captures, including the 67 collected before the
correction. The earlier accepted results and captures retained their original
hashes. The audit verified collection and provenance. Statistical analysis is
a subsequent step.

The targeted evidence below records earlier, configuration-specific
verification. A passing workload matches its declared scenario contract.

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

## Historical strict fanout and churn verification

Before the final campaign, a targeted Part 1 rerun exercised 25 fanout/control candidates with 10 messages,
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

- `NETWORK-MTU-9000-*` variants whose credential or TLS handshake flight
  exceeds 1500 bytes are environment-blocked on hosts without a jumbo-capable
  path (host NIC, Docker bridge, veths). On such hosts the broker observes
  zero auth attempts because oversized datagrams are dropped before auth;
  only small-payload siblings (e.g. plain-JWT MTU-9000) can pass there. This
  was observed on commit `214cfca` (c10/m10 qualification: idx44/45/47 fail,
  idx46 passes). These scenarios are unchanged and require a jumbo-capable
  host for verification, not a scenario fix.

- `BASELINE-NO-AUTH` pins QoS 0 and `TOKEN-QOS2-{JWT|BISCUIT}` pins QoS 2.
  They remain in Part 2 for other sweep dimensions but are not QoS sweeps.
- `DYNAMIC-SECURITY-CHURN` is restricted to QoS 1/2 by executable sweep
  metadata and a runner guard. Its post-control denial is client-observable
  as PUBACK rc135 (QoS 1) / PUBREC rc135 (QoS 2); at QoS 0 the denial has no
  client-visible acknowledgement.
- Fixed-workload stress and lifecycle/control scenarios use scenario-defined
  axes. Use the effective axes in the analysis index when comparing them.
- Removed `acl_read_cost_per_subscriber_ms` values must not be used. They were
  derived from an invalid interpretation of cross-process timing. Current
  fanout scaling uses publish-side timing and validated delivery counts; receive
  latency is retained only with the current clock-provenance contract.
- Local result files are evidence for the recorded configuration only. They do
  not imply that another QoS, topology, issuer mode, TLS mode, or workload axis
  has been verified.

## Historical incident records

These records describe earlier freezes and explain why their affected results
were held. Final dataset membership comes from the analysis index.

- [Part 1 Batch B provenance decision](mqtt-auth-biscuit/benchmarks/PROVENANCE-p1-b23eb22-c10-m100-batchB-r2-HOLD.md)
- [Part 1 HTTP latency CONNECT diagnosis](mqtt-auth-biscuit/benchmarks/DIAGNOSIS-p1-b23eb22-c10-m100-lat1000-connect-race.md)
- The early Part 2 freeze `770a096` retained `results-p2-fixed-qos-c10-m10-r1`
  for that historical dataset. Its c10/m10/q0/r1 matrix attempt and subsequent
  churn qualification outputs were diagnostic evidence.
