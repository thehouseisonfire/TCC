# Implementation notes and project history

Benchmark execution is complete. The [run plan](RUN.md) records the planned
matrix, and the [semantic verification record](SEMANTIC-VERIFIED.md) describes
the evidence in this repository and its interpretation limits. The earlier
implementation tracker and issue history are available in Git
(`git show 0189093:PROGRESS.md`).

## Implementation details that affect interpretation

### Dynamic Security control durability

A valid control command can update live policy even if the Dynamic Security
JSON file cannot be written. The control result reports the persistence
warning. Pending structural mutations are reapplied after policy reloads and
retried on later control commands. Changes held only in memory are lost on
broker restart. Runs with writable fixtures exercise the normal persistence
path. [Dynamic Security implementation](mqtt-auth-biscuit/crates/mosquitto-plugin/src/dynamic_security_policy/mod.rs)

### Cached reads and notify-only revocation

On cached sessions, `acl_read_full_authz=false` uses expiry-only checks for
`MOSQ_ACL_READ`. A notify-only control mutation updates policy but leaves
existing cached readers able to receive until they reconnect or resubscribe.
Kick-based enforcement terminates the session, while strict
`acl_read_full_authz=true` checks the new policy on delivery. This affects
which outcomes can be compared across enforcement modes. [Scenario policies](SCENARIO_POLICIES.md)

### Token verification and reauthentication

The broker caches parsed, verified credentials in session state. Authorization
still follows the scenario's policy path, including the expiry-only
`ACL_READ` mode where configured. The deterministic cryptographic baselines
are ES256 JWT via `jsonwebtoken` with AWS-LC and Ed25519 Biscuit via
`biscuit-auth`. Comparisons include those algorithm and library choices.

The Rust `mqtt-auth-client` microbenchmark sends MQTT 5 enhanced-auth data in
CONNECT and an AUTH packet with reason code `0x19` for in-session
reauthentication. It measures CONNECT and reauthentication separately.
[Benchmark runbook](mqtt-auth-biscuit/benchmarks/RUNNING_BENCHMARKS.md)

### Traffic shaping and resource collection

The `netem` service joins Mosquitto's network namespace and carries the
`NET_ADMIN` capability needed to shape the broker interfaces. cAdvisor has
the host mounts needed to collect container metrics. Prometheus scrapes
cAdvisor from a separate Compose service.
[Compose configuration](mqtt-auth-biscuit/docker/docker-compose.yml)
