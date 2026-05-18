# TODO: Support `container-per-client` for Fanout Scenarios (Implemented)

## Current Limitation

`mqtt-auth-biscuit/benchmarks/run_scenarios.py` explicitly rejects:

```text
--client-topology container-per-client
--mode fanout
```

The current `container-per-client` implementation starts one identical `loadgen` service per MQTT client and forces each process to run with `--clients 1`. That is valid for simple publish/control workloads, but fanout benchmarks are role-sensitive: they need a publisher role and a subscriber cohort with coordinated expectations for receive counts, ACL_READ enforcement, churn timing, and resource attribution.

If the runner simply split the current fanout command into one-client containers, each container would not know whether it should act as the publisher or as one subscriber in the fanout population. That would make delivery counts, `received_messages.expected`, ACL_READ cost estimates, and churn semantics ambiguous or wrong.

## Why This Matters

Supporting fanout under `container-per-client` would be research-useful when evaluating ACL_READ cost and broker-side authorization behavior with per-subscriber resource isolation. It would let the benchmark separate:

- broker/auth service cost
- publisher-side load generation cost
- subscriber-side receive cost
- per-client container scheduling and resource effects

Until role separation exists, `container-single` is the correct containerized topology for fanout because it preserves the existing in-process fanout coordination.

## Implementation Plan

1. Define explicit fanout roles for loadgen.
   - Add a role argument such as `--fanout-role publisher|subscriber|combined`.
   - Keep `combined` as the default to preserve existing host and `container-single` behavior.
   - For `subscriber`, require deterministic client identity via `--client-index-start`.
   - For `publisher`, use `--fanout-publisher-username` and publisher token material without also creating subscriber workers.

2. Split fanout orchestration in `run_scenarios.py`.
   - Build the loadgen image once.
   - Start N subscriber containers first.
   - Wait until all subscribers have connected/subscribed and are ready.
   - Start one publisher container after subscriber readiness.
   - Keep deterministic names such as `fanout_subscriber_1`, `fanout_subscriber_2`, and `fanout_publisher`.

3. Add a subscriber readiness protocol.
   - Prefer a structured readiness artifact or health endpoint over log scraping.
   - Options:
     - write a ready file to a shared benchmark run directory
     - expose a small local HTTP readiness server in loadgen
     - publish readiness to a control topic with a unique run nonce
   - Include a timeout and fail the scenario if the subscriber cohort does not become ready.

4. Merge role-specific JSON outputs.
   - Publisher output should contribute publish latency, publish throughput, token/delegation/attenuation metrics, and errors.
   - Subscriber outputs should contribute receive latency, receive throughput, received message counts, fanout churn metrics, and errors.
   - Recompute `received_messages.expected` from scenario semantics, not from a copied first-client payload.
   - Preserve role metadata in `topology`, for example:

```json
{
  "mode": "container-per-client",
  "fanout_roles": {
    "publishers": 1,
    "subscribers": 10
  }
}
```

5. Preserve churn semantics.
   - Apply dynamic-security or SQLite churn once per scenario, not once per subscriber container.
   - Ensure subscriber containers agree on the same control topic, control payload, and run nonce.
   - Attribute churn-trigger timing to the subscriber cohort and publisher message index consistently.

6. Add tests before enabling the mode.
   - Unit-test command construction for publisher and subscriber containers.
   - Unit-test readiness timeout behavior.
   - Unit-test merge behavior for publisher-only and subscriber-only fields.
   - Add an integration smoke test with a small subscriber count and one message.

## Acceptance Criteria

- `container-per-client` no longer rejects fanout only after role splitting is implemented.
- Fanout results match `container-single` semantics for small deterministic scenarios.
- `received_messages.count` and `received_messages.expected` are correct across all subscriber containers.
- Churn scenarios apply exactly one policy transition stream per run.
- The merged result clearly records fanout role topology.
- Existing host and `container-single` fanout behavior remains unchanged.
