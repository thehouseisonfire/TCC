# TODO: Support `container-per-client` for Biscuit Delegation Handoff

## Current Limitation

The benchmark suite includes `TOKEN-DELEGATION-HANDOFF-BISCUIT`, which models
runtime Biscuit delegation by publishing delegated tokens over MQTT. However,
the current `container-per-client` topology starts one identical one-client
loadgen process per container. That shape does not cleanly represent the
research-relevant handoff workflow:

- one delegator or master principal creates restricted delegated tokens
- multiple independent delegatee clients receive those tokens
- delegatees connect and exercise the delegated authority

Without explicit delegation roles, a per-client container run risks turning a
multi-principal delegation workflow into isolated self-contained delegation
work. That would weaken the scenario's claim that it measures decentralized
delegation across independent clients.

## Why This Matters

Biscuit delegation is one of the main features that differentiates Biscuit from
JWT in this project. Supporting delegation handoff under `container-per-client`
would connect two important evaluation claims:

- Biscuit can express and transport restricted delegated authority.
- The benchmark topology can model independent IoT-style clients with isolated
  load generation resources.

A reasonable reviewer could ask whether the delegation result still holds when
the delegator and delegatees are separate client processes rather than workers
inside one process. Adding this scenario would make the delegation evidence
stronger and more realistic without expanding the benchmark matrix
frivolously.

## Implementation Plan

1. Define explicit delegation handoff roles.
   - Add a loadgen role option such as
     `--delegation-handoff-role delegator|delegatee|combined`.
   - Keep `combined` as the default for existing host and `container-single`
     behavior.
   - `delegator` should create delegated tokens and publish them to the handoff
     topic.
   - `delegatee` should subscribe for its delegated token, then connect and run
     the benchmark operation using that token.

2. Use a shared handoff run identifier.
   - Generate a unique nonce or run ID in `run_scenarios.py`.
   - Pass it to all delegator and delegatee containers.
   - Require delegatees to ignore handoff messages with the wrong nonce.
   - Include the nonce or a redacted run ID in result metadata for auditability.

3. Orchestrate containers by role.
   - Build the loadgen image once.
   - Start delegatee containers first so they can subscribe to the handoff topic.
   - Wait for delegatee readiness before starting the delegator.
   - Start one delegator container to publish delegated tokens.
   - Collect JSON output from every container.
   - Use deterministic names such as `delegation_delegatee_1` and
     `delegation_delegator`.

4. Add delegatee readiness.
   - Prefer a structured readiness signal over log scraping.
   - Acceptable options:
     - shared ready files in a run-specific directory
     - a small readiness HTTP endpoint in loadgen
     - MQTT readiness messages on a control topic with the run nonce
   - Fail the scenario if all delegatees are not ready before a bounded timeout.

5. Make token ownership explicit.
   - The delegator should generate one delegated token per delegatee client ID.
   - Delegatees should reject tokens not addressed to their own client ID.
   - The delegated token should preserve the intended restrictions: topic,
     operation, TTL, and any additional checks or denies.

6. Merge role-specific results.
   - Delegator output should contribute delegation latency, delegation token
     length, handoff publish latency, and errors.
   - Delegatee output should contribute connect latency, publish/receive
     latency, token acceptance failures, and errors.
   - Recompute aggregate counts from all delegatees rather than copying the
     first delegatee payload.
   - Preserve topology metadata, for example:

```json
{
  "topology": {
    "mode": "container-per-client",
    "delegation_handoff": {
      "delegators": 1,
      "delegatees": 10,
      "topic": "delegation/handoff",
      "qos": 1,
      "retain": true
    }
  }
}
```

7. Preserve existing behavior.
   - Host and `container-single` handoff scenarios should continue to use the
     current combined in-process implementation.
   - `container-per-client` should remain rejected or guarded until role-aware
     handoff is implemented.

8. Add tests.
   - Unit-test delegator and delegatee command construction.
   - Unit-test readiness timeout behavior.
   - Unit-test that delegatees ignore wrong-nonce and wrong-client tokens.
   - Unit-test merge behavior for delegator-only and delegatee-only metrics.
   - Add a small integration smoke test with one delegator and two delegatees.

## Acceptance Criteria

- `container-per-client` supports Biscuit delegation handoff only through
  explicit delegator/delegatee roles.
- Delegatees are ready before the delegator publishes handoff tokens.
- Every delegatee receives and uses the token intended for its own client ID.
- Missing, stale, wrong-nonce, or wrong-client handoff tokens fail the scenario.
- Merged output reports delegation and delegatee operation metrics without
  first-client artifacts.
- Existing host and `container-single` delegation handoff behavior remains
  unchanged.
