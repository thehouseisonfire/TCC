# TODO: Add Multi-Client Reauthentication Storm Scenarios (Implemented)

## Current Limitation

The benchmark suite includes MQTT v5 reauthentication and proactive token
refresh coverage, but the proactive lifecycle scenarios currently focus on a
single client. That is enough to validate correctness of the refresh path, but
it does not measure what happens when many clients renew credentials around the
same time.

In realistic IoT deployments, devices are often provisioned in batches and may
share similar token issuance or expiry windows. That can create renewal bursts
where broker authentication, token verification, and token issuer capacity are
exercised concurrently.

## Why This Matters

A multi-client reauthentication storm would complement the existing
thundering-herd connect scenario. The current thundering-herd scenario measures
simultaneous initial connection pressure; a reauthentication storm would measure
mid-session credential renewal pressure.

This is worth adding if the evaluation makes claims about token lifecycle,
operational viability, or MQTT v5 reauthentication under load. It would provide
evidence for questions a reasonable reviewer could ask:

- Does proactive refresh remain stable when many clients refresh together?
- Do JWT and Biscuit renewal paths differ under concurrent reauthentication?
- Does broker-side authorization latency or token size affect renewal burst
  tail latency?
- Can sessions remain continuous during a synchronized refresh wave?

This scenario should not become a broad matrix expansion. It should be a small,
focused lifecycle stress slice.

## Implementation Plan

1. Define a dedicated scenario family.
   - Add paired JWT and Biscuit scenarios, for example:
     - `TOKEN-LIFECYCLE-REAUTH-STORM-JWT`
     - `TOKEN-LIFECYCLE-REAUTH-STORM-BISCUIT`
   - Use a bounded client count that is large enough to expose concurrency but
     still practical for CI or local research runs, such as 10 or 25 clients.
   - Keep larger counts optional through CLI parameters rather than expanding
     the default matrix.

2. Preserve session continuity semantics.
   - Use MQTT v5 reauthentication rather than disconnect/reconnect.
   - Keep `proactive_refresh_assert_continuity` enabled.
   - Treat any expiry denial, dropped session, or missed refresh as a scenario
     failure.

3. Add synchronized refresh timing.
   - Reuse the existing proactive refresh machinery, but align token expiry or
     refresh margins so clients attempt reauthentication within the same window.
   - If exact synchronization is required, add a small in-process refresh barrier
     for `container-single`.
   - For `container-per-client`, only enable synchronized storm semantics after
     the cross-container barrier from `TODO2.md` exists.

4. Keep refresh timing separate from connect timing.
   - Continue reporting initial `connect` latency.
   - Report refresh latency in `proactive_refresh` and/or `token_refresh`.
   - Add storm-specific metadata such as:

```json
{
  "reauth_storm": {
    "clients": 25,
    "attempts": 25,
    "successes": 25,
    "failures": 0,
    "max_refresh_skew_ms": 18.7,
    "session_continuity_ok": true
  }
}
```

5. Add loadgen metrics if needed.
   - Record per-client refresh attempt time and completion time.
   - Compute refresh skew across clients.
   - Keep reauthentication latency measured from AUTH request initiation to
     successful AUTH completion, not from scenario start.

6. Bound the scenario for reproducibility.
   - Use deterministic token TTLs and refresh margins.
   - Use a fixed message count and message size.
   - Avoid combining the first version with fanout, churn, MTU, or HTTP failure
     profiles.
   - Add those combinations only if the thesis explicitly needs them.

7. Add result validation.
   - Fail if `proactive_refresh_attempts < client_count`.
   - Fail if successes do not equal attempts.
   - Fail if `session_continuity_ok` is false.
   - Fail if expiry denials occur.
   - Include clear errors in the scenario JSON when validation fails.

8. Add tests.
   - Unit-test scenario shape for JWT and Biscuit parity.
   - Unit-test aggregation of proactive refresh counters across clients.
   - Unit-test storm metadata computation.
   - Add a small smoke test with two clients and short TTLs.

## Acceptance Criteria

- The benchmark suite includes focused JWT and Biscuit multi-client
  reauthentication storm scenarios.
- All clients perform MQTT v5 reauthentication without disconnecting.
- The result JSON reports attempts, successes, failures, continuity status, and
  refresh skew.
- Scenario validation fails on missed refreshes, expiry denials, or session
  continuity loss.
- The scenario remains a focused lifecycle stress slice and does not multiply
  unnecessarily across unrelated policy, network, or churn dimensions.
