# TODO: Support `container-per-client` for Synchronized Connect Scenarios

## Current Limitation

`mqtt-auth-biscuit/benchmarks/run_scenarios.py` explicitly rejects:

```text
--client-topology container-per-client
--sync-connect
```

The Rust load generator implements `--sync-connect` with an in-process gate. In `container-per-client`, the Python runner starts one loadgen process per client and rewrites each command to `--clients 1`. That means each container creates a one-client gate and releases independently. The result is not an N-client synchronized connect burst; it is N separate one-client starts.

Allowing that silently would invalidate synchronized-connect benchmark semantics.

## Why This Matters

A cross-container barrier is research-useful if the evaluation needs both:

- per-client resource isolation from one container per MQTT client
- a coordinated thundering-herd connect event

This matters for experiments about authentication admission pressure, broker connection bursts, fairness, resource scheduling, and tail latency under simultaneous client arrival. If those claims are not part of the evaluation, `container-single` is sufficient because it already preserves synchronized starts with the existing in-process gate.

## Implementation Plan

1. Define the barrier contract.
   - Every client container must signal `ready`.
   - No client container may call MQTT connect before the coordinator releases the barrier.
   - Release must happen once all expected clients are ready or the scenario times out.
   - Every output should include enough timing metadata to audit barrier behavior.

2. Add loadgen barrier support.
   - Add CLI options such as:
     - `--sync-connect-barrier-url`
     - `--sync-connect-run-id`
     - `--sync-connect-participant-id`
     - `--sync-connect-participants`
   - Keep existing in-process `--sync-connect` behavior for host and `container-single`.
   - Use the external barrier only when the barrier URL/options are provided.

3. Implement a small coordinator service.
   - Prefer a simple benchmark-local HTTP service over ad hoc sleeps or log parsing.
   - Endpoints can be minimal:
     - `POST /runs/{run_id}/ready/{participant_id}`
     - `GET /runs/{run_id}/wait`
     - `POST /runs/{run_id}/release`
     - `GET /runs/{run_id}/status`
   - The coordinator should enforce participant count, unique IDs, release time, and timeout.
   - It can run as:
     - a lightweight Python subprocess started by `run_scenarios.py`
     - a small service in `docker-compose.yml`
     - a mode inside the existing loadgen binary

4. Wire the barrier into `run_scenarios.py`.
   - Start the coordinator before launching per-client containers.
   - Pass the same run ID and participant count to all containers.
   - Launch all client containers.
   - Wait for readiness from all participants.
   - Release the barrier.
   - Collect all JSON outputs and merge as normal.
   - Tear down the coordinator even when a client fails.

5. Make timing explicit in result JSON.
   - Add fields such as:

```json
{
  "sync_connect": {
    "barrier": "external",
    "participants": 10,
    "ready_count": 10,
    "released_at_unix_ms": 1760000000000,
    "max_ready_skew_ms": 12.4
  }
}
```

   - Record client-side time spent waiting at the barrier.
   - Preserve normal `connect` latency as MQTT connect latency, not barrier wait time.

6. Handle failure modes deliberately.
   - If a client never reaches ready, fail the scenario with a clear timeout error.
   - If a client exits before release, fail the run and include stderr.
   - If the coordinator releases with fewer than expected participants, fail unless an explicit test-only override is set.
   - Use unique run IDs to avoid stale participants from prior failed runs.

7. Add tests before enabling the mode.
   - Unit-test barrier command arguments.
   - Unit-test coordinator ready/release behavior.
   - Unit-test timeout and partial-readiness failures.
   - Unit-test that per-client `sync_connect` no longer removes synchronization semantics.
   - Add a small integration test that verifies multiple containers block before release.

## Acceptance Criteria

- `container-per-client` supports `sync_connect` only through a real cross-container barrier.
- Connect bursts remain synchronized across containers within a documented skew bound.
- Barrier wait time is measured separately from MQTT connect latency.
- Failed or partial barriers fail the scenario instead of producing benchmark output that looks valid.
- Existing host and `container-single` synchronized-connect behavior remains unchanged.
