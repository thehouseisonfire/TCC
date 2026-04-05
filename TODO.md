# Token Identity Binding Modes TODO

## Summary

The project should stop treating token identity semantics as an implicit,
hard-coded assumption.

Instead, the Mosquitto plugin should expose explicit identity-binding controls
for both JWT and Biscuit so benchmark scenarios can choose between:

- capability-style semantics
- identity-bound semantics

This allows:

- realistic JWT deployments where tokens are bound to the MQTT `client_id`
- parity scenarios where Biscuit is also bound to `client_id`
- Biscuit capability scenarios where attenuation/delegation remain intentionally
  unbound from MQTT client identity

This document replaces the earlier assumption that JWT identity binding must be
unconditionally enforced across the whole project.

## Goal

Add plugin-level identity-binding options that make token semantics explicit and
scenario-selectable.

The system should support all of the following modes:

1. JWT capability-bound, Biscuit capability-bound
2. JWT identity-bound, Biscuit capability-bound
3. JWT identity-bound, Biscuit identity-bound

Mode 3 is required for parity scenarios where Biscuit attenuation/delegation is
not being exercised and the benchmark intends to compare equivalent semantics.

## Rationale

### Why the original issue was confusing

The original finding was:

- the plugin accepts a JWT
- caches it under the live broker `client_id`
- does not verify that JWT identity claims match that `client_id`

That looks like a bug only if JWT is assumed to be identity-bound.

However, the current benchmark inventory already contains many fan-out and
shared-token scenarios whose behavior is more naturally interpreted as
capability-style token use.

So the actual problem is broader:

- token identity semantics are currently ambiguous
- the plugin, issuer, authz-server, docs, and scenarios do not describe one
  coherent model

### Why a flag-based design is better

A flag-based design is the cleanest compromise because it:

- preserves realistic identity-bound JWT benchmarking
- preserves Biscuit capability/delegation benchmarking
- enables matched-semantics parity slices when desired
- avoids forcing one global semantic across all experiments

### Why Biscuit should support identity binding too

Biscuit is valuable precisely because it can support attenuation and delegation
offline.

But not every benchmark slice is about that feature.

For parity slices that compare plain authorization cost rather than delegation
capability, Biscuit should also be able to bind to MQTT `client_id` so the
comparison is not confounded by different trust semantics.

## Feature Definition

### New plugin options

Add two explicit plugin options:

- `plugin_opt_jwt_identity_binding`
- `plugin_opt_biscuit_identity_binding`

Initial supported values should be:

- `off`
- `strict`

Meaning:

- `off`: token possession is sufficient; no MQTT `client_id` binding is checked
- `strict`: token identity must match the live broker MQTT `client_id`

Do not implement a JWT-only `sub` check. The behavior must be token-type aware
and explicit.

### JWT strict mode semantics

When `plugin_opt_jwt_identity_binding=strict`:

1. The broker client must have a non-empty MQTT `client_id`
2. The JWT must provide a usable identity
3. If both `claims.client_id` and `claims.sub` are present, they must match
4. The effective JWT identity must equal the live broker `client_id`
5. On mismatch, authentication fails before caching

Effective identity selection:

1. If both `client_id` and `sub` are present and equal, use either
2. If only `client_id` is present, use it
3. If only `sub` is present, use it
4. If neither is present, reject

### Biscuit strict mode semantics

When `plugin_opt_biscuit_identity_binding=strict`:

1. The broker client must have a non-empty MQTT `client_id`
2. The Biscuit token must contain an explicit identity fact
3. The extracted Biscuit identity must equal the live broker `client_id`
4. On mismatch, authentication fails before caching

The implementation should not overload `right(...)` or role facts for this.
Use a dedicated identity fact so semantics stay legible.

Recommended initial fact shape:

```text
client_id("client_1")
```

Recommended supporting config:

- `plugin_opt_biscuit_client_id_fact`

Default:

- `client_id`

That keeps the predicate name configurable without hard-wiring future schema
choices into the verifier.

## Scenario Semantics

### Capability scenarios

Use:

- `jwt_identity_binding=off`
- `biscuit_identity_binding=off`

These scenarios measure capability-style bearer semantics.

This mode is appropriate for:

- shared-token fan-out slices
- Biscuit attenuation
- Biscuit delegation
- any architecture experiment where token possession is the intended model

### Realistic JWT deployment scenarios

Use:

- `jwt_identity_binding=strict`
- `biscuit_identity_binding=off`

These scenarios model a conventional JWT identity-binding deployment and a
capability-style Biscuit deployment. They are valid, but they are not strict
parity scenarios.

### Parity scenarios

Use:

- `jwt_identity_binding=strict`
- `biscuit_identity_binding=strict`

These scenarios are the ones that may claim equivalent identity semantics.

This should be the default for any benchmark family presented as a direct
JWT-versus-Biscuit authorization comparison where attenuation/delegation is not
part of the measurement target.

## Implementation Requirements

### Plugin requirements

Add shared helpers in the plugin for:

- resolving and validating JWT identity under the configured mode
- resolving and validating Biscuit identity under the configured mode

The check must happen before:

- session caching
- session binding
- synthetic username derivation that assumes a valid token

The helpers should return explicit, non-secret-bearing error strings suitable
for debug logging.

### Config requirements

Update plugin config parsing to support:

- `jwt_identity_binding`
- `biscuit_identity_binding`
- `biscuit_client_id_fact`

Defaults should preserve current benchmark behavior:

- JWT: `off`
- Biscuit: `off`
- Biscuit identity fact predicate: `client_id`

Reason:

- current scenario inventory already contains shared-token fan-out behavior
- changing defaults would silently invalidate existing scenario semantics

### Token issuance requirements

#### JWT

When strict identity binding is intended, issued JWTs must carry identity
claims consistent with the MQTT client they are meant for.

At minimum:

- `sub`

Optional but recommended:

- `client_id`

#### Biscuit

When strict identity binding is intended, issued Biscuit tokens must carry the
configured identity fact, for example:

```text
client_id("client_7")
```

Offline fixtures and token-issuer responses must both support this.

### Authz-server alignment

The authz-server currently treats JWT client binding as meaningful when
extracting token roles.

That behavior must be aligned with the new plugin semantics.

Required outcome:

- if JWT identity binding is documented as optional, server-side JWT role
  extraction must not hard-code identity-bound assumptions for scenarios that
  run with binding disabled

This may require:

- matching server config knobs
- or narrowing server-side role extraction to scenarios explicitly using strict
  binding

### Benchmark harness requirements

The harness must classify scenarios by semantics rather than assuming one global
token model.

For strict identity-bound scenarios:

- any multi-client run must provision one token per client identity

For capability-bound scenarios:

- shared token reuse is allowed if documented as intentional

The harness must surface these semantics in scenario metadata.

Recommended metadata keys:

- `jwt_identity_binding`
- `biscuit_identity_binding`
- `semantic_class`

Recommended `semantic_class` values:

- `capability`
- `mixed`
- `parity_identity_bound`

## Test Requirements

### Plugin tests

Add tests for JWT:

- strict mode accepts matching `sub`
- strict mode accepts matching `sub` and `client_id`
- strict mode rejects live `client_id` mismatch
- strict mode rejects inconsistent `sub` and `client_id`
- off mode accepts the same token even when MQTT `client_id` differs

Add equivalent tests for Biscuit:

- strict mode accepts matching identity fact
- strict mode rejects mismatched identity fact
- strict mode rejects missing identity fact
- off mode accepts the same token without MQTT `client_id` binding

Cover both:

- basic auth
- MQTT v5 enhanced auth

### Scenario-level tests

Add tests proving:

- parity scenarios enable strict identity binding for both token types
- capability scenarios keep identity binding disabled
- multi-client strict scenarios fail validation if per-client token provisioning
  is missing
- multi-client capability scenarios may still use a shared token when declared

## Documentation Requirements

Update the following files after implementation:

- `ARTICLE.md`
- `PROGRESS.md`
- `SCENARIO_POLICIES.md`
- `mqtt-auth-biscuit/benchmarks/RUNNING_BENCHMARKS.md`

Documentation must explicitly state:

- whether a scenario is capability-bound, mixed, or parity identity-bound
- whether JWT identity binding is enabled
- whether Biscuit identity binding is enabled
- that Biscuit attenuation/delegation scenarios are intentionally not parity
  scenarios

## Cleanup Consequences

### What becomes obsolete

The earlier assumption that all JWT semantics should be globally changed to
identity-bound is no longer valid.

That means prior work based on:

- mandatory JWT identity binding everywhere
- mandatory per-client JWT provisioning everywhere
- rerun scopes derived only from "JWT should always be identity-bound"

must be revisited.

### Scenario cleanup

Each existing scenario family must be classified into one of the semantic
classes above.

Likely consequences:

- existing shared-token fan-out slices become explicitly `capability`
- direct JWT-vs-Biscuit fairness slices may need new parity variants
- Biscuit-only delegation and attenuation slices stay capability-oriented

### Rerun consequences

Not every historical run becomes invalid.

Reruns are needed only when:

- the scenario is now classified as `parity_identity_bound`
- and its historical token provisioning or token contents did not satisfy that
  semantic

Capability-mode historical runs may remain valid if the writeup reflects that
semantic accurately.

### Code cleanup

After the feature lands, remove or revise:

- comments that imply JWT is always identity-bound
- assumptions in helpers/tests that identity mismatch is always an error
- benchmark validation logic that treats shared-token use as inherently wrong in
  all modes

## Non-goals

- Do not redesign Biscuit delegation/attenuation semantics
- Do not force all scenarios into one token semantic
- Do not silently change existing scenario meaning without documenting it
- Do not claim parity for mixed-semantics scenarios

## Recommended Implementation Order

The document already contains most of the requirements, but it does not yet
contain a concrete execution sequence.

Implement in this order:

1. Add plugin config surface and defaults (Completed)
   - Add parsing and typed config support for:
     - `jwt_identity_binding`
     - `biscuit_identity_binding`
     - `biscuit_client_id_fact`
   - Keep defaults at `off`, `off`, and `client_id`
   - Reject invalid enum values and invalid predicate identifiers

2. Add shared plugin identity-binding helpers (Completed)
   - Implement token-type-specific helpers for:
     - resolving JWT effective identity
     - resolving Biscuit identity fact
     - enforcing configured binding mode against live MQTT `client_id`
   - Return explicit non-secret-bearing errors for logging/tests

3. Wire enforcement into both auth entry points before caching (Completed)
   - Apply the checks in:
     - basic auth flow
     - MQTT v5 enhanced auth flow
   - Ensure rejection happens before:
     - cache insert
     - session binding
     - username derivation

4. Extend plugin unit/integration tests first (Completed)
   - Add focused tests for JWT and Biscuit in both `off` and `strict` modes
   - Cover both auth paths:
     - basic auth
     - enhanced auth
   - Add tests that prove mismatched tokens are not cached

5. Align token issuance with the new semantics
   - Update token issuer fixtures/endpoints so strict-mode JWTs can include:
     - `sub`
     - optional matching `client_id`
   - Update Biscuit issuance/fixtures so strict-mode tokens can include:
     - configurable identity fact such as `client_id("client_7")`

6. Align authz-server behavior with optional identity binding
   - Remove hard-coded assumptions that JWT identity binding is always on
   - If needed, add matching config knobs so role extraction behavior is
     scenario-aware

7. Add benchmark scenario metadata and validation
   - Extend scenario definitions and emitted metadata with:
     - `jwt_identity_binding`
     - `biscuit_identity_binding`
     - `semantic_class`
   - Add validation rules:
     - strict multi-client scenarios require per-client provisioning
     - capability scenarios may intentionally reuse shared tokens

8. Classify existing scenario families and add runnable parity variants where possible
   - Mark existing shared-token fan-out and delegation flows as `capability`
   - Mark mixed JWT-strict/Biscuit-off cases as `mixed`
   - Add runnable `parity_identity_bound` variants only for single-client
     strict slices
   - Do not relabel existing multi-client shared-token families as parity

9. Update benchmark and regression tests around scenario semantics
   - Add tests for:
     - scenario metadata correctness
      - strict provisioning validation
      - capability-mode shared token allowance
      - single-client parity metadata/binding correctness

10. Implement generic per-client strict token provisioning
    - Add harness support to provision one strict-bound token per client
      identity
    - Support both JWT and Biscuit strict modes
    - Apply provisioning at scenario startup, not only refresh/error paths
    - Make the capability generic across eligible multi-client scenario
      families

11. Add blocked multi-client parity variants after provisioning exists
    - Add or split explicit runnable `parity_identity_bound` variants for
      multi-client JWT/Biscuit comparison families
    - Enable strict binding for both token types in those variants
    - Add tests proving valid multi-client strict parity runs now pass
      validation

12. Update docs and cleanup stale assumptions
    - Update:
      - `ARTICLE.md`
      - `PROGRESS.md`
      - `SCENARIO_POLICIES.md`
      - `mqtt-auth-biscuit/benchmarks/RUNNING_BENCHMARKS.md`
    - Remove comments/docs/tests that imply JWT is always identity-bound

13. Run targeted verification in the same order
    - Verify in layers:
      - plugin unit tests
      - token issuer/authz-server tests
      - benchmark scenario metadata tests
      - one capability scenario and one parity scenario end-to-end

Recommended batching for implementation:

- Batch 1: steps 1 to 4 (Completed)
- Batch 2: steps 5 to 6 (Completed)
- Batch 3A: steps 7 to 9 (Completed)
- Feature: step 10 (Completed)
- Batch 3B: step 11 (Completed)
- Batch 4: steps 12 to 13 (Completed)

## Acceptance Criteria

This work is complete when:

1. The plugin exposes explicit JWT and Biscuit identity-binding modes
2. JWT strict mode enforces client binding correctly
3. Biscuit strict mode enforces client binding correctly
4. Capability mode remains supported for both token types
5. Scenario metadata and docs state which semantic each benchmark uses
6. Parity scenarios can run with both token types identity-bound
7. Biscuit delegation/attenuation scenarios remain available as capability
   scenarios without being mislabeled as parity comparisons
