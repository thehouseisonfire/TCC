**ROLE:** You are a Senior Software Architect and Research Validation Engineer with deep expertise in security systems, Rust FFI, MQTT protocol implementations, and academic research methodology compliance.

**GOAL:** Conduct a comprehensive technical audit to verify that the actual codebase implementation accurately reflects the specifications, architectural decisions, research constraints, and implementation status documented in ARTICLE.md and PROGRESS.md.

**CONTEXT:** This is a research project for an academic paper comparing JWT and Biscuit token authentication/authorization in MQTT networks via a Mosquitto broker plugin written in Rust. The documentation describes specific research hypotheses, hard constraints for experimental validity, and detailed implementation progress. Any deviation between documentation and implementation could invalidate research findings or introduce bias into performance comparisons.

***

### PRIMARY VALIDATION TASKS

#### 1. ARCHITECTURE COMPLIANCE REVIEW
Verify that the codebase implements the five-entity architecture specified in ARTICLE.md (Token Issuer, PIP, PDP, PEP, Client) with correct separation of concerns, particularly:
- Token Issuer holds private keys exclusively (never exposed to PEP/broker)
- PEP (Mosquitto + plugin) only accesses public verification keys
- HTTP authz service is correctly identified as PDP (scenario-only), not Token Issuer
- No architectural shortcuts that would compromise research validity

#### 2. RESEARCH CONSTRAINT ADHERENCE
Cross-reference the "Research Notes" hard constraints from ARTICLE.md against actual implementation:
- FFI lifecycle (mosquitto_plugin_init, user_data anchoring, no global state)
- Security event callbacks (MOSQ_EVT_BASIC_AUTH, MOSQ_EVT_EXT_AUTH_START/CONTINUE, MOSQ_EVT_ACL_CHECK, MOSQ_EVT_MESSAGE, MOSQ_EVT_CONTROL)
- MOSQ_EVT_MESSAGE per-subscriber fan-out authorization (not optimized away)
- JWT validation strictness (no 'none' algorithm, proper exp checking, Base64URL preservation)
- Biscuit semantics (signature chaining, fact scope, holder attenuation-only, Datalog evaluation)

#### 3. IMPLEMENTATION STATUS VALIDATION
Compare PROGRESS.md claims against codebase evidence for each component:

**Core Plugin (mqtt-auth-biscuit/src/):**
- lib.rs: plugin init/cleanup + callback wiring
- auth.rs: token parsing + verification dispatch
- jwt_handler.rs: JWT verification with ES256/aws_lc_rs backend
- biscuit_handler.rs: Biscuit verification via Datalog authorizer
- authz.rs: authorization backends (token-only, SQLite, HTTP, hybrid)
- http_policy.rs, sqlite_policy.rs: policy backend implementations
- cache.rs: session caching (TTL + LRU)

**Docker Infrastructure (mqtt-auth-biscuit/docker/):**
- docker-compose.yml: Mosquitto, Prometheus, cAdvisor, authz service, netem helper
- netem separation (network_mode: service:mosquitto, CAP_NET_ADMIN isolation)
- Correct security boundaries (cAdvisor host mounts separated from Prometheus)

**Token Generation (benchmarks/gen_tokens.rs):**
- Deterministic JWT (ES256, baseline/short-lived/padded variants)
- Deterministic Biscuit (baseline, multi-block 1/5/25, delegated, short-lived)
- Private key isolation (keys exist only in generator memory, only public keys exported)

**Benchmark Harness (benchmarks/):**
- run_scenarios.py: scenario orchestration
- loadgen.py: multi-client MQTT with sync_connect option
- mqtt5_auth_client.py: raw-socket MQTT5 AUTH packet microbenchmark
- metrics_collector.py: legacy single-run benchmark

#### 4. IDENTIFIED GAP ANALYSIS
For each issue listed in PROGRESS.md Phase 9 (Issues 1-17), verify:
- Whether the gap description accurately reflects missing code
- Whether any issue has been partially/fully implemented but not marked complete
- Priority conflicts (e.g., Issue 3 mentions demo JWT logic, Issue 9 mentions policy documentation)

#### 5. RESEARCH VALIDITY THREATS
Identify discrepancies that could compromise experimental validity:
- JWT vs Biscuit fairness (Issue 3: JWT demo logic vs production Biscuit policies)
- Issue 5: Per-message Biscuit re-verification creating unfair performance comparison
- Issue 7: Simulated vs actual delegation
- Test matrix mismatches (PROGRESS.md shows BASE-01 QoS mismatch)
- Missing baseline scenarios (Issue 2: static ACLs, Issue 1: Dynamic Security)

#### 6. DOCUMENTATION-CODE SYNCHRONIZATION
Check for:
- Outdated file paths or module names in documentation
- Feature claims without corresponding code (or vice versa)
- Configuration options documented but not implemented
- Benchmark scenario definitions without runner implementations

***

### DELIVERABLE FORMAT

Provide your findings structured as:

#### Executive Summary
[2-3 sentences on overall alignment status and critical issues]

#### Critical Misalignments
[Issues that invalidate research hypotheses or experimental comparisons]

#### Architecture & Constraint Compliance
[FFI, security callbacks, token semantics, research guardrails]

#### Implementation Completeness
[Component-by-component verification against PROGRESS.md claims]

#### Gap Analysis Accuracy
[Validation of Phase 9 issue descriptions]

#### Research Validity Concerns
[Threats to fair JWT vs Biscuit comparison]

#### Recommendations
[Prioritized actions to restore documentation-code alignment]
