# Abstract

Security in IoT networks based on the MQTT protocol requires authorization mechanisms that balance protection and efficiency. This work addresses the limitations of the JSON Web Token (JWT) standard compared to Biscuit, a capability token that provides offline attenuation and delegation. The main objective is to implement and evaluate a security plugin for the Mosquitto broker, developed in Rust, that natively supports both formats. The methodology adopts a predominantly quantitative approach to compare the two technologies in terms of latency, throughput, and resource consumption. The study aims to validate the practical viability of Biscuit by analyzing whether the benefits outweigh the expected higher processing cost, contributing a reproducible prototype and guidelines for the adoption of more autonomous authorization models that leverage its architecture.

# Introduction

## Contextualization

The exponential growth of the *Internet of Things* (IoT) has consolidated the MQTT protocol as the de facto standard in the industry, driven by its lightweight nature and efficiency in constrained and unstable networks. With the expansion of this ecosystem into critical infrastructures, security has become a priority non-functional requirement, demanding authentication and authorization mechanisms that balance robust protection with the resource scarcity typical of embedded devices.

Currently, the dominant standard for access control in these architectures is based on JSON Web Tokens (JWT). This technology offers a proven *stateless* authentication model, allowing *brokers* to validate credentials without maintaining persistent sessions. However, as IoT networks evolve toward more complex and decentralized topologies, and authorization rules grow in scope and level of detail, challenges emerge related to the dependence on external services for policy resolution, which can introduce unwanted latency and points of failure.

## Problem

Although the use of JWT is predominant due to its low computational cost and broad compatibility, it presents significant architectural limitations in advanced authorization scenarios. The rigidity of the format makes it difficult to delegate permissions without constant intervention from an authorization server, creating excessive dependence on stable connectivity, which is especially undesirable in the IoT context.

The Biscuit token emerges as a modern alternative, promising to address these gaps through a declarative logic language (Datalog) and a signature chaining architecture that enables offline rights attenuation. However, this complexity raises a critical question of technical viability, particularly regarding the computational cost it may entail.

The current technical literature lacks empirical data that quantify whether the autonomy benefits of Biscuit justify its impact on CPU consumption, memory, and latency compared to the JWT standard, or even a technical demonstration that proves its functionality in the MQTT context.

## General Objective

To develop and evaluate an extension module for the Mosquitto *broker* that natively supports both the Biscuit token and the JWT token, comparatively analyzing the performance, security, and ergonomics between the standards in controlled yet representative scenarios of MQTT networks.

## Specific Objectives

- Design the architecture of an authentication and authorization extension module for Mosquitto, defining the interaction via *Foreign Function Interface* (FFI) between the C-based *broker* and the Rust security logic.
- Implement a functional prototype capable of validating Biscuit tokens, supporting privilege attenuation flows and decentralized delegation, in parallel with an equivalent control flow via JWT.
- Establish a suite of reproducible tests that simulate real MQTT usage patterns, isolating critical metrics such as connection latency, message throughput, resource consumption, and token size.
- Execute comparative experiments in a virtualized environment, varying client load and access policy complexity to stress the verification mechanisms.
- Analyze the quantitative results to validate the viability of Biscuit in MQTT networks, proposing a guide of best practices for adopting decentralized authorization models in this ecosystem.

## Justification

The investigation of alternatives to JWT is crucial for the maturation of IoT security. From an architectural standpoint, the ability to attenuate permissions without constant communication with an external server drastically increases network resilience, mitigating overload risks and enabling continuous operation in scenarios of intermittent connectivity.

Academically, this work fills a gap in the literature on distributed systems by providing a cost-benefit analysis of a new token architecture for the MQTT protocol. In practice, the availability of an open-source module for Mosquitto contributes to the Mosquitto ecosystem, offering a concrete tool for engineers seeking to implement decentralized security and authorization models, modernizing the *broker*'s technology stack.

# Research Notes

This chapter exists to prevent coding LLMs from filling in gaps with assumptions that would change the implementation semantics or invalidate the experimental comparison.
All points below are **hard constraints** for implementation and must be treated as non-negotiable.

## Mosquitto Plugin API Constraints (FFI + Callbacks)

- The plugin lifecycle is defined by Mosquitto calling `mosquitto_plugin_version` to verify API compatibility and then `mosquitto_plugin_init` to initialize the module.
- `mosquitto_plugin_init` provides configuration and a pointer to user memory (`user_data`) that Mosquitto will preserve and pass back to subsequent callback invocations, so long-lived Rust state must be anchored through this mechanism rather than invented global state.
- Security-relevant events that must be treated as ground truth are: `MOSQ_EVT_Basic_AUTH`, `MOSQ_EVT_EXT_AUTH_START`, `MOSQ_EVT_EXT_AUTH_CONTINUE`, `MOSQ_EVT_ACL_CHECK`, `MOSQ_EVT_MESSAGE`, and `MOSQ_EVT_CONTROL`.
- `MOSQ_EVT_ACL_CHECK` is triggered during message publish request (parameter type `MOSQ_ACL_WRITE`), topic subscription request (parameter type `MOSQ_ACL_SUBSCRIBE`) , and is invoked individually for each subscriber that will receive the message (fan-out, parameter type `MOSQ_ACL_READ`), which means per-message authorization cost can scale with subscriber count if not careful to check the event subtype. It is the primary vector for applying authorization rules.
- The `$CONTROL` topic is relevant because it is used by Mosquitto's Dynamic Security extension for runtime ACL/RBAC management, so any evaluation scenario involving dynamic ACLs must align to this control-plane behavior rather than an invented interface.
- Mosquitto provides utilities like `mosquitto_kick_client_by_clientid` / `mosquitto_kick_client_by_username` for forced disconnection.

## JWT Correctness Guardrails (Do Not Be Permissive)

- JWTs are structurally Base64URL-encoded, and Base64URL introduces an approximate 33% size increase compared to the original binary representation, which must be preserved as-is when studying MTU/fragmentation behavior (no "binary JWT" shortcuts).
- Historical JWT implementation failures include accepting the `none` algorithm (unsigned tokens) and confusion between symmetric and asymmetric key usage, so the implementation must enforce strict validation rules rather than best-effort compatibility.

## Biscuit Correctness Guardrails (Do Not Simplify Semantics)

- Biscuit tokens are a chain of cryptographically signed blocks: an issuer-created Authority Block plus holder-appended attenuation blocks, and the implementation must preserve this model (holders can restrict, not expand, rights).
- During Datalog evaluation, the authorizer combines token data with request context (e.g., time, IP, resource), so request context must be injected via the authorizer rather than encoded as mutable client-controlled facts.
- For security, fact scope is controlled: rules from an attenuated block can operate only on facts generated in that same block, the authority block, or authorizer-provided facts, which prevents intermediate-block fact injection and must not be broken by alternate evaluation strategies.
- Biscuit mitigates stateless revocation limitations via unique signature identifiers in each block such that revoking a "root" token revokes all derived tokens, which should be respected when designing revocation/lifecycle checks (no ad-hoc revocation semantics).
- Biscuit supports Snapshots for detailed auditing and reproduction of authorization decisions, which may be used as an optional artifact for debugging/reproducibility.
- Biscuit v3 introduces “third-party blocks” to incorporate authorizations from external entities (identity federation). A scenario could possibly explore this cost.

## Experimental Reproducibility Guardrails (Docker)

- The experimental harness must use Docker resource controls to reduce run-to-run variance by deterministic allocation of compute and memory resources (e.g., `--memory`, `--cpus`).
- CPU pinning must be supported/used where applicable (e.g., `--cpuset-cpus`) to keep broker and load generator on stable cores across scenarios.
- If disk I/O becomes a confounder, the Docker `blkio` controller is the normative mechanism to constrain disk I/O bandwidth for controlled experiments.
- Known limitation: Docker has limitations for direct measurement of container energy consumption, so energy metrics are out-of-scope for this harness unless external measurement is added.

# Methodology

## Approach

This research adopts a predominantly quantitative approach, complemented by qualitative documentation on software engineering aspects involved in the solution's development. For the experimental evaluation, three main hypotheses are defined:

- **H**₁: The use of the Biscuit token is functionally viable in the MQTT ecosystem, covering all authentication and authorization use cases that JWT can support in the Mosquitto broker.
- **H**₂: The Biscuit token presents performance equivalent to JWT in scenarios where both have native support for the functionality (e.g., identity authentication and integrity verification).
- **H**₃: In complex authorization scenarios, where JWT-based architecture requires external introspection or queries to additional systems, Biscuit demonstrates superior performance in terms of latency and throughput.

Among the independent variables, the primary one is the **token type**, crossed with different policy sources: static ACLs native to Mosquitto, dynamic ACLs (via the *Dynamic Security* module), verification in a local database (on the same *broker* instance), and calls to external authorization services via HTTP.

Additionally, there will be variation in MQTT protocol parameters, specifically in Quality of Service (QoS) levels, the load imposed on the system (number of simultaneous connections and message size), and the complexity of access policies (ranging from simple rules to conditionals based on time and attributes).

The dependent variables focus on performance metrics. Authentication and authorization latencies (processing time during publish and subscribe actions) will be collected, distinguishing cryptographic processing time from logical evaluation time. Throughput (messages per second), the load ratio between the control plane and the data plane, and system resource consumption (CPU and memory) will also be monitored, isolating the impact of token size and the frequency of external calls. Connection establishment time (from TCP `SYN` packet to the first actual publication) will be evaluated as a composite variable.

As control variables, hardware, operating system version, and physical network topology will remain constant across all test batteries.

### Entities and Flows

The experiment involves five distinct logical entities:

- **Token Issuer:** Entity holding the private keys, responsible for issuing tokens containing credentials and initial permissions.
- **Policy Information Point (PIP):** Entity that holds the "truth" about access rules (ACLs, databases, or external services).
- **Policy Decision Point (PDP):** The Mosquitto extension module to be developed, responsible for processing the rules.
- **Policy Enforcement Point (PEP):** The Mosquitto server equipped with the module. Verifies token signatures (via static public key) and consults the PDP to allow or deny requests.
- **Client:** Device requesting access to topics. Requests, stores, and presents the token to the PEP. In the specific case of Biscuit, it can append attenuation blocks to tokens it holds.

Due to the architectural characteristics of each technology, the PIP query flow varies significantly:

**Biscuit Flow:** Since Biscuit supports attenuation (but not expansion) of rights, the Issuer must know the maximum permissions at the time of token creation. The query to the primary PIP occurs mostly at issuance. From this point on, the token itself acts as a portable PIP until its invalidation, reducing the need for external queries.

**JWT Flow:** Since standard JWT does not act as an effective capability token (it only carries identity or role claims), the PDP frequently needs to query the PIP in real-time at each request to validate complex or granular permissions.

To ensure test parity and avoid bias, common scenarios in JWT usage, where the token performs only the identification role and the PDP fetches detailed permissions at access time, will also be replicated in the Biscuit architecture for direct comparison purposes.

## Proposed Solution

The proposed solution consists of developing an extension module for Mosquitto, developed in Rust. The choice is justified by Rust's memory safety and performance guarantees, in addition to the native availability of the Biscuit reference implementation. The final artifact will be a dynamic library (*Shared Object* - `.so`) loaded at runtime by Mosquitto.

Using the `cbindgen` tool, C headers (`.h`) will be generated that expose Rust functions to the Mosquitto plugin API (focused on version 2.0+ and MQTT 5.0 protocol). The exported functions will intercept *broker* events, specifically: `MOSQ_EVT_BASIC_AUTH` and `MOSQ_EVT_EXT_AUTH` for authentication; and `MOSQ_EVT_ACL_CHECK`, `MOSQ_EVT_MESSAGE`, and `MOSQ_EVT_CONTROL` for publication, subscription, and control authorization.

For issuance and verification, the module will integrate the `jsonwebtoken` and `biscuit_auth` libraries. By default, it is assumed that clients will request tokens from an external authority before contacting the *broker*. The server will have the root public key pre-configured.

The connection flow will follow MQTT 5.0 specifications:
1. Clients will send their tokens through the `password` field of the `CONNECT` packet. The 65kB limit (defined by the protocol) is sufficient to accommodate both token types.
2. The *broker* will initiate the session after validating the cryptographic signature.
3. To manage expiration without disconnecting the client, a reauthentication flow will be implemented via `AUTH` packets. Upon expiration, the client will request a new token and send it to Mosquitto via another `AUTH` packet, allowing transparent session renewal.

For continuous authorization, the solution will optimize Biscuit performance, avoiding complete cryptographic reverification at each message and performing only policy evaluation (Datalog). If viable, *caching* will be employed for static rules, reevaluating only contextual rules at each message. The use of `AUTH` packets will also allow specific rejection reasons to be communicated, facilitating debugging.

## Proposed Environment

The experimental environment will be standardized with Docker (version 29.0.x), hosting Mosquitto (2.0.x) and clients in isolated containers. The module development will use Rust (version 1.92.x), integrating the `biscuit_auth` (6.x, with support for Biscuit 3.0+) and `jsonwebtoken` (10.x.x) libraries. The SQLite database (3.51.x) will be used for scenarios requiring local persistence of access policies (excluding static ACLs and the *Dynamic Security* module).

To ensure test integrity and minimize neighborhood noise, Docker's `--cpuset` option will be used to pin the *broker* and load generator processes to distinct and consistent physical cores of the host machine.

Network emulation will use `iperf3` to measure the nominal channel capacity, while `tc` (with the `netem` module) will introduce latency, packet loss, and bandwidth limitation in a controlled manner. More complex topologies will be orchestrated via Mininet or Containernet.

## Test Scenarios

The test battery is divided into four categories: isolated (microbenchmarks), integrated (pub/sub workloads), at scale (sustained and bursts), and failure (recovery and latency).

Initially, baseline cases will be established to define the minimum latency and maximum throughput of the environment (without authentication and with native authentication). Next, the use of tokens solely for identity authentication is evaluated, which represents the theoretical "best case" for JWT.

Highlighted scenarios include:

**Fragmentation and MTU (*Maximum Transmission Unit*):** MTU manipulation via `tc` (200B, 500B, 1500B, 9000B) to identify the inflection point at which token size (especially attenuated Biscuits with multiple blocks) causes excessive TCP fragmentation and degrades performance.

**Thundering Herd Problem:** Simulation of *broker* restart with simultaneous reconnection of a large number of clients. The objective is to evaluate whether the computational cost of Biscuit signature verification prevents rapid system recovery compared to JWT.

**Policy Complexity:** Progressive increase of blocks and logical rules in Biscuit (1, 5, 25 blocks) against constant requests by the JWT mechanism to external services for new tokens. The goal is to validate the efficiency of local Biscuit verification against the latency of multiple calls.

**External Latency:** Introduction of degradation in the management network (200ms to 1s, 1% to 5% loss). Biscuit is expected to maintain stable performance (being self-contained), while the JWT model, dependent on introspection, suffers throughput degradation.

**Hybrid Architecture and Contingency:** Test in which Biscuits are evaluated as JWTs (identity only) with external authorization in normal operation, but carry latent policies for local evaluation (with reduced/secure access) if the external service fails.

**Revocation and Lifecycle:** Comparison between revocation list verification (long-lived tokens) *versus* short-lived tokens (5, 15, 60 min) with frequent renewal via `AUTH` flow.

**Delegation:** Simulation of flow in which "master" clients issue attenuated tokens to "worker" clients with permissions strictly limited to the task, exploring the decentralized delegation capabilities unique to Biscuit, as speculated by.

## Data Collection and Analysis

Data collection will be automated through real-time telemetry, extracting metrics from the Mosquitto module, simulated clients, and system tools (`perf`, `tcpdump`). An exporter component will persist time series in appropriate databases, such as InfluxDB or Prometheus.

Statistical treatment will include calculation of the median, standard deviation, and tail percentiles (p50, p95, p99) to identify latency spikes (*tail latency*) that simple averages would obscure.

Data interpretation will focus on validating **H**₂ and **H**₃, quantifying whether the additional computational cost (CPU/Memory) of Biscuit is offset by savings in network resources (latency/bandwidth) compared to the introspection and external traffic required by complex JWT architectures.

Finally, software engineering metrics, such as lines of code and cyclomatic complexity, will be used to discuss the solution's ergonomics, complementing the validation of **H**₁ (functional viability) demonstrated by the successful execution of the test scenarios.
