**ROLE:**  
You are a Senior Systems Architect and Security Engineer specializing in IoT security, MQTT protocols, token-based authorization systems, and low-level systems programming with Rust and C Foreign Function Interface (FFI). You possess deep expertise in authorization tokens (JWT, Biscuit), cryptographic authentication mechanisms, broker architecture, containerized testing environments, and performance benchmarking methodologies.[2][3]

**GOAL:**  
Develop and evaluate a production-grade authentication/authorization plugin for the Eclipse Mosquitto MQTT broker (v2.0.14+) that natively supports both JWT and Biscuit tokens. The implementation must enable comprehensive comparative analysis of performance (latency, throughput, resource consumption), security capabilities (delegation, attenuation, offline authorization), and operational viability in IoT/constrained network environments.[4]

**CONTEXT:**  
This project addresses critical limitations in current MQTT authorization architectures, specifically the rigid, centralized nature of JWT-based systems that require constant connectivity to authorization servers. Biscuit tokens offer decentralized delegation and offline attenuation capabilities through Datalog-based policy definitions and cryptographic signature chaining, potentially transforming IoT security models. The deliverable includes a Rust-based Mosquitto plugin (.so shared library), containerized testing infrastructure, reproducible benchmark suite, and empirical validation of three hypotheses: (H1) functional viability of Biscuit in MQTT ecosystems, (H2) performance equivalence in basic scenarios, and (H3) superior performance in complex authorization scenarios requiring external policy lookups.[3][4]

**COMPLETE STEP-BY-STEP IMPLEMENTATION GUIDE:**

***

### **PHASE 1: Environment Setup & Prerequisites**

**Step 1.1 - Development Environment Configuration**
- Install Rust toolchain (v1.92+) with cargo, rustc, and rustfmt[5]
- Install Mosquitto development headers: `sudo apt install libmosquitto-dev mosquitto mosquitto-dev`[6]
- Install Docker Engine (v29.0.x+) and docker-compose for containerization
- Install cbindgen tool: `cargo install cbindgen` for generating C headers from Rust[7]
- Clone Mosquitto source: `git clone https://github.com/eclipse/mosquitto.git` to access `mosquitto_plugin.h` and `mosquitto_broker.h`

**Step 1.2 - Project Structure Initialization**
```
mqtt-auth-biscuit/
├── Cargo.toml              # Rust project manifest
├── cbindgen.toml           # C header generation config
├── src/
│   ├── lib.rs              # FFI entry points
│   ├── auth.rs             # Authentication logic
│   ├── authz.rs            # Authorization logic
│   ├── jwt_handler.rs      # JWT verification
│   ├── biscuit_handler.rs  # Biscuit verification
│   └── cache.rs            # Session/policy caching
├── docker/
│   ├── Dockerfile.mosquitto
│   ├── docker-compose.yml
│   └── mosquitto.conf
├── tests/
│   ├── scenarios/          # Test scenario definitions
│   └── clients/            # MQTT client simulators
└── benchmarks/
    └── metrics_collector.py
```

**Step 1.3 - Dependency Declaration (Cargo.toml)**
```toml
[package]
name = "mosquitto-auth-biscuit"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
biscuit-auth = "6.0"              # Biscuit v3.0 support
jsonwebtoken = "10.0"             # JWT verification
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
rusqlite = { version = "0.34", features = ["bundled"] }  # SQLite for ACL storage
log = "0.4"
env_logger = "0.11"
libc = "0.2"                      # C FFI types
once_cell = "1.19"                # Global state management
base64 = "0.22"
chrono = "0.4"
```

***

### **PHASE 2: Mosquitto Plugin FFI Implementation**

**Step 2.1 - Define C-Compatible Plugin Entry Points (src/lib.rs)**
```rust
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

#[repr(C)]
pub struct MosquittoPlugin {
    // Plugin state structure
}

// Required Mosquitto API functions
#[no_mangle]
pub extern "C" fn mosquitto_plugin_version() -> c_int {
    5  // API version 5.0 for MQTT 5.0 support
}

#[no_mangle]
pub extern "C" fn mosquitto_plugin_init(
    user_data: *mut *mut c_void,
    opts: *mut c_void,
    opt_count: c_int,
) -> c_int {
    // Initialize plugin, load keys, setup cache
    // Return MOSQ_ERR_SUCCESS (0) or error code
}

#[no_mangle]
pub extern "C" fn mosquitto_plugin_cleanup(
    user_data: *mut c_void,
    opts: *mut c_void,
    opt_count: c_int,
) -> c_int {
    // Cleanup resources
}
```


**Step 2.2 - Register Authentication Callbacks**
Implement handlers for:
- `MOSQ_EVT_BASIC_AUTH`: username/password authentication (token in password field)
- `MOSQ_EVT_EXT_AUTH_START`: MQTT 5.0 enhanced auth initiation
- `MOSQ_EVT_EXT_AUTH_CONTINUE`: AUTH packet exchange for token refresh
[8][3]

**Step 2.3 - Register Authorization Callbacks**
- `MOSQ_EVT_ACL_CHECK`: Topic access control (pub/sub permissions)
- `MOSQ_EVT_MESSAGE`: Per-subscriber message filtering
- `MOSQ_EVT_CONTROL`: Dynamic security control topic handling

**Step 2.4 - Generate C Header with cbindgen**
```bash
cbindgen --config cbindgen.toml --crate mosquitto-auth-biscuit --output mosquitto_auth_biscuit.h
```


***

### **PHASE 3: Token Verification Engines**

**Step 3.1 - JWT Verification Module (src/jwt_handler.rs)**
```rust
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,           // Subject (client ID)
    exp: usize,            // Expiration timestamp
    iss: String,           // Issuer
    aud: Option<String>,   // Audience
    client_id: Option<String>,
    roles: Option<Vec<String>>,
}

pub fn verify_jwt_token(
    token: &str,
    public_key: &DecodingKey,
) -> Result<Claims, jsonwebtoken::errors::Error> {
    let validation = Validation::new(Algorithm::RS256);
    let token_data = decode::<Claims>(token, public_key, &validation)?;
    Ok(token_data.claims)
}
```


**Step 3.2 - Biscuit Verification Module (src/biscuit_handler.rs)**
```rust
use biscuit_auth::{Biscuit, PublicKey, Authorizer};

pub fn verify_biscuit_token(
    token_bytes: &[u8],
    root_public_key: &PublicKey,
    topic: &str,
    operation: &str, // "publish" or "subscribe"
) -> Result<bool, biscuit_auth::error::Token> {
    // Deserialize token
    let biscuit = Biscuit::from(token_bytes, root_public_key)?;
    
    // Create authorizer with context
    let mut authorizer = Authorizer::new();
    authorizer.add_fact(format!("resource(\"{}\")", topic))?;
    authorizer.add_fact(format!("operation(\"{}\")", operation))?;
    authorizer.add_fact(format!("time({})", chrono::Utc::now().timestamp()))?;
    
    // Add allow/deny policies
    authorizer.add_policy("allow if true")?;
    
    // Authorize
    authorizer.authorize()?;
    Ok(true)
}
```


**Step 3.3 - Session Cache Implementation (src/cache.rs)**
Implement LRU cache for validated tokens to avoid re-verification on every message:
- Key: token signature hash
- Value: (client_id, expiration, permissions_map)
- Eviction: TTL-based + LRU policy

***

### **PHASE 4: MQTT Flow Integration**

**Step 4.1 - CONNECT Packet Handling**
1. Extract token from `password` field (MQTT 3.1.1/5.0) or User Property (MQTT 5.0)
2. Detect token type: JWT (starts with `eyJ`) vs Biscuit (binary/base64)
3. Verify signature cryptographically
4. Store session metadata in cache
5. Return `MOSQ_ERR_SUCCESS` or `MOSQ_ERR_AUTH`
[3]

**Step 4.2 - AUTH Packet Flow (Token Refresh)**
Implement MQTT 5.0 re-authentication:
```
Client -> AUTH(reason=re-authenticate, token=new_jwt)
Plugin verifies token
Plugin -> AUTH(reason=success) or DISCONNECT
```


**Step 4.3 - ACL Check on PUBLISH/SUBSCRIBE**
```rust
fn check_acl(client_id: &str, topic: &str, access: AccessType) -> bool {
    // 1. Retrieve session from cache
    // 2. For JWT: query external PIP or local SQLite ACL
    // 3. For Biscuit: evaluate Datalog rules with topic context
    // 4. Support MQTT wildcards (+, #) in topic matching
}
```


***

### **PHASE 5: Containerized Testing Infrastructure**

**Step 5.1 - Dockerfile for Mosquitto + Plugin**
```dockerfile
FROM eclipse-mosquitto:2.0.14
RUN apk add --no-cache libgcc libstdc++
COPY target/release/libmosquitto_auth_biscuit.so /mosquitto/plugins/
COPY mosquitto.conf /mosquitto/config/
```


**Step 5.2 - docker-compose.yml for Test Topology**
```yaml
version: '3.9'
services:
  mosquitto:
    build: ./docker
    ports:
      - "1883:1883"
    cpuset: "0-1"         # Pin to CPU cores
    mem_limit: 512m
    networks:
      - mqtt-net
  
  client-publisher:
    image: eclipse-mosquitto:2.0.14
    command: |
      mosquitto_pub -h mosquitto -t sensors/temp -m "25.3" 
      -u jwt -P <jwt_token>
    depends_on:
      - mosquitto
    networks:
      - mqtt-net
  
  metrics-collector:
    image: prom/prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    networks:
      - mqtt-net

networks:
  mqtt-net:
    driver: bridge
```


**Step 5.3 - Network Emulation with tc (Traffic Control)**
```bash
# Add 100ms latency
docker exec mosquitto tc qdisc add dev eth0 root netem delay 100ms

# Limit bandwidth to 1Mbps
docker exec mosquitto tc qdisc add dev eth0 root tbf rate 1mbit burst 32kbit latency 400ms

# Packet loss 5%
docker exec mosquitto tc qdisc change dev eth0 root netem loss 5%
```


***

### **PHASE 6: Benchmark Test Scenarios**

**Step 6.1 - Define Test Matrices**
| Scenario | Clients | QoS | Token Type | Policy Source | Metrics |
|----------|---------|-----|------------|---------------|---------|
| Baseline | 10-1000 | 0-2 | None | N/A | Latency, CPU |
| JWT-Simple | 100 | 1 | JWT | Static ACL | Connect time, msg/s |
| JWT-External | 100 | 1 | JWT | HTTP Introspection | Network calls, latency |
| Biscuit-Simple | 100 | 1 | Biscuit | Embedded rules | Verify time, throughput |
| Biscuit-Attenuated | 100 | 1 | Biscuit (5 blocks) | Chained rules | Block verification cost |
| MTU-Fragmentation | 50 | 1 | Both | N/A | Token size vs MTU |

**Step 6.2 - Automated Load Generation**
Use `mqtt-stresser` or custom Python clients with `paho-mqtt`:
```python
import paho.mqtt.client as mqtt
import time

clients = []
for i in range(1000):
    client = mqtt.Client(f"client_{i}")
    client.username_pw_set("jwt", jwt_token)
    client.connect("localhost", 1883)
    clients.append(client)
    client.publish("sensors/temp", f"temp_{i}")
```


**Step 6.3 - Metrics Collection**
- **Latency**: Time from CONNECT to CONNACK, PUBLISH to ACK
- **Throughput**: Messages/second sustained over 60s
- **CPU/Memory**: `docker stats` + cAdvisor
- **Token Size**: Bytes on wire, impact on MTU (200B, 1500B, 9000B)
- **Network Calls**: Count of external PIP queries (JWT introspection)

***

### **PHASE 7: Data Analysis & Validation**

**Step 7.1 - Statistical Processing**
- Calculate median, p50, p95, p99 percentiles for latency distributions
- Compare JWT vs Biscuit across scenarios using paired t-tests
- Identify crossover points (e.g., "Biscuit faster when >X external calls")

**Step 7.2 - Hypothesis Testing**
- **H1 (Functional Viability)**: Document all MQTT 5.0 features supported (AUTH flow, wildcards, QoS levels)
- **H2 (Performance Equivalence)**: Show <10% difference in baseline scenarios
- **H3 (Complex Scenarios)**: Prove Biscuit reduces latency by 30%+ when JWT requires external lookups

**Step 7.3 - Visualization**
Generate plots:
- Latency CDF curves (JWT vs Biscuit)
- Throughput vs concurrent clients
- CPU usage over time with different token types
- Token size impact on connection establishment time

***

### **PHASE 8: Advanced Features (Optional)**

**Step 8.1 - Biscuit Delegation Demo**
Create test scenario:
```
1. Root token issued to "gateway" with rights: [publish("sensors/*"), subscribe("commands/*")]
2. Gateway attenuates token for "sensor-1": [publish("sensors/temp"), ttl=3600]
3. Sensor-1 connects with attenuated token
4. Verify: can publish to sensors/temp, CANNOT publish to sensors/humidity
```


**Step 8.2 - Revocation Mechanisms**
- Implement Biscuit revocation via unique signature IDs in Redis/SQLite
- Compare with JWT short-lived + refresh token pattern

**Step 8.3 - Hybrid Architecture**
JWT for authentication + Biscuit for authorization:
- Use JWT `sub` claim to fetch Biscuit from cache
- Fallback to external policy server if Biscuit expired

***

### **PHASE 9: Documentation & Deliverables**

**Step 9.1 - Code Documentation**
- Rustdoc comments for all public functions
- Architecture diagram (client → plugin → Mosquitto → backend)
- API reference for configuration options

**Step 9.2 - Reproducibility Package**
- Docker images on Docker Hub or GitHub Container Registry
- `README.md` with exact reproduction steps
- Automated benchmark script: `./run_benchmarks.sh`

**Step 9.3 - Academic Paper Sections**
Structure aligned with TCC:
1. **Methodology**: Environment specs, test scenarios, statistical methods
2. **Results**: Tables/graphs comparing latency, throughput, resource consumption
3. **Discussion**: Interpretation of H1-H3, tradeoffs, practical recommendations
4. **Conclusion**: Viability statement, contribution to IoT security field

***

***

**CRITICAL SUCCESS FACTORS:**
1. **Cryptographic Correctness**: Validate key handling (Ed25519, RSA-2048) with test vectors from RFCs
2. **Memory Safety**: Run under Valgrind/AddressSanitizer to detect FFI boundary violations[5]
3. **Reproducibility**: Pin all dependency versions, document CPU architecture impact (x86_64 vs ARM64)
4. **Statistical Rigor**: Use sufficient sample sizes (n>1000 per scenario), report confidence intervals
5. **Open Source Best Practices**: MIT/Apache-2.0 license, CI/CD with GitHub Actions, semantic versioning

This implementation addresses the core research question: "Can Biscuit tokens provide a practical alternative to JWT in resource-constrained MQTT environments while enabling decentralized authorization patterns impossible with traditional approaches?"[4]

[2](https://www.reddit.com/r/rust/comments/k5wlw9/mosquitto_broker_plugin_library_mosquittoplugin/)
[3](https://www.codementor.io/@emqtech/a-deep-dive-into-token-based-authentication-and-oauth-2-0-in-mqtt-25rzd9xy2n)
[4](https://news.ycombinator.com/item?id=38635617)
[5](https://doc.rust-lang.org/nomicon/ffi.html)
[6](https://dev.to/arshidkv12/mosquitto-auth-plugin-rust-53kj)
[7](https://github.com/TotalKrill/mosquitto_plugin)
[8](https://cedalo.com/blog/mosquitto-mqtt-jwt/)
[9](https://crates.io/crates/mosquitto-plugin/dependencies)
[10](https://docs.rs/mosquitto-plugin)
[11](https://stackoverflow.com/questions/37582444/jwt-vs-cookies-for-token-based-authentication)
