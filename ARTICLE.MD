\documentclass{article}

\begin{document}
\maketitle

\chapter{Abstract}

Security in IoT networks based on the MQTT protocol requires authorization mechanisms that balance protection and efficiency. This work addresses the limitations of the JSON Web Token (JWT) standard compared to Biscuit, a capability token that provides offline attenuation and delegation. The main objective is to implement and evaluate a security plugin for the Mosquitto broker, developed in Rust, that natively supports both formats. The methodology adopts a predominantly quantitative approach to compare the two technologies in terms of latency, throughput, and resource consumption. The study aims to validate the practical viability of Biscuit by analyzing whether the benefits outweigh the expected higher processing cost, contributing a reproducible prototype and guidelines for the adoption of more autonomous authorization models that leverage its architecture.

\chapter{Introduction}

\section{Introduction/Contextualization}

The exponential growth of the \emph{Internet of Things} (IoT) has consolidated the MQTT protocol as the de facto standard in the industry, driven by its lightweight nature and efficiency in constrained and unstable networks. With the expansion of this ecosystem into critical infrastructures, security has become a priority non-functional requirement, demanding authentication and authorization mechanisms that balance robust protection with the resource scarcity typical of embedded devices.

Currently, the dominant standard for access control in these architectures is based on JSON Web Tokens (JWT). This technology offers a proven \emph{stateless} authentication model, allowing \emph{brokers} to validate credentials without maintaining persistent sessions. However, as IoT networks evolve toward more complex and decentralized topologies, and authorization rules grow in scope and level of detail, challenges emerge related to the dependence on external services for policy resolution, which can introduce unwanted latency and points of failure.

\section{Problem}

Although the use of JWT is predominant due to its low computational cost and broad compatibility, it presents significant architectural limitations in advanced authorization scenarios. The rigidity of the format makes it difficult to delegate permissions without constant intervention from an authorization server, creating excessive dependence on stable connectivity, which is especially undesirable in the IoT context.

The Biscuit token emerges as a modern alternative, promising to address these gaps through a declarative logic language (Datalog) and a signature chaining architecture that enables offline rights attenuation. However, this complexity raises a critical question of technical viability, particularly regarding the computational cost it may entail.

The current technical literature lacks empirical data that quantify whether the autonomy benefits of Biscuit justify its impact on CPU consumption, memory, and latency compared to the JWT standard, or even a technical demonstration that proves its functionality in the MQTT context.

\section{General Objective}

To develop and evaluate an extension module for the Mosquitto \emph{broker} that natively supports both the Biscuit token and the JWT token, comparatively analyzing the performance, security, and ergonomics between the standards in controlled yet representative scenarios of MQTT networks.

\section{Specific Objectives}

\begin{itemize}
    \item Design the architecture of an authentication and authorization extension module for Mosquitto, defining the interaction via \emph{Foreign Function Interface} (FFI) between the C-based \emph{broker} and the Rust security logic.
    \item Implement a functional prototype capable of validating Biscuit tokens, supporting privilege attenuation flows and decentralized delegation, in parallel with an equivalent control flow via JWT.
    \item Establish a suite of reproducible tests that simulate real MQTT usage patterns, isolating critical metrics such as connection latency, message throughput, resource consumption, and token size.
    \item Execute comparative experiments in a virtualized environment, varying client load and access policy complexity to stress the verification mechanisms.
    \item Analyze the quantitative results to validate the viability of Biscuit in MQTT networks, proposing a guide of best practices for adopting decentralized authorization models in this ecosystem.
\end{itemize}

\section{Justification}

The investigation of alternatives to JWT is crucial for the maturation of IoT security. From an architectural standpoint, the ability to attenuate permissions without constant communication with an external server drastically increases network resilience, mitigating overload risks and enabling continuous operation in scenarios of intermittent connectivity.

Academically, this work fills a gap in the literature on distributed systems by providing a cost-benefit analysis of a new token architecture for the MQTT protocol. In practice, the availability of an open-source module for Mosquitto contributes to the Mosquitto ecosystem, offering a concrete tool for engineers seeking to implement decentralized security and authorization models, modernizing the \emph{broker}'s technology stack.


\chapter{Methodology}

\section{Approach}

This research adopts a predominantly quantitative approach, complemented by qualitative documentation on software engineering aspects involved in the solution's development. For the experimental evaluation, three main hypotheses are defined:

\begin{itemize}
  \item $\mathbf{H}_1$: The use of the Biscuit token is functionally viable in the MQTT ecosystem, covering all authentication and authorization use cases that JWT can support in the Mosquitto broker.
  \item $\mathbf{H}_2$: The Biscuit token presents performance equivalent to JWT in scenarios where both have native support for the functionality (e.g., identity authentication and integrity verification).
  \item $\mathbf{H}_3$: In complex authorization scenarios, where JWT-based architecture requires external introspection or queries to additional systems, Biscuit demonstrates superior performance in terms of latency and throughput.
\end{itemize}

Among the independent variables, the primary one is the \textbf{token type}, crossed with different policy sources: static ACLs native to Mosquitto, dynamic ACLs (via the \emph{Dynamic Security} module), verification in a local database (on the same \emph{broker} instance), and calls to external authorization services via HTTP.

Additionally, there will be variation in MQTT protocol parameters, specifically in Quality of Service (QoS) levels, the load imposed on the system (number of simultaneous connections and message size), and the complexity of access policies (ranging from simple rules to conditionals based on time and attributes).

The dependent variables focus on performance metrics. Authentication and authorization latencies (processing time during publish and subscribe actions) will be collected, distinguishing cryptographic processing time from logical evaluation time. Throughput (messages per second), the load ratio between the control plane and the data plane, and system resource consumption (CPU and memory) will also be monitored, isolating the impact of token size and the frequency of external calls. Connection establishment time (from TCP \texttt{SYN} packet to the first actual publication) will be evaluated as a composite variable.

As control variables, hardware, operating system version, and physical network topology will remain constant across all test batteries.

\subsection{Entities and Flows}

The experiment involves five distinct logical entities:

\begin{itemize}
 \item \textbf{Token Issuer:} Entity holding the private keys, responsible for issuing tokens containing credentials and initial permissions.
 \item \textbf{Policy Information Point (PIP):} Entity that holds the "truth" about access rules (ACLs, databases, or external services).
 \item \textbf{Policy Decision Point (PDP):} The Mosquitto extension module to be developed, responsible for processing the rules.
 \item \textbf{Policy Enforcement Point (PEP):} The Mosquitto server equipped with the module. Verifies token signatures (via static public key) and consults the PDP to allow or deny requests.
 \item \textbf{Client:} Device requesting access to topics. Requests, stores, and presents the token to the PEP. In the specific case of Biscuit, it can append attenuation blocks to tokens it holds.
\end{itemize}

Due to the architectural characteristics of each technology, the PIP query flow varies significantly:

\textbf{Biscuit Flow:} Since Biscuit supports attenuation (but not expansion) of rights, the Issuer must know the maximum permissions at the time of token creation. The query to the primary PIP occurs mostly at issuance. From this point on, the token itself acts as a portable PIP until its invalidation, reducing the need for external queries.

\textbf{JWT Flow:} Since standard JWT does not act as an effective capability token (it only carries identity or role claims), the PDP frequently needs to query the PIP in real-time at each request to validate complex or granular permissions.

To ensure test parity and avoid bias, common scenarios in JWT usage, where the token performs only the identification role and the PDP fetches detailed permissions at access time, will also be replicated in the Biscuit architecture for direct comparison purposes.

\section{Proposed Solution}

The proposed solution consists of developing an extension module for Mosquitto, developed in Rust. The choice is justified by Rust's memory safety and performance guarantees, in addition to the native availability of the Biscuit reference implementation. The final artifact will be a dynamic library (\emph{Shared Object} - \texttt{.so}) loaded at runtime by Mosquitto.

Using the \texttt{cbindgen} tool, C headers (\texttt{.h}) will be generated that expose Rust functions to the Mosquitto plugin API (focused on version 2.0+ and MQTT 5.0 protocol). The exported functions will intercept \emph{broker} events, specifically: \texttt{MOSQ\_EVT\_BASIC\_AUTH} and \texttt{MOSQ\_EVT\_EXT\_AUTH} for authentication; and \texttt{MOSQ\_EVT\_ACL\_CHECK}, \texttt{MOSQ\_EVT\_MESSAGE}, and \texttt{MOSQ\_EVT\_CONTROL} for publication, subscription, and control authorization.

For issuance and verification, the module will integrate the \texttt{jsonwebtoken} and \texttt{biscuit\_auth} libraries. By default, it is assumed that clients will request tokens from an external authority before contacting the \emph{broker}. The server will have the root public key pre-configured \cite{rust_jsonwebtoken}.

The connection flow will follow MQTT 5.0 specifications:
\begin{enumerate}
    \item Clients will send their tokens through the \texttt{password} field of the \texttt{CONNECT} packet. The 65kB limit (defined by the protocol) is sufficient to accommodate both token types.
    \item The \emph{broker} will initiate the session after validating the cryptographic signature.
    \item To manage expiration without disconnecting the client, a reauthentication flow will be implemented via \texttt{AUTH} packets. Upon expiration, the client will request a new token and send it to Mosquitto via another \texttt{AUTH} packet, allowing transparent session renewal.
\end{enumerate}

For continuous authorization, the solution will optimize Biscuit performance, avoiding complete cryptographic reverification at each message and performing only policy evaluation (Datalog). If viable, \emph{caching} will be employed for static rules, reevaluating only contextual rules at each message. The use of \texttt{AUTH} packets will also allow specific rejection reasons to be communicated, facilitating debugging.

\section{Proposed Environment}

The experimental environment will be standardized with Docker (version 29.0.x), hosting Mosquitto (2.0.x) and clients in isolated containers. The module development will use Rust (version 1.92.x), integrating the \texttt{biscuit\_auth} (6.x, with support for Biscuit 3.0+) and \texttt{jsonwebtoken} (10.x.x) libraries \cite{rust_jsonwebtoken}. The SQLite database (3.51.x) will be used for scenarios requiring local persistence of access policies (excluding static ACLs and the \emph{Dynamic Security} module).

To ensure test integrity and minimize neighborhood noise, Docker's \texttt{--cpuset} option will be used to pin the \emph{broker} and load generator processes to distinct and consistent physical cores of the host machine.

Network emulation will use \texttt{iperf3} to measure the nominal channel capacity, while \texttt{tc} (with the \texttt{netem} module) will introduce latency, packet loss, and bandwidth limitation in a controlled manner \cite{iperf3}. Load tests will use specialized tools such as \texttt{mqtt-stresser} and \texttt{emqtt-bench} \cite{mqtt-stresser,emqtt-bench}. More complex topologies will be orchestrated via Mininet or Containernet \cite{mininet,containernet}.

\section{Test Scenarios}

The test battery is divided into four categories: isolated (microbenchmarks), integrated (pub/sub workloads), at scale (sustained and bursts), and failure (recovery and latency).

Initially, baseline cases will be established to define the minimum latency and maximum throughput of the environment (without authentication and with native authentication). Next, the use of tokens solely for identity authentication is evaluated, which represents the theoretical "best case" for JWT.

Highlighted scenarios include:

\textbf{Fragmentation and MTU (\emph{Maximum Transmission Unit}):} MTU manipulation via \texttt{tc} (200B, 500B, 1500B, 9000B) to identify the inflection point at which token size (especially attenuated Biscuits with multiple blocks) causes excessive TCP fragmentation and degrades performance.

\textbf{Thundering Herd Problem:} Simulation of \emph{broker} restart with simultaneous reconnection of a large number of clients. The objective is to evaluate whether the computational cost of Biscuit signature verification prevents rapid system recovery compared to JWT.

\textbf{Policy Complexity:} Progressive increase of blocks and logical rules in Biscuit (1, 5, 25 blocks) against constant requests by the JWT mechanism to external services for new tokens. The goal is to validate the efficiency of local Biscuit verification against the latency of multiple calls.

\textbf{External Latency:} Introduction of degradation in the management network (200ms to 1s, 1\% to 5\% loss). Biscuit is expected to maintain stable performance (being self-contained), while the JWT model, dependent on introspection, suffers throughput degradation.

\textbf{Hybrid Architecture and Contingency:} Test in which Biscuits are evaluated as JWTs (identity only) with external authorization in normal operation, but carry latent policies for local evaluation (with reduced/secure access) if the external service fails.

\textbf{Revocation and Lifecycle:} Comparison between revocation list verification (long-lived tokens) \emph{versus} short-lived tokens (5, 15, 60 min) with frequent renewal via \texttt{AUTH} flow.

\textbf{Delegation:} Simulation of flow in which "master" clients issue attenuated tokens to "worker" clients with permissions strictly limited to the task, exploring the decentralized delegation capabilities unique to Biscuit, as speculated by \citeonline{identity_management_for_agents}.

\section{Data Collection and Analysis}

Data collection will be automated through real-time telemetry, extracting metrics from the Mosquitto module, simulated clients, and system tools (\texttt{perf}, \texttt{tcpdump}). An exporter component will persist time series in appropriate databases, such as InfluxDB or Prometheus \cite{influxdb,prometheus}.

Statistical treatment will include calculation of the median, standard deviation, and tail percentiles ($p50, p95, p99$) to identify latency spikes (\emph{tail latency}) that simple averages would obscure.

Data interpretation will focus on validating $\mathbf{H}_2$ and $\mathbf{H}_3$, quantifying whether the additional computational cost (CPU/Memory) of Biscuit is offset by savings in network resources (latency/bandwidth) compared to the introspection and external traffic required by complex JWT architectures.

Finally, software engineering metrics, such as lines of code and cyclomatic complexity, will be used to discuss the solution's ergonomics, complementing the validation of $\mathbf{H}_1$ (functional viability) demonstrated by the successful execution of the test scenarios.
\end{document}
