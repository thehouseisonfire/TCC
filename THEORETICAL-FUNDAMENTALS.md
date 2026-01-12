\chapter{Theoretical Fundamentals}

\section{MQTT Protocol}

MQTT is a \emph{publish-subscribe} messaging protocol designed to be lightweight and efficient. Created in 1999 by Andy Stanford-Clark of IBM and Arlen Nipper of Eurotech under the name \emph{Message Queue Telemetry Transport}, the protocol was originally developed for the energy sector, aiming to monitor oil and gas pipelines via satellite connections \cite{hivemq_origin,wikipedia_mqtt}. In 2010, IBM released the protocol as an open standard in version 3.1 \cite{ibm_v31}. Subsequently, in 2013, it was officially endorsed by the \emph{Organization for the Advancement of Structured Information Standards} (OASIS), becoming the ISO/IEC 20922:2016 standard \cite{oasis_2013,iso_20922}. Despite the original nomenclature, the protocol does not implement message queues in the traditional sense, and the "MQ" prefix is a legacy of its predecessor technology, IBM MQSeries \cite{wikipedia_mqtt,hivemq_origin}.

The raison d'être of MQTT lies in its ability to operate robustly in resource-constrained environments, providing low bandwidth usage, minimal power consumption, and reliable communication in unstable or high-latency networks. Such characteristics make it an attractive choice for connecting a wide range of devices, such as sensors, mobile applications, industrial control systems, and smart appliances, as well as for networks deployed in remote or hard-to-access environments, such as underwater monitoring stations or agricultural sensors \cite{influx_mqtt_use_cases,emqx_mqtt_use_cases,ibm_v31,oasis_v311,hivemq_essentials}.

At its core, MQTT operates on a client-broker model, in contrast to the client-server architecture common in protocols like the \emph{Hypertext Transfer Protocol} (HTTP), where communication occurs directly between endpoints \cite{oasis_v311}. Thus, its architecture defines three distinct functions:

\begin{itemize}
   \item \textbf{Publisher}: Client that sends (publishes) messages to the \emph{broker}.
   \item \textbf{Subscriber}: Client that receives (subscribes to) messages from the \emph{broker}.
   \item \textbf{Broker}: Central server responsible for receiving all messages from publishers, filtering them, and routing them to the appropriate subscribers \cite{oasis_v311}.
\end{itemize}

In this topology, clients do not communicate directly with each other, and the \emph{broker} acts as a mandatory intermediary for all network communications. To guarantee bidirectionality, the same client can act simultaneously as a publisher and a subscriber.

The mechanism employed for routing between senders and receivers is called a "topic". Topics are textual labels that serve as addressing channels. Similar to other network protocols, topics are structured hierarchically, using slashes (/) as separators, often referred to as paths or filters (e.g., 'sensors/building1/floor2/temperature'). This tree structure allows for a clear separation of interests, although it imposes rigidity: a topic cannot belong to two logical domains simultaneously, requiring duplication if such visibility is needed \cite{oasis_v311,hivemq_topics}.

To flexibilize data consumption, MQTT supports two types of \emph{wildcards} in subscriptions: the single-level wildcard (+) and the multi-level wildcard (\#). The single-level wildcard replaces exactly one segment of the hierarchy. For example, a subscription to \seqsplit{'sensors/building1/+/temperature'} would receive messages from \seqsplit{'sensors/building1/floor1/temperature'} and \seqsplit{'sensors/building1/floor2/temperature'}, but would ignore \seqsplit{'sensors/building1/floor1/humidity'}. The multi-level wildcard, on the other hand, corresponds to any number of segments from its position to the end of the path. A subscription to 'sensors/building1/\#' would receive all messages under that domain. It is important to note that the multi-level wildcard must be the last character of the filter. These features have direct implications for the implementation of authorization policies, as they allow defining granular permissions across entire hierarchies or specific levels of topics \cite{oasis_v311,hivemq_topics,emqx_acl_explanation}.

The MQTT model is enriched by stateful features such as retained messages, persistent sessions, and Quality of Service (QoS). When a message is published with the \texttt{retain} flag set to true, the \emph{broker} stores the last valid message for that topic. Any client that subsequently subscribes to the topic will immediately receive the retained message, guaranteeing access to the last known state without the need to wait for a new publication \cite{oasis_v311,ibm_v31}. The \emph{broker} can also maintain a persistent session, storing subscriptions and undelivered messages in case of disconnection. Session management is controlled by specific parameters: in versions 3.1 and 3.1.1, by the \emph{Clean Session} flag; in version 5.0, by the combination of \emph{Clean Start} and \emph{Session Expiry Interval}, providing granular control over the session lifecycle \cite{oasis_v311,oasis_v50}.

The QoS system is one of the pillars of the protocol, allowing for a balance between delivery reliability and bandwidth and processing cost. The protocol defines three levels:

\begin{itemize}
    \item \textbf{QoS 0 (At most once)}: The fastest and least reliable level, operating with a "fire and forget" logic. The publisher sends the message once without requiring confirmation. There is no guarantee of delivery.
    \item \textbf{QoS 1 (At least once)}: Guarantees message delivery but may generate duplicates. The publisher sends a \texttt{PUBLISH} packet and waits for a \texttt{PUBACK}. If the confirmation is not received in time, the packet is resent.
    \item \textbf{QoS 2 (Exactly once)}: The most reliable and expensive level. It uses a four-way handshake to ensure the message is delivered exactly once, eliminating duplicates \cite{ibm_v31,oasis_v311,oasis_v50}.
\end{itemize}

The choice of QoS represents a critical trade-off. QoS 0 is suitable for periodic sensor readings where occasional losses are tolerable. QoS 1 is ideal for critical telemetry where the application can handle idempotency. QoS 2 is reserved for control commands where duplication could cause undesirable side effects. Since QoS is defined by the publishing client, open networks may need control mechanisms on the \emph{broker} to prevent clients from indiscriminately using QoS 2, overloading the infrastructure.

Additionally, MQTT uses connection monitoring mechanisms. The \emph{keep-alive} system detects idle or broken connections through the periodic exchange of \texttt{PINGREQ} and \texttt{PINGRESP} packets. Complementarily, the \emph{Last Will and Testament} (LWT) mechanism allows a client to register, at the time of connection, a message to be automatically published by the \emph{broker} should the connection be interrupted abruptly, serving as a failure notification to other network members \cite{oasis_v311}.

The lifecycle of an MQTT connection follows a strict sequence. The client initiates communication by sending a \texttt{CONNECT} packet, containing identifiers, credentials (username/password), and session configurations. The \emph{broker} responds with a \texttt{CONNACK}, indicating success or the cause of failure (e.g., invalid credentials). After connection, message sending (\texttt{PUBLISH}, among others) and topic subscription (\texttt{SUBSCRIBE}/\texttt{SUBACK}) occur. Ordered termination occurs via the \texttt{DISCONNECT} packet, instructing the \emph{broker} to close the connection without triggering the LWT message \cite{oasis_v311}.

The protocol has evolved significantly since its initial development. Version 3.1 (2010) established the fundamental foundations \cite{ibm_v31}, while version 3.1.1 (2013) focused on correcting ambiguities for standardization by OASIS \cite{oasis_v311}. Version 5.0 (2019) introduced substantial changes. Among the innovations, enhanced reason codes for error handling, shared subscriptions for load balancing, and crucially, user properties stand out. The latter allow attaching arbitrary key-value metadata to packets, offering a standardized vector for implementing extended authentication mechanisms as per the protocol specification \cite{oasis_v50,oasis_v50_new_features,emqx_mqtt5_new_features}.

\section{MQTT Broker}

\subsection{Broker Functions}

The MQTT \emph{broker} constitutes the central and most critical component of the network, acting as the mandatory intermediary for all communication between clients \cite{oasis_v311}. From an operational standpoint, the \emph{broker} performs three essential functions for the operation of an MQTT network.

The first is message routing, where the \emph{broker} receives \texttt{PUBLISH} packets from publishers and distributes them to all subscribers whose topic filters match the message's topic \cite{oasis_v311}.

The second responsibility is session and persistence management. The \emph{broker} must maintain the state of each connected client, including their active subscriptions, undelivered messages (depending on the QoS level), and session configurations. For persistent sessions, the \emph{broker} stores this information even after disconnections, allowing clients to restore their state upon reconnection \cite{oasis_v311,oasis_v50}. 

The third indispensable function is the application of QoS levels.

Beyond these operational functions, the \emph{broker} assumes responsibilities for security and maintaining network integrity. Client authentication is the first point of control, verifying the identity of every device attempting to connect. Although the MQTT protocol, in versions prior to 5.0, natively supports authentication via username and password, more complex implementations are possible in all recent versions through extension modules \cite{oasis_v311,oasis_v50,eclipse_mosquitto_conf,rfc9431_section_2_2_4_1}.

Consequently, the enforcement of authorization emerges as a natural extension of the \emph{broker}'s role. A robust authorization system in MQTT defines permissions for publish and subscribe operations on specific topics. This verification must be highly efficient, as it may be executed thousands of times per second in high-load networks with dynamic policies.

\emph{Rate limiting} mechanisms are essential to prevent Denial of Service (DoS) attacks and protect \emph{broker} and subscriber resources. The \emph{broker} can apply controls such as message limits per second, quotas per topic, and restrictions on the number of connections or subscriptions per client. Ideally, such limits should be configurable by identity and integrated with the authorization system, allowing for granular policies \cite{emqx_rate_limit,vernemq_rate_limit,oasis_v50_5_4_8}.

Finally, the \emph{broker} is the natural point for network auditing due to its greater processing and storage capacity. It acts as a central point for collecting system-relevant events, such as authentications, publications, and subscriptions, recording their results and durations \cite{emqx_audit,vernemq_tracing}.

Architecturally, modern \emph{brokers} offer various deployment options. The single \emph{broker} model is the simplest and most traditional configuration but represents a single point of failure and limits scalability to vertical growth. For high availability scenarios, \emph{cluster} architectures have become advantageous. In these, multiple \emph{broker} instances cooperate, synchronizing sessions and messages so the network operates as a unified service \cite{emqx_clustering,vernemq_clustering}. The most common model is \emph{masterless}, where all nodes are peers, although this introduces complexity in state synchronization and handling network partitions \cite{emqx_clustering_benefits}. Conversely, \emph{bridging} connects distinct \emph{broker} instances to forward messages on specific topics without replicating the entire state. This approach is simpler and may have performance advantages but does not offer the same availability guarantee as a \emph{cluster} \cite{emqx_bridge,vernemq_bridge,eclipse_mosquitto_conf}.

\subsection{Implementation Scenario}

The MQTT \emph{broker} ecosystem offers a vast landscape of active implementations, reflecting different use cases. Among the most consolidated open-source solutions, EMQX, VerneMQ, NanoMQ, and Mosquitto stand out \cite{emqx_compare,vernemq_docs,nanomq_site,eclipse_mosquitto_site}.

EMQX, developed in Erlang, is designed for high-demand scenarios, integration with other protocols such as CoAP, and native support for \emph{clustering} \cite{emqx_overview,emqx_coap,emqx_clustering}. Similarly, VerneMQ, also in Erlang, focuses on scalability, offering \emph{clustering} and an extension system in Lua \cite{vernemq_docs,vernemq_lua_plugins}. In contrast, NanoMQ, written in C, is optimized for edge devices, exchanging advanced features for lower resource consumption while maintaining \emph{bridging} capability to connect to larger \emph{brokers} \cite{nanomq_site,nanomq_docs_bridge}.

Additionally, cloud providers like Amazon Web Services (AWS) and Microsoft Azure offer managed \emph{brokers} (IoT Core and IoT Hub, respectively). Such services abstract the complexity of operation and scaling, but their implementations are closed-source, preventing internal modifications or deployment on own infrastructure \cite{aws_iot,azure_iot}.

In general, implementations converge on compatibility with MQTT v3.1, v3.1.1, and v5.0 specifications and support for \emph{Transport Layer Security} (TLS). The main differences lie in the deployment model, performance niche (scalability vs. lightness), and extensibility mechanisms \cite{oasis_v50_1_6,oasis_v50_5_4,emqx_compare}.

\subsection{Mosquitto}

Among the analyzed implementations, the Mosquitto \emph{broker} stands out as one of the most mature, lightweight, and widely adopted open-source solutions. Developed by Roger Light and maintained by the Eclipse Foundation, the project focuses on resource efficiency and strict protocol compliance \cite{eclipse_mosquitto_github,eclipse_mosquitto_site}. Implemented in C, Mosquitto presents low CPU and memory consumption compared to \emph{brokers} like EMQX \cite{eclipse_mosquitto_site,emqx_compare}.

This characteristic positions it in a niche similar to NanoMQ. Although NanoMQ, being a more recent project, offers architectural advantages such as \emph{multithreading} and support for MQTT-over-QUIC, Mosquitto retains a clear advantage in popularity, maturity, and stability, with more exhaustive documentation and a more active user ecosystem \cite{nanomq_site,emqx_compare,github_broker_topic}.

In terms of compliance, Mosquitto fully implements the MQTT v3.1, v3.1.1, and v5.0 specifications and provides essential security mechanisms such as TLS support and access control via Access Control Lists (ACLs) \cite{eclipse_mosquitto_conf,eclipse_mosquitto_auth_methods}. The most relevant characteristic for this work, however, is the support for extension modules for authentication and authorization. The \emph{broker} exposes a set of \emph{hooks} (triggers) that allow intercepting critical connection lifecycle events, delegating security decisions to custom logic \cite{eclipse_mosquitto_plugin,mosquitto_auth_plug,mosquitto_go_auth}.

The fact that Mosquitto is implemented in C facilitates the use of FFI, allowing security logic to be written in other languages.

The choice of Mosquitto as the basis for this work was motivated by this combination of factors. Its lightness, maturity, and widespread adoption make it a reliable platform. However, the main motivation lies in the flexibility of its module mechanism and easy integration via FFI. While other solutions focus on features not essential to the project's scope, Mosquitto's operational simplicity and powerful extension API make it ideal for developing and validating a custom authorization mechanism, with the guarantee that results will be relevant to a broader user community.


\section{Security and Authorization Models}

\subsection{Authentication (AuthN) versus Authorization (AuthZ)}

Authentication (AuthN) and Authorization (AuthZ) are essential pillars of system security and, in MQTT, represent distinct yet complementary processes. Authentication verifies a subject's identity through credentials such as username and password, digital certificates, or tokens, with the main objective of establishing 'who' the client attempting to connect to the \emph{broker} is \cite{eclipse_mosquitto_conf,rfc3539_section_1_2,ibm_authn_authz,microsoft_authn_authz,freecodecamp_authn_authz}.

Authorization, on the other hand, occurs after successful authentication, determining whether the subject has permission to execute specific actions on specific resources, such as publishing or subscribing to MQTT topics \cite{emqx_acl_explanation}. It is worth noting that authorization also applies to anonymous clients, who operate with a standard and restricted list of permissions \cite{eclipse_mosquitto_conf}. Furthermore, authorization must be periodically re-evaluated to allow updates in access levels as necessary \cite{owasp_auth,nist_security_80053-ac3,ibm_authn_authz,microsoft_authn_authz,freecodecamp_authn_authz}.

This clear distinction between AuthN and AuthZ allows for the implementation of dynamic and granular security models.

\subsection{Authorization Models: RBAC, ABAC, and DAC}

Various models structure the authorization of entities in systems; among the most relevant are \emph{Role-Based Access Control} (RBAC), \emph{Attribute-Based Access Control} (ABAC), and \emph{Discretionary Access Control} (DAC).

In RBAC, permissions are assigned to specific roles, and entities receive access by being associated with those roles. This intermediate model simplifies permission management in environments with stable functions, facilitating centralized updates \cite{ferraiolo1992}. For example, if the 'Engineer' role needs a new permission, it suffices to add it to the corresponding role for all engineers to receive it automatically. However, in complex systems with many role variations, the high number of roles can make management burdensome \cite{ferraiolo1992,owasp_auth}.

ABAC uses attributes of the subject, resource, action, and environment to evaluate authorization rules, allowing for detailed contextual policies, such as allowing access to devices only during business hours \cite{nist_abac_800162}. This model offers high granularity and flexibility but imposes greater complexity in defining and maintaining rules, as well as high computational costs due to real-time evaluation \cite{nist_abac_800162}.

DAC, in turn, grants the resource owner the definition of access permissions for other entities. In the MQTT context, where the \emph{broker} acts as the central owner, this often manifests through ACLs, which directly assign publish and subscribe permissions to specific clients or groups \cite{emqx_acl_guide,eclipse_mosquitto_conf}. This approach is simple and intuitive but can incur a high administrative cost due to the need for individual permission updates in case of policy changes.

\subsection{Identity-Based Authorization and Capability-Based Authorization}

There are two distinct philosophies regarding the use of tokens for authentication and authorization. On one side, the maximum separation between authentication and authorization, where the access token contains only the user's minimum identity, leaving the authorization system to determine their permissions with each new connection. This approach ensures that permission changes are reflected immediately in access control, although it prevents the token from being used as an autonomous license \cite{permitio_jwt_authorization}.

On the other side, the philosophy of capability tokens, where the token carries an explicit list of permissions, enabling decentralized authorization systems and a minimal need for continuous connection. This approach also allows networks to grant access exclusively based on the token's claims, without considering the client's identity. However, this model delays the propagation of new access rules, as previously issued tokens remain valid until they expire, configuring the so-called 'New Enemy problem' \cite{neil_madden_capacity_api_security,storj_capacity,wikipedia_capacity_security}.

\subsection{Symmetric and Asymmetric Cryptography}

Cryptography can be divided into two distinct strategies: symmetric and asymmetric.

Symmetric cryptography uses a single shared key to both encrypt and decrypt the message. It is a fast and efficient method, ideal for large volumes of information. However, its main challenges are the secure distribution of this key between parties and the separation between the right to encrypt and decrypt. The \emph{Advanced Encryption Standard} (AES) is an example of a prominent algorithm for this strategy \cite{nist_fips_197}.

In contrast, asymmetric cryptography, or public-key cryptography, uses a pair of keys: a public one, which can be freely distributed, and a private one, which must be kept secret. The public key performs one of the operations and the private key the reverse, depending on the use case. For exchanging secret messages, the public key is used to encrypt them. For digital signatures, it decrypts. Rivest-Shamir-Adleman (RSA) is a classic example of an algorithm in this strategy \cite{rsa_paper}.

Both methods can be used in a complementary way, with many systems using asymmetric cryptography to securely exchange a symmetric key, subsequently using it for the rest of the communication.

\subsection{Transport Layer Security (TLS)}

Transport Layer Security (TLS) is a cryptographic protocol that establishes secure communication channels between machines through a \emph{handshake} process, during which security parameters are negotiated and authentication of at least one party is performed, usually via digital certificates such as the X.509 standard. TLS guarantees three pillars of information security: confidentiality (through encryption), integrity (preventing undetected alterations), and authentication. 

MQTT, like other protocols such as HTTP, can operate over TLS to guarantee transport security, reducing the risks of interception and manipulation of sensitive information \cite{rfc8446}.

\subsection{Authentication and Authorization in MQTT}

Historically, MQTT version 3.1.1 offered native support for restricted authentication. The specification was limited to the \texttt{username} and \texttt{password} fields, not providing dedicated structures for additional metadata \cite{ibm_v31}. To implement token-based methods, developers often resorted to these text fields to transport credentials, adapting the specification to modern security needs \cite{ibm_v31,rfc9431_section_2_2_4_1}.

The introduction of version 5.0 significantly expanded these capabilities. The \texttt{CONNECT} packet started supporting \emph{User Properties} that allow the transport of tokens or additional context in a structured way. Furthermore, the variable header received the \texttt{Authentication Method} and \texttt{Authentication Data} fields, allowing for the explicit negotiation of the security mechanism and the initial sending of data. 

A critical innovation of MQTT 5.0 is the support for extended authentication flows through the \texttt{AUTH} packet. Unlike the classic single request-response model, the \texttt{AUTH} packet allows the server to challenge the client, requiring successive exchanges of data until the identity is confirmed. This enables the implementation of complex mechanisms such as cryptographic challenges (Challenge-Response) or authentication via SCRAM. Additionally, the specification allows reauthentication during an active connection: the \emph{broker} can request, at any time, that the client renew their credentials by sending an \texttt{AUTH} packet, without the need to drop the \emph{Transmission Control Protocol} (TCP) connection. Figure \ref{fig:fig1} illustrates this extended flow.

\begin{figure}[htb!]
\centering\includegraphics[width=.80\textwidth]{figuras/1-auth-flow.png}
\caption{Example of extended authentication flow in MQTT 5 using the \texttt{AUTH} packet}
\label{fig:fig1}
{\footnotesize Source: \url{https://www.codementor.io/@emqtech/leveraging-enhanced-authentication-for-mqtt-security-25opca0497}. Accessed on: Nov 14, 2025.}
\end{figure}

Despite native improvements, robust security often depends on external approaches. mTLS (\emph{Mutual TLS}) is the gold standard, using X.509 certificates to validate both the server and the client. Although it eliminates the need for passwords and offers strong guarantees via Public Key Infrastructure (PKI), its adoption in IoT faces barriers of operational complexity (certificate lifecycle management) and computational cost, which can be prohibitive \cite{cloudflare_mtls,eclipse_mosquitto_conf,tls_mqtt_cost_evaluation}.

A more flexible alternative is token-based authentication, often orchestrated via OAuth 2.0. In this flow, responsibility for authentication is delegated to an external server (Identity Provider), which issues short-lived access tokens (\emph{Access Tokens}) and long-lived refresh tokens (\emph{Refresh Tokens}). The client presents the access token to the \emph{broker}, which validates it locally, if it is a self-contained token like a JWT, or via remote introspection. It is notable that the OAuth 2.0 protocol does not impose a specific format for the access token, although JWT is the predominant choice \cite{rfc6749,rfc6749_section_1_4,rfc7519,rfc8725}.

In terms of authorization, the most widespread mechanism is based on ACLs that map identities to topic patterns. The Mosquitto \emph{broker}, for example, natively supports static ACLs via configuration files \cite{eclipse_mosquitto_conf,emqx_acl_explanation}. For dynamic scenarios, extension modules such as \emph{Dynamic Security} allow the implementation of RBAC models, manageable at runtime via system control topics, such as \texttt{\$CONTROL} \cite{eclipse_mosquitto_dynamic}.

The evolution of IoT architectures tends to favor integration with external policy systems. Replacing static files with databases or external services allows for the implementation of ABAC (\emph{Attribute-Based Access Control}) and granular RBAC models, centralizing business logic outside the \emph{broker}, although it introduces network latency in verification.

\section{JSON Web Token}

The JSON Web Token (JWT) is a compact open standard for transmitting claims (\emph{claims}) between parties, structured as a \emph{JavaScript Object Notation} (JSON) object. Standardized by the \emph{Internet Engineering Task Force} (IETF) via \emph{Request for Comments} (RFC) 7519 in 2015 \cite{rfc7519}, the JWT integrates the \emph{JSON Object Signing and Encryption} (JOSE) ecosystem. This set of specifications (RFC 7515-7520) specifies different signing and encryption mechanisms, allowing adaptation in content protection and token verifiability \cite{rfc7515,rfc7516,rfc7517,rfc7518,rfc7519,rfc7520}.

Historically, JWT emerged to meet the demand for a lightweight and interoperable format capable of authenticating and transporting identity or attributes between clients and services. Currently, the prevalence of JWT in modern ecosystems is evidenced by the availability of libraries in virtually all relevant programming languages. As an example, the JOSE package in the NPM registry records millions of weekly downloads \cite{jose_npm}.

\subsection{Structure and Format}

Structurally, the JWT consists of a sequence of characters encoded in Base64URL, composed of segments delimited by a dot ('.'). The standard offers two main architectures that define which segments will be present and the security treatment applied: \emph{JSON Web Signature} (JWS), defined in RFC 7515 for signed tokens, and \emph{JSON Web Encryption} (JWE), defined in RFC 7516 for tokens with confidential content \cite{rfc7515,rfc7516}.

In the case of JWS, the token is composed of three parts: the header, the payload, and the signature.

The \textbf{header} is a JSON object that describes the cryptographic operations applied to the token. Two key-value pairs stand out: \texttt{alg}, which specifies the signature or encryption algorithm, and \texttt{typ}, which indicates the type of object, typically filled with "JWT", with other valid types being "at+jwt" for the case where it is being used as an access token in an OAuth system \cite{rfc7519_section_3_1,rfc7515_section_3_3}. Among the most used signing algorithms are \emph{Hash-Based Message Authentication Code} (HMAC) with \emph{Secure Hash Algorithm} of 256 bits (SHA-256) for symmetric schemes, and RSA or \emph{Elliptic Curve Digital Signature Algorithm} (ECDSA) of 256 bits for asymmetric schemes \cite{rfc7515,rfc7518,rsa_paper,rfc9068_section_2_1}.

The \textbf{payload} transports the set of claims. In JWS, this content is only encoded, not encrypted, remaining readable to any entity that possesses the token. The most common reserved claims include: \texttt{iss} (issuer), \texttt{sub} (subject), \texttt{aud} (audience/recipient), \texttt{exp} (expiration), \texttt{nbf} (\emph{not before}, the time before which the token should not be accepted), \texttt{iat} (issued at time) and \texttt{jti} (unique token ID, used to prevent replay attacks) \cite{rfc7519_section_4_1}.

The \textbf{signature} is the cryptographic result generated by the algorithm defined in \texttt{alg}, applied to the concatenation of the encoded header and payload. When validating the signature, using the public key in asymmetric schemes, the receiver guarantees the integrity and authenticity of the token, ensuring it was generated by a trusted issuer and has not been tampered with \cite{rfc7515}.

Figure \ref{fig:fig2} illustrates the composition of these parts.

\begin{figure}[htb!]
\centering\includegraphics[width=.85\textwidth]{figuras/2-example-jwt-jws.png}
\caption{Structure of a JWT implementing JWS}
\label{fig:fig2}
{\footnotesize Source: \url{https://logto.io/jwt-decoder}. Accessed on: Nov 14, 2025.}
\end{figure}

On the other hand, JWE has a structure of five parts: the header, the encrypted key, the initialization vector, the ciphertext, and the authentication tag \cite{rfc7516}.

The JWE header is a JSON object that, like JWS, describes the algorithms used. However, it contains additional fields. The "alg" field specifies the key management algorithm, i.e., how the content encryption key was protected. Algorithms such as RSA with \emph{Optimal Asymmetric Encryption Padding} (RSA-OAEP) and \emph{Elliptic Curve Diffie-Hellman Ephemeral Static} (ECDH-ES) are considered the most recommended for this purpose by the RFC. Other options, such as AES Key Wrap (128 and 256 bits) and the \texttt{dir} option (direct key), are also listed as recommended for implementation, although no algorithm is mandatory. The "enc" field indicates the payload encryption algorithm, which can be AES with HMAC or \emph{AES Galois/Counter Mode} (GCM), with between 128 and 256 bits for AES and 256 to 512 bits for HMAC \cite{rfc7516,rfc7518,rfc8037_section_3_2}.

The JWE encrypted key contains the Content Encryption Key (CEK), which is the secret used to encrypt the token content. This makes part of the JWE a secret that is itself encrypted. By definition, the payload is always symmetrically encrypted, regardless of the algorithm chosen to encrypt the CEK \cite{rfc7516}.

The initialization vector, or the \texttt{iv} field of the JWE, is a value, typically random, used to ensure that encrypting the same content at different times results in different ciphertexts. It is used by the encryption algorithm, along with the CEK, to encrypt the payload, as modern symmetric encryption algorithms like AES-GCM require these values to prevent exploitable patterns in the cipher (known as \emph{nonce reuse}) \cite{rfc8452}.

The JWE ciphertext is just the payload encrypted with the CEK and the initialization vector. To obtain it, the token must be decrypted for the CEK to be usable.

Finally, the authentication tag is a value generated by authenticated encryption algorithms such as AES-GCM. Its function is the same as the JWS signature: to guarantee the integrity and authenticity of the data. When decrypting the token, the receiver can recalculate this tag and compare the result with the received one, thus knowing if the token has been manipulated if the values are not equal.

\subsection{Analysis of Advantages and Limitations}

Due to its nature, both JWT versions are considered \emph{stateless}. Verification depends only on the key, eliminating the need to query a centralized database to validate each request \cite{wikipedia_jwt,okta_auth0_jwt_myths}. This simplicity has driven the mass adoption of JWT. Data from the TheirStack platform indicates that thousands of companies use JWT and OAuth in their technology stacks \cite{theirstack_jwt,theirstack_oauth}.

However, the model presents architectural limitations. The \emph{stateless} characteristic makes immediate revocation difficult: once issued, a token remains valid until its expiration, even if the user's permissions are changed on the server. This requires a delicate balance in defining the token's Time to Live (TTL). Additionally, the use of Base64URL encoding results in an approximate 33\% increase in data size compared to the original binary \cite{rfc4648_section_4}.

Another critical disadvantage is the rigidity of claims. The JWT content is fixed at issuance, making it impossible for the client to add restrictions or attenuate their own permissions without requesting a new token from the issuer.

Historically, implementation vulnerabilities have also affected JWT's reputation, such as the undue acceptance of the \texttt{none} algorithm (allowing unsigned tokens) and confusion between symmetric and asymmetric keys. Such failures motivated the emergence of alternatives like PASETO (\emph{Platform-Agnostic Security Tokens}), which aims to eliminate insecure choices by default \cite{paseto_io,paragonie_paseto}.

\section{Biscuit Token}

Biscuit is an authorization token format originally developed by Geoffroy Couprie in 2018 and officially adopted by the Eclipse Foundation in 2025 \cite{biscuit_site,eclipse_website_biscuit}. Conceived as a response to the limitations of traditional tokens in microservice architectures, Biscuit prioritizes the reduction of network calls and the decentralization of authorization.

Biscuit's design was heavily influenced by Google's Macaroons. Like Macaroons, Biscuit supports offline attenuation, allowing a holder to derive a new token with privileges equal to or inferior to the original without interacting with the issuer. The main evolution lies in the cryptographic base: while Macaroons use HMAC (symmetric), Biscuit employs cryptography with algorithms such as Ed25519 or ECDSA on the secp256r1 curve (asymmetric), segregating issuance and verification. Furthermore, Biscuit formalizes a language for expressing policies based on Datalog \cite{biscuit_cryptography,biscuit_v2}.

Structurally, a Biscuit token is a chain of cryptographically signed blocks. The first block, called the \emph{Authority Block}, is created by the issuer and defines the fundamental rights. Subsequent blocks, called attenuation blocks, can be attached by other holders. Integrity is guaranteed by a scheme of chained signatures: each block contains the Datalog instructions and the public key corresponding to the private key that will encrypt the next block, both encrypted. In this system:
\begin{enumerate}
    \item The attenuator knows the private key corresponding to the public key of the previous block (necessary to sign the new block);
    \item The attenuator generates a new ephemeral key pair, inserting the public key into the block and passing the private one to the next holder.
\end{enumerate}
To prevent further attenuations (seal the token), it suffices not to transmit the last private key \cite{biscuit_cryptography}.

\subsection{Policy Language: Datalog}

The use of Datalog allows for the expression of complex security policies through three elements: facts, rules, and checks.
\begin{itemize}
    \item \textbf{Facts:} Declare information or privileges (e.g., \texttt{right("file1", "read")}).
    \item \textbf{Rules:} Allow inferring new facts from others, following the form \texttt{head <- body}. For example, to grant reading if the resource belongs to "alice":
    \begin{verbatim}
    right($res, "read") <- resource($res), owner("alice", $res)
    \end{verbatim}
    \item \textbf{Checks:} Queries that must be satisfied to validate the token. The authorizer combines token data with the request context (time, IP, resource) and evaluates the \texttt{check if} clauses or the \texttt{allow/deny} policies.
\end{itemize}

For security reasons, the scope of facts is controlled: rules from an attenuated block operate only on facts generated in that same block, the authority block, or by the authorizer, preventing the injection of false facts in intermediate blocks. Figure \ref{fig:fig3} demonstrates the chaining and visibility of facts.

\begin{figure}[htb!]
\centering\includegraphics[width=.80\textwidth]{figuras/3-biscuit-blocks.png}
\caption{Chaining of blocks in the Biscuit token and scope of fact visibility}
\label{fig:fig3}
{\footnotesize Source: \url{https://doc.biscuitsec.org}. Accessed on: Nov 14, 2025.}
\end{figure}

\subsection{Comparative Advantages and Adoption}

Biscuit's architecture enables advanced delegation scenarios. A user can receive a "root" token and generate specific derived tokens for different services, restricting access only to what is necessary (principle of least privilege) without overloading the authentication server. From version 3.0, support for \emph{Third-party Blocks} allows incorporating authorizations from external entities, facilitating identity federation \cite{biscuit_v3}.

Compared to JWT, Biscuit stands out for its flexibility in ABAC (\emph{Attribute-Based Access Control}) systems. While JWT is static, Biscuit carries executable logic, adaptable to the verifier's current context. In terms of performance, it uses \emph{Protocol Buffers} for serialization, which tends to be more efficient in \emph{parsing} than JSON and does not suffer from the inflation caused by Base64URL, although the final token size depends on the complexity and quantity of chained blocks \cite{biscuit_spec}. Figure \ref{fig:fig5} summarizes the fundamental differences.

\begin{figure}[htb!]
\centering\includegraphics[width=.80\textwidth]{figuras/5-biscuit-vs-jwt.png}
  \caption{Comparison table: JWT vs. Biscuit}
\label{fig:fig5}
{\footnotesize Source: Elaborated by the author.}
\end{figure}

Regarding revocation, Biscuit inherits the challenges of \emph{stateless} systems but mitigates the problem through unique signature identifiers in each block, so that revoking a 'root' token automatically revokes all its derivatives. Furthermore, support for \emph{Snapshots} allows detailed auditing, enabling the reproduction of the authorization decision process for debugging purposes, or even partially delegating it \cite{biscuit_snapshots}.

In terms of maturity and industrial adoption, Biscuit has sponsorship and production use from companies such as Clever Cloud (in the Pulsar service) and 3DS Outscale, which uses the token in its Identity and Access Management (IAM) system \cite{biscuit_contributors,eclipse_website_biscuit_proposal}. The ecosystem has official implementations in Rust, Haskell, Python, C\#, and JavaScript (via WebAssembly), as detailed in Figure \ref{fig:fig4}.

\begin{figure}[htb!]
\centering\includegraphics[width=.80\textwidth]{figuras/4-biscuit-implementation-feature-map.png}
\caption{Feature matrix of Biscuit implementations (Nov 2025)}
\label{fig:fig4}
{\footnotesize Source: \url{https://github.com/eclipse-biscuit/biscuit}. Accessed on: Nov 14, 2025.}
\end{figure}

\section{Foreign Function Interface}

The \emph{Foreign Function Interface} constitutes a mechanism that allows a program written in a given programming language to invoke functions or use services developed in another language \cite{ffi_wikipedia}. This interface is fundamental in heterogeneous software ecosystems, where different languages are selected based on their intrinsic advantages. The most common scenario involves the interaction between high-level languages (such as Rust, Go, or Java) and low-level system software, typically written in C, which acts as a computational \textit{lingua franca} \cite{ffi_wikipedia}. The FFI abstracts the complexity inherent in function call conversion, such as translating data types and managing memory between runtime environments, whose paradigms may diverge significantly.

Modern languages often offer tools to facilitate this interoperability pattern. \texttt{cgo}, for example, is the Go language tool that enables mutual invocation of C and Go code \cite{cgo_doc}, being used in projects like \texttt{mosquitto-go-auth} \cite{mosquitto_go_auth}. In the Rust ecosystem, tools like \texttt{cbindgen} automate the generation of C headers from Rust code \cite{cbindgen_docs}, while \texttt{bindgen} performs the reverse process \cite{bindgen_docs}. In the context of this work, the FFI is the architectural element that enables the integration between the proposed authorization module, written in Rust to leverage memory safety and Biscuit token libraries, and the Mosquitto \emph{broker}, developed in C.

\section{Docker and Containerization}

Containerization is an operating system-level virtualization technology that allows packaging an application, along with its dependencies and libraries, into an isolated unit called a container \cite{docker_container, docker_what_it_is}. Unlike traditional virtual machines, which require complete virtualization of hardware and a guest operating system (\textit{guest OS}), containers share the host operating system's \textit{kernel}. This architectural characteristic results in significantly lighter and more efficient instances \cite{docker_container}. The main utility of containerization lies in guaranteeing environmental consistency: it ensures that software runs identically in both development environments and production servers.

Launched in 2013, Docker popularized this technology by providing a standardized ecosystem for building, deploying, and managing containers \cite{docker_11_years}. For the experiments proposed in this work, Docker's isolation and resource control features are essential for the scientific validation of test scenarios. The platform allows the deterministic allocation of hardware resources via execution parameters. Options such as \texttt{--memory} and \texttt{--cpus} allow limiting the RAM memory and the number of processing cycles available to the \emph{broker} or emulated clients \cite{docker_controls_memory, docker_controls_cpu}. Additionally, the \texttt{--cpuset-cpus} option allows restricting execution to specific CPU cores, useful in systems with heterogeneous cores, while the \texttt{blkio} controller manages disk input and output bandwidth (\emph{disk} I/O) \cite{docker_controls_io}.

In the context of network simulation, Docker offers robust abstractions. The \texttt{bridge} mode isolates the container in its own subnet \cite{docker_bridge_driver}, facilitating port management and \emph{Network Address Translation} (NAT), which allows the coexistence of multiple \emph{broker} instances on the same host without conflicts \cite{docker_networking_overview}. To replicate the adverse conditions typical of IoT networks, tools such as \texttt{tc} (\textit{Traffic Control}) and its \texttt{netem} module can be integrated into containers to inject artificial latency, packet loss, and reordering \cite{tc_utility, netem_utility}.

Experimental reproducibility is guaranteed by Docker's image system. Through the \textit{Dockerfile} file, the exact version of the required software is specified (e.g., \texttt{FROM eclipse-mosquitto:2.0.15}), ensuring that all test batteries use the same environment \cite{docker_dockerfile}. The \texttt{docker-compose} orchestrator complements this functionality, allowing the definition of the entire test topology (clients, brokers, and networks) as code, executable with a single command \cite{docker_compose}.

Despite its versatility, it should be noted that Docker presents limitations for the direct measurement of container energy consumption, a relevant metric for analyzing impact on embedded devices.

\section{Mosquitto Extensibility}

Mosquitto provides an API for developing extension modules, defined in the headers \texttt{mosquitto\_plugin.h} and, from version 2.0 of the \emph{broker}, in the file \texttt{mosquitto\_broker.h}, which introduces version 5.0 of the API as a complement. This architecture is based on the registration of \emph{callback} functions, which are invoked by the \emph{broker} upon the occurrence of key events. This model allows developers to intercept the execution flow to modify behaviors or validate operations without the need to alter the \emph{broker}'s source code \cite{eclipse_mosquitto_plugin, eclipse_mosquitto_plugin_callback_options}.

The lifecycle of a module begins when the \emph{broker} loads it and invokes the mandatory function \texttt{mosquitto\_plugin\_version} to verify API compatibility. Next, the function \texttt{mosquitto\_plugin\_init} is executed, responsible for initialization. At this stage, the module receives an identifier, configuration options, and a pointer to user memory, which Mosquitto will preserve and return in each subsequent call. After initialization, the module uses the functions \texttt{mosquitto\_callback\_register} and \texttt{mosquitto\_callback\_unregister} to manage events of interest.

Among the events available in the API, those critical for implementing security mechanisms stand out:

\begin{itemize}
  \item \texttt{MOSQ\_EVT\_Basic\_AUTH}: Triggered by a connection request containing traditional credentials (username and password).
  \item \texttt{MOSQ\_EVT\_EXT\_AUTH\_START}: Invoked at the beginning of an extended authentication flow.
  \item \texttt{MOSQ\_EVT\_EXT\_AUTH\_CONTINUE}: Called during intermediate stages of extended authentication (exchange of \texttt{AUTH} packets).
  \item \texttt{MOSQ\_EVT\_ACL\_CHECK}: Triggered whenever a subscription or publication request on a topic occurs, to verify permissions.
  \item \texttt{MOSQ\_EVT\_MESSAGE}: Occurs during message processing. It is relevant to note that, in the outbound flow, this event is triggered individually for each subscriber that will receive the message, allowing for granular filtering.
  \item \texttt{MOSQ\_EVT\_CONTROL}: Related to publication events on the \texttt{\$CONTROL} topic, used by the official \emph{Dynamic Security} extension for dynamic ACL management.
\end{itemize}

The API also provides utility functions for session management, such as \texttt{mosquitto\_kick\_client\_by\_clientid} and \texttt{mosquitto\_kick\_client\_by\_username}, which allow for the forced disconnection of clients \cite{eclipse_mosquitto_plugin_callback_options}.

Examples consolidated in the community demonstrate the effectiveness of this model. The \texttt{mosquitto-go-auth} project uses this interface to create a bridge in Go, mapping the \emph{broker}'s functions to various authentication \emph{backends}, such as databases. Similarly, \texttt{mosquitto-auth-plug} implements analogous functionalities, using version 4.0 of the API \cite{eclipse_mosquitto_plugin}.
