Short answer: **The broker (Mosquitto) can accept a binary CONNECT password (that’s in the MQTT spec). The Paho clients’ *public* APIs, however, expect a text/password string — so don’t rely on raw arbitrary bytes unless you test your exact client version.**

Details & proof:

* The MQTT spec (v3.1.1 and v5.0) explicitly defines the Password field as *binary* data (0–65535 bytes, length-prefixed). So the protocol allows arbitrary bytes in the CONNECT password field. ([docs.oasis-open.org][1])

* Mosquitto implements MQTT and will accept CONNECT packets that obey the spec. In practice brokers (including Mosquitto) accept binary data in the password field because the spec says so (i.e. the wire format does not force text-only). (Mosquitto docs + general MQTT packet docs). ([Eclipse Mosquitto][2])

* **Paho (what you asked about):**

  * The **Paho-Python** public API `Client.username_pw_set(username, password)` is documented to take `password: str | None` and if passed a `str` it will be UTF-8 encoded for the wire. The docs do **not** advertise arbitrary-binary support for the `password` parameter. That means relying on passing arbitrary `bytes` to `username_pw_set` is not guaranteed by the public API. ([Eclipse Dev][3])
  * Other Paho clients (Java, C, etc.) expose password APIs that take character/strings (Java: `setPassword(char[])`), again indicating the public API expects textual credentials rather than opaque binary blobs. ([Eclipse Dev][4])

What this means for your Biscuit (Protobuf) binary in practice

* If you control **both** sides (your client and broker plugin) and you *test* with your exact Paho version, you **can** probably get away with sending raw bytes in the CONNECT password (the wire supports it and Mosquitto will accept a valid packet). BUT: **it’s not guaranteed portable across client libraries or versions** because many clients’ public APIs assume/expect text and may encode/validate or even reject non-string inputs.
* For robustness and interoperability I recommend one of these approaches:

  1. **Encode the Biscuit bytes into ASCII (base64 or hex)** and put that ASCII string in the CONNECT password (works everywhere). Base64 is denser; hex is simpler and may be preferred if you want only hex on the wire. (You already noted these options.)
  2. **Use MQTT v5 AUTH or user properties** if you want a more explicit/binary-capable auth flow — MQTT v5 was designed to be more flexible for this kind of thing and some client/broker combos expose binary auth fields more explicitly.
  3. **If you must send raw binary**, test thoroughly with the exact Paho version(s) you run (try both `username_pw_set(..., password=bytes_obj)` and, if necessary, set the internal/private `_password` byte buffer the client uses before connect). Treat that as a brittle, implementation-dependent solution.

[1]: https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html?utm_source=chatgpt.com "MQTT Version 3.1.1 - OASIS"
[2]: https://mosquitto.org/documentation/?utm_source=chatgpt.com "Documentation - Eclipse Mosquitto"
[3]: https://eclipse.dev/paho/files/paho.mqtt.python/html/client.html "client module — Eclipse paho-mqtt  documentation"
[4]: https://eclipse.dev/paho/files/javadoc/org/eclipse/paho/client/mqttv3/MqttConnectOptions.html?utm_source=chatgpt.com "MqttConnectOptions - Eclipse"

---

Several mature MQTT client libraries expose a binary/password API** (so you can pass raw bytes) — but **not all** do, and behavior can vary by language/binding. Below are the mature clients I can vouch for and the practical caveats.

## Clients that accept binary (mature / production-ready)

* **MQTT.js (Node.js)** — `password` in the CONNECT options can be a `Buffer` (binary). Good for sending arbitrary bytes. ([GitHub][1])
* **MQTTnet (C#/.NET)** — builder overload accepts `WithCredentials(string username, byte[] password)` (explicit `byte[]` password API). ([docs.dndocs.com][2])
* **Eclipse Paho (C, async and sync)** — the C async connect options include an explicit `binarypwd` field (length + pointer) for a binary password. The Paho C API therefore supports binary passwords. ([eclipse.dev][3])
* **HiveMQ MQTT client (Java)** — the modern HiveMQ client exposes simple-auth builders and examples where the password is provided as bytes (examples/community posts show `.password(myString.getBytes(UTF_8))` usage), i.e. a byte-array password path exists in the API. (This is an actively maintained, production Java client.) ([HiveMQ Support Forum][4])

## Practical recommendations (be sure)

1. **Prefer clients in the “accept binary” list** if you want to send Biscuit’s raw Protobuf bytes in the CONNECT password (MQTT v3.1.1/5 wire supports it). Good picks: **MQTT.js**, **MQTTnet**, **Paho C** (or HiveMQ Java client). ([GitHub][1])
3. **Always verify on the wire** (capture with `tcpdump`/Wireshark) after a test connect to ensure the CONNECT password bytes are what you expect. Implementation bugs / wrappers can still mangle bytes.
4. **Consider MQTT v5 AUTH** if you want a more flexible binary auth flow — v5 has better auth extensibility and some clients/brokers give nicer APIs for binary auth data.


[1]: https://github.com/mqttjs/MQTT.js/?utm_source=chatgpt.com "mqttjs/MQTT.js: The MQTT client for Node.js and the browser - GitHub"
[2]: https://docs.dndocs.com/n/MQTTnet/4.3.6.1152/api/MQTTnet.Client.MqttClientOptionsBuilder.html "Class MqttClientOptionsBuilder
 \| MQTTnet 4.3.6.1152 | DNDocs "
[3]: https://eclipse.dev/paho/files/mqttdoc/MQTTAsync/html/struct_m_q_t_t_async__connect_options.html "Paho Asynchronous MQTT C Client Library: MQTTAsync_connectOptions Struct Reference"
[4]: https://community.hivemq.com/t/reconnector-use-new-authentication-details/3290?utm_source=chatgpt.com "Reconnector use new authentication details - HiveMQ Support Forum"
[5]: https://manpages.ubuntu.com/manpages/xenial/man3/libmosquitto.3.html?utm_source=chatgpt.com "Ubuntu Manpage: libmosquitto - MQTT version 3.1 client library"
[6]: https://eclipse.dev/paho/files/javadoc/org/eclipse/paho/client/mqttv3/MqttConnectOptions.html?utm_source=chatgpt.com "MqttConnectOptions - Eclipse"
